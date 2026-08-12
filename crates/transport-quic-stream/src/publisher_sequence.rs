//! Durable publisher-sequence reservation boundary.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::{AgentTextStreamRecordV1, AgentTextStreamTranscriptV1};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

use crate::{AgentTextStreamCrypto, QuicTextStreamError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherSequenceSnapshot {
    pub next_seq: u64,
    pub transcript_hash: [u8; 32],
    pub chunk_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherSequenceReservation {
    pub expected: PublisherSequenceSnapshot,
    pub resulting: PublisherSequenceSnapshot,
    pub token: [u8; 16],
}

pub trait PublisherSequenceStore: Send + Sync {
    fn load(&self, context_id: &[u8; 32]) -> Result<Option<PublisherSequenceSnapshot>, String>;

    fn reserve(
        &self,
        context_id: &[u8; 32],
        initial_transcript_hash: &[u8; 32],
        reservation: &PublisherSequenceReservation,
    ) -> Result<(), String>;

    fn confirm(&self, context_id: &[u8; 32], token: &[u8; 16]) -> Result<(), String>;
}

pub struct ReservedPublisherRecords {
    pub records: Vec<AgentTextStreamRecordV1>,
    pub transcript_hash: [u8; 32],
    pub chunk_count: u64,
    context_id: [u8; 32],
    token: [u8; 16],
    store: Arc<dyn PublisherSequenceStore>,
}

impl ReservedPublisherRecords {
    pub fn confirm(self) -> Result<(), QuicTextStreamError> {
        self.store
            .confirm(&self.context_id, &self.token)
            .map_err(QuicTextStreamError::PublisherSequence)
    }
}

pub fn reserve_publisher_records(
    crypto: &AgentTextStreamCrypto,
    stream_id: &[u8],
    start_event_id: &MessageId,
    frames: &[(u8, Vec<u8>)],
) -> Result<ReservedPublisherRecords, QuicTextStreamError> {
    let store = crypto
        .publisher_sequence_store()
        .ok_or(QuicTextStreamError::PublisherSequenceStateRequired)?;
    let context_id: [u8; 32] = Sha256::digest(crypto.context.encode()).into();
    let initial =
        AgentTextStreamTranscriptV1::new(stream_id.to_vec(), start_event_id.clone()).hash();
    let expected = store
        .load(&context_id)
        .map_err(QuicTextStreamError::PublisherSequence)?
        .unwrap_or(PublisherSequenceSnapshot {
            next_seq: 1,
            transcript_hash: initial,
            chunk_count: 0,
        });
    let mut transcript = AgentTextStreamTranscriptV1::from_state(
        stream_id.to_vec(),
        start_event_id.clone(),
        expected.transcript_hash,
        expected.chunk_count,
    );
    let mut records = Vec::with_capacity(frames.len());
    for (offset, (record_type, plaintext)) in frames.iter().enumerate() {
        let seq = expected
            .next_seq
            .checked_add(offset as u64)
            .ok_or_else(|| {
                QuicTextStreamError::PublisherSequence(
                    "agent stream publisher sequence exhausted".to_owned(),
                )
            })?;
        let record =
            AgentTextStreamRecordV1::new(stream_id.to_vec(), seq, *record_type, plaintext.clone());
        record.validate()?;
        transcript.append(seq, *record_type, plaintext);
        records.push(record);
    }
    let mut token = [0_u8; 16];
    OsRng.fill_bytes(&mut token);
    let resulting = PublisherSequenceSnapshot {
        next_seq: expected
            .next_seq
            .checked_add(records.len() as u64)
            .ok_or_else(|| {
                QuicTextStreamError::PublisherSequence(
                    "agent stream publisher sequence exhausted".to_owned(),
                )
            })?,
        transcript_hash: transcript.hash(),
        chunk_count: transcript.chunk_count(),
    };
    store
        .reserve(
            &context_id,
            &initial,
            &PublisherSequenceReservation {
                expected,
                resulting,
                token,
            },
        )
        .map_err(QuicTextStreamError::PublisherSequence)?;
    Ok(ReservedPublisherRecords {
        records,
        transcript_hash: resulting.transcript_hash,
        chunk_count: resulting.chunk_count,
        context_id,
        token,
        store,
    })
}

/// Process-local implementation for tests and explicit development harnesses.
/// Production encrypted publishers use the account SQLCipher-backed store.
type EphemeralPublisherState = HashMap<[u8; 32], (PublisherSequenceSnapshot, Option<[u8; 16]>)>;

#[derive(Default)]
pub struct EphemeralPublisherSequenceStore {
    states: Mutex<EphemeralPublisherState>,
}

impl PublisherSequenceStore for EphemeralPublisherSequenceStore {
    fn load(&self, context_id: &[u8; 32]) -> Result<Option<PublisherSequenceSnapshot>, String> {
        let states = self.states.lock().map_err(|_| "state lock poisoned")?;
        match states.get(context_id) {
            Some((_, Some(_))) => Err("publisher continuity is ambiguous".to_owned()),
            Some((snapshot, None)) => Ok(Some(*snapshot)),
            None => Ok(None),
        }
    }

    fn reserve(
        &self,
        context_id: &[u8; 32],
        _initial_transcript_hash: &[u8; 32],
        reservation: &PublisherSequenceReservation,
    ) -> Result<(), String> {
        let mut states = self.states.lock().map_err(|_| "state lock poisoned")?;
        if let Some((current, token)) = states.get(context_id)
            && (*current != reservation.expected || token.is_some())
        {
            return Err("publisher state changed or is ambiguous".to_owned());
        }
        states.insert(
            *context_id,
            (reservation.resulting, Some(reservation.token)),
        );
        Ok(())
    }

    fn confirm(&self, context_id: &[u8; 32], token: &[u8; 16]) -> Result<(), String> {
        let mut states = self.states.lock().map_err(|_| "state lock poisoned")?;
        let (_, current) = states
            .get_mut(context_id)
            .ok_or_else(|| "publisher reservation is missing".to_owned())?;
        if current.as_ref() != Some(token) {
            return Err("publisher reservation is not current".to_owned());
        }
        *current = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::{
        EpochId, GroupId, MemberId, SecretBytes,
        agent_text_stream::{AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamKeyContextV1},
    };

    fn crypto(store: Arc<dyn PublisherSequenceStore>) -> AgentTextStreamCrypto {
        let stream_id = vec![0x22; 32];
        let start_event_id = MessageId::new(vec![0x44; 32]);
        AgentTextStreamCrypto::new(
            SecretBytes::new(vec![0x11; 32]),
            AgentTextStreamKeyContextV1::new(
                GroupId::new(vec![0x33; 16]),
                stream_id,
                EpochId(7),
                MemberId::new(vec![0x55; 32]),
                start_event_id,
            ),
        )
        .with_publisher_sequence_store(store)
    }

    #[test]
    fn repeated_session_use_continues_sequence_and_never_reuses_key_nonce() {
        let store = Arc::new(EphemeralPublisherSequenceStore::default());
        let crypto = crypto(store);
        let stream_id = crypto.context.stream_id.clone();
        let start = crypto.context.start_event_id.clone();
        let first = reserve_publisher_records(
            &crypto,
            &stream_id,
            &start,
            &[(AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"one".to_vec())],
        )
        .unwrap();
        let first_record = first.records[0].clone();
        first.confirm().unwrap();
        let second = reserve_publisher_records(
            &crypto,
            &stream_id,
            &start,
            &[(AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"two".to_vec())],
        )
        .unwrap();
        let second_record = second.records[0].clone();
        assert_eq!((first_record.seq, second_record.seq), (1, 2));
        assert_eq!(
            crate::derive_record_key(&crypto).unwrap(),
            crate::derive_record_key(&crypto).unwrap()
        );
        assert_ne!(
            crate::derive_record_nonce(&crypto, first_record.seq).unwrap(),
            crate::derive_record_nonce(&crypto, second_record.seq).unwrap()
        );
        second.confirm().unwrap();
    }

    #[test]
    fn unconfirmed_reservation_fails_closed_after_restart_boundary() {
        let store = Arc::new(EphemeralPublisherSequenceStore::default());
        let crypto = crypto(store);
        let stream_id = crypto.context.stream_id.clone();
        let start = crypto.context.start_event_id.clone();
        let _ambiguous = reserve_publisher_records(
            &crypto,
            &stream_id,
            &start,
            &[(AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"reserved".to_vec())],
        )
        .unwrap();
        assert!(matches!(
            reserve_publisher_records(
                &crypto,
                &stream_id,
                &start,
                &[(AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"retry".to_vec())],
            ),
            Err(QuicTextStreamError::PublisherSequence(_))
        ));
    }
}
