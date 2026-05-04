//! `MockPeeler` — a pass-through peeler that wraps `EncryptedPayload`
//! verbatim into `TransportMessage` and back. Real crypto would obscure
//! payloads from the harness; we want assertable inner bytes.
//!
//! Transport ids and timestamps are assigned from a per-client deterministic
//! sequence so vector traces do not inherit OpenMLS key/signature randomness.

use async_trait::async_trait;
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct MockPeeler {
    owner: Vec<u8>,
    next_sequence: AtomicU64,
}

impl MockPeeler {
    pub fn new(owner: impl Into<Vec<u8>>) -> Self {
        Self {
            owner: owner.into(),
            next_sequence: AtomicU64::new(0),
        }
    }

    fn next_transport_id(&self, kind: &[u8], extras: &[&[u8]]) -> (MessageId, Timestamp) {
        let sequence = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        let sequence_bytes = sequence.to_be_bytes();
        let mut parts = vec![kind, self.owner.as_slice(), sequence_bytes.as_slice()];
        parts.extend_from_slice(extras);
        (hash_id(&parts), Timestamp(sequence))
    }
}

impl Default for MockPeeler {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

fn hash_id(parts: &[&[u8]]) -> MessageId {
    let mut h = 0xcbf29ce484222325u64;
    for part in parts {
        for b in *part {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    MessageId::new(h.to_be_bytes().to_vec())
}

#[async_trait]
impl TransportPeeler for MockPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::Welcome {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        let (id, timestamp) = self.next_transport_id(b"group", &[]);
        Ok(TransportMessage {
            id,
            payload: payload.ciphertext.clone(),
            timestamp,
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        let (id, timestamp) = self.next_transport_id(b"welcome", &[recipient.as_slice()]);
        Ok(TransportMessage {
            id,
            payload: payload.ciphertext.clone(),
            timestamp,
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}
