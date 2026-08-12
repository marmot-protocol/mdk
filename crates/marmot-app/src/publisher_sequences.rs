//! SQLCipher-backed QUIC preview publisher lifecycle state.

use storage_sqlite::{AgentStreamPublisherReservationRequest, SqliteAccountStorage};
use transport_quic_stream::{
    PublisherSequenceReservation, PublisherSequenceSnapshot, PublisherSequenceStore,
};

pub(crate) struct SqlitePublisherSequenceStore {
    storage: SqliteAccountStorage,
}

impl SqlitePublisherSequenceStore {
    pub(crate) fn new(storage: SqliteAccountStorage) -> Self {
        Self { storage }
    }
}

impl PublisherSequenceStore for SqlitePublisherSequenceStore {
    fn load(&self, context_id: &[u8; 32]) -> Result<Option<PublisherSequenceSnapshot>, String> {
        self.storage
            .agent_stream_publisher_state(context_id)
            .map_err(|err| err.to_string())?
            .map(|state| {
                if state.ambiguous {
                    return Err("publisher continuity is ambiguous".to_owned());
                }
                if state.next_seq == 0 {
                    return Err("publisher sequence state is corrupt".to_owned());
                }
                Ok(PublisherSequenceSnapshot {
                    next_seq: state.next_seq,
                    transcript_hash: state.transcript_hash,
                    chunk_count: state.chunk_count,
                })
            })
            .transpose()
    }

    fn reserve(
        &self,
        context_id: &[u8; 32],
        initial_transcript_hash: &[u8; 32],
        reservation: &PublisherSequenceReservation,
    ) -> Result<(), String> {
        let record_count = reservation
            .resulting
            .chunk_count
            .checked_sub(reservation.expected.chunk_count)
            .ok_or_else(|| "publisher transcript count regressed".to_owned())?;
        self.storage
            .reserve_agent_stream_publisher_records(AgentStreamPublisherReservationRequest {
                context_id,
                initial_transcript_hash,
                expected_transcript_hash: &reservation.expected.transcript_hash,
                expected_chunk_count: reservation.expected.chunk_count,
                resulting_transcript_hash: &reservation.resulting.transcript_hash,
                record_count,
                resulting_chunk_count: reservation.resulting.chunk_count,
                token: reservation.token,
            })
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    fn confirm(&self, context_id: &[u8; 32], token: &[u8; 16]) -> Result<(), String> {
        self.storage
            .confirm_agent_stream_publisher_reservation(context_id, token)
            .map_err(|err| err.to_string())
    }
}
