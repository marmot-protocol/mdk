//! Durable, fail-closed publisher sequence reservations for QUIC previews.

use crate::{SqliteAccountStorage, SqliteResultExt, connection::retry_on_busy, unix_now_ms};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

/// Hard bound for durable start contexts in one account-device database.
/// Once reached, an unseen context fails closed instead of evicting a nonce
/// tombstone that could later permit sequence reuse.
pub const MAX_AGENT_STREAM_PUBLISHER_CONTEXTS: u64 = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentStreamPublisherReservation {
    pub first_seq: u64,
    pub token: [u8; 16],
}

pub struct AgentStreamPublisherReservationRequest<'a> {
    pub context_id: &'a [u8; 32],
    pub initial_transcript_hash: &'a [u8; 32],
    pub expected_transcript_hash: &'a [u8; 32],
    pub expected_chunk_count: u64,
    pub resulting_transcript_hash: &'a [u8; 32],
    pub record_count: u64,
    pub resulting_chunk_count: u64,
    pub token: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentStreamPublisherState {
    pub next_seq: u64,
    pub transcript_hash: [u8; 32],
    pub chunk_count: u64,
    pub ambiguous: bool,
}

impl SqliteAccountStorage {
    /// Atomically advance the next-unused sequence and transcript before any
    /// external record write. A surviving reservation token after a crash is
    /// intentionally ambiguous and permanently disables that preview.
    pub fn reserve_agent_stream_publisher_records(
        &self,
        request: AgentStreamPublisherReservationRequest<'_>,
    ) -> StorageResult<AgentStreamPublisherReservation> {
        if request.record_count == 0 {
            return Err(StorageError::Backend(
                "agent stream reservation cannot be empty".to_owned(),
            ));
        }
        retry_on_busy(|| {
            let mut conn = self.connection.lock()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            let row = tx
                .query_row(
                    "SELECT next_seq, transcript_hash, chunk_count,
                            reservation_token, disabled
                     FROM agent_stream_publisher_sequences
                     WHERE context_id = ?1",
                    params![request.context_id.as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Option<Vec<u8>>>(3)?,
                            row.get::<_, bool>(4)?,
                        ))
                    },
                )
                .optional()
                .storage()?;

            let (first_seq, current_hash, current_chunks) = match row {
                Some((next_seq, transcript_hash, chunk_count, reservation, disabled)) => {
                    if disabled || reservation.is_some() {
                        tx.execute(
                            "UPDATE agent_stream_publisher_sequences
                             SET disabled = 1, updated_at_ms = ?2
                             WHERE context_id = ?1",
                            params![request.context_id.as_slice(), unix_now_ms()],
                        )
                        .storage()?;
                        tx.commit().storage()?;
                        return Err(StorageError::Backend(
                            "agent stream publisher continuity is ambiguous".to_owned(),
                        ));
                    }
                    if transcript_hash.len() != 32 || chunk_count < 0 || next_seq < 1 {
                        return Err(StorageError::Backend(
                            "agent stream publisher state is corrupt".to_owned(),
                        ));
                    }
                    let current_hash: [u8; 32] = transcript_hash.try_into().map_err(|_| {
                        StorageError::Backend(
                            "agent stream publisher transcript is corrupt".to_owned(),
                        )
                    })?;
                    (
                        u64::try_from(next_seq).map_err(|_| {
                            StorageError::Backend(
                                "agent stream publisher sequence is corrupt".to_owned(),
                            )
                        })?,
                        current_hash,
                        u64::try_from(chunk_count).map_err(|_| {
                            StorageError::Backend(
                                "agent stream publisher chunk count is corrupt".to_owned(),
                            )
                        })?,
                    )
                }
                None => {
                    let count = tx
                        .query_row(
                            "SELECT count(*) FROM agent_stream_publisher_sequences",
                            [],
                            |row| row.get::<_, i64>(0),
                        )
                        .storage()?;
                    if u64::try_from(count).unwrap_or(u64::MAX)
                        >= MAX_AGENT_STREAM_PUBLISHER_CONTEXTS
                    {
                        return Err(StorageError::Backend(
                            "agent stream publisher state limit reached".to_owned(),
                        ));
                    }
                    tx.execute(
                        "INSERT INTO agent_stream_publisher_sequences (
                            context_id, next_seq, transcript_hash, chunk_count,
                            reservation_token, disabled, updated_at_ms
                         ) VALUES (?1, 1, ?2, 0, NULL, 0, ?3)",
                        params![
                            request.context_id.as_slice(),
                            request.initial_transcript_hash.as_slice(),
                            unix_now_ms()
                        ],
                    )
                    .storage()?;
                    (1, *request.initial_transcript_hash, 0)
                }
            };
            if current_hash != *request.expected_transcript_hash
                || current_chunks != request.expected_chunk_count
            {
                return Err(StorageError::Backend(
                    "agent stream publisher state changed concurrently".to_owned(),
                ));
            }
            if request.resulting_chunk_count != current_chunks.saturating_add(request.record_count)
            {
                return Err(StorageError::Backend(
                    "agent stream transcript count does not match reservation".to_owned(),
                ));
            }
            let next_seq = first_seq.checked_add(request.record_count).ok_or_else(|| {
                StorageError::Backend("agent stream publisher sequence exhausted".to_owned())
            })?;
            tx.execute(
                "UPDATE agent_stream_publisher_sequences
                 SET next_seq = ?2, transcript_hash = ?3, chunk_count = ?4,
                     reservation_token = ?5, updated_at_ms = ?6
                 WHERE context_id = ?1",
                params![
                    request.context_id.as_slice(),
                    i64::try_from(next_seq).map_err(|_| StorageError::Backend(
                        "agent stream publisher sequence exhausted".to_owned()
                    ))?,
                    request.resulting_transcript_hash.as_slice(),
                    i64::try_from(request.resulting_chunk_count).map_err(|_| {
                        StorageError::Backend(
                            "agent stream publisher chunk count exhausted".to_owned(),
                        )
                    })?,
                    request.token.as_slice(),
                    unix_now_ms(),
                ],
            )
            .storage()?;
            tx.commit().storage()?;
            Ok(AgentStreamPublisherReservation {
                first_seq,
                token: request.token,
            })
        })
    }

    pub fn confirm_agent_stream_publisher_reservation(
        &self,
        context_id: &[u8; 32],
        token: &[u8; 16],
    ) -> StorageResult<()> {
        retry_on_busy(|| {
            let changed = self
                .connection
                .lock()?
                .execute(
                    "UPDATE agent_stream_publisher_sequences
             SET reservation_token = NULL, updated_at_ms = ?3
             WHERE context_id = ?1 AND reservation_token = ?2 AND disabled = 0",
                    params![context_id.as_slice(), token.as_slice(), unix_now_ms()],
                )
                .storage()?;
            if changed != 1 {
                return Err(StorageError::Backend(
                    "agent stream publisher reservation is not current".to_owned(),
                ));
            }
            Ok(())
        })
    }

    pub fn agent_stream_publisher_state(
        &self,
        context_id: &[u8; 32],
    ) -> StorageResult<Option<AgentStreamPublisherState>> {
        self.connection
            .lock()?
            .query_row(
                "SELECT next_seq, transcript_hash, chunk_count,
                        reservation_token IS NOT NULL OR disabled
                 FROM agent_stream_publisher_sequences
                 WHERE context_id = ?1",
                params![context_id.as_slice()],
                |row| {
                    let next_seq = row.get::<_, i64>(0)?;
                    let hash = row.get::<_, Vec<u8>>(1)?;
                    let chunks = row.get::<_, i64>(2)?;
                    let ambiguous = row.get::<_, bool>(3)?;
                    let hash: [u8; 32] = hash.try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            1,
                            "transcript_hash".to_owned(),
                            rusqlite::types::Type::Blob,
                        )
                    })?;
                    Ok(AgentStreamPublisherState {
                        next_seq: u64::try_from(next_seq).unwrap_or_default(),
                        transcript_hash: hash,
                        chunk_count: u64::try_from(chunks).unwrap_or_default(),
                        ambiguous,
                    })
                },
            )
            .optional()
            .storage()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_is_durable_monotonic_and_fail_closed_when_ambiguous() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let context = [1_u8; 32];
        let initial = [2_u8; 32];
        let after = [3_u8; 32];
        let token = [4_u8; 16];

        let reserved = storage
            .reserve_agent_stream_publisher_records(AgentStreamPublisherReservationRequest {
                context_id: &context,
                initial_transcript_hash: &initial,
                expected_transcript_hash: &initial,
                expected_chunk_count: 0,
                resulting_transcript_hash: &after,
                record_count: 2,
                resulting_chunk_count: 2,
                token,
            })
            .unwrap();
        assert_eq!(reserved.first_seq, 1);
        assert_eq!(
            storage.agent_stream_publisher_state(&context).unwrap(),
            Some(AgentStreamPublisherState {
                next_seq: 3,
                transcript_hash: after,
                chunk_count: 2,
                ambiguous: true,
            })
        );
        assert!(
            storage
                .reserve_agent_stream_publisher_records(AgentStreamPublisherReservationRequest {
                    context_id: &context,
                    initial_transcript_hash: &initial,
                    expected_transcript_hash: &after,
                    expected_chunk_count: 2,
                    resulting_transcript_hash: &[5; 32],
                    record_count: 1,
                    resulting_chunk_count: 3,
                    token: [6; 16],
                })
                .is_err()
        );
        assert!(
            storage
                .confirm_agent_stream_publisher_reservation(&context, &token)
                .is_err()
        );
    }

    #[test]
    fn confirmed_reservation_continues_at_next_sequence() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let context = [1_u8; 32];
        let initial = [2_u8; 32];
        let after_one = [3_u8; 32];
        let first = storage
            .reserve_agent_stream_publisher_records(AgentStreamPublisherReservationRequest {
                context_id: &context,
                initial_transcript_hash: &initial,
                expected_transcript_hash: &initial,
                expected_chunk_count: 0,
                resulting_transcript_hash: &after_one,
                record_count: 1,
                resulting_chunk_count: 1,
                token: [4; 16],
            })
            .unwrap();
        storage
            .confirm_agent_stream_publisher_reservation(&context, &first.token)
            .unwrap();
        let second = storage
            .reserve_agent_stream_publisher_records(AgentStreamPublisherReservationRequest {
                context_id: &context,
                initial_transcript_hash: &initial,
                expected_transcript_hash: &after_one,
                expected_chunk_count: 1,
                resulting_transcript_hash: &[5; 32],
                record_count: 1,
                resulting_chunk_count: 2,
                token: [6; 16],
            })
            .unwrap();
        assert_eq!(second.first_seq, 2);
    }

    #[test]
    fn corrupt_publisher_state_fails_closed() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let context = [1_u8; 32];
        let connection = storage.connection.lock().unwrap();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        connection
            .execute(
                "INSERT INTO agent_stream_publisher_sequences (
                    context_id, next_seq, transcript_hash, chunk_count,
                    reservation_token, disabled, updated_at_ms
                 ) VALUES (?1, 0, ?2, 0, NULL, 0, 0)",
                params![context.as_slice(), [2_u8; 31].as_slice()],
            )
            .unwrap();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = OFF;")
            .unwrap();
        drop(connection);

        assert!(
            storage
                .reserve_agent_stream_publisher_records(AgentStreamPublisherReservationRequest {
                    context_id: &context,
                    initial_transcript_hash: &[3; 32],
                    expected_transcript_hash: &[3; 32],
                    expected_chunk_count: 0,
                    resulting_transcript_hash: &[4; 32],
                    record_count: 1,
                    resulting_chunk_count: 1,
                    token: [5; 16],
                })
                .is_err(),
            "a corrupt sequence/hash row must never fall back to seq=1"
        );
    }
}
