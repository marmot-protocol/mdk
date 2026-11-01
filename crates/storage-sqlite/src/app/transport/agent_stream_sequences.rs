//! Durable, fail-closed publisher sequence reservations for QUIC previews.

#[cfg(test)]
use crate::SqliteAccountStorage;
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, base::connection::retry_on_busy, unix_now_ms};
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

impl SqliteAppStorage {
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
                .query_row_cached(
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
                        tx.execute_cached(
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
                        .query_row_cached(
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
                    tx.execute_cached(
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
            tx.execute_cached(
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
                .execute_cached(
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
            .query_row_cached(
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

    const CONTEXT: [u8; 32] = [1; 32];
    const INITIAL: [u8; 32] = [2; 32];

    /// A reservation of `record_count` records on top of the transcript the
    /// publisher last saw (`expected`, `expected_chunk_count`).
    fn request<'a>(
        context: &'a [u8; 32],
        expected: &'a [u8; 32],
        expected_chunk_count: u64,
        resulting: &'a [u8; 32],
        record_count: u64,
        token: u8,
    ) -> AgentStreamPublisherReservationRequest<'a> {
        AgentStreamPublisherReservationRequest {
            context_id: context,
            initial_transcript_hash: &INITIAL,
            expected_transcript_hash: expected,
            expected_chunk_count,
            resulting_transcript_hash: resulting,
            record_count,
            resulting_chunk_count: expected_chunk_count + record_count,
            token: [token; 16],
        }
    }

    fn refusal<T: std::fmt::Debug>(result: StorageResult<T>) -> String {
        match result {
            Err(StorageError::Backend(message)) => message,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_reservation_advances_the_sequence_and_an_unconfirmed_one_fails_closed() {
        let storage = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let after = [3_u8; 32];
        let reserved = storage
            .reserve_agent_stream_publisher_records(request(&CONTEXT, &INITIAL, 0, &after, 2, 4))
            .unwrap();
        assert_eq!(reserved.first_seq, 1);
        assert_eq!(
            storage.agent_stream_publisher_state(&CONTEXT).unwrap(),
            Some(AgentStreamPublisherState {
                next_seq: 3,
                transcript_hash: after,
                chunk_count: 2,
                ambiguous: true,
            })
        );
        // The first reservation was never confirmed: its records may have
        // gone out, so the context is disabled for good.
        assert_eq!(
            refusal(storage.reserve_agent_stream_publisher_records(request(
                &CONTEXT, &after, 2, &[5; 32], 1, 6
            ))),
            "agent stream publisher continuity is ambiguous"
        );
        assert_eq!(
            refusal(storage.confirm_agent_stream_publisher_reservation(&CONTEXT, &reserved.token)),
            "agent stream publisher reservation is not current"
        );
    }

    #[test]
    fn confirmed_reservation_continues_at_next_sequence() {
        let storage = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let after_one = [3_u8; 32];
        let first = storage
            .reserve_agent_stream_publisher_records(request(
                &CONTEXT, &INITIAL, 0, &after_one, 1, 4,
            ))
            .unwrap();
        storage
            .confirm_agent_stream_publisher_reservation(&CONTEXT, &first.token)
            .unwrap();
        let second = storage
            .reserve_agent_stream_publisher_records(request(
                &CONTEXT, &after_one, 1, &[5; 32], 1, 6,
            ))
            .unwrap();
        assert_eq!(second.first_seq, 2);
    }

    /// Each row is corrupt in one way only, so each guard clause is the one
    /// that refuses it.
    #[test]
    fn corrupt_publisher_state_fails_closed() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let rows: [(u8, i64, &[u8], i64); 3] = [
            (1, 0, &[3; 32], 0),
            (2, 1, &[3; 31], 0),
            (3, 1, &[3; 32], -1),
        ];
        let raw_row = |context: &[u8; 32]| {
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT next_seq, transcript_hash, chunk_count, reservation_token, disabled
                     FROM agent_stream_publisher_sequences WHERE context_id = ?1",
                    params![context.as_slice()],
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
                .unwrap()
        };
        for (context, next_seq, hash, chunks) in rows {
            let context = [context; 32];
            let connection = store.lock().unwrap();
            connection
                .execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
            connection
                .execute(
                    "INSERT INTO agent_stream_publisher_sequences (
                        context_id, next_seq, transcript_hash, chunk_count,
                        reservation_token, disabled, updated_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, NULL, 0, 0)",
                    params![context.as_slice(), next_seq, hash, chunks],
                )
                .unwrap();
            connection
                .execute_batch("PRAGMA ignore_check_constraints = OFF;")
                .unwrap();
            drop(connection);
            let before = raw_row(&context);

            // The request matches the stored transcript, so only the
            // corruption can refuse it; it must never fall back to seq 1.
            let stored: [u8; 32] = [3; 32];
            let chunks = chunks.max(0) as u64;
            assert_eq!(
                refusal(
                    store
                        .app_storage()
                        .reserve_agent_stream_publisher_records(request(
                            &context, &stored, chunks, &[4; 32], 1, 5
                        ))
                ),
                "agent stream publisher state is corrupt",
                "row {before:?}"
            );
            assert_eq!(raw_row(&context), before);
        }
    }
}
