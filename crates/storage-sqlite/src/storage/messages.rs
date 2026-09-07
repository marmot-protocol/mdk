use super::snapshots;
use crate::connection::CachedSql;
use crate::connection::retry_on_busy;
use crate::{
    SqliteAccountStorage, SqliteResultExt, deserialize, epoch_to_i64, i64_to_u64,
    message_state_from_i64, message_state_to_i64, serialize, unix_now_seconds_i64,
};
use cgka_traits::engine::GroupEvent;
use cgka_traits::message::{
    DeferredMessageMetadata, DeferredPeelLifecycle, MessageRecord, MessageState,
};
use cgka_traits::storage::{GroupStateCheckpointRef, MessageStorage, StorageError, StorageResult};
use cgka_traits::types::{EpochId, GroupId, MessageId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

const INGRESS_DEDUP_MARKER_CAPACITY: i64 = 4_096;
const RELEASED_TRANSPORT_RECEIPT_CAPACITY: i64 = 8_192;
const NORMALIZED_MESSAGE_STORAGE_FORMAT: i64 = 2;
const MESSAGE_FORMAT_PROMOTION_BATCH_MAX: usize = 256;

const MESSAGE_COLUMNS: &str =
    "id, group_id, epoch, state, storage_format, record, payload, deferred_peel";

type MessageColumns = (
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageFormatPromotionProgress {
    pub promoted: usize,
    pub has_more: bool,
}

/// Logical blob/value sizes used by the storage-format benchmark rail.
///
/// This excludes SQLite page overhead; the startup-scaling harness reports
/// the complete database-file footprint separately.
#[cfg(feature = "storage-format-benchmarks")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageFormatBenchSizes {
    pub message_value_bytes: u64,
    pub largest_snapshot_bytes: u64,
}

impl SqliteAccountStorage {
    /// Retire stale host receipts and durably arm backfill before acknowledging
    /// release evidence. The caller must remove returned ids from its in-memory
    /// seen ring synchronously, before its next checkpoint or duplicate check.
    /// A process death after commit is safe: both disk receipt stores are already
    /// clean and backfill intent survives. An interrupted engine effects batch
    /// needs no special handling because the release journal is authoritative.
    pub fn consume_released_transport_receipts(&self) -> StorageResult<Vec<MessageId>> {
        // Avoid a write transaction on the ordinary no-release hot path.
        if !self
            .lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM cgka_released_transport_receipts)",
                [],
                |row| row.get::<_, bool>(0),
            )
            .storage()?
        {
            return Ok(Vec::new());
        }
        let consume = || {
            let conn = self.lock()?;
            let ids = conn
                .prepare_cached("SELECT id FROM cgka_released_transport_receipts ORDER BY id")
                .storage()?
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?;
            for id in &ids {
                retire_transport_receipts(&conn, &MessageId::new(id.clone()))?;
            }
            conn.execute_cached(
                "INSERT INTO app_epoch_backfill_intents(group_id, stalled_epoch, updated_at)
                 SELECT group_id, MAX(epoch), ?1 FROM cgka_released_transport_receipts
                 GROUP BY group_id
                 ON CONFLICT(group_id) DO UPDATE SET
                    stalled_epoch = MAX(app_epoch_backfill_intents.stalled_epoch, excluded.stalled_epoch),
                    updated_at = excluded.updated_at",
                params![unix_now_seconds_i64()],
            ).storage()?;
            conn.execute_cached("DELETE FROM cgka_released_transport_receipts", [])
                .storage()?;
            Ok(ids.into_iter().map(MessageId::new).collect())
        };
        retry_on_busy(|| self.connection.with_transaction(consume))
    }

    /// Read aggregate value sizes without returning any stored content.
    #[cfg(feature = "storage-format-benchmarks")]
    pub fn storage_format_bench_sizes(
        &self,
        group_id: &GroupId,
        message_id: &MessageId,
    ) -> StorageResult<StorageFormatBenchSizes> {
        let conn = self.lock()?;
        let message_value_bytes = conn
            .query_row_cached(
                "SELECT length(id) + length(group_id) + coalesce(length(payload), 0) +
                        coalesce(length(record), 0) + coalesce(length(deferred_peel), 0)
                 FROM cgka_messages WHERE id = ?1",
                params![message_id.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .storage()?
            .ok_or(StorageError::NotFound)?;
        let largest_snapshot_bytes = conn
            .query_row_cached(
                "SELECT max(length(snapshot)) FROM cgka_group_snapshots WHERE group_id = ?1",
                params![group_id.as_slice()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .storage()?
            .ok_or_else(|| StorageError::SnapshotMissing("benchmark-size-anchor".into()))?;
        Ok(StorageFormatBenchSizes {
            message_value_bytes: u64::try_from(message_value_bytes).map_err(|error| {
                StorageError::Backend(format!("invalid message benchmark size: {error}"))
            })?,
            largest_snapshot_bytes: u64::try_from(largest_snapshot_bytes).map_err(|error| {
                StorageError::Backend(format!("invalid snapshot benchmark size: {error}"))
            })?,
        })
    }

    /// Promote at most `limit` legacy message rows to normalized format 2.
    ///
    /// The bounded batch is atomic and idempotent. A malformed row rolls the
    /// whole batch back, so a caller never observes a skipped or half-promoted
    /// prefix. Hosts may schedule repeated batches away from session-open
    /// latency; this method emits no identifiers or payload data.
    pub fn promote_legacy_message_rows(
        &self,
        limit: usize,
    ) -> StorageResult<MessageFormatPromotionProgress> {
        if limit == 0 || limit > MESSAGE_FORMAT_PROMOTION_BATCH_MAX {
            return Err(StorageError::Backend(format!(
                "message format promotion batch must be between 1 and {MESSAGE_FORMAT_PROMOTION_BATCH_MAX}"
            )));
        }
        retry_on_busy(|| {
            let mut conn = self.lock()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            let rows = {
                let mut statement = tx
                    .prepare_cached(&format!(
                        "SELECT {MESSAGE_COLUMNS} FROM cgka_messages
                         WHERE storage_format = 1
                         ORDER BY insert_order
                         LIMIT ?1"
                    ))
                    .storage()?;
                statement
                    .query_map(
                        params![i64::try_from(limit).unwrap_or(i64::MAX)],
                        message_columns,
                    )
                    .storage()?
                    .collect::<Result<Vec<_>, _>>()
                    .storage()?
            };
            let promoted = rows.len();
            #[cfg(test)]
            let mut promoted_so_far = 0;
            for columns in rows {
                let record = decode_message_columns(columns)?;
                put_message_on_connection(&tx, None, &record)?;
                #[cfg(test)]
                {
                    promoted_so_far += 1;
                    promotion_crash_pause(promoted_so_far);
                }
            }
            let has_more = tx
                .query_row_cached(
                    "SELECT EXISTS(
                        SELECT 1 FROM cgka_messages WHERE storage_format = 1
                     )",
                    [],
                    |row| row.get(0),
                )
                .storage()?;
            tx.commit().storage()?;
            Ok(MessageFormatPromotionProgress { promoted, has_more })
        })
    }
}

#[cfg(test)]
fn promotion_crash_pause(promoted: usize) {
    let expected = promoted.to_string();
    if std::env::var("MDK_STORAGE_TEST_PROMOTION_CRASH_AFTER").as_deref() != Ok(expected.as_str()) {
        return;
    }
    let ready = std::env::var_os("MDK_STORAGE_TEST_CRASH_READY_FILE")
        .expect("promotion crash ready-file path");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(ready)
        .expect("create promotion crash ready file");
    loop {
        std::thread::park();
    }
}

impl MessageStorage for SqliteAccountStorage {
    fn put_message(&self, record: &MessageRecord) -> StorageResult<()> {
        let write = || {
            let conn = self.lock()?;
            put_message_on_connection(&conn, None, record)
        };
        if self.connection.is_current_thread_transaction_owner() {
            write()
        } else {
            // Single autocommit statement: safe to retry as a complete unit on
            // transient lock contention (issue #484).
            retry_on_busy(write)
        }
    }

    fn get_message(&self, id: &MessageId) -> StorageResult<MessageRecord> {
        let columns = self
            .lock()?
            .query_row_cached(
                &format!("SELECT {MESSAGE_COLUMNS} FROM cgka_messages WHERE id = ?1"),
                params![id.as_slice()],
                message_columns,
            )
            .optional()
            .storage()?
            .ok_or(StorageError::NotFound)?;
        decode_message_columns(columns)
    }

    fn delete_message(&self, id: &MessageId) -> StorageResult<()> {
        if self.connection.is_current_thread_transaction_owner() {
            let conn = self.lock()?;
            delete_message_on_connection(&conn, id)
        } else {
            retry_on_busy(|| {
                let mut conn = self.lock()?;
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .storage()?;
                delete_message_on_connection(&tx, id)?;
                tx.commit().storage()?;
                Ok(())
            })
        }
    }

    fn release_message_for_replay(&self, record: &MessageRecord) -> StorageResult<()> {
        let release = || {
            let conn = self.lock()?;
            // App ownership is durable before engine hydration. It must not
            // depend on individual receipts: the app's active seen ring may
            // not have checkpointed yet, and inventory writes are best-effort.
            // A standalone engine has no app consumer and needs only deletion.
            if !conn
                .query_row_cached("SELECT EXISTS(SELECT 1 FROM account_state)", [], |row| {
                    row.get::<_, bool>(0)
                })
                .storage()?
            {
                return delete_message_on_connection(&conn, &record.id);
            }
            // Bound journal metadata even if a host never consumes it. At the
            // bound, fail before deleting bytes; never evict replay evidence.
            let recorded = conn
                .execute_cached(
                    "INSERT INTO cgka_released_transport_receipts(id, group_id, epoch)
                 SELECT ?1, ?2, ?3 WHERE
                    (SELECT count(*) FROM cgka_released_transport_receipts) < ?4
                    OR EXISTS(SELECT 1 FROM cgka_released_transport_receipts WHERE id = ?1)
                 ON CONFLICT(id) DO UPDATE SET epoch = excluded.epoch",
                    params![
                        record.id.as_slice(),
                        record.group_id.as_slice(),
                        epoch_to_i64(record.epoch)?,
                        RELEASED_TRANSPORT_RECEIPT_CAPACITY
                    ],
                )
                .storage()?;
            if recorded == 0 {
                return Err(StorageError::Backend(
                    "released transport receipt journal is full".into(),
                ));
            }
            retire_transport_receipts(&conn, &record.id)?;
            delete_message_on_connection(&conn, &record.id)
        };
        if self.connection.is_current_thread_transaction_owner() {
            release()
        } else {
            retry_on_busy(|| self.connection.with_transaction(release))
        }
    }

    fn update_message_state(&self, id: &MessageId, new_state: MessageState) -> StorageResult<()> {
        // #424: when this runs inside an engine `with_transaction` (convergence
        // apply path), the outer SQL transaction is already open and owns
        // commit/rollback, so we must not start a nested one. Mirror the
        // openmls value-store pattern: operate directly on the locked
        // connection when we're the transaction owner, otherwise wrap our own.
        if self.connection.is_current_thread_transaction_owner() {
            let conn = self.lock()?;
            update_message_state_on_connection(&conn, id, new_state)
        } else {
            // #484: own a fresh transaction here, so retry the whole
            // read-modify-write on transient lock contention. SQLite rolls the
            // transaction back on SQLITE_BUSY, so re-running from BEGIN is safe
            // and idempotent.
            retry_on_busy(|| {
                let mut conn = self.lock()?;
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .storage()?;
                update_message_state_on_connection(&tx, id, new_state)?;
                tx.commit().storage()?;
                Ok(())
            })
        }
    }

    fn list_messages(
        &self,
        group_id: &GroupId,
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>> {
        let conn = self.lock()?;
        list_messages_on_connection(&conn, group_id, at_or_after_epoch, None)
    }

    fn has_messages_in_states(
        &self,
        group_id: &GroupId,
        states: &[MessageState],
        at_or_after_epoch: EpochId,
    ) -> StorageResult<bool> {
        if states.is_empty() {
            return Ok(false);
        }
        let sql = format!(
            "SELECT EXISTS(
                SELECT 1 FROM cgka_messages
                WHERE group_id = ?1 AND epoch >= ?2 AND state IN ({})
             )",
            state_placeholders(states)
        );
        let conn = self.lock()?;
        conn.query_row_cached(
            &sql,
            rusqlite::params_from_iter(state_query_params(group_id, at_or_after_epoch, states)?),
            |row| row.get(0),
        )
        .storage()
    }

    fn list_deferred_message_metadata(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<DeferredMessageMetadata>> {
        let conn = self.lock()?;
        // length(BLOB) reads its size without copying it into Rust. Legacy
        // format 1 has no independent metadata, so only those rows need the
        // record blob; they promote through the existing bounded migration.
        let mut stmt = conn
            .prepare_cached(
                "SELECT id, group_id, epoch, storage_format,
                    CASE WHEN storage_format = 1 THEN record END,
                    CASE WHEN typeof(payload) = 'blob' THEN length(payload) END,
                    deferred_peel
             FROM cgka_messages WHERE group_id = ?1 AND state = ?2 AND epoch >= 0
             ORDER BY insert_order",
            )
            .storage()?;
        let rows = stmt
            .query_map(
                params![
                    group_id.as_slice(),
                    message_state_to_i64(MessageState::PeelDeferred)
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?,
                    ))
                },
            )
            .storage()?;
        rows.map(|row| {
            let (id, group_id, epoch, format, record, payload_len, lifecycle) = row.storage()?;
            match format {
                1 => {
                    let record = record.ok_or_else(|| {
                        StorageError::Serialization(
                            "legacy message row is missing its record blob".into(),
                        )
                    })?;
                    Ok(DeferredMessageMetadata::from(deserialize::<MessageRecord>(
                        &record,
                    )?))
                }
                NORMALIZED_MESSAGE_STORAGE_FORMAT => Ok(DeferredMessageMetadata {
                    id: MessageId::new(id),
                    group_id: GroupId::new(group_id),
                    epoch: EpochId(i64_to_u64(epoch)?),
                    payload_len: usize::try_from(payload_len.ok_or_else(|| {
                        StorageError::Serialization(
                            "normalized message row is missing its payload blob".into(),
                        )
                    })?)
                    .map_err(|_| {
                        StorageError::Serialization("invalid deferred payload length".into())
                    })?,
                    deferred_peel: lifecycle
                        .as_deref()
                        .map(deserialize::<DeferredPeelLifecycle>)
                        .transpose()?,
                }),
                version => Err(StorageError::Serialization(format!(
                    "unsupported message storage format {version}"
                ))),
            }
        })
        .collect()
    }

    fn list_messages_in_states(
        &self,
        group_id: &GroupId,
        states: &[MessageState],
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>> {
        if states.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {MESSAGE_COLUMNS} FROM cgka_messages
             WHERE group_id = ?1 AND epoch >= ?2 AND state IN ({})
             ORDER BY insert_order",
            state_placeholders(states)
        );
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(&sql).storage()?;
        let records = stmt
            .query_map(
                rusqlite::params_from_iter(state_query_params(
                    group_id,
                    at_or_after_epoch,
                    states,
                )?),
                message_columns,
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        records.into_iter().map(decode_message_columns).collect()
    }

    fn put_pending_application_event(&self, event: &GroupEvent) -> StorageResult<()> {
        let (group_id, message_id) = match event {
            GroupEvent::MessageReceived {
                group_id,
                message_id,
                ..
            } => (group_id, message_id),
            GroupEvent::GroupJoined {
                group_id,
                via_welcome,
                ..
            } => (group_id, via_welcome),
            _ => {
                return Err(StorageError::Backend(
                    "pending application outbox accepts only MessageReceived and GroupJoined events"
                        .to_owned(),
                ));
            }
        };
        let record = serialize(event)?;
        let write = || {
            let conn = self.lock()?;
            let inserted = conn
                .execute_cached(
                    "INSERT INTO pending_application_events (
                        message_id, group_id, message_insert_order, record
                     )
                     SELECT ?1, ?2, insert_order, ?3
                     FROM cgka_messages
                     WHERE id = ?1 AND group_id = ?2
                     ON CONFLICT(message_id) DO NOTHING",
                    params![message_id.as_slice(), group_id.as_slice(), &record],
                )
                .storage()?;
            if inserted == 0 {
                let existing = conn
                    .query_row_cached(
                        "SELECT record FROM pending_application_events WHERE message_id = ?1",
                        params![message_id.as_slice()],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
                    .storage()?;
                return match existing {
                    Some(existing) if existing == record => Ok(()),
                    Some(_) => Err(StorageError::Backend(
                        "pending application event id reused with different content".to_owned(),
                    )),
                    None => Err(StorageError::NotFound),
                };
            }
            Ok(())
        };
        if self.connection.is_current_thread_transaction_owner() {
            write()
        } else {
            retry_on_busy(write)
        }
    }

    fn list_pending_application_events(&self) -> StorageResult<Vec<GroupEvent>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare_cached(
                "SELECT record
                 FROM pending_application_events
                 ORDER BY message_insert_order, message_id",
            )
            .storage()?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.iter().map(|event| deserialize(event)).collect()
    }

    fn delete_pending_application_events(&self, ids: &[MessageId]) -> StorageResult<()> {
        let delete = || {
            let conn = self.lock()?;
            for id in ids {
                conn.execute_cached(
                    "DELETE FROM pending_application_events WHERE message_id = ?1",
                    params![id.as_slice()],
                )
                .storage()?;
            }
            Ok(())
        };
        if self.connection.is_current_thread_transaction_owner() {
            delete()
        } else {
            retry_on_busy(|| self.connection.with_transaction(delete))
        }
    }

    fn create_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint: &GroupStateCheckpointRef,
    ) -> StorageResult<()> {
        snapshots::create_group_state_checkpoint(self, group_id, checkpoint)
    }

    fn restore_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint_id: &str,
    ) -> StorageResult<()> {
        snapshots::restore_group_state_checkpoint(self, group_id, checkpoint_id)
    }

    fn list_group_state_checkpoints(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<GroupStateCheckpointRef>> {
        snapshots::list_group_state_checkpoints(self, group_id)
    }

    fn release_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint_id: &str,
    ) -> StorageResult<()> {
        snapshots::release_group_state_checkpoint(self, group_id, checkpoint_id)
    }

    fn put_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<()> {
        retry_on_busy(|| {
            self.connection.with_transaction(|| {
                let conn = self.lock()?;
                conn.execute_cached(
                    "INSERT OR IGNORE INTO cgka_ingress_dedup (id) VALUES (?1)",
                    params![id.as_slice()],
                )
                .storage()?;
                conn.execute_cached(
                    "DELETE FROM cgka_ingress_dedup
                     WHERE insert_order <= (
                        SELECT insert_order FROM cgka_ingress_dedup
                        ORDER BY insert_order DESC LIMIT 1 OFFSET ?1
                     )",
                    params![INGRESS_DEDUP_MARKER_CAPACITY],
                )
                .storage()?;
                Ok(())
            })
        })
    }

    fn has_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM cgka_ingress_dedup WHERE id = ?1)",
                params![id.as_slice()],
                |row| row.get(0),
            )
            .storage()
    }

    fn put_processed_transport_id(
        &self,
        group_id: &GroupId,
        transport_id: &MessageId,
    ) -> StorageResult<()> {
        let write = || {
            let conn = self.lock()?;
            put_processed_transport_id_on_connection(&conn, group_id, transport_id)
        };
        if self.connection.is_current_thread_transaction_owner() {
            write()
        } else {
            retry_on_busy(write)
        }
    }

    fn has_processed_transport_id(&self, transport_id: &MessageId) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT EXISTS(
                    SELECT 1 FROM cgka_processed_transport_ids WHERE id = ?1
                 )",
                params![transport_id.as_slice()],
                |row| row.get(0),
            )
            .storage()
    }

    fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        snapshots::create(self, group_id, name)
    }

    fn create_group_state_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        snapshots::create_state_scoped(self, group_id, name)
    }

    fn list_group_snapshots(&self, group_id: &GroupId) -> StorageResult<Vec<String>> {
        snapshots::list(self, group_id)
    }

    fn rollback_group_to_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        snapshots::rollback(self, group_id, name)
    }

    fn rollback_group_state_to_snapshot(
        &self,
        group_id: &GroupId,
        name: &str,
    ) -> StorageResult<()> {
        snapshots::rollback_group_state(self, group_id, name)
    }

    fn release_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        snapshots::release(self, group_id, name)
    }
}

#[cfg(test)]
thread_local! {
    static FULL_MESSAGE_READS: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

fn message_columns(row: &rusqlite::Row<'_>) -> rusqlite::Result<MessageColumns> {
    let columns: MessageColumns = (
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    );
    #[cfg(test)]
    FULL_MESSAGE_READS.with(|stats| {
        let (rows, bytes) = stats.get();
        stats.set((
            rows + 1,
            bytes + columns.5.as_ref().map_or(0, Vec::len) + columns.6.as_ref().map_or(0, Vec::len),
        ));
    });
    Ok(columns)
}

fn decode_message_columns(columns: MessageColumns) -> StorageResult<MessageRecord> {
    let (id, group_id, epoch, state, storage_format, record, payload, deferred_peel) = columns;
    match storage_format {
        1 => deserialize(record.as_deref().ok_or_else(|| {
            StorageError::Serialization("legacy message row is missing its record blob".to_owned())
        })?),
        NORMALIZED_MESSAGE_STORAGE_FORMAT => Ok(MessageRecord {
            id: MessageId::new(id),
            group_id: GroupId::new(group_id),
            epoch: EpochId(i64_to_u64(epoch)?),
            state: message_state_from_i64(state)?,
            payload: payload.ok_or_else(|| {
                StorageError::Serialization(
                    "normalized message row is missing its payload blob".to_owned(),
                )
            })?,
            deferred_peel: deferred_peel
                .as_deref()
                .map(deserialize::<DeferredPeelLifecycle>)
                .transpose()?,
        }),
        version => Err(StorageError::Serialization(format!(
            "unsupported message storage format {version}"
        ))),
    }
}

fn list_messages_on_connection(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    at_or_after_epoch: EpochId,
    include_insert_order: Option<&mut Vec<i64>>,
) -> StorageResult<Vec<MessageRecord>> {
    let mut statement = conn
        .prepare_cached(&format!(
            "SELECT insert_order, {MESSAGE_COLUMNS} FROM cgka_messages
             WHERE group_id = ?1 AND epoch >= ?2
             ORDER BY insert_order"
        ))
        .storage()?;
    let rows = statement
        .query_map(
            params![group_id.as_slice(), epoch_to_i64(at_or_after_epoch)?],
            |row| Ok((row.get::<_, i64>(0)?, message_columns_at(row, 1)?)),
        )
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let mut orders = include_insert_order;
    rows.into_iter()
        .map(|(insert_order, columns)| {
            if let Some(orders) = orders.as_deref_mut() {
                orders.push(insert_order);
            }
            decode_message_columns(columns)
        })
        .collect()
}

fn message_columns_at(row: &rusqlite::Row<'_>, offset: usize) -> rusqlite::Result<MessageColumns> {
    Ok((
        row.get(offset)?,
        row.get(offset + 1)?,
        row.get(offset + 2)?,
        row.get(offset + 3)?,
        row.get(offset + 4)?,
        row.get(offset + 5)?,
        row.get(offset + 6)?,
        row.get(offset + 7)?,
    ))
}

pub(super) fn ordered_messages_on_connection(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
) -> StorageResult<Vec<(i64, MessageRecord)>> {
    let mut orders = Vec::new();
    let records = list_messages_on_connection(conn, group_id, EpochId(0), Some(&mut orders))?;
    Ok(orders.into_iter().zip(records).collect())
}

pub(super) fn put_message_on_connection(
    conn: &rusqlite::Connection,
    insert_order: Option<i64>,
    record: &MessageRecord,
) -> StorageResult<()> {
    let deferred_peel = record.deferred_peel.as_ref().map(serialize).transpose()?;
    match insert_order {
        None => conn.execute_cached(
            "INSERT INTO cgka_messages (
                 id, group_id, epoch, state, storage_format, record, payload, deferred_peel
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                group_id = excluded.group_id,
                epoch = excluded.epoch,
                state = excluded.state,
                storage_format = excluded.storage_format,
                record = NULL,
                payload = excluded.payload,
                deferred_peel = excluded.deferred_peel",
            params![
                record.id.as_slice(),
                record.group_id.as_slice(),
                epoch_to_i64(record.epoch)?,
                message_state_to_i64(record.state),
                NORMALIZED_MESSAGE_STORAGE_FORMAT,
                &record.payload,
                deferred_peel,
            ],
        ),
        Some(insert_order) => conn.execute_cached(
            "INSERT INTO cgka_messages (
                 insert_order, id, group_id, epoch, state, storage_format,
                 record, payload, deferred_peel
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8)",
            params![
                insert_order,
                record.id.as_slice(),
                record.group_id.as_slice(),
                epoch_to_i64(record.epoch)?,
                message_state_to_i64(record.state),
                NORMALIZED_MESSAGE_STORAGE_FORMAT,
                &record.payload,
                deferred_peel,
            ],
        ),
    }
    .storage()?;
    Ok(())
}

/// `?N` placeholder list for a state `IN (...)` clause, numbered after the
/// fixed `?1` group-id and `?2` epoch parameters.
fn state_placeholders(states: &[MessageState]) -> String {
    (0..states.len())
        .map(|index| format!("?{}", index + 3))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Positional parameters matching [`state_placeholders`]: group id, epoch
/// floor, then one integer per requested state.
fn state_query_params(
    group_id: &GroupId,
    at_or_after_epoch: EpochId,
    states: &[MessageState],
) -> StorageResult<Vec<rusqlite::types::Value>> {
    let mut params = Vec::with_capacity(states.len() + 2);
    params.push(rusqlite::types::Value::Blob(group_id.as_slice().to_vec()));
    params.push(rusqlite::types::Value::Integer(epoch_to_i64(
        at_or_after_epoch,
    )?));
    params.extend(
        states
            .iter()
            .map(|state| rusqlite::types::Value::Integer(message_state_to_i64(*state))),
    );
    Ok(params)
}

/// Update normalized rows without reading or rewriting their payload. A legacy
/// row is decoded once and promoted atomically so subsequent state flips use
/// the scalar fast path.
fn update_message_state_on_connection(
    conn: &rusqlite::Connection,
    id: &MessageId,
    new_state: MessageState,
) -> StorageResult<()> {
    let storage_format: i64 = conn
        .query_row_cached(
            "SELECT storage_format FROM cgka_messages WHERE id = ?1",
            params![id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .storage()?
        .ok_or(StorageError::NotFound)?;
    let changed = if storage_format == NORMALIZED_MESSAGE_STORAGE_FORMAT {
        conn.execute_cached(
            "UPDATE cgka_messages
             SET state = ?1,
                 deferred_peel = CASE WHEN ?1 = ?2 THEN deferred_peel ELSE NULL END
             WHERE id = ?3",
            params![
                message_state_to_i64(new_state),
                message_state_to_i64(MessageState::PeelDeferred),
                id.as_slice(),
            ],
        )
        .storage()?
    } else if storage_format == 1 {
        let columns = conn
            .query_row_cached(
                &format!("SELECT {MESSAGE_COLUMNS} FROM cgka_messages WHERE id = ?1"),
                params![id.as_slice()],
                message_columns,
            )
            .storage()?;
        let mut record = decode_message_columns(columns)?;
        record.state = new_state;
        if new_state != MessageState::PeelDeferred {
            record.deferred_peel = None;
        }
        put_message_on_connection(conn, None, &record)?;
        1
    } else {
        return Err(StorageError::Serialization(format!(
            "unsupported message storage format {storage_format}"
        )));
    };
    if changed == 0 {
        return Err(StorageError::NotFound);
    }
    Ok(())
}

fn retire_transport_receipts(conn: &rusqlite::Connection, id: &MessageId) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM seen_events WHERE event_id = ?1",
        params![hex::encode(id.as_slice())],
    )
    .storage()?;
    conn.execute_cached(
        "DELETE FROM transport_reconciliation_items WHERE event_id = ?1",
        params![id.as_slice()],
    )
    .storage()?;
    Ok(())
}

/// Delete a protocol message and its not-yet-acknowledged application event on
/// the same connection/transaction so neither row can outlive the other.
fn delete_message_on_connection(conn: &rusqlite::Connection, id: &MessageId) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM pending_application_events WHERE message_id = ?1",
        params![id.as_slice()],
    )
    .storage()?;
    conn.execute_cached(
        "DELETE FROM cgka_messages WHERE id = ?1",
        params![id.as_slice()],
    )
    .storage()?;
    Ok(())
}

fn put_processed_transport_id_on_connection(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    transport_id: &MessageId,
) -> StorageResult<()> {
    conn.execute_cached(
        "INSERT OR IGNORE INTO cgka_processed_transport_ids (id, group_id)
         VALUES (?1, ?2)",
        params![transport_id.as_slice(), group_id.as_slice()],
    )
    .storage()?;
    let stored_group_id = conn
        .query_row_cached(
            "SELECT group_id FROM cgka_processed_transport_ids WHERE id = ?1",
            params![transport_id.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .storage()?;
    if stored_group_id != group_id.as_slice() {
        return Err(StorageError::Backend(
            "processed transport id is already assigned to another group".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::INGRESS_DEDUP_MARKER_CAPACITY;
    use crate::storage::test_support::{gid, mid, sample_group, sample_message};
    use crate::{SqliteAccountStorage, serialize};
    use cgka_traits::engine::GroupEvent;
    use cgka_traits::message::{DeferredPeelLifecycle, MessageState};
    use cgka_traits::storage::{
        GroupStorage, MessageStorage, StorageError, StorageProvider, StorageResult,
    };
    use cgka_traits::types::{EpochId, MemberId, MessageId};
    use rusqlite::params;

    #[test]
    fn released_transport_receipt_journal_does_not_limit_standalone_engine_lifetime() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        // Exercise more distinct releases than the app journal can retain.
        // This database has no app owner and consequently no journal consumer.
        store
            .with_transaction(|storage| -> StorageResult<()> {
                for id in 0..=super::RELEASED_TRANSPORT_RECEIPT_CAPACITY {
                    let mut record =
                        sample_message(MessageId::new(id.to_be_bytes().to_vec()), gid(1), 0);
                    record.state = MessageState::PeelDeferred;
                    storage.put_message(&record)?;
                    storage.release_message_for_replay(&record)?;
                    assert!(matches!(
                        storage.get_message(&record.id),
                        Err(StorageError::NotFound)
                    ));
                }
                Ok(())
            })
            .unwrap();
        assert!(
            store
                .consume_released_transport_receipts()
                .unwrap()
                .is_empty()
        );
        assert!(store.pending_epoch_backfill_intents().unwrap().is_empty());
    }

    #[test]
    fn released_transport_receipt_journal_tracks_app_without_persisted_receipts() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.ensure_account_projection("app-owner").unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let mut record = sample_message(mid(1), gid(1), 0);
        record.state = MessageState::PeelDeferred;
        store.put_message(&record).unwrap();
        // Neither receipt table has ever been populated. Ownership alone must
        // preserve the evidence needed by an app with unsaved seen entries.
        store.release_message_for_replay(&record).unwrap();
        assert_eq!(
            store.consume_released_transport_receipts().unwrap(),
            vec![record.id]
        );
    }

    #[test]
    fn released_transport_receipts_survive_reopen_and_retire_both_receipt_stores() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("release.db");
        let key = crate::SqlCipherKey::new("synthetic release regression").unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        store.ensure_account_projection("app-owner").unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let mut record = sample_message(MessageId::new(vec![42; 32]), gid(1), 3);
        record.state = MessageState::PeelDeferred;
        store.put_message(&record).unwrap();
        let seed_receipts = |store: &SqliteAccountStorage| {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO seen_events(event_id, seen_at) VALUES (?1, 1)",
                params![hex::encode(record.id.as_slice())],
            )
            .unwrap();
            conn.execute("INSERT INTO transport_reconciliation_items(route_kind, route_id, event_id, created_at)
                VALUES(1, ?1, ?2, 1)", params![vec![9_u8; 32], record.id.as_slice()]).unwrap();
        };
        seed_receipts(&store);
        store.release_message_for_replay(&record).unwrap();
        assert!(matches!(
            store.get_message(&record.id),
            Err(StorageError::NotFound)
        ));
        for table in ["seen_events", "transport_reconciliation_items"] {
            assert_eq!(
                store
                    .lock()
                    .unwrap()
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        // Model an old app checkpoint before it has consumed the release.
        seed_receipts(&store);
        store.close().unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            store.consume_released_transport_receipts().unwrap(),
            vec![record.id.clone()]
        );
        assert!(
            store
                .consume_released_transport_receipts()
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.pending_epoch_backfill_intents().unwrap().len(), 1);
        for table in ["seen_events", "transport_reconciliation_items"] {
            assert_eq!(
                store
                    .lock()
                    .unwrap()
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        store.close().unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            store.pending_epoch_backfill_intents().unwrap().len(),
            1,
            "death after journal acknowledgement must not lose recovery intent"
        );
        store.close().unwrap();
    }

    #[test]
    fn released_transport_receipt_transaction_rolls_back_with_raw_bytes() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.ensure_account_projection("app-owner").unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let mut record = sample_message(mid(1), gid(1), 0);
        record.state = MessageState::PeelDeferred;
        store.put_message(&record).unwrap();
        let result: StorageResult<()> = store.with_transaction(|storage| {
            storage.release_message_for_replay(&record)?;
            Err(StorageError::Backend("injected interruption".into()))
        });
        assert!(result.is_err());
        assert_eq!(store.get_message(&record.id).unwrap(), record);
        assert!(
            store
                .consume_released_transport_receipts()
                .unwrap()
                .is_empty()
        );
        store.release_message_for_replay(&record).unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_release_ack BEFORE DELETE ON
            cgka_released_transport_receipts BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert!(store.consume_released_transport_receipts().is_err());
        assert!(store.pending_epoch_backfill_intents().unwrap().is_empty());
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_release_ack;")
            .unwrap();
        assert_eq!(
            store.consume_released_transport_receipts().unwrap(),
            vec![record.id]
        );
    }

    #[test]
    fn released_transport_receipt_capacity_never_drops_replay_evidence_or_raw_bytes() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.ensure_account_projection("app-owner").unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        store
            .with_transaction(|storage| -> StorageResult<()> {
                let conn = storage.lock()?;
                for id in 0_u64..8192 {
                    conn.execute(
                        "INSERT INTO cgka_released_transport_receipts(id, group_id, epoch)
                    VALUES(?1, ?2, 0)",
                        params![id.to_be_bytes().as_slice(), gid(1).as_slice()],
                    )
                    .unwrap();
                }
                Ok(())
            })
            .unwrap();
        let record = sample_message(mid(42), gid(1), 0);
        store.put_message(&record).unwrap();
        assert!(store.release_message_for_replay(&record).is_err());
        assert_eq!(store.get_message(&record.id).unwrap(), record);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM cgka_released_transport_receipts",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            8192
        );
        store.delete_group(&gid(1)).unwrap();
        assert!(
            store
                .consume_released_transport_receipts()
                .unwrap()
                .is_empty(),
            "account group deletion must retire its release journal"
        );
    }

    #[test]
    fn deferred_metadata_does_not_read_normalized_payloads() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let mut expected = Vec::new();
        for id in [9, 2, 7] {
            let mut message = sample_message(mid(id), gid(1), u64::from(id));
            message.state = MessageState::PeelDeferred;
            message.payload = vec![id; 16 * 1024];
            expected.push(cgka_traits::message::DeferredMessageMetadata::from(
                message.clone(),
            ));
            store.put_message(&message).unwrap();
        }
        store
            .put_message(&sample_message(mid(3), gid(1), 0))
            .unwrap();
        super::FULL_MESSAGE_READS.with(|stats| stats.set((0, 0)));
        assert_eq!(
            store.list_deferred_message_metadata(&gid(1)).unwrap(),
            expected
        );
        assert_eq!(
            super::FULL_MESSAGE_READS.with(|stats| stats.get()),
            (0, 0),
            "scheduler metadata must not materialize normalized message payloads"
        );
    }

    #[test]
    fn deferred_metadata_preserves_legacy_and_normalized_rows_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let key = crate::SqlCipherKey::new("synthetic metadata regression").unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        store.put_group(&sample_group(gid(2), 0, 0)).unwrap();
        let mut expected = Vec::new();
        for (index, id) in [9, 2, 7].into_iter().enumerate() {
            let mut message = sample_message(mid(id), gid(1), u64::from(id));
            message.state = MessageState::PeelDeferred;
            message.payload = vec![id; 1024 + index];
            message.deferred_peel = Some(DeferredPeelLifecycle {
                first_observed_wall_ms: 10_000,
                wall_high_water_ms: 10_400,
                clock_instance_id: 7,
                residence_deadline_monotonic_ms: 2_000,
                residence_deadline_wall_ms: 11_000,
                distinct_context_attempts: index as u32,
                last_context_fingerprint: Some([id; 32]),
            });
            if index == 1 {
                store
                    .lock()
                    .unwrap()
                    .execute(
                        "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            message.id.as_slice(),
                            message.group_id.as_slice(),
                            message.epoch.0 as i64,
                            super::message_state_to_i64(message.state),
                            serialize(&message).unwrap()
                        ],
                    )
                    .unwrap();
            } else {
                store.put_message(&message).unwrap();
            }
            expected.push(cgka_traits::message::DeferredMessageMetadata::from(message));
        }
        let mut unrelated = sample_message(mid(4), gid(2), 0);
        unrelated.state = MessageState::PeelDeferred;
        store.put_message(&unrelated).unwrap();
        store.close().unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            store.list_deferred_message_metadata(&gid(1)).unwrap(),
            expected
        );
        store.promote_legacy_message_rows(2).unwrap();
        assert_eq!(
            store.list_deferred_message_metadata(&gid(1)).unwrap(),
            expected
        );
        store
            .update_message_state(&mid(2), MessageState::Processed)
            .unwrap();
        expected.remove(1);
        assert_eq!(
            store.list_deferred_message_metadata(&gid(1)).unwrap(),
            expected
        );
        store.close().unwrap();
    }

    /// Compare full-row preparation with metadata preparation in the same
    /// encrypted database. Logical bytes exclude SQLite pages and cache effects.
    #[test]
    #[ignore = "explicit encrypted-storage preparation benchmark"]
    fn deferred_metadata_file_backed_benchmark() {
        let mut measurements = Vec::new();
        for processed in [0, 4096] {
            for deferred in [0, 64, 512, 2048] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("preparation.db");
                let key = crate::SqlCipherKey::new("synthetic preparation benchmark").unwrap();
                let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
                store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
                store
                    .with_transaction(|tx| {
                        for index in 0..processed + deferred {
                            let mut message = sample_message(
                                cgka_traits::MessageId::new((index as u64).to_be_bytes().to_vec()),
                                gid(1),
                                (index % 17) as u64,
                            );
                            message.state = if index < processed {
                                MessageState::Processed
                            } else {
                                MessageState::PeelDeferred
                            };
                            message.payload = vec![0x71; 4096];
                            if index >= processed {
                                message.deferred_peel = Some(DeferredPeelLifecycle {
                                    first_observed_wall_ms: 10_000,
                                    wall_high_water_ms: 10_400,
                                    clock_instance_id: 7,
                                    residence_deadline_monotonic_ms: 2_000,
                                    residence_deadline_wall_ms: 11_000,
                                    distinct_context_attempts: 3,
                                    last_context_fingerprint: Some([0xA5; 32]),
                                });
                            }
                            tx.put_message(&message)?;
                        }
                        Ok::<_, StorageError>(())
                    })
                    .unwrap();
                let mut timings = [std::time::Duration::ZERO; 2];
                let mut full_reads = [(0, 0); 2];
                for repetition in 0..12 {
                    for mode in [repetition % 2, 1 - repetition % 2] {
                        super::FULL_MESSAGE_READS.with(|stats| stats.set((0, 0)));
                        let start = std::time::Instant::now();
                        let count = if mode == 0 {
                            store
                                .list_messages_in_states(
                                    &gid(1),
                                    &[MessageState::PeelDeferred],
                                    EpochId(0),
                                )
                                .unwrap()
                                .len()
                        } else {
                            store.list_deferred_message_metadata(&gid(1)).unwrap().len()
                        };
                        assert_eq!(count, deferred);
                        if repetition >= 2 {
                            timings[mode] += start.elapsed();
                            full_reads[mode] = super::FULL_MESSAGE_READS.with(|stats| stats.get());
                        }
                    }
                }
                measurements.push(serde_json::json!({
                    "processed": processed, "deferred": deferred,
                    "payload_bytes": 4096, "epochs": 17, "samples": 10,
                    "full_avg_us": timings[0].as_micros() / 10,
                    "metadata_avg_us": timings[1].as_micros() / 10,
                    "full_rows": full_reads[0].0, "full_blob_bytes": full_reads[0].1,
                    "metadata_full_rows": full_reads[1].0,
                    "metadata_full_blob_bytes": full_reads[1].1,
                }));
                store.close().unwrap();
                assert_ne!(&std::fs::read(&path).unwrap()[..16], b"SQLite format 3\0");
            }
        }
        if let Some(path) = std::env::var_os("MDK_DEFERRED_PREPARATION_BENCHMARK_OUT") {
            fs_private::write_private(
                std::path::Path::new(&path),
                &serde_json::to_vec_pretty(&measurements).unwrap(),
            )
            .unwrap();
        }
    }

    fn application_event(message_id: cgka_traits::MessageId) -> GroupEvent {
        GroupEvent::MessageReceived {
            group_id: gid(1),
            message_id,
            sender: MemberId::new(vec![7; 32]),
            epoch: EpochId(0),
            payload: b"authenticated chat".to_vec(),
            retention: None,
        }
    }

    #[test]
    fn message_state_transitions() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let message = sample_message(mid(1), gid(1), 0);
        store.put_message(&message).unwrap();
        assert_eq!(
            store.get_message(&message.id).unwrap().state,
            MessageState::Created
        );

        store
            .update_message_state(&message.id, MessageState::Retryable)
            .unwrap();
        assert_eq!(
            store.get_message(&message.id).unwrap().state,
            MessageState::Retryable
        );

        store
            .update_message_state(&message.id, MessageState::PeelDeferred)
            .unwrap();
        assert_eq!(
            store.get_message(&message.id).unwrap().state,
            MessageState::PeelDeferred
        );
    }

    #[cfg(feature = "storage-format-benchmarks")]
    #[test]
    fn storage_format_bench_sizes_accepts_legacy_message_rows() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 0, 0);
        let message = sample_message(mid(1), group.id.clone(), 0);
        let record = serialize(&message).unwrap();
        store.put_group(&group).unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
                 VALUES (?1, ?2, 0, 0, ?3)",
                rusqlite::params![message.id.as_slice(), group.id.as_slice(), record],
            )
            .unwrap();
        store
            .create_group_snapshot(&group.id, "legacy-size")
            .unwrap();

        let sizes = store
            .storage_format_bench_sizes(&group.id, &message.id)
            .expect("legacy row size is defined");
        assert_eq!(
            sizes.message_value_bytes,
            u64::try_from(message.id.as_slice().len() + group.id.as_slice().len() + record.len())
                .unwrap()
        );
        assert!(sizes.largest_snapshot_bytes > 0);
    }

    #[test]
    fn normalized_row_keeps_payload_out_of_state_updates() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let message = sample_message(mid(1), gid(1), 0);
        store.put_message(&message).unwrap();

        let before: (i64, bool, Vec<u8>) = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT storage_format, record IS NULL, payload
                 FROM cgka_messages WHERE id = ?1",
                rusqlite::params![message.id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(before, (2, true, message.payload.clone()));

        store
            .update_message_state(&message.id, MessageState::Processed)
            .unwrap();
        let after: (i64, bool, Vec<u8>) = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT storage_format, record IS NULL, payload
                 FROM cgka_messages WHERE id = ?1",
                rusqlite::params![message.id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(after, before, "state update must not rewrite payload bytes");
    }

    #[test]
    fn legacy_row_reads_and_promotes_on_state_update() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let message = sample_message(mid(1), gid(1), 0);
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
                 VALUES (?1, ?2, 0, 1, ?3)",
                rusqlite::params![
                    message.id.as_slice(),
                    message.group_id.as_slice(),
                    serialize(&message).unwrap(),
                ],
            )
            .unwrap();
        assert_eq!(store.get_message(&message.id).unwrap(), message);

        store
            .update_message_state(&message.id, MessageState::Processed)
            .unwrap();
        let promoted = store.get_message(&message.id).unwrap();
        assert_eq!(promoted.state, MessageState::Processed);
        assert_eq!(promoted.payload, message.payload);
        let format: (i64, bool, bool) = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT storage_format, record IS NULL, payload IS NOT NULL
                 FROM cgka_messages WHERE id = ?1",
                rusqlite::params![message.id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(format, (2, true, true));
    }

    #[test]
    fn bounded_legacy_promotion_converges_in_atomic_batches() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        for index in 1..=3 {
            let message = sample_message(mid(index), gid(1), 0);
            store
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
                     VALUES (?1, ?2, 0, 1, ?3)",
                    rusqlite::params![
                        message.id.as_slice(),
                        message.group_id.as_slice(),
                        serialize(&message).unwrap(),
                    ],
                )
                .unwrap();
        }

        assert_eq!(
            store.promote_legacy_message_rows(2).unwrap(),
            super::MessageFormatPromotionProgress {
                promoted: 2,
                has_more: true,
            }
        );
        assert_eq!(
            store.promote_legacy_message_rows(2).unwrap(),
            super::MessageFormatPromotionProgress {
                promoted: 1,
                has_more: false,
            }
        );
        assert_eq!(
            store.promote_legacy_message_rows(2).unwrap(),
            super::MessageFormatPromotionProgress {
                promoted: 0,
                has_more: false,
            }
        );
    }

    #[test]
    fn malformed_legacy_promotion_rolls_back_the_whole_batch() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let valid = sample_message(mid(1), gid(1), 0);
        for (id, record) in [
            (mid(1), serialize(&valid).unwrap()),
            (mid(2), b"not-json".to_vec()),
        ] {
            store
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
                     VALUES (?1, ?2, 0, 1, ?3)",
                    rusqlite::params![id.as_slice(), gid(1).as_slice(), record],
                )
                .unwrap();
        }

        assert!(store.promote_legacy_message_rows(2).is_err());
        let legacy_count: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM cgka_messages WHERE storage_format = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_count, 2);
    }

    #[test]
    fn deferred_peel_lifecycle_round_trips_and_clears_on_retirement() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let mut message = sample_message(mid(1), gid(1), 0);
        message.state = MessageState::PeelDeferred;
        message.deferred_peel = Some(DeferredPeelLifecycle {
            first_observed_wall_ms: 10_000,
            wall_high_water_ms: 10_400,
            clock_instance_id: 7,
            residence_deadline_monotonic_ms: 2_000,
            residence_deadline_wall_ms: 11_000,
            distinct_context_attempts: 3,
            last_context_fingerprint: Some([0xA5; 32]),
        });
        store.put_message(&message).unwrap();
        assert_eq!(store.get_message(&message.id).unwrap(), message);

        store
            .update_message_state(&message.id, MessageState::Processed)
            .unwrap();
        let updated = store.get_message(&message.id).unwrap();
        assert_eq!(updated.state, MessageState::Processed);
        assert_eq!(updated.deferred_peel, None);
    }

    #[test]
    fn deleted_message_id_can_be_inserted_again() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let message = sample_message(mid(1), gid(1), 0);
        store.put_message(&message).unwrap();
        store
            .put_pending_application_event(&application_event(message.id.clone()))
            .unwrap();

        store.delete_message(&message.id).unwrap();
        assert!(matches!(
            store.get_message(&message.id),
            Err(StorageError::NotFound)
        ));
        assert!(store.list_pending_application_events().unwrap().is_empty());

        store.put_message(&message).unwrap();
        assert_eq!(store.get_message(&message.id).unwrap(), message);
    }

    #[test]
    fn ingress_dedup_markers_are_group_independent_and_idempotent() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let id = mid(42);
        assert!(!store.has_ingress_dedup_marker(&id).unwrap());
        store.put_ingress_dedup_marker(&id).unwrap();
        store.put_ingress_dedup_marker(&id).unwrap();
        assert!(store.has_ingress_dedup_marker(&id).unwrap());
    }

    #[test]
    fn ingress_prune_query_work() {
        use rusqlite::trace::{TraceEvent, TraceEventCodes};
        use rusqlite::{StatementStatus, params};
        use std::sync::Mutex;

        static PRUNE_SQL: Mutex<String> = Mutex::new(String::new());
        let store = SqliteAccountStorage::in_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            // Sparse keys catch incorrect cutoffs based on MAX(rowid) - capacity.
            conn.execute(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < ?1)
                 INSERT INTO cgka_ingress_dedup(insert_order, id)
                 SELECT x*3, CAST(printf('%032x', x) AS BLOB) FROM n",
                params![INGRESS_DEDUP_MARKER_CAPACITY],
            )
            .unwrap();
            conn.trace_v2(
                TraceEventCodes::SQLITE_TRACE_PROFILE,
                Some(|event| {
                    let TraceEvent::Profile(statement, _) = event else {
                        return;
                    };
                    if statement
                        .sql()
                        .starts_with("DELETE FROM cgka_ingress_dedup")
                    {
                        *PRUNE_SQL.lock().unwrap() = statement.sql().into_owned();
                    }
                }),
            );
        }
        let id = mid(42);
        store.put_ingress_dedup_marker(&id).unwrap();
        store.put_ingress_dedup_marker(&id).unwrap();
        let conn = store.lock().unwrap();
        conn.trace_v2(TraceEventCodes::empty(), None);
        let bounds: (i64, i64) = conn
            .query_row(
                "SELECT count(*), min(insert_order) FROM cgka_ingress_dedup",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(bounds, (INGRESS_DEDUP_MARKER_CAPACITY, 6));
        conn.execute(
            "INSERT INTO cgka_ingress_dedup(id) VALUES (?1)",
            params![mid(43).as_slice()],
        )
        .unwrap();
        let production_sql = PRUNE_SQL.lock().unwrap().clone();
        assert!(!production_sql.is_empty());
        let legacy_sql = "DELETE FROM cgka_ingress_dedup WHERE insert_order NOT IN (
            SELECT insert_order FROM cgka_ingress_dedup ORDER BY insert_order DESC LIMIT ?1)";
        let mut measurements = Vec::new();
        for sql in [legacy_sql, production_sql.as_str()] {
            let mut statement = conn.prepare(sql).unwrap();
            let start = std::time::Instant::now();
            for _ in 0..20 {
                conn.execute_batch("SAVEPOINT bench").unwrap();
                assert_eq!(
                    statement
                        .execute(params![INGRESS_DEDUP_MARKER_CAPACITY])
                        .unwrap(),
                    1
                );
                conn.execute_batch("ROLLBACK TO bench; RELEASE bench")
                    .unwrap();
            }
            measurements.push((
                statement.get_status(StatementStatus::VmStep) / 20,
                start.elapsed() / 20,
            ));
        }
        eprintln!(
            "ingress prune capacity={INGRESS_DEDUP_MARKER_CAPACITY}: old={:?}, new={:?} (VM steps, elapsed)",
            measurements[0], measurements[1]
        );
        assert!(measurements[0].0 > measurements[1].0 * 5);
    }

    #[test]
    fn processed_transport_ids_survive_marker_capacity_churn_and_cascade() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 0, 0);
        store.put_group(&group).unwrap();

        let processed_ids = (0..=INGRESS_DEDUP_MARKER_CAPACITY)
            .map(|index| indexed_id(0xa1, index))
            .collect::<Vec<_>>();
        for id in &processed_ids {
            store.put_processed_transport_id(&group.id, id).unwrap();
        }

        let bounded_ids = (0..=INGRESS_DEDUP_MARKER_CAPACITY)
            .map(|index| indexed_id(0xb2, index))
            .collect::<Vec<_>>();
        for id in &bounded_ids {
            store.put_ingress_dedup_marker(id).unwrap();
        }

        assert!(
            store.has_processed_transport_id(&processed_ids[0]).unwrap(),
            "processed wrapper evidence must survive beyond the bounded marker capacity"
        );
        assert!(
            !store.has_ingress_dedup_marker(&bounded_ids[0]).unwrap(),
            "the hostile/unassociated marker pool must remain bounded"
        );
        assert!(
            store
                .has_ingress_dedup_marker(bounded_ids.last().unwrap())
                .unwrap()
        );

        store.delete_group(&group.id).unwrap();
        assert!(
            !store.has_processed_transport_id(&processed_ids[0]).unwrap(),
            "processed wrapper evidence must cascade with its owning group"
        );
    }

    #[test]
    fn processed_transport_id_conflict_rolls_back_canonical_message_admission() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let first_group = sample_group(gid(1), 0, 0);
        let second_group = sample_group(gid(2), 0, 0);
        store.put_group(&first_group).unwrap();
        store.put_group(&second_group).unwrap();
        let transport_id = indexed_id(0xc3, 0);
        store
            .put_processed_transport_id(&first_group.id, &transport_id)
            .unwrap();
        let message = sample_message(indexed_id(0xd4, 0), second_group.id.clone(), 0);

        let result: StorageResult<()> = store.with_transaction(|storage| {
            storage.put_message(&message)?;
            storage.put_processed_transport_id(&second_group.id, &transport_id)
        });

        assert!(result.is_err());
        assert!(matches!(
            store.get_message(&message.id),
            Err(StorageError::NotFound)
        ));
        assert!(store.has_processed_transport_id(&transport_id).unwrap());
    }

    fn indexed_id(prefix: u8, index: i64) -> cgka_traits::MessageId {
        let mut bytes = vec![prefix; 32];
        bytes[24..].copy_from_slice(&index.to_be_bytes());
        cgka_traits::MessageId::new(bytes)
    }

    #[test]
    fn update_message_state_keeps_read_modify_write_in_one_transaction() {
        let source = include_str!("messages.rs");
        let body = source
            .split("fn update_message_state")
            .nth(1)
            .expect("update_message_state body");

        assert!(body.contains("transaction_with_behavior(TransactionBehavior::Immediate)"));
        assert!(!body.contains("self.get_message(id)"));
    }

    #[test]
    fn update_message_state_runs_inside_outer_engine_transaction() {
        // #424 regression: when the convergence-apply path runs the disposition
        // writes inside an engine `with_transaction`, `update_message_state`
        // must reuse the open transaction instead of opening a nested one
        // ("cannot start a transaction within a transaction").
        use cgka_traits::storage::StorageProvider;

        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let message = sample_message(mid(1), gid(1), 0);
        store.put_message(&message).unwrap();

        let result: Result<(), StorageError> = store.with_transaction(|storage| {
            storage.update_message_state(&message.id, MessageState::Processed)?;
            Ok(())
        });
        assert!(result.is_ok(), "nested update must succeed: {result:?}");
        assert_eq!(
            store.get_message(&message.id).unwrap().state,
            MessageState::Processed
        );
    }

    #[test]
    fn put_message_reuses_outer_engine_transaction() {
        use cgka_traits::storage::{StorageError, StorageProvider};

        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let message = sample_message(mid(1), gid(1), 0);

        let result: Result<(), StorageError> = store.with_transaction(|storage| {
            storage.put_message(&message)?;
            Err(StorageError::Backend("force rollback".to_string()))
        });

        assert!(result.is_err());
        assert!(matches!(
            store.get_message(&message.id),
            Err(StorageError::NotFound)
        ));
    }

    #[test]
    fn update_message_state_rolls_back_with_outer_transaction() {
        // #424 regression: a torn convergence apply must not leave a message
        // state half-committed. When the outer transaction aborts, the state
        // change made via `update_message_state` rolls back with it.
        use cgka_traits::storage::{StorageError, StorageProvider};

        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let message = sample_message(mid(1), gid(1), 0);
        store.put_message(&message).unwrap();

        let result: Result<(), StorageError> = store.with_transaction(|storage| {
            storage.update_message_state(&message.id, MessageState::Processed)?;
            Err(StorageError::Backend("force rollback".to_string()))
        });
        assert!(result.is_err());
        assert_eq!(
            store.get_message(&message.id).unwrap().state,
            MessageState::Created,
            "message state must roll back with the aborted outer transaction",
        );
    }

    #[test]
    fn pending_application_event_commits_and_rolls_back_with_message_state() {
        use cgka_traits::storage::StorageProvider;

        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let committed = sample_message(mid(1), gid(1), 0);
        let rolled_back = sample_message(mid(2), gid(1), 0);
        store.put_message(&committed).unwrap();
        store.put_message(&rolled_back).unwrap();

        store
            .with_transaction(|storage| {
                storage.update_message_state(&committed.id, MessageState::Processed)?;
                storage.put_pending_application_event(&application_event(committed.id.clone()))?;
                Ok::<_, StorageError>(())
            })
            .unwrap();
        assert_eq!(
            store.list_pending_application_events().unwrap(),
            vec![application_event(committed.id.clone())]
        );
        let mut conflicting = application_event(committed.id.clone());
        if let GroupEvent::MessageReceived { payload, .. } = &mut conflicting {
            *payload = b"conflicting authenticated chat".to_vec();
        }
        assert!(matches!(
            store.put_pending_application_event(&conflicting),
            Err(StorageError::Backend(_))
        ));
        assert_eq!(
            store.list_pending_application_events().unwrap(),
            vec![application_event(committed.id.clone())],
            "a conflicting duplicate must not overwrite durable delivery evidence",
        );

        let result: Result<(), StorageError> = store.with_transaction(|storage| {
            storage.update_message_state(&rolled_back.id, MessageState::Processed)?;
            storage.put_pending_application_event(&application_event(rolled_back.id.clone()))?;
            Err(StorageError::Backend("force rollback".to_owned()))
        });
        assert!(result.is_err());
        assert_eq!(
            store.get_message(&rolled_back.id).unwrap().state,
            MessageState::Created
        );
        assert_eq!(
            store.list_pending_application_events().unwrap(),
            vec![application_event(committed.id.clone())]
        );

        store
            .delete_pending_application_events(&[committed.id])
            .unwrap();
        assert!(store.list_pending_application_events().unwrap().is_empty());
    }

    #[test]
    fn state_filtered_queries_match_the_full_listing() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        store.put_group(&sample_group(gid(2), 0, 0)).unwrap();

        let with_state = |id, group, epoch, state| {
            let mut message = sample_message(id, group, epoch);
            message.state = state;
            store.put_message(&message).unwrap();
        };
        with_state(mid(1), gid(1), 0, MessageState::Created);
        with_state(mid(2), gid(1), 5, MessageState::PeelDeferred);
        with_state(mid(3), gid(1), 2, MessageState::Retryable);
        with_state(mid(4), gid(1), 7, MessageState::Processed);
        with_state(mid(5), gid(2), 0, MessageState::PeelDeferred);

        let ids = |states: &[MessageState], epoch: u64| {
            store
                .list_messages_in_states(&gid(1), states, EpochId(epoch))
                .unwrap()
                .into_iter()
                .map(|m| m.id)
                .collect::<Vec<_>>()
        };

        assert_eq!(ids(&[MessageState::PeelDeferred], 0), vec![mid(2)]);
        assert_eq!(
            ids(&[MessageState::Created, MessageState::Retryable], 0),
            vec![mid(1), mid(3)],
            "insert order must be preserved",
        );
        assert_eq!(
            ids(&[MessageState::Created, MessageState::Retryable], 1),
            vec![mid(3)],
            "epoch floor must apply",
        );
        assert_eq!(ids(&[], 0), Vec::<cgka_traits::MessageId>::new());

        assert!(
            store
                .has_messages_in_states(&gid(1), &[MessageState::PeelDeferred], EpochId(0))
                .unwrap()
        );
        assert!(
            !store
                .has_messages_in_states(&gid(1), &[MessageState::PeelDeferred], EpochId(6))
                .unwrap(),
            "epoch floor must apply to the existence probe",
        );
        assert!(
            !store
                .has_messages_in_states(&gid(1), &[MessageState::Failed], EpochId(0))
                .unwrap()
        );
        assert!(
            !store
                .has_messages_in_states(&gid(1), &[], EpochId(0))
                .unwrap()
        );

        // Parity with the trait's default (list + filter) semantics.
        for states in [
            &[MessageState::PeelDeferred][..],
            &[MessageState::Created, MessageState::Retryable][..],
            &[MessageState::Processed][..],
        ] {
            let expected: Vec<_> = store
                .list_messages(&gid(1), EpochId(0))
                .unwrap()
                .into_iter()
                .filter(|record| states.contains(&record.state))
                .collect();
            assert_eq!(
                store
                    .list_messages_in_states(&gid(1), states, EpochId(0))
                    .unwrap(),
                expected
            );
            assert_eq!(
                store
                    .has_messages_in_states(&gid(1), states, EpochId(0))
                    .unwrap(),
                !expected.is_empty()
            );
        }
    }

    #[test]
    fn list_messages_filters_by_group_epoch_and_insert_order() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        store.put_group(&sample_group(gid(2), 0, 0)).unwrap();
        store
            .put_message(&sample_message(mid(3), gid(1), 0))
            .unwrap();
        store
            .put_message(&sample_message(mid(1), gid(1), 5))
            .unwrap();
        store
            .put_message(&sample_message(mid(2), gid(2), 9))
            .unwrap();

        let ids: Vec<_> = store
            .list_messages(&gid(1), EpochId(0))
            .unwrap()
            .into_iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(ids, vec![mid(3), mid(1)]);

        let ids: Vec<_> = store
            .list_messages(&gid(1), EpochId(3))
            .unwrap()
            .into_iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(ids, vec![mid(1)]);
    }
}
