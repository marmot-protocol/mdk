use super::snapshots;
use crate::connection::retry_on_busy;
use crate::{
    SqliteAccountStorage, SqliteResultExt, deserialize, epoch_to_i64, message_state_to_i64,
    serialize,
};
use cgka_traits::engine::GroupEvent;
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::{GroupStateCheckpointRef, MessageStorage, StorageError, StorageResult};
use cgka_traits::types::{EpochId, GroupId, MessageId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

const INGRESS_DEDUP_MARKER_CAPACITY: i64 = 4_096;

impl MessageStorage for SqliteAccountStorage {
    fn put_message(&self, record: &MessageRecord) -> StorageResult<()> {
        let serialized = serialize(record)?;
        let epoch = epoch_to_i64(record.epoch)?;
        let write = || {
            let conn = self.lock()?;
            conn.execute(
                "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                    group_id = excluded.group_id,
                    epoch = excluded.epoch,
                    state = excluded.state,
                    record = excluded.record",
                params![
                    record.id.as_slice(),
                    record.group_id.as_slice(),
                    epoch,
                    message_state_to_i64(record.state),
                    serialized,
                ],
            )
            .storage()?;
            Ok(())
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
        let record: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT record FROM cgka_messages WHERE id = ?1",
                params![id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?
            .ok_or(StorageError::NotFound)?;
        deserialize(&record)
    }

    fn delete_message(&self, id: &MessageId) -> StorageResult<()> {
        let delete = || {
            self.lock()?
                .execute(
                    "DELETE FROM cgka_messages WHERE id = ?1",
                    params![id.as_slice()],
                )
                .storage()?;
            Ok(())
        };
        if self.connection.is_current_thread_transaction_owner() {
            delete()
        } else {
            retry_on_busy(delete)
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
        let mut stmt = conn
            .prepare(
                "SELECT record FROM cgka_messages
                 WHERE group_id = ?1 AND epoch >= ?2
                 ORDER BY insert_order",
            )
            .storage()?;
        let records = stmt
            .query_map(
                params![group_id.as_slice(), epoch_to_i64(at_or_after_epoch)?],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        records.iter().map(|record| deserialize(record)).collect()
    }

    fn put_pending_application_event(&self, event: &GroupEvent) -> StorageResult<()> {
        let GroupEvent::MessageReceived {
            group_id,
            message_id,
            ..
        } = event
        else {
            return Err(StorageError::Backend(
                "pending application outbox accepts only MessageReceived events".to_owned(),
            ));
        };
        let event_json = serialize(event)?;
        let write = || {
            let conn = self.lock()?;
            let inserted = conn
                .execute(
                    "INSERT INTO pending_application_events (
                        message_id, group_id, message_insert_order, event_json
                     )
                     SELECT ?1, ?2, insert_order, ?3
                     FROM cgka_messages
                     WHERE id = ?1 AND group_id = ?2
                     ON CONFLICT(message_id) DO NOTHING",
                    params![message_id.as_slice(), group_id.as_slice(), &event_json],
                )
                .storage()?;
            if inserted == 0 {
                let existing = conn
                    .query_row(
                        "SELECT event_json FROM pending_application_events WHERE message_id = ?1",
                        params![message_id.as_slice()],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
                    .storage()?;
                return match existing {
                    Some(existing) if existing == event_json => Ok(()),
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
            .prepare(
                "SELECT event_json
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
                conn.execute(
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
                conn.execute(
                    "INSERT OR IGNORE INTO cgka_ingress_dedup (id) VALUES (?1)",
                    params![id.as_slice()],
                )
                .storage()?;
                conn.execute(
                    "DELETE FROM cgka_ingress_dedup
                     WHERE insert_order NOT IN (
                        SELECT insert_order FROM cgka_ingress_dedup
                        ORDER BY insert_order DESC LIMIT ?1
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
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM cgka_ingress_dedup WHERE id = ?1)",
                params![id.as_slice()],
                |row| row.get(0),
            )
            .storage()
    }

    fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        snapshots::create(self, group_id, name)
    }

    fn list_group_snapshots(&self, group_id: &GroupId) -> StorageResult<Vec<String>> {
        snapshots::list(self, group_id)
    }

    fn rollback_group_to_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        snapshots::rollback(self, group_id, name)
    }

    fn release_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        snapshots::release(self, group_id, name)
    }
}

/// Read-modify-write the stored state of a single message on an already-locked
/// connection (which may be a bare `Connection` or a `Transaction` — both deref
/// to `Connection`). Factored out so `update_message_state` can run it either
/// inside the caller's open engine transaction or inside a fresh local one.
fn update_message_state_on_connection(
    conn: &rusqlite::Connection,
    id: &MessageId,
    new_state: MessageState,
) -> StorageResult<()> {
    let record_bytes: Vec<u8> = conn
        .query_row(
            "SELECT record FROM cgka_messages WHERE id = ?1",
            params![id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .storage()?
        .ok_or(StorageError::NotFound)?;
    let mut record: MessageRecord = deserialize(&record_bytes)?;
    record.state = new_state;
    if new_state != MessageState::PeelDeferred {
        record.deferred_peel = None;
    }
    let changed = conn
        .execute(
            "UPDATE cgka_messages SET state = ?1, record = ?2 WHERE id = ?3",
            params![
                message_state_to_i64(new_state),
                serialize(&record)?,
                id.as_slice()
            ],
        )
        .storage()?;
    if changed == 0 {
        return Err(StorageError::NotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::storage::test_support::{gid, mid, sample_group, sample_message};
    use cgka_traits::engine::GroupEvent;
    use cgka_traits::message::{DeferredPeelLifecycle, MessageState};
    use cgka_traits::storage::{GroupStorage, MessageStorage, StorageError};
    use cgka_traits::types::{EpochId, MemberId};

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

        store.delete_message(&message.id).unwrap();
        assert!(matches!(
            store.get_message(&message.id),
            Err(StorageError::NotFound)
        ));

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
