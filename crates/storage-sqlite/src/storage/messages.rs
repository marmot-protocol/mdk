use super::snapshots;
use crate::{
    SqliteAccountStorage, SqliteResultExt, deserialize, epoch_to_i64, message_state_to_i64,
    serialize,
};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::{MessageStorage, StorageError, StorageResult};
use cgka_traits::types::{EpochId, GroupId, MessageId};
use rusqlite::{OptionalExtension, params};

impl MessageStorage for SqliteAccountStorage {
    fn put_message(&self, record: &MessageRecord) -> StorageResult<()> {
        self.lock()?
            .execute(
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
                    epoch_to_i64(record.epoch)?,
                    message_state_to_i64(record.state),
                    serialize(record)?
                ],
            )
            .storage()?;
        Ok(())
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

    fn update_message_state(&self, id: &MessageId, new_state: MessageState) -> StorageResult<()> {
        // #424: when this runs inside an engine `with_transaction` (convergence
        // apply path), the outer SQL transaction is already open and owns
        // commit/rollback, so we must not start a nested one. Mirror the
        // openmls value-store pattern: operate directly on the locked
        // connection when we're the transaction owner, otherwise wrap our own.
        let mut conn = self.lock()?;
        if self.connection.is_current_thread_transaction_owner() {
            update_message_state_on_connection(&conn, id, new_state)
        } else {
            let tx = conn.transaction().storage()?;
            update_message_state_on_connection(&tx, id, new_state)?;
            tx.commit().storage()?;
            Ok(())
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
    use cgka_traits::message::MessageState;
    use cgka_traits::storage::{GroupStorage, MessageStorage};
    use cgka_traits::types::EpochId;

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
    fn update_message_state_keeps_read_modify_write_in_one_transaction() {
        let source = include_str!("messages.rs");
        let body = source
            .split("fn update_message_state")
            .nth(1)
            .expect("update_message_state body");

        assert!(body.contains("transaction()"));
        assert!(!body.contains("self.get_message(id)"));
    }

    #[test]
    fn update_message_state_runs_inside_outer_engine_transaction() {
        // #424 regression: when the convergence-apply path runs the disposition
        // writes inside an engine `with_transaction`, `update_message_state`
        // must reuse the open transaction instead of opening a nested one
        // ("cannot start a transaction within a transaction").
        use cgka_traits::storage::{StorageError, StorageProvider};

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
