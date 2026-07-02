use crate::connection::retry_on_busy;
use crate::{SqliteAccountStorage, SqliteResultExt, created_at_to_i64, deserialize, serialize};
use cgka_traits::storage::{
    OutboundIntentStorage, QueuedOutboundIntent, StorageError, StorageResult,
};
use cgka_traits::types::{GroupId, MessageId};
use rusqlite::params;

impl OutboundIntentStorage for SqliteAccountStorage {
    fn put_queued_outbound_intent(&self, record: &QueuedOutboundIntent) -> StorageResult<()> {
        // #484: the queued-outbound path is taken by `Engine::do_send` when
        // convergence is unsettled, so this is a real user message-send write.
        // It is a single autocommit statement, so the whole statement is safe
        // to retry on transient lock contention from a concurrent writer.
        let serialized = serialize(record)?;
        let created_at = created_at_to_i64(record.created_at_ms)?;
        retry_on_busy(|| {
            self.lock()?
                .execute(
                    "INSERT INTO cgka_queued_outbound (id, group_id, created_at_ms, record)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                    group_id = excluded.group_id,
                    created_at_ms = excluded.created_at_ms,
                    record = excluded.record",
                    params![
                        record.id.as_slice(),
                        record.group_id.as_slice(),
                        created_at,
                        serialized,
                    ],
                )
                .storage()?;
            Ok(())
        })
    }

    fn list_queued_outbound_intents(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<QueuedOutboundIntent>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT record FROM cgka_queued_outbound
                 WHERE group_id = ?1
                 ORDER BY insert_order",
            )
            .storage()?;
        let records = stmt
            .query_map(params![group_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        records.iter().map(|record| deserialize(record)).collect()
    }

    fn delete_queued_outbound_intent(&self, id: &MessageId) -> StorageResult<()> {
        // #484: delete is also on the queued send path (the intent is removed
        // once it is published), and is a single autocommit statement, so the
        // whole statement is safe to retry on transient lock contention.
        let changed = retry_on_busy(|| {
            self.lock()?
                .execute(
                    "DELETE FROM cgka_queued_outbound WHERE id = ?1",
                    params![id.as_slice()],
                )
                .storage()
        })?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::storage::test_support::{gid, mid, sample_group, sample_queued_intent};
    use cgka_traits::storage::{GroupStorage, OutboundIntentStorage};

    #[test]
    fn queued_outbound_intents_are_group_scoped_and_ordered() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        store.put_group(&sample_group(gid(2), 0, 0)).unwrap();
        store
            .put_queued_outbound_intent(&sample_queued_intent(mid(3), gid(1)))
            .unwrap();
        store
            .put_queued_outbound_intent(&sample_queued_intent(mid(1), gid(1)))
            .unwrap();
        store
            .put_queued_outbound_intent(&sample_queued_intent(mid(2), gid(2)))
            .unwrap();

        let ids: Vec<_> = store
            .list_queued_outbound_intents(&gid(1))
            .unwrap()
            .into_iter()
            .map(|queued| queued.id)
            .collect();
        assert_eq!(ids, vec![mid(3), mid(1)]);

        store.delete_queued_outbound_intent(&mid(3)).unwrap();
        let ids: Vec<_> = store
            .list_queued_outbound_intents(&gid(1))
            .unwrap()
            .into_iter()
            .map(|queued| queued.id)
            .collect();
        assert_eq!(ids, vec![mid(1)]);
    }

    // Regression for issue #484: the queued-outbound path is a real user
    // message-send write (`Engine::do_send` queues here when convergence is
    // unsettled). A concurrent writer on a SECOND connection to the same
    // database file briefly holds the SQLite write lock; with a busy timeout
    // shorter than the hold, the first attempt sees SQLITE_BUSY. The queued
    // put/delete must retry-with-backoff and succeed instead of bubbling
    // "database is locked" to the send caller.
    #[test]
    fn queued_send_contention_is_retried_not_surfaced() {
        use crate::storage::test_support::{gid, mid, sample_group, sample_queued_intent};
        use crate::{SqlCipherKey, SqliteAccountStorage, SqliteStorageOptions};
        use cgka_traits::storage::{GroupStorage, OutboundIntentStorage};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queued-contention.sqlite");
        let key = SqlCipherKey::new("queued contention test key").unwrap();
        // Short busy timeout so the first attempt fails fast and the win comes
        // from the retry loop rather than from SQLite's own busy_timeout wait.
        let options = SqliteStorageOptions {
            busy_timeout_ms: 50,
            ..SqliteStorageOptions::default()
        };

        let writer =
            SqliteAccountStorage::open_encrypted_with_options(&path, &key, options.clone())
                .unwrap();
        writer.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        // Pre-seed an intent to delete under contention later.
        writer
            .put_queued_outbound_intent(&sample_queued_intent(mid(9), gid(1)))
            .unwrap();

        // Spawn a blocker that holds an exclusive write transaction on a
        // separate connection for longer than one busy-timeout window.
        let spawn_blocker = |blocker_gid: u8| {
            let hold = std::time::Duration::from_millis(200);
            let blocker_options = options.clone();
            let blocker_key = SqlCipherKey::new("queued contention test key").unwrap();
            let blocker_path = path.clone();
            std::thread::spawn(move || {
                let blocker = SqliteAccountStorage::open_encrypted_with_options(
                    &blocker_path,
                    &blocker_key,
                    blocker_options,
                )
                .unwrap();
                let conn = blocker.lock().unwrap();
                conn.execute_batch("BEGIN IMMEDIATE").unwrap();
                conn.execute(
                    "INSERT INTO cgka_groups (id, record) VALUES (?1, ?2)",
                    rusqlite::params![gid(blocker_gid).as_slice(), b"blocker".as_slice()],
                )
                .ok();
                std::thread::sleep(hold);
                conn.execute_batch("COMMIT").unwrap();
            })
        };

        // 1. put_queued_outbound_intent under contention must succeed via retry.
        let blocker = spawn_blocker(2);
        std::thread::sleep(std::time::Duration::from_millis(40));
        writer
            .put_queued_outbound_intent(&sample_queued_intent(mid(1), gid(1)))
            .expect("contended queued put must succeed via busy retry, not surface as failure");
        blocker.join().unwrap();

        // 2. delete_queued_outbound_intent under contention must succeed too.
        let blocker = spawn_blocker(3);
        std::thread::sleep(std::time::Duration::from_millis(40));
        writer
            .delete_queued_outbound_intent(&mid(9))
            .expect("contended queued delete must succeed via busy retry, not surface as failure");
        blocker.join().unwrap();

        let ids: Vec<_> = writer
            .list_queued_outbound_intents(&gid(1))
            .unwrap()
            .into_iter()
            .map(|queued| queued.id)
            .collect();
        assert_eq!(
            ids,
            vec![mid(1)],
            "the put persisted and the delete removed the pre-seeded intent after contention cleared"
        );
    }
}
