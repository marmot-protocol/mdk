use crate::base::connection::CachedSql;
use crate::{
    SqliteAccountStorage, SqliteResultExt, base::connection::retry_on_busy, deserialize, serialize,
};
use cgka_traits::storage::{StorageError, StorageResult, WelcomeStorage};
use cgka_traits::types::MessageId;
use cgka_traits::welcome::PendingWelcome;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

impl WelcomeStorage for SqliteAccountStorage {
    fn put_welcome(&self, welcome: &PendingWelcome) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT OR REPLACE INTO cgka_welcomes (message_id, group_id, record)
                 VALUES (?1, ?2, ?3)",
                params![
                    welcome.message_id.as_slice(),
                    welcome.group_id.as_slice(),
                    serialize(welcome)?
                ],
            )
            .storage()?;
        Ok(())
    }

    fn take_welcome(&self, id: &MessageId) -> StorageResult<PendingWelcome> {
        if self.connection.is_current_thread_transaction_owner() {
            let conn = self.lock()?;
            return take_welcome_on_connection(&conn, id);
        }
        retry_on_busy(|| {
            let mut conn = self.lock()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            let welcome = take_welcome_on_connection(&tx, id)?;
            tx.commit().storage()?;
            Ok(welcome)
        })
    }

    fn list_welcomes(&self) -> StorageResult<Vec<PendingWelcome>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached("SELECT record FROM cgka_welcomes ORDER BY rowid")
            .storage()?;
        let records = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        let mut welcomes = Vec::with_capacity(records.len());
        for record in records {
            match deserialize(&record) {
                Ok(welcome) => welcomes.push(welcome),
                Err(StorageError::Serialization(_)) => {
                    tracing::warn!(
                        target: "storage_sqlite::protocol::storage::welcomes",
                        method = "list_welcomes",
                        "skipping an undecodable pending welcome"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        Ok(welcomes)
    }
}

fn take_welcome_on_connection(conn: &Connection, id: &MessageId) -> StorageResult<PendingWelcome> {
    let record: Vec<u8> = conn
        .query_row_cached(
            "SELECT record FROM cgka_welcomes WHERE message_id = ?1",
            params![id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .storage()?
        .ok_or(StorageError::NotFound)?;
    let welcome = deserialize(&record)?;
    conn.execute_cached(
        "DELETE FROM cgka_welcomes WHERE message_id = ?1",
        params![id.as_slice()],
    )
    .storage()?;
    Ok(welcome)
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::base::test_support::{gid, mid};
    use cgka_traits::storage::{StorageError, WelcomeStorage};
    use cgka_traits::welcome::PendingWelcome;

    #[test]
    fn welcome_take_is_one_shot() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let welcome = PendingWelcome {
            message_id: mid(1),
            group_id: gid(1),
            welcome_bytes: vec![1, 2, 3],
            rejoin: None,
        };
        store.put_welcome(&welcome).unwrap();
        assert_eq!(store.list_welcomes().unwrap(), vec![welcome.clone()]);
        assert_eq!(store.take_welcome(&mid(1)).unwrap(), welcome);
        assert!(matches!(
            store.take_welcome(&mid(1)),
            Err(StorageError::NotFound)
        ));
    }

    #[test]
    fn take_welcome_retains_row_when_decode_fails() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_welcomes (message_id, group_id, record)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![mid(1).as_slice(), gid(1).as_slice(), b"not json"],
            )
            .unwrap();

        assert!(matches!(
            store.take_welcome(&mid(1)),
            Err(StorageError::Serialization(_))
        ));
        let remaining: i64 = store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM cgka_welcomes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn list_welcomes_skips_an_undecodable_row() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let welcome = PendingWelcome {
            message_id: mid(2),
            group_id: gid(1),
            welcome_bytes: vec![1, 2, 3],
            rejoin: None,
        };
        store.put_welcome(&welcome).unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_welcomes (message_id, group_id, record)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![mid(1).as_slice(), gid(1).as_slice(), b"not json"],
            )
            .unwrap();

        assert_eq!(store.list_welcomes().unwrap(), vec![welcome]);
    }

    #[test]
    fn take_welcome_reuses_outer_engine_transaction() {
        use cgka_traits::storage::StorageProvider;

        let store = SqliteAccountStorage::in_memory().unwrap();
        let welcome = PendingWelcome {
            message_id: mid(1),
            group_id: gid(1),
            welcome_bytes: vec![1, 2, 3],
            rejoin: None,
        };
        store.put_welcome(&welcome).unwrap();

        let result: Result<(), StorageError> = store.with_transaction(|storage| {
            assert_eq!(storage.take_welcome(&mid(1))?, welcome);
            Err(StorageError::Backend("force rollback".to_owned()))
        });

        // Only the injected error proves the take ran inside the transaction:
        // a nested-transaction failure is also `Backend`.
        assert!(
            matches!(&result, Err(StorageError::Backend(message)) if message == "force rollback"),
            "{result:?}"
        );
        assert_eq!(store.take_welcome(&mid(1)).unwrap(), welcome);
    }

    #[test]
    fn take_welcome_retries_concurrent_writer_contention() {
        use crate::protocol::storage::write_contention::SharedDatabase;

        let db = SharedDatabase::new(50);
        let store = db.open();
        let welcome = PendingWelcome {
            message_id: mid(1),
            group_id: gid(1),
            welcome_bytes: vec![1, 2, 3],
            rejoin: None,
        };
        store.put_welcome(&welcome).unwrap();

        let blocker = db.hold_write_lock(|_| {});
        assert_eq!(
            store
                .take_welcome(&mid(1))
                .expect("welcome take retries after transient contention"),
            welcome
        );
        blocker.join().unwrap();
    }
}
