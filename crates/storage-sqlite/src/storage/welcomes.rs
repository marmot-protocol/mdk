use crate::{
    SqliteAccountStorage, SqliteResultExt, connection::retry_on_busy, deserialize, serialize,
};
use cgka_traits::storage::{StorageError, StorageResult, WelcomeStorage};
use cgka_traits::types::MessageId;
use cgka_traits::welcome::PendingWelcome;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

impl WelcomeStorage for SqliteAccountStorage {
    fn put_welcome(&self, welcome: &PendingWelcome) -> StorageResult<()> {
        self.lock()?
            .execute(
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
            .prepare("SELECT record FROM cgka_welcomes ORDER BY rowid")
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
                        target: "storage_sqlite::welcomes",
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
        .query_row(
            "SELECT record FROM cgka_welcomes WHERE message_id = ?1",
            params![id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .storage()?
        .ok_or(StorageError::NotFound)?;
    let welcome = deserialize(&record)?;
    conn.execute(
        "DELETE FROM cgka_welcomes WHERE message_id = ?1",
        params![id.as_slice()],
    )
    .storage()?;
    Ok(welcome)
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::storage::test_support::{gid, mid};
    use cgka_traits::storage::{StorageError, WelcomeStorage};
    use cgka_traits::welcome::PendingWelcome;

    #[test]
    fn welcome_take_is_one_shot() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let welcome = PendingWelcome {
            message_id: mid(1),
            group_id: gid(1),
            welcome_bytes: vec![1, 2, 3],
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
        };
        store.put_welcome(&welcome).unwrap();

        let result: Result<(), StorageError> = store.with_transaction(|storage| {
            assert_eq!(storage.take_welcome(&mid(1))?, welcome);
            Err(StorageError::Backend("force rollback".to_owned()))
        });

        assert!(result.is_err());
        assert_eq!(store.take_welcome(&mid(1)).unwrap(), welcome);
    }

    #[test]
    fn take_welcome_retries_concurrent_writer_contention() {
        use crate::{SqlCipherKey, SqliteStorageOptions};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("welcome-contention.sqlite");
        let key = SqlCipherKey::new("welcome contention key").unwrap();
        let options = SqliteStorageOptions {
            busy_timeout_ms: 50,
            ..SqliteStorageOptions::default()
        };
        let store = SqliteAccountStorage::open_encrypted_with_options(&path, &key, options.clone())
            .unwrap();
        let welcome = PendingWelcome {
            message_id: mid(1),
            group_id: gid(1),
            welcome_bytes: vec![1, 2, 3],
        };
        store.put_welcome(&welcome).unwrap();

        let blocker_path = path.clone();
        let blocker_key = SqlCipherKey::new("welcome contention key").unwrap();
        let (lock_acquired_tx, lock_acquired_rx) = std::sync::mpsc::channel();
        let blocker = std::thread::spawn(move || {
            let blocker = SqliteAccountStorage::open_encrypted_with_options(
                &blocker_path,
                &blocker_key,
                options,
            )
            .unwrap();
            let conn = blocker.lock().unwrap();
            conn.execute_batch("BEGIN IMMEDIATE").unwrap();
            lock_acquired_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
            conn.execute_batch("COMMIT").unwrap();
        });
        lock_acquired_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();

        assert_eq!(
            store
                .take_welcome(&mid(1))
                .expect("welcome take retries after transient contention"),
            welcome
        );
        blocker.join().unwrap();
    }
}
