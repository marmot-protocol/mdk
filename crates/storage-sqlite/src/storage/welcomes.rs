use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::storage::{StorageError, StorageResult, WelcomeStorage};
use cgka_traits::types::MessageId;
use cgka_traits::welcome::PendingWelcome;
use rusqlite::{OptionalExtension, params};

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
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let record: Vec<u8> = tx
            .query_row(
                "SELECT record FROM cgka_welcomes WHERE message_id = ?1",
                params![id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?
            .ok_or(StorageError::NotFound)?;
        let welcome = deserialize(&record)?;
        tx.execute(
            "DELETE FROM cgka_welcomes WHERE message_id = ?1",
            params![id.as_slice()],
        )
        .storage()?;
        tx.commit().storage()?;
        Ok(welcome)
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
        records.iter().map(|record| deserialize(record)).collect()
    }
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
}
