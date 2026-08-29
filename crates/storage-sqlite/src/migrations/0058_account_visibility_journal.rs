//! Migration 0058: durable ordered account-runtime visibility outbox.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE account_visibility_journal (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id BLOB NOT NULL CHECK (length(operation_id) > 0),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    batch_id BLOB NOT NULL UNIQUE CHECK (length(batch_id) > 0),
    record BLOB NOT NULL,
    UNIQUE (operation_id, ordinal)
);
"#,
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::migrations::{MIGRATIONS, run};
    use cgka_traits::storage::StorageError;
    use rusqlite::{Connection, OptionalExtension, params};

    #[test]
    fn migration_adds_an_empty_ordered_visibility_journal_after_schema_57() {
        let mut connection = Connection::open_in_memory().unwrap();
        run(&mut connection, &MIGRATIONS[..57]).unwrap();
        let absent: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name = 'account_visibility_journal'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(absent, None);

        run(&mut connection, MIGRATIONS).unwrap();
        let initial: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM account_visibility_journal",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(initial, 0, "migration must not synthesize visibility");

        let operation = [0_u8, 0xff, 0x80];
        let batch = [9_u8, 0, 8];
        let record = [7_u8, 0xff, 6, 0];
        connection
            .execute(
                "INSERT INTO account_visibility_journal
                    (operation_id, ordinal, batch_id, record)
                 VALUES (?1, 0, ?2, ?3)",
                params![operation.as_slice(), batch.as_slice(), record.as_slice()],
            )
            .unwrap();
        let stored: (Vec<u8>, i64, Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT operation_id, ordinal, batch_id, record
                 FROM account_visibility_journal",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            stored,
            (operation.to_vec(), 0, batch.to_vec(), record.to_vec())
        );
    }

    #[test]
    fn schema_57_runner_refuses_a_visibility_journal_database_without_mutating_rows() {
        let mut connection = Connection::open_in_memory().unwrap();
        run(&mut connection, MIGRATIONS).unwrap();
        let operation = [1_u8, 2, 3];
        let batch = [4_u8, 5, 6];
        let record = [0_u8, 0xff, 0x80, 0x00];
        connection
            .execute(
                "INSERT INTO account_visibility_journal
                    (operation_id, ordinal, batch_id, record)
                 VALUES (?1, 0, ?2, ?3)",
                params![operation.as_slice(), batch.as_slice(), record.as_slice()],
            )
            .unwrap();

        let error = run(&mut connection, &MIGRATIONS[..57]).unwrap_err();
        assert!(matches!(
            error,
            StorageError::UnsupportedSchemaVersion {
                found: 58,
                latest_supported: 57,
            }
        ));
        let retained: Vec<u8> = connection
            .query_row(
                "SELECT record FROM account_visibility_journal WHERE batch_id = ?1",
                params![batch.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, record);
    }
}
