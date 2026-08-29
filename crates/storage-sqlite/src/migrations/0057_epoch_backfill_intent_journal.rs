//! Migration 0053: durable per-account epoch-backfill intent state.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE app_epoch_backfill_intent_journal (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    record BLOB NOT NULL
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
    fn migration_adds_an_empty_singleton_blob_journal_after_schema_56() {
        let mut connection = Connection::open_in_memory().unwrap();
        run(&mut connection, &MIGRATIONS[..56]).unwrap();
        let absent: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name = 'app_epoch_backfill_intent_journal'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(absent, None);

        run(&mut connection, &MIGRATIONS[..57]).unwrap();

        let initial: Option<Vec<u8>> = connection
            .query_row(
                "SELECT record FROM app_epoch_backfill_intent_journal WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(initial, None, "migration must not synthesize an intent");

        let opaque = [0_u8, 0xff, 0x80, 0x00];
        connection
            .execute(
                "INSERT INTO app_epoch_backfill_intent_journal (singleton, record)
                 VALUES (1, ?1)",
                params![opaque.as_slice()],
            )
            .unwrap();
        let stored: Vec<u8> = connection
            .query_row(
                "SELECT record FROM app_epoch_backfill_intent_journal WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, opaque);

        assert!(
            connection
                .execute(
                    "INSERT INTO app_epoch_backfill_intent_journal (singleton, record)
                     VALUES (2, ?1)",
                    params![opaque.as_slice()],
                )
                .is_err(),
            "the per-account journal must admit only its singleton row"
        );
    }

    #[test]
    fn schema_56_runner_refuses_a_journal_database_without_mutating_the_blob() {
        let mut connection = Connection::open_in_memory().unwrap();
        run(&mut connection, &MIGRATIONS[..57]).unwrap();
        let opaque = [0_u8, 0xff, 0x80, 0x00];
        connection
            .execute(
                "INSERT INTO app_epoch_backfill_intent_journal (singleton, record)
                 VALUES (1, ?1)",
                params![opaque.as_slice()],
            )
            .unwrap();

        let error = run(&mut connection, &MIGRATIONS[..56]).unwrap_err();
        assert!(matches!(
            error,
            StorageError::UnsupportedSchemaVersion {
                found: 57,
                latest_supported: 56,
            }
        ));
        let retained: Vec<u8> = connection
            .query_row(
                "SELECT record FROM app_epoch_backfill_intent_journal WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, opaque);
    }
}
