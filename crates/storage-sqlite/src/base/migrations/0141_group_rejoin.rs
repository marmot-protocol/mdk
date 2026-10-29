//! Migration 0141: bounded durable authenticated group-rejoin handshakes.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS cgka_group_rejoin (
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    role INTEGER NOT NULL CHECK (role IN (0, 1)),
    request_id BLOB NOT NULL CHECK (length(request_id) = 32),
    record BLOB NOT NULL,
    PRIMARY KEY (group_id, role, request_id)
) WITHOUT ROWID;
CREATE UNIQUE INDEX IF NOT EXISTS cgka_group_rejoin_recipient_idx
    ON cgka_group_rejoin (group_id) WHERE role = 0;
CREATE INDEX IF NOT EXISTS cgka_group_rejoin_role_idx
    ON cgka_group_rejoin (role, group_id);
"#,
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::migrations::{MIGRATIONS, run, run_all};
    use crate::base::test_support::{gid, sample_group};
    use cgka_traits::storage::StorageError;
    use rusqlite::{Connection, params};

    #[test]
    fn group_rejoin_migration() {
        let mut connection = Connection::open_in_memory().unwrap();
        let index = MIGRATIONS
            .iter()
            .position(|migration| migration.version == 141)
            .unwrap();
        run(&mut connection, &MIGRATIONS[..index]).unwrap();
        let group = sample_group(gid(1), 23, 2);
        let original = crate::serialize(&group).unwrap();
        connection
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, 23, ?2)",
                params![group.id.as_slice(), original],
            )
            .unwrap();
        {
            let transaction = connection.transaction().unwrap();
            apply(&transaction).unwrap();
            transaction.rollback().unwrap();
        }
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'cgka_group_rejoin')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!present);
        assert_eq!(run_all(&mut connection).unwrap(), 1);
        let preserved: Vec<u8> = connection
            .query_row(
                "SELECT record FROM cgka_groups WHERE id = ?1",
                params![group.id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(preserved, original);
        assert!(matches!(
            run(&mut connection, &MIGRATIONS[..index]),
            Err(StorageError::UnsupportedSchemaVersion {
                found: 141,
                latest_supported: 140
            })
        ));
        assert_eq!(run_all(&mut connection).unwrap(), 0);
    }
}
