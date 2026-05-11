#[path = "migrations/0001_initial_schema.rs"]
mod migration_0001_initial_schema;
#[path = "migrations/0002_account_device_signers.rs"]
mod migration_0002_account_device_signers;

use crate::SqliteResultExt;
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub(crate) struct Migration {
    pub(crate) version: i64,
    pub(crate) name: &'static str,
    pub(crate) apply: fn(&Transaction<'_>) -> StorageResult<()>,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_initial_schema",
        apply: migration_0001_initial_schema::apply,
    },
    Migration {
        version: 2,
        name: "0002_account_device_signers",
        apply: migration_0002_account_device_signers::apply,
    },
];

pub(crate) fn run_all(connection: &mut Connection) -> StorageResult<()> {
    run(connection, MIGRATIONS)
}

pub(crate) fn run(connection: &mut Connection, migrations: &[Migration]) -> StorageResult<()> {
    ensure_migration_table(connection)?;
    ensure_ordered(migrations)?;
    reject_unknown_future_migrations(connection, migrations)?;

    for migration in migrations {
        match applied_name(connection, migration.version)? {
            Some(name) if name == migration.name => continue,
            Some(name) => {
                return Err(StorageError::Backend(format!(
                    "migration {} was applied as {name}, expected {}",
                    migration.version, migration.name
                )));
            }
            None => apply_migration(connection, migration)?,
        }
    }

    Ok(())
}

fn ensure_migration_table(connection: &Connection) -> StorageResult<()> {
    connection
        .execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS cgka_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_unix_seconds INTEGER NOT NULL
);
"#,
        )
        .storage()
}

fn ensure_ordered(migrations: &[Migration]) -> StorageResult<()> {
    let mut previous = None;
    for migration in migrations {
        if migration.version <= 0 {
            return Err(StorageError::Backend(format!(
                "migration versions must be positive: {}",
                migration.version
            )));
        }
        if let Some(previous) = previous
            && migration.version <= previous
        {
            return Err(StorageError::Backend(format!(
                "migrations must be strictly ordered: {previous} then {}",
                migration.version
            )));
        }
        previous = Some(migration.version);
    }
    Ok(())
}

fn reject_unknown_future_migrations(
    connection: &Connection,
    migrations: &[Migration],
) -> StorageResult<()> {
    let latest_known = migrations.last().map(|m| m.version).unwrap_or(0);
    let unknown: Option<i64> = connection
        .query_row(
            "SELECT version FROM cgka_schema_migrations
             WHERE version > ?1
             ORDER BY version DESC
             LIMIT 1",
            params![latest_known],
            |row| row.get(0),
        )
        .optional()
        .storage()?;
    if let Some(version) = unknown {
        return Err(StorageError::Backend(format!(
            "database was migrated by a newer storage-sqlite version: {version}"
        )));
    }
    Ok(())
}

fn applied_name(connection: &Connection, version: i64) -> StorageResult<Option<String>> {
    connection
        .query_row(
            "SELECT name FROM cgka_schema_migrations WHERE version = ?1",
            params![version],
            |row| row.get(0),
        )
        .optional()
        .storage()
}

fn apply_migration(connection: &mut Connection, migration: &Migration) -> StorageResult<()> {
    let tx = connection.transaction().storage()?;
    (migration.apply)(&tx)?;
    tx.execute(
        "INSERT INTO cgka_schema_migrations
            (version, name, applied_at_unix_seconds)
         VALUES (?1, ?2, CAST(strftime('%s', 'now') AS INTEGER))",
        params![migration.version, migration.name],
    )
    .storage()?;
    tx.commit().storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SqlCipherKey, SqliteStorage};

    fn applied_migrations(store: &SqliteStorage) -> Vec<(i64, String)> {
        let conn = store.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT version, name FROM cgka_schema_migrations ORDER BY version")
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    #[test]
    fn initial_schema_migration_is_recorded() {
        let store = SqliteStorage::in_memory().unwrap();
        assert_eq!(
            applied_migrations(&store),
            vec![
                (1, "0001_initial_schema".to_string()),
                (2, "0002_account_device_signers".to_string())
            ]
        );
    }

    #[test]
    fn encrypted_reopen_does_not_reapply_migrations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("migration key").unwrap();

        {
            let store = SqliteStorage::open_encrypted(&path, &key).unwrap();
            assert_eq!(applied_migrations(&store).len(), 2);
        }

        let reopened = SqliteStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            applied_migrations(&reopened),
            vec![
                (1, "0001_initial_schema".to_string()),
                (2, "0002_account_device_signers".to_string())
            ]
        );
    }

    #[test]
    fn rust_migrations_can_transform_existing_data() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let migrations = [
            Migration {
                version: 1,
                name: "0001_create_fixture",
                apply: |tx| {
                    tx.execute_batch(
                        "CREATE TABLE transform_fixture (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                         INSERT INTO transform_fixture (id, value) VALUES (1, 'needs-transform');",
                    )
                    .storage()
                },
            },
            Migration {
                version: 2,
                name: "0002_transform_fixture",
                apply: |tx| {
                    let value: String = tx
                        .query_row(
                            "SELECT value FROM transform_fixture WHERE id = 1",
                            [],
                            |row| row.get(0),
                        )
                        .storage()?;
                    tx.execute(
                        "UPDATE transform_fixture SET value = ?1 WHERE id = 1",
                        [value.replace("needs", "did")],
                    )
                    .storage()?;
                    Ok(())
                },
            },
        ];

        run(&mut conn, &migrations).unwrap();

        let transformed: String = conn
            .query_row(
                "SELECT value FROM transform_fixture WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(transformed, "did-transform");
    }
}
