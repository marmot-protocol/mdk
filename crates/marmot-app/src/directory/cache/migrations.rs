//! Independent schema history for app-cache.sqlite3, including plaintext legacy imports.
use cgka_traits::storage::StorageError;
use rusqlite::{Connection, Transaction, TransactionBehavior, params};

use super::{AppError, DirectoryCache};

struct Migration {
    version: i64,
    name: &'static str,
    apply: fn(&Transaction<'_>) -> Result<(), AppError>,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "0001_directory_cache",
    apply: version_1,
}];

const VERSION_1_SQL: &str = include_str!("v1.sql");

pub(super) fn run_all(conn: &mut Connection) -> Result<(), AppError> {
    // SQLite/JSON errors can contain database-controlled names or values.
    // Keep the typed downgrade error, but never surface those private details.
    run(conn, MIGRATIONS).map_err(|error| match error {
        AppError::Storage(StorageError::UnsupportedSchemaVersion { .. }) => error,
        _ => StorageError::Backend("directory cache schema migration failed".into()).into(),
    })
}

fn run(conn: &mut Connection, migrations: &[Migration]) -> Result<(), AppError> {
    let mut previous = 0;
    for migration in migrations {
        if migration.version <= previous {
            return Err(invalid_history());
        }
        previous = migration.version;
    }
    let latest_supported = previous;
    for migration in migrations {
        // Lock before reading history so concurrent openers cannot both apply a
        // migration. Even ledger creation is rolled back on first-open failure.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS app_cache_schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at_unix_seconds INTEGER NOT NULL
            );",
        )?;
        let recorded = {
            let mut statement = tx.prepare(
                "SELECT version, name FROM app_cache_schema_migrations ORDER BY version",
            )?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        if let Some((found, _)) = recorded.last()
            && *found > latest_supported
        {
            return Err(StorageError::UnsupportedSchemaVersion {
                found: *found,
                latest_supported,
            }
            .into());
        }
        // History must be a prefix, with exactly the compiled names. Check all
        // rows before any pending migration can change the database.
        for (index, (version, name)) in recorded.iter().enumerate() {
            let Some(expected) = migrations.get(index) else {
                return Err(invalid_history());
            };
            if *version != expected.version || name != expected.name {
                return Err(invalid_history());
            }
        }
        if !recorded
            .iter()
            .any(|(version, _)| *version == migration.version)
        {
            (migration.apply)(&tx)?;
            tx.execute(
                "INSERT INTO app_cache_schema_migrations
                    (version, name, applied_at_unix_seconds)
                 VALUES (?1, ?2, CAST(strftime('%s', 'now') AS INTEGER))",
                params![migration.version, migration.name],
            )?;
        }
        tx.commit()?;
    }
    Ok(())
}

fn invalid_history() -> AppError {
    StorageError::Backend("invalid directory cache migration history".into()).into()
}

fn version_1(tx: &Transaction<'_>) -> Result<(), AppError> {
    tx.execute_batch(VERSION_1_SQL)?;
    validate_version_1(tx)?;
    DirectoryCache::migrate_legacy_json_records(tx)
}

/// IF NOT EXISTS can adopt an existing table without checking its shape. Use
/// the frozen v1 DDL as the reference, including types, nullability, defaults,
/// primary keys and index columns, before blessing an unversioned database.
/// The reference is empty and memory-only; no cached records leave SQLCipher.
fn validate_version_1(conn: &Connection) -> Result<(), AppError> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(VERSION_1_SQL)?;
    let mut statement = reference.prepare(
        "SELECT type, name FROM sqlite_master WHERE type IN ('table', 'index')
         AND name NOT LIKE 'sqlite_%'",
    )?;
    let objects = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for object in objects {
        let (kind, name) = object?;
        let object_query = "SELECT type, tbl_name FROM sqlite_master WHERE name = ?1";
        let expected: (String, String) =
            reference.query_row(object_query, [&name], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let actual: (String, String) =
            conn.query_row(object_query, [&name], |row| Ok((row.get(0)?, row.get(1)?)))?;
        if actual != expected {
            return Err(invalid_history());
        }
        if kind == "index" {
            let query = r#"SELECT "unique", partial FROM pragma_index_list(?1) WHERE name = ?2"#;
            let flags = |db: &Connection| -> rusqlite::Result<(i64, i64)> {
                db.query_row(query, [&expected.1, &name], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
            };
            if flags(conn)? != flags(&reference)? {
                return Err(invalid_history());
            }
        }
        // Names come exclusively from our frozen DDL, never stored user data.
        let query = if kind == "table" {
            format!(
                "SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info('{name}') ORDER BY cid"
            )
        } else {
            format!("SELECT name, '', 0, NULL, 0 FROM pragma_index_info('{name}') ORDER BY seqno")
        };
        if shape(conn, &query)? != shape(&reference, &query)? {
            return Err(invalid_history());
        }
    }
    Ok(())
}

type ColumnShape = (String, String, i64, Option<String>, i64);

fn shape(conn: &Connection, query: &str) -> Result<Vec<ColumnShape>, AppError> {
    Ok(conn
        .prepare(query)?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<Result<_, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_rejects_missing_columns_keys_and_wrong_indexes() {
        for mutation in [
            "ALTER TABLE directory_users DROP COLUMN profile_json",
            "ALTER TABLE directory_search_graph_users DROP COLUMN metadata_expires_at",
            "DROP TABLE directory_known_user_reasons; CREATE TABLE directory_known_user_reasons (
                account_id_hex TEXT NOT NULL, reason TEXT NOT NULL,
                first_seen_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL)",
            "DROP INDEX directory_user_follows_follow_idx;
                CREATE INDEX directory_user_follows_follow_idx ON directory_user_follows(position)",
            "DROP INDEX directory_user_follows_follow_idx;
                CREATE UNIQUE INDEX directory_user_follows_follow_idx ON directory_user_follows(follow_account_id_hex)",
        ] {
            let mut conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(VERSION_1_SQL).unwrap();
            conn.execute_batch(mutation).unwrap();
            assert!(run_all(&mut conn).is_err(), "{mutation}");
            assert!(!DirectoryCache::table_exists_locked(&conn, "app_cache_schema_migrations").unwrap());
        }
    }

    #[test]
    fn migration_adopts_frozen_unversioned_schema() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(VERSION_1_SQL).unwrap();
        conn.execute_batch(
            "INSERT INTO directory_search_graph_users
            (account_id_hex, npub, profile_json, metadata_updated_at, metadata_expires_at,
             follows_known, follows_updated_at, created_at, updated_at)
            VALUES ('search', 'npub', '{}', 10, 20, 1, 12, 8, 14);
            INSERT INTO directory_search_graph_follows VALUES ('search', 'friend', 0, 12);",
        )
        .unwrap();
        let before: String = conn
            .query_row(
                "SELECT json_array(account_id_hex, npub, profile_json, metadata_updated_at,
                metadata_expires_at, follows_known, follows_updated_at, created_at, updated_at)
             FROM directory_search_graph_users",
                [],
                |row| row.get(0),
            )
            .unwrap();
        run_all(&mut conn).unwrap();
        let after: String = conn
            .query_row(
                "SELECT json_array(account_id_hex, npub, profile_json, metadata_updated_at,
                metadata_expires_at, follows_known, follows_updated_at, created_at, updated_at)
             FROM directory_search_graph_users",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(before, after);
        let friend: String = conn
            .query_row(
                "SELECT follow_account_id_hex FROM directory_search_graph_follows",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(friend, "friend");
    }

    #[test]
    fn migration_ledger_insert_failure_rolls_back_body() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_all(&mut conn).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_migration BEFORE INSERT ON app_cache_schema_migrations
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
        let migrations = [
            Migration {
                version: 1,
                name: MIGRATIONS[0].name,
                apply: version_1,
            },
            Migration {
                version: 2,
                name: "0002_test",
                apply: |tx| {
                    tx.execute_batch(
                        "CREATE TABLE rollback_probe (value INTEGER);
                    INSERT INTO rollback_probe VALUES (1);
                    INSERT INTO directory_known_user_reasons VALUES ('test', 'test', 0, 0);",
                    )?;
                    Ok(())
                },
            },
        ];
        assert!(run(&mut conn, &migrations).is_err());
        assert!(!DirectoryCache::table_exists_locked(&conn, "rollback_probe").unwrap());
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM directory_known_user_reasons",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM app_cache_schema_migrations",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
