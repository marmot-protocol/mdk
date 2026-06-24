#[path = "migrations/0001_initial_schema.rs"]
mod migration_0001_initial_schema;
#[path = "migrations/0002_account_device_signers.rs"]
mod migration_0002_account_device_signers;
#[path = "migrations/0003_group_foreign_keys.rs"]
mod migration_0003_group_foreign_keys;
#[path = "migrations/0004_app_timeline.rs"]
mod migration_0004_app_timeline;
#[path = "migrations/0005_account_projection.rs"]
mod migration_0005_account_projection;
#[path = "migrations/0006_chat_list_projection.rs"]
mod migration_0006_chat_list_projection;
#[path = "migrations/0007_timeline_projection_indexes.rs"]
mod migration_0007_timeline_projection_indexes;
#[path = "migrations/0008_timeline_invalidation_status.rs"]
mod migration_0008_timeline_invalidation_status;
#[path = "migrations/0009_app_event_source_epoch.rs"]
mod migration_0009_app_event_source_epoch;
#[path = "migrations/0010_encrypted_media_epoch_secrets.rs"]
mod migration_0010_encrypted_media_epoch_secrets;
#[path = "migrations/0011_chat_list_avatar_url.rs"]
mod migration_0011_chat_list_avatar_url;
#[path = "migrations/0012_app_event_origin_commit.rs"]
mod migration_0012_app_event_origin_commit;
#[path = "migrations/0013_app_event_kind_order_index.rs"]
mod migration_0013_app_event_kind_order_index;
#[path = "migrations/0014_message_timeline_reply_lookup_index.rs"]
mod migration_0014_message_timeline_reply_lookup_index;
#[path = "migrations/0015_member_validation_cache.rs"]
mod migration_0015_member_validation_cache;
#[path = "migrations/0016_leave_requests.rs"]
mod migration_0016_leave_requests;
#[path = "migrations/0017_notification_settings_default_on.rs"]
mod migration_0017_notification_settings_default_on;
#[path = "migrations/0018_account_group_self_membership.rs"]
mod migration_0018_account_group_self_membership;
#[path = "migrations/0019_chat_list_unread_mention_count.rs"]
mod migration_0019_chat_list_unread_mention_count;

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
    Migration {
        version: 3,
        name: "0003_group_foreign_keys",
        apply: migration_0003_group_foreign_keys::apply,
    },
    Migration {
        version: 4,
        name: "0004_app_timeline",
        apply: migration_0004_app_timeline::apply,
    },
    Migration {
        version: 5,
        name: "0005_account_projection",
        apply: migration_0005_account_projection::apply,
    },
    Migration {
        version: 6,
        name: "0006_chat_list_projection",
        apply: migration_0006_chat_list_projection::apply,
    },
    Migration {
        version: 7,
        name: "0007_timeline_projection_indexes",
        apply: migration_0007_timeline_projection_indexes::apply,
    },
    Migration {
        version: 8,
        name: "0008_timeline_invalidation_status",
        apply: migration_0008_timeline_invalidation_status::apply,
    },
    Migration {
        version: 9,
        name: "0009_app_event_source_epoch",
        apply: migration_0009_app_event_source_epoch::apply,
    },
    Migration {
        version: 10,
        name: "0010_encrypted_media_epoch_secrets",
        apply: migration_0010_encrypted_media_epoch_secrets::apply,
    },
    Migration {
        version: 11,
        name: "0011_chat_list_avatar_url",
        apply: migration_0011_chat_list_avatar_url::apply,
    },
    Migration {
        version: 12,
        name: "0012_app_event_origin_commit",
        apply: migration_0012_app_event_origin_commit::apply,
    },
    Migration {
        version: 13,
        name: "0013_app_event_kind_order_index",
        apply: migration_0013_app_event_kind_order_index::apply,
    },
    Migration {
        version: 14,
        name: "0014_message_timeline_reply_lookup_index",
        apply: migration_0014_message_timeline_reply_lookup_index::apply,
    },
    Migration {
        version: 15,
        name: "0015_member_validation_cache",
        apply: migration_0015_member_validation_cache::apply,
    },
    Migration {
        version: 16,
        name: "0016_leave_requests",
        apply: migration_0016_leave_requests::apply,
    },
    Migration {
        version: 17,
        name: "0017_notification_settings_default_on",
        apply: migration_0017_notification_settings_default_on::apply,
    },
    Migration {
        version: 18,
        name: "0018_account_group_self_membership",
        apply: migration_0018_account_group_self_membership::apply,
    },
    Migration {
        version: 19,
        name: "0019_chat_list_unread_mention_count",
        apply: migration_0019_chat_list_unread_mention_count::apply,
    },
];

pub(crate) fn run_all(connection: &mut Connection) -> StorageResult<()> {
    run(connection, MIGRATIONS)
}

pub(crate) fn run(connection: &mut Connection, migrations: &[Migration]) -> StorageResult<()> {
    ensure_migration_table(connection)?;
    ensure_ordered(migrations)?;
    reconcile_legacy_migration_names(connection, migrations)?;
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

fn reconcile_legacy_migration_names(
    connection: &mut Connection,
    migrations: &[Migration],
) -> StorageResult<()> {
    const LEGACY_CHAT_LIST_AVATAR_URL: &str = "0009_chat_list_avatar_url";
    const APP_EVENT_SOURCE_EPOCH: &str = "0009_app_event_source_epoch";

    let expects_app_event_source_epoch = migrations
        .iter()
        .any(|migration| migration.version == 9 && migration.name == APP_EVENT_SOURCE_EPOCH);
    if !expects_app_event_source_epoch {
        return Ok(());
    }

    let Some(applied) = applied_name(connection, 9)? else {
        return Ok(());
    };
    if applied != LEGACY_CHAT_LIST_AVATAR_URL {
        return Ok(());
    }

    let tx = connection.transaction().storage()?;
    add_column_if_missing(&tx, "app_events", "source_epoch", "INTEGER")?;
    add_column_if_missing(&tx, "message_timeline", "source_epoch", "INTEGER")?;
    tx.execute(
        "UPDATE cgka_schema_migrations
            SET name = ?1
          WHERE version = 9
            AND name = ?2",
        params![APP_EVENT_SOURCE_EPOCH, LEGACY_CHAT_LIST_AVATAR_URL],
    )
    .storage()?;
    tx.commit().storage()
}

fn add_column_if_missing(
    tx: &Transaction<'_>,
    table: &str,
    column: &str,
    definition: &str,
) -> StorageResult<()> {
    if table_has_column(tx, table, column)? {
        return Ok(());
    }
    tx.execute_batch(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {definition};"
    ))
    .storage()
}

fn table_has_column(tx: &Transaction<'_>, table: &str, column: &str) -> StorageResult<bool> {
    let mut statement = tx
        .prepare(&format!("PRAGMA table_info({table})"))
        .storage()?;
    let mut rows = statement.query([]).storage()?;
    while let Some(row) = rows.next().storage()? {
        let name: String = row.get("name").storage()?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
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
    use crate::{SqlCipherKey, SqliteAccountStorage};

    fn applied_migrations(store: &SqliteAccountStorage) -> Vec<(i64, String)> {
        let conn = store.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT version, name FROM cgka_schema_migrations ORDER BY version")
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn expected_migrations() -> Vec<(i64, String)> {
        MIGRATIONS
            .iter()
            .map(|migration| (migration.version, migration.name.to_string()))
            .collect()
    }

    #[test]
    fn initial_schema_migration_is_recorded() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        assert_eq!(applied_migrations(&store), expected_migrations());
    }

    #[test]
    fn message_timeline_reply_lookup_index_is_migrated() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let conn = store.lock().unwrap();
        assert!(connection_has_index(
            &conn,
            "message_timeline",
            "idx_message_timeline_reply_lookup"
        ));
    }

    #[test]
    fn notification_settings_default_migration_preserves_existing_choices() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        // Versions 1-16 are the schema state immediately before
        // 0017_notification_settings_default_on.
        run(&mut conn, &MIGRATIONS[..16]).unwrap();
        assert_eq!(
            column_default(
                &conn,
                "notification_settings",
                "local_notifications_enabled"
            )
            .as_deref(),
            Some("0")
        );
        conn.execute(
            "INSERT INTO notification_settings (
                account_label, account_id_hex, native_push_enabled, updated_at_ms
             )
             VALUES ('legacy-default', 'aa', 0, 10)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO notification_settings (
                account_label, account_id_hex, local_notifications_enabled,
                native_push_enabled, updated_at_ms
             )
             VALUES ('explicit-on', 'bb', 1, 0, 11)",
            [],
        )
        .unwrap();

        run(&mut conn, MIGRATIONS).unwrap();

        assert_eq!(
            column_default(
                &conn,
                "notification_settings",
                "local_notifications_enabled"
            )
            .as_deref(),
            Some("1")
        );
        let preserved_disabled: i64 = conn
            .query_row(
                "SELECT local_notifications_enabled
                 FROM notification_settings
                 WHERE account_label = 'legacy-default'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(preserved_disabled, 0);
        let preserved_enabled: i64 = conn
            .query_row(
                "SELECT local_notifications_enabled
                 FROM notification_settings
                 WHERE account_label = 'explicit-on'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(preserved_enabled, 1);

        conn.execute(
            "INSERT INTO notification_settings (
                account_label, account_id_hex, native_push_enabled, updated_at_ms
             )
             VALUES ('new-default', 'cc', 0, 12)",
            [],
        )
        .unwrap();
        let new_default: i64 = conn
            .query_row(
                "SELECT local_notifications_enabled
                 FROM notification_settings
                 WHERE account_label = 'new-default'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(new_default, 1);
    }

    #[test]
    fn account_group_self_membership_migration_defaults_existing_rows_to_member() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        // Versions 1-17 are the schema state immediately before
        // 0018_account_group_self_membership.
        run(&mut conn, &MIGRATIONS[..17]).unwrap();
        assert!(!connection_has_column(
            &conn,
            "account_groups",
            "self_membership"
        ));
        conn.execute(
            "INSERT INTO account_groups (group_id_hex, endpoint, updated_at)
             VALUES ('11', 'relay', 1)",
            [],
        )
        .unwrap();

        run(&mut conn, MIGRATIONS).unwrap();

        assert!(connection_has_column(
            &conn,
            "account_groups",
            "self_membership"
        ));
        assert_eq!(
            column_default(&conn, "account_groups", "self_membership").as_deref(),
            Some("'member'")
        );
        let legacy_membership: String = conn
            .query_row(
                "SELECT self_membership FROM account_groups WHERE group_id_hex = '11'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_membership, "member");
    }

    #[test]
    fn encrypted_reopen_does_not_reapply_migrations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("migration key").unwrap();

        {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            assert_eq!(applied_migrations(&store).len(), MIGRATIONS.len());
        }

        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(applied_migrations(&reopened), expected_migrations());
    }

    #[test]
    fn canonical_pre_avatar_database_upgrades_through_current_migrations() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..8]).unwrap();
        assert_eq!(
            applied_name(&conn, 8).unwrap().as_deref(),
            Some("0008_timeline_invalidation_status")
        );
        assert_eq!(applied_name(&conn, 9).unwrap(), None);
        assert!(!connection_has_column(&conn, "app_events", "source_epoch"));
        assert!(!connection_has_column(
            &conn,
            "chat_list_rows",
            "avatar_url"
        ));

        run(&mut conn, MIGRATIONS).unwrap();

        assert_eq!(
            applied_name(&conn, 9).unwrap().as_deref(),
            Some("0009_app_event_source_epoch")
        );
        assert_eq!(
            applied_name(&conn, 11).unwrap().as_deref(),
            Some("0011_chat_list_avatar_url")
        );
        assert!(connection_has_column(&conn, "app_events", "source_epoch"));
        assert!(connection_has_column(
            &conn,
            "encrypted_media_epoch_secrets",
            "secret"
        ));
        assert!(connection_has_column(&conn, "chat_list_rows", "avatar_url"));
        assert_eq!(
            applied_migrations_from_connection(&conn),
            expected_migrations()
        );
    }

    #[test]
    fn legacy_chat_list_avatar_migration_slot_is_reconciled() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let legacy_migrations = [
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
            Migration {
                version: 3,
                name: "0003_group_foreign_keys",
                apply: migration_0003_group_foreign_keys::apply,
            },
            Migration {
                version: 4,
                name: "0004_app_timeline",
                apply: migration_0004_app_timeline::apply,
            },
            Migration {
                version: 5,
                name: "0005_account_projection",
                apply: migration_0005_account_projection::apply,
            },
            Migration {
                version: 6,
                name: "0006_chat_list_projection",
                apply: migration_0006_chat_list_projection::apply,
            },
            Migration {
                version: 7,
                name: "0007_timeline_projection_indexes",
                apply: migration_0007_timeline_projection_indexes::apply,
            },
            Migration {
                version: 8,
                name: "0008_timeline_invalidation_status",
                apply: migration_0008_timeline_invalidation_status::apply,
            },
            Migration {
                version: 9,
                name: "0009_chat_list_avatar_url",
                apply: |tx| {
                    tx.execute_batch("ALTER TABLE chat_list_rows ADD COLUMN avatar_url TEXT;")
                        .storage()
                },
            },
        ];
        run(&mut conn, &legacy_migrations).unwrap();
        assert_eq!(
            applied_name(&conn, 9).unwrap().as_deref(),
            Some("0009_chat_list_avatar_url")
        );
        assert!(connection_has_column(&conn, "chat_list_rows", "avatar_url"));
        assert!(!connection_has_column(&conn, "app_events", "source_epoch"));
        assert!(!connection_has_column(
            &conn,
            "message_timeline",
            "source_epoch"
        ));

        run(&mut conn, MIGRATIONS).unwrap();

        assert_eq!(
            applied_name(&conn, 9).unwrap().as_deref(),
            Some("0009_app_event_source_epoch")
        );
        assert!(connection_has_column(&conn, "app_events", "source_epoch"));
        assert!(connection_has_column(
            &conn,
            "message_timeline",
            "source_epoch"
        ));
        assert!(connection_has_column(&conn, "chat_list_rows", "avatar_url"));
        let applied = applied_migrations_from_connection(&conn);
        assert_eq!(applied, expected_migrations());
    }

    #[test]
    fn group_owned_tables_have_cascading_foreign_keys() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let conn = store.lock().unwrap();

        for (table, column) in [
            ("cgka_messages", "group_id"),
            ("cgka_queued_outbound", "group_id"),
            ("cgka_member_capabilities", "group_id"),
            ("cgka_convergence_policies", "group_id"),
            ("cgka_member_validation_cache", "group_id"),
            ("cgka_group_snapshots", "group_id"),
        ] {
            assert_eq!(
                foreign_key(&conn, table, column),
                Some(("cgka_groups".to_owned(), "CASCADE".to_owned())),
                "{table}.{column} should cascade when a group is deleted"
            );
        }
    }

    #[test]
    fn group_owned_tables_reject_orphan_rows() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let conn = store.lock().unwrap();
        let orphan_group = vec![0x99_u8; 4];

        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
             VALUES (?1, ?2, 0, 0, ?3)",
            params![vec![0x01_u8; 4], orphan_group, vec![0xAA_u8]],
        ));
        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_queued_outbound (id, group_id, created_at_ms, record)
             VALUES (?1, ?2, 0, ?3)",
            params![vec![0x02_u8; 4], orphan_group, vec![0xAA_u8]],
        ));
        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_member_capabilities (group_id, member_id, capabilities)
             VALUES (?1, ?2, ?3)",
            params![orphan_group, vec![0x03_u8; 4], vec![0xAA_u8]],
        ));
        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_convergence_policies (group_id, policy)
             VALUES (?1, ?2)",
            params![orphan_group, vec![0xAA_u8]],
        ));
        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_member_validation_cache (group_id, marker)
             VALUES (?1, ?2)",
            params![orphan_group, vec![0xAA_u8]],
        ));
        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_group_snapshots (group_id, name, snapshot)
             VALUES (?1, 'anchor', ?2)",
            params![orphan_group, vec![0xAA_u8]],
        ));
    }

    #[test]
    fn foreign_key_migration_fails_hard_on_existing_orphans() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run(
            &mut conn,
            &[Migration {
                version: 1,
                name: "0001_initial_schema",
                apply: migration_0001_initial_schema::apply,
            }],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
             VALUES (?1, ?2, 0, 0, ?3)",
            params![vec![0x01_u8; 4], vec![0x99_u8; 4], vec![0xAA_u8]],
        )
        .unwrap();

        let result = run(
            &mut conn,
            &[
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
                Migration {
                    version: 3,
                    name: "0003_group_foreign_keys",
                    apply: migration_0003_group_foreign_keys::apply,
                },
            ],
        );

        assert!(result.is_err());
        assert_eq!(applied_name(&conn, 3).unwrap(), None);
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

    fn foreign_key(
        conn: &rusqlite::Connection,
        table: &str,
        column: &str,
    ) -> Option<(String, String)> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA foreign_key_list({table})"))
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(6)?,
            ))
        })
        .unwrap()
        .filter_map(Result::ok)
        .find_map(|(parent_table, from_column, on_delete)| {
            if from_column == column {
                Some((parent_table, on_delete))
            } else {
                None
            }
        })
    }

    fn assert_foreign_key_error(result: rusqlite::Result<usize>) {
        let err = result.expect_err("orphan insert should fail");
        assert!(
            err.to_string().contains("FOREIGN KEY constraint failed"),
            "unexpected error: {err}"
        );
    }

    fn applied_migrations_from_connection(conn: &rusqlite::Connection) -> Vec<(i64, String)> {
        let mut stmt = conn
            .prepare("SELECT version, name FROM cgka_schema_migrations ORDER BY version")
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn connection_has_column(conn: &rusqlite::Connection, table: &str, column: &str) -> bool {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>("name"))
            .unwrap()
            .any(|name| name.as_deref() == Ok(column))
    }

    fn column_default(conn: &rusqlite::Connection, table: &str, column: &str) -> Option<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>("name")?,
                row.get::<_, Option<String>>("dflt_value")?,
            ))
        })
        .unwrap()
        .filter_map(Result::ok)
        .find_map(|(name, default)| if name == column { default } else { None })
    }

    fn connection_has_index(conn: &rusqlite::Connection, table: &str, index: &str) -> bool {
        let mut stmt = conn
            .prepare(&format!("PRAGMA index_list({table})"))
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>("name"))
            .unwrap()
            .any(|name| name.as_deref() == Ok(index))
    }
}
