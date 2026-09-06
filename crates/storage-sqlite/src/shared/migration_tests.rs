use super::super::*;
use super::*;
use rusqlite::Connection;

fn count(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM shared_schema_migrations", [], |r| {
        r.get(0)
    })
    .unwrap()
}

#[test]
fn fresh_file_preserves_pragmas_permissions_and_close() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.sqlite3");
    let storage = SqliteSharedStorage::open(&path).unwrap();
    {
        let conn = storage.lock().unwrap();
        assert_eq!(count(&conn), 1);
        for (pragma, expected) in [
            ("busy_timeout", 5000),
            ("synchronous", 1),
            ("foreign_keys", 1),
            ("trusted_schema", 0),
            ("temp_store", 2),
        ] {
            assert_eq!(
                conn.query_row(&format!("PRAGMA {pragma}"), [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                expected
            );
        }
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for suffix in ["", "-wal", "-shm"] {
                let file = dir.path().join(format!("shared.sqlite3{suffix}"));
                assert_eq!(
                    std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }
    let clone = storage.clone();
    storage.close().unwrap();
    assert!(matches!(
        clone.telemetry_install_id(),
        Err(StorageError::Closed(_))
    ));
    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.starts_with(b"SQLite format 3\0"));
}

#[test]
fn current_open_is_read_only_and_idempotent_while_writer_holds_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.sqlite3");
    let first = SqliteSharedStorage::open(&path).unwrap();
    let before: i64 = first
        .lock()
        .unwrap()
        .query_row(
            "SELECT applied_at_unix_seconds FROM shared_schema_migrations",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let writer = Connection::open(&path).unwrap();
    writer
        .execute_batch(
            "BEGIN IMMEDIATE; UPDATE shared_schema_migrations SET applied_at_unix_seconds = 0",
        )
        .unwrap();
    let second = SqliteSharedStorage::open(&path).unwrap();
    let conn = second.lock().unwrap();
    assert_eq!(count(&conn), 1);
    assert_eq!(
        conn.query_row(
            "SELECT applied_at_unix_seconds FROM shared_schema_migrations",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        before
    );
    conn.execute_batch("PRAGMA query_only = ON").unwrap();
    drop(conn);
    run_all(&mut second.lock().unwrap()).unwrap();
    writer.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn concurrent_openers_record_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.sqlite3");
    // Establish WAL independently so this tests migration serialization, not a
    // racing journal-mode transition. Both openers start with no ledger.
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode = WAL").unwrap();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    let storage = SqliteSharedStorage::open(&path).unwrap();
                    assert_eq!(count(&storage.lock().unwrap()), 1);
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    });
    assert_eq!(count(&conn), 1);
}

#[test]
fn pending_migration_busy_remains_transient() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.sqlite3");
    let writer = Connection::open(&path).unwrap();
    writer
        .execute_batch("PRAGMA journal_mode = WAL; BEGIN IMMEDIATE")
        .unwrap();
    let mut conn = Connection::open(&path).unwrap();
    conn.busy_timeout(Duration::ZERO).unwrap();
    assert!(matches!(run_all(&mut conn), Err(StorageError::Busy(_))));
}

#[test]
fn invalid_schema_shapes_are_refused_without_ledger() {
    for sql in [
        VERSION_1_SQL.replace("    profile_json TEXT,", ""),
        VERSION_1_SQL.replace("npub TEXT NOT NULL", "npub BLOB NOT NULL"),
        VERSION_1_SQL.replace("npub TEXT NOT NULL", "npub TEXT"),
        VERSION_1_SQL.replace(
            "PRIMARY KEY (account_id_hex, follow_account_id_hex)",
            "PRIMARY KEY (account_id_hex, position)",
        ),
        VERSION_1_SQL.replace(
            "REFERENCES directory_users(account_id_hex) ON DELETE CASCADE",
            "",
        ),
        VERSION_1_SQL.replace("ON DELETE CASCADE", "ON DELETE RESTRICT"),
        VERSION_1_SQL.replace("DEFAULT 60", "DEFAULT 30"),
        VERSION_1_SQL.replace("CHECK (id = 1)", "CHECK (id > 0)"),
        VERSION_1_SQL.replace("CHECK (id = 1)", "CHECK (id = 1 OR 1)"),
        VERSION_1_SQL.replace(
            "account_id_hex TEXT PRIMARY KEY",
            "account_id_hex TEXT COLLATE NOCASE PRIMARY KEY",
        ),
        format!("{VERSION_1_SQL} CREATE UNIQUE INDEX wrong ON directory_users(npub)"),
        format!("{VERSION_1_SQL} CREATE INDEX wrong ON directory_user_follows(position DESC)"),
        format!(
            "{VERSION_1_SQL} CREATE TRIGGER unexpected AFTER UPDATE ON relay_telemetry_settings BEGIN DELETE FROM directory_users; END"
        ),
        VERSION_1_SQL.replace(
            "CREATE TABLE IF NOT EXISTS telemetry_install",
            "CREATE TABLE IF NOT EXISTS wrong_install",
        ) + "; CREATE VIEW telemetry_install AS SELECT * FROM wrong_install;",
    ] {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&sql).unwrap();
        assert_eq!(
            run_all(&mut conn).unwrap_err().to_string(),
            "backend failure: invalid shared store schema shape"
        );
        assert!(!table_exists(&conn, "shared_schema_migrations").unwrap());
    }
}

#[test]
fn invalid_history_and_future_versions_fail_before_body() {
    for rows in [
        "(1, 'private name', 0)",
        "(0, '0001_shared_store', 0)",
        "(-1, '0001_shared_store', 0), (1, '0001_shared_store', 0)",
        "(2, 'future private name', 0)",
    ] {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(LEDGER_SQL).unwrap();
        conn.execute_batch(&format!(
            "INSERT INTO shared_schema_migrations VALUES {rows}"
        ))
        .unwrap();
        let error = run_all(&mut conn).unwrap_err();
        if rows.starts_with("(2") {
            assert!(matches!(
                error,
                StorageError::UnsupportedSchemaVersion {
                    found: 2,
                    latest_supported: 1
                }
            ));
        } else {
            assert_eq!(
                error.to_string(),
                "backend failure: invalid shared store migration history"
            );
        }
        assert!(!table_exists(&conn, "directory_users").unwrap());
    }
}

#[test]
fn malformed_ledger_and_gapped_test_registry_are_refused() {
    for ddl in [
        "CREATE TABLE shared_schema_migrations (version INTEGER, name TEXT, applied_at_unix_seconds INTEGER)",
        "CREATE TABLE shared_schema_migrations (private TEXT)",
        "CREATE VIEW shared_schema_migrations AS SELECT 1 AS version, '0001_shared_store' AS name",
    ] {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(ddl).unwrap();
        assert_eq!(
            run_all(&mut conn).unwrap_err().to_string(),
            "backend failure: invalid shared store migration history"
        );
    }
    let mut conn = Connection::open_in_memory().unwrap();
    for versions in [[1, 1], [2, 1], [1, 3]] {
        let registry = versions.map(|version| Migration {
            version,
            name: "test",
            apply: version_1,
        });
        assert!(run(&mut conn, &registry).is_err());
        assert!(!table_exists(&conn, "directory_users").unwrap());
    }
}

#[test]
fn body_and_ledger_failures_roll_back_and_redact_sqlite_messages() {
    let mut conn = Connection::open_in_memory().unwrap();
    let failing = [Migration {
        version: 1,
        name: "test",
        apply: |tx| {
            tx.execute_batch(
                "CREATE TABLE probe (value TEXT); INSERT INTO probe VALUES ('private');",
            )
            .map_err(sqlite_error)?;
            tx.execute_batch("INSERT INTO missing VALUES (1)")
                .map_err(sqlite_error)?;
            Ok(())
        },
    }];
    assert!(run(&mut conn, &failing).is_err());
    assert!(!table_exists(&conn, "probe").unwrap());
    assert!(!table_exists(&conn, "shared_schema_migrations").unwrap());

    conn.execute_batch(LEDGER_SQL).unwrap();
    conn.execute_batch("CREATE TRIGGER reject BEFORE INSERT ON shared_schema_migrations BEGIN SELECT RAISE(ABORT, 'https://collector.example/?token=secret'); END").unwrap();
    let error = run_all(&mut conn).unwrap_err();
    let message = format!("{error:?} {error}");
    assert!(!message.contains("collector"));
    assert!(!message.contains("secret"));
    assert!(
        message.contains("1811"),
        "extended SQLITE_CONSTRAINT_TRIGGER code retained"
    );
    assert_eq!(count(&conn), 0);
    assert!(!table_exists(&conn, "directory_users").unwrap());
    conn.execute_batch("DROP TRIGGER reject").unwrap();
    run_all(&mut conn).unwrap();
    assert_eq!(count(&conn), 1);
}

#[test]
fn ignored_ledger_insert_cannot_commit_body() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(LEDGER_SQL).unwrap();
    conn.execute_batch("CREATE TRIGGER skip BEFORE INSERT ON shared_schema_migrations BEGIN SELECT RAISE(IGNORE); END").unwrap();
    assert!(run_all(&mut conn).is_err());
    assert_eq!(count(&conn), 0);
    assert!(!table_exists(&conn, "directory_users").unwrap());
}

#[test]
fn fresh_schema_matches_frozen_contract_and_has_independent_ledger() {
    let storage = SqliteSharedStorage::in_memory().unwrap();
    let conn = storage.lock().unwrap();
    let reference = Connection::open_in_memory().unwrap();
    reference.execute_batch(VERSION_1_SQL).unwrap();
    for table in TABLES {
        assert!(table_matches(&conn, &reference, table).unwrap());
    }
    for other in ["cgka_schema_migrations", "app_cache_schema_migrations"] {
        assert!(!table_exists(&conn, other).unwrap());
    }
}

#[test]
fn recorded_gap_and_duplicate_rows_cannot_bless_a_schema() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(LEDGER_SQL).unwrap();
    conn.execute_batch("INSERT INTO shared_schema_migrations VALUES (2, 'second', 0)")
        .unwrap();
    let registry = [
        Migration {
            version: 1,
            name: "first",
            apply: |_| panic!("gap must fail before body"),
        },
        Migration {
            version: 2,
            name: "second",
            apply: |_| panic!("gap must fail before body"),
        },
    ];
    assert_eq!(
        run(&mut conn, &registry).unwrap_err().to_string(),
        "backend failure: invalid shared store migration history"
    );
    conn.execute_batch("DROP TABLE shared_schema_migrations;
        CREATE TABLE shared_schema_migrations (version INTEGER, name TEXT NOT NULL, applied_at_unix_seconds INTEGER NOT NULL);
        INSERT INTO shared_schema_migrations VALUES (1, '0001_shared_store', 0), (1, '0001_shared_store', 0)").unwrap();
    assert_eq!(
        run_all(&mut conn).unwrap_err().to_string(),
        "backend failure: invalid shared store migration history"
    );
    assert!(!table_exists(&conn, "directory_users").unwrap());
}

#[test]
fn retired_column_defaults_and_types_are_not_wildcards() {
    for sql in [
        LEGACY_SQL.replace("otlp_endpoint TEXT", "otlp_endpoint BLOB"),
        LEGACY_SQL.replace("otlp_endpoint TEXT", "otlp_endpoint TEXT NOT NULL"),
        LEGACY_SQL.replace("'obfuscated_sensitive_data'", "'full_data'"),
        LEGACY_SQL.replace(
            "'obfuscated_sensitive_data'",
            "'obfuscated_ sensitive_data'",
        ),
    ] {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&sql).unwrap();
        assert_eq!(
            run_all(&mut conn).unwrap_err().to_string(),
            "backend failure: invalid shared store schema shape"
        );
        assert!(!table_exists(&conn, LEDGER).unwrap());
    }
}

#[test]
fn extended_busy_and_locked_errors_remain_transient_and_redacted() {
    for code in [
        rusqlite::ffi::SQLITE_BUSY,
        rusqlite::ffi::SQLITE_BUSY_RECOVERY,
        rusqlite::ffi::SQLITE_LOCKED,
        rusqlite::ffi::SQLITE_LOCKED_SHAREDCACHE,
    ] {
        let error = sqlite_error(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            Some("private database value".into()),
        ));
        assert!(error.is_transient());
        assert!(error.to_string().contains(&code.to_string()));
        assert!(!format!("{error} {error:?}").contains("private database value"));
    }
}

#[test]
fn migration_and_settings_errors_never_log_or_return_private_trigger_text() {
    #[derive(Clone)]
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let output = Capture(Arc::new(std::sync::Mutex::new(Vec::new())));
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("fixtures/legacy_repairs.sql"))
        .unwrap();
    conn.execute_batch("INSERT INTO relay_telemetry_settings VALUES (1, 1, 'https://collector.example/?token=secret', 37, 0)").unwrap();
    run_all(&mut conn).unwrap();
    let storage = SqliteSharedStorage::from_connection(conn).unwrap();
    storage.lock().unwrap().execute_batch("CREATE TRIGGER reject_settings BEFORE UPDATE ON relay_telemetry_settings BEGIN SELECT RAISE(ABORT, 'https://collector.example/?token=secret'); END").unwrap();
    let error = storage
        .set_relay_telemetry_settings(&StoredRelayTelemetrySettings {
            export_enabled: false,
            export_interval_seconds: 90,
        })
        .unwrap_err();
    let messages = format!(
        "{error} {error:?} {}",
        String::from_utf8(output.0.lock().unwrap().clone()).unwrap()
    );
    for private in ["collector", "token", "secret"] {
        assert!(!messages.contains(private));
    }
}
