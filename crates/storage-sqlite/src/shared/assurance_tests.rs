//! Deterministic synthetic upgrades from independently extracted historical DDL.
//! Abrupt process exit exercises SQLite recovery, not physical power loss.
use super::super::{SqliteSharedStorage, StoredAuditLogSettings, StoredRelayTelemetrySettings};
use super::*;
use rusqlite::types::Value;

const ORIGINAL: &str = include_str!("fixtures/original.sql");
const FIVE_TABLES: &str = include_str!("fixtures/five_tables_audit_mode.sql");
const PRE_LEDGER: &str = include_str!("fixtures/pre_ledger.sql");
const REPAIRS: &str = include_str!("fixtures/legacy_repairs.sql");

fn snapshot(conn: &Connection, tables: &[&str]) -> Vec<Vec<Vec<Value>>> {
    tables
        .iter()
        .map(|table| {
            let mut stmt = conn
                .prepare(&format!("SELECT rowid, * FROM {table} ORDER BY rowid"))
                .unwrap();
            let columns = stmt.column_count();
            stmt.query_map([], |row| {
                (0..columns).map(|column| row.get(column)).collect()
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
        })
        .collect()
}

fn seed(conn: &mut Connection, users: i64) {
    let tx = conn.transaction().unwrap();
    tx.execute(
        r#"WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < ?1)
        INSERT INTO directory_users
        SELECT printf('%064x',n), 'npub-'||n,
            CASE n % 3 WHEN 0 THEN NULL WHEN 1 THEN '{invalid cached JSON'
            ELSE '{"name":"日本語 🦫","unknown":[1,null]}' END,
            '{}', NULL, 'event-'||n, n % 4, n FROM seq"#,
        [users],
    )
    .unwrap();
    tx.execute_batch("INSERT INTO directory_user_follows SELECT account_id_hex, 'z-friend', 0, event_id_hex, event_created_at FROM directory_users;
        INSERT INTO directory_user_follows SELECT account_id_hex, 'a-friend', 1, NULL, NULL FROM directory_users;
        INSERT INTO relay_telemetry_settings (id, export_enabled, export_interval_seconds, updated_at_ms) VALUES (1, 1, 37, 1234);
        INSERT INTO audit_log_settings (id, enabled, updated_at_ms) VALUES (1, 1, 1235);
        INSERT INTO telemetry_install VALUES (1, 'synthetic-install-identity-🦫', 1236);").unwrap();
    tx.commit().unwrap();
}

fn assert_integrity(conn: &Connection) {
    let result: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(result, "ok");
    assert!(
        conn.prepare("PRAGMA foreign_key_check")
            .unwrap()
            .query([])
            .unwrap()
            .next()
            .unwrap()
            .is_none()
    );
}

fn assert_live_api(storage: &SqliteSharedStorage) {
    let record = storage
        .public_directory_user(&format!("{:064x}", 1))
        .unwrap()
        .unwrap();
    assert_eq!(record.follows, ["z-friend", "a-friend"]);
    assert_eq!(
        storage.relay_telemetry_settings().unwrap(),
        StoredRelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 37
        }
    );
    assert_eq!(
        storage.audit_log_settings().unwrap(),
        StoredAuditLogSettings { enabled: true }
    );
    assert_eq!(
        storage.telemetry_install_id().unwrap().as_deref(),
        Some("synthetic-install-identity-🦫")
    );
}

#[test]
fn populated_current_shape_adoption_preserves_every_value_and_rowid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.sqlite3");
    let mut conn = Connection::open(&path).unwrap();
    conn.execute_batch(PRE_LEDGER).unwrap();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    seed(&mut conn, 10_000); // 30,003 rows, all values and rowids compared.
    let before = snapshot(&conn, TABLES);
    let storage = SqliteSharedStorage::open(&path).unwrap();
    assert_eq!(snapshot(&storage.lock().unwrap(), TABLES), before);
    assert_live_api(&storage);
    assert_integrity(&storage.lock().unwrap());
    storage.close().unwrap();
    let storage = SqliteSharedStorage::open(&path).unwrap();
    assert_eq!(snapshot(&storage.lock().unwrap(), TABLES), before);
}

#[test]
fn every_verified_schema_generation_preserves_live_and_retired_rows() {
    for fixture in [ORIGINAL, FIVE_TABLES, PRE_LEDGER] {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(fixture).unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        seed(&mut conn, 100);
        let mut tables = TABLES.to_vec();
        if fixture == ORIGINAL {
            conn.execute_batch("INSERT INTO directory_events VALUES ('old-event', 'author', 0, 99);
                INSERT INTO directory_key_packages VALUES (printf('%064x', 1), NULL, NULL, 'old key package', 99);
                INSERT INTO directory_search_graph_users VALUES ('old-user', 'npub', NULL, NULL, NULL, NULL, NULL, NULL);
                INSERT INTO directory_search_graph_follows VALUES ('old-user', 'friend', 0, NULL, NULL)").unwrap();
            tables.extend([
                "directory_events",
                "directory_key_packages",
                "directory_search_graph_users",
                "directory_search_graph_follows",
            ]);
        }
        if fixture != PRE_LEDGER {
            conn.execute_batch("UPDATE audit_log_settings SET data_mode = 'full_data'")
                .unwrap();
        }
        let before = snapshot(&conn, &tables);
        let storage = SqliteSharedStorage::from_connection(conn).unwrap();
        assert_eq!(snapshot(&storage.lock().unwrap(), &tables), before);
        assert_live_api(&storage);
        assert_integrity(&storage.lock().unwrap());
        storage
            .set_audit_log_settings(&StoredAuditLogSettings { enabled: false })
            .unwrap();
        if fixture != PRE_LEDGER {
            let mode: String = storage
                .lock()
                .unwrap()
                .query_row("SELECT data_mode FROM audit_log_settings", [], |r| r.get(0))
                .unwrap();
            assert_eq!(mode, "full_data");
        }
    }
}

#[test]
fn legacy_endpoint_and_appended_audit_column_remain_inert() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(REPAIRS).unwrap();
    conn.execute_batch("ALTER TABLE audit_log_settings ADD COLUMN data_mode TEXT NOT NULL DEFAULT 'obfuscated_sensitive_data';
        INSERT INTO audit_log_settings VALUES (1, 1, 1235, 'full_data');
        INSERT INTO relay_telemetry_settings VALUES (1, 1, 'https://collector.example/v1/metrics?token=secret', 37, 1234)").unwrap();
    let before = snapshot(&conn, &["audit_log_settings"]);
    let storage = SqliteSharedStorage::from_connection(conn).unwrap();
    assert_eq!(
        snapshot(&storage.lock().unwrap(), &["audit_log_settings"]),
        before
    );
    assert_eq!(
        storage
            .relay_telemetry_settings()
            .unwrap()
            .export_interval_seconds,
        37
    );
    assert_eq!(
        storage.audit_log_settings().unwrap(),
        StoredAuditLogSettings { enabled: true }
    );
    storage
        .set_audit_log_settings(&StoredAuditLogSettings { enabled: false })
        .unwrap();
    storage
        .set_relay_telemetry_settings(&StoredRelayTelemetrySettings {
            export_enabled: false,
            export_interval_seconds: 90,
        })
        .unwrap();
    let mut conn = storage.lock().unwrap();
    let endpoint: Option<String> = conn
        .query_row(
            "SELECT otlp_endpoint FROM relay_telemetry_settings",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(endpoint, None);
    assert_eq!(
        conn.query_row("SELECT data_mode FROM audit_log_settings", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "full_data"
    );
    conn.pragma_update(None, "query_only", true).unwrap();
    run_all(&mut conn).unwrap();
    assert_integrity(&conn);
}

#[test]
fn endpoint_neutralization_rolls_back_when_ledger_insert_fails() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(REPAIRS).unwrap();
    conn.execute_batch("INSERT INTO relay_telemetry_settings VALUES (1, 1, 'https://collector.example/?token=secret', 37, 1234)").unwrap();
    conn.execute_batch(LEDGER_SQL).unwrap();
    conn.execute_batch("CREATE TRIGGER reject BEFORE INSERT ON shared_schema_migrations BEGIN SELECT RAISE(ABORT, 'private trigger payload'); END").unwrap();
    let before = snapshot(&conn, &["relay_telemetry_settings", "audit_log_settings"]);
    let error = run_all(&mut conn).unwrap_err();
    assert!(!format!("{error} {error:?}").contains("private trigger payload"));
    assert_eq!(
        snapshot(&conn, &["relay_telemetry_settings", "audit_log_settings"]),
        before
    );
    assert!(!table_exists(&conn, "directory_users").unwrap());
    conn.execute_batch("DROP TRIGGER reject").unwrap();
    run_all(&mut conn).unwrap();
    assert_integrity(&conn);
}

#[test]
fn orphaned_foreign_key_data_is_refused_without_changes() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(PRE_LEDGER).unwrap();
    conn.pragma_update(None, "foreign_keys", false).unwrap();
    conn.execute_batch(
        "INSERT INTO directory_user_follows VALUES ('missing', 'friend', 0, NULL, NULL)",
    )
    .unwrap();
    let before = snapshot(&conn, TABLES);
    assert_eq!(
        run_all(&mut conn).unwrap_err().to_string(),
        "backend failure: invalid shared store schema shape"
    );
    assert!(!table_exists(&conn, LEDGER).unwrap());
    assert_eq!(snapshot(&conn, TABLES), before);
}

#[test]
fn interrupted_shared_upgrade_recovers_in_delete_and_wal_modes() {
    const CHILD_PATH: &str = "MDK_SHARED_UPGRADE_CRASH_TEST_PATH";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let mut conn = Connection::open(path).unwrap();
        let interrupted = [Migration {
            version: 1,
            name: MIGRATIONS[0].name,
            apply: |tx| {
                version_1(tx)?;
                // Force dirty pages to the journal/WAL before leaving without any
                // Rust or SQLite destructor. Exit occurs before ledger insertion.
                tx.execute_batch(
                    "PRAGMA cache_size = 1; CREATE TABLE crash_probe (data BLOB);
                INSERT INTO crash_probe VALUES (zeroblob(262144));",
                )
                .map_err(sqlite_error)?;
                std::process::exit(77);
            },
        }];
        run(&mut conn, &interrupted).unwrap();
        panic!("child must exit in the transaction");
    }
    for journal in ["DELETE", "WAL"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.sqlite3");
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "journal_mode", journal).unwrap();
        conn.execute_batch(REPAIRS).unwrap();
        conn.execute_batch("INSERT INTO relay_telemetry_settings VALUES (1, 1, 'synthetic-private-endpoint', 37, 1234);
            INSERT INTO audit_log_settings VALUES (1, 1, 1235)").unwrap();
        let before = snapshot(&conn, &["relay_telemetry_settings", "audit_log_settings"]);
        drop(conn);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "shared::migrations::assurance_tests::interrupted_shared_upgrade_recovers_in_delete_and_wal_modes", "--nocapture"])
            .env(CHILD_PATH, &path).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("interrupted-upgrade child exceeded its deadline");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(77), "{journal}");
        let mut conn = Connection::open(&path).unwrap();
        assert_eq!(
            snapshot(&conn, &["relay_telemetry_settings", "audit_log_settings"]),
            before,
            "{journal}"
        );
        assert!(!table_exists(&conn, LEDGER).unwrap());
        assert!(!table_exists(&conn, "directory_users").unwrap());
        assert!(!table_exists(&conn, "crash_probe").unwrap());
        assert_integrity(&conn);
        run_all(&mut conn).unwrap();
        assert_integrity(&conn);
        let endpoint: Option<String> = conn
            .query_row(
                "SELECT otlp_endpoint FROM relay_telemetry_settings",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(endpoint, None);
    }
}

#[test]
fn appended_endpoint_is_neutralized_without_rewriting_live_settings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.sqlite3");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(PRE_LEDGER).unwrap();
    // Defensive compatibility case from review, not a claimed historical build.
    conn.execute_batch("ALTER TABLE relay_telemetry_settings ADD COLUMN otlp_endpoint TEXT;
        INSERT INTO relay_telemetry_settings VALUES (1, 1, 37, 1234, 'https://collector.example/?token=secret')").unwrap();
    let before = snapshot(&conn, &["relay_telemetry_settings"]);
    let storage = SqliteSharedStorage::open(&path).unwrap();
    let mut expected = before;
    *expected[0][0].last_mut().unwrap() = Value::Null;
    assert_eq!(
        snapshot(&storage.lock().unwrap(), &["relay_telemetry_settings"]),
        expected
    );
    assert_integrity(&storage.lock().unwrap());
    storage.close().unwrap();
    let storage = SqliteSharedStorage::open(&path).unwrap();
    let mut conn = storage.lock().unwrap();
    conn.pragma_update(None, "query_only", true).unwrap();
    run_all(&mut conn).unwrap();
    assert_eq!(snapshot(&conn, &["relay_telemetry_settings"]), expected);
}

#[test]
fn retired_orphans_do_not_gate_live_store_adoption() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(ORIGINAL).unwrap();
    seed(&mut conn, 3);
    conn.pragma_update(None, "foreign_keys", false).unwrap();
    conn.execute_batch(
        "INSERT INTO directory_key_packages VALUES ('retired-orphan', NULL, NULL, 'unused', 99)",
    )
    .unwrap();
    let before = snapshot(&conn, &["directory_key_packages"]);
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    run_all(&mut conn).unwrap();
    assert_eq!(snapshot(&conn, &["directory_key_packages"]), before);
    assert!(
        conn.prepare("PRAGMA foreign_key_check(directory_user_follows)")
            .unwrap()
            .query([])
            .unwrap()
            .next()
            .unwrap()
            .is_none()
    );
    assert_eq!(
        conn.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    // Retired data remains untouched, including the pre-existing violation.
    assert!(
        conn.prepare("PRAGMA foreign_key_check(directory_key_packages)")
            .unwrap()
            .query([])
            .unwrap()
            .next()
            .unwrap()
            .is_some()
    );
}
