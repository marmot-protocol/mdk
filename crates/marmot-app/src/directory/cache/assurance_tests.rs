//! Populated-database and interrupted-upgrade checks using historical DDL.
//! All data and keys are synthetic; no installed app databases are accessed.
use super::*;
use sha2::{Digest, Sha256};
use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

const HISTORICAL_SQL: &str = include_str!("fixtures/pre_ledger.sql");
const TABLES: &[&str] = &[
    "directory_users",
    "directory_user_follows",
    "directory_follow_source_relays",
    "directory_known_user_reasons",
    "directory_search_graph_users",
    "directory_search_graph_follows",
];

fn encrypted_connection(path: &std::path::Path) -> Connection {
    fs_private::ensure_private_db_files(path).unwrap();
    let conn = Connection::open(path).unwrap();
    open_hardened_sqlcipher(
        &conn,
        &SqlCipherKey::new("synthetic-upgrade-test-key").unwrap(),
        SqlCipherHardening::live_cache(),
    )
    .unwrap();
    conn
}

/// Hash every typed value, including rowids, with deterministic row ordering.
fn snapshot(conn: &Connection, tables: &[&str], limit: i64) -> Vec<(u64, Vec<u8>)> {
    tables
        .iter()
        .map(|table| {
            let mut statement = conn
                .prepare(&format!(
                    "SELECT rowid, * FROM {table} ORDER BY rowid LIMIT {limit}"
                ))
                .unwrap();
            let columns = statement.column_count();
            let mut rows = statement.query([]).unwrap();
            let mut hash = Sha256::new();
            let mut count = 0;
            while let Some(row) = rows.next().unwrap() {
                for column in 0..columns {
                    let value: rusqlite::types::Value = row.get(column).unwrap();
                    let bytes = format!("{value:?}").into_bytes();
                    hash.update((bytes.len() as u64).to_le_bytes());
                    hash.update(bytes);
                }
                count += 1;
            }
            (count, hash.finalize().to_vec())
        })
        .collect()
}

fn seed_structured(conn: &mut Connection, users: i64) {
    conn.execute_batch(HISTORICAL_SQL).unwrap();
    let tx = conn.transaction().unwrap();
    // Include Unicode, unknown metadata, NULLs, empty JSON, and intentionally
    // invalid cached JSON: adoption must not inspect or rewrite stored records.
    tx.execute(
        r#"WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < ?1)
         INSERT INTO directory_users
         SELECT printf('%064x',n), 'npub-'||n, NULL,
             CASE n % 3 WHEN 0 THEN NULL WHEN 1 THEN '{invalid cached JSON'
             ELSE '{"name":"日本語 🦫","future_field":{"a":[1,null]}}' END,
             '{}', NULL, n FROM seq"#,
        [users],
    )
    .unwrap();
    tx.execute_batch(
        "INSERT INTO directory_user_follows
             SELECT account_id_hex, 'friend', 0, updated_at FROM directory_users;
         INSERT INTO directory_follow_source_relays
             SELECT account_id_hex, 'wss://synthetic.example', 0, updated_at FROM directory_users;
         INSERT INTO directory_known_user_reasons
             SELECT account_id_hex, 'directory', updated_at, updated_at FROM directory_users;
         INSERT INTO directory_search_graph_users
             SELECT account_id_hex, npub, profile_json, updated_at, updated_at+86400,
                    1, updated_at, updated_at, updated_at FROM directory_users;
         INSERT INTO directory_search_graph_follows
             SELECT * FROM directory_user_follows;",
    )
    .unwrap();
    tx.commit().unwrap();
}

fn seed_legacy(conn: &mut Connection, users: u64) -> Vec<crate::UserDirectoryRecord> {
    conn.execute_batch(
        "CREATE TABLE user_directory_records (
            account_id_hex TEXT PRIMARY KEY NOT NULL,
            entry_json TEXT NOT NULL, updated_at INTEGER NOT NULL);",
    )
    .unwrap();
    let tx = conn.transaction().unwrap();
    let mut expected = Vec::new();
    for n in 1..=users {
        let record = crate::UserDirectoryRecord {
            account_id_hex: format!("{:064x}", n + 1_000_000),
            npub: format!("synthetic-legacy-{n}"),
            local_account: None,
            profile: Some(crate::UserProfileMetadata {
                name: Some(format!("legacy-{n}")),
                about: Some("synthetic profile ".repeat(128)),
                ..Default::default()
            }),
            follows: vec!["synthetic-follow".into()],
            follow_source_relays: vec!["wss://synthetic.example".into()],
            relay_lists: crate::AccountRelayListStatus::empty(),
            key_package: None,
        };
        tx.execute(
            "INSERT INTO user_directory_records VALUES (?1, ?2, 0)",
            params![
                record.account_id_hex,
                serde_json::to_string(&record).unwrap()
            ],
        )
        .unwrap();
        expected.push(record);
    }
    tx.commit().unwrap();
    expected
}

fn assert_converted(conn: &Connection, expected: &[crate::UserDirectoryRecord]) {
    for record in expected {
        let row = DirectoryCache::directory_user_row(conn, &record.account_id_hex)
            .unwrap()
            .unwrap();
        assert_eq!(
            DirectoryCache::record_from_directory_user_row(conn, row).unwrap(),
            *record
        );
    }
}

#[test]
fn populated_historical_encrypted_cache_preserves_all_120000_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app-cache.sqlite3");
    let mut conn = encrypted_connection(&path);
    seed_structured(&mut conn, 20_000);
    let before = snapshot(&conn, TABLES, -1);
    assert!(before.iter().all(|(count, _)| *count == 20_000));
    drop(conn);

    let cache = DirectoryCache::open(
        path.clone(),
        &SqlCipherKey::new("synthetic-upgrade-test-key").unwrap(),
    )
    .unwrap();
    assert_eq!(snapshot(&cache.lock().unwrap(), TABLES, -1), before);
    cache.close().unwrap();
    let conn = encrypted_connection(&path);
    assert_eq!(snapshot(&conn, TABLES, -1), before);
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
}

#[test]
fn legacy_conversion_disk_full_preserves_both_tiers_and_retries() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = encrypted_connection(&dir.path().join("app-cache.sqlite3"));
    seed_structured(&mut conn, 25);
    let expected = seed_legacy(&mut conn, 1_000);
    let tables = [TABLES, &["user_directory_records"]].concat();
    let before = snapshot(&conn, &tables, -1);
    let pages: i64 = conn
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .unwrap();
    // Permit the ledger and some converted records, but not the full conversion.
    // The progress assertion below guards this premise against allocation changes.
    conn.pragma_update(None, "max_page_count", pages + 64)
        .unwrap();
    super::super::LEGACY_RECORDS_CONVERTED.with(|count| count.set(0));
    let error = run_all(&mut conn).unwrap_err();
    assert!(
        super::super::LEGACY_RECORDS_CONVERTED.with(|count| count.get()) > 0,
        "disk exhaustion must occur after at least one legacy record was converted"
    );
    assert!(
        super::super::LEGACY_RECORDS_CONVERTED.with(|count| count.get()) < expected.len(),
        "disk exhaustion must interrupt legacy conversion"
    );
    assert!(
        matches!(error, AppError::Sqlite(rusqlite::Error::SqliteFailure(code, None))
        if code.code == rusqlite::ErrorCode::DiskFull)
    );
    assert_eq!(snapshot(&conn, &tables, -1), before);
    assert!(!DirectoryCache::table_exists_locked(&conn, "app_cache_schema_migrations").unwrap());
    conn.pragma_update(None, "max_page_count", pages + 10_000)
        .unwrap();
    run_all(&mut conn).unwrap();
    assert!(!DirectoryCache::table_exists_locked(&conn, "user_directory_records").unwrap());
    let count: i64 = conn
        .query_row("SELECT count(*) FROM directory_users", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1_025);
    assert_converted(&conn, &expected);
    // Existing structured rows remain unchanged even alongside legacy records.
    assert_eq!(snapshot(&conn, TABLES, 25), before[..6]);
}

/// This test is also the child process: exit bypasses every Rust/SQLite
/// destructor after conversion and table removal, before the ledger commit.
#[test]
fn interrupted_encrypted_legacy_upgrade_recovers_without_losing_records() {
    const CHILD_PATH: &str = "MDK_DIRECTORY_UPGRADE_CRASH_TEST_PATH";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let mut conn = encrypted_connection(std::path::Path::new(&path));
        let interrupted = [Migration {
            version: 1,
            name: MIGRATIONS[0].name,
            apply: |tx| {
                version_1(tx)?;
                std::process::exit(77);
            },
        }];
        run(&mut conn, &interrupted).unwrap();
        panic!("child must exit inside the transaction");
    }
    for journal in ["DELETE", "WAL"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-cache.sqlite3");
        let mut conn = encrypted_connection(&path);
        conn.pragma_update(None, "journal_mode", journal).unwrap();
        seed_structured(&mut conn, 25);
        let expected = seed_legacy(&mut conn, 1_000);
        let tables = [TABLES, &["user_directory_records"]].concat();
        let before = snapshot(&conn, &tables, -1);
        drop(conn);

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact",
                "directory::cache::migrations::assurance_tests::interrupted_encrypted_legacy_upgrade_recovers_without_losing_records",
                "--nocapture"])
            .env(CHILD_PATH, &path)
            .status().unwrap();
        assert_eq!(status.code(), Some(77), "{journal}");
        let mut conn = encrypted_connection(&path);
        assert_eq!(snapshot(&conn, &tables, -1), before, "{journal}");
        assert!(
            !DirectoryCache::table_exists_locked(&conn, "app_cache_schema_migrations").unwrap()
        );
        run_all(&mut conn).unwrap();
        assert!(!DirectoryCache::table_exists_locked(&conn, "user_directory_records").unwrap());
        let count: i64 = conn
            .query_row("SELECT count(*) FROM directory_users", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1_025);
        assert_converted(&conn, &expected);
        assert_eq!(snapshot(&conn, TABLES, 25), before[..6]);
        let integrity: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
    }
}
