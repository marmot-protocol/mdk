//! Upgrade of an account database written by MDK v0.10.4.
//!
//! `fixtures/account-v0.10.4.sql` is a full account database produced by the
//! v0.10.4 app runtime (see `fixtures/README.md`): three groups, messages from
//! three members, one group whose Nostr route rotated so it keeps a retained
//! prior route with no recorded switch time, and a persisted transport cursor.
//! The test loads it into an encrypted file and opens it through the
//! production open path.

use super::{MIGRATIONS, run};
use crate::{SqlCipherHardening, SqlCipherKey, SqliteAccountStorage, open_hardened_sqlcipher};
use cgka_traits::storage::StorageError;
use rusqlite::types::Value;

const FIXTURE: &str = include_str!("../../fixtures/account-v0.10.4.sql");
const FIXTURE_KEY: &str = "mdk storage v0.10.4 fixture key";
const FIXTURE_LABEL: &str = "bob";
const V0_10_4_LATEST_MIGRATION: usize = 89;
const ROTATED_GROUP: &str = "5cd77cb71f1a861ace44d13e4dfdae3d";
const RETAINED_ROUTE: &str = "17f6648f67003fec1ac26f7b1e027e5185beb61b22c131605ea80ec8aaf4810e";
const PERSISTED_CURSOR: i64 = 1_790_635_089;

/// Tables whose original values forward migrations must carry over, except
/// the explicit presentation-refresh revision in migration 0107 below.
const PRESERVED_TABLES: &[&str] = &[
    "cgka_groups",
    "cgka_messages",
    "openmls_values",
    "cgka_group_snapshots",
    "cgka_member_capabilities",
    "cgka_transport_group_routes",
    "cgka_group_maintenance",
    "account_groups",
    "account_group_app_components",
    "app_events",
    "message_timeline",
    "chat_list_rows",
    "chat_presentation_members",
    "seen_events",
    "transport_reconciliation_items",
];

fn write_fixture(path: &std::path::Path) {
    let key = SqlCipherKey::new(FIXTURE_KEY).unwrap();
    let conn = rusqlite::Connection::open(path).unwrap();
    open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
    conn.execute_batch(FIXTURE).unwrap();
}

fn raw(path: &std::path::Path) -> rusqlite::Connection {
    let key = SqlCipherKey::new(FIXTURE_KEY).unwrap();
    let conn = rusqlite::Connection::open(path).unwrap();
    open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
    conn
}

fn rows(conn: &rusqlite::Connection, sql: &str) -> Vec<Vec<Value>> {
    let mut statement = conn.prepare(sql).unwrap();
    let width = statement.column_count();
    statement
        .query_map([], |row| (0..width).map(|index| row.get(index)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Every row of `table` in a canonical order (some tables have no rowid).
fn table_rows(conn: &rusqlite::Connection, table: &str) -> Vec<Vec<Value>> {
    let mut all = rows(conn, &format!("SELECT * FROM {table}"));
    all.sort_by_cached_key(|row| format!("{row:?}"));
    all
}

fn count(conn: &rusqlite::Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn schema(conn: &rusqlite::Connection) -> Vec<Vec<Value>> {
    rows(
        conn,
        "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name",
    )
}

fn cursor(conn: &rusqlite::Connection) -> Option<i64> {
    conn.query_row(
        "SELECT last_transport_timestamp FROM account_state WHERE label = ?1",
        [FIXTURE_LABEL],
        |row| row.get(0),
    )
    .unwrap()
}

fn retained_routes(conn: &rusqlite::Connection) -> Vec<(String, serde_json::Value)> {
    rows(
        conn,
        "SELECT group_id_hex, prior_nostr_routes_json FROM account_groups
         WHERE prior_nostr_routes_json <> '[]' ORDER BY group_id_hex",
    )
    .into_iter()
    .map(|row| match (&row[0], &row[1]) {
        (Value::Text(group), Value::Text(json)) => {
            (group.clone(), serde_json::from_str(json).unwrap())
        }
        other => panic!("unexpected account_groups row: {other:?}"),
    })
    .collect()
}

#[test]
fn v0_10_4_account_upgrades_without_losing_state_or_raising_notices() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("v0.10.4-account.sqlite3");
    write_fixture(&database);

    // What v0.10.4 left behind.
    let (before_tables, before_cursor, before_routes, chat_revision_column) = {
        let conn = raw(&database);
        assert_eq!(
            count(&conn, "cgka_schema_migrations"),
            V0_10_4_LATEST_MIGRATION as i64
        );
        let tables: Vec<_> = PRESERVED_TABLES
            .iter()
            .map(|table| table_rows(&conn, table))
            .collect();
        assert_eq!(count(&conn, "cgka_groups"), 3);
        assert!(count(&conn, "message_timeline") >= 18);
        let chat_revision_column: usize = conn
            .prepare("SELECT * FROM chat_list_rows")
            .unwrap()
            .column_names()
            .iter()
            .position(|name| *name == "presentation_source_revision")
            .unwrap();
        (
            tables,
            cursor(&conn),
            retained_routes(&conn),
            chat_revision_column,
        )
    };
    assert_eq!(before_cursor, Some(PERSISTED_CURSOR));
    assert_eq!(before_routes.len(), 1);
    assert_eq!(before_routes[0].0, ROTATED_GROUP);
    assert_eq!(before_routes[0].1[0]["nostr_group_id_hex"], RETAINED_ROUTE);
    assert!(
        before_routes[0].1[0].get("replaced_at").is_none(),
        "v0.10.4 did not record route switch times"
    );

    // Forward migration through the production open path.
    let key = SqlCipherKey::new(FIXTURE_KEY).unwrap();
    let store = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
    assert_eq!(
        store.migration_summary().0,
        MIGRATIONS.len() - V0_10_4_LATEST_MIGRATION
    );
    {
        let conn = store.lock().unwrap();
        let ledger = rows(
            &conn,
            "SELECT version, name FROM cgka_schema_migrations ORDER BY version",
        );
        let expected: Vec<Vec<Value>> = MIGRATIONS
            .iter()
            .map(|m| vec![Value::Integer(m.version), Value::Text(m.name.to_owned())])
            .collect();
        assert_eq!(ledger, expected);

        // Same schema as a database created by this build.
        let fresh = SqliteAccountStorage::in_memory().unwrap();
        assert_eq!(schema(&conn), schema(&fresh.lock().unwrap()));

        let integrity: String = conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        assert!(rows(&conn, "PRAGMA foreign_key_check").is_empty());

        // Nothing v0.10.4 held becomes recovery debt or a notice.
        for table in [
            "account_recovery_obligations",
            "account_recovery_scopes",
            "account_delivery_loss_evidence",
            "account_delivery_spill",
            "app_epoch_stall_evidence",
            "app_group_recovery_failures",
        ] {
            assert_eq!(count(&conn, table), 0, "{table} must start empty");
        }

        for (table, before) in PRESERVED_TABLES.iter().zip(&before_tables) {
            let mut expected = before.clone();
            if *table == "chat_list_rows" {
                // Migration 0107 dirties metadata for bounded re-preparation,
                // retaining every original value (especially selected display
                // and avatar bytes). The two appended filter inputs start NULL.
                for row in &mut expected {
                    let Value::Integer(revision) = &mut row[chat_revision_column] else {
                        panic!("fixture presentation revision must be an integer");
                    };
                    *revision += 1;
                    row.extend([Value::Null, Value::Null]);
                }
            }
            assert_eq!(table_rows(&conn, table), expected, "{table} changed");
        }
        assert_eq!(
            count(&conn, "chat_folder_roster_work"),
            count(&conn, "cgka_groups")
        );
        assert_eq!(count(&conn, "chat_folder_rosters"), 0);
        assert_eq!(count(&conn, "chat_folder_members"), 0);
        assert_eq!(cursor(&conn), Some(PERSISTED_CURSOR));
        assert_eq!(retained_routes(&conn), before_routes);
    }
    assert!(store.parked_recovery_obligations().unwrap().is_empty());

    // The first account load stamps the retained route once.
    let first_load = 1_800_000_000;
    assert_eq!(
        store
            .stamp_unrecorded_prior_route_switches(first_load)
            .unwrap(),
        1
    );
    let stamped = retained_routes(&store.lock().unwrap());
    let mut expected = before_routes.clone();
    expected[0].1[0]["replaced_at"] = first_load.into();
    assert_eq!(stamped, expected);
    assert_eq!(
        store
            .stamp_unrecorded_prior_route_switches(first_load + 600)
            .unwrap(),
        0
    );
    assert_eq!(retained_routes(&store.lock().unwrap()), stamped);
    store.close().unwrap();

    // A second open migrates nothing and keeps the stamp.
    let reopened = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
    assert_eq!(reopened.migration_summary().0, 0);
    assert_eq!(
        reopened
            .stamp_unrecorded_prior_route_switches(first_load + 86_400)
            .unwrap(),
        0
    );
    {
        let conn = reopened.lock().unwrap();
        assert_eq!(retained_routes(&conn), stamped);
        assert_eq!(cursor(&conn), Some(PERSISTED_CURSOR));
    }
    assert!(reopened.parked_recovery_obligations().unwrap().is_empty());
    reopened.close().unwrap();

    // v0.10.4 refuses the upgraded database instead of misreading it.
    let mut older = raw(&database);
    let error = run(&mut older, &MIGRATIONS[..V0_10_4_LATEST_MIGRATION]).unwrap_err();
    assert!(matches!(
        error,
        StorageError::UnsupportedSchemaVersion { found, latest_supported }
            if found == MIGRATIONS.last().unwrap().version
                && latest_supported == V0_10_4_LATEST_MIGRATION as i64
    ));
}
