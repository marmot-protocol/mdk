use crate::SqliteAccountStorage;
use crate::encrypted_media_secrets::retire_unreferenced_encrypted_media_secret_epochs_tx;
use rusqlite::StatementStatus;
use rusqlite::trace::{TraceEvent, TraceEventCodes};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;

static QUERY_STEPS: AtomicI64 = AtomicI64::new(0);

fn measured<T>(
    store: &SqliteAccountStorage,
    label: &str,
    max_steps: i64,
    action: impl FnOnce() -> T,
) -> T {
    {
        let conn = store.lock().unwrap();
        conn.flush_prepared_statement_cache();
        QUERY_STEPS.store(0, Ordering::Relaxed);
        conn.trace_v2(
            TraceEventCodes::SQLITE_TRACE_PROFILE,
            Some(|event| {
                if let TraceEvent::Profile(statement, _) = event {
                    QUERY_STEPS.fetch_add(
                        i64::from(statement.get_status(StatementStatus::VmStep)),
                        Ordering::Relaxed,
                    );
                }
            }),
        );
    }
    let start = Instant::now();
    let result = action();
    let elapsed = start.elapsed();
    store
        .lock()
        .unwrap()
        .trace_v2(TraceEventCodes::empty(), None);
    let steps = QUERY_STEPS.load(Ordering::Relaxed);
    eprintln!("{label}: {steps} VM steps, {elapsed:?}");
    assert!(steps < max_steps, "{label}: {steps} >= {max_steps}");
    result
}

fn seed_query_history(conn: &rusqlite::Connection, count: i64) {
    conn.execute_batch(
        "CREATE TEMP TABLE fixture_numbers(x INTEGER PRIMARY KEY);
         INSERT INTO cgka_groups(id, epoch, record) VALUES (x'aa', 1, x'00');",
    )
    .unwrap();
    conn.execute(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < ?1)
         INSERT INTO fixture_numbers SELECT x FROM n",
        [count],
    )
    .unwrap();
    conn.execute_batch(
        "INSERT INTO cgka_messages(id, group_id, epoch, state, storage_format, payload)
         SELECT CAST(printf('%032x', x) AS BLOB), x'aa', x, 2, 2, x'00'
         FROM fixture_numbers;
         INSERT INTO app_events(group_id_hex, message_id_hex, direction, sender,
             plaintext, kind, tags_json, recorded_at, received_at)
         SELECT 'aa', printf('%064x', x), 'received', 'sender', 'text', 9, '[]', x, x
         FROM fixture_numbers;
         UPDATE app_events SET origin_commit_id = (
             SELECT lower(hex(id)) FROM cgka_messages WHERE insert_order = 1
         ), invalidated = 1, invalidation_reason = 'SupersededByBranchSelection'
         WHERE insert_order IN (1, 2);
         UPDATE cgka_messages SET state = 7 WHERE insert_order = 3;
         UPDATE app_events SET origin_commit_id = (
             SELECT lower(hex(id)) FROM cgka_messages WHERE insert_order = 3
         ) WHERE insert_order IN (3, 4);
         INSERT INTO encrypted_media_epoch_secrets(group_id_hex, component_id,
             source_epoch, secret, created_at_unix_seconds, retention_managed)
         SELECT 'aa', 1, x, x'1234', 0, 1 FROM fixture_numbers;
         INSERT INTO cgka_disband_tombstones(group_id, record)
         SELECT CAST(printf('%032x', x) AS BLOB), x'00' FROM fixture_numbers;
         INSERT INTO account_groups(group_id_hex, endpoint, updated_at)
         SELECT printf('%032x', x), 'fixture', 0 FROM fixture_numbers WHERE x <= 32;
         INSERT INTO chat_list_rows(group_id_hex, updated_at, unread_count)
         SELECT group_id_hex, 0, 1 FROM account_groups;
         DROP TABLE fixture_numbers;",
    )
    .unwrap();
}

#[test]
fn maintenance_query_work() {
    for count in [256, 4_096] {
        eprintln!("history rows={count}");
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed_query_history(&store.lock().unwrap(), count);

        let promotion = measured(&store, "legacy promotion", 64, || {
            store.promote_legacy_message_rows(16).unwrap()
        });
        assert_eq!(promotion.promoted, 0);
        assert!(!promotion.has_more);

        let pending = measured(&store, "terminal pending sends", 64, || {
            store
                .invalidate_pending_sent_app_events_for_group("aa", "terminal")
                .unwrap()
        });
        assert!(pending.is_none());

        let unread = measured(&store, "unread disband checks", 1_600, || {
            store.account_unread_total().unwrap()
        });
        assert_eq!(unread.unread_count, 32);

        let branches = measured(&store, "branch reconciliation", 256, || {
            store.diverged_branch_selection_withdrawals().unwrap()
        });
        assert_eq!(branches.to_revive, [hex::encode(format!("{:032x}", 1))]);
        assert_eq!(branches.to_withdraw, [hex::encode(format!("{:032x}", 3))]);

        let retired = measured(&store, "media epoch retirement", 160, || {
            let mut conn = store.lock().unwrap();
            let tx = conn.transaction().unwrap();
            let count = retire_unreferenced_encrypted_media_secret_epochs_tx(
                &tx,
                "aa",
                &BTreeSet::from([count]),
            )
            .unwrap();
            tx.commit().unwrap();
            count
        });
        assert_eq!(retired, 1);

        // A matching opaque id still excludes its chat, including uppercase hex.
        store
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO cgka_disband_tombstones VALUES (x'abcd', x'00');
             INSERT INTO account_groups(group_id_hex, endpoint, updated_at)
             VALUES ('ABCD', 'fixture', 0);
             INSERT INTO chat_list_rows(group_id_hex, updated_at, unread_count)
             VALUES ('ABCD', 0, 5);",
            )
            .unwrap();
        assert_eq!(store.account_unread_total().unwrap().unread_count, 32);
    }
}

#[test]
fn query_indexes_upgrade() {
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    super::run(&mut conn, &super::MIGRATIONS[..62]).unwrap();
    seed_query_history(&conn, 256);
    let contents = |conn: &rusqlite::Connection| {
        let mut rows = Vec::new();
        for table in [
            "cgka_messages",
            "app_events",
            "encrypted_media_epoch_secrets",
            "cgka_disband_tombstones",
            "account_groups",
            "chat_list_rows",
        ] {
            let mut stmt = conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let columns = stmt.column_count();
            rows.extend(
                stmt.query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get::<_, rusqlite::types::Value>(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap(),
            );
        }
        rows
    };
    let before = contents(&conn);
    super::run_all(&mut conn).unwrap();
    super::run_all(&mut conn).unwrap();
    assert_eq!(contents(&conn), before);
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
}

#[test]
fn branch_origin_hex_matching() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed_query_history(&store.lock().unwrap(), 256);
    store
        .lock()
        .unwrap()
        .execute_batch(
            "INSERT INTO cgka_messages(id, group_id, epoch, state, storage_format, payload)
         VALUES (x'abcd', x'aa', 1, 7, 2, x'00');
         UPDATE app_events SET origin_commit_id = 'ABCD' WHERE insert_order = 5;
         UPDATE app_events SET origin_commit_id = 'abcd!' WHERE insert_order = 6;
         UPDATE app_events SET origin_commit_id = '' WHERE insert_order = 7;
         UPDATE app_events SET origin_commit_id = 'abc' WHERE insert_order = 8;",
        )
        .unwrap();
    let branches = store.diverged_branch_selection_withdrawals().unwrap();
    assert_eq!(branches.to_withdraw, [hex::encode(format!("{:032x}", 3))]);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE app_events SET origin_commit_id = 'abcd' WHERE insert_order = 5",
            [],
        )
        .unwrap();
    let branches = store.diverged_branch_selection_withdrawals().unwrap();
    assert_eq!(
        branches.to_withdraw,
        [hex::encode(format!("{:032x}", 3)), "abcd".to_owned()]
    );
}
