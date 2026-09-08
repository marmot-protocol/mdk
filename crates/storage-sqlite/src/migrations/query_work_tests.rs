use crate::SqliteAccountStorage;
use crate::encrypted_media_secrets::retire_unreferenced_encrypted_media_secret_epochs_tx;
use rusqlite::StatementStatus;
use rusqlite::trace::{TraceEvent, TraceEventCodes};
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;

static QUERY_STEPS: AtomicI64 = AtomicI64::new(0);
static QUERY_MEASUREMENT: Mutex<()> = Mutex::new(());

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
    assert!(
        steps < max_steps,
        "{label}: {steps} >= {max_steps}, elapsed={elapsed:?}"
    );
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
    let _measurement = QUERY_MEASUREMENT.lock().unwrap();
    for count in [256, 4_096] {
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

fn seed_replay_history(store: &SqliteAccountStorage, count: i64, now: i64) {
    let group = openmls::group::GroupId::from_slice(&[0xaa]);
    let group_key = serde_json::to_vec(&group).unwrap();
    let conn = store.lock().unwrap();
    conn.execute_batch("CREATE TEMP TABLE fixture_numbers(x INTEGER PRIMARY KEY);")
        .unwrap();
    conn.execute(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < ?1)
         INSERT INTO fixture_numbers SELECT x FROM n",
        [count],
    )
    .unwrap();
    conn.execute_batch(
        "INSERT INTO cgka_groups(id, epoch, record) VALUES (x'cc', 1, x'00'), (x'dd', 1, x'00');
         INSERT INTO cgka_messages(id, group_id, epoch, state, storage_format, payload)
         SELECT CAST('c' || printf('%032x', x) AS BLOB), x'cc', x, 2, 2, x'00' FROM fixture_numbers;
         INSERT INTO cgka_messages(id, group_id, epoch, state, storage_format, payload)
         SELECT CAST('d' || printf('%032x', x) AS BLOB), x'dd', x, 2, 2, x'00' FROM fixture_numbers;
         INSERT INTO app_events(group_id_hex, message_id_hex, direction, sender,
             plaintext, kind, tags_json, recorded_at, received_at)
         SELECT CASE WHEN x%2 = 0 THEN 'aa' ELSE 'bb' END, printf('%064x', x),
             'received', 'sender', 'text', 9, '[]', x, x FROM fixture_numbers;",
    )
    .unwrap();
    // Frozen storage labels: cached epoch keys must survive proposal cleanup.
    conn.execute(
        "INSERT INTO openmls_values(provider_version, label, storage_key, group_key, value)
         SELECT ?1, CAST('EpochKeyPairs' AS BLOB), CAST(printf('%032x', x) AS BLOB), ?2, x'00'
         FROM fixture_numbers",
        rusqlite::params![openmls_traits::storage::CURRENT_VERSION, group_key],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO openmls_values(provider_version, label, storage_key, value)
         SELECT ?1, CAST('KeyPackage' AS BLOB), CAST('kp' || x AS BLOB), x'00'
         FROM fixture_numbers WHERE x <= 4",
        [openmls_traits::storage::CURRENT_VERSION],
    )
    .unwrap();
    for (label, key) in [
        (b"QueuedProposal".as_slice(), b"queue".as_slice()),
        (b"ProposalQueueRefs".as_slice(), b"refs".as_slice()),
    ] {
        conn.execute(
            "INSERT INTO openmls_values(provider_version, label, storage_key, group_key, value)
             VALUES (?1, ?2, ?3, ?4, x'00')",
            rusqlite::params![
                openmls_traits::storage::CURRENT_VERSION,
                label,
                key,
                group_key
            ],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO transport_reconciliation_items(route_kind, route_id, event_id, created_at)
         SELECT 0, x'', CAST(printf('%032x', x) AS BLOB), ?1 FROM fixture_numbers",
        [now],
    )
    .unwrap();
    conn.execute_batch("DROP TABLE fixture_numbers;").unwrap();
}

#[test]
fn replay_query_work() {
    use cgka_traits::storage::{KeyPackageBundleStorage, MessageStorage};
    use openmls_traits::storage::StorageProvider;

    let _measurement = QUERY_MEASUREMENT.lock().unwrap();
    for count in [256, 4_096] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let now = crate::unix_now_seconds();
        seed_replay_history(&store, count, i64::try_from(now).unwrap());

        let messages = measured(&store, "account recent messages", 1_000, || {
            store
                .app_messages(crate::StoredAppMessageQuery {
                    group_id_hex: None,
                    kinds: None,
                    limit: Some(16),
                })
                .unwrap()
        });
        assert_eq!(
            messages
                .iter()
                .map(|row| row.recorded_at)
                .collect::<Vec<_>>(),
            ((count - 15) as u64..=count as u64).collect::<Vec<_>>()
        );

        let packages = measured(&store, "key package enumeration", 50, || {
            store.stored_key_package_bundles().unwrap()
        });
        assert_eq!(packages.len(), 4);
        assert!(
            packages
                .iter()
                .all(|package| package.value.as_slice() == [0])
        );

        measured(&store, "proposal queue cleanup", 120, || {
            store.openmls.clear_proposal_queue::<openmls::group::GroupId,
                openmls::ciphersuite::hash_ref::ProposalRef>(&openmls::group::GroupId::from_slice(&[0xaa])).unwrap();
        });
        let remaining: i64 = store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM openmls_values", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, count + 4);

        measured(&store, "local deletion frontier", 400, || {
            store.delete_local_group_data("cc").unwrap();
        });
        let frontier = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT message_insert_order FROM local_group_deletion_frontiers
             WHERE group_id_hex = 'cc'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(frontier, count);

        // Adding a frontier index must not turn an epoch-range read into a history scan.
        let messages = measured(&store, "epoch filtered messages", 50, || {
            store
                .list_messages(
                    &cgka_traits::GroupId::new(vec![0xcc]),
                    cgka_traits::EpochId(count as u64),
                )
                .unwrap()
        });
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].epoch.0, count as u64);

        measured(&store, "duplicate reconciliation", 120, || {
            store
                .record_transport_reconciliation_item(
                    &crate::TransportReconciliationRoute::Inbox,
                    &crate::TransportReconciliationItem {
                        event_id: format!("{count:032x}").into_bytes().try_into().unwrap(),
                        created_at: now,
                    },
                )
                .unwrap();
        });
        let retained: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM transport_reconciliation_items",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, count);
    }
}

#[test]
fn openmls_index_scope() {
    use cgka_traits::storage::KeyPackageBundleStorage;
    use openmls_traits::storage::StorageProvider;

    let store = SqliteAccountStorage::in_memory().unwrap();
    seed_replay_history(&store, 16, 0);
    {
        let conn = store.lock().unwrap();
        conn.execute_batch(
            "INSERT INTO openmls_values
             SELECT provider_version + 1, label, storage_key, group_key, value
             FROM openmls_values;
             INSERT INTO openmls_values
             SELECT provider_version, label, storage_key || 'other', x'ff', value
             FROM openmls_values WHERE label = CAST('QueuedProposal' AS BLOB);",
        )
        .unwrap();
    }
    assert_eq!(store.stored_key_package_bundles().unwrap().len(), 4);
    store.openmls.clear_proposal_queue::<openmls::group::GroupId,
        openmls::ciphersuite::hash_ref::ProposalRef>(
            &openmls::group::GroupId::from_slice(&[0xaa])).unwrap();
    let remaining: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM openmls_values WHERE label = CAST('QueuedProposal' AS BLOB)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 3);
}

#[test]
fn query_indexes_upgrade() {
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    super::run(&mut conn, &super::MIGRATIONS[..62]).unwrap();
    seed_query_history(&conn, 256);
    conn.execute_batch("INSERT INTO openmls_values VALUES (1, x'01', x'02', x'03', x'04');")
        .unwrap();
    // Keep comparing every pre-upgrade column, even when later migrations add new ones.
    let tables: Vec<_> = [
        "cgka_messages",
        "app_events",
        "encrypted_media_epoch_secrets",
        "cgka_disband_tombstones",
        "account_groups",
        "chat_list_rows",
        "openmls_values",
    ]
    .into_iter()
    .map(|table| {
        let mut query = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let columns = query
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        (table, columns.join(", "))
    })
    .collect();
    let contents = |conn: &rusqlite::Connection| {
        let mut rows = Vec::new();
        for (table, columns) in &tables {
            let mut stmt = conn
                .prepare(&format!("SELECT {columns} FROM {table} ORDER BY rowid"))
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
    let tx = conn.transaction().unwrap();
    super::migration_0063_query_indexes::apply(&tx).unwrap();
    tx.execute_batch("DROP INDEX idx_openmls_values_group;")
        .unwrap();
    super::migration_0063_query_indexes::apply(&tx).unwrap();
    tx.commit().unwrap();
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
