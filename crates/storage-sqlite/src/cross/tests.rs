//! Crossing contracts the protocol and app owners cannot prove alone.

use crate::SqliteAccountStorage;
use crate::app::account_projection::DeleteLocalGroupDataResult;
use rusqlite::params;

fn count(store: &SqliteAccountStorage, sql: &str) -> i64 {
    store
        .lock()
        .unwrap()
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}

/// The logical wipe has committed when the checkpoint finish runs, so a
/// failed finish reports that wipe instead of an error that would invite the
/// caller to restore erased state, and keeps the intent so a retry erases the
/// WAL.
#[test]
fn a_failed_checkpoint_finish_reports_the_committed_wipe_and_keeps_its_intent() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .lock()
        .unwrap()
        .execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('aa', '', 0);
             CREATE TRIGGER fail_finish BEFORE DELETE ON secure_delete_checkpoint_intents
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();

    assert_eq!(
        store.delete_local_group_data("aa").unwrap(),
        DeleteLocalGroupDataResult {
            deleted_rows: 1,
            completed_pending_checkpoint: false,
            erasure_pending: true,
        }
    );
    assert_eq!(count(&store, "SELECT count(*) FROM account_groups"), 0);
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM secure_delete_checkpoint_intents"
        ),
        1
    );

    store
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_finish")
        .unwrap();
    assert_eq!(
        store.delete_local_group_data("aa").unwrap(),
        DeleteLocalGroupDataResult {
            deleted_rows: 1,
            completed_pending_checkpoint: true,
            erasure_pending: false,
        }
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM secure_delete_checkpoint_intents"
        ),
        0
    );
}

/// The app queues an engine authority request only for a message the engine
/// still holds in that group, once.
#[test]
fn an_authority_backfill_is_queued_once_and_only_for_a_message_the_engine_holds() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let conn = store.lock().unwrap();
    conn.execute_batch(
        "INSERT INTO cgka_groups(id, epoch, record) VALUES (x'01', 7, x'00'), (x'02', 7, x'00');
         INSERT INTO cgka_messages(id, group_id, epoch, state, record)
         VALUES (x'aa', x'01', 7, 0, x'00');",
    )
    .unwrap();
    for (message, group) in [(b"\xaa", b"\x02"), (b"\xbb", b"\x01")] {
        super::authority::request_authority_backfill(&conn, message, group, b"stray").unwrap();
    }
    super::authority::request_authority_backfill(&conn, b"\xaa", b"\x01", b"first").unwrap();
    super::authority::request_authority_backfill(&conn, b"\xaa", b"\x01", b"again").unwrap();

    let queued = conn
        .prepare("SELECT message_id, group_id, record FROM pending_application_authority")
        .unwrap()
        .query_map(params![], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(queued, [(vec![0xaa], vec![0x01], b"first".to_vec())]);
}

/// Both the retained chat and a device-group association are private group
/// data, even when a terminal local delete keeps the disband tombstone.
#[test]
fn terminal_local_delete_removes_sibling_welcome_timing_associations() {
    let store = SqliteAccountStorage::in_memory_for_test().unwrap();
    store.lock().unwrap().execute_batch(
        "INSERT INTO cgka_groups(id, epoch, record) VALUES(x'aa', 1, x'00');
         INSERT INTO cgka_disband_tombstones(group_id, record) VALUES(x'aa', x'00');
         INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES('aa', '', 0);
         INSERT INTO sibling_welcome_resends(welcome_id, chat_id, device_group_id, target_slot, carrier, prepared_carrier, last_carrier_created_at)
         VALUES(x'01', x'aa', x'bb', zeroblob(32), x'11', x'11', 1),
               (x'02', x'bb', x'aa', zeroblob(32), x'12', x'12', 1),
               (x'03', x'bb', x'cc', zeroblob(32), x'13', x'13', 1);"
    ).unwrap();
    store.delete_local_group_data("aa").unwrap();
    assert_eq!(
        count(&store, "SELECT count(*) FROM sibling_welcome_resends"),
        1
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM sibling_welcome_resends WHERE welcome_id=x'03'"
        ),
        1
    );
    assert_eq!(
        count(&store, "SELECT count(*) FROM cgka_groups WHERE id=x'aa'"),
        0
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM cgka_disband_tombstones WHERE group_id=x'aa'"
        ),
        1
    );
}

/// A commit refusal (mdk#2333) and a change not delivered (mdk#2332) go with
/// their group's local state, by each wipe branch: forgetting the group and
/// deleting a terminal one remove them, while wiping an active chat keeps the
/// group live, so the warning stays.
#[test]
fn commit_outcome_records_go_with_a_forgotten_or_terminal_group_and_outlive_an_active_wipe() {
    for ((case, tombstone, forget, kept), (table, key)) in [
        ("active wipe", false, false, 1),
        ("terminal delete", true, false, 0),
        ("forget", false, true, 0),
    ]
    .into_iter()
    .flat_map(|wipe| {
        [
            ("cgka_commit_refusals", "fanout_id"),
            ("cgka_changes_not_delivered", "commit_id"),
        ]
        .map(|table| (wipe, table))
    }) {
        let store = SqliteAccountStorage::in_memory_for_test().unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(&format!(
                "INSERT INTO cgka_groups(id, epoch, record) VALUES(x'aa', 1, x'00');
                 INSERT INTO {table}({key}, group_id, record) VALUES(x'01', x'aa', x'00');"
            ))
            .unwrap();
        if tombstone {
            store
                .lock()
                .unwrap()
                .execute_batch(
                    "INSERT INTO cgka_disband_tombstones(group_id, record) VALUES(x'aa', x'00');",
                )
                .unwrap();
        }
        if forget {
            store
                .forget_group_local_data("aa", cgka_traits::Timestamp(1))
                .unwrap();
        } else {
            store.delete_local_group_data("aa").unwrap();
        }
        assert_eq!(
            count(&store, &format!("SELECT count(*) FROM {table}")),
            kept,
            "{table}: {case}"
        );
    }
}

/// Regression for #3798: uppercase or mixed-case `group_id_hex` inputs must
/// normalize to lowercase once before deleting across all app tables and
/// recording the deletion frontier.
#[test]
fn delete_local_group_data_and_forget_normalize_uppercase_group_id_hex() {
    let store = SqliteAccountStorage::in_memory_for_test().unwrap();
    store
        .lock()
        .unwrap()
        .execute_batch(
            "INSERT INTO cgka_groups(id, epoch, record) VALUES(x'aabb', 1, x'00'), (x'ccdd', 1, x'00');
             INSERT INTO account_groups(group_id_hex, endpoint, updated_at)
             VALUES('aabb', '', 0), ('ccdd', '', 0);
             INSERT INTO app_events(group_id_hex, message_id_hex, direction, sender, plaintext, kind, tags_json, recorded_at, received_at)
             VALUES('aabb', 'm1', 'received', 's', 'secret', 9, '[]', 1, 1);
             INSERT INTO chat_list_rows(group_id_hex, updated_at) VALUES('aabb', 1), ('ccdd', 1);
             INSERT INTO encrypted_media_epoch_secrets(group_id_hex, component_id, source_epoch, secret, created_at_unix_seconds)
             VALUES('aabb', 0, 1, x'0102', 1);
             INSERT INTO device_groups(group_id_hex, trust, key_package_ref_hex, recorded_at)
             VALUES('ccdd', 'untrusted', NULL, 1);
             INSERT INTO message_drafts(group_id_hex, content, created_at_ms, updated_at_ms)
             VALUES('ccdd', 'draft', 1, 1);
             INSERT INTO chat_pin_positions(group_id_hex, ordinal) VALUES('ccdd', 1);",
        )
        .unwrap();

    let wiped = store.delete_local_group_data("AABB").unwrap();
    assert!(wiped.did_delete(), "uppercase wipe must delete app rows");
    for table in [
        "account_groups",
        "app_events",
        "chat_list_rows",
        "encrypted_media_epoch_secrets",
    ] {
        assert_eq!(
            count(
                &store,
                &format!("SELECT count(*) FROM {table} WHERE group_id_hex = 'aabb'")
            ),
            0,
            "{table} still retained rows after uppercase delete_local_group_data"
        );
    }
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM local_group_deletion_frontiers WHERE group_id_hex = 'aabb'"
        ),
        1
    );

    assert!(
        store
            .forget_group_local_data("CcDd", cgka_traits::Timestamp(10))
            .unwrap()
    );
    for table in [
        "account_groups",
        "chat_list_rows",
        "device_groups",
        "message_drafts",
        "chat_pin_positions",
    ] {
        assert_eq!(
            count(
                &store,
                &format!("SELECT count(*) FROM {table} WHERE group_id_hex = 'ccdd'")
            ),
            0,
            "{table} still retained rows after mixed-case forget_group_local_data"
        );
    }
}

/// Regression for PR #3818 review: group wipe must delete persisted uppercase
/// and mixed-case rows (such as public app-event writes storing verbatim casing)
/// and complete or preserve pre-upgrade pending WAL checkpoint intents recorded
/// under non-lowercase scopes.
#[test]
fn delete_local_group_data_wipes_persisted_mixed_case_rows_and_pre_upgrade_intents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed-case-wipe.sqlite");
    let key = crate::SqlCipherKey::raw([0x77; 32]);
    let store = SqliteAccountStorage::open_encrypted_with_options(
        &path,
        &key,
        crate::SqliteStorageOptions {
            busy_timeout_ms: 0,
            ..crate::SqliteStorageOptions::default()
        },
    )
    .unwrap();

    // 1. Public app-event write stores uppercase `group_id_hex` verbatim, along
    //    with persisted uppercase/mixed-case rows in other app/forget tables.
    store
        .app_storage()
        .record_app_event(&crate::StoredAppEvent {
            group_id_hex: "AABB".to_owned(),
            message_id_hex: "m1".to_owned(),
            source_message_id_hex: None,
            source_epoch: None,
            direction: "received".to_owned(),
            sender: "alice".to_owned(),
            plaintext: "persisted uppercase".to_owned(),
            kind: 9,
            tags: Vec::new(),
            recorded_at: 1,
            received_at: 1,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute_batch(
            "INSERT INTO cgka_groups(id, epoch, record) VALUES(x'aabb', 1, x'00'), (x'ccdd', 1, x'00');
             INSERT INTO account_groups(group_id_hex, endpoint, updated_at)
             VALUES('AABB', '', 0), ('CcDd', '', 0);
             INSERT INTO chat_list_rows(group_id_hex, updated_at) VALUES('AABB', 1), ('CcDd', 1);
             INSERT INTO encrypted_media_epoch_secrets(group_id_hex, component_id, source_epoch, secret, created_at_unix_seconds)
             VALUES('AABB', 0, 1, x'0102', 1);
             INSERT INTO device_groups(group_id_hex, trust, key_package_ref_hex, recorded_at)
             VALUES('CcDd', 'untrusted', NULL, 1);
             INSERT INTO message_drafts(group_id_hex, content, created_at_ms, updated_at_ms)
             VALUES('CcDd', 'draft', 1, 1);",
        )
        .unwrap();

    let wiped = store.delete_local_group_data("aabb").unwrap();
    assert!(
        wiped.did_delete(),
        "wipe must delete persisted uppercase rows"
    );
    for table in [
        "app_events",
        "message_timeline",
        "account_groups",
        "chat_list_rows",
        "encrypted_media_epoch_secrets",
    ] {
        assert_eq!(
            count(
                &store,
                &format!("SELECT count(*) FROM {table} WHERE LOWER(group_id_hex) = 'aabb'")
            ),
            0,
            "{table} still retained mixed-case rows after lowercase wipe"
        );
    }
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM encrypted_media_epoch_secret_retirement_watermarks WHERE group_id_hex = 'aabb'"
        ),
        1
    );

    assert!(
        store
            .forget_group_local_data("ccdd", cgka_traits::Timestamp(10))
            .unwrap()
    );
    for table in [
        "account_groups",
        "chat_list_rows",
        "device_groups",
        "message_drafts",
    ] {
        assert_eq!(
            count(
                &store,
                &format!("SELECT count(*) FROM {table} WHERE LOWER(group_id_hex) = 'ccdd'")
            ),
            0,
            "{table} still retained mixed-case rows after lowercase forget"
        );
    }

    // 2. Pre-upgrade pending WAL checkpoint intent stored under uppercase scope
    //    `'EEFF'`: an empty retry while WAL checkpoint is blocked must report
    //    `erasure_pending = true`, and a subsequent retry after the reader
    //    releases must consume the old intent and report completion.
    let op = crate::app::account_projection::SECURE_DELETE_LOCAL_GROUP_OPERATION;
    store
        .lock()
        .unwrap()
        .execute(
            r#"INSERT INTO secure_delete_checkpoint_intents(operation_kind, scope, intent_nonce, result_json)
               VALUES(?1, 'EEFF', randomblob(16), '{"deleted_rows":4,"completed_pending_checkpoint":false,"erasure_pending":false}')"#,
            params![op],
        )
        .unwrap();
    let reader = rusqlite::Connection::open(&path).unwrap();
    crate::open_hardened_sqlcipher(&reader, &key, crate::SqlCipherHardening::cipher_only())
        .unwrap();
    reader
        .execute_batch("BEGIN; SELECT count(*) FROM sqlite_master;")
        .unwrap();

    let blocked_retry = store.delete_local_group_data("eeff").unwrap();
    assert_eq!(
        blocked_retry,
        DeleteLocalGroupDataResult {
            deleted_rows: 4,
            completed_pending_checkpoint: false,
            erasure_pending: true,
        },
        "empty retry must preserve pre-upgrade uppercase pending checkpoint intent while reader blocks WAL truncate"
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM secure_delete_checkpoint_intents"
        ),
        1
    );

    reader.execute_batch("COMMIT;").unwrap();
    drop(reader);

    let completed_retry = store.delete_local_group_data("EEFF").unwrap();
    assert_eq!(
        completed_retry,
        DeleteLocalGroupDataResult {
            deleted_rows: 4,
            completed_pending_checkpoint: true,
            erasure_pending: false,
        },
        "empty retry after reader releases must consume pre-upgrade uppercase intent"
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM secure_delete_checkpoint_intents"
        ),
        0
    );

    // 3. Merging a new deletion onto a pre-upgrade uppercase intent consolidates
    //    the accumulated count under canonical lowercase scope and drops the old row.
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES('DD01', '', 0)",
            [],
        )
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            r#"INSERT INTO secure_delete_checkpoint_intents(operation_kind, scope, intent_nonce, result_json)
               VALUES(?1, 'DD01', randomblob(16), '{"deleted_rows":3,"completed_pending_checkpoint":false,"erasure_pending":false}')"#,
            params![op],
        )
        .unwrap();
    let reader = rusqlite::Connection::open(&path).unwrap();
    crate::open_hardened_sqlcipher(&reader, &key, crate::SqlCipherHardening::cipher_only())
        .unwrap();
    reader
        .execute_batch("BEGIN; SELECT count(*) FROM sqlite_master;")
        .unwrap();

    let merged_blocked = store.delete_local_group_data("dd01").unwrap();
    assert_eq!(
        merged_blocked,
        DeleteLocalGroupDataResult {
            deleted_rows: 4,
            completed_pending_checkpoint: false,
            erasure_pending: true,
        }
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM secure_delete_checkpoint_intents WHERE scope = 'dd01'"
        ),
        1
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM secure_delete_checkpoint_intents WHERE scope = 'DD01'"
        ),
        0
    );
    reader.execute_batch("COMMIT;").unwrap();
    drop(reader);

    let merged_done = store.delete_local_group_data("DD01").unwrap();
    assert_eq!(
        merged_done,
        DeleteLocalGroupDataResult {
            deleted_rows: 4,
            completed_pending_checkpoint: true,
            erasure_pending: false,
        }
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM secure_delete_checkpoint_intents"
        ),
        0
    );

    // 4. Coexisting uppercase and lowercase pending intents both complete
    //    atomically on an empty retry with their row counts summed.
    store
        .lock()
        .unwrap()
        .execute(
            r#"INSERT INTO secure_delete_checkpoint_intents(operation_kind, scope, intent_nonce, result_json)
               VALUES(?1, 'FF01', randomblob(16), '{"deleted_rows":2,"completed_pending_checkpoint":false,"erasure_pending":false}'),
                     (?1, 'ff01', randomblob(16), '{"deleted_rows":5,"completed_pending_checkpoint":false,"erasure_pending":false}')"#,
            params![op],
        )
        .unwrap();
    let combined_done = store.delete_local_group_data("ff01").unwrap();
    assert_eq!(
        combined_done,
        DeleteLocalGroupDataResult {
            deleted_rows: 7,
            completed_pending_checkpoint: true,
            erasure_pending: false,
        }
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM secure_delete_checkpoint_intents"
        ),
        0
    );
}

/// Regression for #3798 / PR #3818 review: wiping an uppercase or mixed-case
/// group must leave a retirement barrier that still fences subsequent
/// `remember_encrypted_media_epoch_secret`, `encrypted_media_epoch_secret`, and
/// `encrypted_media_epoch_secret_may_be_served` calls made with uppercase or
/// mixed-case `group_id_hex`.
#[test]
fn uppercase_wipe_retirement_watermark_fences_uppercase_secret_restoration() {
    let store = SqliteAccountStorage::in_memory_for_test().unwrap();
    let app = store.app_storage();

    app.remember_encrypted_media_epoch_secret("AABB", 1, 5, b"original-secret")
        .unwrap();
    assert_eq!(
        app.encrypted_media_epoch_secret("AABB", 1, 5)
            .unwrap()
            .as_deref(),
        Some(b"original-secret".as_slice())
    );
    assert!(
        app.encrypted_media_epoch_secret_may_be_served("AABB", 5)
            .unwrap()
    );

    let wiped = store.delete_local_group_data("AABB").unwrap();
    assert!(wiped.did_delete());

    // Attempting to re-insert the wiped epoch secret with uppercase or
    // mixed-case group id must be fenced by the retirement watermark.
    app.remember_encrypted_media_epoch_secret("AABB", 1, 5, b"resurrected")
        .unwrap();
    app.remember_encrypted_media_epoch_secret("AaBb", 1, 5, b"resurrected")
        .unwrap();
    for casing in ["AABB", "AaBb", "aabb"] {
        assert_eq!(
            app.encrypted_media_epoch_secret(casing, 1, 5).unwrap(),
            None,
            "wiped secret must not be restorable under casing {casing}"
        );
        assert!(
            !app.encrypted_media_epoch_secret_may_be_served(casing, 5)
                .unwrap(),
            "may_be_served must remain false under casing {casing}"
        );
    }

    // A pre-existing uppercase watermark (written before canonicalization)
    // must also fence lowercase callers.
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO encrypted_media_epoch_secret_retirement_watermarks(
                 group_id_hex, retired_through_epoch, retired_at_unix_seconds
             ) VALUES('EE01', 10, 1)",
            [],
        )
        .unwrap();
    app.remember_encrypted_media_epoch_secret("ee01", 1, 5, b"blocked")
        .unwrap();
    assert_eq!(
        app.encrypted_media_epoch_secret("ee01", 1, 5).unwrap(),
        None
    );
    assert!(
        !app.encrypted_media_epoch_secret_may_be_served("ee01", 5)
            .unwrap()
    );
}

/// Regression for #3798 / PR #3818 review: `delete_local_group_data` must keep
/// indexed `group_id_hex` lookups on large message tables (`app_events`,
/// `message_timeline`) rather than forcing full-table scans via `LOWER(...)`.
#[test]
fn delete_local_group_data_uses_group_id_indexes_on_large_tables() {
    thread_local! {
        static DELETE_SQLS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    fn record_deletes(event: rusqlite::trace::TraceEvent<'_>) {
        if let rusqlite::trace::TraceEvent::Stmt(_, sql) = event
            && (sql.contains("DELETE FROM app_events ")
                || sql.contains("DELETE FROM message_timeline "))
        {
            DELETE_SQLS.with_borrow_mut(|sqls| sqls.push(sql.to_owned()));
        }
    }

    let store = SqliteAccountStorage::in_memory_for_test().unwrap();
    DELETE_SQLS.with_borrow_mut(Vec::clear);
    store.lock().unwrap().trace_v2(
        rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
        Some(record_deletes),
    );
    store.delete_local_group_data("aabb").unwrap();
    store
        .lock()
        .unwrap()
        .trace_v2(rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT, None);

    let sqls = DELETE_SQLS.take();
    assert_eq!(
        sqls.len(),
        2,
        "expected app_events and message_timeline deletes: {sqls:?}"
    );
    let conn = store.lock().unwrap();
    for sql in sqls {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let params_vec = vec!["aabb"; stmt.parameter_count()];
        let details: Vec<String> = stmt
            .query_map(rusqlite::params_from_iter(params_vec), |row| {
                row.get::<_, String>(3)
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let target_plan = details.first().map(String::as_str).unwrap_or("");
        assert!(
            target_plan.starts_with("SEARCH ") && target_plan.contains("USING "),
            "expected indexed SEARCH plan for `{sql}`, got {details:?}"
        );
        assert!(
            !target_plan.starts_with("SCAN "),
            "must not full-table SCAN target table for `{sql}`, got {details:?}"
        );
    }
}
