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

/// Regression for PR #3818 review: migration 0228 canonicalizes pre-existing
/// mixed-case rows and pending WAL checkpoint intents on upgrade so plain
/// indexed lowercase wipes and checkpoint retries handle them without loose
/// index scans or `LOWER(...)` runtime predicates.
#[test]
fn delete_local_group_data_wipes_persisted_mixed_case_rows_and_pre_upgrade_intents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed-case-wipe.sqlite");
    let key = crate::SqlCipherKey::raw([0x77; 32]);
    let op = crate::app::account_projection::SECURE_DELETE_LOCAL_GROUP_OPERATION;

    // Seed a pre-0228 encrypted database containing mixed-case/uppercase rows
    // and pre-upgrade uppercase/colliding pending WAL checkpoint intents.
    {
        let mut raw = rusqlite::Connection::open(&path).unwrap();
        crate::open_hardened_sqlcipher(&raw, &key, crate::SqlCipherHardening::live_cache())
            .unwrap();
        crate::base::migrations::run_through(&mut raw, 227).unwrap();
        raw.execute_batch(
            "INSERT INTO cgka_groups(id, epoch, record) VALUES(x'aabb', 1, x'00'), (x'ccdd', 1, x'00');
             INSERT INTO account_groups(group_id_hex, endpoint, updated_at)
             VALUES('AABB', '', 0), ('CcDd', '', 0), ('DD01', '', 0);
             INSERT INTO chat_list_rows(group_id_hex, updated_at) VALUES('AABB', 1), ('CcDd', 1);
             INSERT INTO app_events(
                 group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                 tags_json, recorded_at, received_at
             ) VALUES('AABB', 'm1', 'received', 'alice', 'persisted uppercase', 9, '[]', 1, 1);
             INSERT INTO message_timeline(
                 group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                 tags_json, timeline_at, received_at, reactions_json
             ) VALUES('AABB', 'm1', 'received', 'alice', 'persisted uppercase', 9, '[]', 1, 1, '[]');
             INSERT INTO encrypted_media_epoch_secrets(
                 group_id_hex, component_id, source_epoch, secret, created_at_unix_seconds
             ) VALUES('AABB', 0, 1, x'0102', 1);
             INSERT INTO device_groups(group_id_hex, trust, key_package_ref_hex, recorded_at)
             VALUES('CcDd', 'untrusted', NULL, 1);
             INSERT INTO message_drafts(group_id_hex, content, created_at_ms, updated_at_ms)
             VALUES('CcDd', 'draft', 1, 1);",
        )
        .unwrap();
        raw.execute(
            r#"INSERT INTO secure_delete_checkpoint_intents(operation_kind, scope, intent_nonce, result_json)
               VALUES(?1, 'EEFF', randomblob(16), '{"deleted_rows":4,"completed_pending_checkpoint":false,"erasure_pending":false}'),
                     (?1, 'DD01', randomblob(16), '{"deleted_rows":3,"completed_pending_checkpoint":false,"erasure_pending":false}'),
                     (?1, 'FF01', randomblob(16), '{"deleted_rows":2,"completed_pending_checkpoint":false,"erasure_pending":false}'),
                     (?1, 'ff01', randomblob(16), '{"deleted_rows":5,"completed_pending_checkpoint":false,"erasure_pending":false}')"#,
            params![op],
        )
        .unwrap();
    }

    // Opening runs migration 0228 and canonicalizes every persisted group id
    // and checkpoint scope to lowercase ASCII.
    let store = SqliteAccountStorage::open_encrypted_with_options(
        &path,
        &key,
        crate::SqliteStorageOptions {
            busy_timeout_ms: 0,
            ..crate::SqliteStorageOptions::default()
        },
    )
    .unwrap();

    // 1. Public app-event write with uppercase group id also stores canonical
    //    lowercase on disk, and lowercase wipe deletes both migrated and new rows.
    let update = store
        .app_storage()
        .record_app_event(&crate::StoredAppEvent {
            group_id_hex: "AABB".to_owned(),
            message_id_hex: "m2".to_owned(),
            source_message_id_hex: None,
            source_epoch: None,
            direction: "received".to_owned(),
            sender: "alice".to_owned(),
            plaintext: "written after upgrade".to_owned(),
            kind: 9,
            tags: Vec::new(),
            recorded_at: 2,
            received_at: 2,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    assert_eq!(update.group_id_hex, "aabb");
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM app_events WHERE group_id_hex = 'aabb'"
        ),
        2
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM app_events WHERE group_id_hex != lower(group_id_hex)"
        ),
        0
    );

    let wiped = store.delete_local_group_data("aabb").unwrap();
    assert!(
        wiped.did_delete(),
        "wipe must delete migrated and newly written rows"
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
            "{table} still retained rows after lowercase wipe"
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
            "{table} still retained rows after lowercase forget"
        );
    }

    // 2. Pre-upgrade pending WAL checkpoint intent migrated from `'EEFF'` -> `'eeff'`:
    //    an empty retry while WAL checkpoint is blocked reports `erasure_pending = true`,
    //    and a retry after the reader releases consumes it and reports completion.
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
        "empty retry must preserve migrated pending checkpoint intent while reader blocks WAL truncate"
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
        "empty retry after reader releases must consume migrated pending intent"
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM secure_delete_checkpoint_intents WHERE scope = 'eeff'"
        ),
        0
    );

    // 3. Merging a new deletion onto a migrated intent (`'DD01'` -> `'dd01'`)
    //    accumulates the deleted row count under canonical lowercase scope.
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

    // 4. Colliding pre-upgrade uppercase (`'FF01'`, 2) and lowercase (`'ff01'`, 5)
    //    intents were folded by migration 0228 into a single lowercase row (7)
    //    that completes atomically on retry.
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
/// group must leave a canonical retirement barrier that fences subsequent
/// `remember_encrypted_media_epoch_secret`, `encrypted_media_epoch_secret`, and
/// `encrypted_media_epoch_secret_may_be_served` calls made with any casing,
/// and migration 0228 canonicalizes pre-existing non-lowercase watermarks.
#[test]
fn uppercase_wipe_retirement_watermark_fences_uppercase_secret_restoration() {
    let mut raw = rusqlite::Connection::open_in_memory().unwrap();
    raw.pragma_update(None, "foreign_keys", true).unwrap();
    crate::base::migrations::run_through(&mut raw, 227).unwrap();
    raw.execute(
        "INSERT INTO encrypted_media_epoch_secret_retirement_watermarks(
             group_id_hex, retired_through_epoch, retired_at_unix_seconds
         ) VALUES('EE01', 10, 1), ('EeFf', 10, 1)",
        [],
    )
    .unwrap();
    let store = SqliteAccountStorage::from_connection_with_options(
        raw,
        crate::SqliteStorageOptions::default(),
    )
    .unwrap();
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

    // Pre-existing uppercase/mixed-case watermarks migrated by 0228 must fence
    // both lowercase and uppercase callers.
    for (target, probe) in [
        ("ee01", "ee01"),
        ("eeff", "eeff"),
        ("EEFF", "eeff"),
        ("EeFf", "eeff"),
    ] {
        app.remember_encrypted_media_epoch_secret(target, 1, 5, b"blocked")
            .unwrap();
        assert_eq!(
            app.encrypted_media_epoch_secret(probe, 1, 5).unwrap(),
            None,
            "migrated watermark must fence secret restoration for {target} -> {probe}"
        );
        assert!(
            !app.encrypted_media_epoch_secret_may_be_served(probe, 5)
                .unwrap(),
            "migrated watermark must keep may_be_served false for {probe}"
        );
    }
}

/// Regression for #3798 / PR #3818 review: mixed-case secrets and app events
/// without matching `account_groups` / `chat_list_rows` rows (both via public
/// API canonicalization and upgraded from pre-0228 storage) are wiped and
/// fenced by `delete_local_group_data`.
#[test]
fn wipe_discovers_and_fences_mixed_case_secrets_and_events_without_projection_rows() {
    let mut raw = rusqlite::Connection::open_in_memory().unwrap();
    raw.pragma_update(None, "foreign_keys", true).unwrap();
    crate::base::migrations::run_through(&mut raw, 227).unwrap();
    raw.execute_batch(
        "INSERT INTO encrypted_media_epoch_secrets(
             group_id_hex, component_id, source_epoch, secret, created_at_unix_seconds
         ) VALUES('CcDd', 1, 7, x'9988', 1);
         INSERT INTO app_events(
             group_id_hex, message_id_hex, direction, sender, plaintext, kind,
             tags_json, recorded_at, received_at
         ) VALUES('CcDd', 'm-mixed', 'received', 'alice', 'secret plaintext', 9, '[]', 1, 1);",
    )
    .unwrap();
    let store = SqliteAccountStorage::from_connection_with_options(
        raw,
        crate::SqliteStorageOptions::default(),
    )
    .unwrap();
    let app = store.app_storage();

    // 1. Mixed-case secret persisted via the public API with no projection row.
    app.remember_encrypted_media_epoch_secret("AaBb", 1, 5, b"mixed-api-secret")
        .unwrap();
    assert_eq!(
        app.encrypted_media_epoch_secret("AaBb", 1, 5)
            .unwrap()
            .as_deref(),
        Some(b"mixed-api-secret".as_slice())
    );

    let wiped_ab = store.delete_local_group_data("aabb").unwrap();
    assert!(
        wiped_ab.did_delete(),
        "wipe must delete mixed-case secret even without a projection row"
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM encrypted_media_epoch_secrets WHERE LOWER(group_id_hex) = 'aabb'"
        ),
        0
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM encrypted_media_epoch_secret_retirement_watermarks WHERE group_id_hex = 'aabb'"
        ),
        1
    );
    app.remember_encrypted_media_epoch_secret("AaBb", 1, 5, b"resurrected")
        .unwrap();
    assert_eq!(
        app.encrypted_media_epoch_secret("AaBb", 1, 5).unwrap(),
        None
    );
    assert!(
        !app.encrypted_media_epoch_secret_may_be_served("AaBb", 5)
            .unwrap()
    );

    // 2. Pre-0228 mixed-case secret and app event with no projection row.
    let wiped_cd = store.delete_local_group_data("ccdd").unwrap();
    assert!(
        wiped_cd.did_delete(),
        "wipe must delete migrated mixed-case rows without projection rows"
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM encrypted_media_epoch_secrets WHERE LOWER(group_id_hex) = 'ccdd'"
        ),
        0
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM app_events WHERE LOWER(group_id_hex) = 'ccdd'"
        ),
        0
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM encrypted_media_epoch_secret_retirement_watermarks WHERE group_id_hex = 'ccdd'"
        ),
        1
    );
}

/// Regression for #3798 / PR #3818 review: with migration 0228 + boundary
/// canonicalization enforcing lowercase `group_id_hex` on disk,
/// `delete_local_group_data` must use direct single-seek indexed `group_id_hex = ?1`
/// queries on large message tables without loose-index-scan CTEs or `LOWER(...)`.
#[test]
fn delete_local_group_data_uses_group_id_indexes_on_large_tables() {
    thread_local! {
        static TRACED_SQLS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    fn record_queries(event: rusqlite::trace::TraceEvent<'_>) {
        if let rusqlite::trace::TraceEvent::Stmt(_, sql) = event
            && (sql.contains("FROM app_events")
                || sql.contains("FROM message_timeline")
                || sql.contains("FROM encrypted_media_epoch_secrets")
                || sql.contains("FROM secure_delete_checkpoint_intents"))
        {
            TRACED_SQLS.with_borrow_mut(|sqls| sqls.push(sql.to_owned()));
        }
    }

    let store = SqliteAccountStorage::in_memory_for_test().unwrap();
    store
        .lock()
        .unwrap()
        .execute_batch(
            "INSERT INTO app_events(
                 group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                 tags_json, recorded_at, received_at
             ) VALUES ('aabb', 'm1', 'received', 'alice', 'hi', 9, '[]', 1, 1);
             INSERT INTO message_timeline(
                 group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                 tags_json, timeline_at, received_at, reactions_json
             ) VALUES ('aabb', 'm1', 'received', 'alice', 'hi', 9, '[]', 1, 1, '[]');",
        )
        .unwrap();
    TRACED_SQLS.with_borrow_mut(Vec::clear);
    store.lock().unwrap().trace_v2(
        rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
        Some(record_queries),
    );
    store.delete_local_group_data("AABB").unwrap();
    store
        .lock()
        .unwrap()
        .trace_v2(rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT, None);

    let sqls = TRACED_SQLS.take();
    assert!(
        sqls.iter().any(|s| s.contains("DELETE FROM app_events "))
            && sqls
                .iter()
                .any(|s| s.contains("DELETE FROM message_timeline ")),
        "expected direct DELETEs for app_events and message_timeline: {sqls:?}"
    );
    assert!(
        sqls.iter()
            .all(|s| !s.contains("WITH RECURSIVE") && !s.to_ascii_lowercase().contains("lower(")),
        "wipe must not emit recursive CTEs or LOWER() predicates: {sqls:?}"
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
        assert!(
            details.iter().any(|line| {
                line.contains("SEARCH app_events USING ")
                    || line.contains("SEARCH message_timeline USING ")
                    || line.contains("SEARCH encrypted_media_epoch_secrets USING ")
                    || line.contains("SEARCH secure_delete_checkpoint_intents USING ")
            }),
            "expected indexed SEARCH plan for `{sql}`, got {details:?}"
        );
        assert!(
            !details.iter().any(|line| {
                line.contains("SCAN app_events")
                    || line.contains("SCAN message_timeline")
                    || line.contains("SCAN encrypted_media_epoch_secrets")
                    || line.contains("SCAN secure_delete_checkpoint_intents")
            }),
            "must not full-table SCAN for `{sql}`, got {details:?}"
        );
    }
}

/// Regression for #3798 / PR #3818 review: public read/write boundaries
/// canonicalize uppercase/mixed-case `group_id_hex` inputs to lowercase ASCII
/// on disk and return consistent results regardless of caller casing.
#[test]
fn public_api_boundaries_canonicalize_uppercase_group_ids_on_write_and_read() {
    let store = SqliteAccountStorage::in_memory_for_test().unwrap();
    let app = store.app_storage();

    // Timeline write & read boundaries.
    let update = app
        .record_app_event(&crate::StoredAppEvent {
            group_id_hex: "AbCd01".to_owned(),
            message_id_hex: "m1".to_owned(),
            source_message_id_hex: Some("src1".to_owned()),
            source_epoch: Some(3),
            direction: "received".to_owned(),
            sender: "alice".to_owned(),
            plaintext: "hello".to_owned(),
            kind: 9,
            tags: Vec::new(),
            recorded_at: 10,
            received_at: 10,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    assert_eq!(update.group_id_hex, "abcd01");
    for casing in ["ABCD01", "AbCd01", "abcd01"] {
        let msg = app.timeline_message(casing, "m1").unwrap().unwrap();
        assert_eq!(msg.group_id_hex, "abcd01");
        let target = app.timeline_message_target(casing, "m1").unwrap().unwrap();
        assert_eq!(target.plaintext, "hello");
        let page = app
            .message_timeline(crate::TimelineMessageQuery {
                group_id_hex: Some(casing.to_owned()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].group_id_hex, "abcd01");
        let exported = app.history_export_page(casing, None, 20, 10).unwrap();
        assert_eq!(exported.len(), 1);
    }

    // Link chat report (`group_id` column) boundary.
    app.save_link_chat_report(
        "AbCd01",
        &crate::LinkChatReport {
            slot: "slot-1".to_owned(),
            link_ref: "ref-1".to_owned(),
            digest: vec![1, 2, 3],
            total: 2,
            remaining: 1,
            expires_at: 1_000,
        },
    )
    .unwrap();
    for casing in ["ABCD01", "AbCd01", "abcd01"] {
        assert_eq!(app.link_chat_reports(casing, 500).unwrap().len(), 1);
    }

    // Blocked notification suppression (`group_id` column) boundary.
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO user_blocks(public_key, is_private, created_at_ms) VALUES('mallory', 0, 1)",
            [],
        )
        .unwrap();
    assert!(
        app.suppress_blocked_notification("mallory", "AbCd01", "m-blk")
            .unwrap()
    );
    for casing in ["ABCD01", "AbCd01", "abcd01"] {
        assert!(
            app.blocked_notification_suppressed(casing, "m-blk")
                .unwrap()
        );
    }

    // Verify zero non-lowercase rows exist on disk in any written table.
    for (table, column) in [
        ("app_events", "group_id_hex"),
        ("message_timeline", "group_id_hex"),
        ("link_chat_reports", "group_id"),
        ("blocked_notification_suppressions", "group_id"),
    ] {
        assert_eq!(
            count(
                &store,
                &format!("SELECT count(*) FROM {table} WHERE {column} != lower({column})")
            ),
            0,
            "{table}.{column} must only store canonical lowercase group ids"
        );
    }
}
