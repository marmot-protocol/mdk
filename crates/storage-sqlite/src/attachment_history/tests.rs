use super::*;
use rusqlite::params;

fn seed(store: &SqliteAccountStorage, id: usize, slots: usize) {
    store.lock().unwrap().execute(
        "INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,source_epoch,
            direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json,media_json)
         VALUES('aa',?1,?1,?2,'received','alice','',9,'[]',7,?3,'[]',?4)",
        params![format!("{id:06}"), (id / 100) as i64, (10000-id) as i64,
            serde_json::json!({"imeta": (0..slots).map(|n| serde_json::json!(["imeta",format!("slot {n}")])).collect::<Vec<_>>()}).to_string()],
    ).unwrap();
}
fn page(store: &SqliteAccountStorage) -> AttachmentHistoryPage {
    store.attachment_history_page("aa", 1, None).unwrap()
}
fn sql(store: &SqliteAccountStorage, text: &str) {
    store.lock().unwrap().execute_batch(text).unwrap();
}

#[test]
fn sparse_history_albums_and_equal_times_traverse_once_in_canonical_order() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for n in 0..350 {
        seed(&store, n, if n % 7 == 0 { 3 } else { 0 });
    }
    let expected: Vec<_> = (0..350)
        .rev()
        .filter(|n| n % 7 == 0)
        .flat_map(|n| (0..3).map(move |i| (format!("{n:06}"), i)))
        .collect();
    for limit in [1, 2, 13, 100] {
        let mut cursor = None;
        let mut actual = Vec::new();
        loop {
            let p = store
                .attachment_history_page("aa", limit, cursor.as_ref())
                .unwrap();
            assert!(p.entries.len() <= limit);
            actual.extend(
                p.entries
                    .into_iter()
                    .map(|e| (e.message_id_hex, e.attachment_index)),
            );
            cursor = p.next_cursor;
            if cursor.is_none() {
                break;
            }
            assert!(actual.len() <= expected.len());
        }
        assert_eq!(actual, expected);
    }
    assert!(
        store
            .attachment_history_page("bb", 1, None)
            .unwrap()
            .entries
            .is_empty()
    );
    for limit in [0, 101, usize::MAX] {
        assert!(matches!(
            store.attachment_history_page("aa", limit, None),
            Err(AttachmentHistoryError::InvalidLimit)
        ));
    }
}

#[test]
fn source_changes_invalidate_pages_but_unrelated_rows_and_reactions_do_not() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for n in 0..4 {
        seed(&store, n, 2);
    }
    let initial = page(&store);
    let cursor = initial.next_cursor.unwrap();
    let second = store
        .attachment_history_page("aa", 1, Some(&cursor))
        .unwrap();
    assert_eq!(second.entries[0].attachment_index, 1);
    sql(
        &store,
        "UPDATE message_timeline SET reactions_json='[1]' WHERE message_id_hex='000003'",
    );
    seed(&store, 10, 0);
    assert_eq!(
        store.attachment_history_version("aa").unwrap(),
        initial.version
    );
    for change in [
        "UPDATE message_timeline SET deleted=1 WHERE message_id_hex='000003'",
        "UPDATE message_timeline SET invalidation_status='branch_selection_withdrawn' WHERE message_id_hex='000002'",
        "UPDATE message_timeline SET media_json='{}' WHERE message_id_hex='000001'",
    ] {
        sql(&store, change);
        assert!(matches!(
            store.attachment_history_page("aa", 1, Some(&cursor)),
            Err(AttachmentHistoryError::StaleCursor)
        ));
    }
    let remaining = store.attachment_history_page("aa", 100, None).unwrap();
    assert_eq!(remaining.entries.len(), 2);
    assert!(
        remaining
            .entries
            .iter()
            .all(|e| e.message_id_hex == "000000")
    );
    let before = remaining.version;
    sql(
        &store,
        "UPDATE message_timeline SET invalidation_status=NULL WHERE message_id_hex='000002'",
    );
    assert_ne!(store.attachment_history_version("aa").unwrap(), before);
    assert_eq!(
        store
            .attachment_history_page("aa", 100, None)
            .unwrap()
            .entries
            .len(),
        4
    );
}

#[test]
fn malformed_slots_legacy_epochs_and_pending_sends() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, 1, 1);
    sql(
        &store,
        "UPDATE message_timeline SET source_epoch=NULL,media_json='{\"imeta\":[[\"imeta\"],null,17,\"bad\",{},true,false]}'",
    );
    let p = store.attachment_history_page("aa", 100, None).unwrap();
    assert_eq!(p.entries.len(), 7);
    assert!(p.entries.iter().all(|e| e.source_epoch.is_none()));
    assert_eq!(p.entries[2].slot, serde_json::json!(17));
    assert_eq!(p.entries[3].slot, serde_json::json!("bad"));
    assert_eq!(p.entries[5].slot, serde_json::json!(true));
    assert_eq!(p.entries[6].slot, serde_json::json!(false));
    for bad in ["'corrupt'", "'[]'", "'{\"imeta\":null}'", "zeroblob(10)"] {
        sql(
            &store,
            &format!("UPDATE message_timeline SET media_json={bad}"),
        );
        assert_eq!(page(&store).entries[0].slot, serde_json::Value::Null);
    }
    sql(
        &store,
        "UPDATE message_timeline SET source_message_id_hex=NULL",
    );
    assert!(page(&store).entries.is_empty());
}

#[test]
fn blocking_and_invite_visibility_are_revisioned_without_read_time_scans() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, 1, 3);
    let before = page(&store);
    sql(&store, "INSERT INTO user_blocks VALUES('alice',0,0)");
    assert!(page(&store).entries.is_empty());
    assert_ne!(page(&store).version, before.version);
    sql(
        &store,
        "INSERT INTO blocked_pending_invites VALUES('aa'); DELETE FROM user_blocks",
    );
    assert!(page(&store).entries.is_empty());
    sql(&store, "DELETE FROM blocked_pending_invites");
    assert_eq!(page(&store).entries.len(), 1);
    sql(
        &store,
        "INSERT INTO user_blocks VALUES('bob',0,0); UPDATE user_blocks SET public_key='alice'",
    );
    assert!(page(&store).entries.is_empty());
}

#[test]
fn account_group_fences_and_atomic_rollback() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, 1, 3);
    let before = page(&store);
    let cursor = before.next_cursor.unwrap();
    let other = SqliteAccountStorage::in_memory().unwrap();
    seed(&other, 1, 3);
    assert!(matches!(
        other.attachment_history_page("aa", 1, Some(&cursor)),
        Err(AttachmentHistoryError::CursorMismatch)
    ));
    assert!(matches!(
        store.attachment_history_page("bb", 1, Some(&cursor)),
        Err(AttachmentHistoryError::CursorMismatch)
    ));
    sql(
        &store,
        "CREATE TRIGGER fail_attachment_removal BEFORE DELETE ON attachment_history BEGIN SELECT RAISE(ABORT,'test'); END",
    );
    assert!(
        store
            .lock()
            .unwrap()
            .execute("UPDATE message_timeline SET deleted=1", [])
            .is_err()
    );
    assert_eq!(page(&store).version, before.version);
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT deleted FROM message_timeline", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    sql(
        &store,
        "DROP TRIGGER fail_attachment_removal; INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES('aa','',0); DELETE FROM account_groups; DELETE FROM message_timeline",
    );
    seed(&store, 1, 3);
    assert!(matches!(
        store.attachment_history_page("aa", 1, Some(&cursor)),
        Err(AttachmentHistoryError::StaleCursor)
    ));
}

#[test]
fn page_work_is_bounded_even_with_large_hidden_history() {
    let _guard = crate::query_work_test_support::QUERY_MEASUREMENT
        .lock()
        .unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, 0, 3);
    let cursor = page(&store).next_cursor.unwrap();
    sql(&store, "INSERT INTO user_blocks VALUES('bob',0,0)");
    sql(&store, "BEGIN");
    for n in 1..3000 {
        seed(&store, n, 1);
    }
    sql(
        &store,
        "UPDATE message_timeline SET sender='bob' WHERE message_id_hex!='000000'; COMMIT",
    );
    // The original cursor must restart after the mutations; both first page and
    // subsequent seek are bounded despite thousands of hidden, newer slots.
    assert!(matches!(
        store.attachment_history_page("aa", 1, Some(&cursor)),
        Err(AttachmentHistoryError::StaleCursor)
    ));
    let first =
        crate::query_work_test_support::measured(&store, "attachment first", 1000, || page(&store));
    crate::query_work_test_support::measured(&store, "attachment seek", 1000, || {
        store
            .attachment_history_page("aa", 1, first.next_cursor.as_ref())
            .unwrap()
    });
}

#[test]
fn production_projection_rebuild_invalidation_expiry_and_encrypted_reopen() {
    use cgka_traits::app_event::AppMessageRetentionDecision;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attachments.sqlite3");
    let key = crate::SqlCipherKey::new("attachment-test-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let event = crate::StoredAppEvent {
        group_id_hex: "aa".into(),
        message_id_hex: "message".into(),
        source_message_id_hex: Some("source".into()),
        source_epoch: Some(7),
        direction: "received".into(),
        sender: "alice".into(),
        plaintext: "body".into(),
        kind: 9,
        tags: vec![
            vec!["imeta".into(), "url https://example.com/a".into()],
            vec!["imeta".into(), "url https://example.com/b".into()],
        ],
        recorded_at: 10,
        received_at: 10,
        origin_commit_id: None,
        moderation_grant: false,
    };
    store
        .record_app_event_with_source(
            &event,
            Some(AppMessageRetentionDecision {
                retention_seconds: 10,
                expires_at: Some(20),
            }),
            None,
        )
        .unwrap();
    let initial = page(&store);
    let cursor = initial.next_cursor.unwrap();
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(page(&store).version, initial.version);
    assert_eq!(
        store
            .attachment_history_page("aa", 1, Some(&cursor))
            .unwrap()
            .entries[0]
            .attachment_index,
        1
    );
    store.rebuild_message_timeline_for_group("aa").unwrap();
    assert_eq!(
        store
            .attachment_history_page("aa", 100, None)
            .unwrap()
            .entries
            .len(),
        2
    );
    assert!(matches!(
        store.attachment_history_page("aa", 1, Some(&cursor)),
        Err(AttachmentHistoryError::StaleCursor)
    ));
    store
        .invalidate_app_event_by_source("source", "branch_selection_withdrawn")
        .unwrap();
    assert!(page(&store).entries.is_empty());
    let mut second = event.clone();
    second.message_id_hex = "second".into();
    second.source_message_id_hex = Some("source-second".into());
    store
        .record_app_event_with_source(
            &second,
            Some(AppMessageRetentionDecision {
                retention_seconds: 10,
                expires_at: Some(20),
            }),
            None,
        )
        .unwrap();
    assert_eq!(
        store
            .attachment_history_page("aa", 100, None)
            .unwrap()
            .entries
            .len(),
        2
    );
    store
        .secure_prune_expired_app_events("aa", 20, "self", &|_, _| false)
        .unwrap();
    assert!(page(&store).entries.is_empty());
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(page(&store).entries.is_empty());
}

#[test]
fn changes_in_another_group_do_not_restart_this_group() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, 1, 2);
    let before = page(&store);
    sql(
        &store,
        "INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json,media_json) VALUES('bb','other','source-other','received','bob','',9,'[]',1,1,'[]','{\"imeta\":[[\"imeta\"]]}')",
    );
    sql(
        &store,
        "UPDATE message_timeline SET deleted=1 WHERE group_id_hex='bb'",
    );
    assert_eq!(page(&store).version, before.version);
    assert!(
        store
            .attachment_history_page("aa", 1, before.next_cursor.as_ref())
            .is_ok()
    );
    let debug = format!("{:?}", page(&store));
    assert!(!debug.contains("alice"));
    assert!(!debug.contains("000001"));
}

#[test]
fn authenticated_epoch_order_wins_over_wall_clock_and_legacy_rows() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, 1, 2);
    seed(&store, 2, 1);
    seed(&store, 3, 1);
    sql(
        &store,
        "UPDATE message_timeline SET source_epoch=9,timeline_at=1 WHERE message_id_hex='000001'; UPDATE message_timeline SET source_epoch=2,timeline_at=9999 WHERE message_id_hex='000002'; UPDATE message_timeline SET source_epoch=NULL,timeline_at=99999 WHERE message_id_hex='000003'",
    );
    let rows = store.attachment_history_page("aa", 100, None).unwrap();
    assert_eq!(
        rows.entries
            .iter()
            .map(|e| (e.message_id_hex.as_str(), e.attachment_index))
            .collect::<Vec<_>>(),
        [("000001", 0), ("000001", 1), ("000002", 0), ("000003", 0)]
    );
}
