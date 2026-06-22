use super::*;
use crate::StoredAppEvent;
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION, QUOTE_REF_TAG, STREAM_TAG,
};

fn group(id: &str, name: &str) -> StoredAccountGroup {
    StoredAccountGroup {
        group_id_hex: id.to_owned(),
        endpoint: "wss://relay.example".to_owned(),
        profile_name: name.to_owned(),
        profile_description: String::new(),
        image_hash_hex: String::new(),
        image_key_hex: String::new(),
        image_nonce_hex: String::new(),
        image_upload_key_hex: String::new(),
        image_media_type: None,
        admin_keys_hex: String::new(),
        archived: false,
        pending_confirmation: false,
        welcomer_account_id_hex: None,
        via_welcome_message_id_hex: None,
        components: vec![
            StoredAccountGroupComponent {
                component_id: 0x8001,
                component_name: "marmot.group.profile.v1".to_owned(),
                component_data_hex: "0102".to_owned(),
            },
            StoredAccountGroupComponent {
                component_id: 0x8004,
                component_name: "marmot.group.message-retention.v1".to_owned(),
                component_data_hex: "0304".to_owned(),
            },
        ],
    }
}

fn app_event(id: &str, group_id_hex: &str, at: u64) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: group_id_hex.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: "sender".to_owned(),
        plaintext: id.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
    }
}

fn agent_stream_start_event(
    id: &str,
    group_id_hex: &str,
    stream_id_hex: &str,
    at: u64,
) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: group_id_hex.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: "agent".to_owned(),
        plaintext: id.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
        tags: vec![vec![STREAM_TAG.to_owned(), stream_id_hex.to_owned()]],
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
    }
}

fn reply_event(id: &str, group_id_hex: &str, target: &str, at: u64) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: group_id_hex.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: "sender".to_owned(),
        plaintext: id.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: vec![
            vec![EVENT_REF_TAG.to_owned(), target.to_owned()],
            vec![QUOTE_REF_TAG.to_owned(), target.to_owned()],
        ],
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
    }
}

fn reaction_event(id: &str, group_id_hex: &str, target: &str, at: u64) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: group_id_hex.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: "reactor".to_owned(),
        plaintext: "+".to_owned(),
        kind: MARMOT_APP_EVENT_KIND_REACTION,
        tags: vec![vec![EVENT_REF_TAG.to_owned(), target.to_owned()]],
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
    }
}

fn delete_event(
    id: &str,
    group_id_hex: &str,
    sender: &str,
    target: &str,
    at: u64,
) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: group_id_hex.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: sender.to_owned(),
        plaintext: String::new(),
        kind: MARMOT_APP_EVENT_KIND_DELETE,
        tags: vec![vec![EVENT_REF_TAG.to_owned(), target.to_owned()]],
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
    }
}

#[test]
fn account_projection_state_roundtrips_groups_components_and_seen_events() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let state = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: vec!["old".to_owned(), "kept".to_owned()],
        last_transport_timestamp: Some(1_700_000_001),
        groups: vec![group("aa", "alpha")],
    };

    store.save_account_projection_state(&state, 1).unwrap();

    let restored = store.load_account_projection_state("alice", 16).unwrap();
    assert_eq!(restored.seen_events, vec!["kept"]);
    assert_eq!(restored.last_transport_timestamp, Some(1_700_000_001));
    assert_eq!(restored.groups[0].profile_name, "alpha");
    assert_eq!(restored.groups[0].components.len(), 2);
    assert_eq!(restored.groups[0].components[1].component_id, 0x8004);
}

#[test]
fn account_projection_state_deletes_groups_removed_from_snapshot() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let state = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: vec![group("aa", "alpha"), group("bb", "beta")],
    };
    store.save_account_projection_state(&state, 16).unwrap();

    let updated = StoredAccountState {
        groups: vec![group("bb", "beta")],
        ..state
    };
    store.save_account_projection_state(&updated, 16).unwrap();

    let restored = store.load_account_projection_state("alice", 16).unwrap();
    assert_eq!(restored.groups.len(), 1);
    assert_eq!(restored.groups[0].group_id_hex, "bb");
    let stale_components: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM account_group_app_components WHERE group_id_hex = 'aa'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stale_components, 0);
}

#[test]
fn account_projection_state_does_not_rewrite_unchanged_group_rows() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let state = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: vec![group("aa", "alpha")],
    };
    store.save_account_projection_state(&state, 16).unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE write_audit (table_name TEXT NOT NULL);
                 CREATE TRIGGER audit_groups_insert
                 AFTER INSERT ON account_groups
                 BEGIN
                    INSERT INTO write_audit (table_name) VALUES ('account_groups');
                 END;
                 CREATE TRIGGER audit_groups_update
                 AFTER UPDATE ON account_groups
                 BEGIN
                    INSERT INTO write_audit (table_name) VALUES ('account_groups');
                 END;
                 CREATE TRIGGER audit_components_insert
                 AFTER INSERT ON account_group_app_components
                 BEGIN
                    INSERT INTO write_audit (table_name) VALUES ('account_group_app_components');
                 END;
                 CREATE TRIGGER audit_components_update
                 AFTER UPDATE ON account_group_app_components
                 BEGIN
                    INSERT INTO write_audit (table_name) VALUES ('account_group_app_components');
                 END;
                 CREATE TRIGGER audit_components_delete
                 AFTER DELETE ON account_group_app_components
                 BEGIN
                    INSERT INTO write_audit (table_name) VALUES ('account_group_app_components');
                 END;",
        )
        .unwrap();
    }

    let mut updated = state;
    updated.seen_events.push("event-after".to_owned());
    store.save_account_projection_state(&updated, 16).unwrap();

    let writes: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM write_audit", [], |row| row.get(0))
        .unwrap();
    assert_eq!(writes, 0);
}

#[test]
fn app_messages_list_raw_events_and_prune_updates_timeline() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&app_event("old-aa", "aa", 10))
        .unwrap();
    store
        .record_app_event(&app_event("new-aa", "aa", 20))
        .unwrap();
    store
        .record_app_event(&app_event("old-bb", "bb", 10))
        .unwrap();

    assert_eq!(store.prune_app_events_before("aa", 15).unwrap(), 1);

    let aa = store
        .app_messages(StoredAppMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            limit: None,
        })
        .unwrap();
    assert_eq!(aa.len(), 1);
    assert_eq!(aa[0].message_id_hex, "new-aa");
    let bb = store
        .app_messages(StoredAppMessageQuery {
            group_id_hex: Some("bb".to_owned()),
            limit: None,
        })
        .unwrap();
    assert_eq!(bb.len(), 1);

    let timeline = store
        .message_timeline(crate::TimelineMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            ..crate::TimelineMessageQuery::default()
        })
        .unwrap();
    assert_eq!(timeline.messages.len(), 1);
    assert_eq!(timeline.messages[0].message_id_hex, "new-aa");
}

#[test]
fn prune_app_events_before_does_not_delete_surviving_timeline_rows() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&app_event("old-aa", "aa", 10))
        .unwrap();
    store
        .record_app_event(&app_event("new-aa", "aa", 20))
        .unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_survivor_timeline_delete
             BEFORE DELETE ON message_timeline
             WHEN OLD.message_id_hex = 'new-aa'
             BEGIN
                SELECT RAISE(FAIL, 'unexpected survivor timeline delete');
             END;",
        )
        .unwrap();
    }

    assert_eq!(store.prune_app_events_before("aa", 15).unwrap(), 1);

    let timeline = store
        .message_timeline(crate::TimelineMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            ..crate::TimelineMessageQuery::default()
        })
        .unwrap();
    assert_eq!(timeline.messages.len(), 1);
    assert_eq!(timeline.messages[0].message_id_hex, "new-aa");
}

#[test]
fn prune_app_events_before_deletes_only_pruned_agent_stream_start_rows() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&agent_stream_start_event(
            "old-stream",
            "aa",
            "stream-old",
            10,
        ))
        .unwrap();
    store
        .record_app_event(&agent_stream_start_event(
            "new-stream",
            "aa",
            "stream-new",
            20,
        ))
        .unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_survivor_stream_start_delete
             BEFORE DELETE ON agent_stream_starts
             WHEN OLD.message_id_hex = 'new-stream'
             BEGIN
                SELECT RAISE(FAIL, 'unexpected survivor stream start delete');
             END;",
        )
        .unwrap();
    }

    assert_eq!(store.prune_app_events_before("aa", 15).unwrap(), 1);

    let conn = store.lock().unwrap();
    let stream_start_ids = conn
        .prepare("SELECT message_id_hex FROM agent_stream_starts ORDER BY message_id_hex")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(stream_start_ids, vec!["new-stream"]);
}

#[test]
fn prune_app_events_before_chunks_projection_deletes_under_sqlite_variable_limit() {
    const EVENT_COUNT: usize = 1_005;

    let store = SqliteAccountStorage::in_memory().unwrap();
    {
        let conn = store.lock().unwrap();
        // SAFETY: The raw handle is only used to lower this test connection's
        // bind-parameter limit before any concurrent use; rusqlite keeps owning
        // the connection and no pointer is retained.
        unsafe {
            rusqlite::ffi::sqlite3_limit(
                conn.handle(),
                rusqlite::ffi::SQLITE_LIMIT_VARIABLE_NUMBER,
                1_000,
            );
        }
    }
    for index in 0..EVENT_COUNT {
        store
            .record_app_event(&app_event(&format!("old-{index:04}"), "aa", index as u64))
            .unwrap();
    }

    assert_eq!(
        store.prune_app_events_before("aa", 2_000).unwrap(),
        EVENT_COUNT
    );

    let conn = store.lock().unwrap();
    let timeline_rows: i64 = conn
        .query_row(
            "SELECT count(*) FROM message_timeline WHERE group_id_hex = 'aa'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(timeline_rows, 0);
}

#[test]
fn prune_app_events_before_does_not_reproject_replies_when_parent_is_pruned() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&app_event("old-parent", "aa", 10))
        .unwrap();
    store
        .record_app_event(&reply_event("reply", "aa", "old-parent", 20))
        .unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_reply_timeline_update
             BEFORE UPDATE ON message_timeline
             WHEN OLD.message_id_hex = 'reply'
             BEGIN
                SELECT RAISE(FAIL, 'unexpected reply timeline reproject');
             END;
             CREATE TRIGGER fail_reply_timeline_delete
             BEFORE DELETE ON message_timeline
             WHEN OLD.message_id_hex = 'reply'
             BEGIN
                SELECT RAISE(FAIL, 'unexpected reply timeline delete');
             END;",
        )
        .unwrap();
    }

    assert_eq!(store.prune_app_events_before("aa", 15).unwrap(), 1);

    let timeline = store
        .message_timeline(crate::TimelineMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            ..crate::TimelineMessageQuery::default()
        })
        .unwrap();
    assert_eq!(timeline.messages.len(), 1);
    let reply = &timeline.messages[0];
    assert_eq!(reply.message_id_hex, "reply");
    assert_eq!(reply.reply_to_message_id_hex.as_deref(), Some("old-parent"));
    assert!(reply.reply_preview.is_none());
}

#[test]
fn prune_app_events_before_reprojects_survivor_when_reaction_is_pruned() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&app_event("target", "aa", 20))
        .unwrap();
    store
        .record_app_event(&reaction_event("old-reaction", "aa", "target", 10))
        .unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_target_timeline_delete
             BEFORE DELETE ON message_timeline
             WHEN OLD.message_id_hex = 'target'
             BEGIN
                SELECT RAISE(FAIL, 'unexpected survivor timeline delete');
             END;",
        )
        .unwrap();
    }

    assert_eq!(store.prune_app_events_before("aa", 15).unwrap(), 1);

    let timeline = store
        .message_timeline(crate::TimelineMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            ..crate::TimelineMessageQuery::default()
        })
        .unwrap();
    assert_eq!(timeline.messages.len(), 1);
    let target = &timeline.messages[0];
    assert_eq!(target.message_id_hex, "target");
    assert!(target.reactions.user_reactions.is_empty());
    assert!(target.reactions.by_emoji.is_empty());
}

#[test]
fn prune_app_events_before_reprojects_survivor_when_delete_is_pruned() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&app_event("target", "aa", 20))
        .unwrap();
    store
        .record_app_event(&delete_event("old-delete", "aa", "sender", "target", 10))
        .unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_target_timeline_delete
             BEFORE DELETE ON message_timeline
             WHEN OLD.message_id_hex = 'target'
             BEGIN
                SELECT RAISE(FAIL, 'unexpected survivor timeline delete');
             END;",
        )
        .unwrap();
    }

    assert_eq!(store.prune_app_events_before("aa", 15).unwrap(), 1);

    let timeline = store
        .message_timeline(crate::TimelineMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            ..crate::TimelineMessageQuery::default()
        })
        .unwrap();
    assert_eq!(timeline.messages.len(), 1);
    let target = &timeline.messages[0];
    assert_eq!(target.message_id_hex, "target");
    assert!(!target.deleted);
    assert_eq!(target.plaintext, "target");
}

#[test]
fn app_messages_tie_break_on_message_id_matches_cursor_order() {
    // Same `recorded_at`, but `message_id_hex` lexical order differs from both
    // insertion order and `received_at` order. `dm messages list` filters
    // cursor ties on `(recorded_at, message_id_hex)`, so the projection must
    // return same-timestamp rows in `message_id_hex` order or pagination skips
    // or duplicates rows. Regression test for issue #390.
    let store = SqliteAccountStorage::in_memory().unwrap();
    let recorded_at = 100;
    // Insert so that received_at order (and insert order) is the REVERSE of
    // message_id_hex lexical order: "aaa" received last, "ccc" received first.
    // Under the buggy (recorded_at, received_at, insert_order) ordering the
    // projection would return ccc, bbb, aaa; the cursor tie-breaker expects
    // message_id_hex order aaa, bbb, ccc.
    for (id, received_at) in [("ccc", 10u64), ("bbb", 20u64), ("aaa", 30u64)] {
        let mut event = app_event(id, "gg", recorded_at);
        event.received_at = received_at;
        store.record_app_event(&event).unwrap();
    }

    let ordered_ids = |limit: Option<usize>| {
        store
            .app_messages(StoredAppMessageQuery {
                group_id_hex: Some("gg".to_owned()),
                limit,
            })
            .unwrap()
            .into_iter()
            .map(|message| message.message_id_hex)
            .collect::<Vec<_>>()
    };

    // Ascending display order must be by message_id_hex, matching the cursor
    // tie-breaker used by `apply_message_cursors`.
    assert_eq!(ordered_ids(None), vec!["aaa", "bbb", "ccc"]);

    // The newest-N limited path takes the lexically-greatest ids, then returns
    // them in ascending message_id_hex order. With limit 2 that is bbb, ccc.
    assert_eq!(ordered_ids(Some(2)), vec!["bbb", "ccc"]);
}

#[test]
fn notification_settings_default_local_notifications_on() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let account_id_hex = "aa".repeat(32);

    let settings = store
        .notification_settings("alice", &account_id_hex)
        .unwrap();

    assert_eq!(settings.account_label, "alice");
    assert_eq!(settings.account_id_hex, account_id_hex);
    assert!(settings.local_notifications_enabled);
    assert!(!settings.native_push_enabled);

    store
        .set_local_notifications_enabled("alice", &account_id_hex, false)
        .unwrap();
    let rotated_account_id_hex = "bb".repeat(32);
    let settings = store
        .notification_settings("alice", &rotated_account_id_hex)
        .unwrap();

    assert_eq!(settings.account_id_hex, rotated_account_id_hex);
    assert!(!settings.local_notifications_enabled);
    assert!(!settings.native_push_enabled);
}

#[test]
fn push_registration_preserves_created_at_when_token_rotates() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let registration = AccountPushRegistration {
        account_label: "alice".to_owned(),
        account_id_hex: "aa".repeat(32),
        platform: 1,
        token_fingerprint: "first".to_owned(),
        server_pubkey_hex: "bb".repeat(32),
        relay_hint: None,
        created_at_ms: 10,
        updated_at_ms: 10,
        last_shared_at_ms: None,
    };
    store
        .upsert_push_registration(registration.clone(), vec![1, 2, 3])
        .unwrap();
    store.mark_push_registration_shared("alice", 11).unwrap();
    let mut rotated = registration;
    rotated.token_fingerprint = "second".to_owned();
    rotated.updated_at_ms = 12;
    rotated.created_at_ms = 12;

    let stored = store
        .upsert_push_registration(rotated, vec![4, 5, 6])
        .unwrap();

    assert_eq!(stored.registration.created_at_ms, 10);
    assert_eq!(stored.registration.last_shared_at_ms, None);
    assert_eq!(stored.token_bytes, vec![4, 5, 6]);
}
