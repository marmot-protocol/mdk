use super::*;

#[test]
fn save_state_rolls_back_all_tables_when_component_write_fails() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("test-key").unwrap();
    let mut db = LegacyAccountProjectionDb::open(dir.path().join("app.sqlite3"), &key).unwrap();
    let original = AccountState {
        label: "alice".to_owned(),
        seen_events: vec!["event-before".to_owned()],
        last_transport_timestamp: Some(1_700_000_001),
        groups: vec![AppGroupRecord::new(
            "aa".to_owned(),
            test_routing([0xAA; 32], "ws://127.0.0.1:18080"),
            "before".to_owned(),
            "".to_owned(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(Vec::new()),
            AppGroupMessageRetentionComponent::disabled(),
        )],
    };
    db.save_state(&original).unwrap();
    db.conn
        .execute_batch(
            "CREATE TRIGGER fail_image_component_insert
             BEFORE INSERT ON group_app_components
             WHEN NEW.component_id = 32770
             BEGIN
                SELECT RAISE(FAIL, 'image component write failed');
             END;",
        )
        .unwrap();

    let updated = AccountState {
        label: "alice".to_owned(),
        seen_events: vec!["event-after".to_owned()],
        last_transport_timestamp: Some(1_700_000_002),
        groups: vec![AppGroupRecord::new(
            "bb".to_owned(),
            test_routing([0xBB; 32], "ws://127.0.0.1:18081"),
            "after".to_owned(),
            "".to_owned(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(Vec::new()),
            AppGroupMessageRetentionComponent::disabled(),
        )],
    };

    assert!(db.save_state(&updated).is_err());

    let restored = db.load_state("alice").unwrap();
    assert_eq!(restored.seen_events, original.seen_events);
    assert_eq!(
        restored.last_transport_timestamp,
        original.last_transport_timestamp
    );
    assert_eq!(restored.groups[0].group_id_hex, "aa");
    assert_eq!(restored.groups[0].profile.name, "before");
}

#[test]
fn load_state_uses_agent_text_stream_component_row() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("test-key").unwrap();
    let mut db = LegacyAccountProjectionDb::open(dir.path().join("app.sqlite3"), &key).unwrap();
    let mut group = AppGroupRecord::new(
        "aa".to_owned(),
        test_routing([0xAA; 32], "ws://127.0.0.1:18080"),
        "agent".to_owned(),
        "".to_owned(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );
    group.agent_text_stream = AppAgentTextStreamComponent::from_bytes(&[
        0x01, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let state = AccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: Some(1_700_000_003),
        groups: vec![group],
    };

    db.save_state(&state).unwrap();
    let restored = db.load_state("alice").unwrap();

    assert!(restored.groups[0].agent_text_stream.required);
    assert_eq!(restored.last_transport_timestamp, Some(1_700_000_003));
    assert_eq!(
        restored.groups[0].agent_text_stream.data_hex,
        "010300001000000000000000"
    );
}

#[test]
fn save_state_does_not_rewrite_unchanged_group_rows() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("test-key").unwrap();
    let mut db = LegacyAccountProjectionDb::open(dir.path().join("app.sqlite3"), &key).unwrap();
    let state = AccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: Some(1_700_000_003),
        groups: vec![
            AppGroupRecord::new(
                "aa".to_owned(),
                test_routing([0xAA; 32], "ws://127.0.0.1:18080"),
                "alpha".to_owned(),
                "".to_owned(),
                AppGroupImageInput::default(),
                AppGroupAdminPolicyComponent::new(Vec::new()),
                AppGroupMessageRetentionComponent::disabled(),
            ),
            AppGroupRecord::new(
                "bb".to_owned(),
                test_routing([0xBB; 32], "ws://127.0.0.1:18081"),
                "beta".to_owned(),
                "".to_owned(),
                AppGroupImageInput::default(),
                AppGroupAdminPolicyComponent::new(Vec::new()),
                AppGroupMessageRetentionComponent::disabled(),
            ),
        ],
    };
    db.save_state(&state).unwrap();
    db.conn
        .execute_batch(
            "CREATE TABLE write_audit (table_name TEXT NOT NULL);
             CREATE TRIGGER audit_groups_insert
             AFTER INSERT ON groups
             BEGIN
                INSERT INTO write_audit (table_name) VALUES ('groups');
             END;
             CREATE TRIGGER audit_groups_update
             AFTER UPDATE ON groups
             BEGIN
                INSERT INTO write_audit (table_name) VALUES ('groups');
             END;
             CREATE TRIGGER audit_components_insert
             AFTER INSERT ON group_app_components
             BEGIN
                INSERT INTO write_audit (table_name) VALUES ('group_app_components');
             END;
             CREATE TRIGGER audit_components_update
             AFTER UPDATE ON group_app_components
             BEGIN
                INSERT INTO write_audit (table_name) VALUES ('group_app_components');
             END;
             CREATE TRIGGER audit_components_delete
             AFTER DELETE ON group_app_components
             BEGIN
                INSERT INTO write_audit (table_name) VALUES ('group_app_components');
             END;",
        )
        .unwrap();

    let mut state_with_seen_event = state.clone();
    state_with_seen_event
        .seen_events
        .push("event-after".to_owned());
    db.save_state(&state_with_seen_event).unwrap();

    let group_rewrites: i64 = db
        .conn
        .query_row("SELECT count(*) FROM write_audit", [], |row| row.get(0))
        .unwrap();
    assert_eq!(group_rewrites, 0);
}

#[test]
fn save_state_retains_only_recent_seen_events() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("test-key").unwrap();
    let mut db = LegacyAccountProjectionDb::open(dir.path().join("app.sqlite3"), &key).unwrap();
    let seen_events = (0..(crate::MAX_SEEN_EVENT_IDS + 2))
        .map(|index| format!("event-{index:05}"))
        .collect::<Vec<_>>();
    let state = AccountState {
        label: "alice".to_owned(),
        seen_events,
        last_transport_timestamp: Some(1_700_000_004),
        groups: vec![AppGroupRecord::new(
            "aa".to_owned(),
            test_routing([0xAA; 32], "ws://127.0.0.1:18080"),
            "chat".to_owned(),
            "".to_owned(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(Vec::new()),
            AppGroupMessageRetentionComponent::disabled(),
        )],
    };

    db.save_state(&state).unwrap();

    let restored = db.load_state("alice").unwrap();
    assert_eq!(restored.seen_events.len(), crate::MAX_SEEN_EVENT_IDS);
    assert_eq!(
        restored.seen_events.first().map(String::as_str),
        Some("event-00002")
    );
    let expected_last = format!("event-{:05}", crate::MAX_SEEN_EVENT_IDS + 1);
    assert_eq!(
        restored.seen_events.last().map(String::as_str),
        Some(expected_last.as_str())
    );
}

#[test]
fn save_state_refreshes_reseen_event_recency() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("test-key").unwrap();
    let mut db = LegacyAccountProjectionDb::open(dir.path().join("app.sqlite3"), &key).unwrap();
    db.conn
        .execute(
            "INSERT INTO seen_events (event_id, seen_at) VALUES (?1, ?2)",
            rusqlite::params!["repeat", 1_i64],
        )
        .unwrap();

    let state = AccountState {
        label: "alice".to_owned(),
        seen_events: vec!["repeat".to_owned()],
        last_transport_timestamp: Some(1_700_000_005),
        groups: Vec::new(),
    };

    db.save_state(&state).unwrap();

    let refreshed_seen_at: i64 = db
        .conn
        .query_row(
            "SELECT seen_at FROM seen_events WHERE event_id = ?1",
            rusqlite::params!["repeat"],
            |row| row.get(0),
        )
        .unwrap();
    assert!(refreshed_seen_at > 1);
}

#[test]
fn prune_group_messages_before_removes_only_expired_group_rows() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("test-key").unwrap();
    let db = LegacyAccountProjectionDb::open(dir.path().join("app.sqlite3"), &key).unwrap();
    for (message_id_hex, group_id_hex, recorded_at) in [
        ("old-aa", "aa", 10),
        ("new-aa", "aa", 20),
        ("old-bb", "bb", 10),
    ] {
        db.record_message(&AppMessageProjection {
            message_id_hex: message_id_hex.to_owned(),
            source_message_id_hex: None,
            direction: "received".to_owned(),
            group_id_hex: group_id_hex.to_owned(),
            sender: "sender".to_owned(),
            plaintext: message_id_hex.to_owned(),
            kind: 9,
            tags: Vec::new(),
            source_epoch: None,
            recorded_at: Some(recorded_at),
            origin_commit_id: None,
        })
        .unwrap();
    }

    assert_eq!(db.prune_group_messages_before("aa", 15).unwrap(), 1);

    let aa = db
        .messages(AppMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            limit: None,
        })
        .unwrap();
    assert_eq!(aa.len(), 1);
    assert_eq!(aa[0].message_id_hex, "new-aa");
    let bb = db
        .messages(AppMessageQuery {
            group_id_hex: Some("bb".to_owned()),
            limit: None,
        })
        .unwrap();
    assert_eq!(bb.len(), 1);
    assert_eq!(bb[0].message_id_hex, "old-bb");
}

fn test_routing(nostr_group_id: [u8; 32], relay: &str) -> AppGroupNostrRoutingComponent {
    AppGroupNostrRoutingComponent::new(
        crate::NostrRoutingV1::new(nostr_group_id, vec![relay.to_owned()]).unwrap(),
    )
    .unwrap()
}
