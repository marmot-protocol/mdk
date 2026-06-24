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
fn prune_app_events_before_scrubs_pruned_plaintext_and_media_before_deleting() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut old = app_event("old-aa", "aa", 10);
    old.plaintext = "secret disappearing plaintext".to_owned();
    old.tags = vec![vec![
        "imeta".to_owned(),
        "v encrypted-media-v1".to_owned(),
        format!("ciphertext_sha256 {}", "aa".repeat(32)),
        format!("plaintext_sha256 {}", "bb".repeat(32)),
        "nonce 000102030405060708090a0b".to_owned(),
        "m image/png".to_owned(),
        "filename secret.png".to_owned(),
        format!(
            "locator blossom-v1 https://blossom.example/{}",
            "aa".repeat(32)
        ),
    ]];
    store.record_app_event(&old).unwrap();
    {
        let conn = store.lock().unwrap();
        let media_rows: i64 = conn
            .query_row(
                "SELECT count(*) FROM message_timeline
                 WHERE message_id_hex = 'old-aa' AND media_json IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(media_rows, 1, "test fixture must project media metadata");
        conn.execute_batch(
            "CREATE TEMP TABLE prune_delete_audit (
                table_name TEXT NOT NULL,
                plaintext BLOB NOT NULL,
                tags_json BLOB NOT NULL,
                media_json BLOB
             );
             CREATE TEMP TRIGGER audit_app_event_delete
             BEFORE DELETE ON app_events
             WHEN OLD.message_id_hex = 'old-aa'
             BEGIN
                INSERT INTO prune_delete_audit(table_name, plaintext, tags_json, media_json)
                VALUES ('app_events', OLD.plaintext, OLD.tags_json, NULL);
             END;
             CREATE TEMP TRIGGER audit_timeline_delete
             BEFORE DELETE ON message_timeline
             WHEN OLD.message_id_hex = 'old-aa'
             BEGIN
                INSERT INTO prune_delete_audit(table_name, plaintext, tags_json, media_json)
                VALUES ('message_timeline', OLD.plaintext, OLD.tags_json, OLD.media_json);
             END;",
        )
        .unwrap();
    }

    assert_eq!(store.prune_app_events_before("aa", 15).unwrap(), 1);

    let conn = store.lock().unwrap();
    let rows = conn
        .prepare(
            "SELECT table_name, plaintext, tags_json, media_json
             FROM prune_delete_audit
             ORDER BY table_name",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(rows.len(), 2);
    for (table_name, plaintext, tags_json, media_json) in rows {
        assert!(
            !plaintext.is_empty() && plaintext.iter().all(|byte| *byte == 0),
            "{table_name} plaintext must be zeroed before DELETE"
        );
        assert!(
            !tags_json.is_empty() && tags_json.iter().all(|byte| *byte == 0),
            "{table_name} tags must be zeroed before DELETE"
        );
        if table_name == "message_timeline" {
            let media_json = media_json.expect("timeline row must carry scrubbed media metadata");
            assert!(
                !media_json.is_empty() && media_json.iter().all(|byte| *byte == 0),
                "{table_name} media metadata must be zeroed before DELETE"
            );
        } else {
            assert_eq!(media_json, None);
        }
    }
}

#[test]
fn secure_prune_checkpoint_removes_plaintext_from_database_and_wal_files() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("account.sqlite");
    let options = crate::SqliteStorageOptions {
        secure_delete: false,
        ..crate::SqliteStorageOptions::default()
    };
    let store = SqliteAccountStorage::from_connection_with_options(
        rusqlite::Connection::open(&db_path).unwrap(),
        options,
    )
    .unwrap();
    let secret = "secure-prune-disk-secret-586-plaintext";
    let secret_filename = "secure-prune-disk-secret-586.png";
    let media_hash = "ca".repeat(32);
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![group("aa", "alpha")],
            },
            16,
        )
        .unwrap();
    let mut old = app_event("old-disk", "aa", 10);
    old.plaintext = secret.to_owned();
    old.tags = vec![vec![
        "imeta".to_owned(),
        "v encrypted-media-v1".to_owned(),
        format!("ciphertext_sha256 {media_hash}"),
        "m image/png".to_owned(),
        format!("filename {secret_filename}"),
        format!("locator blossom-v1 https://blossom.example/{media_hash}"),
    ]];
    store.record_app_event(&old).unwrap();
    store.refresh_chat_list_row("alice-account", "aa").unwrap();
    {
        let conn = store.lock().unwrap();
        let (busy, _, _): (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        assert_eq!(busy, 0);
    }
    assert!(
        file_contains(&db_path, secret.as_bytes()),
        "fixture should place plaintext in the database file before secure prune"
    );

    let outcome = store.secure_prune_app_events_before("aa", 15).unwrap();
    assert_eq!(outcome.pruned_messages, 1);
    assert_eq!(outcome.media_ciphertext_sha256, vec![media_hash.clone()]);
    assert!(
        store
            .chat_list_row("aa")
            .unwrap()
            .unwrap()
            .last_message
            .is_none()
    );
    drop(store);

    for path in [
        db_path.clone(),
        db_path.with_extension("sqlite-wal"),
        db_path.with_extension("sqlite-shm"),
    ] {
        if !path.exists() {
            continue;
        }
        assert!(
            !file_contains(&path, secret.as_bytes()),
            "{} must not retain pruned plaintext",
            path.display()
        );
        assert!(
            !file_contains(&path, secret_filename.as_bytes()),
            "{} must not retain pruned media metadata",
            path.display()
        );
    }
}

#[test]
fn secure_prune_removes_pruned_plaintext_from_search_index() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("account.sqlite");
    let store = SqliteAccountStorage::from_connection_with_options(
        rusqlite::Connection::open(&db_path).unwrap(),
        crate::SqliteStorageOptions {
            secure_delete: false,
            ..crate::SqliteStorageOptions::default()
        },
    )
    .unwrap();
    let old_secret = "secure-prune-index-secret-586-old";
    let survivor_secret = "secure-prune-index-secret-586-survivor";
    let mut old = app_event("old-index", "aa", 10);
    old.plaintext = old_secret.to_owned();
    let mut survivor = app_event("survivor-index", "aa", 20);
    survivor.plaintext = survivor_secret.to_owned();
    store.record_app_event(&old).unwrap();
    store.record_app_event(&survivor).unwrap();
    let indexed = store
        .message_timeline(crate::TimelineMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            search: Some("secure-prune-index-secret".to_owned()),
            ..crate::TimelineMessageQuery::default()
        })
        .unwrap();
    assert_eq!(indexed.messages.len(), 2);
    {
        let conn = store.lock().unwrap();
        let (busy, _, _): (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        assert_eq!(busy, 0);
    }
    assert!(
        file_contains(&db_path, old_secret.as_bytes()),
        "fixture should place indexed plaintext in the database file before secure prune"
    );

    let outcome = store.secure_prune_app_events_before("aa", 15).unwrap();

    assert_eq!(outcome.pruned_messages, 1);
    drop(store);
    assert!(
        !file_contains(&db_path, old_secret.as_bytes()),
        "search-indexed pruned plaintext must be scrubbed from the database file"
    );
    assert!(
        file_contains(&db_path, survivor_secret.as_bytes()),
        "surviving indexed plaintext must not be scrubbed"
    );
}

fn file_contains(path: &std::path::Path, needle: &[u8]) -> bool {
    let haystack = std::fs::read(path).unwrap();
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn secure_prune_clears_chat_list_preview_for_pruned_latest_message() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![group("aa", "alpha")],
            },
            16,
        )
        .unwrap();
    let mut old = app_event("old-aa", "aa", 10);
    old.plaintext = "chat list should not retain this".to_owned();
    store.record_app_event(&old).unwrap();
    store.refresh_chat_list_row("alice-account", "aa").unwrap();
    assert_eq!(
        store
            .chat_list_row("aa")
            .unwrap()
            .unwrap()
            .last_message
            .unwrap()
            .plaintext,
        "chat list should not retain this"
    );

    let outcome = store.secure_prune_app_events_before("aa", 15).unwrap();

    assert_eq!(outcome.pruned_messages, 1);
    assert!(
        store
            .chat_list_row("aa")
            .unwrap()
            .unwrap()
            .last_message
            .is_none()
    );
}

#[test]
fn secure_prune_restores_caller_secure_delete_setting() {
    let store = SqliteAccountStorage::in_memory_with_options(crate::SqliteStorageOptions {
        secure_delete: false,
        ..crate::SqliteStorageOptions::default()
    })
    .unwrap();
    assert_eq!(secure_delete_pragma(&store), 0);
    store
        .record_app_event(&app_event("old-aa", "aa", 10))
        .unwrap();

    let outcome = store.secure_prune_app_events_before("aa", 15).unwrap();

    assert_eq!(outcome.pruned_messages, 1);
    assert_eq!(secure_delete_pragma(&store), 0);
}

#[test]
fn secure_prune_returns_hashes_when_wal_checkpoint_is_busy() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("account.sqlite");
    let store = SqliteAccountStorage::from_connection_with_options(
        rusqlite::Connection::open(&db_path).unwrap(),
        crate::SqliteStorageOptions {
            busy_timeout_ms: 1,
            ..crate::SqliteStorageOptions::default()
        },
    )
    .unwrap();
    let media_hash = "db".repeat(32);
    let mut old = app_event("old-aa", "aa", 10);
    old.tags = vec![vec![
        "imeta".to_owned(),
        "v encrypted-media-v1".to_owned(),
        format!("ciphertext_sha256 {media_hash}"),
    ]];
    store.record_app_event(&old).unwrap();

    let reader = rusqlite::Connection::open(&db_path).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let _: i64 = reader
        .query_row("SELECT count(*) FROM app_events", [], |row| row.get(0))
        .unwrap();

    let outcome = store.secure_prune_app_events_before("aa", 15).unwrap();

    assert_eq!(outcome.pruned_messages, 1);
    assert_eq!(outcome.media_ciphertext_sha256, vec![media_hash]);
    reader.execute_batch("COMMIT").unwrap();
}

fn secure_delete_pragma(store: &SqliteAccountStorage) -> i64 {
    store
        .lock()
        .unwrap()
        .query_row("PRAGMA secure_delete", [], |row| row.get(0))
        .unwrap()
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

#[test]
fn delete_local_group_data_removes_app_local_rows_without_touching_protocol_state() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let state = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: vec!["seen-aa".to_owned()],
        last_transport_timestamp: Some(1_700_000_001),
        groups: vec![group("aa", "alpha"), group("bb", "beta")],
    };
    store.save_account_projection_state(&state, 16).unwrap();
    store
        .record_app_event(&app_event("msg-aa", "aa", 10))
        .unwrap();
    store
        .record_app_event(&agent_stream_start_event(
            "stream-aa",
            "aa",
            &"11".repeat(32),
            11,
        ))
        .unwrap();
    store
        .record_app_event(&app_event("msg-bb", "bb", 12))
        .unwrap();
    store
        .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
        .unwrap();
    store
        .remember_encrypted_media_epoch_secret("bb", 0x8008, 7, &[4, 5, 6])
        .unwrap();
    insert_group_push_token(&store, "aa", "member-aa");
    insert_group_push_token(&store, "bb", "member-bb");
    insert_read_and_chat_rows(&store, "aa");
    insert_protocol_group_marker(&store, &[0xaa]);

    assert!(store.delete_local_group_data("aa").unwrap());

    for table in [
        "account_groups",
        "account_group_app_components",
        "app_events",
        "message_timeline",
        "agent_stream_starts",
        "conversation_read_state",
        "chat_list_rows",
        "group_push_tokens",
        "encrypted_media_epoch_secrets",
    ] {
        assert_eq!(group_row_count(&store, table, "aa"), 0, "{table}");
    }
    for table in [
        "account_groups",
        "account_group_app_components",
        "app_events",
        "message_timeline",
        "group_push_tokens",
        "encrypted_media_epoch_secrets",
    ] {
        assert!(group_row_count(&store, table, "bb") > 0, "{table}");
    }
    assert_eq!(all_row_count(&store, "seen_events"), 1);
    assert_eq!(all_row_count(&store, "cgka_groups"), 1);
    assert!(!store.delete_local_group_data("aa").unwrap());
}

#[test]
fn delete_local_group_data_rejects_blank_group_id() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let err = store
        .delete_local_group_data(" \t ")
        .expect_err("blank group IDs must be rejected before opening a transaction");

    assert!(format!("{err}").contains("local group delete id must not be empty"));
}

#[test]
fn delete_local_group_data_rolls_back_all_tables_on_failure() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let state = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: vec![group("aa", "alpha")],
    };
    store.save_account_projection_state(&state, 16).unwrap();
    store
        .record_app_event(&app_event("msg-aa", "aa", 10))
        .unwrap();
    store
        .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
        .unwrap();
    insert_group_push_token(&store, "aa", "member-aa");
    store
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER abort_local_delete\n             AFTER DELETE ON message_timeline\n             WHEN old.group_id_hex = 'aa'\n             BEGIN\n                SELECT RAISE(ABORT, 'abort local delete');\n             END;",
        )
        .unwrap();

    let err = store
        .delete_local_group_data("aa")
        .expect_err("trigger should abort the transaction");
    assert!(format!("{err}").contains("abort local delete"));

    for table in [
        "account_groups",
        "account_group_app_components",
        "app_events",
        "message_timeline",
        "group_push_tokens",
        "encrypted_media_epoch_secrets",
    ] {
        assert!(group_row_count(&store, table, "aa") > 0, "{table}");
    }
}

fn insert_group_push_token(store: &SqliteAccountStorage, group_id_hex: &str, member_id_hex: &str) {
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO group_push_tokens (\n                group_id_hex, member_id_hex, leaf_index, platform, token_fingerprint,\n                server_pubkey_hex, relay_hint, encrypted_token, updated_at_ms\n             ) VALUES (?1, ?2, 0, 1, 'token', ?3, NULL, x'0102', 123)",
            rusqlite::params![group_id_hex, member_id_hex, "cc".repeat(32)],
        )
        .unwrap();
}

fn insert_read_and_chat_rows(store: &SqliteAccountStorage, group_id_hex: &str) {
    let conn = store.lock().unwrap();
    conn.execute(
        "INSERT INTO conversation_read_state (\n            group_id_hex, last_read_message_id_hex, last_read_timeline_at,\n            initialized_at, updated_at\n         ) VALUES (?1, 'msg-aa', 10, 10, 10)",
        rusqlite::params![group_id_hex],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO chat_list_rows (\n            group_id_hex, archived, pending_confirmation, title, group_name,\n            last_message_id_hex, last_message_sender, last_message_preview,\n            last_message_kind, last_message_timeline_at, unread_count, updated_at\n         ) VALUES (?1, 0, 0, 'alpha', 'alpha', 'msg-aa', 'sender', 'hello', 9, 10, 0, 10)",
        rusqlite::params![group_id_hex],
    )
    .unwrap();
}

fn insert_protocol_group_marker(store: &SqliteAccountStorage, group_id: &[u8]) {
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, 0, x'00')",
            rusqlite::params![group_id],
        )
        .unwrap();
}

fn group_row_count(store: &SqliteAccountStorage, table: &str, group_id_hex: &str) -> i64 {
    store
        .lock()
        .unwrap()
        .query_row(
            &format!("SELECT count(*) FROM {table} WHERE group_id_hex = ?1"),
            rusqlite::params![group_id_hex],
            |row| row.get(0),
        )
        .unwrap()
}

fn all_row_count(store: &SqliteAccountStorage, table: &str) -> i64 {
    store
        .lock()
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}
