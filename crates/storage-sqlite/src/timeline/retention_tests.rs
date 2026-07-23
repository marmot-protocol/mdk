use super::*;
use crate::{SqlCipherKey, SqliteAccountStorage};

fn retention_app_event(
    id: &str,
    group_id_hex: &str,
    recorded_at: u64,
    source_retention_secs: Option<u64>,
    expiry_timestamp: Option<u64>,
) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: group_id_hex.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: Some(7),
        direction: "received".to_owned(),
        sender: "alice".to_owned(),
        plaintext: format!("payload-{id}"),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: vec![],
        recorded_at,
        received_at: recorded_at,
        origin_commit_id: None,
        moderation_grant: false,
        source_retention_secs,
        expiry_timestamp,
    }
}

fn stored_retention(
    storage: &SqliteAccountStorage,
    message_id: &str,
) -> (Option<u64>, Option<u64>) {
    let conn = storage.lock().unwrap();
    let values: (Option<Vec<u8>>, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT source_retention_secs, expiry_timestamp
             FROM app_events WHERE message_id_hex = ?1",
            [message_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let decode = |value: Option<Vec<u8>>| {
        value.map(|value| u64::from_be_bytes(value.try_into().expect("8-byte uint64 blob")))
    };
    (decode(values.0), decode(values.1))
}

fn app_event_exists(storage: &SqliteAccountStorage, message_id: &str) -> bool {
    storage
        .lock()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM app_events WHERE message_id_hex = ?1)",
            [message_id],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn secure_prune_expired_app_events_uses_pinned_expiry_only() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .record_app_event(&retention_app_event(
            "expired",
            "aa",
            100,
            Some(10),
            Some(110),
        ))
        .unwrap();
    storage
        .record_app_event(&retention_app_event(
            "future",
            "aa",
            100,
            Some(100),
            Some(200),
        ))
        .unwrap();
    storage
        .record_app_event(&retention_app_event("disabled", "aa", 1, Some(0), None))
        .unwrap();
    storage
        .record_app_event(&retention_app_event("legacy", "aa", 1, None, None))
        .unwrap();
    storage
        .record_app_event(&retention_app_event(
            "overflow",
            "aa",
            u64::MAX,
            Some(1),
            None,
        ))
        .unwrap_err();

    let outcome = storage.secure_prune_expired_app_events("aa", 150).unwrap();
    assert_eq!(outcome.pruned_messages, 1);
    assert!(!app_event_exists(&storage, "expired"));
    for id in ["future", "disabled", "legacy"] {
        assert!(app_event_exists(&storage, id), "{id} must be preserved");
    }
}

#[test]
fn duplicate_record_preserves_first_pinned_retention_fields() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .record_app_event(&retention_app_event(
            "duplicate",
            "aa",
            100,
            Some(60),
            Some(160),
        ))
        .unwrap();
    storage
        .record_app_event(&retention_app_event(
            "duplicate",
            "aa",
            100,
            Some(3_600),
            Some(3_700),
        ))
        .unwrap();

    assert_eq!(
        stored_retention(&storage, "duplicate"),
        (Some(60), Some(160))
    );
}

#[test]
fn duplicate_cannot_turn_known_disabled_retention_into_expiring_retention() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .record_app_event(&retention_app_event(
            "disabled-duplicate",
            "aa",
            100,
            Some(0),
            None,
        ))
        .unwrap();
    storage
        .record_app_event(&retention_app_event(
            "disabled-duplicate",
            "aa",
            100,
            Some(60),
            Some(160),
        ))
        .unwrap();

    assert_eq!(
        stored_retention(&storage, "disabled-duplicate"),
        (Some(0), None)
    );
    let outcome = storage.secure_prune_expired_app_events("aa", 200).unwrap();
    assert_eq!(outcome.pruned_messages, 0);
    assert!(app_event_exists(&storage, "disabled-duplicate"));
}

#[test]
fn duplicate_cannot_reinterpret_legacy_unknown_retention() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .record_app_event(&retention_app_event("legacy", "aa", 100, None, None))
        .unwrap();
    storage
        .record_app_event(&retention_app_event(
            "legacy",
            "aa",
            100,
            Some(60),
            Some(160),
        ))
        .unwrap();

    assert_eq!(stored_retention(&storage, "legacy"), (None, None));
    let outcome = storage.secure_prune_expired_app_events("aa", 200).unwrap();
    assert_eq!(outcome.pruned_messages, 0);
    assert!(app_event_exists(&storage, "legacy"));
}

#[test]
fn reopened_storage_preserves_pinned_retention_and_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("retention-restart.db");
    let key = SqlCipherKey::new("retention restart key").unwrap();
    let initial = retention_app_event("restart", "aa", 100, Some(60), Some(160));
    let duplicate = retention_app_event("restart", "aa", 100, Some(3_600), Some(3_700));

    {
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        storage.record_app_event(&initial).unwrap();
    }
    {
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(stored_retention(&storage, "restart"), (Some(60), Some(160)));
        storage.record_app_event(&duplicate).unwrap();
        assert_eq!(stored_retention(&storage, "restart"), (Some(60), Some(160)));
        let outcome = storage.secure_prune_expired_app_events("aa", 200).unwrap();
        assert_eq!(outcome.pruned_messages, 1);
    }
}

#[test]
fn finalize_app_event_source_retention_pins_unknown_row_once() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut event = retention_app_event("queued-send", "aa", 100, None, None);
    event.direction = "sent".to_owned();
    storage.record_app_event(&event).unwrap();

    let update = storage
        .finalize_app_event_source_retention("aa", "queued-send", Some("source-queued-send"), 3_600)
        .unwrap()
        .expect("finalize should update unknown row");
    assert_eq!(update.group_id_hex, "aa");
    assert_eq!(
        stored_retention(&storage, "queued-send"),
        (Some(3_600), Some(3_700))
    );

    assert!(
        storage
            .finalize_app_event_source_retention("aa", "queued-send", Some("other-source"), 60,)
            .unwrap()
            .is_none(),
        "already-finalized retention must not be overwritten"
    );
    assert_eq!(
        stored_retention(&storage, "queued-send"),
        (Some(3_600), Some(3_700))
    );
}

#[test]
fn finalize_disabled_retention_stores_some_zero_without_expiry() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut event = retention_app_event("disabled-send", "aa", 100, None, None);
    event.direction = "sent".to_owned();
    storage.record_app_event(&event).unwrap();

    storage
        .finalize_app_event_source_retention("aa", "disabled-send", Some("source-disabled"), 0)
        .unwrap()
        .expect("finalize disabled retention");

    assert_eq!(stored_retention(&storage, "disabled-send"), (Some(0), None));
}

#[test]
fn duplicate_record_after_finalize_preserves_first_pinned_retention_fields() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut event = retention_app_event("queued-send", "aa", 100, None, None);
    event.direction = "sent".to_owned();
    storage.record_app_event(&event).unwrap();
    storage
        .finalize_app_event_source_retention("aa", "queued-send", Some("source-queued-send"), 60)
        .unwrap();

    storage
        .record_app_event(&retention_app_event(
            "queued-send",
            "aa",
            100,
            Some(3_600),
            Some(3_700),
        ))
        .unwrap();
    assert_eq!(
        stored_retention(&storage, "queued-send"),
        (Some(60), Some(160))
    );
}

#[test]
fn full_u64_retention_duration_is_persisted_without_invalidating_message() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .record_app_event(&retention_app_event(
            "full-u64-duration",
            "aa",
            100,
            Some(u64::MAX),
            None,
        ))
        .unwrap();

    assert_eq!(
        stored_retention(&storage, "full-u64-duration"),
        (Some(u64::MAX), None)
    );
    let outcome = storage
        .secure_prune_expired_app_events("aa", u64::MAX)
        .unwrap();
    assert_eq!(outcome.pruned_messages, 0);
    assert!(app_event_exists(&storage, "full-u64-duration"));
}
