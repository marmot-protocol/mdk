use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
use storage_sqlite::StoredAppEvent;

use crate::AccountHome;
use crate::MarmotApp;
use crate::conversions::pinned_source_epoch_retention;

fn retention_event(id: &str, recorded_at: u64, disappearing_message_secs: u64) -> StoredAppEvent {
    let (source_retention_secs, expiry_timestamp) =
        pinned_source_epoch_retention(Some(disappearing_message_secs), recorded_at);
    StoredAppEvent {
        group_id_hex: "aa".to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: Some(1),
        direction: "received".to_owned(),
        sender: "sender".to_owned(),
        plaintext: id.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at,
        received_at: recorded_at,
        origin_commit_id: None,
        moderation_grant: false,
        source_retention_secs,
        expiry_timestamp,
    }
}

#[test]
fn sweep_honors_pinned_short_expiry_after_policy_lengthens() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let storage = app.account_storage("alice").unwrap();
    storage
        .record_app_event(&retention_event("short", 100, 60))
        .unwrap();

    let outcome = storage.secure_prune_expired_app_events("aa", 200).unwrap();
    assert_eq!(outcome.pruned_messages, 1);
}

#[test]
fn sweep_does_not_shorten_pinned_long_expiry_when_policy_shortens() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let storage = app.account_storage("alice").unwrap();
    storage
        .record_app_event(&retention_event("long", 100, 3_600))
        .unwrap();

    let outcome = storage.secure_prune_expired_app_events("aa", 200).unwrap();
    assert_eq!(outcome.pruned_messages, 0);
    let timeline = storage
        .message_timeline(storage_sqlite::TimelineMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            ..storage_sqlite::TimelineMessageQuery::default()
        })
        .unwrap();
    assert_eq!(timeline.messages.len(), 1);
}

#[test]
fn received_sync_pins_engine_source_epoch_retention_not_current_policy() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let storage = app.account_storage("alice").unwrap();
    // Engine accepted the message under a 60s epoch-1 rule even though current
    // group policy might later lengthen to 3600s.
    let (source_retention_secs, expiry_timestamp) = pinned_source_epoch_retention(Some(60), 100);
    storage
        .record_app_event(&StoredAppEvent {
            source_retention_secs,
            expiry_timestamp,
            ..retention_event("delayed-epoch", 100, 3_600)
        })
        .unwrap();

    let outcome = storage.secure_prune_expired_app_events("aa", 200).unwrap();
    assert_eq!(outcome.pruned_messages, 1);
}

#[test]
fn legacy_rows_with_source_epoch_but_unknown_retention_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let storage = app.account_storage("alice").unwrap();
    let mut legacy = retention_event("legacy", 10, 60);
    legacy.source_retention_secs = None;
    legacy.expiry_timestamp = None;
    storage.record_app_event(&legacy).unwrap();

    let outcome = storage
        .secure_prune_expired_app_events("aa", 1_000_000)
        .unwrap();
    assert_eq!(outcome.pruned_messages, 0);
}

fn stored_retention_via_query(
    app: &MarmotApp,
    label: &str,
    group_id_hex: &str,
    message_id: &str,
) -> (Option<u64>, Option<u64>) {
    let storage = app.account_storage(label).unwrap();
    let events = storage
        .app_messages(storage_sqlite::StoredAppMessageQuery {
            group_id_hex: Some(group_id_hex.to_owned()),
            limit: None,
        })
        .unwrap();
    let record = events
        .into_iter()
        .find(|event| event.message_id_hex == message_id)
        .expect("message row");
    (record.source_retention_secs, None)
}

#[test]
fn queued_sent_row_finalizes_from_actual_encryption_epoch_short_to_long() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let storage = app.account_storage("alice").unwrap();
    let mut optimistic = retention_event("queued-short-to-long", 100, 60);
    optimistic.direction = "sent".to_owned();
    optimistic.source_retention_secs = None;
    optimistic.expiry_timestamp = None;
    optimistic.source_message_id_hex = None;
    storage.record_app_event(&optimistic).unwrap();

    app.finalize_account_app_event_source_retention(
        "alice",
        "aa",
        "queued-short-to-long",
        Some("mls-source"),
        3_600,
    )
    .unwrap()
    .expect("finalize");

    assert_eq!(
        stored_retention_via_query(&app, "alice", "aa", "queued-short-to-long").0,
        Some(3_600)
    );
    storage
        .record_app_event(&retention_event("queued-short-to-long", 100, 60))
        .unwrap();
    assert_eq!(
        stored_retention_via_query(&app, "alice", "aa", "queued-short-to-long").0,
        Some(3_600)
    );
}

#[test]
fn queued_sent_row_finalizes_from_actual_encryption_epoch_long_to_short() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let storage = app.account_storage("alice").unwrap();
    let mut optimistic = retention_event("queued-long-to-short", 100, 3_600);
    optimistic.direction = "sent".to_owned();
    optimistic.source_retention_secs = None;
    optimistic.expiry_timestamp = None;
    optimistic.source_message_id_hex = None;
    storage.record_app_event(&optimistic).unwrap();

    app.finalize_account_app_event_source_retention(
        "alice",
        "aa",
        "queued-long-to-short",
        Some("mls-source"),
        60,
    )
    .unwrap()
    .expect("finalize");

    assert_eq!(
        stored_retention_via_query(&app, "alice", "aa", "queued-long-to-short").0,
        Some(60)
    );
    let outcome = storage.secure_prune_expired_app_events("aa", 200).unwrap();
    assert_eq!(outcome.pruned_messages, 1);
}
