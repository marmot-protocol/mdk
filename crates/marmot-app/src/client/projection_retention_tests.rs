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
