use super::*;
use crate::{SqlCipherKey, SqliteStorageOptions, StoredAppEvent};
use cgka_traits::app_event::{
    AppMessageRetentionDecision, EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
    MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION,
    QUOTE_REF_TAG, STREAM_TAG,
};
use cgka_traits::engine::GroupEvent;
use cgka_traits::storage::MessageStorage;
use cgka_traits::types::{EpochId, MemberId, MessageId};

/// Test twin of the app layer's transport-cursor future-skew policy (five
/// minutes). The storage layer treats it as an injected bound, so any value
/// works; mirroring production keeps the cursor tests realistic.
const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;

fn no_mentions(_plaintext: &str, _tags: &[Vec<String>]) -> bool {
    false
}

#[test]
fn secure_delete_restore_failure_preserves_committed_outcome() {
    let result = combine_secure_delete_operation_and_restore::<usize>(
        Ok(7),
        Err(StorageError::Backend("injected restore failure".to_owned())),
    )
    .unwrap();

    assert_eq!(result, 7);
}

#[test]
fn source_epoch_retention_decisions_are_frozen_and_drive_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("retention.sqlite");
    let key = SqlCipherKey::new("source epoch retention test key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();

    let mut due = app_event("due", "aa", 10);
    due.source_epoch = Some(4);
    store
        .record_app_event_with_retention(
            &due,
            Some(AppMessageRetentionDecision::new(due.recorded_at, 5)),
        )
        .unwrap();

    // A relay echo or restart replay cannot rewrite either the source epoch or
    // the already-pinned deadline.
    let mut duplicate = due.clone();
    duplicate.source_epoch = Some(99);
    store
        .record_app_event_with_retention(
            &duplicate,
            Some(AppMessageRetentionDecision::new(duplicate.recorded_at, 500)),
        )
        .unwrap();

    let later = app_event("later", "aa", 12);
    store
        .record_app_event_with_retention(
            &later,
            Some(AppMessageRetentionDecision::new(later.recorded_at, 4)),
        )
        .unwrap();
    let disabled = app_event("disabled", "aa", 1);
    store
        .record_app_event_with_retention(
            &disabled,
            Some(AppMessageRetentionDecision::new(disabled.recorded_at, 0)),
        )
        .unwrap();
    let overflow = app_event("overflow", "aa", 1);
    store
        .record_app_event_with_retention(
            &overflow,
            Some(AppMessageRetentionDecision::new(u64::MAX, 1)),
        )
        .unwrap();
    store
        .record_app_event(&app_event("legacy", "aa", 1))
        .unwrap();
    store
        .record_app_event_with_retention(
            &app_event("other-group", "bb", 1),
            Some(AppMessageRetentionDecision::new(1, 1)),
        )
        .unwrap();

    drop(store);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let records = store
        .app_messages(StoredAppMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            limit: None,
        })
        .unwrap();
    let due_record = records
        .iter()
        .find(|record| record.message_id_hex == "due")
        .unwrap();
    assert_eq!(due_record.source_epoch, Some(4));
    assert_eq!(
        due_record.retention,
        Some(AppMessageRetentionDecision::new(10, 5))
    );
    assert_eq!(
        records
            .iter()
            .find(|record| record.message_id_hex == "legacy")
            .unwrap()
            .retention,
        None
    );

    let outcome = store
        .secure_prune_expired_app_events("aa", 15, "local", &no_mentions)
        .unwrap();
    assert_eq!(outcome.pruned_messages, 1);
    let surviving_ids = store
        .app_messages(StoredAppMessageQuery {
            group_id_hex: None,
            limit: None,
        })
        .unwrap()
        .into_iter()
        .map(|record| record.message_id_hex)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!surviving_ids.contains("due"));
    assert!(surviving_ids.contains("later"));
    assert!(surviving_ids.contains("disabled"));
    assert!(surviving_ids.contains("overflow"));
    assert!(surviving_ids.contains("legacy"));
    assert!(surviving_ids.contains("other-group"));

    assert_eq!(
        store
            .secure_prune_expired_app_events("aa", 16, "local", &no_mentions)
            .unwrap()
            .pruned_messages,
        1
    );
}

#[test]
fn optimistic_local_retention_is_finalized_once_from_matching_source_epoch() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let optimistic = app_event("local", "aa", 10);
    store.record_app_event(&optimistic).unwrap();

    assert!(
        store
            .finalize_app_event_source_retention(
                "aa",
                "local",
                Some("transport-id"),
                4,
                AppMessageRetentionDecision::new(12, 5),
            )
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .finalize_app_event_source_retention(
                "aa",
                "local",
                Some("different-id"),
                99,
                AppMessageRetentionDecision::new(10, 500),
            )
            .unwrap()
            .is_none(),
        "a duplicate publication cannot reinterpret a finalized decision"
    );

    let mut pinned_epoch = app_event("pinned-epoch", "aa", 20);
    pinned_epoch.source_epoch = Some(7);
    store.record_app_event(&pinned_epoch).unwrap();
    assert!(
        store
            .finalize_app_event_source_retention(
                "aa",
                "pinned-epoch",
                None,
                8,
                AppMessageRetentionDecision::new(20, 30),
            )
            .unwrap()
            .is_none(),
        "retention from a different epoch must not attach to an existing row"
    );
    assert!(
        store
            .finalize_app_event_source_retention(
                "aa",
                "pinned-epoch",
                None,
                7,
                AppMessageRetentionDecision::new(20, 30),
            )
            .unwrap()
            .is_some()
    );

    let records = store
        .app_messages(StoredAppMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            limit: None,
        })
        .unwrap();
    let local = records
        .iter()
        .find(|record| record.message_id_hex == "local")
        .unwrap();
    assert_eq!(local.source_epoch, Some(4));
    assert_eq!(
        local.retention,
        Some(AppMessageRetentionDecision::new(12, 5))
    );
    let pinned = records
        .iter()
        .find(|record| record.message_id_hex == "pinned-epoch")
        .unwrap();
    assert_eq!(pinned.source_epoch, Some(7));
    assert_eq!(
        pinned.retention,
        Some(AppMessageRetentionDecision::new(20, 30))
    );
}

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
        member_count: None,
        welcomer_account_id_hex: None,
        via_welcome_message_id_hex: None,
        nostr_routing_last_epoch: 0,
        prior_nostr_routes: Vec::new(),
        self_membership: SelfMembership::Member,
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
        moderation_grant: false,
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
        moderation_grant: false,
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
        moderation_grant: false,
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
        moderation_grant: false,
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
        moderation_grant: false,
    }
}

#[test]
fn account_projection_state_roundtrips_groups_components_and_seen_events() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut stored_group = group("aa", "alpha");
    stored_group.nostr_routing_last_epoch = 8;
    stored_group.prior_nostr_routes = vec![StoredNostrRoute {
        nostr_group_id_hex: "11".repeat(32),
        relays: vec!["wss://prior.example".to_owned()],
        last_epoch: 7,
    }];
    let state = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: vec!["old".to_owned(), "kept".to_owned()],
        last_transport_timestamp: Some(1_700_000_001),
        groups: vec![stored_group],
    };

    store
        .save_account_projection_state(&state, 1, MAX_FUTURE_SKEW_SECS)
        .unwrap();

    let restored = store.load_account_projection_state("alice", 16).unwrap();
    assert_eq!(restored.seen_events, vec!["kept"]);
    assert_eq!(restored.last_transport_timestamp, Some(1_700_000_001));
    assert_eq!(restored.groups[0].profile_name, "alpha");
    assert_eq!(restored.groups[0].components.len(), 2);
    assert_eq!(restored.groups[0].components[1].component_id, 0x8004);
    assert_eq!(restored.groups[0].nostr_routing_last_epoch, 8);
    assert_eq!(
        restored.groups[0].prior_nostr_routes,
        vec![StoredNostrRoute {
            nostr_group_id_hex: "11".repeat(32),
            relays: vec!["wss://prior.example".to_owned()],
            last_epoch: 7,
        }]
    );
}

#[test]
fn account_projection_state_refreshes_reseen_event_recency_before_pruning() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    {
        let conn = store.lock().unwrap();
        // Seed tiny historical timestamps so the real save timestamp deterministically
        // refreshes `repeat` to the newest row before the LRU prune runs.
        conn.execute(
            "INSERT INTO seen_events (event_id, seen_at) VALUES (?1, ?2)",
            params!["repeat", 1_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO seen_events (event_id, seen_at) VALUES (?1, ?2)",
            params!["stale-a", 2_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO seen_events (event_id, seen_at) VALUES (?1, ?2)",
            params!["stale-b", 3_i64],
        )
        .unwrap();
    }

    let state = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: vec!["repeat".to_owned()],
        last_transport_timestamp: None,
        groups: Vec::new(),
    };
    store
        .save_account_projection_state(&state, 2, MAX_FUTURE_SKEW_SECS)
        .unwrap();

    let restored = store.load_account_projection_state("alice", 16).unwrap();
    assert_eq!(restored.seen_events, vec!["stale-b", "repeat"]);
}

#[test]
fn account_projection_state_keeps_max_cursor_across_racing_saves() {
    // Two runtimes over the same account database race their saves; whichever
    // order the writes land in, the durable cursor must end at the max — a
    // stale writer must never lower an advanced cursor.
    let ahead = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: Some(1_700_000_200),
        groups: Vec::new(),
    };
    let behind = StoredAccountState {
        last_transport_timestamp: Some(1_700_000_100),
        ..ahead.clone()
    };

    for saves in [[&ahead, &behind], [&behind, &ahead]] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        for state in saves {
            store
                .save_account_projection_state(state, 16, MAX_FUTURE_SKEW_SECS)
                .unwrap();
        }
        let restored = store.load_account_projection_state("alice", 16).unwrap();
        assert_eq!(restored.last_transport_timestamp, Some(1_700_000_200));
    }
}

#[test]
fn account_projection_state_save_without_cursor_preserves_stored_cursor() {
    // A runtime that never learned a cursor (fresh process, no deliveries yet)
    // still saves other state; that save must never wipe an advanced stored
    // cursor back to NULL.
    let store = SqliteAccountStorage::in_memory().unwrap();
    let advanced = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: Some(1_700_000_200),
        groups: Vec::new(),
    };
    store
        .save_account_projection_state(&advanced, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();

    let never_learned = StoredAccountState {
        last_transport_timestamp: None,
        ..advanced
    };
    store
        .save_account_projection_state(&never_learned, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();

    let restored = store.load_account_projection_state("alice", 16).unwrap();
    assert_eq!(restored.last_transport_timestamp, Some(1_700_000_200));
}

#[test]
fn account_projection_state_heals_poisoned_stored_cursor_on_save() {
    // A stored cursor poisoned above `now + skew` (persisted by a version that
    // predates the write-side clamp) must come out of the merge healed down to
    // save-time `now + skew`, not preserved forever by the monotonic max —
    // the save-side twin of the app layer's ingest-time heal.
    let store = SqliteAccountStorage::in_memory().unwrap();
    let now_before = unix_now_seconds();
    let poisoned = now_before + 10 * 365 * 24 * 60 * 60; // ~10 years ahead
    store.ensure_account_projection("alice").unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_state SET last_transport_timestamp = ?1 WHERE label = ?2",
            params![i64::try_from(poisoned).unwrap(), "alice"],
        )
        .unwrap();

    let honest = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: Some(now_before),
        groups: Vec::new(),
    };
    store
        .save_account_projection_state(&honest, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    let now_after = unix_now_seconds();

    let restored = store.load_account_projection_state("alice", 16).unwrap();
    let cursor = restored
        .last_transport_timestamp
        .expect("cursor must survive the save");
    assert!(
        (now_before + MAX_FUTURE_SKEW_SECS..=now_after + MAX_FUTURE_SKEW_SECS).contains(&cursor),
        "poisoned stored cursor must heal to save-time now + skew, got {cursor}"
    );
}

#[test]
fn account_projection_state_clamps_poisoned_snapshot_into_fresh_store() {
    // Legacy-import shape (mdk#182): the marmot-app migration
    // (`migrate_legacy_account_projection_if_needed`) writes a legacy-loaded
    // state into a brand-new account store through this same
    // `save_account_projection_state`. A pre-clamp-era legacy projection can
    // carry a transport cursor poisoned above `now + skew`; adopting it into the
    // fresh store (the `stored = None` arm) must clamp it to save-time
    // `now + skew`, never persist the poison. Because the migration routes
    // through this exact save, a fresh-store save with a poisoned snapshot is
    // the faithful reproduction of that path — no separate migration fixture is
    // needed for the storage layer. A true end-to-end counterpart that drives
    // the migration itself lives in marmot-app
    // (`legacy_account_projection_clamps_poisoned_transport_cursor_on_import`).
    let store = SqliteAccountStorage::in_memory().unwrap();
    let now_before = unix_now_seconds();
    let poisoned = now_before + 10 * 365 * 24 * 60 * 60; // ~10 years ahead
    let imported = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: Some(poisoned),
        groups: Vec::new(),
    };
    store
        .save_account_projection_state(&imported, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    let now_after = unix_now_seconds();

    let restored = store.load_account_projection_state("alice", 16).unwrap();
    let cursor = restored
        .last_transport_timestamp
        .expect("cursor must survive the save");
    assert!(
        (now_before + MAX_FUTURE_SKEW_SECS..=now_after + MAX_FUTURE_SKEW_SECS).contains(&cursor),
        "poisoned snapshot adopted into a fresh store must clamp to save-time now + skew, got {cursor}"
    );
}

/// Fixed merge-time "now" for the pure cursor-merge tests below.
const MERGE_NOW: u64 = 1_800_000_000;

#[test]
fn merged_transport_timestamp_is_explicit_over_missing_sides() {
    assert_eq!(
        merged_transport_timestamp(None, None, MERGE_NOW, MAX_FUTURE_SKEW_SECS),
        None
    );
    // A fresh store adopts whatever the runtime learned.
    assert_eq!(
        merged_transport_timestamp(None, Some(MERGE_NOW), MERGE_NOW, MAX_FUTURE_SKEW_SECS),
        Some(MERGE_NOW)
    );
    // A runtime that never learned a cursor must never wipe the stored one.
    assert_eq!(
        merged_transport_timestamp(Some(MERGE_NOW), None, MERGE_NOW, MAX_FUTURE_SKEW_SECS),
        Some(MERGE_NOW)
    );
}

#[test]
fn merged_transport_timestamp_takes_max_of_in_range_sides() {
    assert_eq!(
        merged_transport_timestamp(
            Some(MERGE_NOW - 100),
            Some(MERGE_NOW),
            MERGE_NOW,
            MAX_FUTURE_SKEW_SECS
        ),
        Some(MERGE_NOW)
    );
    assert_eq!(
        merged_transport_timestamp(
            Some(MERGE_NOW),
            Some(MERGE_NOW - 100),
            MERGE_NOW,
            MAX_FUTURE_SKEW_SECS
        ),
        Some(MERGE_NOW)
    );
}

#[test]
fn merged_transport_timestamp_clamps_both_sides_before_max() {
    let poisoned = MERGE_NOW + 10 * 365 * 24 * 60 * 60; // ~10 years ahead
    // A poisoned stored side is healed to the ceiling instead of winning the
    // max forever.
    assert_eq!(
        merged_transport_timestamp(
            Some(poisoned),
            Some(MERGE_NOW),
            MERGE_NOW,
            MAX_FUTURE_SKEW_SECS
        ),
        Some(MERGE_NOW + MAX_FUTURE_SKEW_SECS)
    );
    // A poisoned snapshot side is bounded the same way (defense in depth; the
    // ingest path already clamps before the value reaches a save).
    assert_eq!(
        merged_transport_timestamp(
            Some(MERGE_NOW),
            Some(poisoned),
            MERGE_NOW,
            MAX_FUTURE_SKEW_SECS
        ),
        Some(MERGE_NOW + MAX_FUTURE_SKEW_SECS)
    );
}

#[test]
fn merged_transport_timestamp_is_cursor_neutral_without_snapshot() {
    // Without a snapshot cursor there is nothing to merge against: the stored
    // value passes through byte-identical, even when poisoned. Healing waits
    // for the next save that learned a cursor, so a cursor-less save never
    // moves the durable value in either direction.
    let poisoned = MERGE_NOW + 10 * 365 * 24 * 60 * 60;
    assert_eq!(
        merged_transport_timestamp(Some(poisoned), None, MERGE_NOW, MAX_FUTURE_SKEW_SECS),
        Some(poisoned)
    );
}

#[test]
fn merged_transport_timestamp_clamps_snapshot_adopted_into_fresh_store() {
    // A fresh store (`stored = None`) adopts the snapshot cursor, but must clamp
    // it on the way in rather than adopt it raw. The legacy-import migration can
    // carry a pre-clamp-era transport cursor poisoned above `now + skew` into a
    // brand-new store through exactly this arm, so the adopted value has to be
    // bounded to the ceiling.
    let poisoned = MERGE_NOW + 10 * 365 * 24 * 60 * 60; // ~10 years ahead
    assert_eq!(
        merged_transport_timestamp(None, Some(poisoned), MERGE_NOW, MAX_FUTURE_SKEW_SECS),
        Some(MERGE_NOW + MAX_FUTURE_SKEW_SECS)
    );
}

#[test]
fn clamp_to_max_future_skew_bounds_only_future_values() {
    // In-range values pass through unchanged.
    assert_eq!(
        clamp_to_max_future_skew(MERGE_NOW - 1, MERGE_NOW, MAX_FUTURE_SKEW_SECS),
        MERGE_NOW - 1
    );
    assert_eq!(
        clamp_to_max_future_skew(
            MERGE_NOW + MAX_FUTURE_SKEW_SECS,
            MERGE_NOW,
            MAX_FUTURE_SKEW_SECS
        ),
        MERGE_NOW + MAX_FUTURE_SKEW_SECS
    );
    // Values beyond the ceiling are pulled back to it.
    assert_eq!(
        clamp_to_max_future_skew(
            MERGE_NOW + MAX_FUTURE_SKEW_SECS + 1,
            MERGE_NOW,
            MAX_FUTURE_SKEW_SECS
        ),
        MERGE_NOW + MAX_FUTURE_SKEW_SECS
    );
    // The ceiling saturates instead of overflowing.
    assert_eq!(
        clamp_to_max_future_skew(MERGE_NOW, u64::MAX, MAX_FUTURE_SKEW_SECS),
        MERGE_NOW
    );
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
    store
        .save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();

    let updated = StoredAccountState {
        groups: vec![group("bb", "beta")],
        ..state
    };
    store
        .save_account_projection_state(&updated, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();

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
fn account_projection_group_prune_chunks_stale_keys_under_sqlite_variable_limit() {
    const GROUP_COUNT: usize = SQLITE_BIND_PARAMETER_CHUNK + 105;

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
    let groups = (0..GROUP_COUNT)
        .map(|index| {
            let mut stored_group = group(&format!("group-{index:04}"), "group");
            stored_group.components.clear();
            stored_group
        })
        .collect::<Vec<_>>();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: groups.clone(),
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();

    let retained = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: groups[1..].to_vec(),
    };
    store
        .save_account_projection_state(&retained, 16, MAX_FUTURE_SKEW_SECS)
        .expect("an unbounded retained set must not become SQL bind parameters");
    assert_eq!(
        store
            .load_account_projection_state("alice", GROUP_COUNT)
            .unwrap()
            .groups
            .len(),
        GROUP_COUNT - 1
    );

    store
        .save_account_projection_state(
            &StoredAccountState {
                groups: Vec::new(),
                ..retained
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .expect("more than one chunk of stale group keys should be deleted");
    assert!(
        store
            .load_account_projection_state("alice", GROUP_COUNT)
            .unwrap()
            .groups
            .is_empty()
    );
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
    store
        .save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
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
    store
        .save_account_projection_state(&updated, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();

    let writes: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM write_audit", [], |row| row.get(0))
        .unwrap();
    assert_eq!(writes, 0);
}

#[test]
fn account_projection_delta_writes_only_observations_and_changed_groups() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let seen_events = (0..64)
        .map(|index| format!("event-{index:05}"))
        .collect::<Vec<_>>();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events,
                last_transport_timestamp: None,
                groups: vec![group("aa", "alpha"), group("bb", "beta")],
            },
            64,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE write_audit (write_kind TEXT NOT NULL);
             CREATE TRIGGER audit_seen_insert AFTER INSERT ON seen_events BEGIN
                INSERT INTO write_audit VALUES ('seen_insert');
             END;
             CREATE TRIGGER audit_seen_update AFTER UPDATE ON seen_events BEGIN
                INSERT INTO write_audit VALUES ('seen_update');
             END;
             CREATE TRIGGER audit_seen_delete AFTER DELETE ON seen_events BEGIN
                INSERT INTO write_audit VALUES ('seen_delete');
             END;
             CREATE TRIGGER audit_group_insert AFTER INSERT ON account_groups BEGIN
                INSERT INTO write_audit VALUES ('group_insert');
             END;
             CREATE TRIGGER audit_group_update AFTER UPDATE ON account_groups BEGIN
                INSERT INTO write_audit VALUES ('group_update');
             END;
             CREATE TRIGGER audit_group_delete AFTER DELETE ON account_groups BEGIN
                INSERT INTO write_audit VALUES ('group_delete');
             END;
             CREATE TRIGGER audit_component_insert
             AFTER INSERT ON account_group_app_components BEGIN
                INSERT INTO write_audit VALUES ('component_insert');
             END;
             CREATE TRIGGER audit_component_update
             AFTER UPDATE ON account_group_app_components BEGIN
                INSERT INTO write_audit VALUES ('component_update');
             END;
             CREATE TRIGGER audit_component_delete
             AFTER DELETE ON account_group_app_components BEGIN
                INSERT INTO write_audit VALUES ('component_delete');
             END;",
        )
        .unwrap();
    }

    let mut changed_group = group("bb", "beta updated");
    changed_group.components[1].component_data_hex = "0506".to_owned();
    store
        .save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: vec!["event-new-a".to_owned(), "event-new-b".to_owned()],
                last_transport_timestamp: None,
                groups: vec![changed_group],
            },
            64,
            MAX_FUTURE_SKEW_SECS,
            &[],
            &[],
        )
        .unwrap();

    let write_count = |kind: &str| -> i64 {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM write_audit WHERE write_kind = ?1",
                params![kind],
                |row| row.get(0),
            )
            .unwrap()
    };
    assert_eq!(write_count("seen_insert"), 2);
    assert_eq!(write_count("seen_update"), 0);
    assert_eq!(write_count("seen_delete"), 2);
    assert_eq!(write_count("group_insert"), 0);
    assert_eq!(write_count("group_update"), 1);
    assert_eq!(write_count("group_delete"), 0);
    assert_eq!(write_count("component_insert"), 0);
    assert_eq!(write_count("component_update"), 1);
    assert_eq!(write_count("component_delete"), 0);

    let restored = store.load_account_projection_state("alice", 64).unwrap();
    assert_eq!(restored.seen_events.len(), 64);
    assert_eq!(
        &restored.seen_events[62..],
        &["event-new-a".to_owned(), "event-new-b".to_owned()]
    );
    assert_eq!(
        restored.groups.len(),
        2,
        "delta must not prune absent groups"
    );
    assert_eq!(restored.groups[0].profile_name, "alpha");
    assert_eq!(restored.groups[1].profile_name, "beta updated");

    store
        .lock()
        .unwrap()
        .execute("DELETE FROM write_audit", [])
        .unwrap();
    store
        .save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: vec!["event-00063".to_owned()],
                last_transport_timestamp: None,
                groups: Vec::new(),
            },
            64,
            MAX_FUTURE_SKEW_SECS,
            &[],
            &[],
        )
        .unwrap();
    assert_eq!(write_count("seen_insert"), 0);
    assert_eq!(write_count("seen_update"), 1);
    assert_eq!(write_count("seen_delete"), 0);

    store
        .lock()
        .unwrap()
        .execute("DELETE FROM write_audit", [])
        .unwrap();
    let mut archived_group = group("aa", "alpha");
    archived_group.archived = true;
    store
        .save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![archived_group],
            },
            64,
            MAX_FUTURE_SKEW_SECS,
            &[],
            &[],
        )
        .unwrap();
    assert_eq!(write_count("seen_insert"), 0);
    assert_eq!(write_count("seen_update"), 0);
    assert_eq!(write_count("seen_delete"), 0);
    assert_eq!(write_count("group_update"), 1);
    assert_eq!(write_count("component_insert"), 0);
    assert_eq!(write_count("component_update"), 0);
    assert_eq!(write_count("component_delete"), 0);
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

    assert_eq!(
        store
            .prune_app_events_before("aa", 15, "local", &no_mentions)
            .unwrap(),
        1
    );

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

    assert_eq!(
        store
            .prune_app_events_before("aa", 15, "local", &no_mentions)
            .unwrap(),
        1
    );

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
            MAX_FUTURE_SKEW_SECS,
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
    store
        .refresh_chat_list_row("alice-account", "aa", &no_mentions)
        .unwrap();
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

    let outcome = store
        .secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        .unwrap();
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

    let outcome = store
        .secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        .unwrap();

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
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    let mut old = app_event("old-aa", "aa", 10);
    old.plaintext = "chat list should not retain this".to_owned();
    store.record_app_event(&old).unwrap();
    store
        .refresh_chat_list_row("alice-account", "aa", &no_mentions)
        .unwrap();
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

    let outcome = store
        .secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        .unwrap();

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

    let outcome = store
        .secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        .unwrap();

    assert_eq!(outcome.pruned_messages, 1);
    assert_eq!(secure_delete_pragma(&store), 0);
}

#[test]
fn secure_prune_retry_after_reopen_recovers_committed_outcome() {
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

    let pending = store
        .secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        .expect("checkpoint contention is a committed result with pending erasure");

    assert_eq!(pending.pruned_messages, 1);
    assert_eq!(pending.media_ciphertext_sha256, vec![media_hash.clone()]);
    assert!(pending.erasure_pending);
    assert_eq!(
        store.app_message_count().unwrap(),
        0,
        "logical deletion commits before the checkpoint failure is surfaced"
    );
    reader.execute_batch("COMMIT").unwrap();
    drop(reader);
    drop(store);

    let store = SqliteAccountStorage::from_connection_with_options(
        rusqlite::Connection::open(&db_path).unwrap(),
        crate::SqliteStorageOptions {
            busy_timeout_ms: 1,
            ..crate::SqliteStorageOptions::default()
        },
    )
    .unwrap();
    let outcome = store
        .secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        .expect("retry after reopen must re-drive the durable pending checkpoint");
    assert_eq!(outcome.pruned_messages, 1);
    assert_eq!(outcome.media_ciphertext_sha256, vec![media_hash]);
    assert!(!outcome.erasure_pending);

    let empty = store
        .secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        .unwrap();
    assert_eq!(
        empty,
        crate::SecurePruneAppEventsResult::default(),
        "the committed result is consumed exactly once after checkpoint completion"
    );
}

#[test]
fn competing_storage_handles_consume_one_checkpoint_intent_once() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("competing-checkpoint.sqlite");
    let store_a = SqliteAccountStorage::from_connection_with_options(
        rusqlite::Connection::open(&db_path).unwrap(),
        SqliteStorageOptions::default(),
    )
    .unwrap();
    let store_b = SqliteAccountStorage::from_connection_with_options(
        rusqlite::Connection::open(&db_path).unwrap(),
        SqliteStorageOptions::default(),
    )
    .unwrap();
    let expected = crate::SecurePruneAppEventsResult {
        pruned_messages: 1,
        pruned_media_epoch_secrets: 0,
        media_ciphertext_sha256: vec!["ab".repeat(32)],
        erasure_pending: false,
    };
    {
        let conn = store_a.lock().unwrap();
        upsert_secure_delete_intent_tx(
            &conn,
            SECURE_DELETE_RETENTION_OPERATION,
            "aa",
            &serde_json::to_string(&expected).unwrap(),
        )
        .unwrap();
    }

    let a = std::thread::spawn(move || {
        finish_secure_delete_checkpoint_intent::<crate::SecurePruneAppEventsResult>(
            &store_a,
            SECURE_DELETE_RETENTION_OPERATION,
            "aa",
        )
        .unwrap()
    });
    let b = std::thread::spawn(move || {
        finish_secure_delete_checkpoint_intent::<crate::SecurePruneAppEventsResult>(
            &store_b,
            SECURE_DELETE_RETENTION_OPERATION,
            "aa",
        )
        .unwrap()
    });
    let outcomes = [a.join().unwrap().result, b.join().unwrap().result];
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_some()).count(),
        1,
        "exactly one competing finisher should consume the durable result"
    );
    assert!(
        outcomes
            .into_iter()
            .flatten()
            .all(|outcome| outcome == expected)
    );
}

#[test]
fn recreated_checkpoint_intent_cannot_be_deleted_by_a_stale_nonce() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let first_result = crate::SecurePruneAppEventsResult {
        pruned_messages: 1,
        ..crate::SecurePruneAppEventsResult::default()
    };
    let second_result = crate::SecurePruneAppEventsResult {
        pruned_messages: 2,
        ..crate::SecurePruneAppEventsResult::default()
    };
    let conn = store.lock().unwrap();
    upsert_secure_delete_intent_tx(
        &conn,
        SECURE_DELETE_RETENTION_OPERATION,
        "aa",
        &serde_json::to_string(&first_result).unwrap(),
    )
    .unwrap();
    let first = secure_delete_intent(&conn, SECURE_DELETE_RETENTION_OPERATION, "aa")
        .unwrap()
        .unwrap();
    conn.execute(
        "DELETE FROM secure_delete_checkpoint_intents
         WHERE operation_kind = ?1 AND scope = ?2",
        params![SECURE_DELETE_RETENTION_OPERATION, "aa"],
    )
    .unwrap();
    upsert_secure_delete_intent_tx(
        &conn,
        SECURE_DELETE_RETENTION_OPERATION,
        "aa",
        &serde_json::to_string(&second_result).unwrap(),
    )
    .unwrap();
    let second = secure_delete_intent(&conn, SECURE_DELETE_RETENTION_OPERATION, "aa")
        .unwrap()
        .unwrap();

    assert_eq!(first.nonce.len(), 16);
    assert_eq!(second.nonce.len(), 16);
    assert_ne!(first.nonce, second.nonce);
    assert_eq!(
        conn.execute(
            "DELETE FROM secure_delete_checkpoint_intents
             WHERE operation_kind = ?1 AND scope = ?2 AND intent_nonce = ?3",
            params![SECURE_DELETE_RETENTION_OPERATION, "aa", &first.nonce],
        )
        .unwrap(),
        0,
        "a stale finisher must not consume a recreated intent"
    );
    let remaining = secure_delete_intent(&conn, SECURE_DELETE_RETENTION_OPERATION, "aa")
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<crate::SecurePruneAppEventsResult>(&remaining.result_json).unwrap(),
        second_result
    );
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

    assert_eq!(
        store
            .prune_app_events_before("aa", 15, "local", &no_mentions)
            .unwrap(),
        1
    );

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

    assert_eq!(
        store
            .prune_app_events_before("aa", 15, "local", &no_mentions)
            .unwrap(),
        1
    );

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
        store
            .prune_app_events_before("aa", 2_000, "local", &no_mentions)
            .unwrap(),
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

    assert_eq!(
        store
            .prune_app_events_before("aa", 15, "local", &no_mentions)
            .unwrap(),
        1
    );

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

    assert_eq!(
        store
            .prune_app_events_before("aa", 15, "local", &no_mentions)
            .unwrap(),
        1
    );

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

    assert_eq!(
        store
            .prune_app_events_before("aa", 15, "local", &no_mentions)
            .unwrap(),
        1
    );

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
    // insertion order and `received_at` order. `wn messages list` filters
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
fn chat_notification_settings_track_timed_forever_and_cleared_mutes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![group("aa", "Muted")],
            },
            1,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();

    let default = store.chat_notification_settings_at("aa", 1000).unwrap();
    assert!(!default.muted);
    assert_eq!(default.muted_until_ms, Some(0));

    let timed = store.set_chat_muted("aa", Some(5000)).unwrap();
    assert_eq!(timed.muted_until_ms, Some(5000));
    let timed = store.chat_notification_settings_at("aa", 1000).unwrap();
    assert!(timed.muted);
    assert_eq!(timed.muted_until_ms, Some(5000));
    assert!(
        store
            .chat_notification_settings_at("aa", 4999)
            .unwrap()
            .muted
    );
    assert!(
        !store
            .chat_notification_settings_at("aa", 5000)
            .unwrap()
            .muted
    );

    let forever = store.set_chat_muted("aa", None).unwrap();
    assert!(forever.muted);
    assert_eq!(forever.muted_until_ms, None);
    assert!(
        store
            .chat_notification_settings_at("aa", i64::MAX)
            .unwrap()
            .muted
    );

    let cleared = store.clear_chat_muted("aa").unwrap();
    assert!(!cleared.muted);
    assert_eq!(cleared.muted_until_ms, Some(0));
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
    store
        .mark_push_registration_shared("alice", "first", 10, 11)
        .unwrap();
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
fn push_registration_tracks_partial_completion_per_group_and_requeues_on_refresh() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![group("aa", "alpha"), group("bb", "beta")],
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    let registration = AccountPushRegistration {
        account_label: "alice".to_owned(),
        account_id_hex: "11".repeat(32),
        platform: 1,
        token_fingerprint: "first".to_owned(),
        server_pubkey_hex: "22".repeat(32),
        relay_hint: None,
        created_at_ms: 10,
        updated_at_ms: 10,
        last_shared_at_ms: None,
    };

    store
        .upsert_push_registration(registration.clone(), vec![1, 2, 3])
        .unwrap();
    store
        .set_native_push_enabled("alice", &"11".repeat(32), true)
        .unwrap();
    assert_eq!(
        store.pending_push_registration_shares("first", 10).unwrap(),
        vec!["aa".to_owned(), "bb".to_owned()]
    );
    assert!(
        store
            .complete_push_registration_share("aa", "first", 10)
            .unwrap()
    );
    assert_eq!(
        store.pending_push_registration_shares("first", 10).unwrap(),
        vec!["bb".to_owned()]
    );
    store
        .mark_push_registration_shared("alice", "first", 10, 11)
        .unwrap();

    let mut refreshed = registration;
    refreshed.updated_at_ms = 10;
    let stored = store
        .upsert_push_registration(refreshed, vec![1, 2, 3])
        .unwrap();

    assert_eq!(stored.registration.last_shared_at_ms, None);
    assert_eq!(stored.registration.updated_at_ms, 11);
    assert_eq!(
        store.pending_push_registration_shares("first", 11).unwrap(),
        vec!["aa".to_owned(), "bb".to_owned()]
    );
    assert!(
        !store
            .complete_push_registration_share("aa", "first", 10)
            .unwrap()
    );
    assert!(
        store
            .complete_push_registration_share("aa", "first", 11)
            .unwrap()
    );
    assert!(
        store
            .complete_push_registration_share("bb", "first", 11)
            .unwrap()
    );
    assert!(
        store
            .mark_push_registration_shared("alice", "first", 11, 12)
            .unwrap()
    );
    store
        .set_native_push_enabled("alice", &"11".repeat(32), false)
        .unwrap();
    assert!(store.push_registration("alice").unwrap().is_none());
    assert!(
        store
            .pending_push_registration_shares("first", 11)
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.pending_push_registration_removals().unwrap().len(), 2);
    store
        .set_native_push_enabled("alice", &"11".repeat(32), true)
        .unwrap();
    assert!(store.push_registration("alice").unwrap().is_none());
    assert_eq!(store.pending_push_registration_removals().unwrap().len(), 2);
}

#[test]
fn push_registration_completion_is_version_guarded_and_membership_scoped() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![group("aa", "alpha"), group("bb", "beta")],
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    let mut registration = AccountPushRegistration {
        account_label: "alice".to_owned(),
        account_id_hex: "11".repeat(32),
        platform: 1,
        token_fingerprint: "first".to_owned(),
        server_pubkey_hex: "22".repeat(32),
        relay_hint: None,
        created_at_ms: 10,
        updated_at_ms: 10,
        last_shared_at_ms: None,
    };
    store
        .upsert_push_registration(registration.clone(), vec![1])
        .unwrap();
    store
        .set_group_self_membership("bb", SelfMembership::Left)
        .unwrap();
    assert_eq!(
        store.pending_push_registration_shares("first", 10).unwrap(),
        vec!["aa".to_owned()]
    );

    registration.token_fingerprint = "second".to_owned();
    registration.updated_at_ms = 20;
    store
        .upsert_push_registration(registration, vec![2])
        .unwrap();
    assert!(
        !store
            .complete_push_registration_share("aa", "first", 10)
            .unwrap()
    );
    assert_eq!(
        store
            .pending_push_registration_shares("second", 20)
            .unwrap(),
        vec!["aa".to_owned()]
    );

    store
        .set_group_self_membership("bb", SelfMembership::Member)
        .unwrap();
    assert_eq!(
        store
            .pending_push_registration_shares("second", 20)
            .unwrap(),
        vec!["aa".to_owned(), "bb".to_owned()]
    );
    store.clear_push_registration("alice").unwrap();
    assert!(
        store
            .pending_push_registration_shares("second", 20)
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.pending_push_registration_removals().unwrap().len(), 2);
}

#[test]
fn push_registration_rotation_and_clear_queue_durable_removals() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![group("aa", "alpha"), group("bb", "beta")],
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    let mut registration = AccountPushRegistration {
        account_label: "alice".to_owned(),
        account_id_hex: "11".repeat(32),
        platform: 1,
        token_fingerprint: "first".to_owned(),
        server_pubkey_hex: "22".repeat(32),
        relay_hint: None,
        created_at_ms: 10,
        updated_at_ms: 10,
        last_shared_at_ms: None,
    };
    store
        .upsert_push_registration(registration.clone(), vec![1])
        .unwrap();

    registration.token_fingerprint = "same-key-refresh".to_owned();
    registration.updated_at_ms = 11;
    store
        .upsert_push_registration(registration.clone(), vec![2])
        .unwrap();
    assert!(
        store
            .pending_push_registration_removals()
            .unwrap()
            .is_empty(),
        "same record key is replaced by its newer update"
    );

    registration.token_fingerprint = "new-server".to_owned();
    registration.server_pubkey_hex = "33".repeat(32);
    registration.updated_at_ms = 12;
    store
        .upsert_push_registration(registration.clone(), vec![3])
        .unwrap();
    let old_server_removals = store.pending_push_registration_removals().unwrap();
    assert_eq!(old_server_removals.len(), 2);
    assert!(
        old_server_removals
            .iter()
            .all(|pending| pending.registration.server_pubkey_hex == "22".repeat(32))
    );

    let cleared = store.clear_push_registration("alice").unwrap().unwrap();
    assert_eq!(cleared.registration.token_fingerprint, "new-server");
    assert!(store.push_registration("alice").unwrap().is_none());
    assert!(
        store
            .pending_push_registration_shares("new-server", 12)
            .unwrap()
            .is_empty()
    );
    let removals = store.pending_push_registration_removals().unwrap();
    assert_eq!(removals.len(), 4);

    let completed = removals[0].clone();
    store
        .mark_push_registration_removal_attempted(&completed, 20)
        .unwrap();
    assert!(
        store
            .complete_push_registration_removal(&completed)
            .unwrap()
    );
    assert!(
        !store
            .complete_push_registration_removal(&completed)
            .unwrap(),
        "completion is guarded by the exact queued revision"
    );
    assert_eq!(store.pending_push_registration_removals().unwrap().len(), 3);
}

#[test]
fn push_registration_removal_outbox_preserves_same_server_revisions() {
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
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    let mut registration = AccountPushRegistration {
        account_label: "alice".to_owned(),
        account_id_hex: "11".repeat(32),
        platform: 1,
        token_fingerprint: "token-a".to_owned(),
        server_pubkey_hex: "22".repeat(32),
        relay_hint: None,
        created_at_ms: 10,
        updated_at_ms: 10,
        last_shared_at_ms: None,
    };
    store
        .upsert_push_registration(registration.clone(), vec![1])
        .unwrap();
    store.clear_push_registration("alice").unwrap();

    registration.token_fingerprint = "token-b".to_owned();
    registration.created_at_ms = 20;
    registration.updated_at_ms = 20;
    store
        .upsert_push_registration(registration, vec![2])
        .unwrap();
    store.clear_push_registration("alice").unwrap();

    let removals = store.pending_push_registration_removals().unwrap();
    assert_eq!(removals.len(), 2);
    assert_eq!(
        removals
            .iter()
            .map(|pending| pending.registration.token_fingerprint.as_str())
            .collect::<Vec<_>>(),
        vec!["token-a", "token-b"]
    );
}

#[test]
fn local_group_delete_preserves_exact_prior_nostr_routes_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("local-delete-routes.sqlite");
    let key = SqlCipherKey::new("local delete route preservation key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut deleted_group = group("aa", "alpha");
    deleted_group.prior_nostr_routes = vec![StoredNostrRoute {
        nostr_group_id_hex: "11".repeat(32),
        relays: vec!["wss://old.example".to_owned()],
        last_epoch: 7,
    }];
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![deleted_group],
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    insert_protocol_group_marker(&store, &[0xaa]);

    assert!(store.delete_local_group_data("aa").unwrap().did_delete());
    drop(store);

    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(
        reopened
            .local_group_deletion_prior_nostr_routes("aa")
            .unwrap(),
        vec![StoredNostrRoute {
            nostr_group_id_hex: "11".repeat(32),
            relays: vec!["wss://old.example".to_owned()],
            last_epoch: 7,
        }]
    );
}

#[test]
fn retained_local_delete_routes_prune_ids_outside_the_engine_overlap_window() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut deleted_group = group("aa", "alpha");
    deleted_group.prior_nostr_routes = vec![
        StoredNostrRoute {
            nostr_group_id_hex: "11".repeat(32),
            relays: vec!["wss://retired.example".to_owned()],
            last_epoch: 1,
        },
        StoredNostrRoute {
            nostr_group_id_hex: "22".repeat(32),
            relays: vec!["wss://retained.example".to_owned()],
            last_epoch: 2,
        },
    ];
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![deleted_group],
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    insert_protocol_group_marker(&store, &[0xaa]);
    {
        let conn = store.lock().unwrap();
        for (route, epoch) in [([0x22_u8; 32], 2_i64), ([0x33_u8; 32], 3_i64)] {
            conn.execute(
                "INSERT INTO cgka_transport_group_routes (
                    transport_group_id, group_id, source_epoch
                 ) VALUES (?1, ?2, ?3)",
                rusqlite::params![route.as_slice(), &[0xaa_u8], epoch],
            )
            .unwrap();
        }
    }
    store.delete_local_group_data("aa").unwrap();

    store
        .retain_local_group_deletion_nostr_routes(
            "aa",
            &[StoredNostrRoute {
                nostr_group_id_hex: "33".repeat(32),
                relays: vec!["wss://current.example".to_owned()],
                last_epoch: 3,
            }],
        )
        .unwrap();

    assert_eq!(
        store.local_group_deletion_prior_nostr_routes("aa").unwrap(),
        vec![
            StoredNostrRoute {
                nostr_group_id_hex: "22".repeat(32),
                relays: vec!["wss://retained.example".to_owned()],
                last_epoch: 2,
            },
            StoredNostrRoute {
                nostr_group_id_hex: "33".repeat(32),
                relays: vec!["wss://current.example".to_owned()],
                last_epoch: 3,
            },
        ],
        "durable exact-route history must advance with the engine-owned overlap window",
    );
}

#[test]
fn failed_resurrection_projection_save_retains_local_deletion_frontier() {
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
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    insert_protocol_group_marker(&store, &[0xaa]);
    store.delete_local_group_data("aa").unwrap();
    let frontier = store.local_group_deletion_frontier("aa").unwrap().unwrap();
    let fresh_message_id = MessageId::new(vec![9]);
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
             VALUES (?1, ?2, 0, 4, ?3)",
            rusqlite::params![fresh_message_id.as_slice(), &[0xaa_u8], &[0_u8]],
        )
        .unwrap();
    let pending_event = GroupEvent::MessageReceived {
        group_id: cgka_traits::GroupId::new(vec![0xaa]),
        message_id: fresh_message_id.clone(),
        sender: MemberId::new(vec![7; 32]),
        epoch: EpochId(0),
        payload: b"fresh chat".to_vec(),
        retention: None,
    };
    store.put_pending_application_event(&pending_event).unwrap();
    store
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_resurrection_projection
             BEFORE INSERT ON account_groups
             BEGIN
                 SELECT RAISE(ABORT, 'injected projection failure');
             END;",
        )
        .unwrap();

    let result = store.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
        &StoredAccountState {
            label: "alice".to_owned(),
            seen_events: Vec::new(),
            last_transport_timestamp: None,
            groups: vec![group("aa", "resurrected")],
        },
        16,
        MAX_FUTURE_SKEW_SECS,
        &[("aa".to_owned(), frontier)],
        std::slice::from_ref(&fresh_message_id),
    );

    assert!(result.is_err());
    assert_eq!(
        store.local_group_deletion_frontier("aa").unwrap(),
        Some(frontier),
        "the marker clear must roll back when the crossing projection fails to persist",
    );
    assert!(
        store
            .load_account_projection_state("alice", 16)
            .unwrap()
            .groups
            .is_empty(),
        "a failed save must not expose a partially resurrected group",
    );
    assert_eq!(
        store.list_pending_application_events().unwrap(),
        vec![pending_event],
        "the durable delivery acknowledgement must roll back with the failed projection",
    );
}

#[test]
fn repeated_local_group_delete_advances_frontier_past_buffered_messages() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    insert_protocol_group_marker(&store, &[0xaa]);
    let first_message_id = MessageId::new(vec![1]);
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
             VALUES (?1, ?2, 0, 0, ?3)",
            rusqlite::params![first_message_id.as_slice(), &[0xaa_u8], &[0_u8]],
        )
        .unwrap();
    store.delete_local_group_data("aa").unwrap();
    let first_frontier = store.local_group_deletion_frontier("aa").unwrap().unwrap();

    let buffered_message_id = MessageId::new(vec![2]);
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
             VALUES (?1, ?2, 0, 0, ?3)",
            rusqlite::params![buffered_message_id.as_slice(), &[0xaa_u8], &[0_u8]],
        )
        .unwrap();
    store.delete_local_group_data("aa").unwrap();
    let repeated_frontier = store.local_group_deletion_frontier("aa").unwrap().unwrap();

    assert!(repeated_frontier > first_frontier);
    assert!(
        !store
            .clear_local_group_deletion_frontier_if_message_is_newer("aa", &buffered_message_id)
            .unwrap(),
        "a message buffered before the repeated delete must remain behind its frontier"
    );
    assert_eq!(
        store.local_group_deletion_frontier("aa").unwrap(),
        Some(repeated_frontier)
    );

    let fresh_message_id = MessageId::new(vec![3]);
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
             VALUES (?1, ?2, 0, 0, ?3)",
            rusqlite::params![fresh_message_id.as_slice(), &[0xaa_u8], &[0_u8]],
        )
        .unwrap();
    assert!(
        store
            .clear_local_group_deletion_frontier_if_message_is_newer("aa", &fresh_message_id)
            .unwrap(),
        "a message inserted after the repeated delete must cross the advanced frontier"
    );
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
    store
        .save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    let mut group_a_message = app_event("msg-aa", "aa", 10);
    group_a_message.source_epoch = Some(7);
    group_a_message.tags = vec![vec!["imeta".to_owned(), "v encrypted-media-v1".to_owned()]];
    store.record_app_event(&group_a_message).unwrap();
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
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO encrypted_media_epoch_secret_retirement_watermarks (
                 group_id_hex, retired_through_epoch, retired_at_unix_seconds
             ) VALUES ('aa', 6, 10)",
            [],
        )
        .unwrap();
    insert_group_push_token(&store, "aa", "member-aa");
    insert_group_push_token(&store, "bb", "member-bb");
    // Tombstones on a distinct leaf so they don't collide with the live rows
    // above; a local wipe must clear these too, or stale tombstones keep
    // rejecting relayed records after the group is re-bootstrapped.
    store
        .apply_group_push_token_tombstone("aa", "member-aa", 9, 1, &"cc".repeat(32), 500, "rd", 500)
        .unwrap();
    store
        .apply_group_push_token_tombstone("bb", "member-bb", 9, 1, &"cc".repeat(32), 500, "rd", 500)
        .unwrap();
    insert_read_and_chat_rows(&store, "aa");
    insert_protocol_group_marker(&store, &[0xaa]);
    let historical_message_id = MessageId::new(vec![1]);
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
             VALUES (?1, ?2, 0, 0, ?3)",
            rusqlite::params![historical_message_id.as_slice(), &[0xaa_u8], &[0_u8]],
        )
        .unwrap();
    let registration = AccountPushRegistration {
        account_label: "alice".to_owned(),
        account_id_hex: "11".repeat(32),
        platform: 1,
        token_fingerprint: "push".to_owned(),
        server_pubkey_hex: "22".repeat(32),
        relay_hint: None,
        created_at_ms: 10,
        updated_at_ms: 10,
        last_shared_at_ms: None,
    };
    store
        .upsert_push_registration(registration.clone(), vec![1])
        .unwrap();
    store
        .queue_push_registration_removals(&registration, 11)
        .unwrap();

    assert!(store.delete_local_group_data("aa").unwrap().did_delete());
    let deletion_frontier = store.local_group_deletion_frontier("aa").unwrap().unwrap();
    assert!(
        !store
            .clear_local_group_deletion_frontier_if_message_is_newer("aa", &historical_message_id,)
            .unwrap(),
        "historical replay already inside the deletion frontier must stay suppressed"
    );
    assert_eq!(
        store.local_group_deletion_frontier("aa").unwrap(),
        Some(deletion_frontier)
    );
    store
        .save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    let after_stale_save = store.load_account_projection_state("alice", 16).unwrap();
    assert!(
        after_stale_save
            .groups
            .iter()
            .all(|group| group.group_id_hex != "aa"),
        "a stale concurrent snapshot must not recreate a locally deleted projection"
    );
    assert!(
        after_stale_save
            .groups
            .iter()
            .any(|group| group.group_id_hex == "bb"),
        "unrelated groups must survive stale snapshot suppression"
    );
    assert_eq!(
        store.local_group_deletion_frontier("aa").unwrap(),
        Some(deletion_frontier)
    );
    let newer_message_id = MessageId::new(vec![2]);
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
             VALUES (?1, ?2, 0, 0, ?3)",
            rusqlite::params![newer_message_id.as_slice(), &[0xaa_u8], &[0_u8]],
        )
        .unwrap();
    assert!(
        store
            .clear_local_group_deletion_frontier_if_message_is_newer("aa", &newer_message_id,)
            .unwrap(),
        "causally newer group activity must clear the deletion frontier"
    );
    assert_eq!(store.local_group_deletion_frontier("aa").unwrap(), None);
    store
        .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[9, 9, 9])
        .unwrap();
    assert_eq!(
        store.encrypted_media_epoch_secret("aa", 0x8008, 7).unwrap(),
        None,
        "local group deletion must prevent retained MLS state from rehydrating wiped secrets"
    );

    for table in [
        "account_groups",
        "account_group_app_components",
        "app_events",
        "message_timeline",
        "agent_stream_starts",
        "conversation_read_state",
        "chat_list_rows",
        "group_push_tokens",
        "group_push_token_tombstones",
        "encrypted_media_epoch_secret_references",
        "pending_push_registration_shares",
        "encrypted_media_epoch_secrets",
    ] {
        assert_eq!(group_row_count(&store, table, "aa"), 0, "{table}");
    }
    assert_eq!(
        group_row_count(
            &store,
            "encrypted_media_epoch_secret_retirement_watermarks",
            "aa",
        ),
        1,
        "the retirement barrier outlives the local group projection"
    );
    assert_eq!(
        group_row_count(&store, "pending_push_registration_removals", "aa"),
        1,
        "removal intent must survive app-local projection deletion"
    );
    for table in [
        "account_groups",
        "account_group_app_components",
        "app_events",
        "message_timeline",
        "group_push_tokens",
        "group_push_token_tombstones",
        "pending_push_registration_shares",
        "pending_push_registration_removals",
        "encrypted_media_epoch_secrets",
    ] {
        assert!(group_row_count(&store, table, "bb") > 0, "{table}");
    }
    assert_eq!(all_row_count(&store, "seen_events"), 1);
    assert_eq!(all_row_count(&store, "cgka_groups"), 1);
    assert!(!store.delete_local_group_data("aa").unwrap().did_delete());
}

#[test]
fn delete_local_group_data_reopens_and_retries_a_committed_pending_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("local-wipe.sqlite");
    let store = SqliteAccountStorage::from_connection_with_options(
        rusqlite::Connection::open(&db_path).unwrap(),
        crate::SqliteStorageOptions {
            busy_timeout_ms: 1,
            secure_delete: false,
            ..crate::SqliteStorageOptions::default()
        },
    )
    .unwrap();
    let group_id_hex = "aa";
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![group(group_id_hex, "alpha")],
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    let secret = "local-wipe-plaintext-secret";
    let mut message = app_event("wipe-me", group_id_hex, 10);
    message.plaintext = secret.to_owned();
    store.record_app_event(&message).unwrap();
    {
        let conn = store.lock().unwrap();
        let (busy, _, _): (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        assert_eq!(busy, 0);
    }
    assert!(file_contains(&db_path, secret.as_bytes()));

    let reader = rusqlite::Connection::open(&db_path).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let _: i64 = reader
        .query_row("SELECT count(*) FROM app_events", [], |row| row.get(0))
        .unwrap();

    let pending = store
        .delete_local_group_data(group_id_hex)
        .expect("logical wipe commits while WAL erasure remains pending");
    assert!(pending.did_delete());
    assert!(pending.erasure_pending);
    assert!(!pending.completed_pending_checkpoint);
    assert_eq!(store.app_message_count().unwrap(), 0);
    assert_eq!(
        secure_delete_pragma(&store),
        0,
        "the caller's secure_delete setting must be restored after the committed wipe"
    );

    reader.execute_batch("COMMIT").unwrap();
    drop(reader);
    drop(store);
    let store = SqliteAccountStorage::from_connection_with_options(
        rusqlite::Connection::open(&db_path).unwrap(),
        crate::SqliteStorageOptions {
            busy_timeout_ms: 1,
            secure_delete: false,
            ..crate::SqliteStorageOptions::default()
        },
    )
    .unwrap();
    let completed = store
        .delete_local_group_data(group_id_hex)
        .expect("retry after reopen should finish the prior checkpoint");
    assert!(completed.did_delete());
    assert!(completed.completed_pending_checkpoint);
    assert!(!completed.erasure_pending);
    assert!(completed.deleted_rows > 0);
    drop(store);
    for path in [
        db_path.clone(),
        db_path.with_extension("sqlite-wal"),
        db_path.with_extension("sqlite-shm"),
    ] {
        if path.exists() {
            assert!(
                !file_contains(&path, secret.as_bytes()),
                "{} must not retain locally wiped plaintext",
                path.display()
            );
        }
    }
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
    store
        .save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
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

#[test]
fn record_app_event_retries_concurrent_writer_contention() {
    // Representative projection-writer regression: the other projection writers use the
    // same with_transaction retry path.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("projection-contention.sqlite");
    let key = SqlCipherKey::new("projection contention key").unwrap();
    let options = SqliteStorageOptions {
        busy_timeout_ms: 50,
        ..SqliteStorageOptions::default()
    };

    let writer = SqliteAccountStorage::open_encrypted_with_options(&path, &key, options.clone())
        .expect("writer storage opens");

    let blocker_path = path.clone();
    let blocker_options = options.clone();
    let blocker_key = SqlCipherKey::new("projection contention key").unwrap();
    let (lock_acquired_tx, lock_acquired_rx) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let blocker = SqliteAccountStorage::open_encrypted_with_options(
            &blocker_path,
            &blocker_key,
            blocker_options,
        )
        .expect("blocker storage opens");
        let conn = blocker.lock().unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        lock_acquired_tx
            .send(())
            .expect("signal BEGIN IMMEDIATE acquired");
        std::thread::sleep(std::time::Duration::from_millis(200));
        conn.execute_batch("COMMIT").unwrap();
    });

    lock_acquired_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("blocker should hold BEGIN IMMEDIATE before writer starts");

    writer
        .record_app_event(&app_event("contended", "aa", 10))
        .expect("projection writer should wait out transient sqlite write-lock contention");

    blocker.join().unwrap();
    assert_eq!(writer.app_message_count().unwrap(), 1);
}

fn push_token(
    group_id_hex: &str,
    member_id_hex: &str,
    owner_ts: i64,
    record_digest: &str,
) -> AccountGroupPushToken {
    AccountGroupPushToken {
        group_id_hex: group_id_hex.to_owned(),
        member_id_hex: member_id_hex.to_owned(),
        leaf_index: 0,
        platform: 1,
        token_fingerprint: "sha256:000000000000000000000000".to_owned(),
        server_pubkey_hex: "cc".repeat(32),
        relay_hint: None,
        encrypted_token: vec![1, 2, 3],
        owner_ts,
        owner_sig: "sig".to_owned(),
        record_digest: record_digest.to_owned(),
        updated_at_ms: owner_ts,
    }
}

#[test]
fn push_token_apply_retries_concurrent_writer_contention() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("push-token-contention.sqlite");
    let key = SqlCipherKey::new("push token contention key").unwrap();
    let options = SqliteStorageOptions {
        busy_timeout_ms: 50,
        ..SqliteStorageOptions::default()
    };
    let writer = SqliteAccountStorage::open_encrypted_with_options(&path, &key, options.clone())
        .expect("writer storage opens");
    let group_id = "aa".repeat(32);
    let member_id = "bb".repeat(32);

    let spawn_blocker = || {
        let blocker_path = path.clone();
        let blocker_options = options.clone();
        let blocker_key = SqlCipherKey::new("push token contention key").unwrap();
        let (lock_acquired_tx, lock_acquired_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let blocker = SqliteAccountStorage::open_encrypted_with_options(
                &blocker_path,
                &blocker_key,
                blocker_options,
            )
            .expect("blocker storage opens");
            let conn = blocker.lock().unwrap();
            conn.execute_batch("BEGIN IMMEDIATE").unwrap();
            lock_acquired_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
            conn.execute_batch("COMMIT").unwrap();
        });
        lock_acquired_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("blocker acquires write lock");
        handle
    };

    let blocker = spawn_blocker();
    assert!(
        writer
            .apply_group_push_token(&push_token(&group_id, &member_id, 100, "d1"))
            .expect("token apply retries after transient contention")
    );
    blocker.join().unwrap();

    let blocker = spawn_blocker();
    assert!(
        writer
            .apply_group_push_token_tombstone(
                &group_id,
                &member_id,
                0,
                1,
                &"cc".repeat(32),
                200,
                "r1",
                200,
            )
            .expect("tombstone apply retries after transient contention")
    );
    blocker.join().unwrap();
    assert!(writer.group_push_tokens(&group_id).unwrap().is_empty());
}

#[test]
fn apply_group_push_token_keeps_sibling_leaves_distinct() {
    // Two devices of one account (same member id, same platform+server, different
    // leaf index) must coexist: leaf_index is part of the record key, so neither
    // leaf's token overwrites the other's and a removal for one leaf does not
    // touch the sibling. Regression for the pre-migration 4-tuple key that
    // collapsed sibling devices (#628).
    let store = SqliteAccountStorage::in_memory().unwrap();
    let g = "aa".repeat(32);
    let m = "bb".repeat(32);
    let leaf = |leaf_index: u32, owner_ts: i64, digest: &str| AccountGroupPushToken {
        leaf_index,
        ..push_token(&g, &m, owner_ts, digest)
    };

    assert!(store.apply_group_push_token(&leaf(1, 100, "d1")).unwrap());
    assert!(store.apply_group_push_token(&leaf(2, 100, "d2")).unwrap());
    assert_eq!(
        store.group_push_tokens(&g).unwrap().len(),
        2,
        "both sibling leaves are stored side by side"
    );

    // A removal targeting leaf 1 must leave leaf 2's record intact.
    assert!(
        store
            .apply_group_push_token_tombstone(&g, &m, 1, 1, &"cc".repeat(32), 200, "r1", 200)
            .unwrap()
    );
    let stored = store.group_push_tokens(&g).unwrap();
    assert_eq!(stored.len(), 1, "only the targeted leaf is removed");
    assert_eq!(stored[0].leaf_index, 2);
}

#[test]
fn apply_group_push_token_rejects_stale_stamp_rollback() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let g = "aa".repeat(32);
    let m = "bb".repeat(32);
    assert!(
        store
            .apply_group_push_token(&push_token(&g, &m, 100, "d2"))
            .unwrap()
    );
    // Lower owner_ts loses (rollback attempt).
    assert!(
        !store
            .apply_group_push_token(&push_token(&g, &m, 50, "d9"))
            .unwrap()
    );
    // Equal owner_ts, lower digest loses (tie-break).
    assert!(
        !store
            .apply_group_push_token(&push_token(&g, &m, 100, "d1"))
            .unwrap()
    );
    // Equal owner_ts, higher digest wins.
    assert!(
        store
            .apply_group_push_token(&push_token(&g, &m, 100, "d3"))
            .unwrap()
    );
    // Strictly greater owner_ts wins.
    assert!(
        store
            .apply_group_push_token(&push_token(&g, &m, 101, "d0"))
            .unwrap()
    );
    let stored = store.group_push_tokens(&g).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].owner_ts, 101);
}

#[test]
fn removal_tombstone_blocks_stale_resurrection_until_fresh_record() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let g = "aa".repeat(32);
    let m = "bb".repeat(32);
    assert!(
        store
            .apply_group_push_token(&push_token(&g, &m, 100, "d1"))
            .unwrap()
    );
    // Removal at a higher stamp tombstones the key and clears the live row.
    assert!(
        store
            .apply_group_push_token_tombstone(&g, &m, 0, 1, &"cc".repeat(32), 200, "r2", 200)
            .unwrap()
    );
    assert!(store.group_push_tokens(&g).unwrap().is_empty());
    // A stale (lower-stamped) record relayed in a later kind 448 cannot resurrect.
    assert!(
        !store
            .apply_group_push_token(&push_token(&g, &m, 150, "d5"))
            .unwrap()
    );
    assert!(store.group_push_tokens(&g).unwrap().is_empty());
    // A strictly-greater record clears the tombstone and re-establishes the key.
    assert!(
        store
            .apply_group_push_token(&push_token(&g, &m, 250, "d7"))
            .unwrap()
    );
    let stored = store.group_push_tokens(&g).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].owner_ts, 250);
}

#[test]
fn member_cleanup_clears_tokens_and_tombstones() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let g = "aa".repeat(32);
    let m = "bb".repeat(32);
    store
        .apply_group_push_token_tombstone(&g, &m, 0, 1, &"cc".repeat(32), 200, "r2", 200)
        .unwrap();
    // Departed member: both the (empty) live set and the durable tombstone go.
    store.remove_group_push_tokens_for_member(&g, &m).unwrap();
    // With the tombstone gone, an old record could apply again — which is safe
    // because the member is no longer in the group and verify_push_gossip would
    // drop it upstream. Here we just confirm the tombstone no longer blocks.
    assert!(
        store
            .apply_group_push_token(&push_token(&g, &m, 10, "d1"))
            .unwrap()
    );
}

#[test]
fn stale_push_token_cleanup_chunks_stale_keys_and_does_not_bind_retained_members() {
    const ACTIVE_COUNT: usize = SQLITE_BIND_PARAMETER_CHUNK + 105;
    const STALE_COUNT: usize = SQLITE_BIND_PARAMETER_CHUNK + 1;

    let store = SqliteAccountStorage::in_memory().unwrap();
    let group_id = "aa".repeat(32);
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
        let mut token = conn
            .prepare(
                "INSERT INTO group_push_tokens (
                    group_id_hex, member_id_hex, leaf_index, platform,
                    token_fingerprint, server_pubkey_hex, relay_hint,
                    encrypted_token, owner_ts, owner_sig, record_digest,
                    updated_at_ms
                 ) VALUES (?1, ?2, 0, 1, 'token', ?3, NULL, x'01', 1, 'sig', 'digest', 1)",
            )
            .unwrap();
        let mut tombstone = conn
            .prepare(
                "INSERT INTO group_push_token_tombstones (
                    group_id_hex, member_id_hex, leaf_index, platform,
                    server_pubkey_hex, owner_ts, record_digest, created_at_ms
                 ) VALUES (?1, ?2, 0, 1, ?3, 1, 'digest', 1)",
            )
            .unwrap();
        for index in 0..(ACTIVE_COUNT + STALE_COUNT) {
            let member_id = format!("member-{index:04}");
            let server_key = "cc".repeat(32);
            token
                .execute(params![&group_id, &member_id, &server_key])
                .unwrap();
            tombstone
                .execute(params![&group_id, &member_id, &server_key])
                .unwrap();
        }
    }
    let active_members = (0..ACTIVE_COUNT)
        .map(|index| format!("member-{index:04}"))
        .collect::<Vec<_>>();

    assert_eq!(
        store
            .remove_stale_group_push_tokens(&group_id, &active_members)
            .expect("retained members must not become an unbounded NOT IN bind set"),
        STALE_COUNT
    );
    let conn = store.lock().unwrap();
    for table in ["group_push_tokens", "group_push_token_tombstones"] {
        let remaining: i64 = conn
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE group_id_hex = ?1"),
                params![&group_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, ACTIVE_COUNT as i64, "{table}");
    }
}

fn insert_group_push_token(store: &SqliteAccountStorage, group_id_hex: &str, member_id_hex: &str) {
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO group_push_tokens (\n                group_id_hex, member_id_hex, leaf_index, platform, token_fingerprint,\n                server_pubkey_hex, relay_hint, encrypted_token, owner_ts, owner_sig,\n                record_digest, updated_at_ms\n             ) VALUES (?1, ?2, 0, 1, 'token', ?3, NULL, x'0102', 123, 'sig', 'digest', 123)",
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

#[test]
fn app_messages_replay_order_matches_cursor_comparator() {
    // #630/#736 boundary contract 1: the raw-event replay query order
    // (`app_messages`) MUST equal the `AppEventReplayCursor` Rust comparator, so
    // the recovery watermark/suppression and the recovery query can never drift.
    // Covers the unscoped (all-groups) case where two groups share the same
    // `(recorded_at, message_id_hex)` and only the local `insert_order`
    // distinguishes them.
    let store = SqliteAccountStorage::in_memory().unwrap();
    // Same second, ids inserted in NON-lexical order; plus a cross-group
    // duplicate id at the same second; plus a later-second row.
    store.record_app_event(&app_event("bbb", "aa", 50)).unwrap(); // insert_order 1
    store.record_app_event(&app_event("aaa", "aa", 50)).unwrap(); // insert_order 2 (smaller id, later insert)
    // The two `dup` rows share `message_id_hex` (allowed: the app_events UNIQUE is
    // per-(group, message_id)) but carry distinct globally-unique
    // `source_message_id_hex` (distinct outer transport events), mirroring a
    // sender posting identical content to two groups in the same second.
    let mut dup_aa = app_event("dup", "aa", 50);
    dup_aa.source_message_id_hex = Some("source-dup-aa".to_owned());
    let mut dup_bb = app_event("dup", "bb", 50);
    dup_bb.source_message_id_hex = Some("source-dup-bb".to_owned());
    store.record_app_event(&dup_aa).unwrap(); // insert_order 3
    store.record_app_event(&dup_bb).unwrap(); // insert_order 4 (same id, other group)
    store.record_app_event(&app_event("zzz", "aa", 60)).unwrap(); // insert_order 5 (later second)

    let rows = store
        .app_messages(StoredAppMessageQuery {
            group_id_hex: None,
            limit: None,
        })
        .unwrap();

    // The SQL ORDER BY must equal sorting the same rows by the cursor comparator.
    let mut by_cursor = rows.clone();
    by_cursor.sort_by_key(|r| r.replay_cursor());
    let key = |r: &StoredAppMessageRecord| (r.message_id_hex.clone(), r.group_id_hex.clone());
    assert_eq!(
        rows.iter().map(key).collect::<Vec<_>>(),
        by_cursor.iter().map(key).collect::<Vec<_>>(),
        "app_messages SQL order must equal the AppEventReplayCursor comparator"
    );

    // Concrete order: same-second by id (aaa<bbb<dup), the two `dup` rows by
    // insert_order (group aa inserted before bb), then the later second.
    assert_eq!(
        rows.iter()
            .map(|r| r.message_id_hex.as_str())
            .collect::<Vec<_>>(),
        vec!["aaa", "bbb", "dup", "dup", "zzz"],
    );
    let dups: Vec<_> = rows.iter().filter(|r| r.message_id_hex == "dup").collect();
    assert_eq!(dups.len(), 2);
    assert!(
        dups[0].insert_order < dups[1].insert_order,
        "cross-group same-id rows are ordered by the local insert_order tiebreak"
    );
    assert_eq!(dups[0].group_id_hex, "aa");
    assert_eq!(dups[1].group_id_hex, "bb");
}

#[test]
fn stored_account_group_component_debug_redacts_blossom_image_payload() {
    use cgka_traits::app_components::GROUP_BLOSSOM_IMAGE_COMPONENT_ID;

    const IMAGE_KEY_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const UPLOAD_KEY_HEX: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let component = StoredAccountGroupComponent {
        component_id: GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
        component_name: "marmot.group.blossom.image.v1".to_owned(),
        component_data_hex: format!("00{IMAGE_KEY_HEX}{UPLOAD_KEY_HEX}"),
    };

    let rendered = format!("{component:?}");
    assert!(!rendered.contains(IMAGE_KEY_HEX));
    assert!(!rendered.contains(UPLOAD_KEY_HEX));
    assert!(rendered.contains("marmot.group.blossom.image.v1"));
    assert!(rendered.contains("redacted"));
}
