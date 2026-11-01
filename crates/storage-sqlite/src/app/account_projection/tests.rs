use super::*;
#[cfg(test)]
use crate::SqliteAccountStorage;
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

/// Asserts that `result` failed with an error whose text contains `expected`,
/// so a rollback or guard test cannot pass on an unrelated failure.
#[track_caller]
fn assert_fails_with<T: std::fmt::Debug, E: std::fmt::Display>(
    result: Result<T, E>,
    expected: &str,
) {
    let error = result.expect_err("the operation must fail");
    assert!(
        error.to_string().contains(expected),
        "expected an error containing {expected:?}, got: {error}"
    );
}

#[test]
fn keyed_group_read_is_bounded() {
    use crate::base::query_work_test_support::measure;
    use rusqlite::trace::{TraceEvent, TraceEventCodes};

    thread_local! {
        static READS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let statements = || {
        store.lock().unwrap().trace_v2(
            TraceEventCodes::SQLITE_TRACE_STMT,
            Some(|event| {
                if let TraceEvent::Stmt(statement, _) = event {
                    READS.with_borrow_mut(|reads| reads.push(statement.sql().into_owned()));
                }
            }),
        );
        app.account_groups(Some("aa")).unwrap();
        store
            .lock()
            .unwrap()
            .trace_v2(TraceEventCodes::empty(), None);
        READS.with_borrow_mut(std::mem::take)
    };
    let mut target = group("aa", "");
    target.archived = true;
    target.pending_confirmation = true;
    target.member_count = Some(2);
    target.direct_member_ids_hex = Some(vec!["11".repeat(32), "22".repeat(32)]);
    target.presentation_member_ids_hex = target.direct_member_ids_hex.clone();
    app.save_account_projection_state(
        &StoredAccountState {
            label: "alice".into(),
            groups: vec![target],
            ..Default::default()
        },
        16_384,
        MAX_FUTURE_SKEW_SECS,
    )
    .unwrap();
    app.set_group_self_membership("aa", SelfMembership::Removed)
        .unwrap();
    let (expected, full_before_steps) = measure(&store, || {
        app.load_account_projection_state("alice", 16_384)
            .unwrap()
            .groups
    });
    let (first, first_steps) = measure(&store, || app.account_groups(Some("aa")).unwrap());
    assert_eq!(first, expected);
    let first_statements = statements();
    assert_eq!(first_statements.len(), 4);
    assert!(
        first_statements
            .iter()
            .all(|sql| { sql.contains("WHERE group_id_hex = ?1") && !sql.contains("seen_events") })
    );

    store
        .lock()
        .unwrap()
        .execute_batch(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<16384)
         INSERT INTO seen_events(event_id, seen_at) SELECT printf('%064x',x),x FROM n;
         WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<500)
         INSERT INTO account_groups(group_id_hex,endpoint,updated_at)
         SELECT printf('%032x',x),'',x FROM n;
         INSERT INTO account_group_app_components
             (group_id_hex,component_id,component_name,component_data_hex,updated_at)
         SELECT group_id_hex,1,'unrelated','00',0 FROM account_groups WHERE group_id_hex<>'aa';
         INSERT INTO direct_conversation_members(group_id_hex,member_id_hex)
         SELECT group_id_hex,'unrelated' FROM account_groups WHERE group_id_hex<>'aa';
         INSERT INTO chat_presentation_members(group_id_hex,member_id_hex)
         SELECT group_id_hex,'unrelated' FROM account_groups WHERE group_id_hex<>'aa';",
        )
        .unwrap();
    let (second, second_steps) = measure(&store, || app.account_groups(Some("aa")).unwrap());
    assert_eq!(second, expected);
    assert_eq!(first_steps, second_steps);
    assert_eq!(first_statements, statements());
    let (full, full_after_steps) = measure(&store, || {
        app.load_account_projection_state("alice", 16_384)
            .unwrap()
            .groups
    });
    eprintln!(
        "group projection VM steps: full={full_before_steps}->{full_after_steps}, keyed={first_steps}->{second_steps}"
    );
    assert_eq!(app.account_groups(None).unwrap(), full);
    // Neither keyed nor list reads require the transport's seen-event table.
    store
        .lock()
        .unwrap()
        .execute_batch("DROP TABLE seen_events")
        .unwrap();
    assert_eq!(app.account_groups(Some("aa")).unwrap(), expected);
    assert_eq!(app.account_groups(None).unwrap().len(), 501);
    assert!(app.account_groups(Some("missing")).unwrap().is_empty());
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
fn account_delivery_recovery_marker_survives_reopen_and_clears_explicitly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delivery-recovery.sqlite");
    let key = SqlCipherKey::raw([0x11; 32]);

    {
        let store = SqliteAccountStorage::open_encrypted(&path, &key)
            .unwrap()
            .app_storage();
        store.ensure_account_projection("alice").unwrap();
        assert_eq!(store.account_delivery_recovery("alice").unwrap(), None);
        store
            .mark_account_delivery_recovery("alice", 11, 3)
            .unwrap();
        let first = store
            .account_delivery_recovery("alice")
            .unwrap()
            .expect("overflow must create a durable marker");
        assert_eq!(first.marker_token, 11);
        assert_eq!(first.dropped_count, 3);

        store
            .mark_account_delivery_recovery("alice", 11, 7)
            .unwrap();
        let updated = store.account_delivery_recovery("alice").unwrap().unwrap();
        assert_eq!(updated.pending_since, first.pending_since);
        assert_eq!(updated.dropped_count, 7);

        store
            .mark_account_delivery_recovery("alice", 12, 1)
            .unwrap();
        let replaced = store.account_delivery_recovery("alice").unwrap().unwrap();
        assert_eq!(replaced.marker_token, 12);
        assert_eq!(replaced.dropped_count, 1);
        assert_ne!(replaced.pending_since, 0);
        assert!(!store.clear_account_delivery_recovery("alice", 11).unwrap());

        // Restore the original token so the reopen half below still exercises
        // its explicit compare-and-clear assertions.
        store
            .mark_account_delivery_recovery("alice", 11, 7)
            .unwrap();
    }

    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(
        reopened
            .app_storage()
            .account_delivery_recovery("alice")
            .unwrap()
            .unwrap()
            .dropped_count,
        7,
        "restart must retain incomplete recovery"
    );
    assert!(
        !reopened
            .app_storage()
            .clear_account_delivery_recovery("alice", 10)
            .unwrap()
    );
    // Token 12 is independent loss, even after the worker re-adopts token 11.
    // Retiring 11 must leave both durable debt and the caller's pending flag set.
    assert!(
        !reopened
            .app_storage()
            .clear_account_delivery_recovery("alice", 11)
            .unwrap()
    );
    let remaining = reopened
        .app_storage()
        .account_delivery_recovery("alice")
        .unwrap()
        .unwrap();
    assert_eq!((remaining.marker_token, remaining.dropped_count), (12, 1));
    drop(reopened);

    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    reopened
        .app_storage()
        .synchronize_account_delivery_loss("alice")
        .unwrap();
    assert_eq!(
        reopened
            .app_storage()
            .account_delivery_recovery("alice")
            .unwrap(),
        Some(remaining)
    );
    assert!(
        !reopened
            .app_storage()
            .clear_account_delivery_recovery("alice", 11)
            .unwrap()
    );
    assert_eq!(
        reopened
            .app_storage()
            .account_delivery_recovery("alice")
            .unwrap(),
        Some(remaining)
    );
    assert!(
        reopened
            .app_storage()
            .clear_account_delivery_recovery("alice", 12)
            .unwrap()
    );
    assert_eq!(
        reopened
            .app_storage()
            .account_delivery_recovery("alice")
            .unwrap(),
        None
    );
    drop(reopened);

    // Completed retirement survives reopen, and duplicate evidence from either
    // retired writer cannot resurrect it. Additional loss must still rearm.
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    reopened
        .app_storage()
        .record_account_delivery_loss("alice", 11, 7, 1)
        .unwrap();
    reopened
        .app_storage()
        .record_account_delivery_loss("alice", 12, 1, 1)
        .unwrap();
    reopened
        .app_storage()
        .synchronize_account_delivery_loss("alice")
        .unwrap();
    assert_eq!(
        reopened
            .app_storage()
            .account_delivery_recovery("alice")
            .unwrap(),
        None
    );
    reopened
        .app_storage()
        .record_account_delivery_loss("alice", 12, 2, 2)
        .unwrap();
    reopened
        .app_storage()
        .synchronize_account_delivery_loss("alice")
        .unwrap();
    let additional = reopened
        .app_storage()
        .account_delivery_recovery("alice")
        .unwrap()
        .unwrap();
    assert_eq!((additional.marker_token, additional.dropped_count), (12, 2));
    drop(reopened);

    let reopened = SqliteAccountStorage::open_encrypted(&path, &key)
        .unwrap()
        .app_storage();
    reopened.synchronize_account_delivery_loss("alice").unwrap();
    assert_eq!(
        reopened.account_delivery_recovery("alice").unwrap(),
        Some(additional)
    );
    assert!(
        !reopened
            .clear_account_delivery_recovery("alice", 11)
            .unwrap()
    );
    assert!(
        reopened
            .clear_account_delivery_recovery("alice", 12)
            .unwrap()
    );
    assert_eq!(reopened.account_delivery_recovery("alice").unwrap(), None);
}

#[test]
fn source_epoch_retention_decisions_are_frozen_and_drive_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("retention.sqlite");
    let key = SqlCipherKey::raw([0x12; 32]);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();

    let mut due = app_event("due", "aa", 10);
    due.source_epoch = Some(4);
    store
        .app_storage()
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
        .app_storage()
        .record_app_event_with_retention(
            &duplicate,
            Some(AppMessageRetentionDecision::new(duplicate.recorded_at, 500)),
        )
        .unwrap();

    let later = app_event("later", "aa", 12);
    store
        .app_storage()
        .record_app_event_with_retention(
            &later,
            Some(AppMessageRetentionDecision::new(later.recorded_at, 4)),
        )
        .unwrap();
    let disabled = app_event("disabled", "aa", 1);
    store
        .app_storage()
        .record_app_event_with_retention(
            &disabled,
            Some(AppMessageRetentionDecision::new(disabled.recorded_at, 0)),
        )
        .unwrap();
    let overflow = app_event("overflow", "aa", 1);
    store
        .app_storage()
        .record_app_event_with_retention(
            &overflow,
            Some(AppMessageRetentionDecision::new(u64::MAX, 1)),
        )
        .unwrap();
    store
        .app_storage()
        .record_app_event(&app_event("legacy", "aa", 1))
        .unwrap();
    store
        .app_storage()
        .record_app_event_with_retention(
            &app_event("other-group", "bb", 1),
            Some(AppMessageRetentionDecision::new(1, 1)),
        )
        .unwrap();

    drop(store);
    let store = SqliteAccountStorage::open_encrypted(&path, &key)
        .unwrap()
        .app_storage();
    let records = store
        .app_messages(StoredAppMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            kinds: None,
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
            kinds: None,
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
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
            kinds: None,
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
        direct_member_ids_hex: None,
        presentation_member_ids_hex: None,
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
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    // Every persisted field holds a value other than its default and whole
    // groups are compared, so a column dropped from the save or the load fails.
    let mut named = group("aa", "alpha");
    named.profile_description = "a description".to_owned();
    named.image_hash_hex = "01".repeat(32);
    named.image_key_hex = "02".repeat(32);
    named.image_nonce_hex = "03".repeat(12);
    named.image_upload_key_hex = "04".repeat(32);
    named.image_media_type = Some("image/png".to_owned());
    named.admin_keys_hex = "05".repeat(32);
    named.archived = true;
    named.pending_confirmation = true;
    named.member_count = Some(2);
    named.presentation_member_ids_hex = Some(vec!["11".repeat(32), "22".repeat(32)]);
    named.welcomer_account_id_hex = Some("33".repeat(32));
    named.via_welcome_message_id_hex = Some("44".repeat(32));
    named.nostr_routing_last_epoch = 8;
    named.prior_nostr_routes = vec![StoredNostrRoute {
        nostr_group_id_hex: "11".repeat(32),
        relays: vec!["wss://prior.example".to_owned()],
        last_epoch: 7,
        replaced_at: Some(1_700_000_000),
    }];
    // The peer index is kept only for a Direct conversation: no name and
    // exactly two member accounts.
    let mut direct = group("bb", "");
    direct.member_count = Some(2);
    direct.direct_member_ids_hex = Some(vec!["11".repeat(32), "66".repeat(32)]);
    let state = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: vec!["old".to_owned(), "kept".to_owned()],
        last_transport_timestamp: Some(1_700_000_001),
        groups: vec![named, direct],
    };

    store
        .save_account_projection_state(&state, 1, MAX_FUTURE_SKEW_SECS)
        .unwrap();

    let restored = store.load_account_projection_state("alice", 16).unwrap();
    assert_eq!(restored.seen_events, vec!["kept"]);
    assert_eq!(restored.last_transport_timestamp, Some(1_700_000_001));
    // The save never writes `self_membership` (`set_group_self_membership`
    // owns it), so both groups keep the `Member` they were given.
    assert_eq!(restored.groups, state.groups);
}

#[test]
fn epoch_stall_evidence_round_trips_and_replaces_in_place() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    insert_protocol_group_marker(&store, &[0xaa]);
    let group = "aa".to_owned();
    let first = StoredEpochStallEvidence {
        group_id_hex: group.clone(),
        stalled_epoch: 7,
        fruitless_completions: 1,
        fruitless_reported: false,
        last_arm_at_ms: 1_700_000_000_000,
    };
    app.record_epoch_stall_evidence(std::slice::from_ref(&first))
        .unwrap();
    assert_eq!(app.epoch_stall_evidence().unwrap(), vec![first.clone()]);

    // The in-memory detector is the single writer and owns the reset rules, so
    // a later row replaces the earlier one outright rather than merging.
    let later = StoredEpochStallEvidence {
        stalled_epoch: 8,
        fruitless_completions: 3,
        fruitless_reported: true,
        last_arm_at_ms: 1_700_000_600_000,
        ..first
    };
    app.record_epoch_stall_evidence(std::slice::from_ref(&later))
        .unwrap();
    assert_eq!(app.epoch_stall_evidence().unwrap(), vec![later]);
}

#[test]
fn epoch_backfill_intents_rearm_and_clear_only_the_completed_epoch() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    insert_protocol_group_marker(&store, &[0xaa]);
    insert_protocol_group_marker(&store, &[0xbb]);

    let sorted = |mut intents: Vec<StoredEpochBackfillIntent>| {
        intents.sort_by(|left, right| left.group_id_hex.cmp(&right.group_id_hex));
        intents
    };

    let aa_epoch_7 = StoredEpochBackfillIntent {
        group_id_hex: "aa".to_owned(),
        stalled_epoch: 7,
    };
    let aa_epoch_8 = StoredEpochBackfillIntent {
        group_id_hex: "aa".to_owned(),
        stalled_epoch: 8,
    };
    let bb_epoch_3 = StoredEpochBackfillIntent {
        group_id_hex: "bb".to_owned(),
        stalled_epoch: 3,
    };
    store
        .app_storage()
        .arm_epoch_backfill_intents(&[aa_epoch_8.clone(), bb_epoch_3.clone()])
        .unwrap();
    store
        .app_storage()
        .arm_epoch_backfill_intents(std::slice::from_ref(&aa_epoch_7))
        .unwrap();
    assert_eq!(
        sorted(
            store
                .app_storage()
                .pending_epoch_backfill_intents()
                .unwrap()
        ),
        vec![aa_epoch_8.clone(), bb_epoch_3.clone()],
        "an older concurrent arm must not regress the durable epoch, even without app projection rows"
    );

    store
        .app_storage()
        .clear_epoch_backfill_intents(&[aa_epoch_7, bb_epoch_3])
        .unwrap();
    assert_eq!(
        sorted(
            store
                .app_storage()
                .pending_epoch_backfill_intents()
                .unwrap()
        ),
        vec![aa_epoch_8.clone()],
        "completion clears exact epochs and preserves newer recovery evidence"
    );

    store
        .lock()
        .unwrap()
        .execute("DELETE FROM cgka_groups WHERE id = ?1", params![&[0xaa_u8]])
        .unwrap();
    assert!(
        store
            .app_storage()
            .pending_epoch_backfill_intents()
            .unwrap()
            .is_empty(),
        "deleting the owning protocol group must consume its recovery intent"
    );
}

#[test]
fn epoch_backfill_intents_clear_by_group_at_whatever_epoch_is_stored() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    insert_protocol_group_marker(&store, &[0xaa]);
    insert_protocol_group_marker(&store, &[0xbb]);

    let aa_epoch_8 = StoredEpochBackfillIntent {
        group_id_hex: "aa".to_owned(),
        stalled_epoch: 8,
    };
    let bb_epoch_3 = StoredEpochBackfillIntent {
        group_id_hex: "bb".to_owned(),
        stalled_epoch: 3,
    };
    app.arm_epoch_backfill_intents(&[aa_epoch_8, bb_epoch_3.clone()])
        .unwrap();

    app.clear_epoch_backfill_intents_for_groups(&["aa".to_owned()])
        .unwrap();
    assert_eq!(
        app.pending_epoch_backfill_intents().unwrap(),
        vec![bb_epoch_3.clone()],
        "clearing by group retires that group and leaves every other group armed"
    );

    // The stored epoch is not part of the key: re-arm at a different epoch and
    // the same by-group clear still retires it.
    app.arm_epoch_backfill_intents(&[StoredEpochBackfillIntent {
        group_id_hex: "aa".to_owned(),
        stalled_epoch: 41,
    }])
    .unwrap();
    app.clear_epoch_backfill_intents_for_groups(&["aa".to_owned()])
        .unwrap();
    assert_eq!(
        app.pending_epoch_backfill_intents().unwrap(),
        vec![bb_epoch_3.clone()],
        "a by-group clear is not epoch-sensitive"
    );

    app.clear_epoch_backfill_intents_for_groups(&[]).unwrap();
    assert_eq!(
        app.pending_epoch_backfill_intents().unwrap(),
        vec![bb_epoch_3],
        "an empty slice clears nothing"
    );
}

#[test]
fn pending_confirmation_group_invites_reads_only_pending_outlines() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    // One applied member group, one pending invite with a welcomer, one
    // pending invite without a welcomer, and one pending-but-archived group.
    // Seen events and component rows are present so the outline result proves
    // the query never fans out into them (mdk#1380).
    let member = group("member-group", "member group");
    let mut invited = group("invited-group", "invited group");
    invited.pending_confirmation = true;
    invited.welcomer_account_id_hex = Some("cc".repeat(32));
    let mut unframed = group("unframed-invite", "unframed invite");
    unframed.pending_confirmation = true;
    let mut archived = group("archived-invite", "archived invite");
    archived.pending_confirmation = true;
    archived.archived = true;

    let state = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: vec!["seen-a".to_owned(), "seen-b".to_owned()],
        last_transport_timestamp: None,
        groups: vec![member, invited, unframed, archived],
    };
    store
        .save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();

    let invites = store.pending_confirmation_group_invites().unwrap();
    assert_eq!(
        invites,
        vec![
            StoredPendingGroupInvite {
                group_id_hex: "invited-group".to_owned(),
                welcomer_account_id_hex: Some("cc".repeat(32)),
            },
            StoredPendingGroupInvite {
                group_id_hex: "unframed-invite".to_owned(),
                welcomer_account_id_hex: None,
            },
        ]
    );

    // A once-pending group that got applied drops out of the outline set on
    // the next reconciliation. (Full projection saves replace the snapshot,
    // so resave the whole set.)
    let member = group("member-group", "member group");
    let mut invited = group("invited-group", "invited group");
    invited.pending_confirmation = true;
    invited.welcomer_account_id_hex = Some("cc".repeat(32));
    let mut applied = group("unframed-invite", "unframed invite");
    applied.pending_confirmation = false;
    let mut archived = group("archived-invite", "archived invite");
    archived.pending_confirmation = true;
    archived.archived = true;
    let state = StoredAccountState {
        groups: vec![member, invited, applied, archived],
        ..state
    };
    store
        .save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    let invites = store.pending_confirmation_group_invites().unwrap();
    assert_eq!(
        invites,
        vec![StoredPendingGroupInvite {
            group_id_hex: "invited-group".to_owned(),
            welcomer_account_id_hex: Some("cc".repeat(32)),
        }]
    );
}

#[test]
fn pending_confirmation_group_invites_uses_the_partial_covering_index() {
    // mdk#1380 review: the invite-policy predicate must not scan retained
    // group state. The partial covering index keeps examined rows at
    // O(pending invites); pin the query plan so a regression that drops the
    // index (or rewrites the query out of it) fails deterministically. The plan
    // is of the statement the read runs, captured from SQLite's trace.
    use rusqlite::trace::{TraceEvent, TraceEventCodes};

    thread_local! {
        static STATEMENTS: std::cell::RefCell<Vec<String>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }
    let store = SqliteAccountStorage::in_memory().unwrap();
    store.lock().unwrap().trace_v2(
        TraceEventCodes::SQLITE_TRACE_STMT,
        Some(|event| {
            if let TraceEvent::Stmt(statement, _) = event {
                STATEMENTS
                    .with_borrow_mut(|statements| statements.push(statement.sql().into_owned()));
            }
        }),
    );
    store
        .app_storage()
        .pending_confirmation_group_invites()
        .unwrap();
    let conn = store.lock().unwrap();
    conn.trace_v2(TraceEventCodes::empty(), None);
    let statements = STATEMENTS.with_borrow_mut(std::mem::take);
    let [production_sql] = statements.as_slice() else {
        panic!("the invite read runs one statement, got {statements:?}");
    };
    let mut statement = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {production_sql}"))
        .unwrap();
    let plan = statement
        .query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join("\n");
    assert!(
        plan.contains("idx_account_groups_pending_invites"),
        "the pending-invite predicate must use its partial covering index, got:\n{plan}"
    );
    // A scan of the PARTIAL index only visits rows matching the predicate
    // (O(pending invites)); the regression to catch is a scan of the full
    // table or of the whole primary-key index (O(retained groups)).
    for line in plan.lines() {
        if line.contains("SCAN account_groups") {
            assert!(
                line.contains("idx_account_groups_pending_invites"),
                "the pending-invite query must not scan the full group table or its primary-key index, got:\n{plan}"
            );
        }
    }
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
        .app_storage()
        .save_account_projection_state(&state, 2, MAX_FUTURE_SKEW_SECS)
        .unwrap();

    let restored = store
        .app_storage()
        .load_account_projection_state("alice", 16)
        .unwrap();
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
    // A runtime that never learned a cursor (fresh process, no deliveries yet)
    // still saves other state; that save must never wipe the stored cursor.
    let never_learned = StoredAccountState {
        last_transport_timestamp: None,
        ..ahead.clone()
    };

    for saves in [
        [&ahead, &behind],
        [&behind, &ahead],
        [&ahead, &never_learned],
        [&never_learned, &ahead],
    ] {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
fn account_projection_state_heals_poisoned_stored_cursor_on_save() {
    // A stored cursor poisoned above `now + skew` (persisted by a version that
    // predates the write-side clamp) must come out of the merge healed down to
    // save-time `now + skew`, not preserved forever by the monotonic max —
    // the save-side twin of the app layer's ingest-time heal.
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let now_before = unix_now_seconds();
    let poisoned = now_before + 10 * 365 * 24 * 60 * 60; // ~10 years ahead
    app.ensure_account_projection("alice").unwrap();
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
    app.save_account_projection_state(&honest, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    let now_after = unix_now_seconds();

    let restored = app.load_account_projection_state("alice", 16).unwrap();
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
        .app_storage()
        .save_account_projection_state(&imported, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    let now_after = unix_now_seconds();

    let restored = store
        .app_storage()
        .load_account_projection_state("alice", 16)
        .unwrap();
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
    let poisoned = MERGE_NOW + 10 * 365 * 24 * 60 * 60; // ~10 years ahead
    for (stored, snapshot, expected) in [
        (None, None, None),
        // A fresh store adopts whatever the runtime learned.
        (None, Some(MERGE_NOW), Some(MERGE_NOW)),
        // A runtime that never learned a cursor must never wipe the stored one.
        (Some(MERGE_NOW), None, Some(MERGE_NOW)),
        // Without a snapshot cursor there is nothing to merge against: the
        // stored value passes through unchanged, even when poisoned. Healing
        // waits for the next save that learned a cursor, so a cursor-less save
        // never moves the durable value in either direction.
        (Some(poisoned), None, Some(poisoned)),
    ] {
        assert_eq!(
            merged_transport_timestamp(stored, snapshot, MERGE_NOW, MAX_FUTURE_SKEW_SECS),
            expected,
            "stored {stored:?}, snapshot {snapshot:?}"
        );
    }
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
    let app = store.app_storage();
    let state = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: vec![group("aa", "alpha"), group("bb", "beta")],
    };
    app.save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();

    let updated = StoredAccountState {
        groups: vec![group("bb", "beta")],
        ..state
    };
    app.save_account_projection_state(&updated, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();

    let restored = app.load_account_projection_state("alice", 16).unwrap();
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
    let app = store.app_storage();
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
    app.save_account_projection_state(
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
    app.save_account_projection_state(&retained, 16, MAX_FUTURE_SKEW_SECS)
        .expect("an unbounded retained set must not become SQL bind parameters");
    assert_eq!(
        app.load_account_projection_state("alice", GROUP_COUNT)
            .unwrap()
            .groups
            .len(),
        GROUP_COUNT - 1
    );

    app.save_account_projection_state(
        &StoredAccountState {
            groups: Vec::new(),
            ..retained
        },
        16,
        MAX_FUTURE_SKEW_SECS,
    )
    .expect("more than one chunk of stale group keys should be deleted");
    assert!(
        app.load_account_projection_state("alice", GROUP_COUNT)
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
        .app_storage()
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
        .app_storage()
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
    let app = store.app_storage();
    let seen_events = (0..64)
        .map(|index| format!("event-{index:05}"))
        .collect::<Vec<_>>();
    app.save_account_projection_state(
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
    app.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
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

    let restored = app.load_account_projection_state("alice", 64).unwrap();
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
    app.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
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
    app.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
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
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
            kinds: None,
            limit: None,
        })
        .unwrap();
    assert_eq!(aa.len(), 1);
    assert_eq!(aa[0].message_id_hex, "new-aa");
    let bb = store
        .app_messages(StoredAppMessageQuery {
            group_id_hex: Some("bb".to_owned()),
            kinds: None,
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
    store.app_storage().record_app_event(&old).unwrap();
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
            .app_storage()
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
    let options = SqliteStorageOptions {
        secure_delete: false,
        ..SqliteStorageOptions::default()
    };
    let store = open_plaintext_file(&db_path, options.clone());
    let app = store.app_storage();
    let secret = "secure-prune-disk-secret-586-plaintext";
    let secret_filename = "secure-prune-disk-secret-586.png";
    let media_hash = "ca".repeat(32);
    app.save_account_projection_state(
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
    app.record_app_event(&old).unwrap();
    app.refresh_chat_list_row("alice-account", "aa", &no_mentions)
        .unwrap();
    assert_eq!(
        app.chat_list_row("aa")
            .unwrap()
            .unwrap()
            .last_message
            .unwrap()
            .plaintext,
        secret,
        "fixture should project the message into the chat-list preview"
    );
    checkpoint_and_truncate_wal(&store);
    drop(app);
    drop(store);
    assert!(
        file_contains(&db_path, secret.as_bytes()),
        "fixture should place plaintext in the database file before secure prune"
    );
    let store = open_plaintext_file(&db_path, options);
    let app = store.app_storage();

    let outcome = app
        .secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        .unwrap();
    assert_eq!(outcome.pruned_messages, 1);
    assert_eq!(outcome.media_ciphertext_sha256, vec![media_hash.clone()]);
    assert!(
        app.chat_list_row("aa")
            .unwrap()
            .unwrap()
            .last_message
            .is_none()
    );
    drop(app);
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
    let options = SqliteStorageOptions {
        secure_delete: false,
        ..SqliteStorageOptions::default()
    };
    let store = open_plaintext_file(&db_path, options.clone());
    let app = store.app_storage();
    let old_secret = "secure-prune-index-secret-586-old";
    let survivor_secret = "secure-prune-index-secret-586-survivor";
    let mut old = app_event("old-index", "aa", 10);
    old.plaintext = old_secret.to_owned();
    let mut survivor = app_event("survivor-index", "aa", 20);
    survivor.plaintext = survivor_secret.to_owned();
    app.record_app_event(&old).unwrap();
    app.record_app_event(&survivor).unwrap();
    let indexed = app
        .message_timeline(crate::TimelineMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            search: Some("secure-prune-index-secret".to_owned()),
            ..crate::TimelineMessageQuery::default()
        })
        .unwrap();
    assert_eq!(indexed.messages.len(), 2);
    checkpoint_and_truncate_wal(&store);
    drop(app);
    drop(store);
    assert!(
        file_contains(&db_path, old_secret.as_bytes()),
        "fixture should place indexed plaintext in the database file before secure prune"
    );
    let store = open_plaintext_file(&db_path, options);
    let app = store.app_storage();

    let outcome = app
        .secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        .unwrap();

    assert_eq!(outcome.pruned_messages, 1);
    drop(app);
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

/// Reads a database file through `std::fs`. Call it only once every connection
/// to the file is closed: closing the descriptor `std::fs` opens drops this
/// process's POSIX locks on a live SQLite file (`crates/storage-sqlite/AGENTS.md`).
fn file_contains(path: &std::path::Path, needle: &[u8]) -> bool {
    let haystack = std::fs::read(path).unwrap();
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Opens an unencrypted file-backed store, so a test can look for plaintext in
/// its files after closing it.
fn open_plaintext_file(
    path: &std::path::Path,
    options: SqliteStorageOptions,
) -> SqliteAccountStorage {
    SqliteAccountStorage::from_connection_with_options(
        rusqlite::Connection::open(path).unwrap(),
        options,
    )
    .unwrap()
}

/// Checkpoints every WAL frame into the database file and truncates the WAL.
fn checkpoint_and_truncate_wal(store: &SqliteAccountStorage) {
    let (busy, _, _): (i64, i64, i64) = store
        .lock()
        .unwrap()
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(busy, 0);
}

#[test]
fn secure_prune_restores_caller_secure_delete_setting() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .lock()
        .unwrap()
        .execute_batch("PRAGMA secure_delete = OFF")
        .unwrap();
    assert_eq!(secure_delete_pragma(&store), 0);
    store
        .app_storage()
        .record_app_event(&app_event("old-aa", "aa", 10))
        .unwrap();

    let outcome = store
        .app_storage()
        .secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        .unwrap();

    assert_eq!(outcome.pruned_messages, 1);
    assert_eq!(secure_delete_pragma(&store), 0);
}

#[test]
fn secure_prune_retry_after_reopen_recovers_committed_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("account.sqlite");
    let options = SqliteStorageOptions {
        busy_timeout_ms: 1,
        ..SqliteStorageOptions::default()
    };
    let store = open_plaintext_file(&db_path, options.clone());
    let with_media = |id: &str, at: u64, hash: &str| {
        let mut event = app_event(id, "aa", at);
        event.tags = vec![vec![
            "imeta".to_owned(),
            "v encrypted-media-v1".to_owned(),
            format!("ciphertext_sha256 {hash}"),
        ]];
        event
    };
    let media_hash = "db".repeat(32);
    let later_hash = "dc".repeat(32);
    store
        .app_storage()
        .record_app_event(&with_media("old-aa", 10, &media_hash))
        .unwrap();

    let reader = rusqlite::Connection::open(&db_path).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let _: i64 = reader
        .query_row("SELECT count(*) FROM app_events", [], |row| row.get(0))
        .unwrap();

    let pending = store
        .app_storage()
        .secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        .expect("checkpoint contention is a committed result with pending erasure");

    assert_eq!(pending.pruned_messages, 1);
    assert_eq!(pending.media_ciphertext_sha256, vec![media_hash.clone()]);
    assert!(pending.erasure_pending);
    assert_eq!(
        store.app_storage().app_message_count().unwrap(),
        0,
        "logical deletion commits before the checkpoint failure is surfaced"
    );

    // A second prune while erasure is still pending reports both prunes: the
    // caller deletes encrypted media by these hashes.
    store
        .app_storage()
        .record_app_event(&with_media("later-aa", 20, &later_hash))
        .unwrap();
    let both = crate::SecurePruneAppEventsResult {
        pruned_messages: 2,
        pruned_media_epoch_secrets: 0,
        media_ciphertext_sha256: vec![media_hash.clone(), later_hash.clone()],
        erasure_pending: true,
    };
    assert_eq!(
        store
            .app_storage()
            .secure_prune_app_events_before("aa", 25, "local", &no_mentions)
            .unwrap(),
        both
    );
    reader.execute_batch("COMMIT").unwrap();
    drop(reader);
    drop(store);

    let store = open_plaintext_file(&db_path, options).app_storage();
    let outcome = store
        .secure_prune_app_events_before("aa", 25, "local", &no_mentions)
        .expect("retry after reopen must re-drive the durable pending checkpoint");
    assert_eq!(
        outcome,
        crate::SecurePruneAppEventsResult {
            erasure_pending: false,
            ..both
        }
    );

    let empty = store
        .secure_prune_app_events_before("aa", 25, "local", &no_mentions)
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
    let store_a = open_plaintext_file(&db_path, SqliteStorageOptions::default());
    let store_b = open_plaintext_file(&db_path, SqliteStorageOptions::default());
    let store_c = open_plaintext_file(&db_path, SqliteStorageOptions::default());
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
            &store_a.app_storage(),
            SECURE_DELETE_RETENTION_OPERATION,
            "aa",
        )
        .unwrap()
    });
    let b = std::thread::spawn(move || {
        finish_secure_delete_checkpoint_intent::<crate::SecurePruneAppEventsResult>(
            &store_b.app_storage(),
            SECURE_DELETE_RETENTION_OPERATION,
            "aa",
        )
        .unwrap()
    });
    let outcomes = [a.join().unwrap(), b.join().unwrap()];
    // A finisher whose checkpoint stays busy past its retries reports the
    // stored result with `erasure_pending` and leaves the intent in place, by
    // design; only a finisher that checkpointed and deleted the intent consumed it.
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.result.is_some() && !outcome.erasure_pending)
            .count(),
        1,
        "exactly one competing finisher should consume the durable result"
    );
    for outcome in outcomes {
        match outcome.result {
            Some(result) => assert_eq!(result, expected),
            None => assert!(!outcome.erasure_pending),
        }
    }
    let conn = store_c.lock().unwrap();
    assert!(
        secure_delete_intent(&conn, SECURE_DELETE_RETENTION_OPERATION, "aa")
            .unwrap()
            .is_none(),
        "the consumer deletes the intent"
    );
}

/// A finisher reads an intent, then checkpoints. Another writer that recreates
/// the intent meanwhile gives it a new nonce, and the finisher's delete, keyed
/// by the nonce it read, must leave the new intent for its own pass.
#[test]
fn recreated_checkpoint_intent_cannot_be_deleted_by_a_stale_nonce() {
    use crate::protocol::storage::write_contention::{Release, SharedDatabase};

    let first_result = crate::SecurePruneAppEventsResult {
        pruned_messages: 1,
        ..crate::SecurePruneAppEventsResult::default()
    };
    let second_result = crate::SecurePruneAppEventsResult {
        pruned_messages: 2,
        media_ciphertext_sha256: vec!["cd".repeat(32)],
        ..crate::SecurePruneAppEventsResult::default()
    };
    let db = SharedDatabase::new();
    let store = db.open();
    let first_nonce = {
        let conn = store.lock().unwrap();
        upsert_secure_delete_intent_tx(
            &conn,
            SECURE_DELETE_RETENTION_OPERATION,
            "aa",
            &serde_json::to_string(&first_result).unwrap(),
        )
        .unwrap();
        secure_delete_intent(&conn, SECURE_DELETE_RETENTION_OPERATION, "aa")
            .unwrap()
            .unwrap()
            .nonce
    };

    // The finisher reads the first intent, and its TRUNCATE checkpoint waits
    // for the write lock that the other connection holds while it recreates
    // the intent.
    let (second_nonce_tx, second_nonce_rx) = std::sync::mpsc::channel();
    let recreated = serde_json::to_string(&second_result).unwrap();
    let blocker = db.hold_write_lock(Release::WhenTheStoreWaits, move |other| {
        let conn = other.lock().unwrap();
        upsert_secure_delete_intent_tx(&conn, SECURE_DELETE_RETENTION_OPERATION, "aa", &recreated)
            .unwrap();
        let nonce = secure_delete_intent(&conn, SECURE_DELETE_RETENTION_OPERATION, "aa")
            .unwrap()
            .unwrap()
            .nonce;
        second_nonce_tx.send(nonce).unwrap();
    });
    let finish = finish_secure_delete_checkpoint_intent::<crate::SecurePruneAppEventsResult>(
        &store.app_storage(),
        SECURE_DELETE_RETENTION_OPERATION,
        "aa",
    )
    .unwrap();
    blocker.join();

    let second_nonce = second_nonce_rx.recv().unwrap();
    assert_eq!(first_nonce.len(), 16);
    assert_eq!(second_nonce.len(), 16);
    assert_ne!(first_nonce, second_nonce);
    assert_eq!(
        finish.result,
        Some(second_result),
        "a stale finisher must not consume a recreated intent; it reports the new one"
    );
    assert!(!finish.erasure_pending);
    assert!(
        secure_delete_intent(
            &store.lock().unwrap(),
            SECURE_DELETE_RETENTION_OPERATION,
            "aa"
        )
        .unwrap()
        .is_none()
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
    let app = store.app_storage();
    app.record_app_event(&app_event("old-aa", "aa", 10))
        .unwrap();
    app.record_app_event(&app_event("new-aa", "aa", 20))
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
        app.prune_app_events_before("aa", 15, "local", &no_mentions)
            .unwrap(),
        1
    );

    let timeline = app
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
    let app = store.app_storage();
    app.record_app_event(&agent_stream_start_event(
        "old-stream",
        "aa",
        "stream-old",
        10,
    ))
    .unwrap();
    app.record_app_event(&agent_stream_start_event(
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
        app.prune_app_events_before("aa", 15, "local", &no_mentions)
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
            .app_storage()
            .record_app_event(&app_event(&format!("old-{index:04}"), "aa", index as u64))
            .unwrap();
    }

    assert_eq!(
        store
            .app_storage()
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
    let app = store.app_storage();
    app.record_app_event(&app_event("old-parent", "aa", 10))
        .unwrap();
    app.record_app_event(&reply_event("reply", "aa", "old-parent", 20))
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
        app.prune_app_events_before("aa", 15, "local", &no_mentions)
            .unwrap(),
        1
    );

    let timeline = app
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
    let app = store.app_storage();
    app.record_app_event(&app_event("target", "aa", 20))
        .unwrap();
    app.record_app_event(&reaction_event("old-reaction", "aa", "target", 10))
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
        app.prune_app_events_before("aa", 15, "local", &no_mentions)
            .unwrap(),
        1
    );

    let timeline = app
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
fn prune_app_events_preserves_minimal_delete_evidence() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    app.record_app_event(&app_event("target", "aa", 20))
        .unwrap();
    app.record_app_event(&delete_event("old-delete", "aa", "sender", "target", 10))
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
        app.prune_app_events_before("aa", 15, "local", &no_mentions)
            .unwrap(),
        1
    );

    let timeline = app
        .message_timeline(crate::TimelineMessageQuery {
            group_id_hex: Some("aa".to_owned()),
            ..crate::TimelineMessageQuery::default()
        })
        .unwrap();
    assert_eq!(timeline.messages.len(), 1);
    let target = &timeline.messages[0];
    assert_eq!(target.message_id_hex, "target");
    assert!(target.deleted);
    assert!(target.plaintext.is_empty());
}

#[test]
fn app_messages_tie_break_on_message_id_matches_cursor_order() {
    // Same `recorded_at`, but `message_id_hex` lexical order differs from both
    // insertion order and `received_at` order. `wn messages list` filters
    // cursor ties on `(recorded_at, message_id_hex)`, so the projection must
    // return same-timestamp rows in `message_id_hex` order or pagination skips
    // or duplicates rows. Regression test for issue #390.
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
                kinds: None,
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
fn app_messages_kinds_filter_restricts_to_listed_kinds() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let mut custom = app_event("custom-1", "gg", 110);
    custom.kind = 30078;
    custom.tags = vec![vec!["d".to_owned(), "game-1".to_owned()]];
    let mut other_custom = app_event("custom-2", "gg", 120);
    other_custom.kind = 30079;
    for event in [app_event("chat-1", "gg", 100), custom, other_custom] {
        store.record_app_event(&event).unwrap();
    }

    let ids = |kinds: Option<Vec<u64>>| {
        store
            .app_messages(StoredAppMessageQuery {
                group_id_hex: Some("gg".to_owned()),
                kinds,
                limit: None,
            })
            .unwrap()
            .into_iter()
            .map(|message| message.message_id_hex)
            .collect::<Vec<_>>()
    };

    // `None` and an empty list both apply no kind constraint.
    assert_eq!(ids(None), vec!["chat-1", "custom-1", "custom-2"]);
    assert_eq!(
        ids(Some(Vec::new())),
        vec!["chat-1", "custom-1", "custom-2"]
    );
    assert_eq!(ids(Some(vec![30078])), vec!["custom-1"]);
    assert_eq!(
        ids(Some(vec![MARMOT_APP_EVENT_KIND_CHAT, 30079])),
        vec!["chat-1", "custom-2"]
    );
    assert!(ids(Some(vec![1])).is_empty());

    // The kind filter composes with the limited newest-first window.
    let limited = store
        .app_messages(StoredAppMessageQuery {
            group_id_hex: Some("gg".to_owned()),
            kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT, 30078]),
            limit: Some(1),
        })
        .unwrap();
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].message_id_hex, "custom-1");
}

#[test]
fn notification_settings_default_local_notifications_on() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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

/// Disabling native push, clearing the registration and moving it to another
/// push server each queue the old registration's server removal in the same
/// transaction. If the removal cannot be queued, nothing changes: deleting the
/// local registration without it would leave the token on the push server.
#[test]
fn push_registration_changes_queue_their_server_removal_or_change_nothing() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let account_id = "11".repeat(32);
    app.save_account_projection_state(
        &StoredAccountState {
            label: "alice".to_owned(),
            groups: vec![group("aa", "alpha")],
            ..Default::default()
        },
        16,
        MAX_FUTURE_SKEW_SECS,
    )
    .unwrap();
    app.set_native_push_enabled("alice", &account_id, true)
        .unwrap();
    let registration = AccountPushRegistration {
        account_label: "alice".to_owned(),
        account_id_hex: account_id.clone(),
        platform: 1,
        token_fingerprint: "first".to_owned(),
        server_pubkey_hex: "bb".repeat(32),
        relay_hint: None,
        created_at_ms: 10,
        updated_at_ms: 10,
        last_shared_at_ms: None,
    };
    app.upsert_push_registration(registration.clone(), vec![1, 2, 3])
        .unwrap();
    let state = || {
        let shares = store
            .lock()
            .unwrap()
            .prepare("SELECT group_id_hex, token_fingerprint FROM pending_push_registration_shares")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        (
            app.push_registration("alice").unwrap(),
            app.notification_settings("alice", &account_id).unwrap(),
            shares,
        )
    };
    let before = state();
    assert!(before.0.is_some());
    assert!(before.1.native_push_enabled);
    assert_eq!(before.2.len(), 1);
    store
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_push_removal BEFORE INSERT ON pending_push_registration_removals
             BEGIN SELECT RAISE(ABORT, 'injected removal failure'); END;",
        )
        .unwrap();
    let moved = AccountPushRegistration {
        server_pubkey_hex: "dd".repeat(32),
        updated_at_ms: 20,
        ..registration
    };
    let changes: [(&str, &dyn Fn() -> StorageResult<()>); 3] = [
        ("disabling native push", &|| {
            app.set_native_push_enabled("alice", &account_id, false)
                .map(drop)
        }),
        ("clearing the registration", &|| {
            app.clear_push_registration("alice").map(drop)
        }),
        ("moving to another push server", &|| {
            app.upsert_push_registration(moved.clone(), vec![4, 5, 6])
                .map(drop)
        }),
    ];
    for (change, apply) in changes {
        assert_fails_with(apply(), "injected removal failure");
        assert_eq!(state(), before, "{change} must change nothing");
    }
}

#[test]
fn push_registration_preserves_progress_on_resume_and_requeues_changed_routing() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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

    let mut resumed = registration.clone();
    resumed.updated_at_ms = 100;
    let unchanged = store
        .upsert_push_registration(resumed.clone(), vec![1, 2, 3])
        .unwrap();
    assert_eq!(unchanged.registration.updated_at_ms, 10);
    assert_eq!(
        store.pending_push_registration_shares("first", 10).unwrap(),
        vec!["bb".to_owned()],
        "foreground registration must retain partial delivery progress"
    );
    assert!(
        store
            .complete_push_registration_share("bb", "first", 10)
            .unwrap()
    );
    assert!(
        store
            .mark_push_registration_shared("alice", "first", 10, 101)
            .unwrap()
    );
    let unchanged = store
        .upsert_push_registration(resumed, vec![1, 2, 3])
        .unwrap();
    assert_eq!(unchanged.registration.last_shared_at_ms, Some(101));
    assert!(
        store
            .pending_push_registration_shares("first", 10)
            .unwrap()
            .is_empty()
    );

    let mut refreshed = registration;
    refreshed.relay_hint = Some("wss://relay.example".to_owned());
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
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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

/// Re-queueing republishes a completed share of the label's current revision,
/// only while native push is on and only for joined groups; another label's
/// registration in the same database neither joins nor breaks the insert.
#[test]
fn current_push_registration_share_requeues_a_completed_revision() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
    store
        .set_group_self_membership("bb", SelfMembership::Left)
        .unwrap();
    let registration = |label: &str, fingerprint: &str, at: i64| AccountPushRegistration {
        account_label: label.to_owned(),
        account_id_hex: "11".repeat(32),
        platform: 1,
        token_fingerprint: fingerprint.to_owned(),
        server_pubkey_hex: "22".repeat(32),
        relay_hint: None,
        created_at_ms: at,
        updated_at_ms: at,
        last_shared_at_ms: None,
    };
    store
        .upsert_push_registration(registration("legacy", "legacy", 30), vec![3])
        .unwrap();
    store
        .set_native_push_enabled("legacy", &"11".repeat(32), true)
        .unwrap();
    store
        .upsert_push_registration(registration("alice", "first", 10), vec![1])
        .unwrap();
    assert!(
        !store
            .queue_current_push_registration_share_for_group("alice", "aa", 40)
            .unwrap(),
        "native push is off"
    );
    store
        .set_native_push_enabled("alice", &"11".repeat(32), true)
        .unwrap();
    for (fingerprint, at) in [("first", 10), ("legacy", 30)] {
        store
            .complete_push_registration_share("aa", fingerprint, at)
            .unwrap();
    }
    assert!(
        store
            .mark_push_registration_shared("alice", "first", 10, 11)
            .unwrap()
    );

    assert!(
        store
            .queue_current_push_registration_share_for_group("alice", "aa", 40)
            .unwrap()
    );
    assert_eq!(
        store.pending_push_registration_shares("first", 10).unwrap(),
        vec!["aa".to_owned()]
    );
    assert!(
        store
            .pending_push_registration_shares("legacy", 30)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .push_registration("alice")
            .unwrap()
            .unwrap()
            .registration
            .last_shared_at_ms,
        None
    );
    assert!(
        !store
            .queue_current_push_registration_share_for_group("alice", "bb", 40)
            .unwrap(),
        "a departed group is not shared with"
    );
}

#[test]
fn push_registration_rotation_and_clear_queue_durable_removals() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
    let key = SqlCipherKey::raw([0x13; 32]);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut deleted_group = group("aa", "alpha");
    deleted_group.prior_nostr_routes = vec![StoredNostrRoute {
        nostr_group_id_hex: "11".repeat(32),
        relays: vec!["wss://old.example".to_owned()],
        last_epoch: 7,
        replaced_at: Some(1_800_000_000),
    }];
    store
        .app_storage()
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
            .app_storage()
            .local_group_deletion_prior_nostr_routes("aa")
            .unwrap(),
        vec![StoredNostrRoute {
            nostr_group_id_hex: "11".repeat(32),
            relays: vec!["wss://old.example".to_owned()],
            last_epoch: 7,
            replaced_at: Some(1_800_000_000),
        }],
        "the frontier keeps the switch time that floors the retained route"
    );
}

#[test]
fn retaining_a_local_delete_route_keeps_its_earliest_known_switch() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let route = |replaced_at| StoredNostrRoute {
        nostr_group_id_hex: "22".repeat(32),
        relays: vec!["wss://retained.example".to_owned()],
        last_epoch: 2,
        replaced_at,
    };
    let mut deleted_group = group("aa", "alpha");
    deleted_group.prior_nostr_routes = vec![route(Some(1_800_000_000))];
    app.save_account_projection_state(
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
    store.delete_local_group_data("aa").unwrap();
    let frontier = || app.local_group_deletion_prior_nostr_routes("aa").unwrap();

    // Retained again as the hidden group's current route: that records no
    // switch, and the earlier one stays.
    app.retain_local_group_deletion_nostr_routes("aa", &[route(None)])
        .unwrap();
    assert_eq!(frontier(), vec![route(Some(1_800_000_000))]);
    app.retain_local_group_deletion_nostr_routes("aa", &[route(Some(1_799_999_000))])
        .unwrap();
    assert_eq!(frontier(), vec![route(Some(1_799_999_000))]);
    app.retain_local_group_deletion_nostr_routes("aa", &[route(Some(1_800_001_000))])
        .unwrap();
    assert_eq!(
        frontier(),
        vec![route(Some(1_799_999_000))],
        "the earliest known switch reaches furthest back"
    );
}

#[test]
fn a_retained_route_stored_without_a_switch_is_stamped_once_at_first_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy-retained-routes.sqlite");
    let key = SqlCipherKey::raw([0x14; 32]);
    let route = |id: &str, replaced_at| StoredNostrRoute {
        nostr_group_id_hex: id.repeat(32),
        relays: vec![format!("wss://retained-{id}.example")],
        last_epoch: 2,
        replaced_at,
    };
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut legacy = group("aa", "alpha");
    legacy.prior_nostr_routes = vec![route("11", None), route("22", Some(1_700_000_000))];
    let mut hidden = group("bb", "beta");
    hidden.prior_nostr_routes = vec![route("33", None)];
    store
        .app_storage()
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![legacy, hidden, group("cc", "gamma")],
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    // A locally deleted group keeps its routes in the frontier, which no
    // projection loads; they stay as they were.
    insert_protocol_group_marker(&store, &[0xbb]);
    store.delete_local_group_data("bb").unwrap();
    let retained = |store: &SqliteAccountStorage| {
        store.app_storage().account_groups(Some("aa")).unwrap()[0]
            .prior_nostr_routes
            .clone()
    };

    let first_load = 1_800_000_000;
    assert_eq!(
        store
            .app_storage()
            .stamp_unrecorded_prior_route_switches(first_load)
            .unwrap(),
        1
    );
    let stamped = vec![
        route("11", Some(first_load)),
        route("22", Some(1_700_000_000)),
    ];
    assert_eq!(retained(&store), stamped);
    assert_eq!(
        store
            .app_storage()
            .local_group_deletion_prior_nostr_routes("bb")
            .unwrap(),
        vec![route("33", None)]
    );

    // Later loads, in this process and after a restart, keep the stamp.
    assert_eq!(
        store
            .app_storage()
            .stamp_unrecorded_prior_route_switches(first_load + 600)
            .unwrap(),
        0
    );
    drop(store);
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(
        reopened
            .app_storage()
            .stamp_unrecorded_prior_route_switches(first_load + 86_400)
            .unwrap(),
        0
    );
    assert_eq!(retained(&reopened), stamped);
}

#[test]
fn retained_local_delete_routes_prune_ids_outside_the_engine_overlap_window() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let mut deleted_group = group("aa", "alpha");
    deleted_group.prior_nostr_routes = vec![
        StoredNostrRoute {
            nostr_group_id_hex: "11".repeat(32),
            relays: vec!["wss://retired.example".to_owned()],
            last_epoch: 1,
            replaced_at: None,
        },
        StoredNostrRoute {
            nostr_group_id_hex: "22".repeat(32),
            relays: vec!["wss://retained.example".to_owned()],
            last_epoch: 2,
            replaced_at: None,
        },
    ];
    app.save_account_projection_state(
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

    app.retain_local_group_deletion_nostr_routes(
        "aa",
        &[StoredNostrRoute {
            nostr_group_id_hex: "33".repeat(32),
            relays: vec!["wss://current.example".to_owned()],
            last_epoch: 3,
            replaced_at: None,
        }],
    )
    .unwrap();

    assert_eq!(
        app.local_group_deletion_prior_nostr_routes("aa").unwrap(),
        vec![
            StoredNostrRoute {
                nostr_group_id_hex: "22".repeat(32),
                relays: vec!["wss://retained.example".to_owned()],
                last_epoch: 2,
                replaced_at: None,
            },
            StoredNostrRoute {
                nostr_group_id_hex: "33".repeat(32),
                relays: vec!["wss://current.example".to_owned()],
                last_epoch: 3,
                replaced_at: None,
            },
        ],
        "durable exact-route history must advance with the engine-owned overlap window",
    );
}

#[test]
fn failed_resurrection_projection_save_retains_local_deletion_frontier() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    app.save_account_projection_state(
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
    let frontier = app.local_group_deletion_frontier("aa").unwrap().unwrap();
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
        authority: None,
        group_id: cgka_traits::GroupId::new(vec![0xaa]),
        message_id: fresh_message_id.clone(),
        sender: MemberId::new(vec![7; 32]),
        sender_leaf_index: None,
        epoch: EpochId(0),
        payload: b"fresh chat".to_vec(),
        retention: None,
        encrypted_media_secret: None,
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

    let result = app.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
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

    assert_fails_with(result, "injected projection failure");
    assert_eq!(
        app.local_group_deletion_frontier("aa").unwrap(),
        Some(frontier),
        "the marker clear must roll back when the crossing projection fails to persist",
    );
    assert!(
        app.load_account_projection_state("alice", 16)
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
    let app = store.app_storage();
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
    let first_frontier = app.local_group_deletion_frontier("aa").unwrap().unwrap();

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
    let repeated_frontier = app.local_group_deletion_frontier("aa").unwrap().unwrap();

    assert!(repeated_frontier > first_frontier);
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
    // The crossing check the app's sync path runs: only a message of this
    // group stored after the frontier crosses it. The buffered message is the
    // repeated delete's frontier itself, so it does not.
    let newer = |group_id_hex: &str, message_id: &MessageId, frontier: u64| {
        app.local_group_deletion_message_is_newer_than(group_id_hex, message_id, frontier)
            .unwrap()
    };
    assert!(newer("aa", &buffered_message_id, first_frontier));
    assert!(
        !newer("aa", &buffered_message_id, repeated_frontier),
        "a message buffered before the repeated delete must remain behind its frontier"
    );
    assert!(!newer("aa", &first_message_id, repeated_frontier));
    assert!(
        newer("aa", &fresh_message_id, repeated_frontier),
        "a message inserted after the repeated delete must cross the advanced frontier"
    );
    assert!(
        !newer("bb", &fresh_message_id, repeated_frontier),
        "another group's message never crosses this group's frontier"
    );
    assert_eq!(
        app.local_group_deletion_frontier("aa").unwrap(),
        Some(repeated_frontier),
        "the check leaves the frontier for the caller's save to clear"
    );

    // `clear_local_group_deletion_frontier_if_message_is_newer` has no
    // production caller; these probes go with it.
    assert!(
        !app.clear_local_group_deletion_frontier_if_message_is_newer("aa", &buffered_message_id)
            .unwrap()
    );
    assert_eq!(
        app.local_group_deletion_frontier("aa").unwrap(),
        Some(repeated_frontier)
    );
    assert!(
        app.clear_local_group_deletion_frontier_if_message_is_newer("aa", &fresh_message_id)
            .unwrap()
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
        .app_storage()
        .save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    let mut group_a_message = app_event("msg-aa", "aa", 10);
    group_a_message.source_epoch = Some(7);
    group_a_message.tags = vec![vec!["imeta".to_owned(), "v encrypted-media-v1".to_owned()]];
    store
        .app_storage()
        .record_app_event(&group_a_message)
        .unwrap();
    store
        .app_storage()
        .record_app_event(&agent_stream_start_event(
            "stream-aa",
            "aa",
            &"11".repeat(32),
            11,
        ))
        .unwrap();
    store
        .app_storage()
        .record_app_event(&app_event("msg-bb", "bb", 12))
        .unwrap();
    store
        .app_storage()
        .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
        .unwrap();
    store
        .app_storage()
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
        .app_storage()
        .apply_group_push_token_tombstone(&push_tombstone("aa", "member-aa", 9, 500, "rd"))
        .unwrap();
    store
        .app_storage()
        .apply_group_push_token_tombstone(&push_tombstone("bb", "member-bb", 9, 500, "rd"))
        .unwrap();
    for group_id_hex in ["aa", "bb"] {
        assert!(
            store
                .app_storage()
                .record_group_push_gossip_join(group_id_hex, 500)
                .unwrap()
        );
    }
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
        .app_storage()
        .upsert_push_registration(registration.clone(), vec![1])
        .unwrap();
    store
        .app_storage()
        .queue_push_registration_removals(&registration, 11)
        .unwrap();

    assert!(store.delete_local_group_data("aa").unwrap().did_delete());
    let deletion_frontier = store
        .app_storage()
        .local_group_deletion_frontier("aa")
        .unwrap()
        .unwrap();
    let crosses_frontier = |message_id: &MessageId| {
        store
            .app_storage()
            .local_group_deletion_message_is_newer_than("aa", message_id, deletion_frontier)
            .unwrap()
    };
    assert!(
        !crosses_frontier(&historical_message_id),
        "historical replay already inside the deletion frontier must stay suppressed"
    );
    store
        .app_storage()
        .save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    let after_stale_save = store
        .app_storage()
        .load_account_projection_state("alice", 16)
        .unwrap();
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
        store
            .app_storage()
            .local_group_deletion_frontier("aa")
            .unwrap(),
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
        crosses_frontier(&newer_message_id),
        "causally newer group activity crosses the deletion frontier"
    );
    store
        .app_storage()
        .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[9, 9, 9])
        .unwrap();
    assert_eq!(
        store
            .app_storage()
            .encrypted_media_epoch_secret("aa", 0x8008, 7)
            .unwrap(),
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
        "group_push_gossip_state",
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
        "group_push_gossip_state",
        "pending_push_registration_shares",
        "pending_push_registration_removals",
        "encrypted_media_epoch_secrets",
    ] {
        assert!(group_row_count(&store, table, "bb") > 0, "{table}");
    }
    assert_eq!(all_row_count(&store, "seen_events"), 1);
    assert_eq!(all_row_count(&store, "cgka_groups"), 1);
    assert!(!store.delete_local_group_data("aa").unwrap().did_delete());

    // The repeated delete advanced the frontier past the newer message. A save
    // that crosses with the frontier it observed before then is stale and
    // clears nothing; one that observed the current frontier clears it in the
    // same transaction that restores the chat.
    let repeated_frontier = store
        .app_storage()
        .local_group_deletion_frontier("aa")
        .unwrap()
        .unwrap();
    assert!(repeated_frontier > deletion_frontier);
    let has_aa = || {
        store
            .app_storage()
            .account_groups(Some("aa"))
            .unwrap()
            .len()
            == 1
    };
    for (observed, cleared) in [(deletion_frontier, false), (repeated_frontier, true)] {
        store
            .app_storage()
            .save_account_projection_state_clearing_local_group_deletion_frontiers(
                &state,
                16,
                MAX_FUTURE_SKEW_SECS,
                &[("aa".to_owned(), observed)],
            )
            .unwrap();
        assert_eq!(
            store
                .app_storage()
                .local_group_deletion_frontier("aa")
                .unwrap(),
            (!cleared).then_some(repeated_frontier),
            "observed frontier {observed}"
        );
        assert_eq!(has_aa(), cleared, "observed frontier {observed}");
    }
}

#[test]
fn delete_local_group_data_reopens_and_retries_a_committed_pending_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("local-wipe.sqlite");
    let options = SqliteStorageOptions {
        busy_timeout_ms: 1,
        secure_delete: false,
        ..SqliteStorageOptions::default()
    };
    let store = open_plaintext_file(&db_path, options.clone());
    let group_id_hex = "aa";
    store
        .app_storage()
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
    store.app_storage().record_app_event(&message).unwrap();
    checkpoint_and_truncate_wal(&store);
    drop(store);
    assert!(file_contains(&db_path, secret.as_bytes()));
    let store = open_plaintext_file(&db_path, options.clone());

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
    assert_eq!(store.app_storage().app_message_count().unwrap(), 0);
    assert_eq!(
        secure_delete_pragma(&store),
        0,
        "the caller's secure_delete setting must be restored after the committed wipe"
    );

    // A second wipe while erasure is still pending adds its rows to the
    // pending result instead of replacing it. Its row is a push-token
    // tombstone: a new message could reuse the page space the wiped plaintext
    // held and hide plaintext the wipe left behind from the on-disk check below.
    assert!(
        store
            .app_storage()
            .apply_group_push_token_tombstone(&push_tombstone(
                group_id_hex,
                &"bb".repeat(32),
                0,
                100,
                "removed-after-wipe",
            ))
            .unwrap()
    );
    let both = store.delete_local_group_data(group_id_hex).unwrap();
    assert!(both.erasure_pending);
    assert!(!both.completed_pending_checkpoint);
    assert!(
        both.deleted_rows > pending.deleted_rows,
        "{} rows reported after a first wipe of {}",
        both.deleted_rows,
        pending.deleted_rows
    );

    reader.execute_batch("COMMIT").unwrap();
    drop(reader);
    drop(store);
    let store = open_plaintext_file(&db_path, options);
    let completed = store
        .delete_local_group_data(group_id_hex)
        .expect("retry after reopen should finish the prior checkpoint");
    assert!(completed.did_delete());
    assert!(completed.completed_pending_checkpoint);
    assert!(!completed.erasure_pending);
    assert_eq!(completed.deleted_rows, both.deleted_rows);
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
    let app = store.app_storage();
    let state = StoredAccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: vec![group("aa", "alpha")],
    };
    app.save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    app.record_app_event(&app_event("msg-aa", "aa", 10))
        .unwrap();
    app.remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
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
    // same with_transaction retry path. The other connection holds the write lock
    // until the writer's first attempt has failed busy, so only a retry succeeds.
    use crate::protocol::storage::write_contention::{Release, SharedDatabase};

    let db = SharedDatabase::new();
    let writer = db.open();
    let blocker = db.hold_write_lock(Release::AfterAFailedAttempt, |_| {});
    writer
        .app_storage()
        .record_app_event(&app_event("contended", "aa", 10))
        .expect("projection writer should wait out transient sqlite write-lock contention");
    blocker.join();
    assert_eq!(writer.app_storage().app_message_count().unwrap(), 1);
}

fn push_tombstone(
    group_id_hex: &str,
    member_id_hex: &str,
    leaf_index: u32,
    owner_ts: i64,
    record_digest: &str,
) -> AccountGroupPushTokenTombstone {
    AccountGroupPushTokenTombstone {
        group_id_hex: group_id_hex.to_owned(),
        member_id_hex: member_id_hex.to_owned(),
        leaf_index,
        platform: 1,
        server_pubkey_hex: "cc".repeat(32),
        owner_ts,
        record_digest: record_digest.to_owned(),
        removal_proof: None,
        created_at_ms: owner_ts,
    }
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

/// Runs `op` while a second connection holds the write lock, and releases the
/// lock only when the store begins a second transaction: the first attempt
/// must fail busy, and only its retry can succeed.
///
/// The push-token applies read inside a deferred transaction before they write.
/// SQLite returns `SQLITE_BUSY` to that upgrade without calling the busy
/// handler, so `write_contention`, which releases from the busy handler, cannot
/// drive them.
fn retried_past_a_held_write_lock<T>(
    store: &SqliteAccountStorage,
    path: &std::path::Path,
    op: impl FnOnce() -> T,
) -> T {
    use rusqlite::trace::{TraceEvent, TraceEventCodes};

    thread_local! {
        static HOLDER: std::cell::RefCell<Option<rusqlite::Connection>> =
            const { std::cell::RefCell::new(None) };
        static BEGINS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    let holder = rusqlite::Connection::open(path).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    HOLDER.set(Some(holder));
    BEGINS.set(0);
    store.lock().unwrap().trace_v2(
        TraceEventCodes::SQLITE_TRACE_STMT,
        Some(|event| {
            if let TraceEvent::Stmt(statement, _) = event
                && statement.sql().starts_with("BEGIN")
            {
                BEGINS.set(BEGINS.get() + 1);
                if BEGINS.get() == 2 {
                    let holder = HOLDER.take().expect("the lock is still held");
                    holder.execute_batch("COMMIT").unwrap();
                }
            }
        }),
    );
    let value = op();
    store
        .lock()
        .unwrap()
        .trace_v2(TraceEventCodes::empty(), None);
    assert_eq!(BEGINS.get(), 2, "one failed attempt, then one retry");
    assert!(HOLDER.take().is_none());
    value
}

#[test]
fn push_token_apply_retries_concurrent_writer_contention() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("push-token-contention.sqlite");
    let store = open_plaintext_file(&path, SqliteStorageOptions::default());
    let writer = store.app_storage();
    let group_id = "aa".repeat(32);
    let member_id = "bb".repeat(32);

    let applied = retried_past_a_held_write_lock(&store, &path, || {
        writer.apply_group_push_token(&push_token(&group_id, &member_id, 100, "d1"))
    });
    assert!(applied.expect("token apply retries after transient contention"));

    let applied = retried_past_a_held_write_lock(&store, &path, || {
        writer
            .apply_group_push_token_tombstone(&push_tombstone(&group_id, &member_id, 0, 200, "r1"))
    });
    assert!(applied.expect("tombstone apply retries after transient contention"));
    assert!(writer.group_push_tokens(&group_id).unwrap().is_empty());
}

#[test]
fn apply_group_push_token_keeps_sibling_leaves_distinct() {
    // Two devices of one account (same member id, same platform+server, different
    // leaf index) must coexist: leaf_index is part of the record key, so neither
    // leaf's token overwrites the other's and a removal for one leaf does not
    // touch the sibling. Regression for the pre-migration 4-tuple key that
    // collapsed sibling devices (#628).
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
            .apply_group_push_token_tombstone(&push_tombstone(&g, &m, 1, 200, "r1"))
            .unwrap()
    );
    let stored = store.group_push_tokens(&g).unwrap();
    assert_eq!(stored.len(), 1, "only the targeted leaf is removed");
    assert_eq!(stored[0].leaf_index, 2);
}

#[test]
fn apply_group_push_token_rejects_stale_stamp_rollback() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
            .apply_group_push_token_tombstone(&push_tombstone(&g, &m, 0, 200, "r2"))
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
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let g = "aa".repeat(32);
    let m = "bb".repeat(32);
    store
        .apply_group_push_token_tombstone(&push_tombstone(&g, &m, 0, 200, "r2"))
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

/// A tombstone keeps the removal's fingerprint and signature, so it can be
/// relayed. A newer removal replaces them; an older one changes nothing. A
/// tombstone written without them lists as unrelayable until the same removal
/// arrives again with them.
#[test]
fn push_tombstones_keep_their_removal_proof_and_list_per_group() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let g = "aa".repeat(32);
    let m = "bb".repeat(32);
    let proof = |fingerprint: &str, sig: &str| AccountPushTokenRemovalProof {
        token_fingerprint: fingerprint.to_owned(),
        owner_sig: sig.to_owned(),
    };
    let relayable = |owner_ts: i64, digest: &str, sig: &str| AccountGroupPushTokenTombstone {
        removal_proof: Some(proof("fp", sig)),
        ..push_tombstone(&g, &m, 0, owner_ts, digest)
    };

    assert!(
        store
            .apply_group_push_token_tombstone(&relayable(200, "r2", "sig-200"))
            .unwrap()
    );
    assert!(
        !store
            .apply_group_push_token_tombstone(&relayable(100, "r1", "sig-100"))
            .unwrap()
    );
    assert_eq!(
        store.group_push_token_tombstones(&g).unwrap(),
        vec![relayable(200, "r2", "sig-200")]
    );
    assert!(
        store
            .apply_group_push_token_tombstone(&relayable(300, "r3", "sig-300"))
            .unwrap()
    );
    let local_only = push_tombstone(&g, &m, 1, 300, "r4");
    let other_group = push_tombstone(&"ee".repeat(32), &m, 0, 300, "r5");
    for tombstone in [&local_only, &other_group] {
        assert!(store.apply_group_push_token_tombstone(tombstone).unwrap());
    }
    assert_eq!(
        store.group_push_token_tombstones(&g).unwrap(),
        vec![relayable(300, "r3", "sig-300"), local_only.clone()]
    );

    // Only the same removal, at an equal stamp, fills in the missing proof.
    let with_proof = |owner_ts: i64, digest: &str| AccountGroupPushTokenTombstone {
        removal_proof: Some(proof("fp", "sig-local")),
        ..push_tombstone(&g, &m, 1, owner_ts, digest)
    };
    for other_removal in [with_proof(300, "r0"), with_proof(299, "r4")] {
        assert!(
            !store
                .apply_group_push_token_tombstone(&other_removal)
                .unwrap()
        );
    }
    assert_eq!(
        store.group_push_token_tombstones(&g).unwrap()[1],
        local_only
    );
    assert!(
        !store
            .apply_group_push_token_tombstone(&with_proof(300, "r4"))
            .unwrap()
    );
    assert_eq!(
        store.group_push_token_tombstones(&g).unwrap()[1],
        with_proof(300, "r4")
    );
    assert!(
        !store
            .apply_group_push_token_tombstone(&AccountGroupPushTokenTombstone {
                removal_proof: Some(proof("fp", "sig-other")),
                ..with_proof(300, "r4")
            })
            .unwrap()
    );
    assert_eq!(
        store.group_push_token_tombstones(&g).unwrap()[1],
        with_proof(300, "r4"),
        "a stored proof is never replaced at an equal stamp"
    );

    // A strictly newer record clears the tombstone, proof and all.
    assert!(
        store
            .apply_group_push_token(&push_token(&g, &m, 400, "d4"))
            .unwrap()
    );
    assert_eq!(store.group_push_token_tombstones(&g).unwrap().len(), 1);
}

/// Gossip state covers one membership of a projected group: writes need a
/// joined group, the first join time stands, the latest announce
/// wins, and leaving, a local delete or a projection prune clears the row.
#[test]
fn push_gossip_state_tracks_the_current_membership() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let save = |groups: Vec<StoredAccountGroup>| {
        app.save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups,
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    };
    let state = |group: &str| app.group_push_gossip_state(group).unwrap();
    assert!(!app.record_group_push_gossip_join("aa", 1).unwrap());
    assert_eq!(state("aa"), None);
    save(vec![group("aa", "alpha"), group("bb", "beta")]);

    assert!(app.record_group_push_gossip_join("aa", 10).unwrap());
    assert!(app.record_group_push_gossip_join("aa", 20).unwrap());
    assert!(
        app.record_group_push_gossip_announce("aa", 50, None)
            .unwrap()
    );
    assert!(
        app.record_group_push_gossip_announce("aa", 40, None)
            .unwrap()
    );
    let recorded = Some(AccountGroupPushGossipState {
        group_id_hex: "aa".to_owned(),
        joining_since_ms: None,
        joined_at_ms: Some(10),
        join_window_counted_ms: 0,
        announce_owed_at_ms: None,
        last_announced_at_ms: Some(50),
        snapshot_owed_after_epoch: None,
    });
    assert_eq!(state("aa"), recorded);
    // Saving the projection again keeps a still-joined group's row.
    let mut renamed = group("aa", "renamed");
    renamed.member_count = Some(3);
    save(vec![renamed, group("bb", "beta")]);
    assert_eq!(state("aa"), recorded);

    for membership in [SelfMembership::Left, SelfMembership::Removed] {
        app.set_group_self_membership("aa", SelfMembership::Member)
            .unwrap();
        assert!(app.record_group_push_gossip_join("aa", 60).unwrap());
        assert_eq!(
            app.record_group_push_announce_owed("aa", 60).unwrap(),
            Some(60)
        );
        app.set_group_self_membership("aa", membership).unwrap();
        assert_eq!(state("aa"), None, "{membership:?} ends the membership");
        assert_eq!(app.record_group_push_announce_owed("aa", 65).unwrap(), None);
        assert!(
            !app.record_group_push_gossip_announce("aa", 70, None)
                .unwrap()
        );
        assert_eq!(state("aa"), None, "no write after {membership:?}");
    }
    app.set_group_self_membership("aa", SelfMembership::Member)
        .unwrap();
    assert!(app.record_group_push_gossip_join("aa", 80).unwrap());
    assert_eq!(state("aa").unwrap().joined_at_ms, Some(80));
    assert_eq!(state("aa").unwrap().last_announced_at_ms, None);

    assert!(app.record_group_push_gossip_join("bb", 90).unwrap());
    store.delete_local_group_data("aa").unwrap();
    assert_eq!(state("aa"), None);
    save(Vec::new());
    assert_eq!(state("bb"), None);
}

/// A Welcome opens this device's push join window with the group's row; a
/// created group has none, a replay keeps the window, time counts toward it
/// only once its join completed, a new Welcome reopens it and drops the
/// earlier join and its counted time, and the announce at its end closes it.
#[test]
fn a_welcome_opens_the_push_join_window_until_the_announce() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let save = |groups: Vec<StoredAccountGroup>| {
        app.save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups,
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    };
    let welcomed = |id: &str, welcome: &str| {
        let mut group = group(id, "welcomed");
        group.via_welcome_message_id_hex = Some(welcome.to_owned());
        group
    };
    let state = |group: &str| app.group_push_gossip_state(group).unwrap();
    let joining = || {
        app.joining_group_push_gossip_states()
            .unwrap()
            .into_iter()
            .map(|state| state.group_id_hex)
            .collect::<Vec<_>>()
    };

    save(vec![group("aa", "created"), welcomed("bb", "w1")]);
    assert_eq!(state("aa"), None, "a created group has no window");
    let opened = state("bb").unwrap().joining_since_ms.unwrap();
    assert_eq!(state("bb").unwrap().joined_at_ms, None);
    assert_eq!(joining(), vec!["bb".to_owned()]);

    // Time counts only toward a window whose join has completed.
    assert_eq!(app.count_push_join_window_time(5).unwrap(), 0);
    assert_eq!(state("bb").unwrap().join_window_counted_ms, 0);

    // Saving the same Welcome again keeps the window, its join time and the
    // time counted toward it.
    assert!(app.record_group_push_gossip_join("bb", 10).unwrap());
    assert_eq!(app.count_push_join_window_time(5).unwrap(), 1);
    assert_eq!(app.count_push_join_window_time(7).unwrap(), 1);
    save(vec![group("aa", "created"), welcomed("bb", "w1")]);
    assert_eq!(state("bb").unwrap().joining_since_ms, Some(opened));
    assert_eq!(state("bb").unwrap().joined_at_ms, Some(10));
    assert_eq!(state("bb").unwrap().join_window_counted_ms, 12);

    // The announce closes the window, and time no longer counts toward it; a
    // new Welcome opens a fresh one and drops the earlier join and its
    // counted time, keeping the announce time.
    assert!(
        app.record_group_push_gossip_announce("bb", 20, None)
            .unwrap()
    );
    assert_eq!(state("bb").unwrap().joining_since_ms, None);
    assert_eq!(joining(), Vec::<String>::new());
    assert_eq!(app.count_push_join_window_time(5).unwrap(), 0);
    save(vec![group("aa", "created"), welcomed("bb", "w2")]);
    let reopened = state("bb").unwrap();
    assert!(reopened.joining_since_ms.is_some());
    assert_eq!(reopened.joined_at_ms, None);
    assert_eq!(reopened.join_window_counted_ms, 0);
    assert_eq!(reopened.last_announced_at_ms, Some(20));

    // A Welcome saved while this device is not a member opens nothing.
    save(vec![
        group("aa", "created"),
        welcomed("bb", "w2"),
        group("cc", "gone"),
    ]);
    app.set_group_self_membership("cc", SelfMembership::Removed)
        .unwrap();
    save(vec![
        group("aa", "created"),
        welcomed("bb", "w2"),
        welcomed("cc", "w3"),
    ]);
    assert_eq!(state("cc"), None);
}

/// An owed announce needs a joined group, and each new debt raises it past
/// the last, even with an earlier clock. A published announce settles it only
/// while it holds the value the announce was built under; a replay of the
/// Welcome keeps it, and a new Welcome drops it.
#[test]
fn an_owed_push_announce_lasts_until_an_announce_built_under_it_or_a_new_welcome() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let save = |welcome: &str| {
        let mut welcomed = group("aa", "welcomed");
        welcomed.via_welcome_message_id_hex = Some(welcome.to_owned());
        app.save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                seen_events: Vec::new(),
                last_transport_timestamp: None,
                groups: vec![welcomed],
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    };
    let owed = || {
        app.group_push_gossip_state("aa")
            .unwrap()
            .unwrap()
            .announce_owed_at_ms
    };
    let owing = || {
        app.owed_group_push_announce_states()
            .unwrap()
            .into_iter()
            .map(|state| state.group_id_hex)
            .collect::<Vec<_>>()
    };
    assert_eq!(app.record_group_push_announce_owed("aa", 10).unwrap(), None);
    save("w1");
    assert_eq!(owed(), None);
    assert!(owing().is_empty());

    assert_eq!(
        app.record_group_push_announce_owed("aa", 10).unwrap(),
        Some(10)
    );
    assert_eq!(
        app.record_group_push_announce_owed("aa", 30).unwrap(),
        Some(30)
    );
    assert_eq!(
        app.record_group_push_announce_owed("aa", 5).unwrap(),
        Some(31),
        "a debt recorded after a clock step back still raises it"
    );
    assert_eq!(owing(), vec!["aa".to_owned()]);
    save("w1");
    assert_eq!(owed(), Some(31), "a replayed Welcome keeps it");

    assert!(
        app.record_group_push_gossip_announce("aa", 20, Some(30))
            .unwrap()
    );
    assert_eq!(
        owed(),
        Some(31),
        "an announce built before the last debt settles nothing"
    );
    assert!(
        app.record_group_push_gossip_announce("aa", 25, None)
            .unwrap()
    );
    assert_eq!(owed(), Some(31));
    assert!(
        app.record_group_push_gossip_announce("aa", 26, Some(31))
            .unwrap()
    );
    assert_eq!(owed(), None);
    assert!(owing().is_empty());

    assert!(
        app.record_group_push_announce_owed("aa", 40)
            .unwrap()
            .is_some()
    );
    save("w2");
    assert_eq!(owed(), None, "a new Welcome drops it");
}

/// An owed push snapshot needs a joined group, keeps the latest owed epoch,
/// is replaced or settled only while it still holds the expected epoch, and
/// ends with the membership.
#[test]
fn push_snapshot_owed_keeps_the_latest_add_for_the_current_membership() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let owed = |group: &str| {
        app.group_push_gossip_state(group)
            .unwrap()
            .and_then(|state| state.snapshot_owed_after_epoch)
    };
    let owed_groups = || {
        app.owed_group_push_snapshots()
            .unwrap()
            .into_iter()
            .map(|state| (state.group_id_hex, state.snapshot_owed_after_epoch))
            .collect::<Vec<_>>()
    };
    assert!(!app.record_group_push_snapshot_owed("aa", 1).unwrap());
    app.save_account_projection_state(
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
    assert_eq!(owed_groups(), Vec::new());

    // An announce row owes nothing; recording keeps the other columns.
    assert!(app.record_group_push_gossip_join("aa", 10).unwrap());
    assert_eq!(owed("aa"), None);
    assert!(app.record_group_push_snapshot_owed("aa", 5).unwrap());
    assert!(app.record_group_push_snapshot_owed("aa", 3).unwrap());
    assert_eq!(owed("aa"), Some(5));
    assert_eq!(
        app.group_push_gossip_state("aa")
            .unwrap()
            .unwrap()
            .joined_at_ms,
        Some(10)
    );
    assert!(
        app.record_group_push_snapshot_owed("bb", u64::MAX >> 1)
            .unwrap()
    );
    assert_eq!(
        owed_groups(),
        vec![
            ("aa".to_owned(), Some(5)),
            ("bb".to_owned(), Some(u64::MAX >> 1))
        ]
    );
    assert_fails_with(
        app.record_group_push_snapshot_owed("bb", u64::MAX),
        "value does not fit in sqlite INTEGER",
    );

    // A stale expectation changes nothing; a current one restores or settles.
    assert!(!app.replace_group_push_snapshot_owed("aa", 4, None).unwrap());
    assert_eq!(owed("aa"), Some(5));
    assert!(
        app.replace_group_push_snapshot_owed("aa", 5, Some(2))
            .unwrap()
    );
    assert_eq!(owed("aa"), Some(2));
    assert!(app.replace_group_push_snapshot_owed("aa", 2, None).unwrap());
    assert_eq!(owed("aa"), None);
    assert!(!app.replace_group_push_snapshot_owed("cc", 0, None).unwrap());
    assert_eq!(owed_groups(), vec![("bb".to_owned(), Some(u64::MAX >> 1))]);

    assert!(app.record_group_push_snapshot_owed("aa", 7).unwrap());
    app.set_group_self_membership("aa", SelfMembership::Left)
        .unwrap();
    assert_eq!(owed("aa"), None);
    assert!(!app.record_group_push_snapshot_owed("aa", 8).unwrap());
    store.delete_local_group_data("bb").unwrap();
    assert_eq!(owed_groups(), Vec::new());
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
            .app_storage()
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
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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
            kinds: None,
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

#[test]
fn seen_event_pruning_edges() {
    for capacity in [0, 1, 3, 8] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute_batch(
                "INSERT INTO seen_events(rowid, event_id, seen_at) VALUES
                 (2, 'old', 1), (5, 'tie-first', 9), (11, 'tie-last', 9);",
            )
            .unwrap();
        }
        store
            .app_storage()
            .save_account_projection_state(
                &StoredAccountState {
                    label: "alice".to_owned(),
                    ..StoredAccountState::default()
                },
                capacity,
                MAX_FUTURE_SKEW_SECS,
            )
            .unwrap();
        let restored = store
            .app_storage()
            .load_account_projection_state("alice", 8)
            .unwrap();
        let expected = ["old", "tie-first", "tie-last"];
        assert_eq!(
            restored.seen_events,
            expected[3_usize.saturating_sub(capacity)..]
        );
    }
}

#[test]
fn seen_event_prune_query_work() {
    use rusqlite::StatementStatus;
    use rusqlite::trace::{TraceEvent, TraceEventCodes};
    use std::sync::Mutex;

    static PRUNE_SQL: Mutex<String> = Mutex::new(String::new());
    let store = SqliteAccountStorage::in_memory().unwrap();
    store.lock().unwrap().trace_v2(
        TraceEventCodes::SQLITE_TRACE_PROFILE,
        Some(|event| {
            let TraceEvent::Profile(statement, _) = event else {
                return;
            };
            if statement.sql().starts_with("DELETE FROM seen_events") {
                *PRUNE_SQL.lock().unwrap() = statement.sql().into_owned();
            }
        }),
    );
    store
        .app_storage()
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                ..StoredAccountState::default()
            },
            0,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    let conn = store.lock().unwrap();
    conn.trace_v2(TraceEventCodes::empty(), None);
    let production_sql = PRUNE_SQL.lock().unwrap().clone();
    assert!(!production_sql.is_empty());
    // Compare the old schema/query with the migrated schema and actual API SQL.
    for capacity in [256, 4_096, 16_384] {
        conn.execute_batch("DELETE FROM seen_events; DROP INDEX idx_seen_events_recency;")
            .unwrap();
        conn.execute(
            "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x < ?1)
             INSERT INTO seen_events(event_id, seen_at) SELECT printf('%064x', x), x/8 FROM n",
            params![capacity],
        )
        .unwrap();
        let legacy_sql = "DELETE FROM seen_events WHERE event_id NOT IN (
            SELECT event_id FROM seen_events ORDER BY seen_at DESC, rowid DESC LIMIT ?1)";
        let mut measurements = Vec::new();
        for sql in [legacy_sql, production_sql.as_str()] {
            if sql == production_sql {
                conn.execute_batch("CREATE INDEX idx_seen_events_recency ON seen_events(seen_at);")
                    .unwrap();
            }
            let mut statement = conn.prepare(sql).unwrap();
            let start = std::time::Instant::now();
            for _ in 0..20 {
                conn.execute_batch("SAVEPOINT bench").unwrap();
                assert_eq!(statement.execute(params![capacity]).unwrap(), 1);
                conn.execute_batch("ROLLBACK TO bench; RELEASE bench")
                    .unwrap();
            }
            measurements.push((
                statement.get_status(StatementStatus::VmStep) / 20,
                start.elapsed() / 20,
            ));
            if sql == production_sql {
                assert_eq!(statement.get_status(StatementStatus::Sort), 0);
            }
        }
        assert!(
            measurements[0].0 > measurements[1].0 * 5,
            "seen prune capacity={capacity}: old={:?}, new={:?} (VM steps, elapsed)",
            measurements[0],
            measurements[1]
        );
    }
}

#[test]
fn forget_group_local_is_atomic_and_prevents_protocol_resurrection() {
    use cgka_traits::storage::GroupStorage;
    let store = SqliteAccountStorage::in_memory().unwrap();
    let state = StoredAccountState {
        label: "alice".into(),
        seen_events: vec![],
        last_transport_timestamp: None,
        groups: vec![group("aa", "forgotten"), group("bb", "kept")],
    };
    store
        .app_storage()
        .save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    insert_protocol_group_marker(&store, &[0xaa]);
    insert_protocol_group_marker(&store, &[0xbb]);
    store
        .app_storage()
        .record_app_event(&app_event("msg-aa", "aa", 10))
        .unwrap();
    assert!(
        store
            .app_storage()
            .insert_device_group(&crate::DeviceGroupRecord {
                group_id_hex: "aa".into(),
                trust: crate::DeviceGroupTrust::Untrusted,
                key_package_ref_hex: None,
                recorded_at: 1,
            })
            .unwrap()
    );
    store
        .lock()
        .unwrap()
        .execute_batch(
            "INSERT INTO pending_push_registration_removals (
            group_id_hex, account_label, account_id_hex, platform, token_fingerprint,
            server_pubkey_hex, registration_created_at_ms, registration_updated_at_ms, queued_at_ms
         ) VALUES ('aa', 'alice', 'account', 1, 'token', 'server', 0, 0, 0);",
        )
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_forget BEFORE DELETE ON cgka_groups
         WHEN OLD.id = x'aa' BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    let id = cgka_traits::GroupId::new(vec![0xaa]);
    assert_fails_with(
        store.forget_group_local(&id, cgka_traits::Timestamp(100)),
        "injected failure",
    );
    assert!(!store.is_group_forgotten(&id).unwrap());
    assert!(store.list_groups().unwrap().contains(&id));
    assert!(store.app_storage().device_group("aa").unwrap().is_some());
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM app_events WHERE group_id_hex = 'aa'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    store
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_forget")
        .unwrap();
    assert!(
        store
            .forget_group_local(&id, cgka_traits::Timestamp(100))
            .unwrap()
    );
    assert!(
        !store
            .forget_group_local(&id, cgka_traits::Timestamp(100))
            .unwrap()
    );
    assert!(store.is_group_forgotten(&id).unwrap());
    assert!(store.app_storage().device_group("aa").unwrap().is_none());
    assert!(
        store
            .app_storage()
            .pending_push_registration_removals()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.list_groups().unwrap(),
        vec![cgka_traits::GroupId::new(vec![0xbb])]
    );
    assert!(
        store
            .app_storage()
            .local_group_deletion_frontier("aa")
            .unwrap()
            .is_none()
    );
    store
        .app_storage()
        .save_account_projection_state(&state, 16, MAX_FUTURE_SKEW_SECS)
        .unwrap();
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM account_groups WHERE group_id_hex = 'aa'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0,
        "a stale app snapshot cannot restore the chat"
    );
    assert_fails_with(
        store.lock().unwrap().execute(
            "INSERT INTO cgka_groups(id, epoch, record) VALUES (x'aa', 0, x'00')",
            [],
        ),
        "group awaiting fresh welcome",
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM account_groups WHERE group_id_hex = 'bb'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn group_reset_completion_rolls_back_and_keeps_replay_cutoff_after_rejoin() {
    use cgka_traits::storage::{GroupStorage, StorageProvider};
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let id = cgka_traits::GroupId::new(vec![0xaa]);
    app.save_account_projection_state(
        &StoredAccountState {
            label: "alice".into(),
            groups: vec![group("aa", "old membership")],
            ..Default::default()
        },
        16,
        MAX_FUTURE_SKEW_SECS,
    )
    .unwrap();
    assert!(
        store
            .forget_group_local(&id, cgka_traits::Timestamp(100))
            .unwrap()
    );
    assert!(
        !store
            .forget_group_local(&id, cgka_traits::Timestamp(200))
            .unwrap()
    );
    assert_eq!(
        store.group_local_reset_cutoff(&id).unwrap(),
        Some(cgka_traits::Timestamp(100))
    );
    assert!(
        !app.encrypted_media_epoch_secret_may_be_served("aa", 1)
            .unwrap()
    );
    let failed: Result<(), StorageError> = store.with_transaction(|storage| {
        storage.complete_group_local_reset(&id)?;
        insert_protocol_group_marker(storage, id.as_slice());
        Err(StorageError::Backend("injected join failure".into()))
    });
    assert_fails_with(failed, "injected join failure");
    assert!(
        !app.encrypted_media_epoch_secret_may_be_served("aa", 1)
            .unwrap()
    );
    assert!(store.is_group_forgotten(&id).unwrap());
    assert!(store.list_groups().unwrap().is_empty());
    store
        .with_transaction::<_, StorageError, _>(|storage| {
            storage.complete_group_local_reset(&id)?;
            insert_protocol_group_marker(storage, id.as_slice());
            Ok(())
        })
        .unwrap();
    assert!(!store.is_group_forgotten(&id).unwrap());
    assert!(
        app.encrypted_media_epoch_secret_may_be_served("aa", 1)
            .unwrap()
    );
    assert_eq!(
        store.group_local_reset_cutoff(&id).unwrap(),
        Some(cgka_traits::Timestamp(100))
    );
    assert!(store.list_groups().unwrap().contains(&id));
    // A second reset cannot move the boundary backward if the local clock regresses.
    assert!(
        store
            .forget_group_local(&id, cgka_traits::Timestamp(90))
            .unwrap()
    );
    assert_eq!(
        store.group_local_reset_cutoff(&id).unwrap(),
        Some(cgka_traits::Timestamp(100))
    );
}

#[test]
fn secure_prune_scrubs_retained_edit_copies_before_reprojection() {
    for expiry in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("edits.sqlite");
        let options = crate::SqliteStorageOptions {
            secure_delete: false,
            ..Default::default()
        };
        let store = open_plaintext_file(&path, options.clone());
        let app = store.app_storage();
        app.save_account_projection_state(
            &StoredAccountState {
                label: "alice".into(),
                seen_events: vec![],
                last_transport_timestamp: None,
                groups: vec![group("aa", "edits")],
            },
            16,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
        let mut target = app_event("target", "aa", 100);
        target.plaintext = "retained original".into();
        app.record_app_event(&target).unwrap();
        let secret = "accepted-edit-prune-secret-1864-unique";
        let mut edit = app_event("edit", "aa", 10);
        edit.kind = 1009;
        edit.plaintext = secret.into();
        edit.tags = vec![vec!["e".into(), "target".into()]];
        app.record_app_event_with_retention(&edit, Some(AppMessageRetentionDecision::new(10, 5)))
            .unwrap();
        app.refresh_chat_list_row("local", "aa", &no_mentions)
            .unwrap();
        assert_eq!(
            app.timeline_message("aa", "target")
                .unwrap()
                .unwrap()
                .plaintext,
            secret
        );
        checkpoint_and_truncate_wal(&store);
        drop(app);
        drop(store);
        assert!(file_contains(&path, secret.as_bytes()));
        let store = open_plaintext_file(&path, options);
        let app = store.app_storage();
        {
            // TEMP objects belong to one connection, so they are created after the reopen.
            let conn = store.lock().unwrap();
            conn.execute_batch("CREATE TEMP TABLE scrub_audit (surface TEXT, prior BLOB);
                CREATE TEMP TRIGGER audit_target_restore BEFORE UPDATE ON message_timeline
                WHEN OLD.message_id_hex='target' AND NEW.plaintext='retained original'
                  AND OLD.plaintext IS NOT NEW.plaintext
                BEGIN INSERT INTO scrub_audit VALUES ('timeline',CAST(OLD.plaintext AS BLOB)); END;
                CREATE TEMP TRIGGER audit_preview_restore BEFORE UPDATE ON chat_list_rows
                WHEN OLD.group_id_hex='aa' AND NEW.last_message_preview='retained original'
                  AND OLD.last_message_preview IS NOT NEW.last_message_preview
                BEGIN INSERT INTO scrub_audit VALUES ('preview',CAST(OLD.last_message_preview AS BLOB)); END;").unwrap();
        }
        let result = if expiry {
            app.secure_prune_expired_app_events("aa", 15, "local", &no_mentions)
        } else {
            app.secure_prune_app_events_before("aa", 15, "local", &no_mentions)
        }
        .unwrap();
        assert_eq!(result.pruned_messages, 1);
        assert!(!result.erasure_pending);
        let row = app.timeline_message("aa", "target").unwrap().unwrap();
        assert_eq!(row.plaintext, "retained original");
        assert!(row.edit.is_none());
        assert!(
            app.message_edit_history("aa", "target", None, 10)
                .unwrap()
                .versions
                .is_empty()
        );
        {
            let conn = store.lock().unwrap();
            let mut stmt = conn
                .prepare("SELECT surface,prior FROM scrub_audit")
                .unwrap();
            let audit = stmt
                .query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(audit.len(), 2);
            for (surface, prior) in audit {
                assert!(
                    !prior.is_empty() && prior.iter().all(|b| *b == 0),
                    "{surface} must be scrubbed before restoring the retained target (expiry={expiry})"
                );
            }
            let secure_delete: i64 = conn
                .query_row("PRAGMA secure_delete", [], |r| r.get(0))
                .unwrap();
            assert_eq!(secure_delete, 0, "restore caller setting");
        }
        drop(app);
        drop(store);
        for file in [path.clone(), path.with_extension("sqlite-wal")] {
            if file.exists() {
                assert!(
                    !file_contains(&file, secret.as_bytes()),
                    "no pruned edit bytes in {file:?}"
                );
            }
        }
    }
}

/// A leaf departure keeps a rejoined device's identical token at its new leaf
/// and account tombstones. Losing the final leaf clears all account records,
/// including stale unknown indexes.
#[test]
fn leaf_cleanup_preserves_sibling_tombstones_until_account_departure() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let g = "aa".repeat(32);
    let m = "bb".repeat(32);
    let first = push_token(&g, &m, 100, "first");
    let mut sibling = first.clone();
    sibling.leaf_index = 1;
    store.apply_group_push_token(&first).unwrap();
    store.apply_group_push_token(&sibling).unwrap();
    assert_eq!(store.group_push_tokens(&g).unwrap().len(), 2);
    store
        .apply_group_push_token_tombstone(&AccountGroupPushTokenTombstone {
            server_pubkey_hex: "dd".repeat(32),
            ..push_tombstone(&g, &m, 2, 500, "withdrawn")
        })
        .unwrap();
    store
        .remove_group_push_tokens_for_leaves(&g, &[(m.clone(), 0)], &[])
        .unwrap();
    let tokens = store.group_push_tokens(&g).unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].leaf_index, 1);
    assert_eq!(tokens[0].token_fingerprint, first.token_fingerprint);
    let mut old = push_token(&g, &m, 100, "old");
    old.leaf_index = 2;
    old.server_pubkey_hex = "dd".repeat(32);
    assert!(
        !store.apply_group_push_token(&old).unwrap(),
        "surviving account retains anti-resurrection evidence"
    );
    let mut stale = sibling.clone();
    stale.leaf_index = 99;
    stale.token_fingerprint = "stale".into();
    store.apply_group_push_token(&stale).unwrap();
    store
        .remove_group_push_tokens_for_leaves(&g, &[(m.clone(), 1)], std::slice::from_ref(&m))
        .unwrap();
    assert!(store.group_push_tokens(&g).unwrap().is_empty());
    assert!(
        store.apply_group_push_token(&old).unwrap(),
        "full account departure clears its tombstones"
    );
}

/// Hydration reconciles exact account/leaf pairs atomically and keeps sibling
/// tombstones, even when a native departure announcement was lost.
#[test]
fn canonical_push_leaf_reconciliation_is_atomic_and_account_scoped() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let g = "aa".repeat(32);
    let m = "bb".repeat(32);
    let peer = "cc".repeat(32);
    let other_group = "ee".repeat(32);
    let departed = push_token(&g, &m, 100, "departed");
    let mut sibling = departed.clone();
    sibling.leaf_index = 1;
    let peer_token = push_token(&g, &peer, 100, "peer");
    let other_token = push_token(&other_group, &m, 100, "other");
    for token in [&departed, &sibling, &peer_token, &other_token] {
        app.apply_group_push_token(token).unwrap();
    }
    let mut old = push_token(&g, &m, 100, "old");
    old.leaf_index = 2;
    old.server_pubkey_hex = "dd".repeat(32);
    app.apply_group_push_token_tombstone(&AccountGroupPushTokenTombstone {
        server_pubkey_hex: old.server_pubkey_hex.clone(),
        ..push_tombstone(&g, &m, 2, 500, "withdrawn")
    })
    .unwrap();
    app.apply_group_push_token_tombstone(&AccountGroupPushTokenTombstone {
        server_pubkey_hex: old.server_pubkey_hex.clone(),
        ..push_tombstone(&g, &peer, 2, 500, "peer-withdrawn")
    })
    .unwrap();
    store
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_leaf_reconcile BEFORE DELETE ON group_push_token_tombstones
         BEGIN SELECT RAISE(FAIL, 'injected tombstone cleanup failure'); END;",
        )
        .unwrap();
    let roster = [(m.clone(), 1)];
    assert_fails_with(
        app.reconcile_group_push_token_leaves(&g, &roster),
        "injected tombstone cleanup failure",
    );
    assert_eq!(
        app.group_push_tokens(&g).unwrap().len(),
        3,
        "token deletes roll back with tombstones"
    );
    store
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_leaf_reconcile")
        .unwrap();
    assert_eq!(
        app.reconcile_group_push_token_leaves(&g, &roster).unwrap(),
        2
    );
    assert_eq!(app.group_push_tokens(&g).unwrap(), vec![sibling]);
    assert_eq!(
        app.group_push_tokens(&other_group).unwrap(),
        vec![other_token]
    );
    assert!(
        !app.apply_group_push_token(&old).unwrap(),
        "surviving sibling retains tombstones"
    );
    let mut old_peer = old.clone();
    old_peer.member_id_hex = peer;
    assert!(
        app.apply_group_push_token(&old_peer).unwrap(),
        "fully departed account drops tombstones"
    );
    assert_eq!(
        app.reconcile_group_push_token_leaves(&g, &roster).unwrap(),
        1
    );
    assert_eq!(
        app.reconcile_group_push_token_leaves(&g, &roster).unwrap(),
        0
    );
}

fn hex_id(byte: u8, len: usize) -> String {
    hex::encode(vec![byte; len])
}

fn direct_group(group_id_hex: &str, local: &str, peer: &str) -> StoredAccountGroup {
    StoredAccountGroup {
        member_count: Some(2),
        direct_member_ids_hex: Some(vec![local.to_owned(), peer.to_owned()]),
        ..group(group_id_hex, "")
    }
}

#[test]
fn fill_unindexed_direct_conversation_members_does_not_clobber_newer_rows() {
    let local = hex_id(0xaa, 32);
    let old_peer = hex_id(0xbb, 32);
    let new_peer = hex_id(0xcc, 32);
    let group_id = hex_id(0x11, 16);
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![direct_group(&group_id, &local, &old_peer)],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    store
        .replace_direct_conversation_members(&group_id, &[local.clone(), new_peer.clone()])
        .unwrap();
    assert!(
        !store
            .fill_unindexed_direct_conversation_members(
                &group_id,
                &[local.clone(), old_peer.clone()]
            )
            .unwrap(),
        "a later projection save must win over a stale backfill write"
    );
    store.refresh_chat_list_rows(&local, &no_mentions).unwrap();
    assert_eq!(
        store
            .direct_conversation_candidate_rows(&new_peer)
            .unwrap()
            .iter()
            .map(|row| row.group_id_hex.as_str())
            .collect::<Vec<_>>(),
        vec![group_id.as_str()]
    );
    assert!(
        store
            .direct_conversation_candidate_rows(&old_peer)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn fill_unindexed_direct_conversation_members_writes_when_empty() {
    let local = hex_id(0xaa, 32);
    let peer = hex_id(0xbb, 32);
    let group_id = hex_id(0x11, 16);
    let mut unindexed = direct_group(&group_id, &local, &peer);
    unindexed.direct_member_ids_hex = None;
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![unindexed],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    store.refresh_chat_list_rows(&local, &no_mentions).unwrap();
    assert_eq!(
        store.unindexed_direct_conversation_group_ids().unwrap(),
        vec![group_id.clone()]
    );
    assert!(
        store
            .fill_unindexed_direct_conversation_members(&group_id, &[local.clone(), peer.clone()])
            .unwrap()
    );
    assert_eq!(
        store
            .direct_conversation_candidate_rows(&peer)
            .unwrap()
            .iter()
            .map(|row| row.group_id_hex.as_str())
            .collect::<Vec<_>>(),
        vec![group_id.as_str()]
    );
}

#[test]
fn reset_direct_conversation_members_backfill_clears_index_and_marker() {
    let local = hex_id(0xaa, 32);
    let peer = hex_id(0xbb, 32);
    let group_id = hex_id(0x11, 16);
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![direct_group(&group_id, &local, &peer)],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    store.refresh_chat_list_rows(&local, &no_mentions).unwrap();
    store
        .mark_account_import_complete("direct-conversation-members-backfill-v1")
        .unwrap();
    assert!(
        !store
            .direct_conversation_candidate_rows(&peer)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .account_import_marker("direct-conversation-members-backfill-v1")
            .unwrap()
    );

    store
        .reset_direct_conversation_members_backfill("direct-conversation-members-backfill-v1")
        .unwrap();

    assert!(
        store
            .direct_conversation_candidate_rows(&peer)
            .unwrap()
            .is_empty()
    );
    assert!(
        !store
            .account_import_marker("direct-conversation-members-backfill-v1")
            .unwrap()
    );
    assert_eq!(
        store.unindexed_direct_conversation_group_ids().unwrap(),
        vec![group_id]
    );
}

#[test]
fn persist_direct_index_follows_two_member_ids_not_stale_count() {
    let local = hex_id(0xaa, 32);
    let peer = hex_id(0xbb, 32);
    let extra = hex_id(0xcc, 32);
    let group_id = hex_id(0x11, 16);
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();

    let mut stale_count = direct_group(&group_id, &local, &peer);
    stale_count.member_count = Some(3);
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![stale_count],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    store.refresh_chat_list_rows(&local, &no_mentions).unwrap();
    let loaded = store
        .load_account_projection_state("alice", 16)
        .unwrap()
        .groups
        .into_iter()
        .find(|group| group.group_id_hex == group_id)
        .expect("stale-count group");
    let mut loaded_members = loaded.direct_member_ids_hex.expect("persisted members");
    loaded_members.sort();
    let mut expected_members = vec![local.clone(), peer.clone()];
    expected_members.sort();
    assert_eq!(
        loaded_members, expected_members,
        "empty-name projections with exactly two member ids must persist the index"
    );

    let mut stale_ids = direct_group(&group_id, &local, &peer);
    stale_ids.direct_member_ids_hex = Some(vec![local.clone(), peer.clone(), extra]);
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![stale_ids],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    store.refresh_chat_list_rows(&local, &no_mentions).unwrap();
    assert!(
        store
            .direct_conversation_candidate_rows(&peer)
            .unwrap()
            .is_empty(),
        "a three-member id slice must not persist the peer index"
    );
}

#[test]
fn replace_direct_conversation_members_rejects_non_two_member_slices() {
    let local = hex_id(0xaa, 32);
    let peer = hex_id(0xbb, 32);
    let extra = hex_id(0xcc, 32);
    let group_id = hex_id(0x11, 16);
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![direct_group(&group_id, &local, &peer)],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    store.refresh_chat_list_rows(&local, &no_mentions).unwrap();

    store
        .replace_direct_conversation_members(&group_id, std::slice::from_ref(&local))
        .unwrap();
    assert!(
        store
            .direct_conversation_candidate_rows(&peer)
            .unwrap()
            .is_empty()
    );

    store
        .replace_direct_conversation_members(&group_id, &[local.clone(), peer.clone(), extra])
        .unwrap();
    assert!(
        store
            .direct_conversation_candidate_rows(&peer)
            .unwrap()
            .is_empty()
    );

    store
        .replace_direct_conversation_members(&group_id, &[local.clone(), peer.clone()])
        .unwrap();
    assert_eq!(
        store
            .direct_conversation_candidate_rows(&peer)
            .unwrap()
            .iter()
            .map(|row| row.group_id_hex.as_str())
            .collect::<Vec<_>>(),
        vec![group_id.as_str()]
    );
}

#[test]
fn account_group_ids_defaulting_to_member_lists_only_default_rows() {
    // Backfill candidate set: rows still carrying the migration default
    // 'member' are returned; rows explicitly flipped to 'removed' are not, so
    // re-running the one-time backfill stays idempotent.
    let other_group = group("22", "Marmot Lab");
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![group("11", "Marmot Lab"), other_group],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();

    // Both rows start at the default 'member', so both are candidates.
    assert_eq!(
        store.account_group_ids_defaulting_to_member().unwrap(),
        vec!["11".to_owned(), "22".to_owned()]
    );

    // Once a row is flipped to 'removed' it drops out of the candidate set.
    store
        .set_group_self_membership("11", SelfMembership::Removed)
        .unwrap();
    assert_eq!(
        store.account_group_ids_defaulting_to_member().unwrap(),
        vec!["22".to_owned()]
    );

    // Re-affirming 'member' keeps a row in the candidate set (still default).
    store
        .set_group_self_membership("22", SelfMembership::Member)
        .unwrap();
    assert_eq!(
        store.account_group_ids_defaulting_to_member().unwrap(),
        vec!["22".to_owned()]
    );

    // No defaulted rows left once every row is explicitly resolved.
    store
        .set_group_self_membership("22", SelfMembership::Removed)
        .unwrap();
    assert!(
        store
            .account_group_ids_defaulting_to_member()
            .unwrap()
            .is_empty()
    );
}
