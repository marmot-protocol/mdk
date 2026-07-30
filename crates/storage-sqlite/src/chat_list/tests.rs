use super::*;
use crate::storage::test_support::sample_group;
use crate::{
    SelfMembership, SqlCipherKey, StoredAccountGroup, StoredAccountGroupComponent,
    StoredAccountState, StoredAppEvent,
};
use cgka_traits::app_components::{
    GROUP_AVATAR_URL_COMPONENT, GROUP_AVATAR_URL_COMPONENT_ID, GroupAvatarUrlV1,
    encode_group_avatar_url_v1,
};
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_REACTION,
};
use cgka_traits::storage::{GroupStorage, LeaveRequest, LeaveRequestStorage};
use cgka_traits::types::{EpochId, GroupId};

const LOCAL: &str = "aa";
const REMOTE: &str = "bb";
const GROUP: &str = "11";
const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;

fn group() -> StoredAccountGroup {
    StoredAccountGroup {
        group_id_hex: GROUP.to_owned(),
        endpoint: "relay".to_owned(),
        profile_name: "Marmot Lab".to_owned(),
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
        components: Vec::new(),
    }
}

fn chat(id: &str, sender: &str, at: u64, plaintext: &str) -> StoredAppEvent {
    chat_with_tags(id, sender, at, plaintext, Vec::new())
}

fn chat_with_tags(
    id: &str,
    sender: &str,
    at: u64,
    plaintext: &str,
    tags: Vec<Vec<String>>,
) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: GROUP.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: if sender == LOCAL { "sent" } else { "received" }.to_owned(),
        sender: sender.to_owned(),
        plaintext: plaintext.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags,
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
        moderation_grant: false,
    }
}

/// Classifier that never matches; used by tests that exercise unread counting
/// without caring about mention detection.
fn no_mentions(_plaintext: &str, _tags: &[Vec<String>]) -> bool {
    false
}

/// Test classifier independent of nostr parsing: a message mentions LOCAL when
/// it carries a `["p", LOCAL]` tag or names LOCAL inline in its plaintext. This
/// validates the counting/windowing logic while the real nostr/NIP-21 parsing
/// is unit-tested in marmot-app.
fn mentions_local(plaintext: &str, tags: &[Vec<String>]) -> bool {
    tags.iter().any(|tag| {
        tag.first().map(String::as_str) == Some("p")
            && tag.get(1).map(String::as_str) == Some(LOCAL)
    }) || plaintext.contains(LOCAL)
}

fn reaction(id: &str, sender: &str, target: &str, at: u64) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: GROUP.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: sender.to_owned(),
        plaintext: "+".to_owned(),
        kind: MARMOT_APP_EVENT_KIND_REACTION,
        tags: vec![vec![EVENT_REF_TAG.to_owned(), target.to_owned()]],
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
        moderation_grant: false,
    }
}

fn setup_store_with_group(group: StoredAccountGroup) -> SqliteAccountStorage {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![group],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    store
}

fn setup_store() -> SqliteAccountStorage {
    setup_store_with_group(group())
}

fn avatar_url_component(url: &str) -> StoredAccountGroupComponent {
    let bytes = encode_group_avatar_url_v1(&GroupAvatarUrlV1 {
        url: url.to_owned(),
        dim: Vec::new(),
        thumbhash: Vec::new(),
    })
    .unwrap();
    StoredAccountGroupComponent {
        component_id: GROUP_AVATAR_URL_COMPONENT_ID,
        component_name: GROUP_AVATAR_URL_COMPONENT.to_owned(),
        component_data_hex: hex::encode(bytes),
    }
}

#[test]
fn manual_unread_is_independent_durable_and_cleared_by_mark_read() {
    let store = setup_store();
    store
        .record_app_event(&chat("history", REMOTE, 10, "old history"))
        .unwrap();

    // Creating manual state preserves the implicit-read baseline instead of
    // turning retained history into unread incoming messages.
    let mut row = store
        .set_chat_manually_unread(LOCAL, GROUP, true, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert!(row.manually_marked_unread);
    assert!(row.has_unread);
    assert_eq!(row.unread_count, 0);
    assert_eq!(store.account_unread_total().unwrap().unread_count, 0);
    assert_eq!(
        store.account_unread_total().unwrap().unread_conversations,
        1
    );

    store
        .record_app_event(&chat("incoming", REMOTE, 20, "new message"))
        .unwrap();
    row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert!(row.manually_marked_unread);
    assert_eq!(row.unread_count, 1);

    row = store
        .mark_timeline_message_read(LOCAL, GROUP, "incoming", &no_mentions)
        .unwrap()
        .expect("chat row");
    assert!(!row.manually_marked_unread);
    assert!(!row.has_unread);
    assert_eq!(row.unread_count, 0);

    // Re-read from the durable projection, not the mutation return value.
    let reopened = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert!(!reopened.manually_marked_unread);
}

#[test]
fn manual_unread_without_history_keeps_the_first_later_delivery_unread() {
    let store = setup_store();
    let row = store
        .set_chat_manually_unread(LOCAL, GROUP, true, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert!(row.manually_marked_unread);
    assert_eq!(row.unread_count, 0);

    // Sender timestamps can predate the local wall clock. With no prior
    // message there is no durable read anchor, so this first later-recorded
    // delivery must not be hidden behind the time of the local mark-unread.
    store
        .record_app_event(&chat("first-delivery", REMOTE, 20, "first"))
        .unwrap();
    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.unread_count, 1);
    assert!(row.manually_marked_unread);
    assert!(row.has_unread);
}

#[test]
fn clearing_manual_unread_does_not_move_the_message_marker() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat("incoming", REMOTE, 20, "new message"))
        .unwrap();
    store
        .set_chat_manually_unread(LOCAL, GROUP, true, &no_mentions)
        .unwrap();

    let row = store
        .set_chat_manually_unread(LOCAL, GROUP, false, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert!(!row.manually_marked_unread);
    assert!(row.has_unread);
    assert_eq!(row.unread_count, 1);
    assert_eq!(row.first_unread_message_id_hex.as_deref(), Some("incoming"));
}

#[test]
fn chat_list_rows_join_effective_mute_without_per_row_queries() {
    let store = setup_store();
    store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();

    let until = unix_now_ms() + 60_000;
    store.set_chat_muted(GROUP, Some(until)).unwrap();
    let timed = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert!(timed.muted);
    assert_eq!(timed.muted_until_ms, Some(until));

    store.set_chat_muted(GROUP, None).unwrap();
    let indefinite = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert!(indefinite.muted);
    assert_eq!(indefinite.muted_until_ms, None);

    store
        .set_chat_muted(GROUP, Some(unix_now_ms() - 1))
        .unwrap();
    let expired = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert!(!expired.muted);
    assert_eq!(expired.muted_until_ms, None);

    store.clear_chat_muted(GROUP).unwrap();
    let cleared = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert!(!cleared.muted);
    assert_eq!(cleared.muted_until_ms, None);
}

#[test]
fn conversation_kind_uses_durable_current_roster_projection() {
    let mut direct = group();
    direct.profile_name.clear();
    direct.member_count = Some(2);
    let store = setup_store_with_group(direct);
    store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
    assert_eq!(
        store
            .chat_list_row(GROUP)
            .unwrap()
            .expect("chat row")
            .conversation_kind,
        ChatConversationKind::Direct
    );

    let mut expanded = group();
    expanded.profile_name.clear();
    expanded.member_count = Some(3);
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![expanded],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    assert_eq!(
        store
            .chat_list_row(GROUP)
            .unwrap()
            .expect("chat row")
            .conversation_kind,
        ChatConversationKind::Group
    );

    let mut legacy = group();
    legacy.profile_name.clear();
    legacy.member_count = None;
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![legacy],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    assert_eq!(
        store
            .chat_list_row(GROUP)
            .unwrap()
            .expect("chat row")
            .conversation_kind,
        ChatConversationKind::Unknown
    );
}

#[test]
fn latest_preview_carries_exact_media_and_delivery_projection() {
    let store = setup_store();
    let mut pending = chat_with_tags(
        "pending",
        LOCAL,
        10,
        "",
        vec![vec!["imeta".to_owned(), "m image/png".to_owned()]],
    );
    pending.source_message_id_hex = None;
    store.record_app_event(&pending).unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    let preview = row.last_message.expect("latest preview");
    assert_eq!(preview.message_id_hex, "pending");
    assert_eq!(
        preview.delivery_state,
        ChatListMessageDeliveryState::Pending
    );
    assert!(preview.media_json.is_some());

    store
        .invalidate_app_event_by_message_id(GROUP, "pending", "local_publish_failed")
        .unwrap();
    let failed = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row")
        .last_message
        .expect("failed preview");
    assert_eq!(failed.message_id_hex, "pending");
    assert_eq!(failed.delivery_state, ChatListMessageDeliveryState::Failed);

    // A successful retry re-records the same durable app event with its MLS
    // source id, clearing the local publish invalidation. The chat row must
    // transition that exact preview back to delivered rather than waiting for
    // a different message to replace it.
    pending.source_message_id_hex = Some("source-after-retry".to_owned());
    store.record_app_event(&pending).unwrap();
    let retried = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row")
        .last_message
        .expect("retried preview");
    assert_eq!(retried.message_id_hex, "pending");
    assert_eq!(
        retried.delivery_state,
        ChatListMessageDeliveryState::Delivered
    );

    store
        .record_app_event(&chat("delivered", LOCAL, 20, "replacement"))
        .unwrap();
    let delivered = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row")
        .last_message
        .expect("delivered preview");
    assert_eq!(delivered.message_id_hex, "delivered");
    assert_eq!(
        delivered.delivery_state,
        ChatListMessageDeliveryState::Delivered
    );
}

#[test]
fn never_messaged_rows_sort_by_creation_then_group_id_across_rebuilds() {
    let second_group = StoredAccountGroup {
        group_id_hex: "22".to_owned(),
        profile_name: "Second".to_owned(),
        ..group()
    };
    let tied_group = StoredAccountGroup {
        group_id_hex: "33".to_owned(),
        profile_name: "Tied".to_owned(),
        ..group()
    };
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![group(), second_group, tied_group],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "UPDATE account_groups
             SET conversation_created_at = CASE group_id_hex
                 WHEN ?1 THEN 100
                 WHEN ?2 THEN 200
                 WHEN ?3 THEN 100
             END",
            params![GROUP, "22", "33"],
        )
        .unwrap();
    }

    store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let before = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap();
    assert_eq!(
        before
            .iter()
            .map(|row| row.group_id_hex.as_str())
            .collect::<Vec<_>>(),
        vec!["22", GROUP, "33"]
    );
    assert_eq!(before[0].conversation_created_at, 200);
    assert_eq!(before[0].activity_sort_at, 200);
    assert_eq!(before[1].conversation_created_at, 100);
    assert_eq!(before[1].activity_sort_at, 100);

    let semantic_before = before
        .iter()
        .map(|row| {
            (
                row.group_id_hex.clone(),
                row.conversation_created_at,
                row.activity_sort_at,
            )
        })
        .collect::<Vec<_>>();
    {
        let conn = store.lock().unwrap();
        conn.execute("UPDATE chat_list_rows SET updated_at = 4000000000", [])
            .unwrap();
    }
    store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let after = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap();
    let semantic_after = after
        .iter()
        .map(|row| {
            (
                row.group_id_hex.clone(),
                row.conversation_created_at,
                row.activity_sort_at,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(semantic_after, semantic_before);
}

#[test]
fn initialize_chat_read_state_returns_none_for_unknown_group() {
    let store = setup_store();

    let row = store
        .initialize_chat_read_state(LOCAL, "missing-group", &no_mentions)
        .unwrap();

    assert_eq!(row, None);
}

#[test]
fn visible_activity_survives_read_metadata_membership_and_secure_prune_updates() {
    for mark_read in [false, true] {
        let store = setup_store();
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "UPDATE account_groups SET conversation_created_at = 5 WHERE group_id_hex = ?1",
                params![GROUP],
            )
            .unwrap();
        }
        store
            .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
            .unwrap();
        store
            .record_app_event(&chat("visible", REMOTE, 100, "semantic activity"))
            .unwrap();
        let mut row = store
            .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
            .unwrap()
            .expect("chat row");
        assert_eq!(row.conversation_created_at, 5);
        assert_eq!(row.activity_sort_at, 100);
        assert_eq!(row.unread_count, 1);

        if mark_read {
            row = store
                .mark_timeline_message_read(LOCAL, GROUP, "visible", &no_mentions)
                .unwrap()
                .expect("chat row");
            assert_eq!(row.unread_count, 0);
            assert_eq!(row.activity_sort_at, 100);
        }

        let mut renamed = group();
        renamed.profile_name = "Renamed Lab".to_owned();
        renamed
            .components
            .push(avatar_url_component("https://cdn.example.com/new.png"));
        store
            .save_account_projection_state(
                &StoredAccountState {
                    label: "alice".to_owned(),
                    groups: vec![renamed],
                    ..StoredAccountState::default()
                },
                256,
                MAX_FUTURE_SKEW_SECS,
            )
            .unwrap();
        store
            .set_group_self_membership(GROUP, SelfMembership::Removed)
            .unwrap();
        row = store
            .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
            .unwrap()
            .expect("chat row");
        assert_eq!(row.conversation_created_at, 5);
        assert_eq!(row.activity_sort_at, 100);

        store
            .secure_prune_app_events_before(GROUP, 101, LOCAL, &no_mentions)
            .unwrap();
        row = store.chat_list_row(GROUP).unwrap().expect("chat row");
        assert_eq!(row.last_message, None);
        assert_eq!(row.unread_count, 0);
        assert_eq!(row.unread_mention_count, 0);
        assert_eq!(row.first_unread_message_id_hex, None);
        assert_eq!(row.activity_sort_at, 100);

        if mark_read {
            // A read cursor is durable source history: even if projection repair
            // must recreate the row after pruning, it recovers the last visible
            // activity rather than falling back to conversation creation.
            let conn = store.lock().unwrap();
            conn.execute(
                "DELETE FROM chat_list_rows WHERE group_id_hex = ?1",
                params![GROUP],
            )
            .unwrap();
        }
        store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
        row = store.chat_list_row(GROUP).unwrap().expect("chat row");
        assert_eq!(row.last_message, None);
        assert_eq!(row.conversation_created_at, 5);
        assert_eq!(row.activity_sort_at, 100);

        store
            .record_app_event(&chat("new-visible", REMOTE, 200, "new activity"))
            .unwrap();
        row = store
            .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
            .unwrap()
            .expect("chat row");
        assert_eq!(row.activity_sort_at, 200);

        store
            .invalidate_app_event_by_message_id(GROUP, "new-visible", "LosingBranch")
            .unwrap();
        row = store
            .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
            .unwrap()
            .expect("chat row");
        assert_eq!(row.last_message, None);
        assert_eq!(row.activity_sort_at, 100);
    }
}

#[test]
fn retained_pruned_anchor_survives_a_real_rebuild_cycle() {
    // A securely pruned message leaves an explicit internal retained-activity
    // floor. This proves the compatibility seam between that durable floor and
    // `rebuild_chat_list_row_for_group_tx`: a retained anchor whose preview has
    // been pruned must survive a real `refresh_chat_list_rows` cycle rather than
    // being overwritten with the conversation-creation fallback.
    let store = setup_store();

    // Emulate the post-prune state directly: the public and retained anchors are
    // 350 and creation is 5, but there is no kind-9 preview in the timeline.
    // A read cursor at 300 is the only other durable history below the anchor.
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "UPDATE account_groups SET conversation_created_at = 5 WHERE group_id_hex = ?1",
            params![GROUP],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO conversation_read_state (
                group_id_hex, last_read_message_id_hex, last_read_timeline_at,
                initialized_at, updated_at
             ) VALUES (?1, 'pruned-message', 300, 0, 300)",
            params![GROUP],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_list_rows (
                group_id_hex, conversation_created_at, activity_sort_at,
                retained_activity_sort_at, updated_at
             ) VALUES (?1, 5, 350, 350, 500)",
            params![GROUP],
        )
        .unwrap();
    }

    // A full rebuild (app warm-up path) must retain the migrated anchor: the
    // preview is gone but its durable position stays, and the recompute floor
    // (max(read cursor 300, creation 5) = 300) does not lower it.
    store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let row = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert_eq!(row.last_message, None);
    assert_eq!(row.conversation_created_at, 5);
    assert_eq!(row.activity_sort_at, 350);

    // The completeness check must treat the retained-then-rebuilt row as current,
    // so ensure is a no-op rather than perpetually rebuilding.
    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let after_ensure = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert_eq!(after_ensure.activity_sort_at, 350);

    // Now introduce a visible message strictly above the retained anchor; the
    // rebuild must advance to it, proving preservation is a floor, not a freeze.
    store
        .record_app_event(&chat("newer", REMOTE, 400, "newer activity"))
        .unwrap();
    let advanced = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(advanced.activity_sort_at, 400);
}

#[test]
fn refresh_chat_list_row_returns_refreshed_single_group_projection() {
    let store = setup_store();

    store
        .record_app_event(&chat("latest", REMOTE, 10, "single row"))
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");

    assert_eq!(row.group_id_hex, GROUP);
    assert_eq!(
        row.last_message
            .as_ref()
            .map(|message| message.message_id_hex.as_str()),
        Some("latest")
    );
    assert_eq!(
        store
            .refresh_chat_list_row(LOCAL, "missing-group", &no_mentions)
            .unwrap(),
        None
    );
}

#[test]
fn refresh_chat_list_row_projects_group_avatar_url() {
    let mut group = group();
    group
        .components
        .push(avatar_url_component("https://cdn.example.com/group.png"));
    let store = setup_store_with_group(group);

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");

    assert_eq!(
        row.avatar_url.as_deref(),
        Some("https://cdn.example.com/group.png")
    );
}

#[test]
fn chat_list_reads_cached_projection_without_rebuilding() {
    let store = setup_store();
    store
        .record_app_event(&chat("old", REMOTE, 10, "cached"))
        .unwrap();

    assert_eq!(
        store
            .chat_list_rows(crate::ChatListQuery::default())
            .unwrap(),
        Vec::new()
    );

    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    let row = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");
    assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "old");

    store
        .record_app_event(&chat("new", REMOTE, 11, "not refreshed yet"))
        .unwrap();
    let row = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");
    assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "old");

    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    let row = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");
    assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "new");
}

#[test]
fn ensure_chat_list_rows_backfills_missing_projection_rows() {
    let store = setup_store();
    store
        .record_app_event(&chat("latest", REMOTE, 10, "backfilled"))
        .unwrap();

    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let row = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");

    assert_eq!(row.group_id_hex, GROUP);
    assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "latest");
}

#[test]
fn ensure_chat_list_rows_rebuilds_stale_account_group_rows() {
    let store = setup_store();
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "UPDATE account_groups
                 SET profile_name = ?1
                 WHERE group_id_hex = ?2",
            params!["Renamed Lab", GROUP],
        )
        .unwrap();
    }

    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let row = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");

    assert_eq!(row.title, "Renamed Lab");
    assert_eq!(row.group_name, "Renamed Lab");
}

#[test]
fn ensure_chat_list_rows_repairs_drifted_self_membership() {
    // A membership change writes `account_groups.self_membership` but does not
    // itself rebuild the projection (and the 0022 migration leaves existing
    // rows at the default 'member'). The open-path completeness check must
    // treat a row whose denormalized membership disagrees with
    // `account_groups` as stale and rebuild it.
    let store = setup_store();
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    assert_eq!(
        store.chat_list_row(GROUP).unwrap().unwrap().self_membership,
        SelfMembership::Member
    );

    // Flip only the source of truth, leaving the projection row stale.
    store
        .set_group_self_membership(GROUP, SelfMembership::Removed)
        .unwrap();

    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();

    let row = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert_eq!(row.self_membership, SelfMembership::Removed);
}

#[test]
fn ensure_chat_list_rows_treats_unknown_self_membership_as_normalized() {
    // Forward-compat: a newer schema could persist a `self_membership` value
    // this version doesn't know. `SelfMembership::from_storage` normalizes the
    // unknown to `Member`, so a rebuild stores 'member'. The completeness check
    // must compare against that same normalized value (like the sibling `title`
    // CASE) — otherwise it sees 'member' != '<unknown>' forever and rebuilds the
    // whole projection on every open.
    let store = setup_store();
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();

    {
        let conn = store.lock().unwrap();
        conn.execute(
            "UPDATE account_groups SET self_membership = 'future_state' WHERE group_id_hex = ?1",
            params![GROUP],
        )
        .unwrap();
        // A far-future timestamp makes a spurious rebuild observable: a rebuild
        // resets `updated_at` to wall-clock now, which is in the past.
        conn.execute(
            "UPDATE chat_list_rows SET updated_at = 4000000000 WHERE group_id_hex = ?1",
            params![GROUP],
        )
        .unwrap();
    }

    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();

    let row = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert_eq!(row.self_membership, SelfMembership::Member);
    assert_eq!(
        row.updated_at, 4_000_000_000,
        "an unknown membership normalizes to the stored 'member', so the \
         completeness check must treat the row as fresh and not rebuild it"
    );
}

#[test]
fn ensure_chat_list_rows_rebuilds_stale_message_rows() {
    let store = setup_store();
    store
        .record_app_event(&chat("old", REMOTE, 10, "old preview"))
        .unwrap();
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat("new", REMOTE, 11, "new preview"))
        .unwrap();

    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let row = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");

    let last_message = row.last_message.expect("last message");
    assert_eq!(last_message.message_id_hex, "new");
    assert_eq!(last_message.plaintext, "new preview");
}

#[test]
fn ensure_chat_list_rows_rebuilds_stale_read_state_rows() {
    let store = setup_store();
    store
        .record_app_event(&chat("unread", REMOTE, 10, "needs read state"))
        .unwrap();
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "INSERT INTO conversation_read_state (
                    group_id_hex, last_read_message_id_hex, last_read_timeline_at,
                    initialized_at, updated_at
                 )
                 VALUES (?1, NULL, NULL, 0, 1)",
            params![GROUP],
        )
        .unwrap();
        conn.execute(
            "UPDATE chat_list_rows SET updated_at = 0 WHERE group_id_hex = ?1",
            params![GROUP],
        )
        .unwrap();
    }

    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let row = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");

    assert_eq!(row.unread_count, 1);
    assert_eq!(row.first_unread_message_id_hex.as_deref(), Some("unread"));
}

#[test]
fn unread_starts_after_first_open_and_advances_by_visible_kind9() {
    let store = setup_store();
    store
        .record_app_event(&chat("old", REMOTE, 10, "before first open"))
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.group_id_hex, GROUP);
    assert_eq!(row.title, "Marmot Lab");
    assert_eq!(row.unread_count, 0);
    assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "old");

    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&reaction("reaction", REMOTE, "old", 11))
        .unwrap();
    store
        .record_app_event(&chat("new", REMOTE, 12, "after first open"))
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.unread_count, 1);
    assert_eq!(row.first_unread_message_id_hex.as_deref(), Some("new"));

    store
        .mark_timeline_message_read(LOCAL, GROUP, "new", &no_mentions)
        .unwrap();
    let row = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");
    assert_eq!(row.unread_count, 0);
    assert_eq!(row.last_read_message_id_hex.as_deref(), Some("new"));
}

#[test]
fn secure_prune_refreshes_unread_count_mentions_and_first_message_atomically() {
    let store = setup_store();
    let mentions = |plaintext: &str, _tags: &[Vec<String>]| plaintext.contains("@local");
    store
        .initialize_chat_read_state(LOCAL, GROUP, &mentions)
        .unwrap();
    store
        .record_app_event(&chat("pruned-unread", REMOTE, 10, "hello @local"))
        .unwrap();
    store
        .record_app_event(&chat("surviving-unread", REMOTE, 20, "hello"))
        .unwrap();
    let before = store
        .refresh_chat_list_row(LOCAL, GROUP, &mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(before.unread_count, 2);
    assert_eq!(before.unread_mention_count, 1);
    assert_eq!(
        before.first_unread_message_id_hex.as_deref(),
        Some("pruned-unread")
    );

    store
        .secure_prune_app_events_before(GROUP, 15, LOCAL, &mentions)
        .unwrap();

    let after = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert_eq!(after.unread_count, 1);
    assert_eq!(after.unread_mention_count, 0);
    assert_eq!(
        after.first_unread_message_id_hex.as_deref(),
        Some("surviving-unread")
    );
}

#[test]
fn invalidated_kind9_tombstones_do_not_count_as_unread() {
    // Repro for #418: a group exchanges chat plus a group-system commit; fork
    // recovery later invalidates some received kind:9 rows (losing branch). The
    // invalidated rows are kept as "did not reach the group" tombstones, not
    // markable chat rows, so the read pointer can never advance past them. They
    // must not keep `unread_count` pinned above zero.
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();

    // A visible received chat the client will actually read.
    store
        .record_app_event(&chat("visible", REMOTE, 10, "real message"))
        .unwrap();
    // Three received chats that will be invalidated as a losing branch. Their
    // sender-claimed timeline_at sits after the visible message, so they sort
    // after any read marker the client can set.
    for id in ["phantom1", "phantom2", "phantom3"] {
        store
            .record_app_event(&chat(id, REMOTE, 11, "losing branch"))
            .unwrap();
    }

    // Before invalidation: all four received chats are unread.
    assert_eq!(
        store
            .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
            .unwrap()
            .expect("chat row")
            .unread_count,
        4
    );

    // Convergence invalidates the losing-branch rows (kept as tombstones).
    for id in ["phantom1", "phantom2", "phantom3"] {
        store
            .invalidate_app_event_by_message_id(GROUP, id, "LosingBranch")
            .unwrap();
    }

    // The client reads the only visible chat row.
    store
        .mark_timeline_message_read(LOCAL, GROUP, "visible", &no_mentions)
        .unwrap();

    let row = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");

    // Invalidated tombstones are not markable chat rows; they must not pin the
    // counter. Previously this stayed at 3.
    assert_eq!(row.unread_count, 0);
    assert_eq!(row.first_unread_message_id_hex, None);
    assert_eq!(row.last_read_message_id_hex.as_deref(), Some("visible"));
}

#[test]
fn own_kind9_send_clears_existing_unread_without_counting_as_unread() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat("remote", REMOTE, 10, "unread"))
        .unwrap();
    assert_eq!(
        store
            .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
            .unwrap()
            .expect("chat row")
            .unread_count,
        1
    );

    store
        .record_app_event(&chat("own", LOCAL, 11, "my reply"))
        .unwrap();
    store
        .mark_timeline_message_read(LOCAL, GROUP, "own", &no_mentions)
        .unwrap();
    let row = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");

    assert_eq!(row.unread_count, 0);
    assert_eq!(row.last_read_message_id_hex.as_deref(), Some("own"));
    assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "own");
}

#[test]
fn chat_list_preview_skips_invalidated_kind9_tombstone() {
    // Repro for #444: a visible delivered chat is followed by an invalidated
    // kind:9 row (losing branch) whose sender-claimed timeline_at sorts after
    // the visible message. The invalidated tombstone must not become the
    // chat-list preview/sort anchor; the latest *delivered* visible message
    // wins. This mirrors the invalidation_status filter already applied to
    // unread-count queries in #443.
    let store = setup_store();

    // Pin conversation creation below the message timestamps so the activity
    // anchor is driven by the kind-9 rows (not the wall-clock creation default),
    // making the phantom-vs-fallback distinction observable.
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "UPDATE account_groups SET conversation_created_at = 5 WHERE group_id_hex = ?1",
            params![GROUP],
        )
        .unwrap();
    }

    // Visible delivered chat.
    store
        .record_app_event(&chat("visible", REMOTE, 10, "real message"))
        .unwrap();
    // Losing-branch chat that arrives "later" by sender-claimed time.
    store
        .record_app_event(&chat("phantom", REMOTE, 11, "losing branch"))
        .unwrap();

    // Before invalidation the latest row wins, as usual.
    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    let last_message = row.last_message.expect("last message");
    assert_eq!(last_message.message_id_hex, "phantom");
    // The losing branch also pinned the activity anchor to its claimed time.
    assert_eq!(row.activity_sort_at, 11);

    // Convergence invalidates the losing-branch row (kept as a tombstone).
    store
        .invalidate_app_event_by_message_id(GROUP, "phantom", "LosingBranch")
        .unwrap();

    // Preview and sort anchor must fall back to the visible delivered message,
    // not the invalidated tombstone. The MAX-preserve upsert must not conflate
    // a convergence tombstone with a pruned message: the phantom anchor is
    // lowered rather than staying permanently pinned at 11.
    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    let last_message = row.last_message.expect("last message");
    assert_eq!(last_message.message_id_hex, "visible");
    assert_eq!(last_message.plaintext, "real message");
    assert_eq!(last_message.timeline_at, 10);
    assert_eq!(row.activity_sort_at, 10);

    // The cached projection read path agrees with the refresh path.
    let cached = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");
    assert_eq!(
        cached.last_message.as_ref().unwrap().message_id_hex,
        "visible"
    );
    assert_eq!(cached.activity_sort_at, 10);

    // And the completeness check considers the projection up to date, so a
    // subsequent ensure pass is a no-op rather than perpetually rebuilding.
    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let after_ensure = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");
    assert_eq!(
        after_ensure.last_message.as_ref().unwrap().message_id_hex,
        "visible"
    );
    assert_eq!(after_ensure.activity_sort_at, 10);
}

#[test]
fn chat_list_preview_is_empty_when_only_invalidated_kind9_exists() {
    // When every kind:9 row in a group is an invalidated tombstone, the
    // chat-list preview must be absent rather than anchored on a losing-branch
    // message.
    let store = setup_store();
    store
        .record_app_event(&chat("phantom", REMOTE, 11, "losing branch"))
        .unwrap();
    store
        .invalidate_app_event_by_message_id(GROUP, "phantom", "LosingBranch")
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.last_message, None);
}

#[test]
fn unread_p_tag_mention_of_local_account_counts() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat_with_tags(
            "ping",
            REMOTE,
            10,
            "hey there",
            vec![vec!["p".to_owned(), LOCAL.to_owned()]],
        ))
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &mentions_local)
        .unwrap()
        .expect("chat row");

    assert_eq!(row.unread_count, 1);
    assert_eq!(row.unread_mention_count, 1);
    assert!(row.has_unread_mention);
}

#[test]
fn unread_inline_mention_of_local_account_counts() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat("inline", REMOTE, 10, &format!("yo {LOCAL} around?")))
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &mentions_local)
        .unwrap()
        .expect("chat row");

    assert_eq!(row.unread_count, 1);
    assert_eq!(row.unread_mention_count, 1);
    assert!(row.has_unread_mention);
}

#[test]
fn unread_mention_of_other_account_does_not_count() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat_with_tags(
            "ping-other",
            REMOTE,
            10,
            "no inline mention here",
            vec![vec!["p".to_owned(), REMOTE.to_owned()]],
        ))
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &mentions_local)
        .unwrap()
        .expect("chat row");

    assert_eq!(row.unread_count, 1);
    assert_eq!(row.unread_mention_count, 0);
    assert!(!row.has_unread_mention);
}

#[test]
fn already_read_mention_does_not_count_as_unread_mention() {
    let store = setup_store();
    // A mention arrives, then the client reads it: it is before the read marker
    // and must not contribute to the unread-mention count.
    store
        .record_app_event(&chat_with_tags(
            "read-mention",
            REMOTE,
            10,
            "mention before read",
            vec![vec!["p".to_owned(), LOCAL.to_owned()]],
        ))
        .unwrap();
    store
        .mark_timeline_message_read(LOCAL, GROUP, "read-mention", &mentions_local)
        .unwrap();
    // A later non-mention message keeps the conversation unread overall.
    store
        .record_app_event(&chat("after", REMOTE, 11, "plain follow-up"))
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &mentions_local)
        .unwrap()
        .expect("chat row");

    assert_eq!(row.unread_count, 1);
    assert_eq!(row.unread_mention_count, 0);
    assert!(!row.has_unread_mention);
}

#[test]
fn self_sent_mention_does_not_count_as_unread_mention() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    // A message authored by the local account that references the local account
    // is excluded by the unread window (sender == local), so it cannot count.
    store
        .record_app_event(&chat_with_tags(
            "self",
            LOCAL,
            10,
            &format!("note to self {LOCAL}"),
            vec![vec!["p".to_owned(), LOCAL.to_owned()]],
        ))
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &mentions_local)
        .unwrap()
        .expect("chat row");

    assert_eq!(row.unread_count, 0);
    assert_eq!(row.unread_mention_count, 0);
    assert!(!row.has_unread_mention);
}

#[test]
fn ensure_chat_list_rows_corrects_stale_unread_mention_count() {
    // Mirrors a migration-0018 upgrade: the projection exists and is otherwise
    // complete, but `unread_mention_count` defaults to 0. `ensure_chat_list_rows`
    // must recompute the mention count per group and rebuild rows that are wrong.
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat_with_tags(
            "ping",
            REMOTE,
            10,
            "mention",
            vec![vec!["p".to_owned(), LOCAL.to_owned()]],
        ))
        .unwrap();
    // Build the projection WITHOUT mention awareness (count stays 0), then
    // simulate the post-migration default explicitly.
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "UPDATE chat_list_rows SET unread_mention_count = 0 WHERE group_id_hex = ?1",
            params![GROUP],
        )
        .unwrap();
    }

    store.ensure_chat_list_rows(LOCAL, &mentions_local).unwrap();
    let row = store
        .chat_list_rows(crate::ChatListQuery::default())
        .unwrap()
        .pop()
        .expect("chat row");

    assert_eq!(row.unread_mention_count, 1);
    assert!(row.has_unread_mention);
}

#[test]
fn account_unread_total_is_zero_on_empty_store() {
    let store = setup_store();

    let total = store.account_unread_total().unwrap();
    assert_eq!(total, AccountUnreadTotal::default());
    assert!(!total.has_unread());
}

#[test]
fn account_unread_total_aggregates_materialized_projection() {
    let store = setup_store();
    // Establish a read baseline on existing history, then receive two new
    // remote kind-9 messages so they count as unread.
    store
        .record_app_event(&chat("old", REMOTE, 10, "before first open"))
        .unwrap();
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat("new-1", REMOTE, 11, "after first open"))
        .unwrap();
    store
        .record_app_event(&chat("new-2", REMOTE, 12, "after first open"))
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.unread_count, 2);

    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 2);
    assert_eq!(total.unread_conversations, 1);
    assert!(total.has_unread());
}

#[test]
fn account_unread_total_excludes_archived_conversations() {
    let mut group = group();
    group.archived = true;
    let store = setup_store_with_group(group);
    store
        .record_app_event(&chat("old", REMOTE, 10, "before first open"))
        .unwrap();
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat("new", REMOTE, 11, "after first open"))
        .unwrap();
    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert!(row.archived);
    assert_eq!(row.unread_count, 1);

    // The archived conversation has unread messages, but the account-level
    // aggregate excludes archived rows.
    let total = store.account_unread_total().unwrap();
    assert_eq!(total, AccountUnreadTotal::default());
    assert!(!total.has_unread());
}

/// Seed `GROUP` with one unread remote message and a materialized chat-list
/// row, returning the store. The single conversation has `unread_count == 1`.
fn setup_store_with_one_unread() -> SqliteAccountStorage {
    let store = setup_store();
    store
        .record_app_event(&chat("old", REMOTE, 10, "before first open"))
        .unwrap();
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat("new", REMOTE, 11, "after first open"))
        .unwrap();
    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.unread_count, 1);
    store
}

#[test]
fn chat_list_row_reports_a_self_leave_as_left() {
    let store = setup_store_with_one_unread();

    store
        .set_group_self_membership(GROUP, SelfMembership::Left)
        .unwrap();
    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");

    assert_eq!(row.self_membership, SelfMembership::Left);
}

#[test]
fn account_unread_total_suppresses_removed_self_membership_group() {
    let store = setup_store_with_one_unread();

    // Default 'member' membership still counts.
    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 1);
    assert_eq!(total.unread_conversations, 1);

    store
        .set_group_self_membership(GROUP, SelfMembership::Removed)
        .unwrap();

    // Once the local account is known-removed, the group's unread is suppressed.
    let total = store.account_unread_total().unwrap();
    assert_eq!(total, AccountUnreadTotal::default());
    assert!(!total.has_unread());
}

#[test]
fn account_unread_total_suppresses_left_self_membership_group() {
    let store = setup_store_with_one_unread();

    // A voluntary self-leave is also a terminal "no longer a member" state, so
    // it suppresses the group's unread exactly like an involuntary removal.
    store
        .set_group_self_membership(GROUP, SelfMembership::Left)
        .unwrap();

    let total = store.account_unread_total().unwrap();
    assert_eq!(total, AccountUnreadTotal::default());
    assert!(!total.has_unread());
}

#[test]
fn account_unread_total_preserves_member_self_membership_group() {
    let store = setup_store_with_one_unread();

    // Default state (no observed self-removal) is 'member' and must preserve the
    // unread count: uncertainty never suppresses.
    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 1);
    assert_eq!(total.unread_conversations, 1);

    // Re-affirming 'member' (e.g. after a re-add) keeps the unread counted.
    store
        .set_group_self_membership(GROUP, SelfMembership::Member)
        .unwrap();
    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 1);
    assert_eq!(total.unread_conversations, 1);
}

#[test]
fn account_unread_total_unsuppresses_after_rejoin() {
    let store = setup_store_with_one_unread();

    store
        .set_group_self_membership(GROUP, SelfMembership::Removed)
        .unwrap();
    assert_eq!(
        store.account_unread_total().unwrap(),
        AccountUnreadTotal::default()
    );

    // A re-add restores counting.
    store
        .set_group_self_membership(GROUP, SelfMembership::Member)
        .unwrap();
    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 1);
    assert_eq!(total.unread_conversations, 1);
}

#[test]
fn account_unread_total_preserves_rows_without_account_group_row() {
    // A chat-list row with no matching account_groups row (LEFT JOIN edge) must
    // be preserved: COALESCE(self_membership, 'member') keeps unknown unread.
    // `chat_list_rows` normally cascades from `account_groups`, so drop the
    // parent with foreign keys off to leave a transient orphan projection row
    // and confirm the aggregate still counts it.
    let store = setup_store_with_one_unread();
    {
        let conn = store.lock().unwrap();
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute(
            "DELETE FROM account_groups WHERE group_id_hex = ?1",
            params![GROUP],
        )
        .unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
    }

    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 1);
    assert_eq!(total.unread_conversations, 1);
}

#[test]
fn set_group_self_membership_survives_projection_resave() {
    // A routine projection re-save (profile/avatar metadata) must not clobber the
    // self_membership owned by the sync membership-change path.
    let store = setup_store_with_one_unread();
    store
        .set_group_self_membership(GROUP, SelfMembership::Removed)
        .unwrap();
    assert_eq!(
        store.account_unread_total().unwrap(),
        AccountUnreadTotal::default()
    );

    let mut renamed = group();
    renamed.profile_name = "Renamed Lab".to_owned();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![renamed],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();

    // Membership stays 'removed' across the re-save, so the total stays suppressed.
    let total = store.account_unread_total().unwrap();
    assert_eq!(total, AccountUnreadTotal::default());
    assert!(!total.has_unread());
}

#[test]
fn account_group_ids_defaulting_to_member_lists_only_default_rows() {
    // Backfill candidate set: rows still carrying the migration default
    // 'member' are returned; rows explicitly flipped to 'removed' are not, so
    // re-running the one-time backfill stays idempotent.
    let other_group = StoredAccountGroup {
        group_id_hex: "22".to_owned(),
        ..group()
    };
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![group(), other_group],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();

    // Both rows start at the default 'member', so both are candidates.
    assert_eq!(
        store.account_group_ids_defaulting_to_member().unwrap(),
        vec![GROUP.to_owned(), "22".to_owned()]
    );

    // Once a row is flipped to 'removed' it drops out of the candidate set.
    store
        .set_group_self_membership(GROUP, SelfMembership::Removed)
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

#[test]
fn set_group_self_membership_propagates_backend_errors() {
    // mdk#573 review follow-up (blocking finding 2): the
    // `self_membership` projection write is the source of truth for the account
    // unread aggregate, so a backend failure must surface as an `Err` (the sync
    // / local-leave callers propagate it with `?`) instead of being swallowed.
    // Drop the table out from under the update to force a backend error.
    let store = setup_store_with_one_unread();
    {
        let conn = store.lock().unwrap();
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute_batch("DROP TABLE account_groups;").unwrap();
    }
    let result = store.set_group_self_membership(GROUP, SelfMembership::Removed);
    assert!(
        result.is_err(),
        "a failed self_membership projection write must return an error, not silently succeed"
    );
}

#[test]
fn chat_list_rows_report_the_durable_leave_request_at_read_time() {
    // A leave is durable in `cgka_leave_requests` from the moment the engine
    // mints the SelfRemove proposal, but `self_membership` stays `Member` until a
    // commit actually removes us. Between those two points — across a publish
    // failure or a cold launch — this read-time derivation is the only way the
    // chat list can tell that the user asked to leave.
    let store = setup_store();
    let group_id = GroupId::new(hex::decode(GROUP).unwrap());
    store
        .put_group(&sample_group(group_id.clone(), 3, 0))
        .unwrap();
    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();

    // No request yet: the field is absent, not defaulted to some sentinel.
    let row = store.chat_list_row(GROUP).unwrap().unwrap();
    assert_eq!(row.leave_requested_at_ms, None);
    assert_eq!(row.self_membership, SelfMembership::Member);

    store
        .put_leave_request(&LeaveRequest {
            group_id: group_id.clone(),
            requested_at_ms: 1_700_000_000_123,
            last_proposed_epoch: Some(EpochId(3)),
        })
        .unwrap();

    // Visible through both read paths without any projection rebuild, and while
    // membership is still `Member` — that is the whole point.
    let row = store.chat_list_row(GROUP).unwrap().unwrap();
    assert_eq!(row.leave_requested_at_ms, Some(1_700_000_000_123));
    assert_eq!(row.self_membership, SelfMembership::Member);
    let rows = store
        .chat_list_rows(ChatListQuery {
            include_archived: true,
        })
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].leave_requested_at_ms, Some(1_700_000_000_123));

    // Read-time derivation means a rebuild neither clears nor staleness-flags the
    // value: the projection has no column for it.
    store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
    assert_eq!(
        store
            .chat_list_row(GROUP)
            .unwrap()
            .unwrap()
            .leave_requested_at_ms,
        Some(1_700_000_000_123)
    );
    {
        let conn = store.lock().unwrap();
        assert!(
            chat_list_projection_complete_tx(&conn, LOCAL, &no_mentions).unwrap(),
            "a pending leave request must not make the projection look stale"
        );
    }

    // The engine clears the request from paths that never touch the projection,
    // so the derived value has to disappear with it and not linger.
    store.clear_leave_request(&group_id).unwrap();
    assert_eq!(
        store
            .chat_list_row(GROUP)
            .unwrap()
            .unwrap()
            .leave_requested_at_ms,
        None
    );
}

fn three_groups() -> Vec<StoredAccountGroup> {
    vec![
        group(),
        StoredAccountGroup {
            group_id_hex: "22".to_owned(),
            profile_name: "Second".to_owned(),
            ..group()
        },
        StoredAccountGroup {
            group_id_hex: "33".to_owned(),
            profile_name: "Third".to_owned(),
            ..group()
        },
    ]
}

#[test]
fn pinned_chats_are_manual_first_and_survive_projection_rebuilds() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: three_groups(),
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "UPDATE account_groups
             SET conversation_created_at = CASE group_id_hex
                 WHEN '11' THEN 100
                 WHEN '22' THEN 300
                 WHEN '33' THEN 200
             END",
            [],
        )
        .unwrap();
    }
    store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let initial = store
        .chat_list_rows(ChatListQuery::default())
        .unwrap()
        .into_iter()
        .map(|row| row.group_id_hex)
        .collect::<Vec<_>>();
    assert_eq!(initial, vec!["22", "33", "11"]);

    assert_eq!(
        store.set_chat_pinned("11", true).unwrap().ordered_group_ids,
        vec!["11"]
    );
    assert_eq!(
        store.set_chat_pinned("33", true).unwrap().ordered_group_ids,
        vec!["33", "11"]
    );
    // Re-pinning is idempotent and does not move an existing pin.
    assert_eq!(
        store.set_chat_pinned("11", true).unwrap().ordered_group_ids,
        vec!["33", "11"]
    );
    assert_eq!(
        store
            .set_chat_pinned("11", false)
            .unwrap()
            .ordered_group_ids,
        vec!["33"]
    );
    // Re-unpinning is also idempotent.
    assert_eq!(
        store
            .set_chat_pinned("11", false)
            .unwrap()
            .ordered_group_ids,
        vec!["33"]
    );
    assert_eq!(
        store.set_chat_pinned("11", true).unwrap().ordered_group_ids,
        vec!["11", "33"]
    );

    let rows = store.chat_list_rows(ChatListQuery::default()).unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.group_id_hex.as_str())
            .collect::<Vec<_>>(),
        vec!["11", "33", "22"]
    );
    assert_eq!(
        rows.iter()
            .map(|row| (row.pinned, row.pinned_position))
            .collect::<Vec<_>>(),
        vec![(true, Some(0)), (true, Some(1)), (false, None)]
    );

    store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
    assert_eq!(
        store
            .chat_list_rows(ChatListQuery::default())
            .unwrap()
            .into_iter()
            .filter(|row| row.pinned)
            .map(|row| row.group_id_hex)
            .collect::<Vec<_>>(),
        vec!["11", "33"]
    );

    assert_eq!(
        store
            .set_pinned_chat_order(&["33".to_owned(), "11".to_owned()])
            .unwrap()
            .ordered_group_ids,
        vec!["33", "11"]
    );
    store
        .record_app_event(&chat("newest", REMOTE, 1_000, "new activity"))
        .unwrap();
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    assert_eq!(
        store
            .chat_list_rows(ChatListQuery::default())
            .unwrap()
            .into_iter()
            .map(|row| row.group_id_hex)
            .collect::<Vec<_>>(),
        vec!["33", "11", "22"]
    );
}

#[test]
fn pin_validation_and_unarchived_eligibility_are_explicit() {
    let mut groups = three_groups();
    groups[0].self_membership = SelfMembership::Left;
    groups[1].pending_confirmation = true;
    groups[2].self_membership = SelfMembership::Removed;
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups,
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();

    store.set_chat_pinned("11", true).unwrap();
    store.set_chat_pinned("22", true).unwrap();
    store.set_chat_pinned("33", true).unwrap();
    assert!(matches!(
        store.set_chat_pinned("missing", true),
        Err(ChatPinError::UnknownGroup(_))
    ));
    assert!(matches!(
        store.set_pinned_chat_order(&["33".to_owned(), "33".to_owned()]),
        Err(ChatPinError::InvalidOrder(_))
    ));
    assert!(matches!(
        store.set_pinned_chat_order(&["33".to_owned()]),
        Err(ChatPinError::InvalidOrder(_))
    ));

    let mut archived_groups = three_groups();
    archived_groups[0].archived = true;
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: archived_groups,
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    assert!(matches!(
        store.set_chat_pinned("11", true),
        Err(ChatPinError::ArchivedChat)
    ));
}

#[test]
fn archiving_and_deleting_clear_pins_without_restoring_them() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: three_groups(),
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
    store.set_chat_pinned("11", true).unwrap();
    store.set_chat_pinned("33", true).unwrap();

    let mut archived_groups = three_groups();
    archived_groups[2].archived = true;
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: archived_groups,
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    let remaining = store.chat_list_row("11").unwrap().unwrap();
    assert!(remaining.pinned);
    assert_eq!(remaining.pinned_position, Some(0));
    let archived = store.chat_list_row("33").unwrap().unwrap();
    assert!(!archived.pinned);

    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: three_groups(),
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    assert!(!store.chat_list_row("33").unwrap().unwrap().pinned);

    assert!(store.delete_local_group_data("11").unwrap().did_delete());
    let pin_count = {
        let conn = store.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM chat_pin_positions WHERE group_id_hex = '11'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
    };
    assert_eq!(pin_count, 0);
}

#[test]
fn pinned_order_survives_encrypted_database_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chat-pins.sqlite3");
    let key = SqlCipherKey::new("chat pin persistence key").unwrap();
    {
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        store
            .save_account_projection_state(
                &StoredAccountState {
                    label: "alice".to_owned(),
                    groups: three_groups(),
                    ..StoredAccountState::default()
                },
                256,
                MAX_FUTURE_SKEW_SECS,
            )
            .unwrap();
        store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
        store.set_chat_pinned("11", true).unwrap();
        store.set_chat_pinned("33", true).unwrap();
    }

    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let pinned = reopened
        .chat_list_rows(ChatListQuery::default())
        .unwrap()
        .into_iter()
        .filter(|row| row.pinned)
        .map(|row| (row.group_id_hex, row.pinned_position))
        .collect::<Vec<_>>();
    assert_eq!(
        pinned,
        vec![("33".to_owned(), Some(0)), ("11".to_owned(), Some(1))]
    );
}
