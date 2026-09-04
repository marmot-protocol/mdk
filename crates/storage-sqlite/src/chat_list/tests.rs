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
    EVENT_REF_TAG, GROUP_SYSTEM_TYPE_ADMIN_ADDED, GROUP_SYSTEM_TYPE_ADMIN_REMOVED,
    GROUP_SYSTEM_TYPE_GROUP_RENAMED, GROUP_SYSTEM_TYPE_MEMBER_ADDED, GROUP_SYSTEM_TYPE_MEMBER_LEFT,
    GROUP_SYSTEM_TYPE_MEMBER_REMOVED, GROUP_SYSTEM_TYPE_TAG, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_GROUP_SYSTEM, MARMOT_APP_EVENT_KIND_REACTION,
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
        direct_member_ids_hex: None,
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

fn group_system(
    id: &str,
    sender: &str,
    at: u64,
    system_type: &str,
    plaintext: &str,
) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: GROUP.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: None,
        source_epoch: Some(at),
        direction: "system".to_owned(),
        sender: sender.to_owned(),
        plaintext: plaintext.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        tags: vec![vec![
            GROUP_SYSTEM_TYPE_TAG.to_owned(),
            system_type.to_owned(),
        ]],
        recorded_at: at,
        received_at: at,
        origin_commit_id: Some(format!("commit-{id}")),
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
fn created_group_projection_and_chat_list_row_commit_atomically() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_created_chat_list_row
             BEFORE INSERT ON chat_list_rows
             BEGIN
                 SELECT RAISE(ABORT, 'injected created row failure');
             END;",
        )
        .unwrap();
    let state = StoredAccountState {
        label: "alice".to_owned(),
        groups: vec![group()],
        ..StoredAccountState::default()
    };

    store
        .save_account_projection_delta_and_refresh_chat_list_row(
            &state,
            256,
            MAX_FUTURE_SKEW_SECS,
            &[],
            &[],
            LOCAL,
            GROUP,
            &no_mentions,
        )
        .expect_err("the injected chat-list failure must roll back the projection delta");
    assert!(
        store
            .load_account_projection_state("alice", 256)
            .unwrap()
            .groups
            .is_empty(),
        "a crash/failure at the remaining app write boundary must expose neither half"
    );

    store
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_created_chat_list_row")
        .unwrap();
    let committed = store
        .save_account_projection_delta_and_refresh_chat_list_row(
            &state,
            256,
            MAX_FUTURE_SKEW_SECS,
            &[],
            &[],
            LOCAL,
            GROUP,
            &no_mentions,
        )
        .unwrap()
        .expect("created chat-list row");
    assert_eq!(store.chat_list_row(GROUP).unwrap(), Some(committed));
}

/// Operational mdk#1487 benchmark for the post-canonical app-local tail.
///
/// Run with an optimized build so the recorded distribution reflects
/// production-shaped encrypted file-backed storage rather than debug code:
///
/// `cargo test -p storage-sqlite file_backed_create_group_tail_benchmark_matrix --release -- --ignored --nocapture`
#[test]
#[ignore = "operational file-backed SQLCipher benchmark"]
fn file_backed_create_group_tail_benchmark_matrix() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let samples = std::env::var("MDK_CREATE_TAIL_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50)
        .max(20);

    for invitees in [1_usize, 8, 32] {
        let baseline = measure_create_tail(samples, invitees, true, false);
        let baseline_with_read = measure_create_tail(samples, invitees, true, true);
        let optimized = measure_create_tail(samples, invitees, false, false);
        tracing::info!(
            target: "storage_sqlite::chat_list",
            method = "file_backed_create_group_tail_benchmark_matrix",
            invitees,
            samples,
            baseline_p50_us = percentile_micros(&baseline, 50),
            baseline_p95_us = percentile_micros(&baseline, 95),
            baseline_with_row_read_p50_us = percentile_micros(&baseline_with_read, 50),
            baseline_with_row_read_p95_us = percentile_micros(&baseline_with_read, 95),
            optimized_p50_us = percentile_micros(&optimized, 50),
            optimized_p95_us = percentile_micros(&optimized, 95),
            "measured file-backed create-group local tail"
        );
    }
}

fn measure_create_tail(
    samples: usize,
    invitees: usize,
    baseline: bool,
    include_row_read: bool,
) -> Vec<u128> {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new(format!(
        "create-tail-benchmark-{invitees}-{baseline}-{include_row_read}"
    ))
    .unwrap();
    let store =
        SqliteAccountStorage::open_encrypted(dir.path().join("account.sqlite3"), &key).unwrap();
    let mut durations = Vec::with_capacity(samples);
    for sample in 0..samples {
        let group_id_hex = format!("{invitees:02x}{sample:062x}");
        let mut created_group = group();
        created_group.group_id_hex = group_id_hex.clone();
        created_group.member_count = Some((invitees + 1) as u64);
        created_group.profile_name = format!("benchmark-{invitees}-{sample}");
        let state = StoredAccountState {
            label: "benchmark".to_owned(),
            groups: vec![created_group],
            ..StoredAccountState::default()
        };
        let pending = (0..invitees)
            .map(|recipient| crate::PendingWelcomeDeliveryRecord {
                message_id_hex: format!("{sample:056x}{recipient:08x}"),
                group_id_hex: group_id_hex.clone(),
                recipient_hex: format!("{recipient:064x}"),
                recorded_at: sample as u64,
            })
            .collect::<Vec<_>>();

        let started = std::time::Instant::now();
        if baseline {
            store.record_pending_welcome_deliveries(&pending).unwrap();
            store
                .save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
                    &state,
                    256,
                    MAX_FUTURE_SKEW_SECS,
                    &[],
                    &[],
                )
                .unwrap();
            if include_row_read {
                std::hint::black_box(
                    store
                        .refresh_chat_list_row(LOCAL, &group_id_hex, &no_mentions)
                        .unwrap()
                        .expect("legacy read-after-create row"),
                );
            }
        } else {
            std::hint::black_box(
                store
                    .save_account_projection_delta_and_refresh_chat_list_row(
                        &state,
                        256,
                        MAX_FUTURE_SKEW_SECS,
                        &[],
                        &[],
                        LOCAL,
                        &group_id_hex,
                        &no_mentions,
                    )
                    .unwrap()
                    .expect("created chat-list row"),
            );
        }
        durations.push(started.elapsed().as_micros());
    }
    durations
}

fn percentile_micros(samples: &[u128], percentile: usize) -> u128 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = ((sorted.len() - 1) * percentile).div_ceil(100);
    sorted[index]
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
    assert_eq!(
        store
            .account_unread_total()
            .unwrap()
            .attention_only_conversations,
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

fn direct_row(group_id_hex: &str, activity_sort_at: u64) -> ChatListRow {
    ChatListRow {
        group_id_hex: group_id_hex.to_owned(),
        pinned: false,
        pinned_position: None,
        archived: false,
        pending_confirmation: false,
        lifecycle_state: cgka_traits::GroupLifecycleState::Stable,
        disbanding: false,
        disband_request: None,
        title: group_id_hex.to_owned(),
        group_name: String::new(),
        avatar_url: None,
        avatar: None,
        last_message: None,
        unread_count: 0,
        has_unread: false,
        manually_marked_unread: false,
        unread_mention_count: 0,
        has_unread_mention: false,
        first_unread_message_id_hex: None,
        last_read_message_id_hex: None,
        last_read_timeline_at: None,
        conversation_created_at: activity_sort_at,
        activity_sort_at,
        updated_at: activity_sort_at,
        self_membership: SelfMembership::Member,
        conversation_kind: ChatConversationKind::Direct,
        muted: false,
        muted_until_ms: None,
        leave_requested_at_ms: None,
    }
}

fn roster(local: &str, peer: &str) -> Vec<String> {
    vec![local.to_owned(), peer.to_owned()]
}

#[test]
fn select_reusable_direct_conversation_covers_policy_cases() {
    let local = "aa".repeat(32);
    let peer = "bb".repeat(32);
    let other = "cc".repeat(32);
    let mut memberships = std::collections::HashMap::new();
    memberships.insert("active".to_owned(), roster(&local, &peer));
    memberships.insert("older".to_owned(), roster(&local, &peer));
    memberships.insert("left".to_owned(), roster(&local, &peer));
    memberships.insert("removed".to_owned(), roster(&local, &peer));
    memberships.insert("disbanded".to_owned(), roster(&local, &peer));
    memberships.insert("leaving".to_owned(), roster(&local, &peer));
    memberships.insert("disbanding".to_owned(), roster(&local, &peer));
    memberships.insert("named".to_owned(), roster(&local, &peer));
    memberships.insert("other-peer".to_owned(), roster(&local, &other));
    memberships.insert("pending".to_owned(), roster(&local, &peer));
    memberships.insert("archived".to_owned(), roster(&local, &peer));

    assert!(
        select_reusable_direct_conversation(&[], &local, &peer, &memberships).is_none(),
        "no match"
    );
    assert!(
        select_reusable_direct_conversation(
            &[direct_row("active", 20)],
            &local,
            &"dd".repeat(32),
            &memberships
        )
        .is_none(),
        "unknown peer"
    );

    let active = select_reusable_direct_conversation(
        &[direct_row("active", 20)],
        &local,
        &peer,
        &memberships,
    )
    .expect("active match");
    assert_eq!(active.group_id_hex, "active");
    assert!(active.reusable);
    assert_eq!(active.self_membership, SelfMembership::Member);
    assert_eq!(
        active.lifecycle_state,
        cgka_traits::GroupLifecycleState::Stable
    );

    let mut left = direct_row("left", 30);
    left.self_membership = SelfMembership::Left;
    assert!(
        select_reusable_direct_conversation(&[left], &local, &peer, &memberships).is_none(),
        "left groups are not reusable"
    );

    let mut removed = direct_row("removed", 30);
    removed.self_membership = SelfMembership::Removed;
    assert!(
        select_reusable_direct_conversation(&[removed], &local, &peer, &memberships).is_none(),
        "removed groups are not reusable"
    );

    let mut disbanded = direct_row("disbanded", 30);
    disbanded.lifecycle_state = cgka_traits::GroupLifecycleState::Disbanded;
    assert!(
        select_reusable_direct_conversation(&[disbanded], &local, &peer, &memberships).is_none(),
        "disbanded groups are not reusable"
    );

    let mut leaving = direct_row("leaving", 30);
    leaving.leave_requested_at_ms = Some(1);
    assert!(
        select_reusable_direct_conversation(&[leaving], &local, &peer, &memberships).is_none(),
        "pending leave is not reusable"
    );

    let mut disbanding = direct_row("disbanding", 30);
    disbanding.disbanding = true;
    assert!(
        select_reusable_direct_conversation(&[disbanding], &local, &peer, &memberships).is_none(),
        "disbanding groups are not reusable"
    );

    let mut named = direct_row("named", 40);
    named.group_name = "Team".to_owned();
    named.conversation_kind = ChatConversationKind::Group;
    assert!(
        select_reusable_direct_conversation(&[named], &local, &peer, &memberships).is_none(),
        "named groups are not direct"
    );

    assert!(
        select_reusable_direct_conversation(
            &[direct_row("other-peer", 40)],
            &local,
            &peer,
            &memberships
        )
        .is_none(),
        "direct group with a different peer is not a match"
    );

    let mut pending = direct_row("pending", 15);
    pending.pending_confirmation = true;
    let pending = select_reusable_direct_conversation(&[pending], &local, &peer, &memberships)
        .expect("pending invite remains reusable");
    assert!(pending.reusable);
    assert!(pending.pending_confirmation);

    let mut archived = direct_row("archived", 10);
    archived.archived = true;
    let archived = select_reusable_direct_conversation(&[archived], &local, &peer, &memberships)
        .expect("archived direct remains reusable");
    assert!(archived.reusable);
    assert!(archived.archived);

    let selected = select_reusable_direct_conversation(
        &[direct_row("older", 10), direct_row("active", 20)],
        &local,
        &peer,
        &memberships,
    )
    .expect("duplicate historical groups pick durable activity order");
    assert_eq!(selected.group_id_hex, "active");
    assert_eq!(selected.activity_sort_at, 20);

    let tied = select_reusable_direct_conversation(
        &[direct_row("zz", 20), direct_row("aa", 20)],
        &local,
        &peer,
        &{
            let mut tied = memberships.clone();
            tied.insert("aa".to_owned(), roster(&local, &peer));
            tied.insert("zz".to_owned(), roster(&local, &peer));
            tied
        },
    )
    .expect("activity ties break on group id");
    assert_eq!(tied.group_id_hex, "aa");
}

fn hex_id(byte: u8, len: usize) -> String {
    hex::encode(vec![byte; len])
}

fn direct_group(group_id_hex: &str, local: &str, peer: &str) -> StoredAccountGroup {
    StoredAccountGroup {
        group_id_hex: group_id_hex.to_owned(),
        profile_name: String::new(),
        member_count: Some(2),
        direct_member_ids_hex: Some(vec![local.to_owned(), peer.to_owned()]),
        ..group()
    }
}

#[test]
fn direct_conversation_candidate_rows_are_keyed_by_peer() {
    let local = hex_id(0xaa, 32);
    let peer = hex_id(0xbb, 32);
    let other = hex_id(0xcc, 32);
    let match_id = hex_id(0x11, 16);
    let older_match_id = hex_id(0x10, 16);
    let named_id = hex_id(0x22, 16);
    let expanded_id = hex_id(0x33, 16);

    let mut named = group();
    named.group_id_hex = named_id.clone();
    named.profile_name = "Team".to_owned();
    named.member_count = Some(2);
    named.direct_member_ids_hex = Some(vec![local.clone(), peer.clone()]);

    let mut expanded = group();
    expanded.group_id_hex = expanded_id;
    expanded.profile_name.clear();
    expanded.member_count = Some(3);

    let mut groups = vec![
        direct_group(&older_match_id, &local, &peer),
        direct_group(&match_id, &local, &peer),
        named,
        expanded,
    ];
    for index in 0..20u8 {
        groups.push(direct_group(
            &hex_id(0x40 + index, 16),
            &local,
            &hex_id(0xd0 + index, 32),
        ));
    }

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
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "UPDATE account_groups
             SET conversation_created_at = CASE group_id_hex
                 WHEN ?1 THEN 100
                 WHEN ?2 THEN 300
                 ELSE 200
             END",
            rusqlite::params![older_match_id, match_id],
        )
        .unwrap();
    }
    store.refresh_chat_list_rows(&local, &no_mentions).unwrap();

    let candidates = store.direct_conversation_candidate_rows(&peer).unwrap();
    assert_eq!(
        candidates
            .iter()
            .map(|row| row.group_id_hex.as_str())
            .collect::<Vec<_>>(),
        vec![match_id.as_str(), older_match_id.as_str()],
        "other-peer DMs, named chats, and 3+ member chats must not enter the candidate set"
    );
    assert!(
        candidates
            .iter()
            .all(|row| row.conversation_kind == ChatConversationKind::Direct)
    );
    assert!(
        store
            .direct_conversation_candidate_rows(&other)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.unindexed_direct_conversation_group_ids().unwrap(),
        Vec::<String>::new()
    );
    let loaded = store
        .load_account_projection_state("alice", 16)
        .unwrap()
        .groups
        .into_iter()
        .find(|group| group.group_id_hex == match_id)
        .expect("matching direct group");
    let mut loaded_members = loaded.direct_member_ids_hex.expect("persisted members");
    loaded_members.sort();
    let mut expected_members = vec![local, peer];
    expected_members.sort();
    assert_eq!(loaded_members, expected_members);

    let plan = store
        .direct_conversation_candidate_query_plan(&hex_id(0xbb, 32))
        .unwrap()
        .join("\n")
        .to_ascii_lowercase();
    assert!(
        plan.contains("idx_direct_conversation_members_member"),
        "peer lookup must be driven by the member index: {plan}"
    );
    assert!(
        !plan.contains("scan chat_list_rows") && !plan.contains("scan account_groups"),
        "peer lookup must not full-scan chat tables: {plan}"
    );
}

#[test]
fn fill_unindexed_direct_conversation_members_does_not_clobber_newer_rows() {
    let local = hex_id(0xaa, 32);
    let old_peer = hex_id(0xbb, 32);
    let new_peer = hex_id(0xcc, 32);
    let group_id = hex_id(0x11, 16);
    let store = SqliteAccountStorage::in_memory().unwrap();
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
    let store = SqliteAccountStorage::in_memory().unwrap();
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
    let store = SqliteAccountStorage::in_memory().unwrap();
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
    let store = SqliteAccountStorage::in_memory().unwrap();

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
    let store = SqliteAccountStorage::in_memory().unwrap();
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
fn unindexed_direct_conversation_group_ids_skip_malformed_hex() {
    let local = hex_id(0xaa, 32);
    let peer = hex_id(0xbb, 32);
    let valid_id = hex_id(0x11, 16);
    let mut malformed = direct_group("not-hex", &local, &peer);
    malformed.direct_member_ids_hex = None;
    let mut valid = direct_group(&valid_id, &local, &peer);
    valid.direct_member_ids_hex = None;
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![malformed, valid],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    store.refresh_chat_list_rows(&local, &no_mentions).unwrap();
    assert_eq!(
        store.unindexed_direct_conversation_group_ids().unwrap(),
        vec![valid_id]
    );
}

#[test]
fn direct_conversation_candidate_rows_follow_activity_not_pin_order() {
    let local = hex_id(0xaa, 32);
    let peer = hex_id(0xbb, 32);
    let older_id = hex_id(0x11, 16);
    let newer_id = hex_id(0x22, 16);
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![
                    direct_group(&older_id, &local, &peer),
                    direct_group(&newer_id, &local, &peer),
                ],
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
                 WHEN ?2 THEN 300
             END",
            rusqlite::params![older_id, newer_id],
        )
        .unwrap();
    }
    store.refresh_chat_list_rows(&local, &no_mentions).unwrap();
    store.set_chat_pinned(&older_id, true).unwrap();

    let chat_list = store
        .chat_list_rows(ChatListQuery::default())
        .unwrap()
        .into_iter()
        .map(|row| row.group_id_hex)
        .collect::<Vec<_>>();
    assert_eq!(
        chat_list,
        vec![older_id.clone(), newer_id.clone()],
        "visible chat list is pin-first"
    );

    let candidates = store
        .direct_conversation_candidate_rows(&peer)
        .unwrap()
        .into_iter()
        .map(|row| row.group_id_hex)
        .collect::<Vec<_>>();
    assert_eq!(
        candidates,
        vec![newer_id, older_id],
        "reuse candidates follow durable activity, not local pin order"
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

    // A bare re-record — relay redelivery, backfill replay, rejoin
    // reprocessing — is not evidence that the send reached the group, so the
    // preview stays failed.
    pending.source_message_id_hex = Some("source-after-replay".to_owned());
    store.record_app_event(&pending).unwrap();
    let replayed = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row")
        .last_message
        .expect("replayed preview");
    assert_eq!(replayed.message_id_hex, "pending");
    assert_eq!(
        replayed.delivery_state,
        ChatListMessageDeliveryState::Failed
    );

    // A successful retry does clear it. A resend inside the same second mints
    // the same NIP-01 id, so the send path re-records this very row and only
    // then calls `clear_local_publish_failure` — that order, because the fresh
    // send intent is the evidence the bare re-record above lacks, and the
    // tombstone must stand until the revival itself commits. The chat row must
    // transition that exact preview back to delivered rather than waiting for a
    // different message to replace it.
    pending.source_message_id_hex = Some("source-after-retry".to_owned());
    store.record_app_event(&pending).unwrap();
    store
        .clear_local_publish_failure(GROUP, "pending")
        .unwrap()
        .expect("a retracted local send clears");
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
fn chat_list_read_state_and_preview_follow_canonical_epoch_order() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    let mut epoch_seven = chat("message-7", REMOTE, 200, "epoch seven");
    epoch_seven.source_epoch = Some(7);
    store.record_app_event(&epoch_seven).unwrap();
    let mut epoch_eight = chat("message-8", REMOTE, 150, "epoch eight");
    epoch_eight.source_epoch = Some(8);
    store.record_app_event(&epoch_eight).unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.last_message.unwrap().message_id_hex, "message-8");

    let row = store
        .mark_timeline_message_read(LOCAL, GROUP, "message-7", &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.unread_count, 1);
    assert_eq!(
        row.first_unread_message_id_hex.as_deref(),
        Some("message-8")
    );

    store
        .mark_timeline_message_read(LOCAL, GROUP, "message-8", &no_mentions)
        .unwrap();
    let row = store
        .mark_timeline_message_read(LOCAL, GROUP, "message-7", &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(
        row.last_read_message_id_hex.as_deref(),
        Some("message-8"),
        "a later wall timestamp from an older epoch must not move the marker backward"
    );
    assert_eq!(row.unread_count, 0);
}

#[test]
fn newer_authenticated_message_replaces_older_pending_preview() {
    let store = setup_store();
    let mut pending = chat("pending", LOCAL, 100, "older pending send");
    pending.source_message_id_hex = None;
    pending.source_epoch = None;
    store.record_app_event(&pending).unwrap();

    let mut delivered = chat("delivered", LOCAL, 100, "newer delivered send");
    delivered.source_epoch = Some(7);
    store.record_app_event(&delivered).unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    let preview = row.last_message.expect("latest preview");
    assert_eq!(preview.message_id_hex, "delivered");
    assert_eq!(
        preview.delivery_state,
        ChatListMessageDeliveryState::Delivered
    );
}

#[test]
fn newer_pending_message_replaces_older_authenticated_preview() {
    let store = setup_store();
    let mut delivered = chat("delivered", LOCAL, 100, "older delivered send");
    delivered.source_epoch = Some(7);
    store.record_app_event(&delivered).unwrap();

    let mut pending = chat("pending", LOCAL, 100, "newer pending send");
    pending.source_message_id_hex = None;
    pending.source_epoch = None;
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
}

#[test]
fn pending_send_with_source_epoch_uses_pending_preview_ordering() {
    let store = setup_store();
    let mut delivered = chat("delivered", LOCAL, 100, "older delivered send");
    delivered.source_epoch = Some(8);
    store.record_app_event(&delivered).unwrap();

    // Source epoch is captured when the MLS message is encrypted, before a
    // relay-assigned source id exists. The missing source id is therefore the
    // authoritative pending signal even when the epoch is already present.
    let mut pending = chat("pending", LOCAL, 100, "newer pending send");
    pending.source_message_id_hex = None;
    pending.source_epoch = Some(7);
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
}

#[test]
fn replayed_older_authenticated_message_does_not_replace_newer_pending_preview() {
    let store = setup_store();
    let mut delivered = chat("delivered", LOCAL, 100, "older delivered send");
    delivered.source_epoch = Some(7);
    store.record_app_event(&delivered).unwrap();

    let mut pending = chat("pending", LOCAL, 150, "newer pending send");
    pending.source_message_id_hex = None;
    pending.source_epoch = None;
    store.record_app_event(&pending).unwrap();

    delivered.received_at = 200;
    store.record_app_event(&delivered).unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(
        row.last_message
            .as_ref()
            .map(|message| message.message_id_hex.as_str()),
        Some("pending")
    );
}

#[test]
fn ensure_repairs_a_stale_pending_preview_after_newer_authenticated_activity() {
    let store = setup_store();
    let mut pending = chat("pending", LOCAL, 100, "older pending send");
    pending.source_message_id_hex = None;
    pending.source_epoch = None;
    store.record_app_event(&pending).unwrap();
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();

    let mut delivered = chat("delivered", LOCAL, 100, "newer delivered send");
    delivered.source_epoch = Some(7);
    store.record_app_event(&delivered).unwrap();
    assert_eq!(
        store
            .chat_list_row(GROUP)
            .unwrap()
            .and_then(|row| row.last_message)
            .map(|message| message.message_id_hex),
        Some("pending".to_owned()),
        "the fixture must start with the stale persisted preview"
    );

    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();

    assert_eq!(
        store
            .chat_list_row(GROUP)
            .unwrap()
            .and_then(|row| row.last_message)
            .map(|message| message.message_id_hex),
        Some("delivered".to_owned())
    );
}

#[test]
fn group_system_read_marker_preserves_same_epoch_canonical_phase() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();

    let mut marker = group_system(
        "system-marker",
        REMOTE,
        200,
        GROUP_SYSTEM_TYPE_ADMIN_ADDED,
        "role changed",
    );
    marker.source_epoch = Some(7);
    store.record_app_event(&marker).unwrap();
    store
        .mark_timeline_message_read(LOCAL, GROUP, "system-marker", &no_mentions)
        .unwrap();

    let mut later_chat = chat("same-epoch-chat", REMOTE, 100, "later canonical phase");
    later_chat.source_epoch = Some(7);
    store.record_app_event(&later_chat).unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(
        row.last_read_message_id_hex.as_deref(),
        Some("system-marker")
    );
    assert_eq!(row.unread_count, 1);
    assert_eq!(
        row.first_unread_message_id_hex.as_deref(),
        Some("same-epoch-chat")
    );
}

#[test]
fn read_marker_follows_pending_send_into_authenticated_history() {
    let store = setup_store();
    let mut pending = chat("pending", LOCAL, 500, "optimistic send");
    pending.source_message_id_hex = None;
    pending.source_epoch = None;
    store.record_app_event(&pending).unwrap();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();

    pending.source_message_id_hex = Some("source-pending".to_owned());
    pending.source_epoch = Some(7);
    store.record_app_event(&pending).unwrap();

    let mut incoming = chat("incoming", REMOTE, 100, "newer authenticated message");
    incoming.source_epoch = Some(8);
    store.record_app_event(&incoming).unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.last_read_message_id_hex.as_deref(), Some("pending"));
    assert_eq!(row.unread_count, 1);
    assert_eq!(row.first_unread_message_id_hex.as_deref(), Some("incoming"));
}

#[test]
fn failed_pending_read_marker_does_not_hide_authenticated_history() {
    let store = setup_store();
    for epoch in 1..=8 {
        let mut accepted = chat(
            &format!("accepted-{epoch}"),
            REMOTE,
            epoch * 10,
            "accepted history",
        );
        accepted.source_epoch = Some(epoch);
        store.record_app_event(&accepted).unwrap();
    }
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();

    let mut pending = chat("pending", LOCAL, 500, "optimistic send");
    pending.source_message_id_hex = None;
    pending.source_epoch = None;
    store.record_app_event(&pending).unwrap();
    store
        .invalidate_app_event_by_message_id(GROUP, "pending", "local_publish_failed")
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.unread_count, 0);
    assert_eq!(row.last_read_message_id_hex.as_deref(), Some("accepted-8"));

    let mut incoming = chat("incoming", REMOTE, 100, "authenticated message");
    incoming.source_epoch = Some(9);
    store.record_app_event(&incoming).unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.last_read_message_id_hex.as_deref(), Some("accepted-8"));
    assert_eq!(row.unread_count, 1);
    assert_eq!(row.first_unread_message_id_hex.as_deref(), Some("incoming"));
}

#[test]
fn pruned_read_marker_keeps_canonical_epoch_anchor() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();

    let mut marker = chat("marker", REMOTE, 150, "newer epoch");
    marker.source_epoch = Some(8);
    store.record_app_event(&marker).unwrap();
    store
        .mark_timeline_message_read(LOCAL, GROUP, "marker", &no_mentions)
        .unwrap();

    {
        let conn = store.lock().unwrap();
        conn.execute(
            "DELETE FROM message_timeline
             WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![GROUP, "marker"],
        )
        .unwrap();
    }

    let mut late_older = chat("late-older", REMOTE, 900, "older epoch");
    late_older.source_epoch = Some(7);
    store.record_app_event(&late_older).unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.unread_count, 0);
    assert_eq!(row.last_read_message_id_hex.as_deref(), Some("marker"));

    let row = store
        .mark_timeline_message_read(LOCAL, GROUP, "late-older", &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.last_read_message_id_hex.as_deref(), Some("marker"));
    assert_eq!(row.last_read_timeline_at, Some(150));
}

#[test]
fn failed_local_send_does_not_replace_delivered_preview_after_prune_or_ensure() {
    let store = setup_store();
    let mut pruned = chat("pruned", REMOTE, 10, "expired history");
    pruned.source_epoch = Some(6);
    store.record_app_event(&pruned).unwrap();
    let mut failed = chat("failed", LOCAL, 300, "did not reach the group");
    failed.source_message_id_hex = None;
    store.record_app_event(&failed).unwrap();
    store
        .invalidate_app_event_by_message_id(GROUP, "failed", "local_publish_failed")
        .unwrap();

    let mut delivered = chat("delivered", REMOTE, 150, "accepted history");
    delivered.source_epoch = Some(8);
    store.record_app_event(&delivered).unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(
        row.last_message
            .as_ref()
            .map(|message| message.message_id_hex.as_str()),
        Some("delivered")
    );

    store
        .secure_prune_app_events_before(GROUP, 20, LOCAL, &no_mentions)
        .unwrap();
    let after_prune = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert_eq!(
        after_prune
            .last_message
            .as_ref()
            .map(|message| message.message_id_hex.as_str()),
        Some("delivered")
    );

    {
        let conn = store.lock().unwrap();
        assert!(
            chat_list_projection_complete_tx(&conn, LOCAL, &no_mentions).unwrap(),
            "failed-send preview priority must match the completeness query"
        );
    }
    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let after_ensure = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert_eq!(
        after_ensure
            .last_message
            .as_ref()
            .map(|message| message.message_id_hex.as_str()),
        Some("delivered")
    );
}

#[test]
fn secure_prune_does_not_resurrect_a_pending_preview_displaced_by_accepted_activity() {
    let store = setup_store();
    let mut pending = chat("pending", LOCAL, 300, "older unresolved send");
    pending.source_message_id_hex = None;
    pending.source_epoch = None;
    store.record_app_event(&pending).unwrap();

    let mut accepted = chat("accepted", REMOTE, 10, "newer accepted activity");
    accepted.source_epoch = Some(7);
    store.record_app_event(&accepted).unwrap();

    let before = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(
        before
            .last_message
            .as_ref()
            .map(|message| message.message_id_hex.as_str()),
        Some("accepted")
    );

    store
        .secure_prune_app_events_before(GROUP, 20, LOCAL, &no_mentions)
        .unwrap();

    let after_prune = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert!(
        after_prune.last_message.is_none(),
        "the older pending send must stay displaced after its accepted witness is pruned"
    );
    let accepted_high_water = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT accepted_activity_insert_order
             FROM chat_list_rows
             WHERE group_id_hex = ?1",
            params![GROUP],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert!(accepted_high_water > 0);

    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();
    assert!(
        store
            .chat_list_row(GROUP)
            .unwrap()
            .expect("rebuilt chat row")
            .last_message
            .is_none(),
        "projection repair must preserve the durable pending demotion"
    );
}

#[test]
fn secure_prune_keeps_chat_preview_on_canonical_latest_epoch() {
    let store = setup_store();
    let mut pruned = chat("pruned", REMOTE, 10, "old");
    pruned.source_epoch = Some(6);
    store.record_app_event(&pruned).unwrap();
    let mut epoch_seven = chat("message-7", REMOTE, 200, "epoch seven");
    epoch_seven.source_epoch = Some(7);
    store.record_app_event(&epoch_seven).unwrap();
    let mut epoch_eight = chat("message-8", REMOTE, 150, "epoch eight");
    epoch_eight.source_epoch = Some(8);
    store.record_app_event(&epoch_eight).unwrap();

    let before = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(before.last_message.unwrap().message_id_hex, "message-8");

    store
        .secure_prune_app_events_before(GROUP, 20, LOCAL, &no_mentions)
        .unwrap();

    let after = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert_eq!(after.last_message.unwrap().message_id_hex, "message-8");
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
fn remote_group_system_event_advances_preview_unread_and_read_marker() {
    let store = setup_store();
    store
        .record_app_event(&chat("old", REMOTE, 10, "before role change"))
        .unwrap();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();

    let system_at = unix_now_seconds() + 1;
    let payload = r#"{"v":1,"system_type":"admin_added","text":"Admin added"}"#;
    store
        .record_app_event(&group_system(
            "made-admin",
            REMOTE,
            system_at,
            GROUP_SYSTEM_TYPE_ADMIN_ADDED,
            payload,
        ))
        .unwrap();
    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");

    let preview = row.last_message.expect("group-system preview");
    assert_eq!(preview.message_id_hex, "made-admin");
    assert_eq!(preview.kind, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM);
    assert_eq!(preview.plaintext, payload);
    assert_eq!(row.activity_sort_at, system_at);
    assert_eq!(row.unread_count, 1);
    assert_eq!(
        row.first_unread_message_id_hex.as_deref(),
        Some("made-admin")
    );

    let read = store
        .mark_timeline_message_read(LOCAL, GROUP, "made-admin", &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(read.unread_count, 0);
    assert_eq!(read.last_read_message_id_hex.as_deref(), Some("made-admin"));
}

#[test]
fn every_membership_and_admin_system_type_signals_activity() {
    for system_type in [
        GROUP_SYSTEM_TYPE_MEMBER_ADDED,
        GROUP_SYSTEM_TYPE_MEMBER_REMOVED,
        GROUP_SYSTEM_TYPE_MEMBER_LEFT,
        GROUP_SYSTEM_TYPE_ADMIN_ADDED,
        GROUP_SYSTEM_TYPE_ADMIN_REMOVED,
    ] {
        let store = setup_store();
        store
            .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
            .unwrap();
        store
            .record_app_event(&group_system(
                system_type,
                REMOTE,
                unix_now_seconds() + 1,
                system_type,
                &format!(r#"{{"v":1,"system_type":"{system_type}","text":"Changed"}}"#),
            ))
            .unwrap();

        let row = store
            .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
            .unwrap()
            .expect("chat row");
        assert_eq!(
            row.last_message
                .expect("group activity preview")
                .message_id_hex,
            system_type,
        );
        assert_eq!(row.unread_count, 1, "system type {system_type}");
    }
}

#[test]
fn own_group_system_event_advances_preview_without_becoming_unread() {
    let store = setup_store();
    store
        .record_app_event(&chat("old", REMOTE, 10, "before role change"))
        .unwrap();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();

    let system_at = unix_now_seconds() + 1;
    store
        .record_app_event(&group_system(
            "own-role-change",
            LOCAL,
            system_at,
            GROUP_SYSTEM_TYPE_ADMIN_ADDED,
            r#"{"v":1,"system_type":"admin_added","text":"Admin added"}"#,
        ))
        .unwrap();
    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");

    assert_eq!(
        row.last_message
            .expect("group-system preview")
            .message_id_hex,
        "own-role-change"
    );
    assert_eq!(row.activity_sort_at, system_at);
    assert_eq!(row.unread_count, 0);
}

#[test]
fn group_system_payload_does_not_increment_mentions() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &mentions_local)
        .unwrap();
    store
        .record_app_event(&group_system(
            "role-change",
            REMOTE,
            20,
            GROUP_SYSTEM_TYPE_ADMIN_ADDED,
            r#"{"v":1,"system_type":"admin_added","text":"Admin added","data":{"subject":"aa"}}"#,
        ))
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &mentions_local)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.unread_count, 1);
    assert_eq!(row.unread_mention_count, 0);
}

#[test]
fn unrelated_group_system_event_does_not_signal_chat_list_activity() {
    let store = setup_store();
    store
        .record_app_event(&chat("old", REMOTE, 10, "existing preview"))
        .unwrap();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    let before = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");

    store
        .record_app_event(&group_system(
            "renamed",
            REMOTE,
            unix_now_seconds() + 1,
            GROUP_SYSTEM_TYPE_GROUP_RENAMED,
            r#"{"v":1,"system_type":"group_renamed","text":"Group renamed"}"#,
        ))
        .unwrap();
    let after = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");

    assert_eq!(
        after.last_message.expect("existing preview").message_id_hex,
        "old"
    );
    assert_eq!(after.activity_sort_at, before.activity_sort_at);
    assert_eq!(after.unread_count, 0);
}

#[test]
fn invalidated_group_activity_is_removed_from_preview_and_unread() {
    let store = setup_store();
    store
        .record_app_event(&chat("old", REMOTE, 10, "existing preview"))
        .unwrap();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&group_system(
            "rolled-back-role",
            REMOTE,
            unix_now_seconds() + 1,
            GROUP_SYSTEM_TYPE_ADMIN_ADDED,
            r#"{"v":1,"system_type":"admin_added","text":"Admin added"}"#,
        ))
        .unwrap();
    let signaled = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(signaled.unread_count, 1);
    assert_eq!(
        signaled.last_message.expect("role preview").message_id_hex,
        "rolled-back-role"
    );

    store
        .invalidate_app_event_by_message_id(GROUP, "rolled-back-role", "LosingBranch")
        .unwrap();
    let reconciled = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(reconciled.unread_count, 0);
    assert_eq!(
        reconciled
            .last_message
            .expect("restored preview")
            .message_id_hex,
        "old"
    );
}

#[test]
fn direct_conversation_does_not_project_admin_activity() {
    let mut direct = group();
    direct.profile_name.clear();
    direct.member_count = Some(2);
    let store = setup_store_with_group(direct);
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();

    store
        .record_app_event(&group_system(
            "direct-role-change",
            REMOTE,
            unix_now_seconds() + 1,
            GROUP_SYSTEM_TYPE_ADMIN_ADDED,
            r#"{"v":1,"system_type":"admin_added","text":"Admin added"}"#,
        ))
        .unwrap();
    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");

    assert_eq!(row.conversation_kind, ChatConversationKind::Direct);
    assert!(row.last_message.is_none());
    assert_eq!(row.unread_count, 0);
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
fn secure_prune_preserves_a_newer_group_system_preview() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat("expiring-chat", REMOTE, 10, "old chat"))
        .unwrap();
    store
        .record_app_event(&group_system(
            "retained-role-change",
            REMOTE,
            20,
            GROUP_SYSTEM_TYPE_ADMIN_ADDED,
            r#"{"v":1,"system_type":"admin_added","text":"Admin added"}"#,
        ))
        .unwrap();

    let before = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(
        before.last_message.expect("system preview").message_id_hex,
        "retained-role-change"
    );
    assert_eq!(before.unread_count, 2);

    store
        .secure_prune_app_events_before(GROUP, 15, LOCAL, &no_mentions)
        .unwrap();

    let after = store.chat_list_row(GROUP).unwrap().expect("chat row");
    let preview = after.last_message.expect("retained system preview");
    assert_eq!(preview.message_id_hex, "retained-role-change");
    assert_eq!(preview.kind, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM);
    assert_eq!(after.unread_count, 1);
    assert_eq!(
        after.first_unread_message_id_hex.as_deref(),
        Some("retained-role-change")
    );
}

#[test]
fn secure_prune_retains_pruned_group_system_activity_as_the_sort_anchor() {
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
        .record_app_event(&chat("older-chat", REMOTE, 100, "older activity"))
        .unwrap();
    store
        .record_app_event(&group_system(
            "pruned-role-change",
            REMOTE,
            200,
            GROUP_SYSTEM_TYPE_ADMIN_ADDED,
            r#"{"v":1,"system_type":"admin_added","text":"Admin added"}"#,
        ))
        .unwrap();

    let before = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(before.activity_sort_at, 200);
    assert_eq!(
        before.last_message.expect("system preview").message_id_hex,
        "pruned-role-change"
    );

    store
        .secure_prune_app_events_before(GROUP, 201, LOCAL, &no_mentions)
        .unwrap();

    let after = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert!(after.last_message.is_none());
    assert_eq!(after.activity_sort_at, 200);
    let retained_activity_sort_at = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT retained_activity_sort_at FROM chat_list_rows WHERE group_id_hex = ?1",
            params![GROUP],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(retained_activity_sort_at, 200);

    store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
    assert_eq!(
        store
            .chat_list_row(GROUP)
            .unwrap()
            .expect("rebuilt chat row")
            .activity_sort_at,
        200
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
fn targeted_refresh_classifies_only_changed_unread_messages() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat("first", REMOTE, 10, "hello"))
        .unwrap();
    store
        .record_app_event(&chat("second", REMOTE, 20, "hello again"))
        .unwrap();

    let classifier_calls = std::cell::Cell::new(0usize);
    let classifier = |plaintext: &str, _tags: &[Vec<String>]| {
        classifier_calls.set(classifier_calls.get() + 1);
        plaintext.contains("@local")
    };
    store
        .refresh_chat_list_row(LOCAL, GROUP, &classifier)
        .unwrap();
    assert_eq!(classifier_calls.get(), 2);

    classifier_calls.set(0);
    store
        .record_app_event(&chat("third", REMOTE, 30, "hello @local"))
        .unwrap();
    let row = store
        .refresh_chat_list_row_for_messages(LOCAL, GROUP, &["third".to_owned()], &classifier)
        .unwrap()
        .expect("chat row");
    assert_eq!(classifier_calls.get(), 1);
    assert_eq!(row.unread_count, 3);
    assert_eq!(row.unread_mention_count, 1);
    assert_eq!(row.first_unread_message_id_hex.as_deref(), Some("first"));

    classifier_calls.set(0);
    store
        .invalidate_app_event_by_message_id(GROUP, "third", "LosingBranch")
        .unwrap();
    let row = store
        .refresh_chat_list_row_for_messages(LOCAL, GROUP, &["third".to_owned()], &classifier)
        .unwrap()
        .expect("chat row");
    assert_eq!(classifier_calls.get(), 0);
    assert_eq!(row.unread_count, 2);
    assert_eq!(row.unread_mention_count, 0);
}

#[test]
fn ensure_repairs_timeline_change_left_dirty_before_chat_list_refresh() {
    let store = setup_store();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat("first", REMOTE, 10, "first"))
        .unwrap();
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();

    // Model a process stop between the timeline commit and the app's targeted
    // chat-list refresh. The trigger-owned marker must make startup repair it.
    store
        .record_app_event(&chat("second", REMOTE, 20, "second"))
        .unwrap();
    {
        let conn = store.lock().unwrap();
        let dirty: i64 = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM chat_list_unread_dirty_groups
                    WHERE group_id_hex = ?1
                 )",
                params![GROUP],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dirty, 1);
    }

    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let row = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert_eq!(row.unread_count, 2);
    let conn = store.lock().unwrap();
    let dirty: i64 = conn
        .query_row(
            "SELECT count(*) FROM chat_list_unread_dirty_groups",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(dirty, 0);
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
        conn.execute(
            "UPDATE chat_list_projection_meta SET mention_counts_version = 0 WHERE id = 1",
            [],
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
fn ensure_chat_list_rows_reconciles_pre_group_system_projection() {
    let store = setup_store();
    store
        .record_app_event(&chat("old", REMOTE, 10, "before first open"))
        .unwrap();
    store
        .initialize_chat_read_state(LOCAL, GROUP, &no_mentions)
        .unwrap();

    let system_at = unix_now_seconds() + 1;
    store
        .record_app_event(&group_system(
            "role-change",
            REMOTE,
            system_at,
            GROUP_SYSTEM_TYPE_ADMIN_ADDED,
            r#"{"v":1,"system_type":"admin_added","text":"Admin added"}"#,
        ))
        .unwrap();
    let mut newest_chat = chat(
        "newest-chat",
        REMOTE,
        system_at + 1,
        "newer visible preview",
    );
    newest_chat.source_epoch = Some(system_at + 1);
    store.record_app_event(&newest_chat).unwrap();
    let current = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(current.unread_count, 2);
    assert_eq!(
        current.last_message.expect("latest preview").message_id_hex,
        "newest-chat"
    );

    // Simulate a version-1 row: its latest preview is structurally correct,
    // but it counted only the kind-9 message and silently omitted the older
    // kind-1210 role event.
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "UPDATE chat_list_rows SET unread_count = 1 WHERE group_id_hex = ?1",
            params![GROUP],
        )
        .unwrap();
        conn.execute(
            "UPDATE chat_list_projection_meta SET mention_counts_version = 1 WHERE id = 1",
            [],
        )
        .unwrap();
    }

    store.ensure_chat_list_rows(LOCAL, &no_mentions).unwrap();
    let reconciled = store.chat_list_row(GROUP).unwrap().expect("chat row");
    assert_eq!(reconciled.unread_count, 2);
    let projection_version: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT mention_counts_version FROM chat_list_projection_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(projection_version, CHAT_LIST_PROJECTION_VERSION);
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

fn chat_in(group_id_hex: &str, id: &str, sender: &str, at: u64, plaintext: &str) -> StoredAppEvent {
    let mut event = chat(id, sender, at, plaintext);
    event.group_id_hex = group_id_hex.to_owned();
    event
}

fn materialize_one_unread(store: &SqliteAccountStorage, group_id_hex: &str) {
    store
        .record_app_event(&chat_in(
            group_id_hex,
            "old",
            REMOTE,
            10,
            "before first open",
        ))
        .unwrap();
    store
        .refresh_chat_list_row(LOCAL, group_id_hex, &no_mentions)
        .unwrap();
    store
        .initialize_chat_read_state(LOCAL, group_id_hex, &no_mentions)
        .unwrap();
    store
        .record_app_event(&chat_in(
            group_id_hex,
            "new",
            REMOTE,
            11,
            "after first open",
        ))
        .unwrap();
    let row = store
        .refresh_chat_list_row(LOCAL, group_id_hex, &no_mentions)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.unread_count, 1);
}

fn put_disband_tombstone_for(store: &SqliteAccountStorage, group_id_hex: &str) {
    use cgka_traits::DisbandTombstone;
    use cgka_traits::storage::DisbandTombstoneStorage;
    use cgka_traits::types::{EpochId, MemberId};

    store
        .put_disband_tombstone(
            &GroupId::new(hex::decode(group_id_hex).expect("group id hex")),
            &DisbandTombstone {
                epoch: EpochId(1),
                actor: MemberId::new(vec![0xbb; 4]),
                origin_commit_id: None,
                commit_digest: [0; 32],
                local_was_committer_leaf: false,
                former_members: Vec::new(),
                announced: false,
            },
        )
        .unwrap();
}

#[test]
fn account_unread_total_counts_pending_invite_as_attention_only() {
    let mut pending = group();
    pending.pending_confirmation = true;
    let store = setup_store_with_group(pending);
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();

    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 0);
    assert_eq!(total.unread_conversations, 1);
    assert_eq!(total.attention_only_conversations, 1);
    assert!(total.has_unread());
}

#[test]
fn account_unread_total_does_not_double_count_unread_plus_manual() {
    let store = setup_store_with_one_unread();
    store
        .set_chat_manually_unread(LOCAL, GROUP, true, &no_mentions)
        .unwrap();

    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 1);
    assert_eq!(total.unread_conversations, 1);
    assert_eq!(total.attention_only_conversations, 0);
}

#[test]
fn account_unread_total_does_not_double_count_unread_plus_pending() {
    let mut pending = group();
    pending.pending_confirmation = true;
    let store = setup_store_with_group(pending);
    materialize_one_unread(&store, GROUP);

    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 1);
    assert_eq!(total.unread_conversations, 1);
    assert_eq!(total.attention_only_conversations, 0);
}

#[test]
fn account_unread_total_excludes_archived_attention_only_rows() {
    let mut archived_pending = group();
    archived_pending.pending_confirmation = true;
    archived_pending.archived = true;
    let store = setup_store_with_group(archived_pending);
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    store
        .set_chat_manually_unread(LOCAL, GROUP, true, &no_mentions)
        .unwrap();

    let total = store.account_unread_total().unwrap();
    assert_eq!(total, AccountUnreadTotal::default());
    assert!(!total.has_unread());
}

#[test]
fn account_unread_total_suppresses_left_removed_and_disbanded_attention() {
    let mut pending = group();
    pending.pending_confirmation = true;
    let store = setup_store_with_group(pending);
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
    assert_eq!(
        store
            .account_unread_total()
            .unwrap()
            .attention_only_conversations,
        1
    );

    store
        .set_group_self_membership(GROUP, SelfMembership::Left)
        .unwrap();
    assert_eq!(
        store.account_unread_total().unwrap(),
        AccountUnreadTotal::default()
    );

    store
        .set_group_self_membership(GROUP, SelfMembership::Member)
        .unwrap();
    store
        .set_group_self_membership(GROUP, SelfMembership::Removed)
        .unwrap();
    assert_eq!(
        store.account_unread_total().unwrap(),
        AccountUnreadTotal::default()
    );

    store
        .set_group_self_membership(GROUP, SelfMembership::Member)
        .unwrap();
    put_disband_tombstone_for(&store, GROUP);
    assert_eq!(
        store.account_unread_total().unwrap(),
        AccountUnreadTotal::default()
    );
}

#[test]
fn account_unread_total_sums_distinct_attention_only_rows() {
    let pending = StoredAccountGroup {
        group_id_hex: "22".to_owned(),
        pending_confirmation: true,
        ..group()
    };
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![group(), pending],
                ..StoredAccountState::default()
            },
            256,
            MAX_FUTURE_SKEW_SECS,
        )
        .unwrap();
    store.refresh_chat_list_rows(LOCAL, &no_mentions).unwrap();
    store
        .set_chat_manually_unread(LOCAL, GROUP, true, &no_mentions)
        .unwrap();

    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 0);
    assert_eq!(total.unread_conversations, 2);
    assert_eq!(total.attention_only_conversations, 2);
    assert!(total.has_unread());
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
