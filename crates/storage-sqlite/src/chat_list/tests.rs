use super::*;
use crate::{StoredAccountGroup, StoredAccountGroupComponent, StoredAccountState, StoredAppEvent};
use cgka_traits::app_components::{
    GROUP_AVATAR_URL_COMPONENT, GROUP_AVATAR_URL_COMPONENT_ID, GroupAvatarUrlV1,
    encode_group_avatar_url_v1,
};
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_REACTION,
};

const LOCAL: &str = "aa";
const REMOTE: &str = "bb";
const GROUP: &str = "11";

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
        welcomer_account_id_hex: None,
        via_welcome_message_id_hex: None,
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
        dim: None,
        thumbhash: None,
    })
    .unwrap();
    StoredAccountGroupComponent {
        component_id: GROUP_AVATAR_URL_COMPONENT_ID,
        component_name: GROUP_AVATAR_URL_COMPONENT.to_owned(),
        component_data_hex: hex::encode(bytes),
    }
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

    // Convergence invalidates the losing-branch row (kept as a tombstone).
    store
        .invalidate_app_event_by_message_id(GROUP, "phantom", "LosingBranch")
        .unwrap();

    // Preview and sort anchor must fall back to the visible delivered message,
    // not the invalidated tombstone.
    let row = store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap()
        .expect("chat row");
    let last_message = row.last_message.expect("last message");
    assert_eq!(last_message.message_id_hex, "visible");
    assert_eq!(last_message.plaintext, "real message");
    assert_eq!(last_message.timeline_at, 10);

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
fn account_unread_total_suppresses_removed_self_membership_group() {
    let store = setup_store_with_one_unread();

    // Default 'member' membership still counts.
    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 1);
    assert_eq!(total.unread_conversations, 1);

    store.set_group_self_membership(GROUP, true).unwrap();

    // Once the local account is known-removed, the group's unread is suppressed.
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
    store.set_group_self_membership(GROUP, false).unwrap();
    let total = store.account_unread_total().unwrap();
    assert_eq!(total.unread_count, 1);
    assert_eq!(total.unread_conversations, 1);
}

#[test]
fn account_unread_total_unsuppresses_after_rejoin() {
    let store = setup_store_with_one_unread();

    store.set_group_self_membership(GROUP, true).unwrap();
    assert_eq!(
        store.account_unread_total().unwrap(),
        AccountUnreadTotal::default()
    );

    // A re-add restores counting.
    store.set_group_self_membership(GROUP, false).unwrap();
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
    store.set_group_self_membership(GROUP, true).unwrap();
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
        )
        .unwrap();

    // Both rows start at the default 'member', so both are candidates.
    assert_eq!(
        store.account_group_ids_defaulting_to_member().unwrap(),
        vec![GROUP.to_owned(), "22".to_owned()]
    );

    // Once a row is flipped to 'removed' it drops out of the candidate set.
    store.set_group_self_membership(GROUP, true).unwrap();
    assert_eq!(
        store.account_group_ids_defaulting_to_member().unwrap(),
        vec!["22".to_owned()]
    );

    // Re-affirming 'member' keeps a row in the candidate set (still default).
    store.set_group_self_membership("22", false).unwrap();
    assert_eq!(
        store.account_group_ids_defaulting_to_member().unwrap(),
        vec!["22".to_owned()]
    );

    // No defaulted rows left once every row is explicitly resolved.
    store.set_group_self_membership("22", true).unwrap();
    assert!(
        store
            .account_group_ids_defaulting_to_member()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn set_group_self_membership_propagates_backend_errors() {
    // darkmatter#573 review follow-up (blocking finding 2): the
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
    let result = store.set_group_self_membership(GROUP, true);
    assert!(
        result.is_err(),
        "a failed self_membership projection write must return an error, not silently succeed"
    );
}
