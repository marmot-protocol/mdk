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
    StoredAppEvent {
        group_id_hex: GROUP.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: if sender == LOCAL { "sent" } else { "received" }.to_owned(),
        sender: sender.to_owned(),
        plaintext: plaintext.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
    }
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
        .initialize_chat_read_state(LOCAL, "missing-group")
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
        .refresh_chat_list_row(LOCAL, GROUP)
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
        store.refresh_chat_list_row(LOCAL, "missing-group").unwrap(),
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
        .refresh_chat_list_row(LOCAL, GROUP)
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

    store.refresh_chat_list_row(LOCAL, GROUP).unwrap();
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

    store.refresh_chat_list_row(LOCAL, GROUP).unwrap();
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

    store.ensure_chat_list_rows(LOCAL).unwrap();
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
    store.refresh_chat_list_row(LOCAL, GROUP).unwrap();
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

    store.ensure_chat_list_rows(LOCAL).unwrap();
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
    store.refresh_chat_list_row(LOCAL, GROUP).unwrap();
    store
        .record_app_event(&chat("new", REMOTE, 11, "new preview"))
        .unwrap();

    store.ensure_chat_list_rows(LOCAL).unwrap();
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
    store.refresh_chat_list_row(LOCAL, GROUP).unwrap();
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

    store.ensure_chat_list_rows(LOCAL).unwrap();
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
        .refresh_chat_list_row(LOCAL, GROUP)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.group_id_hex, GROUP);
    assert_eq!(row.title, "Marmot Lab");
    assert_eq!(row.unread_count, 0);
    assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "old");

    store.initialize_chat_read_state(LOCAL, GROUP).unwrap();
    store
        .record_app_event(&reaction("reaction", REMOTE, "old", 11))
        .unwrap();
    store
        .record_app_event(&chat("new", REMOTE, 12, "after first open"))
        .unwrap();

    let row = store
        .refresh_chat_list_row(LOCAL, GROUP)
        .unwrap()
        .expect("chat row");
    assert_eq!(row.unread_count, 1);
    assert_eq!(row.first_unread_message_id_hex.as_deref(), Some("new"));

    store
        .mark_timeline_message_read(LOCAL, GROUP, "new")
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
    store.initialize_chat_read_state(LOCAL, GROUP).unwrap();

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
            .refresh_chat_list_row(LOCAL, GROUP)
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
        .mark_timeline_message_read(LOCAL, GROUP, "visible")
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
    store.initialize_chat_read_state(LOCAL, GROUP).unwrap();
    store
        .record_app_event(&chat("remote", REMOTE, 10, "unread"))
        .unwrap();
    assert_eq!(
        store
            .refresh_chat_list_row(LOCAL, GROUP)
            .unwrap()
            .expect("chat row")
            .unread_count,
        1
    );

    store
        .record_app_event(&chat("own", LOCAL, 11, "my reply"))
        .unwrap();
    store
        .mark_timeline_message_read(LOCAL, GROUP, "own")
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
