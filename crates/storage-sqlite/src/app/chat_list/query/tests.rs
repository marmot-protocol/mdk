use super::*;
use crate::{
    ChatListMessageDeliveryState, ChatListPageError, ChatListSelectionError, SqliteAccountStorage,
    SqliteAppStorage, StoredAppEvent, base::test_support::chat_list_window_page,
};
use ChatListCondition as C;
use ChatListFilter as F;
use cgka_traits::MARMOT_APP_EVENT_KIND_POLL;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_REACTION};
use cgka_traits::storage::{
    DisbandRequest, DisbandRequestStatus, DisbandRequestStorage, LeaveRequest, LeaveRequestStorage,
};
use cgka_traits::types::GroupId;
use rusqlite::params;

/// The time every read here runs at, unless a test sets its own.
const NOW: i64 = 1_000_000;

/// One chat, with optional base facts. Activity orders rows: earlier seeds sort first.
/// Kind facts: `direct` (two member accounts), `trio` (three), `named` (a group
/// name). With none the member count is unknown and the name empty: Unknown kind.
fn seed(store: &SqliteAccountStorage, id: &str, facts: &[&str]) {
    let has = |fact| facts.contains(&fact);
    let member_count = if has("direct") {
        Some(2)
    } else if has("trio") {
        Some(3)
    } else {
        None
    };
    let conn = store.lock().unwrap();
    conn.execute(
        "INSERT INTO account_groups(group_id_hex, endpoint, updated_at, archived, self_membership, pending_confirmation, member_count)
         VALUES (?1, '', 0, ?2, ?3, ?4, ?5)",
        params![id, has("archived"), if has("left") { "left" } else { "member" }, has("invite"), member_count],
    )
    .unwrap();
    let activity: i64 = conn
        .query_row("SELECT count(*) FROM chat_list_rows", [], |r| r.get(0))
        .unwrap();
    conn.execute(
        "INSERT INTO chat_list_rows(group_id_hex, updated_at, activity_sort_at, archived, self_membership,
             pending_confirmation, unread_count, manually_marked_unread, unread_mention_count, group_name)
         VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            id,
            1000 - activity,
            has("archived"),
            if has("left") { "left" } else { "member" },
            has("invite"),
            if has("unread") || has("mention") { 3 } else { 0 },
            has("manual"),
            i64::from(has("mention")),
            if has("named") { "Team" } else { "" },
        ],
    )
    .unwrap();
    if has("pinned") {
        conn.execute(
            "INSERT INTO chat_pin_positions(group_id_hex, ordinal)
             VALUES (?1, (SELECT count(*) FROM chat_pin_positions))",
            [id],
        )
        .unwrap();
    }
}

/// Mute a chat until `until_ms`, or until unmuted with `None`.
fn mute(store: &SqliteAccountStorage, id: &str, until_ms: Option<i64>) {
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO chat_notification_settings(group_id_hex, muted_until_ms, updated_at_ms)
             VALUES (?1, ?2, 0)",
            params![id, until_ms],
        )
        .unwrap();
}

/// Install base rows as complete: the fixture writes them directly.
fn ready(store: &SqliteAccountStorage) {
    store
        .lock()
        .unwrap()
        .execute("DELETE FROM chat_presentation_row_work", [])
        .unwrap();
}

/// The engine's group row, which leave and disband records reference.
fn engine_group(store: &SqliteAccountStorage, id: &str) -> GroupId {
    let bytes = hex::decode(id).unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_groups(id, epoch, record) VALUES (?1, 0, x'00')",
            [&bytes],
        )
        .unwrap();
    GroupId::new(bytes)
}

fn draft(store: &SqliteAccountStorage, id: &str, content: &str, attachment: bool) {
    let conn = store.lock().unwrap();
    conn.execute(
        "INSERT INTO message_drafts(group_id_hex, content, created_at_ms, updated_at_ms) VALUES (?1, ?2, 0, 0)",
        params![id, content],
    )
    .unwrap();
    if attachment {
        conn.execute(
            "INSERT INTO message_draft_attachments(group_id_hex, position, attachment_id, file_name, media_type, plaintext)
             VALUES (?1, 0, 'a', 'f.png', 'image/png', x'00')",
            [id],
        )
        .unwrap();
    }
}

/// A sent event still waiting for relay acceptance (no source message yet).
fn send(app: &SqliteAppStorage, group: &str, id: &str, kind: u64) {
    app.record_app_event(&StoredAppEvent {
        group_id_hex: group.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: None,
        source_epoch: None,
        direction: "sent".to_owned(),
        sender: "aa".to_owned(),
        plaintext: "hello".to_owned(),
        kind,
        tags: Vec::new(),
        recorded_at: 10,
        received_at: 10,
        origin_commit_id: None,
        moderation_grant: false,
    })
    .unwrap();
}

/// A relay-accepted message from another member, newer than any `send`.
fn receive(app: &SqliteAppStorage, group: &str, id: &str) {
    app.record_app_event(&StoredAppEvent {
        group_id_hex: group.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(id.to_owned()),
        source_epoch: Some(1),
        direction: "received".to_owned(),
        sender: "bb".to_owned(),
        plaintext: "reply".to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: 20,
        received_at: 20,
        origin_commit_id: None,
        moderation_grant: false,
    })
    .unwrap();
}

fn ids(app: &SqliteAppStorage, view: ChatListView, filter: ChatListFilter) -> Vec<String> {
    ids_at(app, view, filter, NOW)
}

/// Window rows of `query` read at `now_ms`.
fn rows_at(
    app: &SqliteAppStorage,
    query: impl Into<ChatListViewQuery>,
    now_ms: i64,
) -> crate::ChatListWindowRead {
    app.read_chat_list_window(crate::ChatListWindowQuery {
        query: query.into(),
        limit: 100,
        anchors: Vec::new(),
        before_anchor: 0,
        now_ms,
    })
    .unwrap()
}

/// Select-all IDs read at `now_ms`, checked against the window and revalidation
/// of every chat in the account at the same time: all three compile one query.
fn ids_at(
    app: &SqliteAppStorage,
    view: ChatListView,
    filter: ChatListFilter,
    now_ms: i64,
) -> Vec<String> {
    let query = ChatListViewQuery {
        view,
        filter: Some(filter),
    };
    let ids = app.chat_list_ids(query.clone(), now_ms).unwrap();
    let page = rows_at(app, query.clone(), now_ms).page;
    assert_eq!(
        page.rows
            .iter()
            .map(|r| &r.group_id_hex)
            .collect::<Vec<_>>(),
        ids.iter().collect::<Vec<_>>()
    );
    let mut every_chat: Vec<String> = [
        ChatListView::Chats,
        ChatListView::Archived,
        ChatListView::Left,
    ]
    .into_iter()
    .flat_map(|view| app.chat_list_ids(view, now_ms).unwrap())
    .collect();
    every_chat.reverse();
    let mut kept = app
        .revalidate_chat_list_ids(query, &every_chat, now_ms)
        .unwrap();
    kept.sort();
    let mut expected = ids.clone();
    expected.sort();
    assert_eq!(kept, expected, "revalidation of every chat");
    ids
}

/// The peer every `present` call with peer names selects.
fn peer() -> String {
    "bb".repeat(32)
}

/// Store a chat's presentation through the production writer, which writes its
/// search text from `title` (`None`: a localized fallback), the stored group
/// name and description, and `peer_names` (the peer's profile names, read by
/// preparation; a `direct` seed). `group_avatar` selects a group avatar, so a
/// peer is a dependency for search alone.
fn present(
    app: &SqliteAppStorage,
    id: &str,
    title: Option<&str>,
    peer_names: &[&str],
    group_avatar: bool,
) {
    use crate::{
        ChatPresentationWrite, ConversationPresentation, PresentationResolution,
        PresentationSource, PresentationText, SelectedAvatar, StoredChatPresentation,
    };
    let peer = (!peer_names.is_empty()).then(peer);
    if let Some(peer) = &peer {
        app.set_chat_presentation_members(id, &["aa".repeat(32), peer.clone()])
            .unwrap();
    }
    let mut input = app.chat_presentation_input(id).unwrap().unwrap();
    input.search_peer_names = peer_names.iter().map(|name| (*name).to_owned()).collect();
    let avatar_source = if group_avatar {
        PresentationSource::Group
    } else {
        PresentationSource::GroupFallback
    };
    let write = app
        .store_chat_presentation(
            &input,
            &StoredChatPresentation {
                presentation: ConversationPresentation {
                    title: title.map_or(
                        PresentationText::UnnamedGroup { member_count: None },
                        |title| PresentationText::Literal(title.to_owned()),
                    ),
                    avatar: SelectedAvatar::Placeholder {
                        stable_seed: id.to_owned(),
                        source: avatar_source,
                    },
                    title_source: PresentationSource::Group,
                    avatar_source,
                    peer_id: peer,
                    resolution: PresentationResolution::Cached,
                },
                profile_version: None,
            },
        )
        .unwrap();
    assert_eq!(write, ChatPresentationWrite::Applied);
}

fn describe(store: &SqliteAccountStorage, id: &str, description: &str) {
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET profile_description = ?2 WHERE group_id_hex = ?1",
            params![id, description],
        )
        .unwrap();
}

fn text(query: &str) -> ChatListFilter {
    F::Text(query.to_owned())
}

fn cond(condition: ChatListCondition) -> ChatListFilter {
    F::Condition(condition)
}

fn group_ids(ids: &[&str]) -> ChatListFilter {
    F::GroupIds(ids.iter().map(|id| (*id).to_owned()).collect())
}

#[test]
fn every_condition_matches_exactly_the_chats_with_that_fact() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    for (id, facts) in [
        ("a0", &[][..]),
        ("a1", &["invite", "unread", "mention", "manual"]),
        ("a2", &["unread", "direct"]),
        ("a3", &["manual", "named"]),
        ("a4", &["mention", "trio"]),
        ("a5", &["pinned"]),
        ("a6", &[]),
        ("a7", &[]),
        ("a8", &[]),
        ("a9", &[]),
        ("aa", &[]),
        ("ab", &[]),
        ("ac", &[]),
        ("ad", &["archived", "unread", "pinned", "named"]),
        ("ae", &["left", "unread", "mention", "manual"]),
        ("af", &[]),
        ("b0", &[]),
    ] {
        seed(&store, id, facts);
    }
    // Muted until unmuted, until after the read, and until exactly the read's time.
    mute(&store, "a5", None);
    mute(&store, "a6", Some(NOW + 1));
    mute(&store, "a8", Some(NOW));
    mute(&store, "ad", None);
    draft(&store, "a6", "  draft text  ", false);
    // Whitespace-only text with a reply target is a reply-only draft: no draft.
    draft(&store, "a7", " \u{3000}\n", false);
    draft(&store, "a8", "", true);
    send(&app, "a9", "9a", MARMOT_APP_EVENT_KIND_CHAT);
    send(&app, "aa", "aa", MARMOT_APP_EVENT_KIND_POLL);
    send(&app, "ab", "ab", MARMOT_APP_EVENT_KIND_CHAT);
    app.invalidate_app_event_by_message_id("ab", "ab", "local_publish_failed")
        .unwrap();
    // A failed send a recipient confirmed is delivered, though it keeps rank 0.
    send(&app, "ac", "ac", MARMOT_APP_EVENT_KIND_CHAT);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE message_timeline SET recipient_confirmed = 1 WHERE message_id_hex = 'ac'",
            [],
        )
        .unwrap();
    // A pending reaction is not chat activity.
    send(&app, "af", "af", MARMOT_APP_EVENT_KIND_REACTION);
    // Older unresolved sends behind newer accepted history: each leaf follows
    // the delivery state the row shows, never a send the row does not show.
    send(&app, "a0", "a0", MARMOT_APP_EVENT_KIND_CHAT);
    app.invalidate_app_event_by_message_id("a0", "a0", "local_publish_failed")
        .unwrap();
    receive(&app, "a0", "b0a0");
    send(&app, "a7", "a7", MARMOT_APP_EVENT_KIND_CHAT);
    receive(&app, "a7", "b0a7");
    // The runtime refreshes a row after each timeline write; do the same here.
    for group in ["a0", "a7", "a9", "aa", "ab", "ac", "af"] {
        app.refresh_chat_list_row("aa", group, &|_: &str, _: &[Vec<String>]| false)
            .unwrap();
    }
    // Leave and disband move a chat to Left.
    let leaving = engine_group(&store, "b0");
    store
        .put_leave_request(&LeaveRequest {
            group_id: leaving,
            requested_at_ms: 1,
            last_proposed_epoch: None,
        })
        .unwrap();
    seed(&store, "b1", &[]);
    store
        .put_disband_request(&DisbandRequest {
            group_id: engine_group(&store, "b1"),
            requested_at_ms: 1,
            status: DisbandRequestStatus::Pending,
            last_prepared_epoch: None,
        })
        .unwrap();
    seed(&store, "b2", &[]);
    engine_group(&store, "b2");
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_disband_candidates VALUES (x'b2', x'01', x'00')",
            [],
        )
        .unwrap();
    ready(&store);

    let all = |view| ids(&app, view, F::All(Vec::new()));
    let chats = [
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "af",
    ];
    assert_eq!(
        all(ChatListView::Chats),
        [
            "a5", "a1", "a2", "a3", "a4", "a6", "a8", "a0", "a7", "a9", "aa", "ab", "ac", "af"
        ]
    );
    assert_eq!(all(ChatListView::Archived), ["ad"]);
    assert_eq!(all(ChatListView::Left), ["ae", "b0", "b1", "b2"]);

    let sorted = |mut ids: Vec<String>| {
        ids.sort();
        ids
    };
    for (condition, chats_matches, other_matches) in [
        (C::Active, &chats[..], &[][..]),
        (C::Archived, &[], &["ad"]),
        (C::Left, &[], &["ae", "b0", "b1", "b2"]),
        (C::PendingInvite, &["a1"], &[]),
        // Badges stay hidden for invitations and Left, so attention never matches there.
        (C::Unread, &["a2", "a3", "a4"], &["ad"]),
        (C::ManualUnread, &["a3"], &[]),
        (C::Mention, &["a4"], &[]),
        (C::Pinned, &["a5"], &["ad"]),
        (C::PendingLeave, &[], &["b0"]),
        (C::Disbanding, &[], &["b1", "b2"]),
        (C::HasDraft, &["a6", "a8"], &[]),
        (C::PendingSend, &["a9", "aa"], &[]),
        (C::FailedSend, &["ab"], &[]),
        // Every other chat has an unknown kind, so it matches neither.
        (C::Direct, &["a2"], &[]),
        (C::Group, &["a3", "a4"], &["ad"]),
        (C::Muted, &["a5", "a6"], &["ad"]),
    ] {
        assert_eq!(
            sorted(ids(&app, ChatListView::Chats, cond(condition))),
            chats_matches,
            "{condition:?} in Chats"
        );
        let others = [ChatListView::Archived, ChatListView::Left]
            .into_iter()
            .flat_map(|view| ids(&app, view, cond(condition)))
            .collect();
        assert_eq!(sorted(others), other_matches, "{condition:?} elsewhere");
        // Send, kind and mute leaves match exactly the rows that show that fact,
        // read at the same time.
        let delivery = |row: &crate::ChatListRow, state| {
            row.last_message
                .as_ref()
                .is_some_and(|message| message.delivery_state == state)
        };
        let shows: Option<&dyn Fn(&crate::ChatListRow) -> bool> = match condition {
            C::PendingSend => Some(&|row| delivery(row, ChatListMessageDeliveryState::Pending)),
            C::FailedSend => Some(&|row| delivery(row, ChatListMessageDeliveryState::Failed)),
            C::Direct => Some(&|row| row.conversation_kind == crate::ChatConversationKind::Direct),
            C::Group => Some(&|row| row.conversation_kind == crate::ChatConversationKind::Group),
            C::Muted => Some(&|row| row.muted),
            _ => None,
        };
        if let Some(shows) = shows {
            let showing: Vec<_> = rows_at(&app, ChatListView::Chats, NOW)
                .page
                .rows
                .into_iter()
                .filter(|row| shows(row))
                .map(|row| row.group_id_hex)
                .collect();
            assert_eq!(sorted(showing), chats_matches, "{condition:?} rows");
        }
        // Unread is the same rule as the Unread view, filtered or not.
        if condition == C::Unread {
            assert_eq!(
                ids(&app, ChatListView::Unread, F::All(Vec::new())),
                ids(&app, ChatListView::Chats, cond(condition))
            );
        }
    }
}

#[test]
fn operators_follow_boolean_truth_tables() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    // (pinned, unread) = 00, 01, 10, 11
    seed(&store, "00", &[]);
    seed(&store, "01", &["unread"]);
    seed(&store, "10", &["pinned"]);
    seed(&store, "11", &["pinned", "unread"]);
    ready(&store);
    let view = ChatListView::Chats;
    let pinned = || cond(C::Pinned);
    let unread = || cond(C::Unread);
    let query = |filter| {
        let mut ids = ids(&app, view, filter);
        ids.sort();
        ids
    };
    assert_eq!(query(F::All(vec![pinned(), unread()])), ["11"]);
    assert_eq!(query(F::Any(vec![pinned(), unread()])), ["01", "10", "11"]);
    assert_eq!(query(F::Not(Box::new(pinned()))), ["00", "01"]);
    assert_eq!(
        query(F::Not(Box::new(F::All(vec![pinned(), unread()])))),
        ["00", "01", "10"]
    );
    assert_eq!(
        query(F::All(vec![F::Not(Box::new(pinned())), unread()])),
        ["01"]
    );
    assert_eq!(query(F::All(vec![pinned()])), ["10", "11"]);
    // Empty All is the identity (every chat); empty Any matches none.
    assert_eq!(query(F::All(Vec::new())), ["00", "01", "10", "11"]);
    assert!(query(F::Any(Vec::new())).is_empty());
    assert_eq!(
        query(F::Not(Box::new(F::Any(Vec::new())))),
        ["00", "01", "10", "11"]
    );
}

#[test]
fn kind_and_mute_leaves_follow_boolean_truth_tables() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    // (kind, muted): Unknown, Direct, Group (named and three members) x 0, 1
    for (id, facts) in [
        ("u0", &[][..]),
        ("u1", &[]),
        ("d0", &["direct"]),
        ("d1", &["direct"]),
        ("g0", &["named"]),
        ("g1", &["trio"]),
    ] {
        seed(&store, id, facts);
    }
    for id in ["u1", "d1", "g1"] {
        mute(&store, id, Some(NOW + 1));
    }
    ready(&store);
    let query = |filter| {
        let mut ids = ids(&app, ChatListView::Chats, filter);
        ids.sort();
        ids
    };
    let not = |filter| F::Not(Box::new(filter));
    let (direct, group, muted) = (|| cond(C::Direct), || cond(C::Group), || cond(C::Muted));
    assert_eq!(query(direct()), ["d0", "d1"]);
    assert_eq!(query(group()), ["g0", "g1"]);
    assert_eq!(query(muted()), ["d1", "g1", "u1"]);
    // An Unknown kind is neither a group nor a DM, so only negation reaches it.
    assert_eq!(query(not(group())), ["d0", "d1", "u0", "u1"]);
    assert_eq!(query(not(direct())), ["g0", "g1", "u0", "u1"]);
    assert_eq!(query(not(F::Any(vec![direct(), group()]))), ["u0", "u1"]);
    assert_eq!(query(F::All(vec![direct(), group()])), Vec::<String>::new());
    assert_eq!(query(F::All(vec![group(), muted()])), ["g1"]);
    assert_eq!(
        query(F::Any(vec![direct(), muted()])),
        ["d0", "d1", "g1", "u1"]
    );
    assert_eq!(query(not(muted())), ["d0", "g0", "u0"]);
    assert_eq!(
        query(F::All(vec![not(muted()), not(group())])),
        ["d0", "u0"]
    );
}

/// `list_kind` tracks the classifier's inputs whichever table a write lands in,
/// and the leaf always agrees with the kind the row presents.
#[test]
fn kind_leaves_follow_the_classifier_inputs_through_every_write() {
    use crate::ChatConversationKind::{Direct, Group, Unknown};
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let insert = |id: &str, name: &str, members: Option<i64>| {
        let conn = store.lock().unwrap();
        conn.execute(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at, member_count)
             VALUES (?1, '', 0, ?2)",
            params![id, members],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_list_rows(group_id_hex, updated_at, group_name) VALUES (?1, 0, ?2)",
            params![id, name],
        )
        .unwrap();
    };
    insert("01", "", None);
    insert("02", "", Some(2));
    insert("03", "", Some(3));
    // Only this account is left.
    insert("04", "", Some(1));
    // A name of Unicode white space is no name.
    insert("05", "\u{3000} \n", Some(2));
    insert("06", "Team", Some(2));
    insert("07", "Team", None);
    ready(&store);
    let check = |expected: &[(&str, crate::ChatConversationKind)]| {
        let rows = rows_at(&app, ChatListView::Chats, NOW).page.rows;
        let mut presented: Vec<_> = rows
            .iter()
            .map(|row| (row.group_id_hex.as_str(), row.conversation_kind))
            .collect();
        presented.sort_by_key(|(id, _)| *id);
        assert_eq!(presented, expected, "presented kinds");
        for (condition, kind) in [(C::Direct, Direct), (C::Group, Group)] {
            let mut matched = ids(&app, ChatListView::Chats, cond(condition));
            matched.sort();
            let kinds: Vec<_> = expected
                .iter()
                .filter(|(_, k)| *k == kind)
                .map(|(id, _)| (*id).to_owned())
                .collect();
            assert_eq!(matched, kinds, "{condition:?}");
        }
    };
    check(&[
        ("01", Unknown),
        ("02", Direct),
        ("03", Group),
        ("04", Group),
        ("05", Direct),
        ("06", Group),
        ("07", Group),
    ]);
    // Member counts change in `account_groups`, names in `chat_list_rows`.
    store
        .lock()
        .unwrap()
        .execute_batch(
            "UPDATE account_groups SET member_count = 2 WHERE group_id_hex = '01';
             UPDATE account_groups SET member_count = 3 WHERE group_id_hex = '02';
             UPDATE account_groups SET member_count = NULL WHERE group_id_hex = '03';
             UPDATE chat_list_rows SET group_name = '' WHERE group_id_hex = '06';
             UPDATE chat_list_rows SET group_name = 'Renamed' WHERE group_id_hex = '05';",
        )
        .unwrap();
    ready(&store);
    check(&[
        ("01", Direct),
        ("02", Group),
        ("03", Unknown),
        ("04", Group),
        ("05", Group),
        ("06", Direct),
        ("07", Group),
    ]);
}

/// A timed mute stops matching exactly at its expiry, with no write, and a
/// window read reports the next expiry among every chat in its view.
#[test]
fn muted_leaf_flips_exactly_at_expiry_and_reports_the_next_expiry_in_the_view() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    for (id, facts) in [
        ("m1", &[][..]),
        ("m2", &[]),
        ("m3", &[]),
        ("m4", &[]),
        ("m5", &["archived"]),
    ] {
        seed(&store, id, facts);
    }
    mute(&store, "m1", Some(NOW + 500));
    mute(&store, "m2", Some(NOW + 900));
    mute(&store, "m3", None);
    // Earlier, but outside the Chats view.
    mute(&store, "m5", Some(NOW + 100));
    ready(&store);
    let muted = || cond(C::Muted);
    let unmuted = || F::Not(Box::new(muted()));
    let at = |now, filter| {
        let mut ids = ids_at(&app, ChatListView::Chats, filter, now);
        ids.sort();
        ids
    };
    let next = |view, filter, now| {
        rows_at(
            &app,
            ChatListViewQuery {
                view,
                filter: Some(filter),
            },
            now,
        )
        .next_mute_expiry_ms
    };
    assert_eq!(at(NOW + 499, muted()), ["m1", "m2", "m3"]);
    assert_eq!(at(NOW + 499, unmuted()), ["m4"]);
    // m1 is not in the unmuted window, yet its expiry is when it enters.
    assert_eq!(
        next(ChatListView::Chats, unmuted(), NOW + 499),
        Some(NOW + 500)
    );
    assert_eq!(at(NOW + 500, muted()), ["m2", "m3"]);
    assert_eq!(at(NOW + 500, unmuted()), ["m1", "m4"]);
    assert_eq!(
        next(ChatListView::Chats, muted(), NOW + 500),
        Some(NOW + 900)
    );
    // Only indefinite mutes remain: nothing to wake for.
    assert_eq!(next(ChatListView::Chats, muted(), NOW + 900), None);
    assert_eq!(
        next(ChatListView::Archived, muted(), NOW + 99),
        Some(NOW + 100)
    );
    // A query that does not test mute needs no wake.
    assert_eq!(next(ChatListView::Chats, F::All(Vec::new()), NOW), None);
}

/// The next-expiry lookup a Muted window read adds walks the view, not the
/// account's mute settings: muting chats outside the view adds no work.
#[test]
fn mute_wake_lookup_cost_grows_with_the_view_not_the_accounts_mutes() {
    let _serial = crate::base::query_work_test_support::QUERY_MEASUREMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "0000", &["unread"]);
    mute(&store, "0000", Some(NOW + 10));
    let mut archived = 0;
    let mut mute_archived = |count: usize| {
        for _ in 0..count {
            archived += 1;
            let id = format!("{archived:04x}");
            seed(&store, &id, &["archived", "unread"]);
            mute(&store, &id, Some(NOW + 1));
        }
        ready(&store);
    };
    let query = || ChatListViewQuery {
        view: ChatListView::Unread,
        filter: Some(cond(C::Muted)),
    };
    let steps = || {
        let (read, steps) =
            crate::base::query_work_test_support::measure(&store, || rows_at(&app, query(), NOW));
        assert_eq!(read.next_mute_expiry_ms, Some(NOW + 10));
        steps
    };
    mute_archived(16);
    let few = steps();
    mute_archived(2048);
    let many = steps();
    assert!(
        many <= few + few / 10,
        "mute wake lookup: {few} VM steps with 16 muted chats elsewhere, {many} with 2064"
    );
}

#[test]
fn excluded_ids_win_and_included_ids_never_leave_the_view() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "01", &["pinned"]);
    seed(&store, "02", &[]);
    seed(&store, "03", &["pinned"]);
    seed(&store, "04", &["archived"]);
    seed(&store, "ABCD", &[]);
    ready(&store);
    // Folder: pinned chats plus 02, 04 and abcd, but never 03.
    let folder = F::All(vec![
        F::Not(Box::new(group_ids(&["03"]))),
        F::Any(vec![
            group_ids(&["02", "03", "04", "abcd"]),
            cond(C::Pinned),
        ]),
    ]);
    let mut matched = ids(&app, ChatListView::Chats, folder.clone());
    matched.sort();
    // 04 is archived: inclusion never adds a chat outside the base view. IDs
    // compare as case-insensitive hex.
    assert_eq!(matched, ["01", "02", "ABCD"]);
    assert_eq!(ids(&app, ChatListView::Archived, folder), ["04"]);
    assert!(ids(&app, ChatListView::Chats, group_ids(&[])).is_empty());
    assert_eq!(
        ids(&app, ChatListView::Chats, group_ids(&["02", "unknown"])),
        ["02"]
    );
}

/// Search is a literal substring of the trimmed, Unicode-lowercased query in
/// one trimmed, lowercased field: title, group name, description or a direct
/// chat's peer profile names. Localized fallback titles have no text.
#[test]
fn text_leaf_matches_a_normalized_literal_substring_of_one_field() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    for (id, facts) in [
        ("01", &[][..]),
        ("02", &[]),
        ("03", &[]),
        ("04", &[]),
        ("05", &["direct", "named"]),
        ("06", &[]),
    ] {
        seed(&store, id, facts);
    }
    ready(&store);
    describe(&store, "01", "  Hiking\nand  Camping ");
    present(&app, "01", Some("Weekend Plans"), &[], false);
    present(&app, "02", Some("ÉCOLE Ölçü ΣΟΦΙΑ"), &[], false);
    present(&app, "03", Some("100% done_now"), &[], false);
    // An unnamed group's title is the host's localized fallback.
    present(&app, "04", None, &[], false);
    // A named direct chat shows its group name; its peer's names still match.
    present(
        &app,
        "05",
        Some("Team"),
        &["Alice Liddell", "alice_l"],
        true,
    );
    present(&app, "06", Some("Ordinary"), &[], false);
    for (query, expected) in [
        ("weekend", &["01"][..]),
        ("WEEKEND", &["01"]),
        ("  Weekend Plans \t", &["01"]),
        ("end pl", &["01"]),
        // Descriptions: trimmed, a line break reads as a space.
        ("hiking and", &["01"]),
        ("école", &["02"]),
        ("ölçü", &["02"]),
        ("σοφια", &["02"]),
        // LIKE wildcards are literal.
        ("%", &["03"]),
        ("_", &["03", "05"]),
        ("0% d", &["03"]),
        ("e_n", &["03"]),
        ("liddell", &["05"]),
        ("ALICE_L", &["05"]),
        ("team", &["05"]),
        // No field spans another, so a query never matches across two.
        ("planshiking", &[]),
        ("plans\u{1f}hiking", &[]),
        ("plans\nhiking", &[]),
        ("unnamed", &[]),
        ("", &[]),
        ("   ", &[]),
    ] {
        let mut expected = expected.to_vec();
        expected.sort();
        let mut found = ids(&app, ChatListView::Chats, text(query));
        found.sort();
        assert_eq!(found, expected, "{query:?}");
    }
    // The peer is a dependency for search alone, so a profile change re-prepares
    // the named chat even though neither its title nor its avatar uses the peer.
    assert_eq!(
        app.chat_presentation_dependents(&peer(), None).unwrap(),
        ["05"]
    );
}

/// While any chat in the view has its presentation, and so its search text,
/// pending, every read of a `Text` query fails as not ready instead of
/// returning a partial set. Queries without text, and views without pending
/// rows, are unaffected.
#[test]
fn text_queries_are_not_ready_while_any_presentation_in_the_view_is_pending() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "01", &[]);
    seed(&store, "02", &[]);
    seed(&store, "03", &["archived"]);
    seed(&store, "04", &["left"]);
    ready(&store);
    present(&app, "01", Some("Alpha"), &[], false);
    present(&app, "04", Some("Alpha left"), &[], false);
    let query = |view, filter| ChatListViewQuery {
        view,
        filter: Some(filter),
    };
    let not_ready = |view| {
        let query = query(view, text("alpha"));
        assert!(matches!(
            app.chat_list_ids(query.clone(), NOW),
            Err(ChatListSelectionError::ProjectionNotReady)
        ));
        assert!(matches!(
            app.revalidate_chat_list_ids(query.clone(), &["01".to_owned()], NOW),
            Err(ChatListSelectionError::ProjectionNotReady)
        ));
        assert!(matches!(
            app.read_chat_list_window(crate::ChatListWindowQuery {
                query,
                limit: 10,
                anchors: Vec::new(),
                before_anchor: 0,
                now_ms: NOW,
            }),
            Err(ChatListPageError::SearchTextNotReady)
        ));
    };
    // 02 was never prepared; 03 is pending in another view.
    not_ready(ChatListView::Chats);
    not_ready(ChatListView::Archived);
    assert_eq!(
        app.chat_list_pending_search_text(ChatListView::Chats, 10)
            .unwrap(),
        ["02"]
    );
    assert_eq!(ids(&app, ChatListView::Left, text("alpha")), ["04"]);
    assert_eq!(
        app.chat_list_ids(query(ChatListView::Chats, cond(C::Active)), NOW)
            .unwrap(),
        ["01", "02"]
    );
    present(&app, "02", Some("Beta"), &[], false);
    assert_eq!(ids(&app, ChatListView::Chats, text("alpha")), ["01"]);
    // A description change invalidates the row until it is prepared again.
    describe(&store, "02", "alpha team");
    not_ready(ChatListView::Chats);
    present(&app, "02", Some("Beta"), &[], false);
    assert_eq!(ids(&app, ChatListView::Chats, text("alpha")), ["01", "02"]);
}

#[test]
fn bounds_and_node_lists_fail_with_typed_errors_and_no_partial_result() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "01", &[]);
    let nested =
        |depth: usize| (1..depth).fold(cond(C::Pinned), |inner, _| F::Not(Box::new(inner)));
    let query = |filter| ChatListViewQuery {
        view: ChatListView::Chats,
        filter: Some(filter),
    };
    assert!(query(nested(MAX_CHAT_LIST_FILTER_DEPTH)).validate().is_ok());
    assert_eq!(
        query(nested(MAX_CHAT_LIST_FILTER_DEPTH + 1)).validate(),
        Err(ChatListQueryError::TooDeep)
    );
    let wide = |leaves: usize| F::Any(vec![cond(C::Pinned); leaves]);
    assert!(
        query(wide(MAX_CHAT_LIST_FILTER_NODES - 1))
            .validate()
            .is_ok()
    );
    assert_eq!(
        query(wide(MAX_CHAT_LIST_FILTER_NODES)).validate(),
        Err(ChatListQueryError::TooManyNodes)
    );
    // The text bound counts bytes across every leaf, before normalization.
    let text_bytes =
        |a: usize, b: usize| F::All(vec![text(&"é".repeat(a / 2)), text(&"x".repeat(b))]);
    assert!(
        query(text_bytes(MAX_CHAT_LIST_FILTER_TEXT_BYTES - 2, 2))
            .validate()
            .is_ok()
    );
    assert_eq!(
        query(text_bytes(MAX_CHAT_LIST_FILTER_TEXT_BYTES - 2, 3)).validate(),
        Err(ChatListQueryError::TextTooLong)
    );
    let id_list = |count: usize| F::GroupIds(vec!["01".to_owned(); count]);
    assert!(
        query(F::Any(vec![
            id_list(MAX_CHAT_LIST_FILTER_GROUP_IDS - 1),
            id_list(1)
        ]))
        .validate()
        .is_ok()
    );
    let too_many_ids = query(F::Any(vec![
        id_list(MAX_CHAT_LIST_FILTER_GROUP_IDS),
        id_list(1),
    ]));
    assert_eq!(
        too_many_ids.validate(),
        Err(ChatListQueryError::TooManyGroupIds)
    );
    // Every read path refuses before reading, whether or not base rows are ready.
    for pending in [true, false] {
        if pending {
            store
                .lock()
                .unwrap()
                .execute("INSERT INTO chat_presentation_row_work VALUES ('01')", [])
                .unwrap();
        } else {
            ready(&store);
        }
        assert!(matches!(
            app.chat_list_ids(too_many_ids.clone(), NOW),
            Err(ChatListSelectionError::InvalidQuery(
                ChatListQueryError::TooManyGroupIds
            ))
        ));
        assert!(matches!(
            app.revalidate_chat_list_ids(too_many_ids.clone(), &["01".to_owned()], NOW),
            Err(ChatListSelectionError::InvalidQuery(
                ChatListQueryError::TooManyGroupIds
            ))
        ));
        assert!(matches!(
            chat_list_window_page(&app, too_many_ids.clone(), 10),
            Err(ChatListPageError::InvalidQuery(
                ChatListQueryError::TooManyGroupIds
            ))
        ));
        assert!(matches!(
            app.read_chat_list_window(crate::ChatListWindowQuery {
                query: too_many_ids.clone(),
                limit: 10,
                anchors: Vec::new(),
                before_anchor: 0,
                now_ms: NOW,
            }),
            Err(ChatListPageError::InvalidQuery(
                ChatListQueryError::TooManyGroupIds
            ))
        ));
    }
}

#[test]
fn node_lists_decode_to_one_tree_or_a_typed_error() {
    use ChatListFilterNode as N;
    assert_eq!(ChatListFilter::from_nodes(Vec::new()), Ok(None));
    assert_eq!(
        ChatListFilter::from_nodes(vec![
            N::All(vec![1, 2]),
            N::Not(3),
            N::GroupIds(vec!["01".into()]),
            N::Condition(C::Pinned),
        ]),
        Ok(Some(F::All(vec![
            F::Not(Box::new(cond(C::Pinned))),
            group_ids(&["01"]),
        ])))
    );
    assert_eq!(
        ChatListFilter::from_nodes(vec![N::Not(1), N::Text("Plans".into())]),
        Ok(Some(F::Not(Box::new(text("Plans")))))
    );
    for (nodes, error) in [
        (
            vec![N::Any(vec![1, 5]), N::Condition(C::Unread)],
            ChatListQueryError::ChildOutOfRange,
        ),
        (vec![N::Not(0)], ChatListQueryError::ChildNotAfterParent),
        (
            vec![N::All(vec![1, 2]), N::Any(vec![2]), N::Condition(C::Unread)],
            ChatListQueryError::SharedChild,
        ),
        (
            vec![N::All(vec![1, 1]), N::Condition(C::Unread)],
            ChatListQueryError::SharedChild,
        ),
        (
            vec![N::Condition(C::Unread), N::Condition(C::Pinned)],
            ChatListQueryError::UnreachableNode,
        ),
        (
            vec![N::Condition(C::Pinned); MAX_CHAT_LIST_FILTER_NODES + 1],
            ChatListQueryError::TooManyNodes,
        ),
        (
            (0..=MAX_CHAT_LIST_FILTER_DEPTH as u32)
                .map(|index| {
                    if index as usize == MAX_CHAT_LIST_FILTER_DEPTH {
                        N::Condition(C::Pinned)
                    } else {
                        N::Not(index + 1)
                    }
                })
                .collect(),
            ChatListQueryError::TooDeep,
        ),
        (
            vec![
                N::Any(vec![1, 2]),
                N::GroupIds(vec!["01".into(); MAX_CHAT_LIST_FILTER_GROUP_IDS]),
                N::GroupIds(vec!["02".into()]),
            ],
            ChatListQueryError::TooManyGroupIds,
        ),
        (
            vec![N::Text("x".repeat(MAX_CHAT_LIST_FILTER_TEXT_BYTES + 1))],
            ChatListQueryError::TextTooLong,
        ),
    ] {
        assert_eq!(ChatListFilter::from_nodes(nodes), Err(error));
    }
}

/// Filtered reads walk the view's page index in order and reach other tables
/// only through per-chat keyed lookups: no temporary sort, no table scan.
#[test]
fn filtered_queries_walk_the_page_index_with_keyed_lookups() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for n in 0..20 {
        seed(&store, &format!("{n:02x}"), &[]);
    }
    ready(&store);
    let every_leaf = F::Any(vec![
        cond(C::PendingInvite),
        cond(C::Mention),
        cond(C::ManualUnread),
        cond(C::Pinned),
        cond(C::PendingLeave),
        cond(C::Disbanding),
        cond(C::HasDraft),
        cond(C::PendingSend),
        cond(C::FailedSend),
        cond(C::Direct),
        cond(C::Group),
        cond(C::Muted),
        F::Not(Box::new(group_ids(&["01"]))),
        text("plans"),
    ]);
    for view in [
        ChatListView::Chats,
        ChatListView::Unread,
        ChatListView::Archived,
        ChatListView::Left,
    ] {
        let compiled = ChatListViewQuery {
            view,
            filter: Some(every_leaf.clone()),
        }
        .compile(NOW, QueryScope::Window)
        .unwrap();
        let conn = store.lock().unwrap();
        let sql = format!(
            "EXPLAIN QUERY PLAN SELECT group_id_hex FROM chat_list_rows INDEXED BY {} WHERE {} ORDER BY {}",
            view.index(),
            compiled.predicate,
            super::super::pages::KEY_COLUMNS
        );
        let plan = conn
            .prepare(&sql)
            .unwrap()
            .query_map(rusqlite::params_from_iter(&compiled.params), |r| {
                r.get::<_, String>(3)
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let plan = plan.join("\n");
        assert!(
            plan.contains(&format!("USING COVERING INDEX {}", view.index()))
                || plan.contains(&format!("USING INDEX {}", view.index())),
            "{view:?}: {plan}"
        );
        assert!(!plan.contains("TEMP B-TREE"), "{view:?}: {plan}");
        for line in plan.lines().filter(|line| line.contains("SCAN")) {
            // The view's own index walk and the bound ID list are the only scans.
            assert!(
                line.contains(view.index()) || line.contains("json_each"),
                "{view:?}: {line}\n{plan}"
            );
        }
        for lookup in [
            "idx_leave_requests_hex",
            "idx_disband_candidates_hex",
            "idx_disband_requests_hex",
            "SEARCH draft USING INDEX",
            "SEARCH pending USING INDEX",
            "SEARCH mute USING INDEX",
        ] {
            assert!(plan.contains(lookup), "{view:?} missing {lookup}:\n{plan}");
        }
    }
}

/// Past the 200-row window cap, windows over a filtered query (each one read)
/// tile exactly its select-all ID set, in order; the count is that length, and
/// revalidating every chat keeps exactly that set. The query searches text too.
#[test]
fn windows_over_a_filtered_query_agree_with_its_complete_id_set() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let mut expected = Vec::new();
    let mut every_chat = Vec::new();
    let excluded = ["0000", "0002", "01f6"];
    for n in 0..520 {
        let mut facts = match n % 4 {
            0 => vec!["unread"],
            1 => vec!["pinned"],
            2 => vec!["unread", "pinned"],
            _ => vec![],
        };
        if n % 3 == 0 {
            facts.push("direct");
        }
        let id = format!("{n:04x}");
        // Muted DMs are dropped: some until after the read, some indefinitely,
        // and some whose mute expired exactly at the read's time (kept).
        let muted_direct = n % 3 == 0 && n % 5 < 2;
        let titled = n % 7 != 6;
        if n % 4 != 3 && !excluded.contains(&id.as_str()) && !muted_direct && titled {
            expected.push(id.clone());
        }
        seed(&store, &id, &facts);
        present(
            &app,
            &id,
            Some(&if titled {
                format!("Weekly {n}")
            } else {
                format!("Other {n}")
            }),
            &[],
            false,
        );
        match n % 5 {
            0 => mute(&store, &id, Some(NOW + 1)),
            1 => mute(&store, &id, None),
            2 => mute(&store, &id, Some(NOW)),
            _ => {}
        }
        every_chat.push(id);
    }
    ready(&store);
    let query = ChatListViewQuery {
        view: ChatListView::Chats,
        filter: Some(F::All(vec![
            F::Any(vec![cond(C::Unread), cond(C::Pinned)]),
            F::Not(Box::new(group_ids(&excluded))),
            F::Not(Box::new(F::All(vec![cond(C::Direct), cond(C::Muted)]))),
            text(" WEEK"),
        ])),
    };
    let all = app.chat_list_ids(query.clone(), NOW).unwrap();
    assert_eq!(all.len(), expected.len());
    assert!(all.len() > 200);
    let mut sorted = all.clone();
    sorted.sort();
    assert_eq!(sorted, expected);
    let window = |anchors: Vec<String>, limit| {
        app.read_chat_list_window(crate::ChatListWindowQuery {
            query: query.clone(),
            limit,
            anchors,
            before_anchor: 0,
            now_ms: NOW,
        })
        .unwrap()
        .page
    };
    let top = window(Vec::new(), 200);
    // A window back-fills before its anchor when fewer rows follow it, so the
    // second one is exactly the remainder.
    let rest = window(vec![all[200].clone()], all.len() - 200);
    assert!(top.has_more_after && !top.has_more_before);
    assert!(rest.has_more_before && !rest.has_more_after);
    let tiled: Vec<_> = top
        .rows
        .iter()
        .chain(&rest.rows)
        .map(|row| row.group_id_hex.clone())
        .collect();
    assert_eq!(tiled, all);
    // Revalidation keeps the caller's order and exactly the matching chats.
    every_chat.reverse();
    let kept = app
        .revalidate_chat_list_ids(query, &every_chat, NOW)
        .unwrap();
    let mut reversed = all.clone();
    reversed.sort();
    reversed.reverse();
    assert_eq!(kept, reversed);
}

/// One relay-accepted event in `group`.
fn event(
    app: &SqliteAppStorage,
    group: &str,
    id: &str,
    sender: &str,
    kind: u64,
    plaintext: &str,
    tags: Vec<Vec<String>>,
) {
    app.record_app_event(&StoredAppEvent {
        group_id_hex: group.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: Some(1),
        direction: "received".to_owned(),
        sender: sender.to_owned(),
        plaintext: plaintext.to_owned(),
        kind,
        tags,
        recorded_at: 30,
        received_at: 30,
        origin_commit_id: None,
        moderation_grant: false,
    })
    .unwrap();
}

fn message_text(query: &str) -> ChatListFilter {
    F::MessageText(query.to_owned())
}

/// Select-all IDs at `now_ms`, checked against revalidation of every chat.
/// A window refuses message text, so it is not compared here.
fn selected_at(app: &SqliteAppStorage, filter: ChatListFilter, now_ms: i64) -> Vec<String> {
    let query = ChatListViewQuery {
        view: ChatListView::Chats,
        filter: Some(filter),
    };
    let ids = app.chat_list_ids(query.clone(), now_ms).unwrap();
    let every_chat = app.chat_list_ids(ChatListView::Chats, now_ms).unwrap();
    assert_eq!(
        app.revalidate_chat_list_ids(query, &every_chat, now_ms)
            .unwrap(),
        ids,
        "revalidation of every chat"
    );
    ids
}

/// A chat matches when a message the timeline shows contains the text, by the
/// shared rule (trim, Unicode lowercase, literal substring). Deleted,
/// invalidated, expired and blocked-sender messages, superseded edit text and
/// group-system rows never match.
#[test]
fn message_text_leaf_matches_only_text_the_timeline_shows() {
    use cgka_traits::app_event::{
        MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_EDIT,
        MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    };
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    for id in [
        "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b",
    ] {
        seed(&store, id, &[]);
    }
    let chat = MARMOT_APP_EVENT_KIND_CHAT;
    let e = |target: &str| vec![vec!["e".to_owned(), target.to_owned()]];
    event(
        &app,
        "01",
        "m01",
        "bb",
        chat,
        "Meet at the ÉCOLE, 100% sure",
        vec![],
    );
    // Edited: the latest edit is the text; the original no longer matches.
    event(&app, "02", "m02", "bb", chat, "original draft", vec![]);
    event(
        &app,
        "02",
        "m02e",
        "bb",
        MARMOT_APP_EVENT_KIND_EDIT,
        "revised plan",
        e("m02"),
    );
    // Deleted by its author.
    event(&app, "03", "m03", "bb", chat, "deleted secret", vec![]);
    event(
        &app,
        "03",
        "m03d",
        "bb",
        MARMOT_APP_EVENT_KIND_DELETE,
        "",
        e("m03"),
    );
    // Invalidated by convergence: a tombstone, not message text.
    event(&app, "04", "m04", "bb", chat, "losing branch", vec![]);
    app.invalidate_app_event_by_source("source-m04", "LosingBranch")
        .unwrap();
    // A poll's question is message text.
    let poll_tags = cgka_traits::poll_tags(
        30,
        "Lunch vote?",
        &["Tea".to_owned(), "Soup".to_owned()],
        cgka_traits::PollType::SingleChoice,
        None,
    )
    .unwrap();
    event(
        &app,
        "05",
        "m05",
        "bb",
        MARMOT_APP_EVENT_KIND_POLL,
        "Lunch vote?",
        poll_tags,
    );
    // Group-system rows are generated, not message text.
    event(
        &app,
        "06",
        "m06",
        "bb",
        MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        "lunch vote member",
        vec![],
    );
    // From an account this account blocked.
    event(&app, "07", "m07", "cc", chat, "blocked lunch vote", vec![]);
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO user_blocks(public_key, is_private, created_at_ms) VALUES ('cc', 0, 0)",
            [],
        )
        .unwrap();
    // Disappearing: shown until its expiry, gone from the expiry second on.
    event(&app, "08", "m08", "bb", chat, "fleeting note", vec![]);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE app_events SET retention_seconds = 60, retention_expires_at = ?1
             WHERE message_id_hex = 'm08'",
            [NOW / 1000 + 5],
        )
        .unwrap();
    // A reaction is not a timeline row of its own.
    event(&app, "09", "m09", "bb", chat, "plain", vec![]);
    event(
        &app,
        "09",
        "m09r",
        "bb",
        MARMOT_APP_EVENT_KIND_REACTION,
        "lunch",
        e("m09"),
    );
    // An own send that reached no one still shows, as failed.
    app.record_app_event(&StoredAppEvent {
        group_id_hex: "0b".to_owned(),
        message_id_hex: "m0b".to_owned(),
        source_message_id_hex: None,
        source_epoch: None,
        direction: "sent".to_owned(),
        sender: "aa".to_owned(),
        plaintext: "meet at the dock".to_owned(),
        kind: chat,
        tags: Vec::new(),
        recorded_at: 30,
        received_at: 30,
        origin_commit_id: None,
        moderation_grant: false,
    })
    .unwrap();
    app.invalidate_app_event_by_message_id(
        "0b",
        "m0b",
        crate::app::timeline::LOCAL_PUBLISH_FAILED_REASON,
    )
    .unwrap();
    // 0a has no messages.
    ready(&store);
    for (query, expected) in [
        ("école", &["01"][..]),
        ("  ÉCOLE ", &["01"]),
        ("100%", &["01"]),
        ("0% s", &["01"]),
        ("10_%", &[]),
        ("revised", &["02"]),
        ("original", &[]),
        ("secret", &[]),
        ("losing", &[]),
        ("dock", &["0b"]),
        ("lunch vote", &["05"]),
        ("tea", &[]),
        ("fleeting", &["08"]),
        ("", &[]),
        ("   ", &[]),
    ] {
        assert_eq!(
            selected_at(&app, message_text(query), NOW),
            expected,
            "{query:?}"
        );
    }
    let expiry_ms = (NOW / 1000 + 5) * 1000;
    assert_eq!(
        selected_at(&app, message_text("fleeting"), expiry_ms - 1),
        ["08"]
    );
    assert!(selected_at(&app, message_text("fleeting"), expiry_ms).is_empty());
    // It composes like any leaf.
    let mut negated = selected_at(&app, F::Not(Box::new(message_text("lunch"))), NOW);
    negated.sort();
    assert_eq!(
        negated,
        ["01", "02", "03", "04", "06", "07", "08", "09", "0a", "0b"]
    );
    assert_eq!(
        selected_at(
            &app,
            F::Any(vec![
                message_text("revised"),
                cond(C::Pinned),
                group_ids(&["0a"])
            ]),
            NOW
        )
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>(),
        ["02".to_owned(), "0a".to_owned()].into()
    );
}

/// A window never evaluates message text: every window read refuses it with a
/// typed error before any readiness check, wherever it sits in the tree.
/// Select-all IDs and revalidation accept the same query.
#[test]
fn a_window_refuses_message_text_before_reading() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "01", &[]);
    let nested = ChatListViewQuery {
        view: ChatListView::Chats,
        filter: Some(F::All(vec![
            cond(C::Active),
            F::Not(Box::new(F::Any(vec![message_text("x"), cond(C::Pinned)]))),
        ])),
    };
    assert_eq!(nested.validate(), Ok(()));
    assert_eq!(
        nested.validate_for_window(),
        Err(ChatListQueryError::MessageTextInWindow)
    );
    assert_eq!(
        nested.compile(NOW, QueryScope::Window).err(),
        Some(ChatListQueryError::MessageTextInWindow)
    );
    for pending in [true, false] {
        if pending {
            store
                .lock()
                .unwrap()
                .execute(
                    "INSERT OR IGNORE INTO chat_presentation_row_work VALUES ('01')",
                    [],
                )
                .unwrap();
        } else {
            ready(&store);
        }
        assert!(matches!(
            app.read_chat_list_window(crate::ChatListWindowQuery {
                query: nested.clone(),
                limit: 10,
                anchors: Vec::new(),
                before_anchor: 0,
                now_ms: NOW,
            }),
            Err(ChatListPageError::InvalidQuery(
                ChatListQueryError::MessageTextInWindow
            ))
        ));
    }
    assert_eq!(app.chat_list_ids(nested.clone(), NOW).unwrap(), ["01"]);
    assert_eq!(
        app.revalidate_chat_list_ids(nested, &["01".to_owned()], NOW)
            .unwrap(),
        ["01"]
    );
}

/// The content-report backfill can still hide a message or replace its text
/// with a later edit, so a message-text query is not ready, never partial,
/// while it is owed. Queries without message text are unaffected.
#[test]
fn message_text_queries_are_not_ready_while_the_deletion_backfill_is_owed() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "01", &[]);
    seed(&store, "02", &[]);
    event(
        &app,
        "01",
        "m01",
        "bb",
        MARMOT_APP_EVENT_KIND_CHAT,
        "hello there",
        vec![],
    );
    ready(&store);
    let set_backfill = |after: i64, through: i64| {
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE content_report_backfill SET after_order = ?1, through_order = ?2",
                [after, through],
            )
            .unwrap();
    };
    let query = ChatListViewQuery {
        view: ChatListView::Chats,
        filter: Some(F::Not(Box::new(message_text("hello")))),
    };
    set_backfill(0, 1);
    assert!(matches!(
        app.chat_list_ids(query.clone(), NOW),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
    assert!(matches!(
        app.revalidate_chat_list_ids(query.clone(), &["02".to_owned()], NOW),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
    let mut active = app
        .chat_list_ids(
            ChatListViewQuery {
                view: ChatListView::Chats,
                filter: Some(cond(C::Active)),
            },
            NOW,
        )
        .unwrap();
    active.sort();
    assert_eq!(active, ["01", "02"]);
    set_backfill(1, 1);
    assert_eq!(app.chat_list_ids(query, NOW).unwrap(), ["02"]);
}

/// Message text reaches the timeline through a keyed search per candidate chat,
/// never an account-wide scan of the timeline.
#[test]
fn message_text_searches_each_chats_history_by_key() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", &[]);
    ready(&store);
    let compiled = ChatListViewQuery {
        view: ChatListView::Chats,
        filter: Some(message_text("plans")),
    }
    .compile(NOW, QueryScope::Selection)
    .unwrap();
    let sql = format!(
        "EXPLAIN QUERY PLAN SELECT group_id_hex FROM chat_list_rows INDEXED BY {} WHERE {} ORDER BY {}",
        ChatListView::Chats.index(),
        compiled.predicate,
        super::super::pages::KEY_COLUMNS
    );
    let conn = store.lock().unwrap();
    let plan = conn
        .prepare(&sql)
        .unwrap()
        .query_map(rusqlite::params_from_iter(&compiled.params), |r| {
            r.get::<_, String>(3)
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join("\n");
    // The view `visible_message_timeline` flattens to its table.
    assert!(!plan.contains("SCAN message_timeline"), "{plan}");
    assert!(!plan.contains("SCAN source"), "{plan}");
    assert!(
        plan.contains("SEARCH message_timeline USING INDEX idx_message_timeline_group_kind_unread (group_id_hex=? AND kind=?"),
        "{plan}"
    );
    assert!(
        plan.contains("SEARCH source USING INDEX sqlite_autoindex_app_events_1"),
        "{plan}"
    );
}

/// Cost check for the message-text leaf (mdk#2983 slice 5): select-all IDs over
/// a large file-backed SQLCipher history, which decides whether the leaf may
/// later enter live windows. Run optimized:
///
/// `cargo test -p storage-sqlite --release --lib message_text_selection_cost -- --ignored --nocapture`
///
/// `MDK_MESSAGE_TEXT_CHATS` and `MDK_MESSAGE_TEXT_PER_CHAT` size the fixture
/// (default 500 chats of 2,000 messages); one message in ten is non-ASCII.
#[test]
#[ignore = "operational file-backed SQLCipher benchmark"]
fn message_text_selection_cost_on_a_large_history() {
    crate::base::connection::use_production_storage_for_test_process();
    let env = |name: &str, default: usize| {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    };
    let chats = env("MDK_MESSAGE_TEXT_CHATS", 500);
    let per_chat = env("MDK_MESSAGE_TEXT_PER_CHAT", 2_000);
    let dir = tempfile::tempdir().unwrap();
    let key = crate::SqlCipherKey::new("message-text-cost").unwrap();
    let path = dir.path().join("account.sqlite3");
    let built = std::time::Instant::now();
    {
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let app = store.app_storage();
        for chat in 0..chats {
            let id = format!("{chat:064x}");
            seed(&store, &id, &[]);
            // One real event per chat is the template the bulk copy repeats.
            event(
                &app,
                &id,
                &format!("tmpl-{chat}"),
                "bb",
                MARMOT_APP_EVENT_KIND_CHAT,
                "x",
                vec![],
            );
        }
        let conn = store.lock().unwrap();
        let columns = |table: &str| -> Vec<String> {
            conn.prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let text = "CASE WHEN n.i % 10 = 0
                THEN printf('Réunion %d à l''ÉCOLE, notes du thème %d', n.i, n.i % 97)
                ELSE printf('message %d about topic %d with some ordinary filler text', n.i, n.i % 97) END";
        conn.execute_batch("BEGIN").unwrap();
        for table in ["app_events", "message_timeline"] {
            let names = columns(table);
            let values = names
                .iter()
                .map(|name| match name.as_str() {
                    "message_id_hex" => "printf('%s-%06d', t.group_id_hex, n.i)".to_owned(),
                    "source_message_id_hex" => {
                        "printf('src-%s-%06d', t.group_id_hex, n.i)".to_owned()
                    }
                    "plaintext" => text.to_owned(),
                    "insert_order" => "NULL".to_owned(),
                    "recorded_at" | "received_at" | "timeline_at" => format!("t.{name} + n.i"),
                    other => format!("t.{other}"),
                })
                .collect::<Vec<_>>();
            conn.execute(
                &format!(
                    "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1)
                     INSERT INTO {table} ({}) SELECT {} FROM {table} AS t, n
                     WHERE t.message_id_hex LIKE 'tmpl-%'",
                    names.join(", "),
                    values.join(", ")
                ),
                [per_chat as i64],
            )
            .unwrap();
        }
        conn.execute_batch(
            "COMMIT; DELETE FROM chat_presentation_row_work;
             UPDATE content_report_backfill SET after_order = through_order;",
        )
        .unwrap();
    }
    let messages = chats * (per_chat + 1);
    let size_mib = std::fs::metadata(&path).unwrap().len() / (1024 * 1024);
    eprintln!(
        "fixture: {chats} chats, {messages} messages, {size_mib} MiB, built in {:?}",
        built.elapsed()
    );
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    let query = |text: &str| ChatListViewQuery {
        view: ChatListView::Chats,
        filter: Some(message_text(text)),
    };
    for (label, needle, expected) in [
        ("no match (full scan)", "zzqx", 0),
        ("ASCII, every chat early", "message 1 ", chats),
        ("non-ASCII, every chat early", "réunion 10 ", chats),
        (
            "ASCII, every chat late",
            &*format!("message {} about", per_chat - 1),
            chats,
        ),
    ] {
        let mut samples = Vec::new();
        let mut first = None;
        for sample in 0..11 {
            let started = std::time::Instant::now();
            let ids = app.chat_list_ids(query(needle), NOW).unwrap();
            let elapsed = started.elapsed();
            assert_eq!(ids.len(), expected, "{label}");
            if sample == 0 {
                first = Some(elapsed);
            } else {
                samples.push(elapsed);
            }
        }
        samples.sort();
        let (_, steps) = crate::base::query_work_test_support::measure(&store, || {
            app.chat_list_ids(query(needle), NOW).unwrap()
        });
        eprintln!(
            "{label}: first {:?}, p50 {:?}, max {:?}, {steps} VM steps",
            first.unwrap(),
            samples[samples.len() / 2],
            samples[samples.len() - 1],
        );
    }
    let time = |run: &dyn Fn()| {
        run();
        let mut samples = (0..5)
            .map(|_| {
                let started = std::time::Instant::now();
                run();
                started.elapsed()
            })
            .collect::<Vec<_>>();
        samples.sort();
        samples[2]
    };
    eprintln!(
        "baseline, unfiltered IDs: p50 {:?}",
        time(&|| {
            app.chat_list_ids(ChatListView::Chats, NOW).unwrap();
        })
    );
    // The match itself over every timeline row: the old ASCII `LIKE NOCASE`
    // against the shared function, on the same rows.
    for (label, predicate) in [
        (
            "raw scan, LIKE NOCASE",
            "plaintext LIKE '%zzqx%' ESCAPE '\\' COLLATE NOCASE",
        ),
        (
            "raw scan, marmot_search_contains",
            "marmot_search_contains(plaintext, 'zzqx')",
        ),
    ] {
        let sql = format!("SELECT count(*) FROM message_timeline WHERE {predicate}");
        eprintln!(
            "{label}: p50 {:?}",
            time(&|| {
                let _: i64 = store
                    .lock()
                    .unwrap()
                    .query_row(&sql, [], |row| row.get(0))
                    .unwrap();
            })
        );
    }
    // The account-wide timeline search this leaf builds on, for comparison:
    // one page of 50, which stops early, and a miss, which scans everything.
    for (label, needle) in [
        ("timeline search, page of 50", "message"),
        ("timeline search, miss", "zzqx"),
    ] {
        let started = std::time::Instant::now();
        app.message_timeline(crate::TimelineMessageQuery {
            group_id_hex: None,
            search: Some(needle.to_owned()),
            ..Default::default()
        })
        .unwrap();
        eprintln!("{label}: {:?}", started.elapsed());
    }
}
