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
        .compile(NOW)
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
/// revalidating every chat keeps exactly that set.
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
        if n % 4 != 3 && !excluded.contains(&id.as_str()) && !muted_direct {
            expected.push(id.clone());
        }
        seed(&store, &id, &facts);
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
