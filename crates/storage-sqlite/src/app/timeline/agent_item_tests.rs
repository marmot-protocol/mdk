//! Agent items (kind 1201) and answers and controls (kind 1202) in the
//! timeline: one row per item at its first event, holding its highest version.
use super::*;
use crate::SqliteAccountStorage;

const GROUP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn hex(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn tag(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// Every tag of an item version, the ones MDK reads and the ones it passes on.
fn item_tags(version: u64, state: &str, seq: u64) -> Vec<Vec<String>> {
    vec![
        tag(&["v", &version.to_string()]),
        tag(&["state", state]),
        tag(&["title", &format!("Running a command ({state})")]),
        tag(&["harness", "codex"]),
        tag(&["item_id", "call-1"]),
        tag(&["seq", &seq.to_string()]),
        tag(&["fields", r#"{"type":"tool","body":{"command":"ls"}}"#]),
        tag(&["session", "session-1"]),
        tag(&["turn", "turn-1"]),
        tag(&["started_by", &hex('a')]),
        tag(&["settles", &hex('b')]),
        tag(&["native", "item/completed", r#"{"id":"call-1"}"#]),
        tag(&["left_out", "native", "70000"]),
        tag(&["cut", "output", "90000"]),
    ]
}

fn event(
    id: &str,
    sender: &str,
    at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
    plaintext: &str,
) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: GROUP.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: Some(3),
        direction: "received".to_owned(),
        sender: sender.to_owned(),
        plaintext: plaintext.to_owned(),
        kind,
        tags,
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
        moderation_grant: false,
    }
}

fn item(id: &str, at: u64, version: u64, state: &str, seq: u64) -> StoredAppEvent {
    event(
        id,
        "agent",
        at,
        MARMOT_APP_EVENT_KIND_AGENT_ITEM,
        item_tags(version, state, seq),
        &format!("v{version} {state}"),
    )
}

fn item_edit(id: &str, target: &str, at: u64, version: u64, state: &str) -> StoredAppEvent {
    let mut tags = vec![tag(&["e", target])];
    // A later version's seq is the driver event's place, which moves on.
    tags.extend(item_tags(version, state, 100 + version));
    event(
        id,
        "agent",
        at,
        MARMOT_APP_EVENT_KIND_EDIT,
        tags,
        &format!("v{version} {state}"),
    )
}

fn row(store: &SqliteAppStorage, id: &str) -> TimelineMessageRecord {
    store.timeline_message(GROUP, id).unwrap().unwrap()
}

fn rows(store: &SqliteAppStorage) -> Vec<String> {
    store
        .message_timeline(TimelineMessageQuery {
            group_id_hex: Some(GROUP.to_owned()),
            ..TimelineMessageQuery::default()
        })
        .unwrap()
        .messages
        .into_iter()
        .map(|message| message.message_id_hex)
        .collect()
}

#[test]
fn an_item_row_holds_every_tag_of_its_latest_version() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let first = store
        .record_app_event(&item("item", 10, 1, "running", 7))
        .unwrap();
    assert!(matches!(
        first.changes.as_slice(),
        [TimelineMessageChange::Upsert {
            trigger: TimelineUpdateTrigger::AgentItem,
            message,
        }] if message.message_id_hex == "item"
    ));
    let first_row = row(&store, "item");
    assert_eq!(first_row.tags, item_tags(1, "running", 7));
    assert_eq!(first_row.reply_to_message_id_hex, Some(hex('a')));

    let update = store
        .record_app_event(&item_edit("edit-2", "item", 11, 2, "done"))
        .unwrap();
    assert!(update.changes.iter().any(|change| matches!(
        change,
        TimelineMessageChange::Upsert { message, .. } if message.message_id_hex == "item"
    )));

    let latest = row(&store, "item");
    assert_eq!(latest.plaintext, "v2 done");
    // Content and every tag are the edit's, without the edit's own `e`.
    assert_eq!(latest.tags, item_tags(2, "done", 102));
    let item = latest.agent_item.expect("a readable item");
    assert_eq!(item.version, 2);
    assert_eq!(item.state, cgka_traits::AgentItemState::Done);
    assert_eq!(item.settles, [hex('b')]);
    // The row stays at its first event, and an item's change of state is not
    // an edit to mark.
    assert_eq!(latest.timeline_order_seq, 7);
    assert_eq!(latest.timeline_at, 10);
    assert_eq!(latest.edit, None);
    assert_eq!(rows(&store), ["item"]);
    assert!(
        store
            .message_edit_history(GROUP, "item", None, 10)
            .unwrap()
            .versions
            .is_empty()
    );
}

#[test]
fn an_items_reply_target_is_the_turn_its_latest_version_names() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let mut first = item("item", 10, 1, "running", 1);
    first.tags.retain(|t| t[0] != "started_by");
    store.record_app_event(&first).unwrap();
    assert_eq!(row(&store, "item").reply_to_message_id_hex, None);

    store
        .record_app_event(&item_edit("edit-2", "item", 11, 2, "done"))
        .unwrap();
    assert_eq!(row(&store, "item").reply_to_message_id_hex, Some(hex('a')));
}

#[test]
fn an_edit_that_arrives_before_its_item_is_held_and_applied() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .record_app_event(&item_edit("edit-2", "item", 11, 2, "waiting"))
        .unwrap();
    assert!(rows(&store).is_empty());

    store
        .record_app_event(&item("item", 10, 1, "running", 1))
        .unwrap();

    let latest = row(&store, "item");
    assert_eq!(latest.plaintext, "v2 waiting");
    assert_eq!(latest.agent_item.unwrap().version, 2);
}

#[test]
fn the_highest_version_wins_in_any_order_and_a_late_older_one_is_ignored() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .record_app_event(&item("item", 10, 1, "running", 1))
        .unwrap();
    // Within one second, and with ids whose order disagrees with the versions.
    store
        .record_app_event(&item_edit("aa-v3", "item", 10, 3, "done"))
        .unwrap();
    assert_eq!(row(&store, "item").plaintext, "v3 done");

    store
        .record_app_event(&item_edit("ff-v2", "item", 10, 2, "running"))
        .unwrap();
    assert_eq!(row(&store, "item").plaintext, "v3 done");

    // A later second does not beat a higher version either.
    store
        .record_app_event(&item_edit("late-v2", "item", 99, 2, "failed"))
        .unwrap();
    let latest = row(&store, "item");
    assert_eq!(latest.plaintext, "v3 done");
    assert_eq!(latest.agent_item.unwrap().version, 3);
}

#[test]
fn an_edit_no_newer_than_the_first_event_or_unreadable_or_foreign_is_ignored() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .record_app_event(&item("item", 10, 2, "running", 1))
        .unwrap();
    store
        .record_app_event(&item_edit("same", "item", 11, 2, "done"))
        .unwrap();
    store
        .record_app_event(&item_edit("older", "item", 12, 1, "done"))
        .unwrap();
    let mut unreadable = item_edit("unreadable", "item", 13, 5, "done");
    unreadable.tags.retain(|t| t[0] != "state");
    store.record_app_event(&unreadable).unwrap();
    let mut foreign = item_edit("foreign", "item", 14, 6, "done");
    foreign.sender = "mallory".to_owned();
    store.record_app_event(&foreign).unwrap();

    let latest = row(&store, "item");
    assert_eq!(latest.plaintext, "v2 running");
    assert_eq!(latest.tags, item_tags(2, "running", 1));
}

#[test]
fn a_turns_rows_follow_seq_within_one_second() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    // Ids sort opposite to seq, which ordered them before.
    store
        .record_app_event(&item("c-first", 10, 1, "running", 1))
        .unwrap();
    store
        .record_app_event(&item("b-second", 10, 1, "running", 2))
        .unwrap();
    store
        .record_app_event(&item("a-third", 10, 1, "running", 3))
        .unwrap();
    store
        .record_app_event(&event(
            "prompt",
            "alice",
            9,
            MARMOT_APP_EVENT_KIND_CHAT,
            Vec::new(),
            "go",
        ))
        .unwrap();
    store
        .record_app_event(&event(
            "answer",
            "agent",
            11,
            MARMOT_APP_EVENT_KIND_CHAT,
            vec![tag(&["turn", "turn-1"])],
            "done",
        ))
        .unwrap();
    // A later version names a later seq; the row stays where it began.
    store
        .record_app_event(&item_edit("edit", "c-first", 10, 2, "done"))
        .unwrap();

    let expected = ["prompt", "c-first", "b-second", "a-third", "answer"];
    assert_eq!(rows(&store), expected);

    // Paging one row at a time in each direction walks the same order.
    let page = |pagination: TimelinePagination| {
        store
            .message_timeline(TimelineMessageQuery {
                group_id_hex: Some(GROUP.to_owned()),
                pagination,
                ..TimelineMessageQuery::default()
            })
            .unwrap()
            .messages
            .into_iter()
            .map(|message| message.message_id_hex)
            .collect::<Vec<_>>()
    };
    let mut forward = vec!["prompt".to_owned()];
    while let Some(last) = forward.last().cloned() {
        let at = row(&store, &last).timeline_at;
        let next = page(TimelinePagination {
            after: Some(at),
            after_message_id: Some(last),
            limit: Some(1),
            ..TimelinePagination::default()
        });
        let Some(next) = next.into_iter().next() else {
            break;
        };
        forward.push(next);
    }
    assert_eq!(forward, expected);
    let mut backward = vec!["answer".to_owned()];
    while let Some(last) = backward.last().cloned() {
        let at = row(&store, &last).timeline_at;
        let previous = page(TimelinePagination {
            before: Some(at),
            before_message_id: Some(last),
            limit: Some(1),
            ..TimelinePagination::default()
        });
        let Some(previous) = previous.into_iter().next() else {
            break;
        };
        backward.push(previous);
    }
    backward.reverse();
    assert_eq!(backward, expected);
}

#[test]
fn an_answer_or_a_control_has_no_row() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .record_app_event(&item("item", 10, 1, "waiting", 1))
        .unwrap();
    let update = store
        .record_app_event(&event(
            "request",
            "alice",
            11,
            MARMOT_APP_EVENT_KIND_AGENT_REQUEST,
            vec![
                tag(&["p", &hex('c')]),
                tag(&["e", "item"]),
                tag(&["details", r#"{"action":"choice","choice":"allow"}"#]),
            ],
            "Allow once",
        ))
        .unwrap();
    assert!(update.changes.iter().all(|change| !matches!(
        change,
        TimelineMessageChange::Upsert { message, .. } if message.message_id_hex == "request"
    )));
    assert_eq!(rows(&store), ["item"]);
    assert!(store.timeline_message(GROUP, "request").unwrap().is_none());
    assert!(store.app_message(GROUP, "request").unwrap().is_some());
}

#[test]
fn an_item_in_the_old_shape_is_an_unreadable_row() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .record_app_event(&event(
            "old",
            "agent",
            10,
            MARMOT_APP_EVENT_KIND_AGENT_ITEM,
            vec![tag(&["status", "error"]), tag(&["e", &hex('a')])],
            r#"{"v":1,"status":"error","text":"could not deliver"}"#,
        ))
        .unwrap();
    let old = row(&store, "old");
    assert_eq!(old.kind, MARMOT_APP_EVENT_KIND_AGENT_ITEM);
    assert_eq!(old.agent_item, None);
    assert_eq!(old.reply_to_message_id_hex, None);
    assert_eq!(old.timeline_order_seq, 0);
}

/// An item in a subagent's thread (marmot-agents D-121) is placed by its
/// NIP-22 tags: `E` names the root and `e` the parent, which a client without
/// a thread view quotes. An edit cannot carry the parent's `e`, so the item
/// stays where its first event placed it, whatever thread tags an edit
/// carries; a rebuild agrees.
#[test]
fn an_item_in_a_thread_stays_where_its_first_event_placed_it() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let thread = |root: &str, parent: &str| {
        vec![
            tag(&["E", root, "", "agent"]),
            tag(&["K", "1201"]),
            tag(&["P", "agent"]),
            tag(&["e", parent, "", "agent"]),
            tag(&["k", "1201"]),
            tag(&["p", "agent"]),
        ]
    };
    let unstarted = |mut event: StoredAppEvent| {
        event.tags.retain(|tag| tag[0] != "started_by");
        event
    };
    store
        .record_app_event(&item("task", 9, 1, "running", 1))
        .unwrap();
    let mut first = unstarted(item("nested", 10, 1, "running", 7));
    first.tags.extend(thread("task", "subtask"));
    store.record_app_event(&first).unwrap();
    let placed = Some(TimelineThreadRef {
        root_message_id_hex: "task".to_owned(),
        parent_message_id_hex: "subtask".to_owned(),
    });
    assert_eq!(row(&store, "task").thread, None);
    assert_eq!(row(&store, "nested").thread, placed);
    assert_eq!(
        row(&store, "nested").reply_to_message_id_hex.as_deref(),
        Some("subtask")
    );

    store
        .record_app_event(&unstarted(item_edit("edit-2", "nested", 11, 2, "running")))
        .unwrap();
    assert_eq!(row(&store, "nested").thread, placed);
    let mut moved = unstarted(item_edit("edit-3", "nested", 12, 3, "done"));
    moved
        .tags
        .extend(thread("elsewhere", "elsewhere").into_iter().take(3));
    store.record_app_event(&moved).unwrap();
    for _ in 0..2 {
        let latest = row(&store, "nested");
        assert_eq!(latest.plaintext, "v3 done");
        assert_eq!(latest.thread, placed);
        assert_eq!(latest.reply_to_message_id_hex.as_deref(), Some("subtask"));
        store.rebuild_message_timeline_for_group(GROUP).unwrap();
    }
}
