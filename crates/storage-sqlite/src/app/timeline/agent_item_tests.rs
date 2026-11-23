//! Agent items (kind 1201) and answers and controls (kind 1202) in the
//! timeline: one row per item at its first event, holding its highest version.
use super::*;
use crate::SqliteAccountStorage;

const GROUP: &str = "1111111111111111111111111111111111111111111111111111111111111111";
/// An item's id. A held edit's target must be an event id.
const ITEM: &str = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";

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
        .record_app_event(&item(ITEM, 10, 1, "running", 7))
        .unwrap();
    assert!(matches!(
        first.changes.as_slice(),
        [TimelineMessageChange::Upsert {
            trigger: TimelineUpdateTrigger::AgentItem,
            message,
        }] if message.message_id_hex == ITEM
    ));
    let first_row = row(&store, ITEM);
    assert_eq!(first_row.tags, item_tags(1, "running", 7));
    assert_eq!(first_row.reply_to_message_id_hex, Some(hex('a')));

    let update = store
        .record_app_event(&item_edit("edit-2", ITEM, 11, 2, "done"))
        .unwrap();
    assert!(update.changes.iter().any(|change| matches!(
        change,
        TimelineMessageChange::Upsert { message, .. } if message.message_id_hex == ITEM
    )));

    let latest = row(&store, ITEM);
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
    assert_eq!(rows(&store), [ITEM]);
    assert!(
        store
            .message_edit_history(GROUP, ITEM, None, 10)
            .unwrap()
            .versions
            .is_empty()
    );
}

#[test]
fn an_items_reply_target_is_the_turn_its_latest_version_names() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let mut first = item(ITEM, 10, 1, "running", 1);
    first.tags.retain(|t| t[0] != "started_by");
    store.record_app_event(&first).unwrap();
    assert_eq!(row(&store, ITEM).reply_to_message_id_hex, None);

    store
        .record_app_event(&item_edit("edit-2", ITEM, 11, 2, "done"))
        .unwrap();
    assert_eq!(row(&store, ITEM).reply_to_message_id_hex, Some(hex('a')));
}

#[test]
fn an_edit_that_arrives_before_its_item_is_held_and_applied() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .record_app_event(&item_edit("edit-2", ITEM, 11, 2, "waiting"))
        .unwrap();
    assert_eq!(row(&store, ITEM).plaintext, "v2 waiting");

    store
        .record_app_event(&item(ITEM, 10, 1, "running", 1))
        .unwrap();

    let latest = row(&store, ITEM);
    assert_eq!(latest.plaintext, "v2 waiting");
    assert_eq!(latest.agent_item.unwrap().version, 2);
    assert!(!latest.agent_item_first_event_missing);
    assert_eq!(latest.timeline_at, 10);
}

/// A member added after an item began never gets its first event, only its
/// later edits, each carrying the whole item (marmot-agents D-124). The
/// item's row is then its earliest edit, at that edit's place, holding the
/// highest version and saying its first event is missing. Only that edit's
/// sender's versions count, an edit naming another message too is no
/// version, and a rebuild agrees. The first event, should it arrive, takes
/// the row back to its own place.
#[test]
fn an_item_whose_first_event_never_arrives_is_shown_from_its_edits() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    // The edit anchoring the row gives it its retention.
    let retention = Some(AppMessageRetentionDecision::new(30, 3600));
    store
        .record_app_event_with_retention(&item_edit("edit-3", ITEM, 30, 3, "running"), retention)
        .unwrap();
    store
        .record_app_event(&item_edit("edit-4", ITEM, 40, 4, "waiting"))
        .unwrap();
    let mut foreign = item_edit("edit-9", ITEM, 50, 9, "done");
    foreign.sender = "someone".to_owned();
    store.record_app_event(&foreign).unwrap();
    let mut two_targets = item_edit("edit-8", ITEM, 20, 8, "failed");
    two_targets.tags.push(tag(&["e", "other"]));
    store.record_app_event(&two_targets).unwrap();
    // An edit of a chat message that never arrived is no item.
    store
        .record_app_event(&event(
            "chat-edit",
            "agent",
            25,
            MARMOT_APP_EVENT_KIND_EDIT,
            vec![tag(&["e", "chat"])],
            "fixed",
        ))
        .unwrap();

    for _ in 0..2 {
        assert_eq!(rows(&store), [ITEM]);
        let held = row(&store, ITEM);
        assert!(held.agent_item_first_event_missing);
        assert_eq!(held.sender, "agent");
        assert_eq!(held.kind, MARMOT_APP_EVENT_KIND_AGENT_ITEM);
        assert_eq!(held.timeline_at, 30);
        assert_eq!(held.plaintext, "v4 waiting");
        assert_eq!(held.tags, item_tags(4, "waiting", 104));
        assert_eq!(held.agent_item.unwrap().version, 4);
        assert_eq!(held.edit, None);
        assert_eq!(held.retention_seconds, Some(3600));
        assert_eq!(held.retention_expires_at, Some(3630));
        store.rebuild_message_timeline_for_group(GROUP).unwrap();
    }

    store
        .record_app_event(&item(ITEM, 10, 1, "running", 1))
        .unwrap();
    let first = row(&store, ITEM);
    assert!(!first.agent_item_first_event_missing);
    assert_eq!(first.timeline_at, 10);
    assert_eq!(first.plaintext, "v4 waiting");
}

/// The agent deleting an item it never sent this device removes the row
/// built from its edits, as it would the item's own.
#[test]
fn an_item_shown_from_its_edits_can_be_deleted_by_its_agent() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .record_app_event(&item_edit("edit-2", ITEM, 20, 2, "running"))
        .unwrap();
    let delete = |id: &str, sender: &str, at: u64| {
        event(
            id,
            sender,
            at,
            MARMOT_APP_EVENT_KIND_DELETE,
            vec![tag(&["e", ITEM])],
            "",
        )
    };
    store
        .record_app_event(&delete("forged", "someone", 21))
        .unwrap();
    assert!(!row(&store, ITEM).deleted);
    store
        .record_app_event(&delete("delete", "agent", 22))
        .unwrap();
    for _ in 0..2 {
        assert!(row(&store, ITEM).deleted);
        store.rebuild_message_timeline_for_group(GROUP).unwrap();
    }
}

#[test]
fn the_highest_version_wins_in_any_order_and_a_late_older_one_is_ignored() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .record_app_event(&item(ITEM, 10, 1, "running", 1))
        .unwrap();
    // Within one second, and with ids whose order disagrees with the versions.
    store
        .record_app_event(&item_edit("aa-v3", ITEM, 10, 3, "done"))
        .unwrap();
    assert_eq!(row(&store, ITEM).plaintext, "v3 done");

    store
        .record_app_event(&item_edit("ff-v2", ITEM, 10, 2, "running"))
        .unwrap();
    assert_eq!(row(&store, ITEM).plaintext, "v3 done");

    // A later second does not beat a higher version either.
    store
        .record_app_event(&item_edit("late-v2", ITEM, 99, 2, "failed"))
        .unwrap();
    let latest = row(&store, ITEM);
    assert_eq!(latest.plaintext, "v3 done");
    assert_eq!(latest.agent_item.unwrap().version, 3);
}

#[test]
fn an_edit_no_newer_than_the_first_event_or_unreadable_or_foreign_is_ignored() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .record_app_event(&item(ITEM, 10, 2, "running", 1))
        .unwrap();
    store
        .record_app_event(&item_edit("same", ITEM, 11, 2, "done"))
        .unwrap();
    store
        .record_app_event(&item_edit("older", ITEM, 12, 1, "done"))
        .unwrap();
    let mut unreadable = item_edit("unreadable", ITEM, 13, 5, "done");
    unreadable.tags.retain(|t| t[0] != "state");
    store.record_app_event(&unreadable).unwrap();
    let mut foreign = item_edit("foreign", ITEM, 14, 6, "done");
    foreign.sender = "mallory".to_owned();
    store.record_app_event(&foreign).unwrap();

    let latest = row(&store, ITEM);
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
        .record_app_event(&item(ITEM, 10, 1, "waiting", 1))
        .unwrap();
    let update = store
        .record_app_event(&event(
            "request",
            "alice",
            11,
            MARMOT_APP_EVENT_KIND_AGENT_REQUEST,
            vec![
                tag(&["p", &hex('c')]),
                tag(&["e", ITEM]),
                tag(&["details", r#"{"action":"choice","choice":"allow"}"#]),
            ],
            "Allow once",
        ))
        .unwrap();
    assert!(update.changes.iter().all(|change| !matches!(
        change,
        TimelineMessageChange::Upsert { message, .. } if message.message_id_hex == "request"
    )));
    assert_eq!(rows(&store), [ITEM]);
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

/// An item outside a thread takes every tag of its latest version, a
/// lowercase `p` among them, but not an `E`: an edit cannot move it into a
/// thread.
#[test]
fn an_item_outside_a_thread_takes_its_edits_tags_but_never_joins_a_thread() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let mut first = item(ITEM, 10, 1, "running", 1);
    first.tags.push(tag(&["p", "someone"]));
    store.record_app_event(&first).unwrap();
    let mut edit = item_edit("edit-2", ITEM, 11, 2, "done");
    edit.tags.push(tag(&["p", "someone-else"]));
    edit.tags.push(tag(&["E", "elsewhere"]));
    store.record_app_event(&edit).unwrap();

    let latest = row(&store, ITEM);
    let mut expected = item_tags(2, "done", 102);
    expected.push(tag(&["p", "someone-else"]));
    assert_eq!(latest.tags, expected);
    assert_eq!(latest.thread, None);
}

/// An item in a subagent's thread whose first event this device never got is
/// placed by the root its edits repeat, answering that root, since an edit
/// cannot name the parent; later edits keep it there.
#[test]
fn an_item_shown_from_its_edits_sits_in_the_thread_they_name() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let in_thread = |mut edit: StoredAppEvent, root: &str| {
        edit.tags.retain(|tag| tag[0] != "started_by");
        edit.tags.extend([
            tag(&["E", root, "", "agent"]),
            tag(&["K", "1201"]),
            tag(&["P", "agent"]),
        ]);
        edit
    };
    store
        .record_app_event(&in_thread(
            item_edit("edit-2", ITEM, 20, 2, "running"),
            "task",
        ))
        .unwrap();
    store
        .record_app_event(&in_thread(
            item_edit("edit-3", ITEM, 30, 3, "done"),
            "elsewhere",
        ))
        .unwrap();
    let held = row(&store, ITEM);
    assert_eq!(held.plaintext, "v3 done");
    assert_eq!(
        held.thread,
        Some(TimelineThreadRef {
            root_message_id_hex: "task".to_owned(),
            parent_message_id_hex: "task".to_owned(),
        })
    );
    assert_eq!(held.reply_to_message_id_hex.as_deref(), Some("task"));
}

/// An item's edit imported from a sibling's history, without the first event,
/// shows the item with that import's source. When its sender deleted an
/// earlier edit in the same second, the row and its source are both the
/// surviving edit's.
#[test]
fn an_item_shown_from_an_imported_edit_names_the_import_source() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    store
        .record_app_event_with_retention(
            &item_edit("aa-edit", ITEM, 20, 3, "running"),
            Some(AppMessageRetentionDecision::new(20, 60)),
        )
        .unwrap();
    store
        .record_app_event(&event(
            "delete",
            "agent",
            21,
            MARMOT_APP_EVENT_KIND_DELETE,
            vec![tag(&["e", "aa-edit"])],
            "",
        ))
        .unwrap();
    let edit = item_edit("edit-2", ITEM, 20, 2, "running");
    let slot = [7; 32];
    store
        .import_app_events(
            GROUP,
            &slot,
            &[ImportedAppEvent {
                message_id_hex: edit.message_id_hex.clone(),
                source_epoch: 3,
                sender: edit.sender.clone(),
                plaintext: edit.plaintext.clone(),
                kind: edit.kind,
                tags: edit.tags.clone(),
                created_at: edit.recorded_at,
                retention: None,
                moderation_grant: None,
                file_keys: Vec::new(),
            }],
            100,
        )
        .unwrap();
    let held = row(&store, ITEM);
    assert!(held.agent_item_first_event_missing);
    assert_eq!(held.plaintext, "v2 running");
    assert_eq!(held.retention_seconds, None);
    assert_eq!(
        held.history_import_provenance,
        Some(HistoryImportProvenance::Device(slot))
    );
}

/// A history import that deletes the only edit an item is shown from tells an
/// open timeline to drop the row; one that also brings the item's first event
/// keeps it.
#[test]
fn an_import_that_deletes_the_only_edit_removes_the_item_from_open_timelines() {
    let imported = |event: StoredAppEvent| ImportedAppEvent {
        message_id_hex: event.message_id_hex,
        source_epoch: 3,
        sender: event.sender,
        plaintext: event.plaintext,
        kind: event.kind,
        tags: event.tags,
        created_at: event.recorded_at,
        retention: None,
        moderation_grant: None,
        file_keys: Vec::new(),
    };
    let delete_edit = || {
        imported(event(
            "delete",
            "agent",
            21,
            MARMOT_APP_EVENT_KIND_DELETE,
            vec![tag(&["e", "edit-2"])],
            "",
        ))
    };
    let item_change = |batch: Vec<ImportedAppEvent>| {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store
            .record_app_event(&item_edit("edit-2", ITEM, 20, 2, "running"))
            .unwrap();
        let changes = store
            .import_app_events(GROUP, &[7; 32], &batch, 100)
            .unwrap()
            .update
            .changes;
        let mut item = changes.into_iter().filter(|change| match change {
            TimelineMessageChange::Upsert { message, .. } => message.message_id_hex == ITEM,
            TimelineMessageChange::Remove { message_id_hex, .. } => message_id_hex == ITEM,
        });
        let change = item.next().expect("the import names the item's row");
        assert!(item.next().is_none());
        change
    };

    assert!(matches!(
        item_change(vec![delete_edit()]),
        TimelineMessageChange::Remove { .. }
    ));
    let TimelineMessageChange::Upsert { message, .. } = item_change(vec![
        delete_edit(),
        imported(item(ITEM, 10, 1, "running", 1)),
    ]) else {
        panic!("the item's first event brings its row back");
    };
    assert!(!message.agent_item_first_event_missing);
    assert_eq!(message.plaintext, "v1 running");
}

/// Once retention has removed an item, an edit of it that reaches this device
/// only later, still within its own retention, does not bring the item back
/// from that edit. That holds for an item shown from its edits too.
#[test]
fn an_item_retention_removed_is_not_shown_again_from_a_late_edit() {
    let swept = |first: StoredAppEvent| {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store
            .record_app_event_with_retention(&first, Some(AppMessageRetentionDecision::new(10, 60)))
            .unwrap();
        store
            .secure_prune_expired_app_events(GROUP, 80, "self", &|_, _| false)
            .unwrap();
        store
            .record_app_event_with_retention(
                &item_edit("late", ITEM, 50, 3, "waiting"),
                Some(AppMessageRetentionDecision::new(50, 60)),
            )
            .unwrap();
        for _ in 0..2 {
            assert!(store.timeline_message(GROUP, ITEM).unwrap().is_none());
            store.rebuild_message_timeline_for_group(GROUP).unwrap();
        }
    };
    swept(item(ITEM, 10, 1, "running", 1));
    swept(item_edit("edit-2", ITEM, 10, 2, "running"));
}

/// An edit naming something that is no event id shows no item: an answer to
/// that item could never name it.
#[test]
fn an_edit_naming_no_event_id_shows_no_item() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    for target in ["item", &ITEM.to_uppercase()] {
        store
            .record_app_event(&item_edit(
                &format!("edit-{target}"),
                target,
                20,
                2,
                "waiting",
            ))
            .unwrap();
    }
    for _ in 0..2 {
        assert!(rows(&store).is_empty());
        store.rebuild_message_timeline_for_group(GROUP).unwrap();
    }
}

/// An edit that named another edit, not the item, shows a row until that
/// edit arrives. Then the row goes, live and on rebuild, and the item stays.
#[test]
fn a_row_shown_from_an_edit_of_an_edit_goes_when_that_edit_arrives() {
    let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
    let earlier = hex('e');
    store
        .record_app_event(&item(ITEM, 10, 1, "running", 1))
        .unwrap();
    store
        .record_app_event(&item_edit("edit-3", &earlier, 30, 3, "done"))
        .unwrap();
    assert_eq!(rows(&store), [ITEM.to_owned(), earlier.clone()]);

    let update = store
        .record_app_event(&item_edit(&earlier, ITEM, 20, 2, "running"))
        .unwrap();
    assert!(update.changes.iter().any(|change| matches!(
        change,
        TimelineMessageChange::Remove { message_id_hex, .. } if *message_id_hex == earlier
    )));
    for _ in 0..2 {
        assert_eq!(rows(&store), [ITEM]);
        assert_eq!(row(&store, ITEM).plaintext, "v2 running");
        store.rebuild_message_timeline_for_group(GROUP).unwrap();
    }
}
