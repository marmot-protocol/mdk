use super::*;
const GROUP: &str = "00112233445566778899aabbccddeeff";
const LOCAL: &str = "aa";
fn no_mentions(_: &str, _: &[Vec<String>]) -> bool {
    false
}
fn seed(store: &SqliteAccountStorage) {
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES (?1, '', 0)",
            [GROUP],
        )
        .unwrap();
    store.lock().unwrap().execute("INSERT INTO conversation_read_state(group_id_hex, initialized_at, updated_at) VALUES (?1, 0, 0)", [GROUP]).unwrap();
    refresh(store);
}
fn refresh(store: &SqliteAccountStorage) {
    store
        .refresh_chat_list_row(LOCAL, GROUP, &no_mentions)
        .unwrap();
}
fn event(id: &str, epoch: u64, at: u64) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: GROUP.into(),
        message_id_hex: id.into(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: Some(epoch),
        direction: "received".into(),
        sender: "bb".into(),
        plaintext: id.into(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: vec![],
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
        moderation_grant: false,
    }
}
fn add(store: &SqliteAccountStorage, id: &str, epoch: u64, at: u64) {
    store.record_app_event(&event(id, epoch, at)).unwrap();
    refresh(store);
}
fn ids(snapshot: &ConversationOpenSnapshot) -> Vec<&str> {
    snapshot
        .page
        .messages
        .iter()
        .map(|m| m.message_id_hex.as_str())
        .collect()
}
#[test]
fn opening_uses_first_unread_in_canonical_order_without_changing_read_state() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    add(&store, "old", 1, 900);
    add(&store, "unread", 2, 100);
    add(&store, "new", 3, 50);
    store
        .mark_timeline_message_read(LOCAL, GROUP, "old", &no_mentions)
        .unwrap();
    let before = store.chat_list_row(GROUP).unwrap().unwrap();
    let opened = store
        .conversation_open(
            GROUP,
            ConversationOpenQuery {
                limit: 3,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(ids(&opened), ["old", "unread", "new"]);
    assert_eq!(
        opened.anchor,
        ConversationOpenAnchorOutcome::FirstUnread { index: 1 }
    );
    assert_eq!(opened.read_state.unread_count, 2);
    assert_eq!(store.chat_list_row(GROUP).unwrap().unwrap(), before);
    assert!(!opened.page.has_more_before && !opened.page.has_more_after);
}

#[test]
fn coherent_read_state_does_not_depend_on_wall_clock_order() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    add(&store, "read", 1, 1);
    add(&store, "unread", 2, 2);
    store
        .mark_timeline_message_read(LOCAL, GROUP, "read", &no_mentions)
        .unwrap();
    // A backwards wall-clock adjustment between source/projection timestamps
    // must not invalidate structurally identical durable read markers.
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_list_rows SET updated_at = 0 WHERE group_id_hex = ?1",
            [GROUP],
        )
        .unwrap();
    let snapshot = open(&store, ConversationOpenTarget::Automatic, 50);
    assert_eq!(snapshot.read_state.unread_count, 1);
    assert_eq!(
        snapshot.anchor,
        ConversationOpenAnchorOutcome::FirstUnread { index: 1 }
    );
    // A real source/projection marker mismatch must still fail closed.
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE conversation_read_state SET manually_marked_unread = 1 WHERE group_id_hex = ?1",
            [GROUP],
        )
        .unwrap();
    assert!(matches!(
        store.conversation_open(GROUP, ConversationOpenQuery::default()),
        Err(ConversationOpenError::ReadStateNotReady)
    ));
}

fn open(
    store: &SqliteAccountStorage,
    target: ConversationOpenTarget,
    limit: usize,
) -> ConversationOpenSnapshot {
    store
        .conversation_open(GROUP, ConversationOpenQuery { target, limit })
        .unwrap()
}
fn remove(store: &SqliteAccountStorage, id: &str) {
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM message_timeline WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![GROUP, id],
        )
        .unwrap();
    refresh(store);
}
#[test]
fn page_budgets_fill_at_both_edges_and_report_exact_boundaries() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    for n in 0..9 {
        add(&store, &format!("m{n}"), 1, 100);
    }
    for limit in [1, 2, 3, 4, 8, 9, 50, 200] {
        for n in 0..9 {
            let snapshot = open(
                &store,
                ConversationOpenTarget::Message(format!("m{n}")),
                limit,
            );
            assert_eq!(snapshot.page.messages.len(), limit.min(9));
            let ConversationOpenAnchorOutcome::Message { index } = snapshot.anchor else {
                panic!("message anchor required")
            };
            assert_eq!(ids(&snapshot)[index], format!("m{n}"));
            let first = ids(&snapshot)[0]
                .strip_prefix('m')
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let last = ids(&snapshot)
                .last()
                .unwrap()
                .strip_prefix('m')
                .unwrap()
                .parse::<usize>()
                .unwrap();
            assert_eq!(last - first + 1, snapshot.page.messages.len());
            assert_eq!(snapshot.page.has_more_before, first > 0);
            assert_eq!(snapshot.page.has_more_after, last < 8);
            assert_eq!(snapshot.anchors.len(), snapshot.page.messages.len());
            for (anchor, message) in snapshot.anchors.iter().zip(&snapshot.page.messages) {
                assert_eq!(anchor.message_id_hex(), message.message_id_hex);
            }
        }
    }
}
#[test]
fn manual_unread_does_not_invent_a_message_anchor_or_change_retained_history_eligibility() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    add(&store, "a", 1, 1);
    add(&store, "b", 2, 2);
    store
        .mark_timeline_message_read(LOCAL, GROUP, "b", &no_mentions)
        .unwrap();
    store
        .set_chat_manually_unread(LOCAL, GROUP, true, &no_mentions)
        .unwrap();
    let snapshot = open(&store, ConversationOpenTarget::Automatic, 1);
    assert_eq!(ids(&snapshot), ["b"]);
    assert_eq!(
        snapshot.anchor,
        ConversationOpenAnchorOutcome::Latest { index: 0 }
    );
    assert!(snapshot.read_state.manually_marked_unread);
    assert_eq!(snapshot.read_state.unread_count, 0);
    add(&store, "c", 3, 3);
    for membership in ["member", "left", "removed"] {
        store.lock().unwrap().execute("UPDATE account_groups SET archived = 1, self_membership = ?1 WHERE group_id_hex = ?2", params![membership, GROUP]).unwrap();
        refresh(&store);
        let snapshot = open(&store, ConversationOpenTarget::Automatic, 1);
        assert_eq!(ids(&snapshot), ["c"]);
        assert_eq!(
            snapshot.anchor,
            ConversationOpenAnchorOutcome::FirstUnread { index: 0 }
        );
        assert_eq!(snapshot.read_state.unread_count, 1);
    }
}
#[test]
fn pending_invite_opens_at_latest_without_erasing_raw_unread() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    add(&store, "a", 1, 1);
    add(&store, "b", 2, 2);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET pending_confirmation = 1 WHERE group_id_hex = ?1",
            [GROUP],
        )
        .unwrap();
    refresh(&store);
    let pending = open(&store, ConversationOpenTarget::Automatic, 1);
    assert!(pending.pending_confirmation);
    assert_eq!(ids(&pending), ["b"]);
    assert_eq!(pending.read_state.unread_count, 2);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET pending_confirmation = 0 WHERE group_id_hex = ?1",
            [GROUP],
        )
        .unwrap();
    refresh(&store);
    let accepted = open(&store, ConversationOpenTarget::Automatic, 1);
    assert!(!accepted.pending_confirmation);
    assert_eq!(ids(&accepted), ["a"]);
    assert_eq!(
        accepted.anchor,
        ConversationOpenAnchorOutcome::FirstUnread { index: 0 }
    );
    assert!(pending.read_state == accepted.read_state);
}
#[test]
fn missing_anchor_recovers_next_then_previous_then_empty_and_explicit_missing_is_an_error() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    for (id, epoch) in [("a", 1), ("b", 2), ("c", 3)] {
        add(&store, id, epoch, 100 - epoch);
    }
    let original = open(&store, ConversationOpenTarget::Message("b".into()), 1)
        .anchors
        .remove(0);
    remove(&store, "b");
    assert!(matches!(
        store.conversation_open(
            GROUP,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Message("b".into()),
                limit: 1
            }
        ),
        Err(ConversationOpenError::MessageNotFound)
    ));
    let next = open(&store, ConversationOpenTarget::Anchor(original.clone()), 1);
    assert_eq!(ids(&next), ["c"]);
    assert_eq!(
        next.anchor,
        ConversationOpenAnchorOutcome::RecoveredNext { index: 0 }
    );
    remove(&store, "c");
    let previous = open(&store, ConversationOpenTarget::Anchor(original.clone()), 1);
    assert_eq!(ids(&previous), ["a"]);
    assert_eq!(
        previous.anchor,
        ConversationOpenAnchorOutcome::RecoveredPrevious { index: 0 }
    );
    remove(&store, "a");
    let empty = open(&store, ConversationOpenTarget::Anchor(original), 1);
    assert_eq!(empty.anchor, ConversationOpenAnchorOutcome::Empty);
    assert!(empty.page.messages.is_empty() && empty.anchors.is_empty());
    assert!(!empty.page.has_more_before && !empty.page.has_more_after);
}
#[test]
fn retained_identity_follows_canonical_reordering_and_keeps_tombstones() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    add(&store, "a", 1, 900);
    let mut pending = event("pending", 2, 100);
    pending.source_epoch = None;
    pending.source_message_id_hex = None;
    pending.direction = "sent".into();
    pending.sender = LOCAL.into();
    store.record_app_event(&pending).unwrap();
    refresh(&store);
    let anchor = open(&store, ConversationOpenTarget::Latest, 1)
        .anchors
        .remove(0);
    add(&store, "b", 3, 10);
    store.lock().unwrap().execute("UPDATE message_timeline SET source_epoch = 2, source_message_id_hex = 'confirmed' WHERE group_id_hex = ?1 AND message_id_hex = 'pending'", [GROUP]).unwrap();
    refresh(&store);
    let retained = open(&store, ConversationOpenTarget::Anchor(anchor.clone()), 3);
    assert_eq!(ids(&retained), ["a", "pending", "b"]);
    assert_eq!(
        retained.anchor,
        ConversationOpenAnchorOutcome::Retained { index: 1 }
    );
    store.lock().unwrap().execute("UPDATE message_timeline SET deleted = 1, plaintext = '', invalidation_status = 'test' WHERE group_id_hex = ?1 AND message_id_hex = 'pending'", [GROUP]).unwrap();
    refresh(&store);
    let retained = open(&store, ConversationOpenTarget::Anchor(anchor), 1);
    assert!(retained.page.messages[0].deleted);
    assert!(retained.page.messages[0].plaintext.is_empty());
    assert_eq!(
        retained.anchor,
        ConversationOpenAnchorOutcome::Retained { index: 0 }
    );
}
#[test]
fn dirty_unread_refuses_read_only_until_source_owner_refreshes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    store.record_app_event(&event("a", 1, 1)).unwrap();
    let changes = store.lock().unwrap().total_changes();
    assert!(matches!(
        store.conversation_open(GROUP, Default::default()),
        Err(ConversationOpenError::ReadStateNotReady)
    ));
    assert_eq!(store.lock().unwrap().total_changes(), changes);
    refresh(&store);
    let opened = open(&store, ConversationOpenTarget::Automatic, 1);
    assert_eq!(ids(&opened), ["a"]);
    store
        .invalidate_app_event_by_message_id(GROUP, "a", "test")
        .unwrap();
    assert!(matches!(
        store.conversation_open(GROUP, Default::default()),
        Err(ConversationOpenError::ReadStateNotReady)
    ));
    refresh(&store);
    let opened = open(&store, ConversationOpenTarget::Automatic, 1);
    assert_eq!(opened.read_state.unread_count, 0);
    assert_eq!(
        opened.anchor,
        ConversationOpenAnchorOutcome::Latest { index: 0 }
    );
    assert!(opened.page.messages[0].invalidation_status.is_some());
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM chat_list_unread_ready_groups WHERE group_id_hex = ?1",
            [GROUP],
        )
        .unwrap();
    assert!(matches!(
        store.conversation_open(GROUP, Default::default()),
        Err(ConversationOpenError::ReadStateNotReady)
    ));
}
#[test]
fn query_only_and_nested_transaction_preserve_ownership_and_rollback() {
    use cgka_traits::StorageProvider;
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    add(&store, "a", 1, 1);
    store
        .lock()
        .unwrap()
        .pragma_update(None, "query_only", true)
        .unwrap();
    assert_eq!(
        ids(&open(&store, ConversationOpenTarget::Automatic, 1)),
        ["a"]
    );
    store
        .lock()
        .unwrap()
        .pragma_update(None, "query_only", false)
        .unwrap();
    let result: StorageResult<()> = store.with_transaction(|store| {
        store.mark_timeline_message_read(LOCAL, GROUP, "a", &no_mentions)?;
        assert_eq!(
            open(store, ConversationOpenTarget::Automatic, 1)
                .read_state
                .unread_count,
            0
        );
        assert!(!store.lock()?.is_autocommit());
        Err(StorageError::Backend("intentional rollback".into()))
    });
    assert!(result.is_err());
    assert_eq!(
        open(&store, ConversationOpenTarget::Automatic, 1)
            .read_state
            .unread_count,
        1
    );
    assert!(store.lock().unwrap().is_autocommit());
}
#[test]
fn anchors_are_scoped_and_limits_and_storage_errors_are_explicit() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    add(&store, "a", 1, 1);
    for limit in [0, 201, usize::MAX] {
        assert!(matches!(
            store.conversation_open(
                GROUP,
                ConversationOpenQuery {
                    limit,
                    ..Default::default()
                }
            ),
            Err(ConversationOpenError::InvalidLimit)
        ));
    }
    assert!(matches!(
        store.conversation_open("missing", Default::default()),
        Err(ConversationOpenError::Storage(StorageError::NotFound))
    ));
    let other = SqliteAccountStorage::in_memory().unwrap();
    seed(&other);
    add(&other, "a", 1, 1);
    let anchor = open(&store, ConversationOpenTarget::Latest, 1)
        .anchors
        .remove(0);
    assert!(matches!(
        other.conversation_open(
            GROUP,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Anchor(anchor.clone()),
                limit: 1
            }
        ),
        Err(ConversationOpenError::AnchorScopeMismatch)
    ));
    store.lock().unwrap().execute("INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('other', '', 0)", []).unwrap();
    assert!(matches!(
        store.conversation_open(
            "other",
            ConversationOpenQuery {
                target: ConversationOpenTarget::Anchor(anchor),
                limit: 1
            }
        ),
        Err(ConversationOpenError::AnchorScopeMismatch)
    ));
    store.close().unwrap();
    assert!(matches!(
        store.conversation_open(GROUP, Default::default()),
        Err(ConversationOpenError::Storage(StorageError::Closed(_)))
    ));
}
#[test]
fn opening_and_retained_tokens_survive_encrypted_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = crate::SqlCipherKey::new("08".repeat(32)).unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store);
    add(&store, "a", 1, 1);
    let before = open(&store, ConversationOpenTarget::Automatic, 1);
    let anchor = before.anchors[0].clone();
    store.close().unwrap();
    drop(store);
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let after = open(&reopened, ConversationOpenTarget::Anchor(anchor), 1);
    assert_eq!(after.page, before.page);
    assert!(after.read_state == before.read_state);
    assert_eq!(
        after.anchor,
        ConversationOpenAnchorOutcome::Retained { index: 0 }
    );
}

thread_local! {
    static AFTER_SOURCE_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

fn read_with_concurrent_writer<T>(
    reader: &SqliteAccountStorage,
    writer: SqliteAccountStorage,
    write: impl FnOnce(SqliteAccountStorage) + 'static,
    read: impl FnOnce() -> T,
) -> T {
    use rusqlite::trace::{TraceEvent, TraceEventCodes};
    AFTER_SOURCE_READ.with(|hook| *hook.borrow_mut() = Some(Box::new(move || write(writer))));
    reader.lock().unwrap().trace_v2(
        TraceEventCodes::SQLITE_TRACE_PROFILE,
        Some(|event| {
            if let TraceEvent::Profile(statement, _) = event
                && statement
                    .sql()
                    .starts_with("SELECT pending_confirmation FROM account_groups")
                && let Some(hook) = AFTER_SOURCE_READ.with(|slot| slot.borrow_mut().take())
            {
                hook();
            }
        }),
    );
    let value = read();
    reader
        .lock()
        .unwrap()
        .trace_v2(TraceEventCodes::empty(), None);
    // Fail if the statement hook stops matching: an unexecuted writer must
    // never turn these race tests into ordinary single-connection reads.
    assert!(AFTER_SOURCE_READ.with(|hook| hook.borrow().is_none()));
    value
}

#[test]
fn opening_read_state_and_history_share_one_wal_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = crate::SqlCipherKey::new("09".repeat(32)).unwrap();
    let reader = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&reader);
    add(&reader, "a", 1, 1);
    let writer = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let during = read_with_concurrent_writer(
        &reader,
        writer,
        |writer| {
            add(&writer, "b", 2, 2);
            writer
                .mark_timeline_message_read(LOCAL, GROUP, "b", &no_mentions)
                .unwrap();
            writer.close().unwrap();
        },
        || open(&reader, ConversationOpenTarget::Automatic, 50),
    );
    assert_eq!(ids(&during), ["a"]);
    assert_eq!(during.read_state.unread_count, 1);
    assert!(during.read_state.last_read_message_id_hex.is_none());
    let after = open(&reader, ConversationOpenTarget::Automatic, 50);
    assert_eq!(ids(&after), ["a", "b"]);
    assert_eq!(after.read_state.unread_count, 0);
    assert_eq!(
        after.read_state.last_read_message_id_hex.as_deref(),
        Some("b")
    );
}

#[test]
fn opening_query_work_is_bounded_for_deep_anchors_and_unrelated_groups() {
    use crate::query_work_test_support::measure;
    for count in [200, 20_000] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store);
        {
            let conn = store.lock().unwrap();
            conn.execute_batch(&format!("CREATE TEMP TABLE numbers(x INTEGER PRIMARY KEY);
                INSERT INTO numbers WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x < {count}) SELECT x FROM n;
                INSERT INTO message_timeline(group_id_hex, message_id_hex, source_message_id_hex, source_epoch, direction, sender, plaintext, kind, tags_json, timeline_at, received_at, reactions_json)
                    SELECT '{GROUP}', printf('m%06d',x), printf('source%06d',x), x, 'received', 'bb', 'message', 9, '[]', 1, 1, '{{\"by_emoji\":{{}},\"user_reactions\":[]}}' FROM numbers;
                INSERT INTO account_groups(group_id_hex, endpoint, updated_at) SELECT printf('other-%06d',x), '', 0 FROM numbers;
                INSERT INTO app_events(group_id_hex, message_id_hex, direction, sender, plaintext, kind, tags_json, recorded_at, received_at)
                    SELECT 'unrelated', printf('event-%06d',x), 'received', 'bb', 'message', 9, '[]', 1, 1 FROM numbers;
                DROP TABLE numbers;")).unwrap();
        }
        refresh(&store);
        let middle = format!("m{:06}", count / 2);
        store
            .mark_timeline_message_read(LOCAL, GROUP, &middle, &no_mentions)
            .unwrap();
        let saved = open(&store, ConversationOpenTarget::Message(middle.clone()), 1)
            .anchors
            .remove(0);
        for target in [
            ConversationOpenTarget::Automatic,
            ConversationOpenTarget::Latest,
            ConversationOpenTarget::Message(middle.clone()),
            ConversationOpenTarget::Anchor(saved.clone()),
        ] {
            let (result, steps) = measure(&store, || {
                store
                    .conversation_open(GROUP, ConversationOpenQuery { target, limit: 50 })
                    .unwrap()
            });
            assert_eq!(result.page.messages.len(), 50);
            eprintln!("history={count}, opening_vm_steps={steps}");
            assert!(
                steps < 12_000,
                "{count} rows: {steps} VM steps for a 50-row window"
            );
        }
        let (captured, steps) = measure(&store, || {
            store
                .conversation_account_snapshot(
                    GROUP,
                    ConversationWindowQuery {
                        opening: ConversationOpenQuery {
                            target: ConversationOpenTarget::Anchor(saved.clone()),
                            limit: 50,
                        },
                        before_anchor: Some(10),
                    },
                )
                .unwrap()
        });
        assert_eq!(captured.page.page().messages.len(), 50);
        eprintln!("history={count}, account_capture_vm_steps={steps}");
        assert!(
            steps < 14_000,
            "{count} rows: capture used {steps} VM steps"
        );
        remove(&store, &middle);
        let (recovered, steps) = measure(&store, || {
            open(&store, ConversationOpenTarget::Anchor(saved), 50)
        });
        assert!(matches!(
            recovered.anchor,
            ConversationOpenAnchorOutcome::RecoveredNext { .. }
        ));
        assert!(
            steps < 12_000,
            "{count} rows: recovery used {steps} VM steps"
        );
    }
}

#[test]
fn live_window_placement_pages_both_ways_without_moving_the_retained_anchor() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    for i in 0..12 {
        add(&store, &format!("m{i:02}"), i, i);
    }
    let opened = store
        .conversation_open(
            GROUP,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Message("m05".into()),
                limit: 3,
            },
        )
        .unwrap();
    let anchor = opened.anchors[1].clone();
    for (limit, before, first, last) in [
        (5, 3, "m02", "m06"),
        (7, 3, "m02", "m08"),
        (7, 5, "m00", "m06"),
    ] {
        let read = store
            .conversation_window(
                GROUP,
                ConversationWindowQuery {
                    opening: ConversationOpenQuery {
                        target: ConversationOpenTarget::Anchor(anchor.clone()),
                        limit,
                    },
                    before_anchor: Some(before),
                },
            )
            .unwrap();
        assert_eq!(read.page.messages.len(), limit);
        assert_eq!(ids(&read).first().copied(), Some(first));
        assert_eq!(ids(&read).last().copied(), Some(last));
        assert_eq!(
            read.anchor,
            ConversationOpenAnchorOutcome::Retained { index: before }
        );
        assert_eq!(read.anchors[before].message_id_hex(), "m05");
    }
    // Window navigation does not acknowledge any messages.
    assert_eq!(
        store
            .conversation_open(GROUP, ConversationOpenQuery::default())
            .unwrap()
            .read_state
            .unread_count,
        opened.read_state.unread_count
    );
}

#[test]
fn live_window_placement_fills_edges_and_recovers_deleted_anchor() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    for i in 0..8 {
        add(&store, &format!("m{i}"), i, i);
    }
    let opened = store
        .conversation_open(
            GROUP,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Message("m1".into()),
                limit: 3,
            },
        )
        .unwrap();
    let anchor = opened.anchors[1].clone();
    let query = ConversationWindowQuery {
        opening: ConversationOpenQuery {
            target: ConversationOpenTarget::Anchor(anchor),
            limit: 5,
        },
        before_anchor: Some(4),
    };
    let read = store.conversation_window(GROUP, query.clone()).unwrap();
    assert_eq!(ids(&read), ["m0", "m1", "m2", "m3", "m4"]);
    assert_eq!(
        read.anchor,
        ConversationOpenAnchorOutcome::Retained { index: 1 }
    );
    remove(&store, "m1");
    let read = store.conversation_window(GROUP, query).unwrap();
    assert_eq!(ids(&read), ["m0", "m2", "m3", "m4", "m5"]);
    assert_eq!(
        read.anchor,
        ConversationOpenAnchorOutcome::RecoveredNext { index: 1 }
    );
    let error = store.conversation_window(
        GROUP,
        ConversationWindowQuery {
            opening: ConversationOpenQuery {
                limit: 5,
                ..Default::default()
            },
            before_anchor: Some(5),
        },
    );
    assert!(matches!(
        error,
        Err(ConversationOpenError::InvalidAnchorPosition)
    ));
}

#[test]
fn account_capture_keeps_prepared_rows_controls_and_draft_descriptors_together() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    let message_id = "ab".repeat(32);
    add(&store, &message_id, 1, 1);
    store
        .save_message_draft(GROUP, "unsent", Some(message_id.as_str()), &[])
        .unwrap();
    store.lock().unwrap().execute(
        "UPDATE account_groups SET archived = 1, profile_name = 'Selected title', admin_keys_hex = 'aa' WHERE group_id_hex = ?1",
        [GROUP],
    ).unwrap();
    let before = store
        .conversation_open(GROUP, Default::default())
        .unwrap()
        .read_state;
    let captured = store
        .conversation_account_snapshot(GROUP, Default::default())
        .unwrap();
    assert_eq!(captured.page.page().messages.len(), 1);
    assert_eq!(captured.page.page().messages[0].message_id_hex, message_id);
    assert_eq!(captured.presentation_input.group_name, "Selected title");
    assert_eq!(
        captured.page.store_epoch(),
        captured.presentation_input.source_version.store_epoch
    );
    assert!(captured.archived);
    assert!(!captured.leave_request_pending);
    assert_eq!(captured.admin_keys_hex, "aa");
    assert_eq!(captured.draft.draft.as_ref().unwrap().content, "unsent");
    assert_eq!(
        captured
            .draft
            .draft
            .as_ref()
            .unwrap()
            .reply_to_message_id_hex
            .as_deref(),
        Some(message_id.as_str())
    );
    assert!(captured.read_state == before);
    assert!(
        store
            .conversation_open(GROUP, Default::default())
            .unwrap()
            .read_state
            == before
    );
}

#[test]
fn account_capture_joins_a_caller_transaction_without_committing_it() {
    use cgka_traits::StorageProvider;
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    let original = store.selected_message_draft(GROUP).unwrap();
    let result: Result<(), StorageError> = store.with_transaction(|store| {
        store.save_message_draft(GROUP, "rolled back", None, &[])?;
        let captured = store
            .conversation_account_snapshot(GROUP, Default::default())
            .unwrap();
        assert_eq!(captured.draft.draft.unwrap().content, "rolled back");
        assert!(!store.lock()?.is_autocommit());
        Err(StorageError::NotFound)
    });
    assert!(matches!(result, Err(StorageError::NotFound)));
    let after = store.selected_message_draft(GROUP).unwrap();
    assert!(after.draft.is_none());
    assert!(after.revision == original.revision);
    assert!(store.lock().unwrap().is_autocommit());
}

#[test]
fn account_capture_rejects_unprepared_state_without_writing() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM chat_list_unread_ready_groups WHERE group_id_hex = ?1",
            [GROUP],
        )
        .unwrap();
    assert!(matches!(
        store.conversation_account_snapshot(GROUP, Default::default()),
        Err(ConversationOpenError::ReadStateNotReady)
    ));
    assert!(store.lock().unwrap().is_autocommit());
}

#[test]
fn account_capture_keeps_all_fields_on_one_snapshot_while_another_connection_commits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = crate::SqlCipherKey::new("0a".repeat(32)).unwrap();
    let reader = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&reader);
    add(&reader, "a", 1, 1);
    reader
        .save_message_draft(GROUP, "before", None, &[])
        .unwrap();
    let original_draft = reader.selected_message_draft(GROUP).unwrap();
    let original_input = reader.chat_presentation_input(GROUP).unwrap().unwrap();
    let writer = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let during = read_with_concurrent_writer(
        &reader,
        writer,
        |writer| {
            add(&writer, "b", 2, 2);
            writer
                .mark_timeline_message_read(LOCAL, GROUP, "b", &no_mentions)
                .unwrap();
            writer
                .save_message_draft(GROUP, "after", None, &[])
                .unwrap();
            writer.lock().unwrap().execute(
                "UPDATE account_groups SET archived = 1, profile_name = 'new name', admin_keys_hex = 'new admins', pending_confirmation = 1 WHERE group_id_hex = ?1",
                [GROUP],
            ).unwrap();
            writer.close().unwrap();
        },
        || {
            reader
                .conversation_account_snapshot(GROUP, Default::default())
                .unwrap()
        },
    );
    assert_eq!(during.page.page().messages.len(), 1);
    assert_eq!(during.read_state.unread_count, 1);
    assert!(during.read_state.last_read_message_id_hex.is_none());
    assert!(!during.archived && !during.pending_confirmation);
    assert!(during.admin_keys_hex.is_empty());
    assert_eq!(
        during.presentation_input.group_name,
        original_input.group_name
    );
    assert!(during.presentation_input.source_version == original_input.source_version);
    assert_eq!(during.draft.draft.unwrap().content, "before");
    assert!(during.draft.revision == original_draft.revision);

    let after = reader
        .conversation_account_snapshot(GROUP, Default::default())
        .unwrap();
    assert_eq!(after.page.page().messages.len(), 2);
    assert_eq!(after.read_state.unread_count, 0);
    assert_eq!(
        after.read_state.last_read_message_id_hex.as_deref(),
        Some("b")
    );
    assert!(after.archived && after.pending_confirmation);
    assert_eq!(after.admin_keys_hex, "new admins");
    assert_eq!(after.presentation_input.group_name, "new name");
    assert_eq!(after.draft.draft.unwrap().content, "after");
    assert!(after.draft.revision != original_draft.revision);
}

#[test]
fn account_capture_and_selected_input_work_on_a_query_only_connection() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    add(&store, "a", 1, 1);
    store
        .lock()
        .unwrap()
        .execute_batch("PRAGMA query_only = ON")
        .unwrap();
    let changes = store.lock().unwrap().total_changes();
    let snapshot = store
        .conversation_account_snapshot(GROUP, Default::default())
        .unwrap();
    assert_eq!(snapshot.page.page().messages.len(), 1);
    assert!(store.chat_presentation_input(GROUP).unwrap().is_some());
    assert_eq!(store.lock().unwrap().total_changes(), changes);
    assert!(store.lock().unwrap().is_autocommit());
    store.close().unwrap();
    assert!(matches!(
        store.conversation_account_snapshot(GROUP, Default::default()),
        Err(ConversationOpenError::Storage(StorageError::Closed(_)))
    ));
}

#[test]
fn account_capture_tracks_only_its_groups_durable_leave_request() {
    use crate::storage::test_support::sample_group;
    use cgka_traits::{
        GroupId,
        storage::{GroupStorage, LeaveRequest, LeaveRequestStorage},
    };
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    let group = GroupId::new(hex::decode(GROUP).unwrap());
    let other = GroupId::new(vec![0x99; 16]);
    for id in [&group, &other] {
        store.put_group(&sample_group(id.clone(), 1, 2)).unwrap();
    }
    let request = |id| LeaveRequest {
        group_id: id,
        requested_at_ms: 123,
        last_proposed_epoch: None,
    };
    store.put_leave_request(&request(other)).unwrap();
    assert!(
        !store
            .conversation_account_snapshot(GROUP, Default::default())
            .unwrap()
            .leave_request_pending
    );
    store.put_leave_request(&request(group.clone())).unwrap();
    assert!(
        store
            .conversation_account_snapshot(GROUP, Default::default())
            .unwrap()
            .leave_request_pending
    );
    store.clear_leave_request(&group).unwrap();
    assert!(
        !store
            .conversation_account_snapshot(GROUP, Default::default())
            .unwrap()
            .leave_request_pending
    );
}

#[test]
fn latest_targets_keep_the_tail_regardless_of_requested_anchor_placement() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    for i in 1..=6 {
        add(&store, &format!("m{i}"), 1, i);
    }
    for target in [
        ConversationOpenTarget::Latest,
        ConversationOpenTarget::Automatic,
    ] {
        if matches!(target, ConversationOpenTarget::Automatic) {
            store
                .mark_timeline_message_read(LOCAL, GROUP, "m6", &no_mentions)
                .unwrap();
        }
        let snapshot = store
            .conversation_window(
                GROUP,
                ConversationWindowQuery {
                    opening: ConversationOpenQuery { target, limit: 3 },
                    before_anchor: Some(0),
                },
            )
            .unwrap();
        assert_eq!(ids(&snapshot), ["m4", "m5", "m6"]);
        assert_eq!(
            snapshot.anchor,
            ConversationOpenAnchorOutcome::Latest { index: 2 }
        );
        assert!(snapshot.page.has_more_before);
        assert!(!snapshot.page.has_more_after);
    }
}
