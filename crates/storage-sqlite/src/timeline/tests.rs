use super::*;

fn chat(id: &str, sender: &str, at: u64, plaintext: &str) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: "11".repeat(32),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: sender.to_owned(),
        plaintext: plaintext.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
    }
}

fn reaction(id: &str, sender: &str, target: &str, at: u64, emoji: &str) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: "11".repeat(32),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: sender.to_owned(),
        plaintext: emoji.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_REACTION,
        tags: vec![vec![EVENT_REF_TAG.to_owned(), target.to_owned()]],
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
    }
}

fn agent_operation(id: &str, sender: &str, target: &str, at: u64) -> StoredAppEvent {
    StoredAppEvent {
            group_id_hex: "11".repeat(32),
            message_id_hex: id.to_owned(),
            source_message_id_hex: Some(format!("source-{id}")),
            source_epoch: None,
            direction: "received".to_owned(),
            sender: sender.to_owned(),
            plaintext: r#"{"v":1,"event_type":"tool_call","status":"started","name":"search","text":"Searching"}"#
                .to_owned(),
            kind: MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
            tags: vec![vec![EVENT_REF_TAG.to_owned(), target.to_owned()]],
            recorded_at: at,
            received_at: at,
            origin_commit_id: None,
        }
}

fn reply(id: &str, sender: &str, target: &str, at: u64, plaintext: &str) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: "11".repeat(32),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: sender.to_owned(),
        plaintext: plaintext.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: vec![
            vec![EVENT_REF_TAG.to_owned(), target.to_owned()],
            vec![QUOTE_REF_TAG.to_owned(), target.to_owned()],
        ],
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
    }
}

fn delete(id: &str, sender: &str, target: &str, at: u64) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: "11".repeat(32),
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
    }
}

fn edit(id: &str, sender: &str, target: &str, at: u64, plaintext: &str) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: "11".repeat(32),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: sender.to_owned(),
        plaintext: plaintext.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_EDIT,
        tags: vec![vec![EVENT_REF_TAG.to_owned(), target.to_owned()]],
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
    }
}

fn fail_on_timeline_delete(store: &SqliteAccountStorage) {
    // This deliberately trips on any materialized-row delete. Use it only in
    // tests that should upsert existing timeline rows, not remove targeted rows.
    let conn = store.lock().unwrap();
    conn.execute_batch(
        "CREATE TRIGGER panic_message_timeline_delete
         BEFORE DELETE ON message_timeline
         BEGIN
            SELECT RAISE(FAIL, 'unexpected full timeline delete');
         END;",
    )
    .unwrap();
}

fn group_system(id: &str, system_type: &str, at: u64) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: "11".repeat(32),
        message_id_hex: id.to_owned(),
        // Synthesized group system rows carry a null source so several rows
        // from one commit don't collide on the partial unique source index.
        source_message_id_hex: None,
        source_epoch: None,
        direction: "system".to_owned(),
        sender: "alice".to_owned(),
        plaintext: format!(r#"{{"v":1,"system_type":"{system_type}","text":"","data":{{}}}}"#),
        kind: MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        tags: vec![vec!["system".to_owned(), system_type.to_owned()]],
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
    }
}

fn list(store: &SqliteAccountStorage) -> Vec<TimelineMessageRecord> {
    store
        .message_timeline(TimelineMessageQuery {
            group_id_hex: Some("11".repeat(32)),
            ..TimelineMessageQuery::default()
        })
        .unwrap()
        .messages
}

fn group_system_from_commit(
    id: &str,
    system_type: &str,
    at: u64,
    origin_commit_id: &str,
) -> StoredAppEvent {
    let mut event = group_system(id, system_type, at);
    event.origin_commit_id = Some(origin_commit_id.to_owned());
    event
}

#[test]
fn invalidate_by_origin_commit_tombstones_all_rows_from_one_commit() {
    // A single rolled-back commit can have synthesized several kind-1210
    // system rows (e.g. it added two members). Invalidating by origin commit
    // must tombstone every one of them while leaving rows from other commits
    // (and from the winning branch) untouched.
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&group_system_from_commit(
            "losing-added",
            "member_added",
            10,
            "commit-losing",
        ))
        .unwrap();
    store
        .record_app_event(&group_system_from_commit(
            "losing-admin",
            "admin_added",
            11,
            "commit-losing",
        ))
        .unwrap();
    store
        .record_app_event(&group_system_from_commit(
            "winning-added",
            "member_added",
            12,
            "commit-winning",
        ))
        .unwrap();

    let update = store
        .invalidate_app_events_by_origin_commit("commit-losing", "LosingBranch")
        .unwrap()
        .expect("matched rows should produce an update");
    // Both losing-branch rows are reported as changed; the winning row is not.
    let changed_ids: Vec<&str> = update
        .changes
        .iter()
        .map(|change| match change {
            TimelineMessageChange::Upsert { message, .. } => message.message_id_hex.as_str(),
            TimelineMessageChange::Remove { message_id_hex, .. } => message_id_hex.as_str(),
        })
        .collect();
    assert!(changed_ids.contains(&"losing-added"));
    assert!(changed_ids.contains(&"losing-admin"));
    assert!(!changed_ids.contains(&"winning-added"));

    // Rows are kept (tombstoned), not deleted; both losing rows carry the
    // invalidation status while the winning row stays live.
    let rows = list(&store);
    let status = |id: &str| {
        rows.iter()
            .find(|row| row.message_id_hex == id)
            .map(|row| row.invalidation_status.clone())
    };
    assert_eq!(
        status("losing-added"),
        Some(Some("LosingBranch".to_owned()))
    );
    assert_eq!(
        status("losing-admin"),
        Some(Some("LosingBranch".to_owned()))
    );
    assert_eq!(status("winning-added"), Some(None));
}

#[test]
fn invalidate_by_origin_commit_returns_none_when_no_rows_match() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&group_system_from_commit(
            "row",
            "member_added",
            10,
            "commit-a",
        ))
        .unwrap();
    assert!(
        store
            .invalidate_app_events_by_origin_commit("commit-unknown", "LosingBranch")
            .unwrap()
            .is_none()
    );
}

#[test]
fn reupsert_with_none_origin_preserves_existing_commit_link() {
    // A deterministic kind-1210 row can be written first from direct ingest
    // with Some(origin_commit_id) and later re-derived through an
    // unattributed convergence path that passes None. The re-upsert must not
    // clear the stored commit link, otherwise a later fork recovery can no
    // longer find/tombstone the row by origin commit.
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&group_system_from_commit(
            "row",
            "member_added",
            10,
            "commit-losing",
        ))
        .unwrap();
    // Re-upsert the same (group_id, message_id) with no attribution.
    store
        .record_app_event(&group_system("row", "member_added", 10))
        .unwrap();

    // The row must still be discoverable and tombstoned by its origin commit.
    let update = store
        .invalidate_app_events_by_origin_commit("commit-losing", "LosingBranch")
        .unwrap()
        .expect("origin commit link must survive the None re-upsert");
    let changed_ids: Vec<&str> = update
        .changes
        .iter()
        .map(|change| match change {
            TimelineMessageChange::Upsert { message, .. } => message.message_id_hex.as_str(),
            TimelineMessageChange::Remove { message_id_hex, .. } => message_id_hex.as_str(),
        })
        .collect();
    assert!(changed_ids.contains(&"row"));
    let rows = list(&store);
    let status = rows
        .iter()
        .find(|row| row.message_id_hex == "row")
        .map(|row| row.invalidation_status.clone());
    assert_eq!(status, Some(Some("LosingBranch".to_owned())));
}

#[test]
fn pagination_rejects_half_and_double_cursors() {
    let store = SqliteAccountStorage::in_memory().unwrap();

    assert!(
        store
            .message_timeline(TimelineMessageQuery {
                pagination: TimelinePagination {
                    before: Some(1),
                    ..TimelinePagination::default()
                },
                ..TimelineMessageQuery::default()
            })
            .is_err()
    );
    assert!(
        store
            .message_timeline(TimelineMessageQuery {
                pagination: TimelinePagination {
                    before: Some(1),
                    before_message_id: Some("a".to_owned()),
                    after: Some(2),
                    after_message_id: Some("b".to_owned()),
                    ..TimelinePagination::default()
                },
                ..TimelineMessageQuery::default()
            })
            .is_err()
    );
}

#[test]
fn before_inclusive_cursor_keeps_window_rows_over_newer_same_second_rows() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    // Four rows; b/c/d all share second 20. A scrolled-back window ends at
    // ("b", 20); c and d are unseen newer same-second rows.
    store
        .record_app_event(&chat("a", "alice", 10, "a"))
        .unwrap();
    store
        .record_app_event(&chat("b", "alice", 20, "b"))
        .unwrap();
    store
        .record_app_event(&chat("c", "alice", 20, "c"))
        .unwrap();
    store
        .record_app_event(&chat("d", "alice", 20, "d"))
        .unwrap();

    let query = |inclusive: bool| TimelineMessageQuery {
        group_id_hex: Some("11".repeat(32)),
        search: None,
        pagination: TimelinePagination {
            before: Some(20),
            before_message_id: Some("b".to_owned()),
            before_inclusive: inclusive,
            limit: Some(2),
            ..TimelinePagination::default()
        },
    };

    // Inclusive: the tight descending LIMIT must NOT be spent on c/d; the
    // window's own rows [a, b] come back. (Exclusive over-fetch + a later
    // trim would have blanked the window here.)
    let inclusive = store.message_timeline(query(true)).unwrap();
    assert_eq!(ids(&inclusive), ["a", "b"]);
    assert!(inclusive.has_more_after);
    assert!(!inclusive.has_more_before);

    // Exclusive (the normal paginate-backwards bound) returns rows strictly
    // older than ("b", 20) — here just [a].
    let exclusive = store.message_timeline(query(false)).unwrap();
    assert_eq!(ids(&exclusive), ["a"]);
}

fn ids(page: &TimelinePage) -> Vec<&str> {
    page.messages
        .iter()
        .map(|message| message.message_id_hex.as_str())
        .collect()
}

#[test]
fn timeline_orders_tied_timestamps_by_message_id() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("bb", "alice", 5, "second"))
        .unwrap();
    store
        .record_app_event(&chat("aa", "alice", 5, "first"))
        .unwrap();

    let messages = list(&store);

    assert_eq!(
        messages
            .iter()
            .map(|message| message.message_id_hex.as_str())
            .collect::<Vec<_>>(),
        vec!["aa", "bb"]
    );
}

#[test]
fn orphan_reaction_applies_when_target_arrives() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 1, "+"))
        .unwrap();
    store
        .record_app_event(&chat("target", "alice", 2, "hello"))
        .unwrap();

    let message = list(&store).pop().unwrap();

    assert_eq!(
        message.reactions.by_emoji.get("+").cloned(),
        Some(vec!["bob".to_owned()])
    );
}

#[test]
fn reply_preview_is_hydrated_even_when_parent_is_outside_page() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("parent", "alice", 1, "the original"))
        .unwrap();
    store
        .record_app_event(&reply("reply", "bob", "parent", 2, "answer"))
        .unwrap();

    let page = store
        .message_timeline(TimelineMessageQuery {
            group_id_hex: Some("11".repeat(32)),
            pagination: TimelinePagination {
                limit: Some(1),
                ..TimelinePagination::default()
            },
            ..TimelineMessageQuery::default()
        })
        .unwrap();

    assert_eq!(page.messages.len(), 1);
    let message = &page.messages[0];
    assert_eq!(message.message_id_hex, "reply");
    assert_eq!(message.reply_to_message_id_hex.as_deref(), Some("parent"));
    let preview = message.reply_preview.as_ref().expect("reply preview");
    assert_eq!(preview.message_id_hex, "parent");
    assert_eq!(preview.sender, "alice");
    assert_eq!(preview.plaintext, "the original");
    assert!(!preview.deleted);
}

#[test]
fn reply_preview_carries_parent_source_epoch_and_media() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut parent = chat("parent", "alice", 1, "look at this");
    parent.source_epoch = Some(5);
    parent.tags = vec![vec![
        "imeta".to_owned(),
        "v encrypted-media-v1".to_owned(),
        "m image/png".to_owned(),
        "filename diagram.png".to_owned(),
    ]];
    store.record_app_event(&parent).unwrap();
    store
        .record_app_event(&reply("reply", "bob", "parent", 2, "answer"))
        .unwrap();

    let page = store
        .message_timeline(TimelineMessageQuery {
            group_id_hex: Some("11".repeat(32)),
            pagination: TimelinePagination {
                limit: Some(1),
                ..TimelinePagination::default()
            },
            ..TimelineMessageQuery::default()
        })
        .unwrap();

    let preview = page.messages[0]
        .reply_preview
        .as_ref()
        .expect("reply preview");
    assert_eq!(preview.source_epoch, Some(5));
    assert!(preview.media.is_some());
}

#[test]
fn record_app_event_returns_projection_shaped_reply_delta() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("parent", "alice", 1, "the original"))
        .unwrap();

    let update = store
        .record_app_event(&reply("reply", "bob", "parent", 2, "answer"))
        .unwrap();

    assert_eq!(update.group_id_hex, "11".repeat(32));
    assert_eq!(update.messages.len(), 1);
    let message = &update.messages[0];
    assert_eq!(message.message_id_hex, "reply");
    assert_eq!(
        message
            .reply_preview
            .as_ref()
            .map(|preview| preview.message_id_hex.as_str()),
        Some("parent")
    );
}

#[test]
fn chat_event_returns_new_message_change() {
    let store = SqliteAccountStorage::in_memory().unwrap();

    let update = store
        .record_app_event(&chat("message", "alice", 1, "hello"))
        .unwrap();

    assert!(matches!(
        update.changes.as_slice(),
        [TimelineMessageChange::Upsert {
            trigger: TimelineUpdateTrigger::NewMessage,
            message,
        }] if message.message_id_hex == "message"
    ));
}

#[test]
fn recording_new_message_does_not_delete_existing_timeline_rows() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("first", "alice", 1, "hello"))
        .unwrap();
    fail_on_timeline_delete(&store);

    let update = store
        .record_app_event(&chat("second", "alice", 2, "again"))
        .unwrap();

    assert!(matches!(
        update.changes.as_slice(),
        [TimelineMessageChange::Upsert {
            trigger: TimelineUpdateTrigger::NewMessage,
            message,
        }] if message.message_id_hex == "second"
    ));
    assert_eq!(
        list(&store)
            .iter()
            .map(|message| message.message_id_hex.as_str())
            .collect::<Vec<_>>(),
        vec!["first", "second"]
    );
}

#[test]
fn re_recording_message_does_not_delete_existing_timeline_rows() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("message", "alice", 1, "hello"))
        .unwrap();
    fail_on_timeline_delete(&store);

    let update = store
        .record_app_event(&chat("message", "alice", 1, "hello"))
        .unwrap();

    assert!(matches!(
        update.changes.as_slice(),
        [TimelineMessageChange::Upsert {
            trigger: TimelineUpdateTrigger::NewMessage,
            message,
        }] if message.message_id_hex == "message"
    ));
    assert_eq!(list(&store).len(), 1);
}

#[test]
fn reaction_event_reprojects_target_without_full_timeline_rebuild() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&chat("unrelated", "alice", 1, "keep me"))
        .unwrap();
    fail_on_timeline_delete(&store);

    let update = store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();

    assert!(matches!(
        update.changes.as_slice(),
        [TimelineMessageChange::Upsert {
            trigger: TimelineUpdateTrigger::ReactionAdded,
            message,
        }] if message.message_id_hex == "target"
    ));
}

#[test]
fn delete_event_reprojects_target_without_full_timeline_rebuild() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&chat("unrelated", "alice", 1, "keep me"))
        .unwrap();
    fail_on_timeline_delete(&store);

    let update = store
        .record_app_event(&delete("delete-message", "alice", "target", 2))
        .unwrap();

    assert!(matches!(
        update.changes.as_slice(),
        [TimelineMessageChange::Upsert {
            trigger: TimelineUpdateTrigger::MessageDeleted,
            message,
        }] if message.message_id_hex == "target" && message.deleted
    ));
}

#[test]
fn edit_event_reprojects_target_without_full_timeline_rebuild() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&chat("unrelated", "alice", 1, "keep me"))
        .unwrap();
    fail_on_timeline_delete(&store);

    let update = store
        .record_app_event(&edit("edit-1", "alice", "target", 2, "edited"))
        .unwrap();

    let changed_ids = update
        .changes
        .iter()
        .map(|change| match change {
            TimelineMessageChange::Upsert { message, .. } => message.message_id_hex.as_str(),
            TimelineMessageChange::Remove { message_id_hex, .. } => message_id_hex.as_str(),
        })
        .collect::<Vec<_>>();
    assert!(changed_ids.contains(&"edit-1"));
    assert!(changed_ids.contains(&"target"));
}

#[test]
fn re_recording_reaction_does_not_full_rebuild() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();
    fail_on_timeline_delete(&store);

    let update = store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();

    assert!(matches!(
        update.changes.as_slice(),
        [TimelineMessageChange::Upsert {
            trigger: TimelineUpdateTrigger::ReactionAdded,
            message,
        }] if message.message_id_hex == "target"
    ));
    assert_eq!(modifier_edge_count(&store, "reaction-1"), 1);
}

#[test]
fn re_targeting_reaction_reprojects_old_and_new_targets() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("old-target", "alice", 1, "old"))
        .unwrap();
    store
        .record_app_event(&chat("new-target", "alice", 1, "new"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "old-target", 2, "+"))
        .unwrap();
    fail_on_timeline_delete(&store);

    let update = store
        .record_app_event(&reaction("reaction-1", "bob", "new-target", 3, "+"))
        .unwrap();

    let changed_ids = update
        .changes
        .iter()
        .map(|change| match change {
            TimelineMessageChange::Upsert { message, .. } => message.message_id_hex.as_str(),
            TimelineMessageChange::Remove { message_id_hex, .. } => message_id_hex.as_str(),
        })
        .collect::<Vec<_>>();
    assert!(changed_ids.contains(&"old-target"));
    assert!(changed_ids.contains(&"new-target"));

    let changed_triggers = update
        .changes
        .iter()
        .filter_map(|change| match change {
            TimelineMessageChange::Upsert { trigger, message } => {
                Some((message.message_id_hex.as_str(), trigger))
            }
            TimelineMessageChange::Remove { .. } => None,
        })
        .collect::<Vec<_>>();
    assert!(changed_triggers.contains(&("old-target", &TimelineUpdateTrigger::ReactionRemoved)));
    assert!(changed_triggers.contains(&("new-target", &TimelineUpdateTrigger::ReactionAdded)));

    let messages = list(&store);
    let old_target = messages
        .iter()
        .find(|message| message.message_id_hex == "old-target")
        .unwrap();
    assert!(old_target.reactions.user_reactions.is_empty());
    let new_target = messages
        .iter()
        .find(|message| message.message_id_hex == "new-target")
        .unwrap();
    assert_eq!(new_target.reactions.user_reactions.len(), 1);
}

#[test]
fn upserting_modifier_as_non_modifier_clears_stale_edges() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();
    assert_eq!(modifier_edge_count(&store, "reaction-1"), 1);
    fail_on_timeline_delete(&store);

    let update = store
        .record_app_event(&chat("reaction-1", "bob", 3, "not a reaction"))
        .unwrap();

    assert_eq!(modifier_edge_count(&store, "reaction-1"), 0);
    let messages = list(&store);
    let target = messages
        .iter()
        .find(|message| message.message_id_hex == "target")
        .unwrap();
    assert!(target.reactions.user_reactions.is_empty());
    assert!(update.changes.iter().any(|change| {
        matches!(
            change,
            TimelineMessageChange::Upsert {
                trigger: TimelineUpdateTrigger::ReactionRemoved,
                message,
            } if message.message_id_hex == "target"
        )
    }));
}

#[test]
fn agent_operation_event_returns_typed_timeline_change() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("prompt", "alice", 1, "search this"))
        .unwrap();

    let update = store
        .record_app_event(&agent_operation("tool-1", "agent", "prompt", 2))
        .unwrap();

    assert!(matches!(
        update.changes.as_slice(),
        [TimelineMessageChange::Upsert {
            trigger: TimelineUpdateTrigger::AgentOperation,
            message,
        }] if message.message_id_hex == "tool-1"
            && message.kind == MARMOT_APP_EVENT_KIND_AGENT_OPERATION
            && message.reply_to_message_id_hex.as_deref() == Some("prompt")
    ));
}

#[test]
fn reaction_event_returns_reaction_added_change_for_target() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();

    let update = store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();

    assert!(matches!(
        update.changes.as_slice(),
        [TimelineMessageChange::Upsert {
            trigger: TimelineUpdateTrigger::ReactionAdded,
            message,
        }] if message.message_id_hex == "target"
    ));
}

#[test]
fn deleting_reaction_returns_reaction_removed_change_for_target() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();

    let update = store
        .record_app_event(&delete("delete-reaction", "bob", "reaction-1", 3))
        .unwrap();

    assert!(update.changes.iter().any(|change| {
        matches!(
            change,
            TimelineMessageChange::Upsert {
                trigger: TimelineUpdateTrigger::ReactionRemoved,
                message,
            } if message.message_id_hex == "target"
        )
    }));
}

#[test]
fn deleting_message_returns_message_deleted_change_for_target() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();

    let update = store
        .record_app_event(&delete("delete-message", "alice", "target", 2))
        .unwrap();

    assert!(matches!(
        update.changes.as_slice(),
        [TimelineMessageChange::Upsert {
            trigger: TimelineUpdateTrigger::MessageDeleted,
            message,
        }] if message.message_id_hex == "target" && message.deleted
    ));
}

#[test]
fn parent_arrival_updates_existing_reply_preview_delta() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&reply("reply", "bob", "parent", 1, "answer"))
        .unwrap();

    let update = store
        .record_app_event(&chat("parent", "alice", 2, "the original"))
        .unwrap();

    let reply_change = update
        .changes
        .iter()
        .find_map(|change| match change {
            TimelineMessageChange::Upsert { trigger, message }
                if message.message_id_hex == "reply" =>
            {
                Some((trigger, message))
            }
            _ => None,
        })
        .expect("reply preview change");
    assert_eq!(reply_change.0, &TimelineUpdateTrigger::ReplyPreviewChanged);
    assert_eq!(
        reply_change
            .1
            .reply_preview
            .as_ref()
            .map(|preview| preview.message_id_hex.as_str()),
        Some("parent")
    );
}

#[test]
fn delete_requires_target_author_and_keeps_tombstone() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&delete("bad-delete", "mallory", "target", 1))
        .unwrap();
    store
        .record_app_event(&delete("good-delete", "alice", "target", 2))
        .unwrap();
    store
        .record_app_event(&chat("target", "alice", 3, "secret"))
        .unwrap();

    let message = list(&store).pop().unwrap();

    assert!(message.deleted);
    assert_eq!(
        message.deleted_by_message_id_hex.as_deref(),
        Some("good-delete")
    );
    assert_eq!(message.plaintext, "");
}

#[test]
fn delete_retracts_reaction_by_reaction_author() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();
    store
        .record_app_event(&delete("delete-reaction", "bob", "reaction-1", 3))
        .unwrap();

    let message = list(&store).pop().unwrap();

    assert!(message.reactions.user_reactions.is_empty());
    assert!(message.reactions.by_emoji.is_empty());
}

#[test]
fn stream_start_and_final_are_materialized_as_linked_timeline_records() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let start = StoredAppEvent {
        group_id_hex: "11".repeat(32),
        message_id_hex: "start".to_owned(),
        source_message_id_hex: Some("source-start".to_owned()),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: "agent".to_owned(),
        plaintext: String::new(),
        kind: MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
        tags: vec![vec![STREAM_TAG.to_owned(), "aa".repeat(32)]],
        recorded_at: 1,
        received_at: 1,
        origin_commit_id: None,
    };
    let final_event = StoredAppEvent {
        group_id_hex: "11".repeat(32),
        message_id_hex: "final".to_owned(),
        source_message_id_hex: Some("source-final".to_owned()),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: "agent".to_owned(),
        plaintext: "done".to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: vec![
            vec![STREAM_TAG.to_owned(), "aa".repeat(32)],
            vec![STREAM_START_TAG.to_owned(), "start".to_owned()],
        ],
        recorded_at: 2,
        received_at: 2,
        origin_commit_id: None,
    };

    store.record_app_event(&start).unwrap();
    store.record_app_event(&final_event).unwrap();

    let messages = list(&store);
    assert_eq!(messages.len(), 2);

    let start = &messages[0];
    assert_eq!(start.message_id_hex, "start");
    assert_eq!(start.kind, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START);
    assert_eq!(
        start
            .agent_text_stream
            .as_ref()
            .and_then(|value| value.get("stream_id_hex"))
            .and_then(Value::as_str),
        Some("aa".repeat(32).as_str())
    );
    assert_eq!(
        start
            .agent_text_stream
            .as_ref()
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str),
        Some("started")
    );

    let final_message = &messages[1];
    assert_eq!(final_message.message_id_hex, "final");
    assert_eq!(
        final_message
            .agent_text_stream
            .as_ref()
            .and_then(|value| value.get("start_event_id"))
            .and_then(Value::as_str),
        Some("start")
    );
    assert_eq!(
        final_message
            .agent_text_stream
            .as_ref()
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str),
        Some("finalized")
    );
}

#[test]
fn timeline_search_matches_plaintext_case_insensitively() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "Hello There"))
        .unwrap();

    let page = store
        .message_timeline(TimelineMessageQuery {
            group_id_hex: Some("11".repeat(32)),
            search: Some("hello".to_owned()),
            ..TimelineMessageQuery::default()
        })
        .unwrap();

    assert_eq!(page.messages.len(), 1);
    assert_eq!(page.messages[0].message_id_hex, "target");
}

#[test]
fn sender_own_invalidated_message_stays_as_tombstone() {
    // Issue #111: a sender's own message invalidated by convergence (losing
    // branch) must not silently disappear; it stays with a status instead.
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut own = chat("target", "alice", 1, "my message");
    own.direction = "sent".to_owned();
    store.record_app_event(&own).unwrap();

    let update = store
        .invalidate_app_event_by_source("source-target", "LosingBranch")
        .unwrap()
        .expect("projection update");

    assert!(
        update.changes.iter().any(|change| matches!(
            change,
            TimelineMessageChange::Upsert { message, .. }
                if message.message_id_hex == "target"
                    && message.invalidation_status.as_deref() == Some("LosingBranch")
        )),
        "invalidation should upsert a tombstone, not remove the row"
    );
    assert!(
        !update
            .changes
            .iter()
            .any(|change| matches!(change, TimelineMessageChange::Remove { .. })),
        "the sender's own message must not be removed"
    );

    let rows = list(&store);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message_id_hex, "target");
    assert_eq!(rows[0].direction, "sent");
    assert_eq!(rows[0].invalidation_status.as_deref(), Some("LosingBranch"));
    assert_eq!(rows[0].plaintext, "my message", "content is preserved");
}

#[test]
fn source_invalidation_keeps_received_message_as_tombstone() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();

    let update = store
        .invalidate_app_event_by_source("source-target", "BeyondAnchor")
        .unwrap()
        .expect("projection update");

    assert!(update.changes.iter().any(|change| matches!(
        change,
        TimelineMessageChange::Upsert { message, .. }
            if message.message_id_hex == "target"
                && message.invalidation_status.as_deref() == Some("BeyondAnchor")
    )));
    let rows = list(&store);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].invalidation_status.as_deref(), Some("BeyondAnchor"));
}

#[test]
fn multiple_group_system_rows_from_one_commit_coexist() {
    // A single commit can synthesize several kind-1210 rows (e.g. inviting
    // two members). They carry a null source, so they all persist instead of
    // colliding on the partial unique `source_message_id_hex` index.
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&group_system("sys-added-1", "member_added", 1))
        .unwrap();
    store
        .record_app_event(&group_system("sys-added-2", "member_added", 1))
        .unwrap();
    store
        .record_app_event(&group_system("sys-admin", "admin_added", 1))
        .unwrap();

    let rows = list(&store);
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter()
            .all(|row| row.kind == MARMOT_APP_EVENT_KIND_GROUP_SYSTEM)
    );
}

#[test]
fn message_id_invalidation_keeps_message_as_tombstone() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();

    let update = store
        .invalidate_app_event_by_message_id(
            &"11".repeat(32),
            "target",
            "UndecryptableInCanonicalState",
        )
        .unwrap()
        .expect("projection update");

    assert!(update.changes.iter().any(|change| matches!(
        change,
        TimelineMessageChange::Upsert { message, .. }
            if message.message_id_hex == "target"
                && message.invalidation_status.as_deref()
                    == Some("UndecryptableInCanonicalState")
    )));
    let rows = list(&store);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].invalidation_status.as_deref(),
        Some("UndecryptableInCanonicalState")
    );
}

#[test]
fn message_id_invalidation_is_group_scoped() {
    // Inner app-event ids are NIP-01 hashes with no group binding, so the same
    // account sending identical content to two groups in the same second
    // produces the same message_id_hex in both. Invalidating one group's copy
    // (e.g. reason "local_publish_failed" when one fan-out leg fails) must NOT
    // touch the other group's delivered copy. Regression for darkmatter#156.
    let store = SqliteAccountStorage::in_memory().unwrap();
    let group_a = "11".repeat(32);
    let group_b = "22".repeat(32);

    // Same message_id_hex ("dup") in both groups; the table's
    // UNIQUE(group_id_hex, message_id_hex) lets both rows coexist. Distinct
    // source ids keep the partial unique source index satisfied.
    let mut event_a = chat("dup", "alice", 1, "hello");
    event_a.group_id_hex = group_a.clone();
    event_a.source_message_id_hex = Some("source-a".to_owned());
    let mut event_b = chat("dup", "alice", 1, "hello");
    event_b.group_id_hex = group_b.clone();
    event_b.source_message_id_hex = Some("source-b".to_owned());
    store.record_app_event(&event_a).unwrap();
    store.record_app_event(&event_b).unwrap();

    // Invalidate only group A's copy.
    let update = store
        .invalidate_app_event_by_message_id(&group_a, "dup", "local_publish_failed")
        .unwrap()
        .expect("projection update");
    // The returned update must be for group A.
    assert_eq!(update.group_id_hex, group_a);

    let rows_a = store
        .message_timeline(TimelineMessageQuery {
            group_id_hex: Some(group_a.clone()),
            ..TimelineMessageQuery::default()
        })
        .unwrap()
        .messages;
    assert_eq!(rows_a.len(), 1);
    assert_eq!(
        rows_a[0].invalidation_status.as_deref(),
        Some("local_publish_failed"),
        "group A's copy should be invalidated"
    );

    // Group B's copy must remain untouched (delivered, not a tombstone).
    let rows_b = store
        .message_timeline(TimelineMessageQuery {
            group_id_hex: Some(group_b.clone()),
            ..TimelineMessageQuery::default()
        })
        .unwrap()
        .messages;
    assert_eq!(rows_b.len(), 1);
    assert_eq!(
        rows_b[0].invalidation_status, None,
        "group B's copy must NOT be invalidated by group A's failure"
    );
}

#[test]
fn parent_invalidation_keeps_parent_as_tombstone_and_reply_preview() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("parent", "alice", 1, "the original"))
        .unwrap();
    store
        .record_app_event(&reply("reply", "bob", "parent", 2, "answer"))
        .unwrap();

    let update = store
        .invalidate_app_event_by_source("source-parent", "LosingBranch")
        .unwrap()
        .expect("projection update");

    // The parent is kept as a tombstone (content preserved), not removed.
    assert!(update.changes.iter().any(|change| matches!(
        change,
        TimelineMessageChange::Upsert { message, .. }
            if message.message_id_hex == "parent"
                && message.invalidation_status.as_deref() == Some("LosingBranch")
    )));
    assert!(
        !update
            .changes
            .iter()
            .any(|change| matches!(change, TimelineMessageChange::Remove { .. }))
    );

    let rows = list(&store);
    let parent = rows
        .iter()
        .find(|m| m.message_id_hex == "parent")
        .expect("parent kept as tombstone");
    assert_eq!(parent.invalidation_status.as_deref(), Some("LosingBranch"));
    assert_eq!(parent.plaintext, "the original");
    // The reply still resolves its preview against the retained parent.
    let reply = rows
        .iter()
        .find(|m| m.message_id_hex == "reply")
        .expect("reply kept");
    assert!(reply.reply_preview.is_some());
}

#[test]
fn reaction_source_invalidation_returns_changed_target_projection() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();

    let update = store
        .invalidate_app_event_by_source("source-reaction-1", "losing_branch")
        .unwrap()
        .expect("projection update");

    assert_eq!(update.messages.len(), 1);
    assert_eq!(update.messages[0].message_id_hex, "target");
    assert!(update.changes.iter().any(|change| {
        matches!(
            change,
            TimelineMessageChange::Upsert {
                trigger: TimelineUpdateTrigger::ReactionRemoved,
                message,
            } if message.message_id_hex == "target"
        )
    }));
    assert!(
        update.messages[0]
            .reactions
            .by_emoji
            .get("+")
            .is_none_or(Vec::is_empty)
    );
    assert!(update.messages[0].reactions.user_reactions.is_empty());
}

#[test]
fn orphan_reaction_invalidation_does_not_remove_missing_target() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 1, "+"))
        .unwrap();

    let update = store
        .invalidate_app_event_by_source("source-reaction-1", "losing_branch")
        .unwrap()
        .expect("projection update");

    assert!(update.messages.is_empty());
    assert!(update.changes.is_empty());
}

#[test]
fn no_op_delete_invalidation_does_not_emit_unchanged_target() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&delete("delete-1", "bob", "target", 2))
        .unwrap();

    let update = store
        .invalidate_app_event_by_source("source-delete-1", "losing_branch")
        .unwrap()
        .expect("projection update");

    assert!(update.changes.is_empty());
}

#[test]
fn timeline_message_target_resolves_single_row_and_reflects_state() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();

    // A present, delivered row returns its sender/plaintext/kind and is neither
    // deleted nor invalidated.
    let found = store
        .timeline_message_target(&"11".repeat(32), "target")
        .unwrap()
        .expect("target row");
    assert_eq!(found.sender, "alice");
    assert_eq!(found.plaintext, "hello");
    assert_eq!(found.kind, MARMOT_APP_EVENT_KIND_CHAT);
    assert!(!found.deleted);
    assert!(!found.invalidated);

    // Absent id in the same group → None.
    assert!(
        store
            .timeline_message_target(&"11".repeat(32), "missing")
            .unwrap()
            .is_none()
    );

    // Scoped to the group: the same id in another group is not visible.
    assert!(
        store
            .timeline_message_target(&"22".repeat(32), "target")
            .unwrap()
            .is_none()
    );
}

#[test]
fn timeline_message_target_reflects_deleted_row() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "secret body"))
        .unwrap();
    // The author deletes their own message; the timeline row is kept but marked
    // deleted with its plaintext cleared.
    store
        .record_app_event(&delete("delete-1", "alice", "target", 2))
        .unwrap();

    let found = store
        .timeline_message_target(&"11".repeat(32), "target")
        .unwrap()
        .expect("deleted target row still present");
    assert!(found.deleted);
    assert!(!found.invalidated);
    // The materialized row clears plaintext on delete; nothing to leak.
    assert_eq!(found.plaintext, "");
}

#[test]
fn timeline_message_target_reflects_invalidated_row() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .invalidate_app_event_by_source("source-target", "LosingBranch")
        .unwrap()
        .expect("projection update");

    let found = store
        .timeline_message_target(&"11".repeat(32), "target")
        .unwrap()
        .expect("invalidated target row still present");
    assert!(found.invalidated);
    assert!(!found.deleted);
}

fn modifier_edge_count(store: &SqliteAccountStorage, modifier_message_id_hex: &str) -> i64 {
    let conn = store.lock().unwrap();
    conn.query_row(
        "SELECT COUNT(*) FROM message_modifier_edges
         WHERE group_id_hex = ?1 AND modifier_message_id_hex = ?2",
        params![&"11".repeat(32), modifier_message_id_hex],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn reaction_appears_in_summary_via_indexed_edge() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();

    let message = list(&store).pop().unwrap();

    assert_eq!(message.reactions.user_reactions.len(), 1);
    assert_eq!(
        message.reactions.user_reactions[0].reaction_message_id_hex,
        "reaction-1"
    );
    assert_eq!(message.reactions.user_reactions[0].emoji, "+");
    assert_eq!(
        message.reactions.by_emoji.get("+").map(Vec::as_slice),
        Some(["bob".to_owned()].as_slice())
    );
}

#[test]
fn reaction_deleted_by_its_sender_is_excluded_but_other_sender_does_not_retract() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();

    // A delete from a DIFFERENT sender than the reaction author must not retract
    // the reaction.
    store
        .record_app_event(&delete("mallory-retract", "mallory", "reaction-1", 3))
        .unwrap();
    let message = list(&store).pop().unwrap();
    assert_eq!(
        message.reactions.user_reactions.len(),
        1,
        "a delete by a different sender must not retract the reaction"
    );

    // The reaction author's own delete retracts it.
    store
        .record_app_event(&delete("bob-retract", "bob", "reaction-1", 4))
        .unwrap();
    let message = list(&store).pop().unwrap();
    assert!(
        message.reactions.user_reactions.is_empty(),
        "a delete by the reaction author retracts the reaction"
    );
    assert!(message.reactions.by_emoji.is_empty());
}

#[test]
fn message_delete_by_sender_clears_content_and_reactions_but_other_sender_does_not() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "secret"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();

    // A delete from someone other than the message author leaves it intact.
    store
        .record_app_event(&delete("mallory-delete", "mallory", "target", 3))
        .unwrap();
    let message = list(&store).pop().unwrap();
    assert!(!message.deleted);
    assert_eq!(message.plaintext, "secret");
    assert_eq!(message.reactions.user_reactions.len(), 1);

    // The message author's own delete clears content and reactions.
    store
        .record_app_event(&delete("alice-delete", "alice", "target", 4))
        .unwrap();
    let message = list(&store).pop().unwrap();
    assert!(message.deleted);
    assert_eq!(
        message.deleted_by_message_id_hex.as_deref(),
        Some("alice-delete")
    );
    assert_eq!(message.plaintext, "");
    assert!(message.reactions.user_reactions.is_empty());
    assert!(message.reactions.by_emoji.is_empty());
}

#[test]
fn re_recording_reaction_does_not_duplicate_edges_or_reaction() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();
    // Re-record the identical reaction (upsert on the same modifier id).
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();

    assert_eq!(
        modifier_edge_count(&store, "reaction-1"),
        1,
        "re-recording a reaction must not duplicate its modifier edge"
    );
    let message = list(&store).pop().unwrap();
    assert_eq!(
        message.reactions.user_reactions.len(),
        1,
        "the reaction must appear exactly once after an upsert"
    );
}

#[test]
fn pruning_modifier_event_cascades_its_edges() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 100, "hello"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-old", "bob", "target", 10, "+"))
        .unwrap();
    assert_eq!(modifier_edge_count(&store, "reaction-old"), 1);

    store.prune_app_events_before(&"11".repeat(32), 50).unwrap();

    assert_eq!(
        modifier_edge_count(&store, "reaction-old"),
        0,
        "pruning the modifier app_event must cascade-delete its modifier edges"
    );
}

#[test]
fn many_reactions_retract_across_bind_parameter_chunk_boundary() {
    // Exercises the chunked deleted-reaction lookup: a single hot message with
    // more reactions than SQLITE_BIND_PARAMETER_CHUNK forces the retract query
    // to span multiple chunks. Every reaction author then deletes their own
    // reaction, so the full set must be retracted regardless of which chunk a
    // given reaction id lands in.
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();

    let count = SQLITE_BIND_PARAMETER_CHUNK + 50;
    for i in 0..count {
        let sender = format!("sender-{i}");
        let reaction_id = format!("reaction-{i}");
        store
            .record_app_event(&reaction(&reaction_id, &sender, "target", 2, "+"))
            .unwrap();
    }

    let message = list(&store).pop().unwrap();
    assert_eq!(
        message.reactions.user_reactions.len(),
        count,
        "every recorded reaction must appear before any retraction"
    );

    // Each reaction author retracts their own reaction. The final projection
    // re-derives over all reaction ids, which crosses the chunk boundary.
    for i in 0..count {
        let sender = format!("sender-{i}");
        let delete_id = format!("delete-{i}");
        let target_reaction = format!("reaction-{i}");
        store
            .record_app_event(&delete(&delete_id, &sender, &target_reaction, 3))
            .unwrap();
    }

    let message = list(&store).pop().unwrap();
    assert!(
        message.reactions.user_reactions.is_empty(),
        "all reactions must retract even when the lookup spans multiple bind-parameter chunks"
    );
    assert!(message.reactions.by_emoji.is_empty());
}
