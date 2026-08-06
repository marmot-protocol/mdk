use super::*;

fn no_mentions(_plaintext: &str, _tags: &[Vec<String>]) -> bool {
    false
}

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
        moderation_grant: false,
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
        moderation_grant: false,
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
        moderation_grant: false,
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
        moderation_grant: false,
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
        moderation_grant: false,
    }
}

fn moderated_delete(id: &str, sender: &str, target: &str, at: u64) -> StoredAppEvent {
    let mut event = delete(id, sender, target, at);
    event.moderation_grant = true;
    event
}

#[test]
fn oversized_timeline_id_sets_are_chunked() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let ids = (0..=SQLITE_BIND_PARAMETER_CHUNK)
        .map(|index| format!("message-{index:04}"))
        .collect::<Vec<_>>();
    store
        .record_app_event(&chat(&ids[0], "alice", 20, "first chunk"))
        .unwrap();
    store
        .record_app_event(&chat(
            &ids[SQLITE_BIND_PARAMETER_CHUNK],
            "alice",
            10,
            "second chunk",
        ))
        .unwrap();
    store
        .record_app_event(&reply(
            "reply",
            "bob",
            &ids[SQLITE_BIND_PARAMETER_CHUNK],
            30,
            "answer",
        ))
        .unwrap();

    let conn = store.lock().unwrap();
    assert_eq!(
        reply_message_ids_for_targets_tx(&conn, &"11".repeat(32), &ids).unwrap(),
        BTreeSet::from(["reply".to_owned()])
    );
    let records =
        timeline_records_by_ids_tx(&conn, &"11".repeat(32), ids.iter().cloned().collect()).unwrap();
    assert_eq!(
        records
            .iter()
            .map(|record| record.message_id_hex.as_str())
            .collect::<Vec<_>>(),
        vec![ids[SQLITE_BIND_PARAMETER_CHUNK].as_str(), ids[0].as_str()]
    );
}

#[test]
fn oversized_reply_preview_target_sets_are_chunked() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let group_id = "11".repeat(32);
    let ids = (0..=SQLITE_BIND_PARAMETER_CHUNK)
        .map(|index| format!("preview-{index:04}"))
        .collect::<Vec<_>>();
    store
        .record_app_event(&chat(&ids[0], "alice", 10, "first"))
        .unwrap();
    store
        .record_app_event(&chat(
            &ids[SQLITE_BIND_PARAMETER_CHUNK],
            "alice",
            20,
            "last",
        ))
        .unwrap();
    let targets = ids
        .into_iter()
        .map(|message_id| (group_id.clone(), message_id))
        .collect();

    let previews = load_reply_previews(&store.lock().unwrap(), targets).unwrap();
    assert_eq!(previews.len(), 2);
}

#[test]
fn timeline_rebuild_tolerates_one_corrupt_source_tag_blob() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let group_id = "11".repeat(32);
    store
        .record_app_event(&chat("corrupt", "alice", 10, "first"))
        .unwrap();
    store
        .record_app_event(&chat("healthy", "bob", 20, "second"))
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE app_events SET tags_json = 'not-json'
             WHERE group_id_hex = ?1 AND message_id_hex = 'corrupt'",
            params![&group_id],
        )
        .unwrap();

    store
        .rebuild_message_timeline_for_group(&group_id)
        .expect("a malformed tag blob must not poison the group rebuild");
    let page = store
        .message_timeline(TimelineMessageQuery {
            group_id_hex: Some(group_id),
            ..TimelineMessageQuery::default()
        })
        .unwrap();
    assert_eq!(page.messages.len(), 2);
    assert!(
        page.messages
            .iter()
            .find(|message| message.message_id_hex == "corrupt")
            .unwrap()
            .tags
            .is_empty()
    );
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
        moderation_grant: false,
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
        moderation_grant: false,
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

#[test]
fn timeline_reads_preserve_every_pinned_retention_state() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let group_id = "11".repeat(32);

    let mut finite = chat("finite", "alice", 10, "expires");
    finite.source_epoch = Some(4);
    let finite_update = store
        .record_app_event_with_retention(
            &finite,
            Some(AppMessageRetentionDecision::new(finite.recorded_at, 300)),
        )
        .unwrap();
    assert_eq!(finite_update.messages[0].source_epoch, Some(4));
    assert_eq!(finite_update.messages[0].retention_seconds, Some(300));
    assert_eq!(finite_update.messages[0].retention_expires_at, Some(310));

    let disabled = chat("disabled", "alice", 20, "kept");
    store
        .record_app_event_with_retention(
            &disabled,
            Some(AppMessageRetentionDecision::new(disabled.recorded_at, 0)),
        )
        .unwrap();
    store
        .record_app_event(&chat("legacy", "alice", 30, "safe retain"))
        .unwrap();
    let overflow = chat("overflow", "alice", 40, "no finite expiry");
    store
        .record_app_event_with_retention(
            &overflow,
            Some(AppMessageRetentionDecision::new(u64::MAX, 1)),
        )
        .unwrap();

    let queried = store
        .message_timeline(TimelineMessageQuery {
            group_id_hex: Some(group_id.clone()),
            pagination: TimelinePagination {
                limit: Some(10),
                ..TimelinePagination::default()
            },
            ..TimelineMessageQuery::default()
        })
        .unwrap()
        .messages;
    let ids = queried
        .iter()
        .map(|record| record.message_id_hex.clone())
        .collect::<BTreeSet<_>>();
    let by_id = timeline_records_by_ids_tx(&store.lock().unwrap(), &group_id, ids).unwrap();

    let retention_by_id = |records: &[TimelineMessageRecord]| {
        records
            .iter()
            .map(|record| {
                (
                    record.message_id_hex.clone(),
                    (record.retention_seconds, record.retention_expires_at),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let expected = BTreeMap::from([
        ("disabled".to_owned(), (Some(0), None)),
        ("finite".to_owned(), (Some(300), Some(310))),
        ("legacy".to_owned(), (None, None)),
        ("overflow".to_owned(), (Some(1), None)),
    ]);
    assert_eq!(retention_by_id(&queried), expected);
    assert_eq!(retention_by_id(&by_id), expected);

    store.rebuild_message_timeline_for_group(&group_id).unwrap();
    assert_eq!(retention_by_id(&list(&store)), expected);
}

#[test]
fn incremental_retention_finalization_is_visible_without_stale_projection_data() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let group_id = "11".repeat(32);
    let optimistic = chat("optimistic", "alice", 50, "pending");

    let initial = store.record_app_event(&optimistic).unwrap();
    assert_eq!(initial.messages[0].source_epoch, None);
    assert_eq!(initial.messages[0].retention_seconds, None);
    assert_eq!(initial.messages[0].retention_expires_at, None);

    let finalized = store
        .finalize_app_event_source_retention(
            &group_id,
            "optimistic",
            Some("source-optimistic"),
            9,
            AppMessageRetentionDecision::new(50, 300),
        )
        .unwrap()
        .expect("retention finalization update");
    assert_eq!(finalized.messages[0].source_epoch, Some(9));
    assert_eq!(finalized.messages[0].retention_seconds, Some(300));
    assert_eq!(finalized.messages[0].retention_expires_at, Some(350));

    let mut reprojected = optimistic;
    reprojected.plaintext = "updated projection".to_owned();
    reprojected.source_message_id_hex = Some("later-duplicate-source".to_owned());
    let update = store.record_app_event(&reprojected).unwrap();
    assert_eq!(update.messages[0].source_epoch, Some(9));
    assert_eq!(update.messages[0].retention_seconds, Some(300));
    assert_eq!(update.messages[0].retention_expires_at, Some(350));

    let page = list(&store);
    assert_eq!(page[0].source_epoch, Some(9));
    assert_eq!(
        page[0].source_message_id_hex.as_deref(),
        Some("source-optimistic"),
        "reprojection must retain the first durable transport source id",
    );
    assert_eq!(page[0].retention_seconds, Some(300));
    assert_eq!(page[0].retention_expires_at, Some(350));
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
fn invalidate_by_origin_commit_is_a_noop_for_already_invalidated_rows() {
    // The engine can name the same superseded commit more than once (e.g. a
    // replayed withdrawal event). The second invalidation must be a no-op: it
    // returns no projection update and does not overwrite the recorded reason.
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&group_system_from_commit(
            "losing-added",
            "member_added",
            10,
            "commit-losing",
        ))
        .unwrap();

    assert!(
        store
            .invalidate_app_events_by_origin_commit("commit-losing", "SupersededByBranchSelection",)
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .invalidate_app_events_by_origin_commit("commit-losing", "LosingBranch")
            .unwrap()
            .is_none(),
        "re-invalidating the same commit must be a no-op"
    );
    let rows = list(&store);
    let status = rows
        .iter()
        .find(|row| row.message_id_hex == "losing-added")
        .map(|row| row.invalidation_status.clone());
    assert_eq!(
        status,
        Some(Some("SupersededByBranchSelection".to_owned())),
        "the first recorded reason must survive a duplicate withdrawal"
    );
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
fn group_timeline_order_is_stable_across_delayed_system_projection() {
    fn history(system_observed_at: [u64; 3]) -> SqliteAccountStorage {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mut system_seven = group_system("system-7a", "member_added", system_observed_at[0]);
        system_seven.source_epoch = Some(7);
        store.record_app_event(&system_seven).unwrap();
        let mut system_seven_second =
            group_system("system-7b", "group_name_changed", system_observed_at[1]);
        system_seven_second.source_epoch = Some(7);
        store.record_app_event(&system_seven_second).unwrap();

        let mut message_seven = chat("message-7", "alice", 200, "epoch seven");
        message_seven.source_epoch = Some(7);
        store.record_app_event(&message_seven).unwrap();

        let mut system_eight = group_system("system-8", "member_removed", system_observed_at[2]);
        system_eight.source_epoch = Some(8);
        store.record_app_event(&system_eight).unwrap();

        // The authenticated app timestamp may move backwards across senders or
        // devices. Epoch boundaries, not wall-clock coincidence, establish the
        // durable relative order.
        let mut message_eight = chat("message-8", "bob", 150, "epoch eight");
        message_eight.source_epoch = Some(8);
        store.record_app_event(&message_eight).unwrap();
        store
    }

    let online = history([100, 101, 300]);
    // Catch-up observes the same epoch-seven system rows in the opposite local
    // timestamp order. Their deterministic ids still decide their order.
    let delayed = history([901, 900, 902]);
    let ids = |store: &SqliteAccountStorage| {
        list(store)
            .into_iter()
            .map(|message| message.message_id_hex)
            .collect::<Vec<_>>()
    };
    let expected = vec![
        "system-7a",
        "system-7b",
        "message-7",
        "system-8",
        "message-8",
    ];

    assert_eq!(ids(&online), expected);
    assert_eq!(ids(&delayed), expected);
}

#[test]
fn virtual_order_columns_match_the_rust_canonical_key() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut legacy = chat("legacy", "alice", 400, "legacy");
    legacy.source_epoch = None;
    store.record_app_event(&legacy).unwrap();

    let mut pending = chat("pending", "local", 500, "pending");
    pending.source_message_id_hex = None;
    pending.source_epoch = None;
    pending.direction = "sent".to_owned();
    store.record_app_event(&pending).unwrap();

    let mut system = group_system("system", "member_added", 900);
    system.source_epoch = Some(7);
    store.record_app_event(&system).unwrap();

    let mut authenticated = chat("authenticated", "bob", 300, "authenticated");
    authenticated.source_epoch = Some(7);
    store.record_app_event(&authenticated).unwrap();

    let expected = [&legacy, &pending, &system, &authenticated]
        .into_iter()
        .map(|event| {
            let key = canonical_timeline_order_key(
                event.source_message_id_hex.as_deref(),
                event.source_epoch,
                None,
                event.kind,
                event.recorded_at,
                &event.message_id_hex,
            );
            (
                event.message_id_hex.clone(),
                i64::from(key.0),
                i64::try_from(key.1).unwrap(),
                i64::from(key.2),
                i64::try_from(key.3).unwrap(),
            )
        })
        .collect::<Vec<_>>();

    let conn = store.lock().unwrap();
    let actual = conn
        .prepare(
            "SELECT message_id_hex, timeline_order_class, timeline_order_primary,
                    timeline_order_phase, timeline_order_at
             FROM message_timeline
             ORDER BY message_id_hex",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut expected = expected;
    expected.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(actual, expected);

    conn.execute(
        "UPDATE message_timeline
         SET invalidation_status = 'local_publish_failed'
         WHERE message_id_hex = 'pending'",
        [],
    )
    .unwrap();
    let failed_class: i64 = conn
        .query_row(
            "SELECT timeline_order_class FROM message_timeline
             WHERE message_id_hex = 'pending'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(failed_class, 2);
    drop(conn);

    let head = store
        .message_timeline(TimelineMessageQuery {
            group_id_hex: Some("11".repeat(32)),
            pagination: TimelinePagination {
                limit: Some(2),
                ..TimelinePagination::default()
            },
            ..TimelineMessageQuery::default()
        })
        .unwrap();
    assert_eq!(head.messages.last().unwrap().message_id_hex, "pending");
    assert_eq!(
        head.messages.last().unwrap().invalidation_status.as_deref(),
        Some("local_publish_failed")
    );
}

#[test]
fn authenticated_kind_1210_message_does_not_establish_an_epoch_boundary() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut chat = chat("chat", "alice", 100, "before explicit system message");
    chat.source_epoch = Some(7);
    store.record_app_event(&chat).unwrap();
    let mut explicit_system = group_system("explicit-system", "custom", 200);
    explicit_system.source_message_id_hex = Some("source-explicit-system".to_owned());
    explicit_system.source_epoch = Some(7);
    explicit_system.direction = "received".to_owned();
    store.record_app_event(&explicit_system).unwrap();

    assert_eq!(
        list(&store)
            .into_iter()
            .map(|message| message.message_id_hex)
            .collect::<Vec<_>>(),
        ["chat", "explicit-system"]
    );
}

#[test]
fn group_timeline_pagination_uses_canonical_epoch_cursor() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut system_seven = group_system("system-7", "member_added", 100);
    system_seven.source_epoch = Some(7);
    store.record_app_event(&system_seven).unwrap();
    let mut message_seven = chat("message-7", "alice", 200, "epoch seven");
    message_seven.source_epoch = Some(7);
    store.record_app_event(&message_seven).unwrap();
    let mut system_eight = group_system("system-8", "member_removed", 300);
    system_eight.source_epoch = Some(8);
    store.record_app_event(&system_eight).unwrap();
    let mut message_eight = chat("message-8", "bob", 150, "epoch eight");
    message_eight.source_epoch = Some(8);
    store.record_app_event(&message_eight).unwrap();

    let page = |pagination| {
        store
            .message_timeline(TimelineMessageQuery {
                group_id_hex: Some("11".repeat(32)),
                pagination,
                ..TimelineMessageQuery::default()
            })
            .unwrap()
    };
    let older = page(TimelinePagination {
        before: Some(300),
        before_message_id: Some("system-8".to_owned()),
        limit: Some(2),
        ..TimelinePagination::default()
    });
    let newer = page(TimelinePagination {
        after: Some(200),
        after_message_id: Some("message-7".to_owned()),
        limit: Some(2),
        ..TimelinePagination::default()
    });

    assert_eq!(ids(&older), ["system-7", "message-7"]);
    assert_eq!(ids(&newer), ["system-8", "message-8"]);
}

#[test]
fn group_timeline_pagination_resolves_reprojected_system_cursor_by_stable_id() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut system_seven = group_system("system-7", "member_added", 100);
    system_seven.source_epoch = Some(7);
    store.record_app_event(&system_seven).unwrap();
    let mut message_seven = chat("message-7", "alice", 200, "epoch seven");
    message_seven.source_epoch = Some(7);
    store.record_app_event(&message_seven).unwrap();
    let mut system_eight = group_system("system-8", "member_removed", 300);
    system_eight.source_epoch = Some(8);
    store.record_app_event(&system_eight).unwrap();
    let mut message_eight = chat("message-8", "bob", 150, "epoch eight");
    message_eight.source_epoch = Some(8);
    store.record_app_event(&message_eight).unwrap();

    // Reprocessing the same deterministic system row updates its local
    // observation timestamp after a client has already retained the old cursor.
    system_eight.recorded_at = 900;
    system_eight.received_at = 900;
    store.record_app_event(&system_eight).unwrap();

    let older = store
        .message_timeline(TimelineMessageQuery {
            group_id_hex: Some("11".repeat(32)),
            pagination: TimelinePagination {
                before: Some(300),
                before_message_id: Some("system-8".to_owned()),
                limit: Some(2),
                ..TimelinePagination::default()
            },
            ..TimelineMessageQuery::default()
        })
        .unwrap();

    assert_eq!(ids(&older), ["system-7", "message-7"]);
}

#[test]
fn group_timeline_pagination_rejects_missing_canonical_cursor() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut message = chat("message-7", "alice", 200, "epoch seven");
    message.source_epoch = Some(7);
    store.record_app_event(&message).unwrap();

    let result = store.message_timeline(TimelineMessageQuery {
        group_id_hex: Some("11".repeat(32)),
        pagination: TimelinePagination {
            before: Some(300),
            before_message_id: Some("pruned-system-8".to_owned()),
            limit: Some(2),
            ..TimelinePagination::default()
        },
        ..TimelineMessageQuery::default()
    });

    assert!(matches!(result, Err(StorageError::TimelineCursorExpired)));
}

#[test]
fn wall_clock_timeline_query_preserves_retention_scan_order() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut system_seven = group_system("system-7", "member_added", 100);
    system_seven.source_epoch = Some(7);
    store.record_app_event(&system_seven).unwrap();
    let mut message_seven = chat("message-7", "alice", 200, "epoch seven");
    message_seven.source_epoch = Some(7);
    store.record_app_event(&message_seven).unwrap();
    let mut system_eight = group_system("system-8", "member_removed", 300);
    system_eight.source_epoch = Some(8);
    store.record_app_event(&system_eight).unwrap();
    let mut message_eight = chat("message-8", "bob", 150, "epoch eight");
    message_eight.source_epoch = Some(8);
    store.record_app_event(&message_eight).unwrap();

    let page = store
        .message_timeline_by_wall_clock(TimelineMessageQuery {
            group_id_hex: Some("11".repeat(32)),
            pagination: TimelinePagination {
                before: Some(300),
                before_message_id: Some("system-8".to_owned()),
                limit: Some(2),
                ..TimelinePagination::default()
            },
            ..TimelineMessageQuery::default()
        })
        .unwrap();

    assert_eq!(ids(&page), ["message-8", "message-7"]);
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
    let mut child = reply("reply", "bob", "parent", 2, "answer");
    child.source_epoch = Some(5);
    store.record_app_event(&child).unwrap();

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
        moderation_grant: false,
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
        moderation_grant: false,
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
fn timeline_search_treats_like_metacharacters_literally() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for (message_id, plaintext) in [
        ("percent", "50% complete"),
        ("percent-wildcard", "500 complete"),
        ("underscore", "a_b"),
        ("underscore-wildcard", "axb"),
        ("backslash", r"path\name"),
        ("backslash-absent", "pathname"),
    ] {
        store
            .record_app_event(&chat(message_id, "alice", 1, plaintext))
            .unwrap();
    }

    for (search, expected_id) in [
        ("50%", "percent"),
        ("a_b", "underscore"),
        (r"path\name", "backslash"),
    ] {
        let page = store
            .message_timeline(TimelineMessageQuery {
                group_id_hex: Some("11".repeat(32)),
                search: Some(search.to_owned()),
                ..TimelineMessageQuery::default()
            })
            .unwrap();
        assert_eq!(
            page.messages
                .iter()
                .map(|message| message.message_id_hex.as_str())
                .collect::<Vec<_>>(),
            vec![expected_id]
        );
    }
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
    // touch the other group's delivered copy. Regression for mdk#156.
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
    let preview = reply.reply_preview.as_ref().expect("reply preview");
    assert_eq!(preview.invalidation_status.as_deref(), Some("LosingBranch"));
    assert_eq!(preview.plaintext, "the original");
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

    let full = store
        .timeline_message(&"11".repeat(32), "target")
        .unwrap()
        .expect("complete target row");
    assert_eq!(full.message_id_hex, "target");
    assert_eq!(full.sender, "alice");
    assert_eq!(full.plaintext, "hello");
    assert_eq!(full.timeline_at, 1);

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
fn moderation_grant_delete_tombstones_other_members_message() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "secret"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();
    store
        .record_app_event(&moderated_delete("admin-delete", "carol", "target", 3))
        .unwrap();

    let message = list(&store).pop().unwrap();

    assert!(message.deleted);
    assert_eq!(
        message.deleted_by_message_id_hex.as_deref(),
        Some("admin-delete")
    );
    assert_eq!(message.plaintext, "");
    assert!(message.reactions.user_reactions.is_empty());
    assert!(message.reactions.by_emoji.is_empty());
}

#[test]
fn moderation_grant_delete_tombstones_target_arriving_later() {
    // Out-of-order delivery: the moderation delete lands before its target.
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&moderated_delete("admin-delete", "carol", "target", 1))
        .unwrap();
    store
        .record_app_event(&chat("target", "alice", 2, "secret"))
        .unwrap();

    let message = list(&store).pop().unwrap();

    assert!(message.deleted);
    assert_eq!(message.plaintext, "");
}

#[test]
fn moderation_grant_survives_full_timeline_rebuild() {
    // The grant is persisted with the delete event, so rebuilding the
    // projection from raw app events must keep honoring the moderated
    // tombstone even though the admin set is long gone from this layer.
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "secret"))
        .unwrap();
    store
        .record_app_event(&moderated_delete("admin-delete", "carol", "target", 2))
        .unwrap();

    store
        .rebuild_message_timeline_for_group(&"11".repeat(32))
        .unwrap();

    let message = list(&store).pop().unwrap();
    assert!(message.deleted);
    assert_eq!(
        message.deleted_by_message_id_hex.as_deref(),
        Some("admin-delete")
    );
    assert_eq!(message.plaintext, "");
}

#[test]
fn moderation_grant_does_not_retract_other_members_reaction() {
    // Reaction retraction keeps its sender-equality forged-delete guard;
    // moderation authority applies to messages, not to reaction removal.
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "hello"))
        .unwrap();
    store
        .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
        .unwrap();
    store
        .record_app_event(&moderated_delete("admin-delete", "carol", "reaction-1", 3))
        .unwrap();

    let message = list(&store).pop().unwrap();

    assert!(!message.deleted);
    assert_eq!(message.reactions.user_reactions.len(), 1);
}

#[test]
fn re_recording_a_delete_freezes_the_stored_moderation_grant() {
    // The default path must keep an honored grant: a re-received / echoed
    // delete recomputed as non-moderated after an admin-set change cannot
    // resurrect the tombstoned message.
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "secret"))
        .unwrap();
    store
        .record_app_event(&moderated_delete("admin-delete", "carol", "target", 2))
        .unwrap();
    // Echo of the same delete id, now without a grant.
    store
        .record_app_event(&delete("admin-delete", "carol", "target", 2))
        .unwrap();

    let message = list(&store).pop().unwrap();
    assert!(message.deleted, "frozen grant must keep the tombstone");
}

#[test]
fn refreshing_variant_replaces_the_stored_moderation_grant() {
    // The local sender's post-publish reconciling projection supersedes the
    // optimistic pre-send grant: a grant recomputed as non-moderated after
    // group sync must drop the tombstone (and vice versa).
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .record_app_event(&chat("target", "alice", 1, "secret"))
        .unwrap();
    store
        .record_app_event(&moderated_delete("admin-delete", "carol", "target", 2))
        .unwrap();
    assert!(list(&store).pop().unwrap().deleted);

    // Post-sync recompute: no longer a moderator → grant withdrawn.
    store
        .record_app_event_refreshing_moderation_grant(&delete("admin-delete", "carol", "target", 2))
        .unwrap();
    assert!(
        !list(&store).pop().unwrap().deleted,
        "refresh must withdraw the tombstone when the grant is recomputed away",
    );

    // Post-sync recompute the other way: moderator confirmed → grant restored.
    store
        .record_app_event_refreshing_moderation_grant(&moderated_delete(
            "admin-delete",
            "carol",
            "target",
            2,
        ))
        .unwrap();
    assert!(list(&store).pop().unwrap().deleted);
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

    store
        .prune_app_events_before(&"11".repeat(32), 50, "local", &no_mentions)
        .unwrap();

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

/// A locally accepted send whose intent the engine retained: the row exists
/// optimistically but has never been published, so `source_message_id_hex` is
/// still NULL and the derived delivery state is `pending`.
fn pending_sent(group_id_hex: &str, id: &str, at: u64) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: group_id_hex.to_owned(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: None,
        source_epoch: None,
        direction: "sent".to_owned(),
        sender: "self".to_owned(),
        plaintext: "held".to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
        moderation_grant: false,
    }
}

#[test]
fn sweeping_a_terminal_group_invalidates_only_its_own_unpublished_sends() {
    // Disband and local removal purge the whole outbound queue, so every one of
    // the group's accepted-but-unpublished sends is dead at once. The sweep must
    // reach exactly those rows: not the group's delivered sends, not received
    // rows, and not another group's held sends.
    let store = SqliteAccountStorage::in_memory().unwrap();
    let dead_group = "11".repeat(32);
    let live_group = "22".repeat(32);
    store
        .record_app_event(&pending_sent(&dead_group, "held-a", 10))
        .unwrap();
    store
        .record_app_event(&pending_sent(&dead_group, "held-b", 11))
        .unwrap();
    store
        .record_app_event(&chat("delivered", "self", 12, "published"))
        .unwrap();
    store
        .record_app_event(&chat("received", "peer", 13, "from a peer"))
        .unwrap();
    store
        .record_app_event(&pending_sent(&live_group, "other-group-held", 14))
        .unwrap();

    let update = store
        .invalidate_pending_sent_app_events_for_group(&dead_group, "local_publish_failed")
        .unwrap()
        .expect("held rows should produce an update");
    assert_eq!(update.group_id_hex, dead_group);

    let status = |group_id_hex: &str, id: &str| {
        store
            .message_timeline(TimelineMessageQuery {
                group_id_hex: Some(group_id_hex.to_owned()),
                ..TimelineMessageQuery::default()
            })
            .unwrap()
            .messages
            .into_iter()
            .find(|row| row.message_id_hex == id)
            .map(|row| row.invalidation_status)
    };
    assert_eq!(
        status(&dead_group, "held-a"),
        Some(Some("local_publish_failed".to_owned()))
    );
    assert_eq!(
        status(&dead_group, "held-b"),
        Some(Some("local_publish_failed".to_owned()))
    );
    assert_eq!(status(&dead_group, "delivered"), Some(None));
    assert_eq!(status(&dead_group, "received"), Some(None));
    assert_eq!(status(&live_group, "other-group-held"), Some(None));
}

#[test]
fn sweeping_a_group_with_no_unpublished_sends_reports_nothing() {
    // A group that disbands with an empty outbound queue — the common case —
    // must not manufacture a projection update for subscribers to react to.
    let store = SqliteAccountStorage::in_memory().unwrap();
    let group_id_hex = "11".repeat(32);
    store
        .record_app_event(&chat("delivered", "self", 10, "published"))
        .unwrap();

    assert!(
        store
            .invalidate_pending_sent_app_events_for_group(&group_id_hex, "local_publish_failed")
            .unwrap()
            .is_none()
    );
}

#[test]
fn sweeping_a_group_twice_leaves_the_first_outcome_intact() {
    // The sweep runs from the sync ingest loop, whose error path retries the
    // whole batch. A second pass over already-swept rows must be inert: no
    // rewritten reason, and no redundant update for live subscribers.
    let store = SqliteAccountStorage::in_memory().unwrap();
    let group_id_hex = "11".repeat(32);
    store
        .record_app_event(&pending_sent(&group_id_hex, "held", 10))
        .unwrap();

    assert!(
        store
            .invalidate_pending_sent_app_events_for_group(&group_id_hex, "local_publish_failed")
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .invalidate_pending_sent_app_events_for_group(&group_id_hex, "something_else")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        list(&store)
            .into_iter()
            .find(|row| row.message_id_hex == "held")
            .map(|row| row.invalidation_status),
        Some(Some("local_publish_failed".to_owned()))
    );
}
