use super::*;

#[test]
fn message_subscription_seen_ids_are_bounded_to_recent_ids() {
    let mut seen =
        MessageSubscriptionSeenIds::from_ids((0..5).map(|index| format!("message-{index}")), 3);

    assert_eq!(seen.len(), 3);
    assert!(!seen.contains("message-0"));
    assert!(!seen.contains("message-1"));
    assert!(seen.contains("message-2"));
    assert!(seen.contains("message-4"));
    assert!(!seen.insert("message-2".to_owned()));
    assert!(seen.insert("message-5".to_owned()));
    assert_eq!(seen.len(), 3);
    assert!(!seen.contains("message-2"));
    assert!(seen.contains("message-3"));
    assert!(seen.contains("message-5"));
}

#[test]
fn message_subscription_seen_ids_do_not_store_empty_ids() {
    let mut seen = MessageSubscriptionSeenIds::with_limit(1);

    assert!(seen.insert(String::new()));
    assert!(seen.insert(String::new()));
    assert_eq!(seen.len(), 0);
}

#[test]
fn parse_quic_candidate_ignores_path_query_and_fragment_after_authority() {
    // Per transports/quic.md a receiver MUST ignore any path, query, or
    // fragment after the authority. A spec-valid start payload from another
    // implementation that appends one of these must still be watchable: the
    // authority (and thus the resolvable port) stops at the first '/', '?',
    // or '#'.
    for (candidate, authority, server_name) in [
        (
            "quic://relay.example:443/path",
            "relay.example:443",
            "relay.example",
        ),
        (
            "quic://relay.example:443?x=1",
            "relay.example:443",
            "relay.example",
        ),
        (
            "quic://relay.example:443#frag",
            "relay.example:443",
            "relay.example",
        ),
        (
            "quic://relay.example:443/p?x=1#frag",
            "relay.example:443",
            "relay.example",
        ),
        (
            "quic://[2001:db8::1]:443?x=1",
            "[2001:db8::1]:443",
            "2001:db8::1",
        ),
        (
            "quic://[2001:db8::1]:443#frag",
            "[2001:db8::1]:443",
            "2001:db8::1",
        ),
    ] {
        let parsed = parse_quic_candidate(candidate)
            .unwrap_or_else(|_| panic!("candidate should parse: {candidate}"));
        assert_eq!(parsed.authority, authority, "authority for {candidate}");
        assert_eq!(
            parsed.server_name, server_name,
            "server name for {candidate}"
        );
    }
}

#[test]
fn stamp_published_profile_created_at_replaces_zero_with_now() {
    // FFI-published profiles arrive with created_at == 0; they must be
    // stamped so the cached own-account entry survives a directory refresh
    // that re-fetches a stale pre-edit kind-0 from a lagging relay.
    let mut profile = UserProfileMetadata {
        name: Some("edited".to_owned()),
        created_at: 0,
        ..UserProfileMetadata::default()
    };
    stamp_published_profile_created_at(&mut profile, 1_700_000_000);
    assert_eq!(profile.created_at, 1_700_000_000);
}

#[test]
fn stamp_published_profile_created_at_preserves_existing_stamp() {
    // Callers that already carry a real timestamp (e.g. the default-profile
    // setup path) must not have it clobbered.
    let mut profile = UserProfileMetadata {
        name: Some("preset".to_owned()),
        created_at: 42,
        ..UserProfileMetadata::default()
    };
    stamp_published_profile_created_at(&mut profile, 1_700_000_000);
    assert_eq!(profile.created_at, 42);
}

#[test]
fn stamped_profile_wins_over_stale_relay_copy_in_if_newer_check() {
    // Regression for darkmatter#206: model the exact comparison
    // remember_directory_profile_if_newer performs. A zero-stamped cache
    // loses to any fetched copy; a now-stamped cache beats an older one.
    let mut zero_cache = UserProfileMetadata {
        created_at: 0,
        ..UserProfileMetadata::default()
    };
    let stale_relay_copy = UserProfileMetadata {
        created_at: 1_699_999_900,
        ..UserProfileMetadata::default()
    };
    // Before the fix: cached(0) > fetched is false, so the stale copy wins.
    assert!(zero_cache.created_at <= stale_relay_copy.created_at);

    // After stamping the just-published edit with a fresh clock:
    stamp_published_profile_created_at(&mut zero_cache, 1_700_000_000);
    // The local edit now beats the older relay copy and is retained.
    assert!(zero_cache.created_at > stale_relay_copy.created_at);
}

#[tokio::test]
async fn managed_account_worker_shutdown_aborts_unresponsive_task_after_timeout() {
    let (commands, _commands_rx) = mpsc::channel(1);
    let (shutdown, _shutdown_rx) = oneshot::channel();
    let handle = tokio::spawn(async {
        std::future::pending::<()>().await;
    });
    let worker = ManagedAccountWorker {
        handle,
        commands,
        shutdown,
    };

    let started = std::time::Instant::now();
    worker
        .shutdown_with_timeout(Duration::from_millis(10))
        .await;

    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn message_subscription_recv_ends_when_runtime_shutdown_begins() {
    let lifecycle = RuntimeLifecycle::new();
    let (updates_tx, updates) = mpsc::channel(1);
    let mut subscription = RuntimeMessagesSubscription {
        snapshot: Vec::new(),
        updates,
        stopping: lifecycle.subscribe_shutdown(),
    };

    lifecycle.begin_shutdown();

    assert!(subscription.recv().await.is_none());
    drop(updates_tx);
}

fn timeline_test_record(message_id_hex: &str, timeline_at: u64) -> TimelineMessageRecord {
    TimelineMessageRecord {
        message_id_hex: message_id_hex.to_owned(),
        source_message_id_hex: None,
        source_epoch: None,
        group_id_hex: "group-1".to_owned(),
        direction: "inbound".to_owned(),
        sender: "sender-1".to_owned(),
        plaintext: message_id_hex.to_owned(),
        kind: 9,
        tags: Vec::new(),
        timeline_at,
        received_at: timeline_at,
        deleted: false,
        deleted_by_message_id_hex: None,
        invalidation_status: None,
        reply_to_message_id_hex: None,
        reply_preview: None,
        media: None,
        agent_text_stream: None,
        reactions: Default::default(),
    }
}

fn timeline_test_page(
    records: &[(&str, u64)],
    has_more_before: bool,
    has_more_after: bool,
) -> TimelinePage {
    TimelinePage {
        messages: records
            .iter()
            .map(|(id, at)| timeline_test_record(id, *at))
            .collect(),
        has_more_before,
        has_more_after,
    }
}

fn empty_timeline_page() -> TimelinePage {
    TimelinePage {
        messages: Vec::new(),
        has_more_before: false,
        has_more_after: false,
    }
}

fn timeline_ids(page: &TimelinePage) -> Vec<String> {
    page.messages
        .iter()
        .map(|message| message.message_id_hex.clone())
        .collect()
}

/// A fake store that hands out canned pages in order and records each query
/// it received, so tests can assert both the merge result and the cursor a
/// pagination/refresh call issued.
#[derive(Clone, Default)]
struct ScriptedTimelineStore {
    responses: Arc<StdMutex<std::collections::VecDeque<TimelinePage>>>,
    queries: Arc<StdMutex<Vec<TimelineMessageQuery>>>,
}

impl ScriptedTimelineStore {
    fn new(responses: Vec<TimelinePage>) -> Self {
        Self {
            responses: Arc::new(StdMutex::new(responses.into_iter().collect())),
            queries: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn query_fn(&self) -> Arc<TimelineQueryFn> {
        let responses = self.responses.clone();
        let queries = self.queries.clone();
        Arc::new(move |query: TimelineMessageQuery| {
            queries.lock().expect("queries lock").push(query);
            let page = responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .expect("scripted timeline store exhausted");
            Ok(page)
        })
    }

    fn recorded_queries(&self) -> Vec<TimelineMessageQuery> {
        self.queries.lock().expect("queries lock").clone()
    }
}

fn timeline_window(
    store: &ScriptedTimelineStore,
    page: TimelinePage,
    window_limit: usize,
) -> TimelineWindow {
    TimelineWindow {
        query: store.query_fn(),
        base_query: TimelineMessageQuery::default(),
        page,
        window_limit,
        generation: 0,
    }
}

fn timeline_window_handle(
    store: &ScriptedTimelineStore,
    page: TimelinePage,
    window_limit: usize,
) -> TimelineWindowHandle {
    TimelineWindowHandle {
        inner: Arc::new(StdMutex::new(timeline_window(store, page, window_limit))),
    }
}

fn timeline_subscription_with(
    store: &ScriptedTimelineStore,
    window: TimelinePage,
    window_limit: usize,
    updates: mpsc::Receiver<TimelineSubscriptionSignal>,
    stopping: watch::Receiver<bool>,
) -> RuntimeTimelineMessagesSubscription {
    RuntimeTimelineMessagesSubscription {
        window: timeline_window_handle(store, window, window_limit),
        updates,
        stopping,
    }
}

#[tokio::test]
async fn timeline_subscription_recv_ends_when_runtime_shutdown_begins() {
    let lifecycle = RuntimeLifecycle::new();
    let store = ScriptedTimelineStore::default();
    let (updates_tx, updates) = mpsc::channel(1);
    let mut subscription = timeline_subscription_with(
        &store,
        empty_timeline_page(),
        TIMELINE_WINDOW_LIMIT,
        updates,
        lifecycle.subscribe_shutdown(),
    );

    lifecycle.begin_shutdown();

    assert!(subscription.recv().await.is_none());
    drop(updates_tx);
}

#[tokio::test]
async fn agent_stream_watch_recv_prioritizes_terminal_update() {
    let lifecycle = RuntimeLifecycle::new();
    let (updates_tx, updates) = mpsc::channel(1);
    updates_tx
        .try_send(RuntimeAgentStreamUpdate::Progress {
            seq: 1,
            text: "searching".to_owned(),
        })
        .expect("provisional queue should accept first update");
    let (terminal_tx, terminal) = oneshot::channel();
    let expected = RuntimeAgentStreamUpdate::Finished {
        text: "done".to_owned(),
        transcript_hash_hex: "00".to_owned(),
        chunk_count: 1,
    };
    terminal_tx
        .send(expected.clone())
        .expect("terminal receiver should be alive");
    let handle = tokio::spawn(async {});
    let mut watch = RuntimeAgentStreamWatch {
        stream_id_hex: "stream".to_owned(),
        updates,
        terminal: Some(terminal),
        abort: handle.abort_handle(),
        stopping: lifecycle.subscribe_shutdown(),
    };

    assert_eq!(watch.recv().await, Some(expected));
    assert!(watch.recv().await.is_none());
}

#[test]
fn timeline_subscription_take_snapshot_retains_window_for_pagination() {
    let lifecycle = RuntimeLifecycle::new();
    let store = ScriptedTimelineStore::default();
    let (_updates_tx, updates) = mpsc::channel(1);
    let subscription = timeline_subscription_with(
        &store,
        timeline_test_page(&[("message-1", 1)], true, false),
        TIMELINE_WINDOW_LIMIT,
        updates,
        lifecycle.subscribe_shutdown(),
    );

    let snapshot = subscription.take_snapshot();

    assert_eq!(snapshot.messages.len(), 1);
    assert!(snapshot.has_more_before);
    // The window is retained (cloned, not drained) so pagination can extend
    // it; a second read returns the same window.
    let again = subscription.take_snapshot();
    assert_eq!(timeline_ids(&again), vec!["message-1".to_owned()]);
    assert!(again.has_more_before);
}

#[test]
fn merge_timeline_window_prepends_older_and_keeps_head_flag() {
    let mut window = timeline_test_page(&[("c", 30), ("d", 40)], true, false);
    let older = timeline_test_page(&[("a", 10), ("b", 20)], false, true);

    merge_timeline_window(&mut window, older, TimelineWindowEdge::Older, 300);

    assert_eq!(timeline_ids(&window), vec!["a", "b", "c", "d"]);
    // The store reported no more history before; the head side is untouched.
    assert!(!window.has_more_before);
    assert!(!window.has_more_after);
}

#[test]
fn merge_timeline_window_older_caps_by_dropping_newest() {
    let mut window = timeline_test_page(&[("c", 30), ("d", 40)], true, false);
    let older = timeline_test_page(&[("a", 10), ("b", 20)], true, true);

    merge_timeline_window(&mut window, older, TimelineWindowEdge::Older, 3);

    // Cap forces dropping the newest row, opening a gap to the head.
    assert_eq!(timeline_ids(&window), vec!["a", "b", "c"]);
    assert!(window.has_more_before);
    assert!(window.has_more_after);
}

#[test]
fn merge_timeline_window_newer_caps_by_dropping_oldest() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], true, true);
    let newer = timeline_test_page(&[("c", 30), ("d", 40)], true, false);

    merge_timeline_window(&mut window, newer, TimelineWindowEdge::Newer, 3);

    assert_eq!(timeline_ids(&window), vec!["b", "c", "d"]);
    assert!(window.has_more_before);
    // The store reported the head was reached.
    assert!(!window.has_more_after);
}

#[test]
fn merge_timeline_window_dedupes_overlap() {
    let mut window = timeline_test_page(&[("b", 20), ("c", 30)], true, false);
    let older = timeline_test_page(&[("a", 10), ("b", 20)], false, true);

    merge_timeline_window(&mut window, older, TimelineWindowEdge::Older, 300);

    assert_eq!(timeline_ids(&window), vec!["a", "b", "c"]);
}

fn projection_for(messages: Vec<TimelineMessageRecord>) -> AppProjectionUpdate {
    AppProjectionUpdate {
        group_id_hex: "group-1".to_owned(),
        timeline_messages: messages,
        timeline_changes: Vec::new(),
        chat_list_row: None,
        chat_list_trigger: Default::default(),
    }
}

#[test]
fn apply_projection_appends_new_message_when_anchored() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], false, false);
    let update = projection_for(vec![timeline_test_record("c", 30)]);

    apply_projection_to_window(&mut window, &update, 300);

    assert_eq!(timeline_ids(&window), vec!["a", "b", "c"]);
    assert!(!window.has_more_after);
}

#[test]
fn apply_projection_suppresses_new_head_message_when_detached() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], true, true);
    let update = projection_for(vec![timeline_test_record("c", 30)]);

    apply_projection_to_window(&mut window, &update, 300);

    // Detached window stays put; the new head message is dropped.
    assert_eq!(timeline_ids(&window), vec!["a", "b"]);
    assert!(window.has_more_after);
}

#[test]
fn apply_projection_applies_in_window_edit_when_detached() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], true, true);
    let mut edited = timeline_test_record("b", 20);
    edited.plaintext = "edited".to_owned();
    let update = projection_for(vec![edited]);

    apply_projection_to_window(&mut window, &update, 300);

    assert_eq!(timeline_ids(&window), vec!["a", "b"]);
    assert_eq!(window.messages[1].plaintext, "edited");
}

#[test]
fn apply_projection_suppresses_same_second_head_when_detached() {
    // Newest is ("b", 20); a brand-new message shares the second but sorts
    // after it by id. Timestamp-only comparison would admit it; canonical
    // `(timeline_at, message_id_hex)` comparison correctly suppresses it.
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], true, true);
    let update = projection_for(vec![timeline_test_record("c", 20)]);

    apply_projection_to_window(&mut window, &update, 300);

    assert_eq!(timeline_ids(&window), vec!["a", "b"]);
    assert!(window.has_more_after);
}

#[test]
fn apply_projection_applies_same_second_in_range_message_when_detached() {
    // Newest is ("c", 20); a same-second message that sorts *before* it is
    // genuinely inside the window and must be applied.
    let mut window = timeline_test_page(&[("a", 10), ("c", 20)], true, true);
    let update = projection_for(vec![timeline_test_record("b", 20)]);

    apply_projection_to_window(&mut window, &update, 300);

    assert_eq!(timeline_ids(&window), vec!["a", "b", "c"]);
}

#[test]
fn apply_projection_suppresses_new_message_when_detached_window_empty() {
    // An emptied detached window (every row removed) has nothing in range, so
    // a head message must be suppressed rather than absorbed.
    let mut window = timeline_test_page(&[], true, true);
    let update = projection_for(vec![timeline_test_record("a", 10)]);

    apply_projection_to_window(&mut window, &update, 300);

    assert!(window.messages.is_empty());
    assert!(window.has_more_after);
}

#[test]
fn apply_projection_removes_message() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], false, false);
    let update = AppProjectionUpdate {
        group_id_hex: "group-1".to_owned(),
        timeline_messages: Vec::new(),
        timeline_changes: vec![TimelineMessageChange::Remove {
            message_id_hex: "a".to_owned(),
            reason: crate::TimelineRemoveReason::Invalidated,
        }],
        chat_list_row: None,
        chat_list_trigger: Default::default(),
    };

    apply_projection_to_window(&mut window, &update, 300);

    assert_eq!(timeline_ids(&window), vec!["b"]);
}

#[test]
fn apply_projection_caps_anchored_window_by_dropping_oldest() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20), ("c", 30)], false, false);
    let update = projection_for(vec![timeline_test_record("d", 40)]);

    apply_projection_to_window(&mut window, &update, 3);

    assert_eq!(timeline_ids(&window), vec!["b", "c", "d"]);
    assert!(window.has_more_before);
    assert!(!window.has_more_after);
}

#[tokio::test]
async fn paginate_backwards_extends_window_and_clears_more_before() {
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        false,
        true,
    )]);
    let handle = timeline_window_handle(
        &store,
        timeline_test_page(&[("c", 30), ("d", 40)], true, false),
        300,
    );

    let page = handle.paginate_backwards(2).await.expect("paginate");

    assert_eq!(timeline_ids(&page), vec!["a", "b", "c", "d"]);
    assert!(!page.has_more_before);
    assert!(!page.has_more_after);
    // The cursor was anchored at the previous oldest message.
    let queries = store.recorded_queries();
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].pagination.before, Some(30));
    assert_eq!(
        queries[0].pagination.before_message_id.as_deref(),
        Some("c")
    );
    assert_eq!(queries[0].pagination.limit, Some(2));
}

#[tokio::test]
async fn paginate_backwards_is_noop_without_more_before() {
    // Empty response queue: a store call would panic, proving none is made.
    let store = ScriptedTimelineStore::new(Vec::new());
    let handle =
        timeline_window_handle(&store, timeline_test_page(&[("a", 10)], false, false), 300);

    let page = handle.paginate_backwards(10).await.expect("paginate");

    assert_eq!(timeline_ids(&page), vec!["a"]);
    assert!(store.recorded_queries().is_empty());
}

#[tokio::test]
async fn paginate_forwards_reaching_head_reanchors() {
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("c", 30), ("d", 40)],
        true,
        false,
    )]);
    let handle = timeline_window_handle(
        &store,
        timeline_test_page(&[("a", 10), ("b", 20)], true, true),
        300,
    );

    let page = handle.paginate_forwards(2).await.expect("paginate");

    assert_eq!(timeline_ids(&page), vec!["a", "b", "c", "d"]);
    assert!(page.has_more_before);
    // Head reached: the window is now anchored again.
    assert!(!page.has_more_after);
    let queries = store.recorded_queries();
    assert_eq!(queries[0].pagination.after, Some(20));
    assert_eq!(queries[0].pagination.after_message_id.as_deref(), Some("b"));
}

#[tokio::test]
async fn paginate_backwards_caps_window_and_opens_head_gap() {
    // A small window cap forces trimming the newest rows when older history
    // is loaded, opening a gap to the head (has_more_after).
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        true,
        true,
    )]);
    let handle = timeline_window_handle(
        &store,
        timeline_test_page(&[("c", 30), ("d", 40)], true, false),
        3,
    );

    let page = handle.paginate_backwards(2).await.expect("paginate");

    assert_eq!(timeline_ids(&page), vec!["a", "b", "c"]);
    assert!(page.has_more_before);
    assert!(page.has_more_after);
}

#[tokio::test]
async fn paginate_does_not_block_on_a_parked_receiver() {
    // Regression for the FFI-equivalent contention: a subscription parked in
    // recv() (no live updates) must not block pagination through the handle.
    let lifecycle = RuntimeLifecycle::new();
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        false,
        true,
    )]);
    let (tx, updates) = mpsc::channel(1);
    let mut subscription = timeline_subscription_with(
        &store,
        timeline_test_page(&[("c", 30), ("d", 40)], true, false),
        300,
        updates,
        lifecycle.subscribe_shutdown(),
    );
    let handle = subscription.window_handle();

    // recv() parks (no signal queued); pagination through the cloned handle
    // proceeds without waiting for a live update.
    let recv = tokio::spawn(async move { subscription.recv().await });
    let page = tokio::time::timeout(Duration::from_secs(2), handle.paginate_backwards(2))
        .await
        .expect("pagination must not block on the parked receiver")
        .expect("paginate");
    assert_eq!(timeline_ids(&page), vec!["a", "b", "c", "d"]);

    // Unblock and join the parked receiver.
    drop(tx);
    let _ = recv.await;
}

#[tokio::test]
async fn recv_projection_applies_to_window() {
    let lifecycle = RuntimeLifecycle::new();
    let store = ScriptedTimelineStore::default();
    let (tx, updates) = mpsc::channel(1);
    let mut subscription = timeline_subscription_with(
        &store,
        timeline_test_page(&[("a", 10)], false, false),
        300,
        updates,
        lifecycle.subscribe_shutdown(),
    );
    tx.send(TimelineSubscriptionSignal::Projection(Box::new(
        RuntimeProjectionUpdate {
            account_id_hex: "account".to_owned(),
            account_label: "label".to_owned(),
            update: projection_for(vec![timeline_test_record("b", 20)]),
        },
    )))
    .await
    .expect("send projection");

    let update = subscription.recv().await.expect("recv");

    assert!(matches!(
        update,
        RuntimeTimelineMessageUpdate::Projection(_)
    ));
    assert_eq!(timeline_ids(&subscription.take_snapshot()), vec!["a", "b"]);
}

#[tokio::test]
async fn recv_refresh_rematerializes_anchored_head() {
    let lifecycle = RuntimeLifecycle::new();
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        true,
        false,
    )]);
    let (tx, updates) = mpsc::channel(1);
    let mut subscription = timeline_subscription_with(
        &store,
        timeline_test_page(&[("a", 10)], false, false),
        300,
        updates,
        lifecycle.subscribe_shutdown(),
    );
    tx.send(TimelineSubscriptionSignal::Refresh)
        .await
        .expect("send refresh");

    let update = subscription.recv().await.expect("recv");

    match update {
        RuntimeTimelineMessageUpdate::Page { page } => {
            assert_eq!(timeline_ids(&page), vec!["a", "b"]);
        }
        other => panic!("expected refreshed page, got {other:?}"),
    }
    // Anchored refresh queries the head (no cursor).
    let queries = store.recorded_queries();
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].pagination.before, None);
    assert_eq!(queries[0].pagination.after, None);
}

#[tokio::test]
async fn recv_refresh_detached_issues_inclusive_upper_cursor() {
    let lifecycle = RuntimeLifecycle::new();
    // The store itself excludes newer same-second rows via the inclusive
    // bound (covered by storage-sqlite's
    // `before_inclusive_cursor_keeps_window_rows_over_newer_same_second_rows`);
    // here we assert the runtime issues that inclusive cursor and installs
    // the returned page verbatim (no post-fetch trimming).
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        true,
        true,
    )]);
    let (tx, updates) = mpsc::channel(1);
    let mut subscription = timeline_subscription_with(
        &store,
        timeline_test_page(&[("a", 10), ("b", 20)], true, true),
        300,
        updates,
        lifecycle.subscribe_shutdown(),
    );
    tx.send(TimelineSubscriptionSignal::Refresh)
        .await
        .expect("send refresh");

    let update = subscription.recv().await.expect("recv");

    match update {
        RuntimeTimelineMessageUpdate::Page { page } => {
            assert_eq!(timeline_ids(&page), vec!["a", "b"]);
        }
        other => panic!("expected refreshed page, got {other:?}"),
    }
    let queries = store.recorded_queries();
    assert_eq!(queries[0].pagination.before, Some(20));
    assert_eq!(
        queries[0].pagination.before_message_id.as_deref(),
        Some("b")
    );
    assert!(queries[0].pagination.before_inclusive);
}

#[tokio::test]
async fn refresh_install_is_dropped_when_window_paginated_during_query() {
    // Deterministic model of the P1(b) race: a refresh captures the window
    // generation before its store read; a pagination completes during that
    // read (bumping the generation); installing the now-stale refresh must
    // be a no-op so the paginated expansion is preserved.
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        false,
        true,
    )]);
    let handle = timeline_window_handle(
        &store,
        timeline_test_page(&[("c", 30), ("d", 40)], true, false),
        300,
    );

    // recv() captures the refresh request (a generation snapshot) before
    // awaiting the store.
    let (_query_fn, _query, generation) = handle.refresh_request();

    // A concurrent pagination lands while the refresh query is "in flight".
    let paginated = handle.paginate_backwards(2).await.expect("paginate");
    assert_eq!(timeline_ids(&paginated), vec!["a", "b", "c", "d"]);

    // Installing the stale refresh is rejected; the paginated window stands.
    let installed = handle.install_refresh(
        timeline_test_page(&[("c", 30), ("d", 40)], true, false),
        generation,
    );
    assert_eq!(timeline_ids(&installed), vec!["a", "b", "c", "d"]);
    assert_eq!(timeline_ids(&handle.snapshot()), vec!["a", "b", "c", "d"]);
}

#[test]
fn refresh_query_for_detached_window_anchors_at_newest() {
    let store = ScriptedTimelineStore::default();
    let window = timeline_window(
        &store,
        timeline_test_page(&[("a", 10), ("b", 20)], true, true),
        300,
    );

    let query = window.refresh_query();

    // Detached: an inclusive upper-bound cursor at the exact newest message,
    // so the descending LIMIT can't be starved by newer same-second rows.
    assert_eq!(query.pagination.before, Some(20));
    assert_eq!(query.pagination.before_message_id.as_deref(), Some("b"));
    assert!(query.pagination.before_inclusive);
    assert_eq!(query.pagination.limit, Some(2));
}

#[test]
fn refresh_query_for_anchored_window_targets_head() {
    let store = ScriptedTimelineStore::default();
    let window = timeline_window(
        &store,
        timeline_test_page(&[("a", 10), ("b", 20)], true, false),
        300,
    );

    let query = window.refresh_query();

    // Anchored: cursorless head refresh sized to the current window.
    assert_eq!(query.pagination.before, None);
    assert_eq!(query.pagination.after, None);
    assert_eq!(query.pagination.limit, Some(2));
}

#[tokio::test]
async fn chat_list_remove_update_is_sent_once_for_visible_rows() {
    let (updates_tx, mut updates_rx) = mpsc::channel(1);
    let mut row_fingerprints = HashMap::from([("group".to_owned(), "fingerprint".to_owned())]);

    assert!(
        send_chat_list_remove_update(
            &updates_tx,
            &mut row_fingerprints,
            ChatListUpdateTrigger::Removed,
            "group",
        )
        .await
    );
    assert_eq!(
        updates_rx.recv().await,
        Some(RuntimeChatListUpdate::RemoveRow {
            trigger: ChatListUpdateTrigger::Removed,
            group_id_hex: "group".to_owned()
        })
    );

    assert!(
        send_chat_list_remove_update(
            &updates_tx,
            &mut row_fingerprints,
            ChatListUpdateTrigger::Removed,
            "group",
        )
        .await
    );
    assert!(updates_rx.try_recv().is_err());
}

#[tokio::test]
async fn chat_list_snapshot_reconciliation_updates_changed_rows_and_removes_missing_rows() {
    let (updates_tx, mut updates_rx) = mpsc::channel(2);
    let initial_row = chat_list_test_row("group", "before");
    let removed_row = chat_list_test_row("removed", "gone");
    let mut row_fingerprints = HashMap::from([
        (
            initial_row.group_id_hex.clone(),
            chat_list_row_fingerprint(&initial_row),
        ),
        (
            removed_row.group_id_hex.clone(),
            chat_list_row_fingerprint(&removed_row),
        ),
    ]);

    assert!(
        reconcile_chat_list_snapshot(
            &updates_tx,
            &mut row_fingerprints,
            ChatListUpdateTrigger::SnapshotRefresh,
            vec![chat_list_test_row("group", "after")],
        )
        .await
    );

    assert!(matches!(
        updates_rx.recv().await,
        Some(RuntimeChatListUpdate::RemoveRow {
            trigger: ChatListUpdateTrigger::SnapshotRefresh,
            group_id_hex,
        }) if group_id_hex == "removed"
    ));
    assert!(matches!(
        updates_rx.recv().await,
        Some(RuntimeChatListUpdate::Row {
            trigger: ChatListUpdateTrigger::SnapshotRefresh,
            row,
        }) if row.group_id_hex == "group" && row.title == "after"
    ));
}

#[test]
fn latest_agent_stream_start_accepts_mixed_case_filter() {
    let stream_id_hex = hex::encode([0xab; 32]);
    let (message_id_hex, start, sender) = latest_agent_stream_start(
        vec![AppMessageRecord {
            message_id_hex: "11".repeat(32),
            direction: "inbound".to_owned(),
            group_id_hex: "22".repeat(32),
            sender: "33".repeat(32),
            plaintext: String::new(),
            kind: MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
            tags: vec![
                vec![STREAM_TAG.to_owned(), stream_id_hex.clone()],
                vec![STREAM_ROUTE_TAG.to_owned(), STREAM_ROUTE_QUIC.to_owned()],
            ],
            source_epoch: None,
            recorded_at: 0,
            received_at: 0,
        }],
        Some(&stream_id_hex.to_uppercase()),
    )
    .unwrap();

    assert_eq!(message_id_hex, "11".repeat(32));
    assert_eq!(start.stream_id_hex, stream_id_hex);
    assert_eq!(sender, "33".repeat(32));
}

fn chat_list_test_row(group_id_hex: &str, title: &str) -> ChatListRow {
    ChatListRow {
        group_id_hex: group_id_hex.to_owned(),
        archived: false,
        pending_confirmation: false,
        title: title.to_owned(),
        group_name: title.to_owned(),
        avatar_url: None,
        avatar: None,
        last_message: None,
        unread_count: 0,
        has_unread: false,
        first_unread_message_id_hex: None,
        last_read_message_id_hex: None,
        last_read_timeline_at: None,
        updated_at: 0,
    }
}

fn message_record(message_id_hex: &str, group_id_hex: &str, kind: u64) -> AppMessageRecord {
    AppMessageRecord {
        message_id_hex: message_id_hex.to_owned(),
        direction: "received".to_owned(),
        group_id_hex: group_id_hex.to_owned(),
        sender: "ab".repeat(32),
        plaintext: "hello".to_owned(),
        kind,
        tags: Vec::new(),
        source_epoch: Some(7),
        recorded_at: 11,
        received_at: 12,
    }
}

#[test]
fn recovery_record_maps_chat_message_to_message_update() {
    let group_id_hex = "cd".repeat(32);
    let record = message_record(&"11".repeat(32), &group_id_hex, 9);
    let mut display_names = HashMap::new();
    display_names.insert("ab".repeat(32), "Alice".to_owned());

    let update = received_message_update_from_record(
        "ac".repeat(32).as_str(),
        "alice",
        record,
        &display_names,
    )
    .expect("update");

    match update {
        RuntimeMessageUpdate::Message(received) => {
            assert_eq!(received.account_id_hex, "ac".repeat(32));
            assert_eq!(received.account_label, "alice");
            assert_eq!(received.message.message_id_hex, "11".repeat(32));
            assert_eq!(
                received.message.sender_display_name.as_deref(),
                Some("Alice")
            );
            assert_eq!(received.message.source_epoch, 7);
            assert_eq!(
                hex::encode(received.message.group_id.as_slice()),
                group_id_hex
            );
        }
        other => panic!("expected Message update, got {other:?}"),
    }
}

#[test]
fn recovery_record_reclassifies_agent_stream_start() {
    let group_id_hex = "cd".repeat(32);
    let record = message_record(
        &"22".repeat(32),
        &group_id_hex,
        MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
    );

    let update = received_message_update_from_record(
        "ac".repeat(32).as_str(),
        "alice",
        record,
        &HashMap::new(),
    )
    .expect("update");

    match update {
        RuntimeMessageUpdate::AgentStreamStarted(received) => {
            assert_eq!(received.message.message_id_hex, "22".repeat(32));
            assert_eq!(received.message.sender_display_name, None);
        }
        other => panic!("expected AgentStreamStarted update, got {other:?}"),
    }
}

#[test]
fn recovery_record_drops_undecodable_group_id() {
    let record = message_record(&"33".repeat(32), "not-hex", 9);
    let update = received_message_update_from_record(
        "ac".repeat(32).as_str(),
        "alice",
        record,
        &HashMap::new(),
    );
    assert!(update.is_none());
}

#[test]
fn messages_recovery_query_drops_initial_replay_limit() {
    // Regression for darkmatter#180 follow-up: the caller's `limit` is an
    // initial-replay cap (latest N rows). Reusing it on lag recovery would
    // reload only the latest N stored rows, so a limited subscriber could
    // still permanently lose messages between the last delivered id and
    // that latest row after broadcast lag. Recovery must drop the limit and
    // lean on `seen_message_ids` to dedupe.
    let group_id_hex = "cd".repeat(32);
    let query = AppMessageQuery {
        group_id_hex: Some(group_id_hex.clone()),
        limit: Some(1),
    };
    let recovery = messages_recovery_query(&query);
    assert_eq!(
        recovery.limit, None,
        "lag recovery must not inherit the initial replay limit"
    );
    assert_eq!(
        recovery.group_id_hex,
        Some(group_id_hex),
        "lag recovery must keep the caller's group filter"
    );
}

#[test]
fn messages_recovery_query_preserves_absent_group_filter() {
    // An all-groups subscription (group_id_hex == None) must recover across
    // all groups, still without a limit.
    let query = AppMessageQuery {
        group_id_hex: None,
        limit: Some(10),
    };
    let recovery = messages_recovery_query(&query);
    assert_eq!(recovery.group_id_hex, None);
    assert_eq!(recovery.limit, None);
}

#[test]
fn limited_subscription_recovery_suppresses_pre_subscription_history() {
    // Regression for the limited-snapshot lag-replay bug: a caller using
    // `limit: Some(N)` to avoid full-history replay must NOT receive the entire
    // older history as live updates on the first broadcast lag. Recovery drops
    // the limit and reloads the full group history, so the watermark
    // (the newest row that existed at subscription time = the last row of the
    // ascending limited snapshot) is what distinguishes pre-existing history
    // (suppress) from genuinely-new post-subscription messages (emit).
    //
    // Scenario: full history is rows recorded_at 10,20,30,40,50; a `limit: 2`
    // snapshot holds 40,50, so the watermark is (50, "id50"). On lag, recovery
    // reloads ALL five rows. Rows 10-50 are at/below the watermark and must be
    // suppressed; a genuinely-new row (60) arriving after subscription must be
    // emitted.
    let watermark = Some((50_u64, "id50".to_owned()));

    // Every pre-subscription row (including the watermark row itself) is
    // suppressed — even the ones the limited snapshot never contained (10/20/30).
    for (at, id) in [
        (10, "id10"),
        (20, "id20"),
        (30, "id30"),
        (40, "id40"),
        (50, "id50"),
    ] {
        assert!(
            recovery_row_is_pre_subscription(watermark.as_ref(), at, id),
            "row ({at}, {id}) existed at subscription time and must be suppressed on recovery"
        );
    }

    // A genuinely-new post-subscription row is emitted.
    assert!(
        !recovery_row_is_pre_subscription(watermark.as_ref(), 60, "id60"),
        "a message newer than the watermark is a real missed live update and must be emitted"
    );

    // Same-second tie-break: a row at the watermark timestamp but a larger
    // message id sorts strictly after the watermark and must be emitted.
    assert!(
        !recovery_row_is_pre_subscription(watermark.as_ref(), 50, "id99"),
        "same-timestamp row with a greater id sorts after the watermark and must be emitted"
    );

    // An empty snapshot has no watermark, so recovery suppresses nothing
    // (unchanged behavior for unlimited / empty-history subscriptions).
    assert!(!recovery_row_is_pre_subscription(None, 10, "id10"));
}

#[test]
fn lifecycle_refuses_account_open_after_shutdown_begins() {
    let lifecycle = RuntimeLifecycle::new();

    lifecycle.begin_shutdown();

    assert!(matches!(
        lifecycle.begin_account_open(),
        Err(AppError::RuntimeStopping)
    ));
}
