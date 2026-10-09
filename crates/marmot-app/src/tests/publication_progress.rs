//! Source projection must not wait for the rest of a queued publication batch.
use super::*;

async fn queued_messages(app: &MarmotApp) -> (AppClient, cgka_traits::GroupId, Vec<String>) {
    let mut client = client_on_app_relay_plane(app, "alice").await;
    let group = client
        .create_group("publication progress", &[])
        .await
        .unwrap();
    let sender = hex::encode(client.runtime.session().self_id().as_slice());
    let mut ids = Vec::new();
    for content in ["first queued message", "second queued message"] {
        let event = build_inner_event(
            &AppMessageIntent::Chat {
                content: content.to_owned(),
            },
            &sender,
            unix_now_seconds(),
        )
        .unwrap();
        client
            .record_send_intent_projection(&group, &sender, &event)
            .unwrap();
        client
            .runtime
            .session_mut()
            .queue_app_message_with_audit_context(
                group.clone(),
                event.encode().unwrap(),
                Default::default(),
            )
            .await
            .unwrap();
        ids.push(event.id);
    }
    (client, group, ids)
}

#[tokio::test]
async fn queued_publication_projects_first_message_before_later_publish_finishes() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(relay.clone());
    let (mut client, group, ids) = queued_messages(&app).await;
    let published_before = relay.published_events.lock().unwrap().len();
    let updates = Arc::new(std::sync::Mutex::new(Vec::new()));
    let progress = updates.clone();
    relay.block_next_publish();
    let advance = client.advance_convergence_with_projection_progress(
        &group,
        Some(Arc::new(move |update| {
            progress.lock().unwrap().push(update);
        })),
    );
    tokio::pin!(advance);
    tokio::select! {
        result = &mut advance => panic!("batch returned before first hold: {result:?}"),
        result = tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish()) => result.unwrap()
    }
    relay.block_next_publish();
    relay.release_publish();
    tokio::select! {
        result = &mut advance => panic!("batch returned before second hold: {result:?}"),
        result = tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish()) => result.unwrap()
    }
    assert_eq!(
        relay.published_events.lock().unwrap().len(),
        published_before + 1,
        "the first message is accepted while the second remains at the relay hold"
    );
    let rows = app
        .timeline_messages_with_query(
            "alice",
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group.as_slice())),
                ..Default::default()
            },
        )
        .unwrap()
        .messages;
    let first = rows
        .iter()
        .find(|row| row.message_id_hex == ids[0])
        .unwrap();
    assert!(
        first.source_message_id_hex.is_some(),
        "the first accepted publication must leave Pending while the second publish is held"
    );
    assert_eq!(
        first.source_message_id_hex.as_deref(),
        Some(
            relay
                .published_events
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .id
                .as_str()
        ),
        "the early source must identify this exact accepted relay event"
    );
    assert!(
        updates.lock().unwrap().iter().any(|update| update
            .timeline_messages
            .iter()
            .any(|row| row.message_id_hex == ids[0]
                && row.source_message_id_hex == first.source_message_id_hex)),
        "the worker sink receives the committed source before the tail completes"
    );
    assert!(
        rows.iter()
            .find(|row| row.message_id_hex == ids[1])
            .unwrap()
            .source_message_id_hex
            .is_none()
    );
    relay.release_publish();
    let summary = tokio::time::timeout(Duration::from_secs(5), advance)
        .await
        .unwrap()
        .unwrap();
    assert!(
        summary.projection_updates.is_empty(),
        "immediate updates must not be replayed as stale final snapshots"
    );
    assert_eq!(updates.lock().unwrap().len(), 2);
}

fn projection_connection(app: &MarmotApp) -> rusqlite::Connection {
    let path = app.account_storage_path("alice");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let key = app
        .sqlcipher_key("alice", &keys, &path, SqlcipherDatabaseKind::Session)
        .unwrap();
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
}

/// Projection failure cannot discard the unstaged publication tail. Retained
/// receipts repair both rows after reopen without publishing their bytes again.
#[tokio::test]
async fn queued_publication_projection_failure_reopens_without_republishing() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(relay.clone());
    let (mut client, group, ids) = queued_messages(&app).await;
    let connection = projection_connection(&app);
    connection
        .execute_batch(
            "CREATE TRIGGER fail_projection BEFORE UPDATE ON app_events
        WHEN NEW.source_message_id_hex IS NOT NULL AND OLD.source_message_id_hex IS NULL
        BEGIN SELECT RAISE(ABORT, 'injected source write failure'); END;",
        )
        .unwrap();
    let attempts = relay.attempted_event_ids().len();
    client
        .advance_convergence_after_runtime_sync(&group)
        .await
        .unwrap();
    assert_eq!(
        relay.attempted_event_ids().len(),
        attempts + 2,
        "both queued messages publish despite early projection failure"
    );
    assert_eq!(
        client
            .runtime
            .session()
            .outbound_fanouts_for_group(&group)
            .unwrap()
            .len(),
        2
    );
    for id in &ids {
        assert!(
            app.timeline_message("alice", &hex::encode(group.as_slice()), id)
                .unwrap()
                .unwrap()
                .source_message_id_hex
                .is_none()
        );
    }
    drop(client);
    connection
        .execute_batch("DROP TRIGGER fail_projection")
        .unwrap();
    drop(connection);
    let mut reopened = app
        .local_client_with_relay_plane("alice", &app.relay_plane, None)
        .await
        .unwrap();
    reopened.prepare_transport().await.unwrap();
    let before_replay = relay.attempted_event_ids();
    let summary = reopened
        .advance_convergence_after_runtime_sync(&group)
        .await
        .unwrap();
    assert_eq!(summary.projection_updates.len(), 2);
    assert!(
        reopened
            .runtime
            .session()
            .outbound_fanouts_for_group(&group)
            .unwrap()
            .is_empty()
    );
    for id in &ids {
        assert!(
            app.timeline_message("alice", &hex::encode(group.as_slice()), id)
                .unwrap()
                .unwrap()
                .source_message_id_hex
                .is_some()
        );
    }
    assert!(
        reopened
            .advance_convergence_after_runtime_sync(&group)
            .await
            .unwrap()
            .projection_updates
            .is_empty()
    );
    assert_eq!(
        relay.attempted_event_ids(),
        before_replay,
        "receipt replay and idempotent finalization never republish"
    );
}

/// Cancelling a batch must drop its callback as well as its network wait.
#[tokio::test]
async fn queued_publication_cancel_removes_scoped_observer() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(relay.clone());
    let (mut client, group, _) = queued_messages(&app).await;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = calls.clone();
    relay.block_next_publish();
    let mut advance = Box::pin(
        client
            .runtime
            .advance_convergence_with_publication_progress(
                &group,
                Arc::new(move |_, _| {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }),
            ),
    );
    tokio::select! {
        result = &mut advance => panic!("batch returned before hold: {result:?}"),
        result = tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish()) => result.unwrap()
    }
    drop(advance);
    assert_eq!(
        Arc::strong_count(&calls),
        1,
        "cancelled callback must release its captured state"
    );
    relay.release_publish();
    client
        .send(&group, b"ordinary send after cancellation")
        .await
        .unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// An early acceptance updates source metadata only; it cannot recreate an
/// absent event or clear a convergence withdrawal.
#[tokio::test]
async fn queued_publication_progress_does_not_revive_deleted_or_withdrawn_rows() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app =
        MarmotApp::with_relay(dir.path(), "wss://progress.example").with_test_relay_client(relay);
    let (mut client, group, ids) = queued_messages(&app).await;
    let connection = projection_connection(&app);
    connection
        .execute(
            "DELETE FROM app_events WHERE message_id_hex = ?1",
            [&ids[0]],
        )
        .unwrap();
    app.invalidate_timeline_app_event(
        "alice",
        &hex::encode(group.as_slice()),
        &ids[1],
        "epoch_invalidated",
    )
    .unwrap();
    client
        .advance_convergence_after_runtime_sync(&group)
        .await
        .unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM app_events WHERE message_id_hex = ?1",
            [&ids[0]],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    let row = app
        .timeline_message("alice", &hex::encode(group.as_slice()), &ids[1])
        .unwrap()
        .unwrap();
    assert_eq!(
        row.invalidation_status.as_deref(),
        Some("epoch_invalidated")
    );
}

/// A mixed batch error must not place an early source snapshot after the
/// finalizer's newer guarded revival of the same local row.
#[tokio::test]
async fn queued_publication_mixed_failure_keeps_progress_before_revival() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(relay.clone());
    let (mut client, group, ids) = queued_messages(&app).await;
    let group_hex = hex::encode(group.as_slice());
    app.invalidate_timeline_app_event(
        "alice",
        &group_hex,
        &ids[0],
        crate::LOCAL_PUBLISH_FAILED_REASON,
    )
    .unwrap();
    relay.block_next_publish();
    {
        let advance = client.advance_convergence_after_runtime_sync(&group);
        tokio::pin!(advance);
        tokio::select! {
            result = &mut advance => panic!("batch returned before first hold: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish()) => result.unwrap()
        }
        relay.block_next_publish();
        relay.release_publish();
        tokio::select! {
            result = &mut advance => panic!("batch returned before second hold: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish()) => result.unwrap()
        }
        let row = app
            .timeline_message("alice", &group_hex, &ids[0])
            .unwrap()
            .unwrap();
        assert!(row.source_message_id_hex.is_some());
        assert_eq!(
            row.invalidation_status.as_deref(),
            Some(crate::LOCAL_PUBLISH_FAILED_REASON),
            "the early path must leave revival to the guarded finalizer"
        );
        relay.reject_next_publish();
        relay.release_publish();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), advance)
                .await
                .unwrap()
                .is_err()
        );
    }
    let summary = tokio::time::timeout(Duration::from_secs(5), client.next_event())
        .await
        .expect("committed progress must reach the public consumer")
        .unwrap();
    assert!(client.take_pending_projection_updates().is_empty());
    assert!(
        client
            .take_pending_applied_sync_summary()
            .projection_updates
            .is_empty(),
        "the public consumer transfers the retained output exactly once"
    );
    let first_snapshots = summary
        .projection_updates
        .iter()
        .flat_map(|update| &update.timeline_messages)
        .filter(|row| row.message_id_hex == ids[0])
        .collect::<Vec<_>>();
    assert!(first_snapshots.len() >= 2);
    assert_eq!(
        first_snapshots
            .first()
            .unwrap()
            .invalidation_status
            .as_deref(),
        Some(crate::LOCAL_PUBLISH_FAILED_REASON)
    );
    assert_eq!(
        first_snapshots.last().unwrap().invalidation_status,
        None,
        "the final delivered snapshot must supersede earlier failed state"
    );
}

/// Dropping a later network wait must retain already committed publication
/// updates for the next public consumer without sending accepted bytes again.
#[tokio::test]
async fn queued_publication_cancel_retains_committed_progress_once() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(relay.clone());
    let (mut client, group, ids) = queued_messages(&app).await;
    relay.block_next_publish();
    {
        let advance = client.advance_convergence_after_runtime_sync(&group);
        tokio::pin!(advance);
        tokio::select! {
            result = &mut advance => panic!("batch returned before first hold: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish()) => result.unwrap()
        }
        relay.block_next_publish();
        relay.release_publish();
        tokio::select! {
            result = &mut advance => panic!("batch returned before second hold: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish()) => result.unwrap()
        }
    }
    let accepted = relay.published_event_ids().last().unwrap().clone();
    let summary = tokio::time::timeout(Duration::from_secs(5), client.next_event())
        .await
        .expect("committed progress must reach the public consumer")
        .unwrap();
    let first = summary
        .projection_updates
        .iter()
        .flat_map(|update| &update.timeline_messages)
        .filter(|row| row.message_id_hex == ids[0])
        .collect::<Vec<_>>();
    assert_eq!(first.len(), 1, "cancellation retains the committed prefix");
    let source = first[0].source_message_id_hex.clone();
    assert!(source.is_some());
    assert!(client.take_pending_projection_updates().is_empty());
    assert!(
        client
            .take_pending_applied_sync_summary()
            .projection_updates
            .is_empty()
    );
    relay.release_publish();
    let resumed = client
        .advance_convergence_after_runtime_sync(&group)
        .await
        .unwrap();
    assert!(
        resumed
            .projection_updates
            .iter()
            .flat_map(|update| &update.timeline_messages)
            .all(|row| row.message_id_hex != ids[0]),
        "delivered progress must not repeat"
    );
    assert_eq!(
        app.timeline_message("alice", &hex::encode(group.as_slice()), &ids[0])
            .unwrap()
            .unwrap()
            .source_message_id_hex,
        source
    );
    assert_eq!(
        relay
            .attempted_event_ids()
            .iter()
            .filter(|id| **id == accepted)
            .count(),
        1
    );
}

/// The finalizer can suspend after guarded revival. Cancellation must keep the
/// older source snapshot before that revival in the shared retained summary.
#[tokio::test]
async fn queued_publication_cancel_finalizer_keeps_progress_before_revival() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(relay.clone());
    let (mut client, group, ids) = queued_messages(&app).await;
    let group_hex = hex::encode(group.as_slice());
    let pending_route = client
        .create_group_with_options_and_telemetry(
            "pending route",
            &[],
            Default::default(),
            &AppPerformanceTelemetry::default(),
        )
        .await
        .unwrap()
        .group_id;
    // Leave a real uninstalled group route for the finalizer's route refresh.
    client
        .routing
        .replace_group_routes(&pending_route, Vec::new());
    app.invalidate_timeline_app_event(
        "alice",
        &group_hex,
        &ids[0],
        crate::LOCAL_PUBLISH_FAILED_REASON,
    )
    .unwrap();
    relay.block_next_subscribe();
    {
        let advance = client.advance_convergence_after_runtime_sync(&group);
        tokio::pin!(advance);
        tokio::select! {
            result = &mut advance => panic!("finalizer should block: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_subscribe()) => result.unwrap()
        }
        let row = app
            .timeline_message("alice", &group_hex, &ids[0])
            .unwrap()
            .unwrap();
        assert!(row.source_message_id_hex.is_some());
        assert!(
            row.invalidation_status.is_none(),
            "the finalizer already revived the row"
        );
    }
    relay.release_subscribe();
    let attempts = relay.attempted_event_ids();
    let summary = tokio::time::timeout(Duration::from_secs(5), client.next_event())
        .await
        .expect("committed progress must reach the public consumer")
        .unwrap();
    let first = summary
        .projection_updates
        .iter()
        .flat_map(|update| &update.timeline_messages)
        .filter(|row| row.message_id_hex == ids[0])
        .collect::<Vec<_>>();
    assert_eq!(first.len(), 2);
    assert_eq!(
        first[0].invalidation_status.as_deref(),
        Some(crate::LOCAL_PUBLISH_FAILED_REASON)
    );
    assert!(first[1].invalidation_status.is_none());
    assert!(client.take_pending_projection_updates().is_empty());
    assert!(
        client
            .take_pending_applied_sync_summary()
            .projection_updates
            .is_empty()
    );
    assert!(
        client
            .advance_convergence_after_runtime_sync(&group)
            .await
            .unwrap()
            .projection_updates
            .is_empty()
    );
    assert_eq!(
        relay.attempted_event_ids(),
        attempts,
        "repair must not republish accepted messages"
    );
}

/// The primary selected-conversation stream must expose a committed source while
/// the real worker is still waiting on a later publication in the same pass.
#[tokio::test]
async fn queued_publication_updates_live_window_before_later_publish_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(relay.clone());
    let (client, group, ids) = queued_messages(&app).await;
    drop(client);
    struct HeldSchedule(String);
    impl Drop for HeldSchedule {
        fn drop(&mut self) {
            crate::runtime::account_worker::HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
                .lock()
                .unwrap()
                .remove(&self.0);
        }
    }
    crate::runtime::account_worker::HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
        .lock()
        .unwrap()
        .insert(account.account_id_hex.clone());
    let held_schedule = HeldSchedule(account.account_id_hex);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let mut window = runtime
        .open_conversation_window("alice", &group, Default::default())
        .await
        .unwrap();
    while window.snapshot.presentation.header.epoch.is_none() {
        window.snapshot = tokio::time::timeout(Duration::from_secs(5), window.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    assert!(window.snapshot.presentation.header.capabilities.can_send);
    assert!(
        window
            .snapshot
            .page
            .page()
            .messages
            .iter()
            .find(|row| row.message_id_hex == ids[0])
            .unwrap()
            .source_message_id_hex
            .is_none()
    );
    let published_before = relay.published_events.lock().unwrap().len();
    relay.block_next_publish();
    drop(held_schedule);
    // Wake the worker after releasing the test-only scheduled-pass gate.
    runtime
        .group_recovery_status("alice", &group)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), relay.wait_for_blocked_publish())
        .await
        .unwrap();
    relay.block_next_publish();
    relay.release_publish();
    tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish())
        .await
        .unwrap();
    assert_eq!(
        relay.published_events.lock().unwrap().len(),
        published_before + 1
    );
    let expected_source = relay
        .published_events
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .id
        .clone();
    let committed = app
        .timeline_message("alice", &hex::encode(group.as_slice()), &ids[0])
        .unwrap()
        .unwrap();
    assert_eq!(
        committed.source_message_id_hex.as_ref(),
        Some(&expected_source)
    );
    let observed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = window.recv().await.unwrap().unwrap();
            if snapshot.page.page().messages.iter().any(|row| {
                row.message_id_hex == ids[0]
                    && row.source_message_id_hex.as_ref() == Some(&expected_source)
            }) {
                break snapshot;
            }
        }
    })
    .await;
    // Release and close even on the expected RED timeout.
    relay.release_publish();
    runtime.shutdown_and_close().await.unwrap();
    let observed = observed.expect("live conversation must show the first accepted source before the later publication is released");
    assert!(observed.presentation.header.epoch.is_some());
    assert!(observed.presentation.header.capabilities.can_send);
    assert!(
        observed
            .page
            .page()
            .messages
            .iter()
            .find(|row| row.message_id_hex == ids[1])
            .unwrap()
            .source_message_id_hex
            .is_none()
    );
}

/// A due, confirmed replica retry cannot retain the owner while a new durable send waits.
#[tokio::test]
async fn durable_send_interrupts_due_secondary_retry_and_updates_live_window() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(relay.clone());
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client
        .create_group_with_options(
            "secondary retry progress",
            &[],
            AppCreateGroupOptions {
                relays: Some(vec![
                    "wss://index.example".to_owned(),
                    "wss://progress.example".to_owned(),
                ]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    drop(client);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let mut window = runtime
        .open_conversation_window("alice", &group, Default::default())
        .await
        .unwrap();
    while window.snapshot.presentation.header.epoch.is_none() {
        window.snapshot = tokio::time::timeout(Duration::from_secs(5), window.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    relay
        .block_indexer_publish
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let first = runtime
        .submit_text(
            "alice",
            &group,
            "confirmed before retry".to_owned(),
            "secondary-first".to_owned(),
        )
        .await
        .unwrap();
    let original_source = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = window.recv().await.unwrap().unwrap();
            if let Some(source) = snapshot
                .page
                .page()
                .messages
                .iter()
                .find(|row| row.message_id_hex == first.message_id_hex)
                .and_then(|row| row.source_message_id_hex.clone())
            {
                break source;
            }
        }
    })
    .await
    .expect("initial publication must reach quorum with secondary ACK withheld");
    // Consume the initial attempt's notification. The next notification proves
    // the ordinary persisted retry deadline has actually elapsed and its ACK
    // wait is in flight, reproducing the device overlap without policy overrides.
    tokio::time::timeout(
        Duration::from_secs(5),
        relay.indexer_publish_started.notified(),
    )
    .await
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(40),
        relay.indexer_publish_started.notified(),
    )
    .await
    .expect("confirmed secondary retry must start on its normal deadline");
    let attempts_before = relay.attempted_events.lock().unwrap().len();
    assert_eq!(
        relay.attempted_events.lock().unwrap().last().unwrap().id,
        original_source,
        "the held operation must be the exact already-accepted publication's retry"
    );
    let accepted = runtime
        .submit_text(
            "alice",
            &group,
            "foreground during secondary retry".to_owned(),
            "secondary-foreground".to_owned(),
        )
        .await
        .unwrap();
    let observed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = window.recv().await.unwrap().unwrap();
            if snapshot.page.page().messages.iter().any(|row| {
                row.message_id_hex == accepted.message_id_hex && row.source_message_id_hex.is_some()
            }) {
                break snapshot;
            }
        }
    })
    .await;
    // Release even on RED so neither a relay hold nor shutdown hides the failure.
    relay
        .block_indexer_publish
        .store(false, std::sync::atomic::Ordering::SeqCst);
    relay.indexer_publish_release.notify_waiters();
    runtime.shutdown_and_close().await.unwrap();
    let observed = observed.expect(
        "new durable send must publish and project while the old secondary ACK remains withheld",
    );
    assert!(observed.presentation.header.capabilities.can_send);
    assert!(relay.attempted_events.lock().unwrap().len() > attempts_before);
}
