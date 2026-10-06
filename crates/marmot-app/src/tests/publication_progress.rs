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
                Arc::new(move |_| {
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
    let updates = client.take_pending_projection_updates();
    let first_snapshots = updates
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
