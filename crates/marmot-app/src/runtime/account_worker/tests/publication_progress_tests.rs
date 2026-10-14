use super::*;

/// Progress reaches the broadcast immediately; accounting cannot re-emit old
/// projection snapshots and distinguishes a closed subscriber set.
#[test]
fn projection_progress_counts_broadcast_results_without_buffering_snapshots() {
    let (events, mut receiver) = broadcast::channel(4);
    let progress = ProjectionPublicationProgress::new(events, "account", "label");
    let update = AppProjectionUpdate {
        group_id_hex: "group".into(),
        timeline_messages: Vec::new(),
        timeline_changes: Vec::new(),
        chat_list_row: None,
        chat_list_trigger: Default::default(),
    };
    progress.publish(update.clone());
    assert!(
        matches!(receiver.try_recv().unwrap(), MarmotAppEvent::ProjectionUpdated(received) if received.update == update)
    );
    drop(receiver);
    progress.publish(update);
    let publication = progress.take_publication();
    assert_eq!(publication.attempted, 2);
    assert_eq!(publication.accepted, 1);
    assert_eq!(publication.no_subscribers, 1);
    assert_eq!(progress.take_publication().attempted, 0);
}

/// Global wakeups alone are not account-local pressure; an active admission is.
#[tokio::test]
async fn secondary_retry_observer_ignores_unrelated_wakes_and_never_waits_on_admission() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    drop(client_on_app_relay_plane(&app, "alice").await);
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    let (wake, receiver) = watch::channel(());
    let (_stop, stopping) = watch::channel(false);
    let observe = wait_for_local_submission_or_shutdown(
        app.clone(),
        "alice".to_owned(),
        gate.clone(),
        receiver,
        stopping,
    );
    tokio::pin!(observe);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), observe.as_mut())
            .await
            .is_err()
    );
    wake.send_replace(());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), observe.as_mut())
            .await
            .is_err(),
        "another account's wake must not interrupt this account's retry"
    );
    let admission = gate.lock().await;
    wake.send_replace(());
    tokio::time::timeout(Duration::from_millis(100), observe)
        .await
        .expect("optional relay work must yield instead of blocking behind admission");
    drop(admission);
    // A new pass must not retain the previous signal once admission has ended.
    let (stop, stopping) = watch::channel(false);
    let fresh = wait_for_local_submission_or_shutdown(
        app,
        "alice".to_owned(),
        gate,
        wake.subscribe(),
        stopping,
    );
    tokio::pin!(fresh);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fresh.as_mut())
            .await
            .is_err()
    );
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_millis(100), fresh)
        .await
        .expect("shutdown must also release optional relay waits");
}
