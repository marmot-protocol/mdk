//! The local send submission queue: cross-account storage isolation, committed-deletion timing
//! boundaries, and durable sends to a group still waiting for hydration.

use super::*;
use cgka_traits::storage::StorageProvider;
use marmot_account::AccountHomeError;

fn queue_snapshot(runtime: &crate::MarmotAppRuntime) -> crate::RuntimePerformanceSnapshot {
    runtime
        .app_performance_snapshot()
        .runtime_operations
        .into_iter()
        .find(|snapshot| snapshot.operation == RuntimeOp::SendQueue)
        .unwrap()
}

struct HeldDatabase {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for HeldDatabase {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_account_admission_does_not_delay_sibling_send_or_resurrect_deleted_timing() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("blocked").unwrap();
    let bob = home.create_account("healthy").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let alice_group = app
        .client(&alice.label)
        .await
        .unwrap()
        .create_group("blocked group", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let bob_group = app
        .client(&bob.label)
        .await
        .unwrap()
        .create_group("healthy group", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    for account in [&alice, &bob] {
        runtime
            .accounts()
            .wait_for_account_network_startup_to_settle(&account.label)
            .await
            .unwrap();
    }
    let storage = app.account_storage(&alice.label).unwrap();
    let (entered, entered_wait) = oneshot::channel();
    let (release, release_wait) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        StorageProvider::with_transaction(&storage, |_| {
            entered.send(()).unwrap();
            release_wait
                .recv_timeout(Duration::from_secs(10))
                .expect("fixture releases blocked database");
            Ok::<_, AppError>(())
        })
        .unwrap();
    });
    let held = HeldDatabase {
        release: Some(release),
        thread: Some(thread),
    };
    entered_wait.await.unwrap();
    let account_gate = runtime
        .shared_services()
        .local_submission_gate(&alice.account_id_hex);
    let admitting = {
        let runtime = runtime.clone();
        let alice = alice.clone();
        tokio::spawn(async move {
            runtime
                .submit_text(
                    &alice.label,
                    &alice_group,
                    "blocked admission".into(),
                    "blocked-token".into(),
                )
                .await
        })
    };
    timeout(Duration::from_secs(2), async {
        while account_gate.try_lock().is_ok() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the blocked account owns its admission/selection gate");
    let healthy = timeout(Duration::from_secs(1), async {
        let accepted = runtime
            .submit_text(
                &bob.label,
                &bob_group,
                "healthy sibling".into(),
                "healthy-token".into(),
            )
            .await?;
        loop {
            if let Some(crate::LocalSendStatus::Completed(summary)) =
                runtime.local_send_status(&bob.label, &bob_group, "healthy-token")?
            {
                break Ok::<_, AppError>((accepted, summary));
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    // Removal must wait for the owned admission before committing its wipe
    // and cancelling observations. Only UUID/temp fixture identities exist.
    let removing = {
        let runtime = runtime.clone();
        let alice = alice.clone();
        tokio::spawn(async move { runtime.accounts().remove_account(&alice.label).await })
    };
    drop(held);
    let admitted = timeout(Duration::from_secs(5), admitting)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(admitted.client_token, "blocked-token");
    timeout(Duration::from_secs(5), removing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let (accepted, published) = healthy
        .expect("one account's database contention cannot postpone another account's durable send")
        .unwrap();
    assert_eq!(
        published.accept_disposition,
        cgka_traits::SendAcceptDisposition::Published
    );
    assert_eq!(published.published, 1);
    assert_eq!(published.message_ids, vec![accepted.message_id_hex]);
    assert!(matches!(
        home.account(&alice.label),
        Err(AccountHomeError::UnknownAccount(_))
    ));
    let snapshot = queue_snapshot(&runtime);
    assert_eq!(
        snapshot.in_flight, 0,
        "an admission cannot register phantom timing after committed deletion"
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_permanent_removal_preserves_live_row_timing_then_committed_removal_cancels_it() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("remove-held-send").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let group = app
        .client(&account.label)
        .await
        .unwrap()
        .create_group("retained send", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime
        .shared_services()
        .set_next_startup_sync_barrier(Arc::new(tokio::sync::Barrier::new(2)));
    runtime.reconcile_accounts().await.unwrap();
    let accepted = runtime
        .submit_text(
            &account.label,
            &group,
            "retain until removal commits".into(),
            "remove-token".into(),
        )
        .await
        .unwrap();
    assert!(matches!(
        runtime
            .local_send_status(&account.label, &group, "remove-token")
            .unwrap(),
        Some(crate::LocalSendStatus::Queued)
    ));
    assert_eq!(queue_snapshot(&runtime).in_flight, 1);
    let obstruction = home.root().join(".wipe-tombstones");
    fs_private::write_private(&obstruction, b"synthetic pre-commit failure").unwrap();
    let failed = runtime.accounts().remove_account(&account.label).await;
    assert!(failed.is_err());
    assert!(home.account(&account.label).is_ok());
    assert_eq!(
        app.account_storage(&account.label)
            .unwrap()
            .app_storage()
            .local_submission(&hex::encode(&group), "remove-token")
            .unwrap()
            .unwrap()
            .message_id_hex,
        accepted.message_id_hex
    );
    let snapshot = queue_snapshot(&runtime);
    assert_eq!(
        snapshot.in_flight, 1,
        "a pre-commit removal failure keeps the live admission instant"
    );
    assert_eq!(snapshot.cancelled, 0);
    std::fs::remove_file(obstruction).unwrap();
    runtime
        .accounts()
        .remove_account(&account.label)
        .await
        .unwrap();
    let snapshot = queue_snapshot(&runtime);
    assert_eq!(snapshot.in_flight, 0);
    assert_eq!(snapshot.cancelled, 1);
    assert!(matches!(
        home.account(&account.label),
        Err(AccountHomeError::UnknownAccount(_))
    ));
    runtime.shutdown_and_close().await.unwrap();
}

/// A send to a group still waiting for startup hydration stays queued, reaches
/// no relay before its safety work, survives a terminal close, and publishes
/// once after the restored worker hydrates the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unhydrated_durable_send_waits_for_safety_and_survives_terminal_close() {
    use nostr_relay_builder::prelude::{
        EventId, Filter as RelayFilter, Kind as RelayKind, MemoryDatabase, MemoryDatabaseOptions,
        NostrDatabase,
    };
    use nostr_relay_builder::{LocalRelay, RelayBuilder};
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(64),
    });
    let relay = LocalRelay::new(RelayBuilder::default().database(database.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("unhydrated")
        .unwrap();
    let normal = crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true);
    let group = {
        let fixture = MarmotApp::with_relay_and_config(dir.path(), url.clone(), normal.clone());
        let mut client = fixture.client(&account.label).await.unwrap();
        client
            .create_group("only unhydrated group", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members")
    };
    let held = normal
        .clone()
        .with_dev_startup_hydration_batch_delay_ms(30_000);
    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), held);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            if runtime
                .app_performance_snapshot()
                .runtime_operations
                .iter()
                .any(|snapshot| {
                    snapshot.operation == RuntimeOp::WorkerHydration && snapshot.in_flight == 1
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the sole stored group enters the held unhydrated pipeline");
    let before = database
        .query(RelayFilter::new().kind(RelayKind::MlsGroupMessage))
        .await
        .unwrap()
        .iter()
        .map(|event| event.id)
        .collect::<std::collections::HashSet<_>>();
    let token = "unhydrated-durable-token";
    let content = "send after hydration is safe";
    let accepted = runtime
        .submit_text(&account.label, &group, content.into(), token.into())
        .await
        .unwrap();
    sleep(Duration::from_millis(100)).await;
    assert!(matches!(
        runtime
            .local_send_status(&account.label, &group, token)
            .unwrap(),
        Some(crate::LocalSendStatus::Queued)
    ));
    assert_eq!(
        app.account_storage(&account.label)
            .unwrap()
            .app_storage()
            .local_submission(&hex::encode(&group), token)
            .unwrap()
            .unwrap()
            .state,
        0
    );
    let after = database
        .query(RelayFilter::new().kind(RelayKind::MlsGroupMessage))
        .await
        .unwrap()
        .iter()
        .map(|event| event.id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        after, before,
        "unhydrated sends cannot reach transport before required safety work"
    );
    assert_eq!(
        runtime
            .app_performance_snapshot()
            .outbound_message_queue_wait
            .attempts,
        0
    );
    timeout(Duration::from_secs(2), runtime.shutdown_and_close())
        .await
        .expect("terminal close interrupts the thirty-second hydration hold")
        .unwrap();
    drop(runtime);
    drop(app);
    let restored = MarmotApp::with_relay_and_config(dir.path(), url, normal);
    let restarted = crate::MarmotAppRuntime::new(restored.clone());
    restarted.reconcile_accounts().await.unwrap();
    let repeated = restarted
        .submit_text(&account.label, &group, content.into(), token.into())
        .await
        .unwrap();
    assert_eq!(repeated.message_id_hex, accepted.message_id_hex);
    let published = timeout(Duration::from_secs(15), async {
        loop {
            if let Some(crate::LocalSendStatus::Completed(summary)) = restarted
                .local_send_status(&account.label, &group, token)
                .unwrap()
            {
                break summary;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("one restored send publishes after real group hydration");
    assert_eq!(
        published.accept_disposition,
        cgka_traits::SendAcceptDisposition::Published
    );
    assert_eq!(published.published, 1);
    assert_eq!(published.message_ids, vec![accepted.message_id_hex.clone()]);
    let source = restored
        .account_storage(&account.label)
        .unwrap()
        .app_storage()
        .timeline_message(&hex::encode(&group), &accepted.message_id_hex)
        .unwrap()
        .unwrap()
        .source_message_id_hex
        .unwrap();
    assert!(
        database
            .event_by_id(&EventId::from_hex(&source).unwrap())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        restored
            .messages(&account.label)
            .unwrap()
            .iter()
            .filter(|message| message.plaintext == content)
            .count(),
        1
    );
    assert_eq!(
        restarted
            .app_performance_snapshot()
            .outbound_message_queue_wait
            .attempts,
        0
    );
    restarted.shutdown_and_close().await.unwrap();
    relay.shutdown();
}
