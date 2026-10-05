//! Cross-account storage isolation and committed-deletion timing boundaries.

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
        .unwrap();
    let bob_group = app
        .client(&bob.label)
        .await
        .unwrap()
        .create_group("healthy group", &[])
        .await
        .unwrap();
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

#[tokio::test]
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
        .unwrap();
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
