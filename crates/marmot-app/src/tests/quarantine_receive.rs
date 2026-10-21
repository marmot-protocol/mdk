//! mdk#2318: a hydration-quarantined group must not stall the managed worker's
//! receive loop for the account's healthy conversations.
use super::*;
use cgka_traits::storage::MessageStorage;

const SNAPSHOTS: [&str; 2] = ["openmls-apply-incident-a", "openmls-apply-incident-b"];

async fn wait_for_message(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    account_label: &str,
    plaintext: &str,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Ok(MarmotAppEvent::MessageReceived(update))
                    if update.account_label == account_label
                        && update.message.plaintext == plaintext =>
                {
                    break;
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    panic!("runtime event stream closed before MessageReceived")
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{account_label} never received {plaintext:?}"));
}

async fn start_runtime(
    app: &MarmotApp,
    relay: Arc<ScriptedPushRelayClient>,
) -> (MarmotAppRuntime, ScriptedEosePump) {
    let eose = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    (runtime, eose)
}

async fn wait_for_joined(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    account_id_hex: &str,
    group: &GroupId,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Ok(MarmotAppEvent::GroupJoined {
                    account_id_hex: joined_account,
                    group_id,
                    ..
                }) if joined_account == account_id_hex && group_id == *group => break,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    panic!("runtime event stream closed before GroupJoined")
                }
            }
        }
    })
    .await
    .expect("bob joins the group");
}

async fn quarantined_group_does_not_block_account_receives_body(locally_deleted: bool) {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    remember_test_member_inbox(&app, &alice.account_id_hex, "wss://relay.example");
    remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");

    let (runtime, eose) = start_runtime(&app, relay.clone()).await;
    let mut events = runtime.subscribe();
    let bob_members = std::slice::from_ref(&bob.account_id_hex);
    let broken = runtime
        .create_group("alice", "quarantined", bob_members, None)
        .await
        .unwrap();
    wait_for_joined(&mut events, &bob.account_id_hex, &broken).await;
    let healthy = runtime
        .create_group("alice", "healthy", bob_members, None)
        .await
        .unwrap();
    wait_for_joined(&mut events, &bob.account_id_hex, &healthy).await;
    runtime
        .send_message("alice", &healthy, b"warmup alice".to_vec())
        .await
        .unwrap();
    wait_for_message(&mut events, "bob", "warmup alice").await;
    runtime
        .send_message("bob", &healthy, b"warmup bob".to_vec())
        .await
        .unwrap();
    wait_for_message(&mut events, "alice", "warmup bob").await;
    if locally_deleted {
        assert!(runtime.delete_group_local("alice", &broken).await.unwrap());
    }
    runtime.shutdown().await;
    drop(eose);

    // Two ambiguous apply snapshots make alice's next open quarantine the
    // group with the production reason, without touching its stored state.
    let storage = app.account_storage("alice").unwrap();
    for snapshot in SNAPSHOTS {
        storage.create_group_snapshot(&broken, snapshot).unwrap();
    }

    // The second pass is a restart that re-quarantines the same group.
    let broken_hex = hex::encode(broken.as_slice());
    let mut held = Vec::new();
    for pass in 0..2 {
        // A restart is a fresh process: new app, relay plane and workers.
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let (runtime, _eose) = start_runtime(&app, relay.clone()).await;
        let mut events = runtime.subscribe();
        let quarantined = runtime.quarantined_groups("alice").await.unwrap();
        assert_eq!(quarantined.len(), 1, "pass {pass}");
        assert_eq!(
            quarantined[0].reason,
            crate::AppGroupHydrationQuarantineReason::GroupRecordLoadFailed
        );

        // The worker drains alice's startup quarantine event before serving
        // commands, so this covers the drain entry. The send-before-drain
        // ordering is pinned by the client-level projection retry test.
        let outgoing = format!("alice outgoing {pass}");
        runtime
            .send_message("alice", &healthy, outgoing.clone().into_bytes())
            .await
            .unwrap();
        wait_for_message(&mut events, "bob", &outgoing).await;

        // Bob also writes in the quarantined group. Alice's copy keeps a
        // route for it, and the engine holds the input until recovery.
        let quarantined_incoming = format!("bob in quarantined {pass}");
        runtime
            .send_message("bob", &broken, quarantined_incoming.clone().into_bytes())
            .await
            .unwrap();
        held.push(quarantined_incoming);

        let incoming = format!("bob incoming {pass}");
        runtime
            .send_message("bob", &healthy, incoming.clone().into_bytes())
            .await
            .unwrap();
        let mut applied_while_quarantined = false;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match events.recv().await {
                    Ok(MarmotAppEvent::MessageReceived(update))
                        if update.account_label == "alice" =>
                    {
                        applied_while_quarantined |= held.contains(&update.message.plaintext);
                        if update.message.plaintext == incoming {
                            break;
                        }
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        panic!("runtime event stream closed before MessageReceived")
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("alice never received {incoming:?}"));
        assert!(
            !applied_while_quarantined,
            "pass {pass}: a quarantined group's input waits for recovery"
        );
        assert_eq!(
            runtime.quarantined_groups("alice").await.unwrap().len(),
            1,
            "pass {pass}: the unhealthy group stays quarantined"
        );
        if locally_deleted {
            assert!(
                app.group("alice", &broken_hex).unwrap().is_none(),
                "pass {pass}: a locally deleted chat stays hidden"
            );
        }
        runtime.shutdown().await;
    }

    // Repair the fixture and recover the group in place. What bob sent
    // while it was quarantined is applied, restoring a deleted chat.
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let (runtime, _eose) = start_runtime(&app, relay.clone()).await;
    let mut events = runtime.subscribe();
    for snapshot in SNAPSHOTS {
        storage.release_group_snapshot(&broken, snapshot).unwrap();
    }
    assert!(
        runtime
            .retry_hydrate_quarantined_group("alice", &broken)
            .await
            .unwrap()
    );
    for message in &held {
        wait_for_message(&mut events, "alice", message).await;
    }
    assert!(app.group("alice", &broken_hex).unwrap().is_some());
    runtime.shutdown().await;
}

#[test]
fn quarantined_group_does_not_block_account_receives() {
    run_composed_app_runtime_test("quarantine-receive", || {
        quarantined_group_does_not_block_account_receives_body(false)
    });
}

#[test]
fn locally_deleted_quarantined_group_does_not_block_account_receives() {
    run_composed_app_runtime_test("quarantine-receive-deleted", || {
        quarantined_group_does_not_block_account_receives_body(true)
    });
}
