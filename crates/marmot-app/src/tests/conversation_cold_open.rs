//! Public runtime cold-opening regressions. Relay holds are explicit barriers;
//! elapsed timings are diagnostic, not a device-performance claim.
use super::*;
use crate::runtime::{ConversationOpenQuery, ConversationOpenTarget};
use cgka_traits::storage::MessageStorage;

#[path = "conversation_cold_open/local_submissions.rs"]
mod local_submissions;

struct History {
    _dir: tempfile::TempDir,
    app: MarmotApp,
    relay: Arc<ScriptedPushRelayClient>,
    group: GroupId,
    account: String,
}
impl History {
    async fn new(count: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("cold history", &[]).await.unwrap();
        let store = app.account_storage("alice").unwrap();
        let group_hex = hex::encode(group.as_slice());
        let epoch = client.runtime.group_record(&group).unwrap().epoch;
        cgka_traits::StorageProvider::with_transaction(&store, |store| {
            for i in 0..count {
                let source = format!("{:064x}", i + 100_000);
                store.put_message(&cgka_traits::MessageRecord {
                    id: cgka_traits::MessageId::new(hex::decode(&source).unwrap()),
                    group_id: group.clone(),
                    epoch,
                    state: cgka_traits::MessageState::Processed,
                    payload: vec![0; 4096],
                    deferred_peel: None,
                })?;
                store.record_app_event(&storage_sqlite::StoredAppEvent {
                    group_id_hex: group_hex.clone(),
                    message_id_hex: format!("{i:064x}"),
                    source_message_id_hex: Some(source),
                    source_epoch: Some(epoch.0),
                    direction: "received".into(),
                    sender: "bb".repeat(32),
                    plaintext: format!("retained message {i}"),
                    kind: 9,
                    tags: vec![],
                    recorded_at: 100 + i as u64,
                    received_at: 100 + i as u64,
                    origin_commit_id: None,
                    moderation_grant: false,
                })?;
            }
            Ok::<_, cgka_traits::StorageError>(())
        })
        .unwrap();
        store
            .refresh_chat_list_row(&account.account_id_hex, &group_hex, &|_, _| false)
            .unwrap();
        drop(client);
        Self {
            _dir: dir,
            app,
            relay,
            group,
            account: account.account_id_hex,
        }
    }
}

#[tokio::test]
async fn live_window_observes_pending_send_while_relay_publish_is_blocked() {
    check_pending_send(false, false).await;
    check_pending_send(true, false).await;
    check_pending_send(false, true).await;
}

async fn check_pending_send(draft: bool, fail: bool) {
    let h = History::new(200).await;
    let runtime = MarmotAppRuntime::new(h.app.clone());
    let mut window = runtime
        .open_conversation_window(
            "alice",
            &h.group,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Latest,
                limit: 50,
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while window.snapshot.presentation.header.epoch.is_none() {
            window.snapshot = window.recv().await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
    // A second viewport must keep its own query while the latest window follows sends.
    let mut history = runtime
        .open_conversation_window(
            "alice",
            &h.group,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Message(format!("{:064x}", 20)),
                limit: 10,
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while history.snapshot.presentation.header.epoch.is_none() {
            history.snapshot = history.recv().await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
    let historical_ids: Vec<_> = history
        .snapshot
        .page
        .page()
        .messages
        .iter()
        .map(|r| r.message_id_hex.clone())
        .collect();
    let revision = if draft {
        let selected = runtime
            .selected_message_draft("alice", &hex::encode(h.group.as_slice()))
            .unwrap();
        Some(
            runtime
                .save_message_draft_if_revision(
                    "alice",
                    &selected.revision,
                    "pending window message",
                    None,
                    vec![],
                )
                .unwrap()
                .revision,
        )
    } else {
        None
    };
    if fail {
        h.relay.reject_next_publish();
    }
    h.relay.block_next_publish();
    let sender = runtime.clone();
    let group = h.group.clone();
    let send = tokio::spawn(async move {
        match revision {
            Some(revision) => {
                sender
                    .send_message_draft("alice", &group, revision, vec![])
                    .await
            }
            None => {
                sender
                    .send_message("alice", &group, b"pending window message".to_vec())
                    .await
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(10), h.relay.wait_for_blocked_publish())
        .await
        .unwrap();
    let pending = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = window.recv().await.unwrap().unwrap();
            if snapshot
                .page
                .page()
                .messages
                .iter()
                .any(|row| row.plaintext == "pending window message")
            {
                return snapshot;
            }
        }
    })
    .await;
    assert!(!send.is_finished());
    h.relay.release_publish();
    let sent = tokio::time::timeout(Duration::from_secs(10), send)
        .await
        .unwrap()
        .unwrap();
    let pending =
        pending.expect("an open window must show the local row before publication completes");
    let row = pending
        .page
        .page()
        .messages
        .iter()
        .find(|row| row.plaintext == "pending window message")
        .unwrap();
    assert!(row.source_message_id_hex.is_none());
    assert!(pending.presentation.header.epoch.is_some());
    assert!(pending.presentation.header.capabilities.can_send);
    if fail {
        assert!(
            sent.is_err(),
            "a definitive publish failure must fail the send: {sent:?}"
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let updated = window.recv().await.unwrap().unwrap();
                if updated.page.page().messages.iter().any(|r| {
                    r.message_id_hex == row.message_id_hex
                        && r.invalidation_status.as_deref() == Some("local_publish_failed")
                }) {
                    break;
                }
            }
        })
        .await
        .expect("the open window must retract the pending send");
        runtime.shutdown_and_close().await.unwrap();
        return;
    }
    let sent = sent.unwrap();
    assert_eq!(sent.message_ids, vec![row.message_id_hex.clone()]);
    let delivered = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let updated = window.recv().await.unwrap().unwrap();
            if updated.page.page().messages.iter().any(|r| {
                r.message_id_hex == row.message_id_hex && r.source_message_id_hex.is_some()
            }) {
                return updated;
            }
        }
    })
    .await
    .unwrap();
    assert!(delivered.revision.sequence > pending.revision.sequence);
    assert_eq!(
        delivered
            .page
            .page()
            .messages
            .iter()
            .filter(|r| r.message_id_hex == row.message_id_hex)
            .count(),
        1
    );
    if draft {
        assert!(delivered.draft.draft.is_none());
    }
    let history = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match history
                .window_handle()
                .set_visible_anchor(&history.snapshot.revision, &historical_ids[5])
                .await
            {
                Err(crate::ConversationWindowError::StaleWindow) => {
                    history.snapshot = history.recv().await.unwrap().unwrap();
                }
                result => break result.unwrap(),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        history
            .page
            .page()
            .messages
            .iter()
            .map(|r| r.message_id_hex.clone())
            .collect::<Vec<_>>(),
        historical_ids
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn cold_open_renders_large_history_during_stalled_initial_sync() {
    for count in [200, 5_000] {
        let h = History::new(count).await;
        h.relay
            .block_account_inbox_subscribe(hex::decode(&h.account).unwrap());
        let runtime = MarmotAppRuntime::new(h.app.clone());
        runtime.reconcile_accounts().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(10),
            h.relay.wait_for_blocked_subscribe(),
        )
        .await
        .expect("production worker must be blocked in initial relay sync");
        let store = h.app.account_storage("alice").unwrap();
        let before_read = store
            .conversation_open(&hex::encode(h.group.as_slice()), Default::default())
            .unwrap()
            .read_state;
        let started = std::time::Instant::now();
        let opened = tokio::time::timeout(
            Duration::from_secs(2),
            runtime.open_conversation_window(
                "alice",
                &h.group,
                ConversationOpenQuery {
                    target: ConversationOpenTarget::Latest,
                    limit: 50,
                },
            ),
        )
        .await;
        eprintln!(
            "cold_open blocked_sync history={count} elapsed_ms={} completed={}",
            started.elapsed().as_millis(),
            opened.is_ok()
        );
        // Always release the test relay, including on the pre-fix failure path.
        if opened.is_err() {
            h.relay.release_subscribe();
            runtime.shutdown_and_close().await.unwrap();
        }
        let mut window = opened
            .expect("local window must not wait for relay sync")
            .unwrap();
        assert_eq!(window.snapshot.page.page().messages.len(), 50);
        assert_eq!(
            window
                .snapshot
                .page
                .page()
                .messages
                .last()
                .unwrap()
                .plaintext,
            format!("retained message {}", count - 1)
        );
        assert!(window.snapshot.presentation.header.epoch.is_none());
        assert!(!window.snapshot.presentation.header.capabilities.can_send);
        assert!(window.snapshot.read_state == before_read);
        // Paging also remains local while the same relay barrier is held.
        let page = window
            .window_handle()
            .page(
                &window.snapshot.revision,
                crate::runtime::ConversationPageDirection::Older,
                20,
            )
            .await
            .unwrap();
        assert_eq!(page.page.page().messages.len(), 70);
        assert!(!page.presentation.header.capabilities.can_send);
        h.relay.release_subscribe();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let update = window.recv().await.unwrap().unwrap();
                if update.presentation.header.epoch.is_some() {
                    assert!(update.presentation.header.capabilities.can_send);
                    assert_eq!(update.page.page().messages.len(), 70);
                    break;
                }
            }
        })
        .await
        .expect("quiet readiness must upgrade the existing window");
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn cold_open_before_hydration_and_after_runtime_restart_keeps_history_local() {
    let h = History::new(5_000).await;
    for _ in 0..2 {
        // Reconstruct exactly as a foreground host does after terminal close.
        let app = MarmotApp::with_relay_and_config(
            h._dir.path(),
            "wss://relay.example",
            crate::MarmotAppConfig::default().with_dev_startup_hydration_batch_delay_ms(60_000),
        )
        .with_test_relay_client(h.relay.clone());
        let runtime = MarmotAppRuntime::new(app);
        runtime.reconcile_accounts().await.unwrap();
        assert_eq!(
            runtime
                .unhydrated_group_count_for_test("alice")
                .await
                .unwrap(),
            1
        );
        let started = std::time::Instant::now();
        let window = tokio::time::timeout(
            Duration::from_secs(2),
            runtime.open_conversation_window(
                "alice",
                &h.group,
                ConversationOpenQuery {
                    target: ConversationOpenTarget::Latest,
                    limit: 50,
                },
            ),
        )
        .await
        .expect("stored history must bypass the startup hydration hold")
        .unwrap();
        eprintln!(
            "cold_open before_hydration history=5000 elapsed_ms={}",
            started.elapsed().as_millis()
        );
        assert_eq!(window.snapshot.page.page().messages.len(), 50);
        assert!(window.snapshot.presentation.header.epoch.is_none());
        assert!(!window.snapshot.presentation.header.capabilities.can_send);
        assert_eq!(
            runtime
                .unhydrated_group_count_for_test("alice")
                .await
                .unwrap(),
            1
        );
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "diagnostic retained-history hydration timing matrix"]
async fn cold_open_storage_and_hydration_timings() {
    for count in [200, 5_000] {
        let h = History::new(count).await;
        let plane = crate::relay_plane::MarmotRelayPlane::new(None, h.relay.clone());
        let mut client = h
            .app
            .local_client_with_relay_plane_and_hydration("alice", &plane, None, true)
            .await
            .unwrap();
        let store = h.app.account_storage("alice").unwrap();
        let start = std::time::Instant::now();
        let page = store
            .conversation_account_snapshot(&hex::encode(h.group.as_slice()), Default::default())
            .unwrap();
        let local_us = start.elapsed().as_micros();
        assert_eq!(page.page.page().messages.len(), 50);
        assert_eq!(client.runtime.session().unhydrated_group_ids().len(), 1);
        let start = std::time::Instant::now();
        assert!(
            client
                .runtime
                .session_mut()
                .ensure_group_hydrated(&h.group)
                .unwrap()
        );
        eprintln!(
            "cold_open phases history={count} local_capture_us={local_us} explicit_hydration_us={}",
            start.elapsed().as_micros()
        );
    }
}

#[tokio::test]
async fn return_to_latest_from_history_uses_send_checkpoint_before_relay_release() {
    let h = History::new(60).await;
    let runtime = MarmotAppRuntime::new(h.app.clone());
    let mut window = runtime
        .open_conversation_window(
            "alice",
            &h.group,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Message(format!("{:064x}", 10)),
                limit: 10,
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while window.snapshot.presentation.header.epoch.is_none() {
            window.snapshot = window.recv().await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
    h.relay.block_next_publish();
    let sender = runtime.clone();
    let group = h.group.clone();
    let sending = tokio::spawn(async move {
        sender
            .send_message("alice", &group, b"latest checkpoint message".to_vec())
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), h.relay.wait_for_blocked_publish())
        .await
        .unwrap();
    // Wait for a background read queued behind publication, so navigation must
    // supersede that read rather than relying on favorable executor ordering.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if runtime
                .app_performance_snapshot()
                .runtime_operations
                .iter()
                .any(|metric| {
                    metric.operation == crate::RuntimePerformanceOperation::ConversationCaptureQueue
                        && metric.in_flight > 0
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let handle = window.window_handle();
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match handle.return_to_latest(&window.snapshot.revision).await {
                Ok(snapshot) => break snapshot,
                Err(crate::ConversationWindowError::StaleWindow) => {
                    window.snapshot = window.recv().await.unwrap().unwrap();
                }
                Err(error) => panic!("navigation failed: {error:?}"),
            }
        }
    })
    .await;
    h.relay.release_publish();
    sending.await.unwrap().unwrap();
    let snapshot = result.expect("navigation waited for relay publication");
    assert!(
        snapshot
            .page
            .page()
            .messages
            .iter()
            .any(|row| row.plaintext == "latest checkpoint message"
                && row.source_message_id_hex.is_none())
    );
    runtime.shutdown_and_close().await.unwrap();
}
