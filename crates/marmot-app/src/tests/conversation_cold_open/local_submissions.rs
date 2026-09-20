use super::*;
use crate::local_submissions::LocalMessageRequest;

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
    // Wait for the actor's ordinary fresh read to queue behind the held send.
    // The latest command must supersede this background read, rather than only
    // working when it happens to arrive before the actor starts that read.
    tokio::time::timeout(Duration::from_secs(2), async {
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
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let handle = window.window_handle();
    let result = tokio::time::timeout(Duration::from_secs(2), async {
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

#[tokio::test]
async fn durable_admission_is_atomic_correlated_and_retry_stable() {
    let h = History::new(0).await;
    let group = hex::encode(h.group.as_slice());
    let selected = h.app.selected_message_draft("alice", &group).unwrap();
    let saved = h
        .app
        .save_message_draft_if_revision("alice", &selected.revision, "same text", None, vec![])
        .unwrap();
    let request = LocalMessageRequest {
        content: String::new(),
        reply_to: None,
        attachments: vec![],
    };
    let (first, update) = h
        .app
        .admit_local_message(
            "alice",
            &h.group,
            "host-secret-token".into(),
            request.clone(),
            Some(saved.revision.clone()),
        )
        .unwrap();
    assert!(
        update
            .unwrap()
            .timeline_messages
            .iter()
            .any(|m| m.client_token.as_deref() == Some("host-secret-token"))
    );
    assert!(
        h.app
            .selected_message_draft("alice", &group)
            .unwrap()
            .draft
            .is_none()
    );
    let (retry, update) = h
        .app
        .admit_local_message(
            "alice",
            &h.group,
            "host-secret-token".into(),
            request,
            Some(saved.revision),
        )
        .unwrap();
    assert_eq!(first, retry);
    assert!(update.is_none());
    let store = h.app.account_storage("alice").unwrap();
    let retained = store.next_local_submission().unwrap().unwrap();
    let event =
        cgka_traits::app_event::MarmotAppEvent::decode(retained.payload.as_ref().unwrap()).unwrap();
    assert!(
        !String::from_utf8(retained.payload.unwrap())
            .unwrap()
            .contains("host-secret-token")
    );
    assert_eq!(event.content, "same text");
    let changed = LocalMessageRequest {
        content: "different".into(),
        reply_to: None,
        attachments: vec![],
    };
    assert!(
        h.app
            .admit_local_message("alice", &h.group, "host-secret-token".into(), changed, None)
            .is_err()
    );
    let (second, _) = h
        .app
        .admit_local_message(
            "alice",
            &h.group,
            "another-token".into(),
            LocalMessageRequest {
                content: "same text".into(),
                reply_to: None,
                attachments: vec![],
            },
            None,
        )
        .unwrap();
    assert_ne!(first.message_id_hex, second.message_id_hex);
    assert!(
        format!(
            "{:?}",
            store
                .timeline_message(&group, &first.message_id_hex)
                .unwrap()
        )
        .contains("has_client_token")
    );
    assert!(
        !format!(
            "{:?}",
            store
                .timeline_message(&group, &first.message_id_hex)
                .unwrap()
        )
        .contains("host-secret-token")
    );
}

#[tokio::test]
async fn durable_admission_proceeds_while_relay_publication_is_blocked() {
    let h = History::new(0).await;
    let runtime = MarmotAppRuntime::new(h.app.clone());
    h.relay.block_next_publish();
    let first = runtime
        .submit_text("alice", &h.group, "first".into(), "first-token".into())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), h.relay.wait_for_blocked_publish())
        .await
        .unwrap();
    assert_eq!(
        h.app
            .account_storage("alice")
            .unwrap()
            .local_submission(&hex::encode(h.group.as_slice()), "first-token")
            .unwrap()
            .unwrap()
            .state,
        1,
        "engine acceptance must atomically retire app-owned work before publication"
    );
    let second = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.submit_text("alice", &h.group, "second".into(), "second-token".into()),
    )
    .await;
    h.relay.release_publish();
    let second = second
        .expect("local admission waited behind publication")
        .unwrap();
    assert_ne!(first.message_id_hex, second.message_id_hex);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                runtime
                    .local_send_status("alice", &h.group, "second-token")
                    .unwrap(),
                Some(crate::LocalSendStatus::Completed(_))
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let store = h.app.account_storage("alice").unwrap();
    assert!(store.next_local_submission().unwrap().is_none());
    let row = store
        .timeline_message(&hex::encode(h.group.as_slice()), &second.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(row.client_token.as_deref(), Some("second-token"));
    assert!(row.source_message_id_hex.is_some());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn durable_admission_is_drained_by_a_new_worker() {
    let h = History::new(0).await;
    let (accepted, _) = h
        .app
        .admit_local_message(
            "alice",
            &h.group,
            "restart-token".into(),
            LocalMessageRequest {
                content: "retained before worker startup".into(),
                reply_to: None,
                attachments: vec![],
            },
            None,
        )
        .unwrap();
    h.app.close_storage().unwrap();
    let reopened = MarmotApp::with_relay(h._dir.path(), "wss://relay.example")
        .with_test_relay_client(h.relay.clone());
    let storage = reopened.account_storage("alice").unwrap();
    let group_hex = hex::encode(h.group.as_slice());
    storage
        .rebuild_message_timeline_for_group(&group_hex)
        .unwrap();
    assert_eq!(
        storage
            .timeline_message(&group_hex, &accepted.message_id_hex)
            .unwrap()
            .unwrap()
            .client_token
            .as_deref(),
        Some("restart-token")
    );
    let runtime = MarmotAppRuntime::new(reopened.clone());
    let retried = runtime
        .submit_text(
            "alice",
            &h.group,
            "retained before worker startup".into(),
            "restart-token".into(),
        )
        .await
        .unwrap();
    assert_eq!(accepted, retried);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                runtime
                    .local_send_status("alice", &h.group, "restart-token")
                    .unwrap(),
                Some(crate::LocalSendStatus::Completed(_))
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        reopened
            .account_storage("alice")
            .unwrap()
            .next_local_submission()
            .unwrap()
            .is_none()
    );
    runtime.shutdown_and_close().await.unwrap();
}
