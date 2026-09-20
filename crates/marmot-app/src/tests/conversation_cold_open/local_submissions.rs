use super::*;
use crate::local_submissions::LocalMessageRequest;

#[tokio::test]
async fn retained_submission_preserves_noncanonical_json_bytes_for_engine_handoff() {
    use cgka_traits::storage::{OutboundIntentStorage, QueuedOutboundIntent};
    use sha2::{Digest, Sha256};
    let h = History::new(0).await;
    let event = crate::messages::build_inner_event(
        &crate::messages::AppMessageIntent::Chat {
            content: "retained bytes".into(),
        },
        &h.account,
        42,
    )
    .unwrap();
    let payload = serde_json::to_vec_pretty(&event).unwrap();
    assert_ne!(
        payload,
        crate::messages::encode_inner_event(&event).unwrap()
    );
    let mut submission = storage_sqlite::LocalSubmission {
        group_id_hex: hex::encode(h.group.as_slice()),
        client_token: "payload-token".into(),
        message_id_hex: event.id.clone(),
        request_hash: vec![1; 32],
        payload_hash: Sha256::digest(&payload).to_vec(),
        payload: Some(payload.clone()),
        request_json: Some("{}".into()),
        state: 0,
        outcome_json: None,
    };
    let store = h.app.account_storage("alice").unwrap();
    store.insert_local_submission(&submission).unwrap();
    let (decoded, retained) = crate::local_submissions::retained_event(&submission).unwrap();
    assert_eq!(decoded.id, event.id);
    assert_eq!(retained, payload);
    store
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: cgka_traits::MessageId::new(vec![5; 32]),
            group_id: h.group.clone(),
            intent: cgka_traits::SendIntent::AppMessage {
                group_id: h.group.clone(),
                payload: retained,
                expected_epoch: None,
            },
            created_at_ms: 1,
            reissue_attempts: 0,
        })
        .unwrap();
    assert_eq!(
        store
            .local_submission(&submission.group_id_hex, &submission.client_token)
            .unwrap()
            .unwrap()
            .state,
        1
    );
    assert!(store.next_local_submission().unwrap().is_none());
    submission.payload.as_mut().unwrap().push(b' ');
    assert!(
        crate::local_submissions::retained_event(&submission).is_err(),
        "a mismatched retained digest must fail before engine work"
    );
    h.app.close_storage().unwrap();
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
        .admit_local_message_at(
            "alice",
            &h.group,
            "host-secret-token".into(),
            request.clone(),
            Some(saved.revision.clone()),
            42,
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
    assert!(event.tags.is_empty(), "correlation must not add wire tags");
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
    let selected = h.app.selected_message_draft("alice", &group).unwrap();
    let newer_draft = h
        .app
        .save_message_draft_if_revision("alice", &selected.revision, "same text", None, vec![])
        .unwrap();
    let collision = h
        .app
        .admit_local_message_at(
            "alice",
            &h.group,
            "another-token".into(),
            LocalMessageRequest {
                content: String::new(),
                reply_to: None,
                attachments: vec![],
            },
            Some(newer_draft.revision.clone()),
            42,
        )
        .unwrap_err();
    assert!(
        matches!(collision, crate::AppError::InvalidAppMessagePayload(ref detail) if detail.contains("message identity collision"))
    );
    assert!(
        store
            .local_submission(&group, "another-token")
            .unwrap()
            .is_none()
    );
    let preserved = h.app.selected_message_draft("alice", &group).unwrap();
    assert_eq!(preserved.revision, newer_draft.revision);
    assert_eq!(preserved.draft.unwrap().content, "same text");
    assert_eq!(
        store
            .timeline_message(&group, &first.message_id_hex)
            .unwrap()
            .unwrap()
            .client_token
            .as_deref(),
        Some("host-secret-token")
    );
    // A later timestamp has a distinct existing-protocol identity. Rejection
    // did not reserve the new token or mutate the original association.
    let (second, _) = h
        .app
        .admit_local_message_at(
            "alice",
            &h.group,
            "another-token".into(),
            LocalMessageRequest {
                content: "same text".into(),
                reply_to: None,
                attachments: vec![],
            },
            None,
            43,
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
