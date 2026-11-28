use super::*;
use crate::local_submissions::LocalMessageRequest;

#[test]
fn pending_edit_request_decoder_preserves_legacy_local_sends() {
    let legacy = serde_json::json!({
        "version": 1,
        "request": { "content": "legacy", "reply_to": null, "attachments": [] }
    });
    let (request, dependency) = LocalMessageRequest::decode_retained(&legacy.to_string()).unwrap();
    assert_eq!(request.content, "legacy");
    assert!(dependency.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        media_upload_receipt_json: None,
        outcome_json: None,
    };
    let store = h.app.account_storage("alice").unwrap();
    store
        .app_storage()
        .insert_local_submission(&submission)
        .unwrap();
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
                only_to_members: None,
            },
            created_at_ms: 1,
            reissue_attempts: 0,
        })
        .unwrap();
    assert_eq!(
        store
            .app_storage()
            .local_submission(&submission.group_id_hex, &submission.client_token)
            .unwrap()
            .unwrap()
            .state,
        1
    );
    assert!(
        store
            .app_storage()
            .next_local_submission()
            .unwrap()
            .is_none()
    );
    submission.payload.as_mut().unwrap().push(b' ');
    assert!(
        crate::local_submissions::retained_event(&submission).is_err(),
        "a mismatched retained digest must fail before engine work"
    );
    h.app.close_storage().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        ..Default::default()
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
    let store = h.app.account_storage("alice").unwrap().app_storage();
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
        ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_edit_is_durable_while_original_publication_is_blocked() {
    let h = History::new(0).await;
    let runtime = MarmotAppRuntime::new(h.app.clone());
    h.relay.block_next_publish();
    let original = runtime
        .submit_text(
            "alice",
            &h.group,
            "before revision".into(),
            "original-token".into(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), h.relay.wait_for_blocked_publish())
        .await
        .unwrap();
    let edit = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.submit_edit_for_local_send(
            "alice",
            &h.group,
            "original-token".into(),
            "after revision".into(),
            "edit-token".into(),
        ),
    )
    .await
    .expect("edit admission waited for relay publication")
    .unwrap();
    assert_ne!(original.message_id_hex, edit.message_id_hex);
    assert_eq!(
        runtime
            .local_send_status("alice", &h.group, "edit-token")
            .unwrap(),
        Some(crate::LocalSendStatus::Queued {
            message_id_hex: edit.message_id_hex.clone()
        })
    );
    h.relay.release_publish();
    local_send_completed(&runtime, &h.group, "edit-token").await;
    let row = h
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .timeline_message(&hex::encode(h.group.as_slice()), &original.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(row.plaintext, "after revision");
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_edit_requires_an_existing_local_original() {
    let h = History::new(0).await;
    let group_hex = hex::encode(h.group.as_slice());
    let error = h
        .app
        .admit_local_message_with_edit_at(
            "alice",
            &h.group,
            "edit-token".into(),
            LocalMessageRequest {
                content: "revision".into(),
                reply_to: None,
                attachments: vec![],
                ..Default::default()
            },
            None,
            Some("missing-original".into()),
            crate::unix_now_seconds(),
        )
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidAppMessagePayload(_)));
    assert!(
        h.app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .local_submission(&group_hex, "edit-token")
            .unwrap()
            .is_none()
    );
    h.app.close_storage().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rapid_edit_limit_reports_a_stable_retryable_error() {
    let h = History::new(0).await;
    h.app
        .admit_local_message_at(
            "alice",
            &h.group,
            "original-token".into(),
            LocalMessageRequest {
                content: "original".into(),
                reply_to: None,
                attachments: vec![],
                ..Default::default()
            },
            None,
            42,
        )
        .unwrap();
    let edit_time = crate::unix_now_seconds();
    for revision in 0..32 {
        let result = h.app.admit_local_message_with_edit_at(
            "alice",
            &h.group,
            format!("edit-{revision}"),
            LocalMessageRequest {
                content: format!("revision {revision}"),
                reply_to: None,
                attachments: vec![],
                ..Default::default()
            },
            None,
            Some("original-token".into()),
            edit_time,
        );
        if revision < 31 {
            result.unwrap();
        } else {
            assert!(
                matches!(result, Err(AppError::InvalidAppMessagePayload(detail))
                if detail == "pending edit rate limit: retry shortly")
            );
        }
    }
    h.app.close_storage().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_rapid_pending_edits_survive_restart_and_target_the_original_send() {
    let h = History::new(0).await;
    let group_hex = hex::encode(h.group.as_slice());
    let (original, _) = h
        .app
        .admit_local_message_at(
            "alice",
            &h.group,
            "original-token".into(),
            LocalMessageRequest {
                content: "before revision".into(),
                reply_to: None,
                attachments: vec![],
                ..Default::default()
            },
            None,
            42,
        )
        .unwrap();
    let (edit, _) = h
        .app
        .admit_local_message_with_edit_at(
            "alice",
            &h.group,
            "edit-token".into(),
            LocalMessageRequest {
                content: "after revision".into(),
                reply_to: None,
                attachments: vec![],
                ..Default::default()
            },
            None,
            Some("original-token".into()),
            crate::unix_now_seconds(),
        )
        .unwrap();
    h.app
        .admit_local_message_with_edit_at(
            "alice",
            &h.group,
            "latest-edit-token".into(),
            LocalMessageRequest {
                content: "latest revision".into(),
                reply_to: None,
                attachments: vec![],
                ..Default::default()
            },
            None,
            Some("original-token".into()),
            crate::unix_now_seconds(),
        )
        .unwrap();
    let storage = h.app.account_storage("alice").unwrap().app_storage();
    let retained = storage
        .local_submission(&group_hex, "edit-token")
        .unwrap()
        .unwrap();
    let (event, _) = crate::local_submissions::retained_event(&retained).unwrap();
    let latest_retained = storage
        .local_submission(&group_hex, "latest-edit-token")
        .unwrap()
        .unwrap();
    let (latest_event, _) = crate::local_submissions::retained_event(&latest_retained).unwrap();
    assert_eq!(event.kind, 1009);
    assert_eq!(event.content, "after revision");
    assert!(latest_event.created_at > event.created_at);
    assert!(event.tags.iter().any(|tag| {
        tag.first().is_some_and(|value| value == "e")
            && tag.get(1) == Some(&original.message_id_hex)
    }));
    assert!(
        !event
            .tags
            .iter()
            .flatten()
            .any(|value| value == "original-token")
    );
    h.app.close_storage().unwrap();

    let reopened = MarmotApp::with_relay(h._dir.path(), "wss://relay.example")
        .with_test_relay_client(h.relay.clone());
    let runtime = MarmotAppRuntime::new(reopened.clone());
    let replay = runtime
        .submit_edit_for_local_send(
            "alice",
            &h.group,
            "original-token".into(),
            "after revision".into(),
            "edit-token".into(),
        )
        .await
        .unwrap();
    assert_eq!(replay, edit);
    let changed = runtime
        .submit_edit_for_local_send(
            "alice",
            &h.group,
            "original-token".into(),
            "a different revision".into(),
            "edit-token".into(),
        )
        .await;
    assert!(
        changed.is_err(),
        "one edit token must never retarget another revision"
    );
    local_send_completed(&runtime, &h.group, "edit-token").await;
    assert!(matches!(
        runtime
            .local_send_status("alice", &h.group, "original-token")
            .unwrap(),
        Some(crate::LocalSendStatus::Completed(_))
    ));
    local_send_completed(&runtime, &h.group, "latest-edit-token").await;
    let row = reopened
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .timeline_message(&group_hex, &original.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(row.plaintext, "latest revision");
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_original_cannot_publish_a_retained_pending_edit() {
    let h = History::new(0).await;
    let group_hex = hex::encode(h.group.as_slice());
    h.app
        .admit_local_message_at(
            "alice",
            &h.group,
            "original-token".into(),
            LocalMessageRequest {
                content: "not accepted".into(),
                reply_to: None,
                attachments: vec![],
                ..Default::default()
            },
            None,
            42,
        )
        .unwrap();
    h.app
        .admit_local_message_with_edit_at(
            "alice",
            &h.group,
            "edit-token".into(),
            LocalMessageRequest {
                content: "must not publish".into(),
                reply_to: None,
                attachments: vec![],
                ..Default::default()
            },
            None,
            Some("original-token".into()),
            crate::unix_now_seconds(),
        )
        .unwrap();
    h.app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .finish_local_submission(&group_hex, "original-token", None)
        .unwrap();
    h.app.close_storage().unwrap();

    let reopened = MarmotApp::with_relay(h._dir.path(), "wss://relay.example")
        .with_test_relay_client(h.relay.clone());
    let runtime = MarmotAppRuntime::new(reopened.clone());
    runtime
        .submit_edit_for_local_send(
            "alice",
            &h.group,
            "original-token".into(),
            "must not publish".into(),
            "edit-token".into(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                runtime
                    .local_send_status("alice", &h.group, "edit-token")
                    .unwrap(),
                Some(crate::LocalSendStatus::Rejected)
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        reopened
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .next_local_submission()
            .unwrap()
            .is_none()
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            .app_storage()
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
    let store = h.app.account_storage("alice").unwrap().app_storage();
    assert!(store.next_local_submission().unwrap().is_none());
    let row = store
        .timeline_message(&hex::encode(h.group.as_slice()), &second.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(row.client_token.as_deref(), Some("second-token"));
    assert!(row.source_message_id_hex.is_some());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
                ..Default::default()
            },
            None,
        )
        .unwrap();
    h.app.close_storage().unwrap();
    let reopened = MarmotApp::with_relay(h._dir.path(), "wss://relay.example")
        .with_test_relay_client(h.relay.clone());
    let storage = reopened.account_storage("alice").unwrap().app_storage();
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
    let completed = local_send_completed(&runtime, &h.group, "restart-token").await;
    assert!(
        reopened
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .next_local_submission()
            .unwrap()
            .is_none()
    );
    runtime.shutdown_and_close().await.unwrap();
    let reopened = MarmotApp::with_relay(h._dir.path(), "wss://relay.example")
        .with_test_relay_client(h.relay.clone());
    let retained = reopened
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .local_submission(&group_hex, "restart-token")
        .unwrap()
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_str(retained.outcome_json.as_ref().unwrap()).unwrap();
    assert_eq!(json["version"], 1);
    let runtime = MarmotAppRuntime::new(reopened.clone());
    assert_eq!(
        runtime
            .local_send_status("alice", &h.group, "restart-token")
            .unwrap(),
        Some(crate::LocalSendStatus::Completed(completed))
    );
    let (retry, update) = reopened
        .admit_local_message(
            "alice",
            &h.group,
            "restart-token".into(),
            LocalMessageRequest {
                content: "retained before worker startup".into(),
                reply_to: None,
                attachments: vec![],
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(retry, accepted);
    assert!(update.is_none());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_submission_requires_a_new_token_after_restart() {
    let h = History::new(0).await;
    let request = LocalMessageRequest {
        content: "rejected attempt".into(),
        reply_to: None,
        attachments: vec![],
        ..Default::default()
    };
    let (accepted, _) = h
        .app
        .admit_local_message_at(
            "alice",
            &h.group,
            "rejected-token".into(),
            request.clone(),
            None,
            42,
        )
        .unwrap();
    let submission = h
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .next_local_submission()
        .unwrap()
        .unwrap();
    h.app
        .finish_local_message("alice", &submission, &Err(AppError::TransportClosed))
        .unwrap();
    h.app.close_storage().unwrap();
    let reopened = MarmotApp::with_relay(h._dir.path(), "wss://relay.example")
        .with_test_relay_client(h.relay.clone());
    let runtime = MarmotAppRuntime::new(reopened.clone());
    assert_eq!(
        runtime
            .local_send_status("alice", &h.group, "rejected-token")
            .unwrap(),
        Some(crate::LocalSendStatus::Rejected)
    );
    let error = reopened
        .admit_local_message_at(
            "alice",
            &h.group,
            "rejected-token".into(),
            request.clone(),
            None,
            43,
        )
        .unwrap_err();
    assert!(
        matches!(error, AppError::InvalidAppMessagePayload(ref detail) if detail.contains("rejected submission"))
    );
    let store = reopened.account_storage("alice").unwrap().app_storage();
    assert!(store.next_local_submission().unwrap().is_none());
    let original = store
        .local_submission(&hex::encode(h.group.as_slice()), "rejected-token")
        .unwrap()
        .unwrap();
    assert_eq!(original.message_id_hex, accepted.message_id_hex);
    assert_eq!(original.state, 3);
    let (new, _) = reopened
        .admit_local_message_at("alice", &h.group, "new-token".into(), request, None, 43)
        .unwrap();
    assert_ne!(new.message_id_hex, accepted.message_id_hex);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completion_write_failure_does_not_stall_later_submissions() {
    let h = History::new(0).await;
    // Admit before worker startup, so later admission wakeups cannot hide a stall.
    let mut accepted = Vec::new();
    for i in 0..3 {
        accepted.push(
            h.app
                .admit_local_message(
                    "alice",
                    &h.group,
                    format!("finish-failure-{i}"),
                    LocalMessageRequest {
                        content: format!("queued message {i}"),
                        reply_to: None,
                        attachments: vec![],
                        ..Default::default()
                    },
                    None,
                )
                .unwrap()
                .0,
        );
    }
    let path = h.app.account_storage_path("alice");
    let keys = h.app.account_home().load_signing_keys("alice").unwrap();
    let key = h
        .app
        .sqlcipher_key("alice", &keys, &path, SqlcipherDatabaseKind::Session)
        .unwrap();
    storage_sqlite::expect_uncounted_writes_for_test(&path);
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection.execute_batch("CREATE TRIGGER fail_local_finish BEFORE UPDATE OF outcome_json ON local_message_submissions
        WHEN NEW.outcome_json IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected finish failure'); END;").unwrap();
    drop(connection);
    let runtime = MarmotAppRuntime::new(h.app.clone());
    runtime.start().await.unwrap();
    let store = h.app.account_storage("alice").unwrap().app_storage();
    let group = hex::encode(h.group.as_slice());
    // Three rows also prevent the initial maintenance tick from masking the bug.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if accepted.iter().all(|a| {
                store
                    .timeline_message(&group, &a.message_id_hex)
                    .unwrap()
                    .is_some_and(|row| row.source_message_id_hex.is_some())
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("completion failure stalled the app-owned queue until maintenance");
    assert!(store.next_local_submission().unwrap().is_none());
    for a in accepted {
        let row = store
            .local_submission(&group, &a.client_token)
            .unwrap()
            .unwrap();
        assert_eq!(row.state, 1);
        assert!(
            row.outcome_json.is_none(),
            "fault injection must prevent outcome persistence"
        );
    }
    runtime.shutdown_and_close().await.unwrap();
}

fn prepared_media_snapshot_fixture(
    h: &History,
) -> (crate::MessageDraftRevision, LocalMessageRequest) {
    use sha2::{Digest, Sha256};
    let attachments: Vec<_> = (0_u8..2)
        .map(|index| crate::MessageDraftAttachment {
            id: format!("native-photo-{index}"),
            file_name: format!("photo-{index}.jpg"),
            media_type: "image/jpeg".into(),
            plaintext: vec![index + 1, index + 2],
            dim: None,
            thumbhash: None,
            duration_seconds: None,
            waveform_samples: vec![],
        })
        .collect();
    let references = attachments
        .iter()
        .enumerate()
        .map(|(index, attachment)| crate::MediaAttachmentReference {
            locators: vec![crate::MediaLocator {
                kind: "blossom-v1".into(),
                value: format!(
                    "https://media.example/{}.bin",
                    hex::encode([index as u8 + 10; 32])
                ),
            }],
            ciphertext_sha256: hex::encode([index as u8 + 10; 32]),
            plaintext_sha256: hex::encode(Sha256::digest(&attachment.plaintext)),
            nonce_hex: hex::encode([index as u8 + 20; 12]),
            file_name: attachment.file_name.clone(),
            media_type: attachment.media_type.clone(),
            version: "encrypted-media-v2".into(),
            source_epoch: 0,
            source_epoch_identity: Some(h.upload_epoch_identity.clone()),
            dim: None,
            thumbhash: None,
        })
        .collect();
    let group = hex::encode(h.group.as_slice());
    let selected = h.app.selected_message_draft("alice", &group).unwrap();
    let saved = h
        .app
        .save_message_draft_if_revision("alice", &selected.revision, "caption", None, attachments)
        .unwrap();
    (
        saved.revision,
        LocalMessageRequest {
            content: "caption".into(),
            reply_to: None,
            attachments: references,
            ..Default::default()
        },
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_media_snapshot_runtime_consumes_and_replays_without_clearing_a_new_draft() {
    let h = History::new(0).await;
    let group = hex::encode(h.group.as_slice());
    let (revision, request) = prepared_media_snapshot_fixture(&h);
    let runtime = MarmotAppRuntime::new(h.app.clone());
    let accepted = runtime
        .submit_prepared_media_snapshot(
            "alice",
            &h.group,
            request.attachments.clone(),
            Some(request.content.clone()),
            "runtime-snapshot".into(),
            Some(revision.clone()),
        )
        .await
        .unwrap();
    let empty = h.app.selected_message_draft("alice", &group).unwrap();
    assert!(empty.draft.is_none());
    let newer = h
        .app
        .save_message_draft_if_revision("alice", &empty.revision, "next message", None, vec![])
        .unwrap();
    let replayed = runtime
        .submit_prepared_media_snapshot(
            "alice",
            &h.group,
            request.attachments,
            Some(request.content),
            "runtime-snapshot".into(),
            Some(revision),
        )
        .await
        .unwrap();
    assert_eq!(accepted, replayed);
    assert_eq!(
        h.app
            .selected_message_draft("alice", &group)
            .unwrap()
            .revision,
        newer.revision
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_media_snapshot_consumption_survives_restart_before_host_cleanup() {
    use crate::local_submissions::LocalDraftAdmission;
    let h = History::new(0).await;
    let group = hex::encode(h.group.as_slice());
    let (revision, request) = prepared_media_snapshot_fixture(&h);
    let expected_tags: Vec<_> = request.attachments.iter().map(|a| a.imeta_tag()).collect();
    let (accepted, _) = h
        .app
        .admit_local_message_with_draft_policy_at(
            "alice",
            &h.group,
            "snapshot-token".into(),
            request.clone(),
            Some(LocalDraftAdmission::ConsumeIfCurrent(revision.clone())),
            None,
            42,
        )
        .unwrap();
    // Reopen immediately, without any host draft-cleanup call.
    h.app.close_storage().unwrap();
    let reopened = MarmotApp::with_relay(h._dir.path(), "wss://relay.example")
        .with_test_relay_client(h.relay.clone());
    assert!(
        reopened
            .selected_message_draft("alice", &group)
            .unwrap()
            .draft
            .is_none()
    );
    let store = reopened.account_storage("alice").unwrap();
    let retained = store
        .app_storage()
        .local_submission(&group, "snapshot-token")
        .unwrap()
        .unwrap();
    let event =
        cgka_traits::app_event::MarmotAppEvent::decode(retained.payload.as_ref().unwrap()).unwrap();
    assert_eq!(event.content, "caption");
    assert_eq!(event.tags, expected_tags);
    drop(store);
    // A new draft must survive replay of the already consumed send.
    let empty = reopened.selected_message_draft("alice", &group).unwrap();
    let newer = reopened
        .save_message_draft_if_revision("alice", &empty.revision, "next message", None, vec![])
        .unwrap();
    let (replayed, update) = reopened
        .admit_local_message_with_draft_policy_at(
            "alice",
            &h.group,
            "snapshot-token".into(),
            request,
            Some(LocalDraftAdmission::ConsumeIfCurrent(revision)),
            None,
            42,
        )
        .unwrap();
    assert_eq!(replayed, accepted);
    assert!(update.is_none());
    assert_eq!(
        reopened
            .selected_message_draft("alice", &group)
            .unwrap()
            .revision,
        newer.revision
    );
    reopened.close_storage().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_media_snapshot_preserves_changed_cleared_and_identical_newer_drafts() {
    use crate::local_submissions::LocalDraftAdmission;
    for change in 0..4 {
        let h = History::new(0).await;
        let group = hex::encode(h.group.as_slice());
        let (revision, request) = prepared_media_snapshot_fixture(&h);
        let original = h.app.message_draft("alice", &group).unwrap().unwrap();
        if change == 0 {
            h.app
                .clear_message_draft_if_revision("alice", &revision)
                .unwrap();
        } else {
            let mut attachments = original.media_attachments.clone();
            if change == 2 {
                attachments[0].id = "new-picker-occurrence".into();
                attachments[0].plaintext = vec![9, 8];
            }
            let newer = h
                .app
                .save_message_draft_if_revision(
                    "alice",
                    &revision,
                    "next message",
                    None,
                    attachments.clone(),
                )
                .unwrap();
            if change == 3 {
                h.app
                    .save_message_draft_if_revision(
                        "alice",
                        &newer.revision,
                        "caption",
                        None,
                        attachments,
                    )
                    .unwrap();
            }
        }
        let expected = h.app.message_draft("alice", &group).unwrap();
        let expected_revision = h
            .app
            .selected_message_draft("alice", &group)
            .unwrap()
            .revision;
        assert_ne!(expected_revision, revision);
        let (accepted, _) = h
            .app
            .admit_local_message_with_draft_policy_at(
                "alice",
                &h.group,
                "snapshot-token".into(),
                request.clone(),
                Some(LocalDraftAdmission::ConsumeIfCurrent(revision)),
                None,
                42,
            )
            .unwrap();
        assert_eq!(h.app.message_draft("alice", &group).unwrap(), expected);
        assert_eq!(
            h.app
                .selected_message_draft("alice", &group)
                .unwrap()
                .revision,
            expected_revision
        );
        let row = h
            .app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .timeline_message(&group, &accepted.message_id_hex)
            .unwrap()
            .unwrap();
        assert_eq!(row.plaintext, "caption");
        assert_eq!(
            row.tags,
            request
                .attachments
                .iter()
                .map(|a| a.imeta_tag())
                .collect::<Vec<_>>()
        );
        h.app.close_storage().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_media_snapshot_rejects_unrelated_payload_without_consuming_the_draft() {
    use crate::local_submissions::LocalDraftAdmission;
    let h = History::new(0).await;
    let group = hex::encode(h.group.as_slice());
    let (revision, request) = prepared_media_snapshot_fixture(&h);
    for mismatch in 0..4 {
        let mut changed = request.clone();
        match mismatch {
            0 => changed.content = "unrelated".into(),
            1 => changed.attachments.reverse(),
            2 => changed.reply_to = Some("aa".repeat(32)),
            _ => changed.attachments[0].plaintext_sha256 = "aa".repeat(32),
        }
        let result = h.app.admit_local_message_with_draft_policy_at(
            "alice",
            &h.group,
            format!("mismatched-{mismatch}"),
            changed,
            Some(LocalDraftAdmission::ConsumeIfCurrent(revision.clone())),
            None,
            42,
        );
        assert!(matches!(result, Err(AppError::InvalidMessageDraft(_))));
        assert_eq!(
            h.app
                .selected_message_draft("alice", &group)
                .unwrap()
                .revision,
            revision
        );
        assert!(
            h.app
                .account_storage("alice")
                .unwrap()
                .app_storage()
                .local_submission(&group, &format!("mismatched-{mismatch}"))
                .unwrap()
                .is_none()
        );
    }
    h.app.close_storage().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_media_snapshot_missing_upload_identity_leaves_admission_and_draft_unchanged() {
    use crate::local_submissions::LocalDraftAdmission;
    let h = History::new(0).await;
    let group = hex::encode(h.group.as_slice());
    let (revision, mut request) = prepared_media_snapshot_fixture(&h);
    let store = h.app.account_storage("alice").unwrap();
    let epoch = cgka_traits::GroupStorage::get_group(&store, &h.group)
        .unwrap()
        .epoch
        .0;
    assert!(
        request
            .attachments
            .iter()
            .all(|reference| reference.source_epoch == epoch)
    );
    request.attachments[0].source_epoch_identity = None;
    let draft_before = h.app.selected_message_draft("alice", &group).unwrap();
    let query = storage_sqlite::TimelineMessageQuery {
        group_id_hex: Some(group.clone()),
        ..Default::default()
    };
    let timeline_before = h
        .app
        .timeline_messages_with_query("alice", query.clone())
        .unwrap()
        .messages;
    let result = h.app.admit_local_message_with_draft_policy_at(
        "alice",
        &h.group,
        "missing-upload-identity".into(),
        request,
        Some(LocalDraftAdmission::ConsumeIfCurrent(revision)),
        None,
        42,
    );
    match result {
        Err(AppError::MediaReferenceStaleEpoch {
            source_epoch,
            current_epoch,
        }) => assert_eq!((source_epoch, current_epoch), (epoch, epoch)),
        Err(_) => panic!("missing upload identity returned the wrong admission error"),
        Ok(_) => panic!("admitted a reference without its upload identity"),
    }
    assert!(
        store
            .app_storage()
            .local_submission(&group, "missing-upload-identity")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        h.app
            .timeline_messages_with_query("alice", query)
            .unwrap()
            .messages,
        timeline_before
    );
    let draft_after = h.app.selected_message_draft("alice", &group).unwrap();
    assert_eq!(draft_after.revision, draft_before.revision);
    assert_eq!(draft_after.draft, draft_before.draft);
    h.app.close_storage().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_media_snapshot_rollback_preserves_both_draft_and_admission() {
    use crate::local_submissions::LocalDraftAdmission;
    use cgka_traits::storage::StorageProvider;
    let h = History::new(0).await;
    let group = hex::encode(h.group.as_slice());
    let (revision, request) = prepared_media_snapshot_fixture(&h);
    let store = h.app.account_storage("alice").unwrap();
    let mut message_id = None;
    let result: Result<(), AppError> = StorageProvider::with_transaction(&store, |_| {
        let (accepted, _) = h.app.admit_local_message_with_draft_policy_at(
            "alice",
            &h.group,
            "rollback-token".into(),
            request,
            Some(LocalDraftAdmission::ConsumeIfCurrent(revision.clone())),
            None,
            42,
        )?;
        message_id = Some(accepted.message_id_hex);
        Err(AppError::InvalidAppMessagePayload(
            "injected transaction rollback".into(),
        ))
    });
    assert!(result.is_err());
    assert!(
        store
            .app_storage()
            .local_submission(&group, "rollback-token")
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .app_storage()
            .timeline_message(&group, &message_id.unwrap())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        h.app
            .selected_message_draft("alice", &group)
            .unwrap()
            .revision,
        revision
    );
    drop(store);
    h.app.close_storage().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_edit_of_a_deleted_message_is_refused_at_admission() {
    // The prepared event skips the send preflight, so admission applies the
    // same rule: an edit of a deleted message would be dropped by recipients.
    let h = History::new(0).await;
    let group_hex = hex::encode(h.group.as_slice());
    let alice = h
        .app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let (original, _) = h
        .app
        .admit_local_message_at(
            "alice",
            &h.group,
            "original-token".into(),
            LocalMessageRequest {
                content: "original".into(),
                reply_to: None,
                attachments: vec![],
                ..Default::default()
            },
            None,
            42,
        )
        .unwrap();
    h.app
        .record_account_app_event(
            "alice",
            &crate::AppMessageProjection {
                authority: None,
                message_id_hex: "de".repeat(32),
                source_message_id_hex: None,
                direction: "sent".into(),
                group_id_hex: group_hex.clone(),
                sender: alice,
                plaintext: String::new(),
                kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_DELETE,
                tags: vec![vec!["e".into(), original.message_id_hex.clone()]],
                source_epoch: None,
                retention: None,
                recorded_at: Some(43),
                origin_commit_id: None,
                moderation_grant: false,
            },
        )
        .unwrap();
    let storage = h.app.account_storage("alice").unwrap().app_storage();
    assert!(
        storage
            .timeline_message(&group_hex, &original.message_id_hex)
            .unwrap()
            .is_some_and(|row| row.deleted),
        "fixture must delete the original"
    );

    let error = h
        .app
        .admit_local_message_with_edit_at(
            "alice",
            &h.group,
            "edit-token".into(),
            LocalMessageRequest {
                content: "revision".into(),
                reply_to: None,
                attachments: vec![],
                ..Default::default()
            },
            None,
            Some("original-token".into()),
            1_000,
        )
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidEditTarget), "{error:?}");
    assert!(
        storage
            .local_submission(&group_hex, "edit-token")
            .unwrap()
            .is_none()
    );
    h.app.close_storage().unwrap();
}

async fn local_send_completed(
    runtime: &MarmotAppRuntime,
    group: &GroupId,
    token: &str,
) -> crate::SendSummary {
    match local_send_settled(runtime, group, token).await {
        crate::LocalSendStatus::Completed(summary) => summary,
        other => panic!("expected a completed send, got {other:?}"),
    }
}

async fn local_send_settled(
    runtime: &MarmotAppRuntime,
    group: &GroupId,
    token: &str,
) -> crate::LocalSendStatus {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match runtime.local_send_status("alice", group, token).unwrap() {
                Some(
                    crate::LocalSendStatus::Queued { .. }
                    | crate::LocalSendStatus::EngineOwned { .. },
                )
                | None => tokio::time::sleep(Duration::from_millis(10)).await,
                Some(settled) => break settled,
            }
        }
    })
    .await
    .unwrap()
}

fn tag(name: &str, value: &str) -> Vec<String> {
    vec![name.to_owned(), value.to_owned()]
}

/// The agent-words contract: a host that crashes after publication but before
/// recording the result resubmits by token and must get the same message, with
/// its tags, and never a second send. Its edits keep their own tags.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tagged_text_and_tagged_edit_are_crash_safe_by_token() {
    let h = History::new(0).await;
    let group_hex = hex::encode(h.group.as_slice());
    let words = vec![tag("turn", "turn-1"), tag("phase", "commentary")];
    let runtime = MarmotAppRuntime::new(h.app.clone());
    let sent = runtime
        .submit_tagged_text(
            "alice",
            &h.group,
            "looking into it".into(),
            words.clone(),
            "words-token".into(),
        )
        .await
        .unwrap();
    let completed = local_send_completed(&runtime, &h.group, "words-token").await;
    runtime.shutdown_and_close().await.unwrap();

    // Restart without the host having recorded `sent`.
    let reopened = MarmotApp::with_relay(h._dir.path(), "wss://relay.example")
        .with_test_relay_client(h.relay.clone());
    let runtime = MarmotAppRuntime::new(reopened.clone());
    assert_eq!(
        runtime
            .local_send_status("alice", &h.group, "words-token")
            .unwrap(),
        Some(crate::LocalSendStatus::Completed(completed))
    );
    let replay = runtime
        .submit_tagged_text(
            "alice",
            &h.group,
            "looking into it".into(),
            words.clone(),
            "words-token".into(),
        )
        .await
        .unwrap();
    assert_eq!(replay, sent);
    let storage = reopened.account_storage("alice").unwrap().app_storage();
    assert!(
        storage.next_local_submission().unwrap().is_none(),
        "a replayed token must not queue a second send"
    );
    let changed_tags = runtime
        .submit_tagged_text(
            "alice",
            &h.group,
            "looking into it".into(),
            vec![tag("turn", "turn-1")],
            "words-token".into(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(changed_tags, AppError::InvalidAppMessagePayload(ref detail) if detail.contains("another submission"))
    );
    let original = storage
        .app_message(&group_hex, &sent.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(original.kind, 9);
    assert_eq!(original.tags, words);

    let edit_tags = vec![tag("turn", "turn-1")];
    let edit = runtime
        .submit_tagged_edit_for_local_send(
            "alice",
            &h.group,
            "words-token".into(),
            "here is the answer".into(),
            edit_tags.clone(),
            "edit-token".into(),
        )
        .await
        .unwrap();
    local_send_completed(&runtime, &h.group, "edit-token").await;
    let edit_event = storage
        .app_message(&group_hex, &edit.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(edit_event.kind, 1009);
    assert_eq!(edit_event.tags[0], tag("e", &sent.message_id_hex));
    assert_eq!(&edit_event.tags[1..], edit_tags);
    assert_eq!(
        storage
            .timeline_message(&group_hex, &sent.message_id_hex)
            .unwrap()
            .unwrap()
            .plaintext,
        "here is the answer"
    );
    let replayed_edit = runtime
        .submit_tagged_edit_for_local_send(
            "alice",
            &h.group,
            "words-token".into(),
            "here is the answer".into(),
            edit_tags,
            "edit-token".into(),
        )
        .await
        .unwrap();
    assert_eq!(replayed_edit, edit);
    assert!(
        runtime
            .submit_tagged_edit_for_local_send(
                "alice",
                &h.group,
                "words-token".into(),
                "here is the answer".into(),
                words,
                "edit-token".into(),
            )
            .await
            .is_err(),
        "an edit token reused with other tags is a changed request"
    );
    let reply = runtime
        .submit_tagged_reply(
            "alice",
            &h.group,
            sent.message_id_hex.clone(),
            "and a follow-up".into(),
            vec![tag("turn", "turn-2")],
            "reply-token".into(),
        )
        .await
        .unwrap();
    local_send_completed(&runtime, &h.group, "reply-token").await;
    assert_eq!(
        storage
            .app_message(&group_hex, &reply.message_id_hex)
            .unwrap()
            .unwrap()
            .tags,
        vec![
            tag("e", &sent.message_id_hex),
            tag("q", &sent.message_id_hex),
            tag("turn", "turn-2"),
        ]
    );
    assert!(storage.next_local_submission().unwrap().is_none());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_event_submission_is_crash_safe_by_token() {
    let h = History::new(0).await;
    let group_hex = hex::encode(h.group.as_slice());
    let item_tags = vec![tag("d", "item-1"), tag("turn", "turn-1")];
    let runtime = MarmotAppRuntime::new(h.app.clone());
    let refused = runtime
        .submit_custom_event(
            "alice",
            &h.group,
            9,
            vec![],
            "forged chat".into(),
            "reserved-token".into(),
        )
        .await;
    assert!(matches!(
        refused,
        Err(AppError::InvalidAppMessagePayload(_))
    ));
    assert_eq!(
        runtime
            .local_send_status("alice", &h.group, "reserved-token")
            .unwrap(),
        None
    );
    let sent = runtime
        .submit_custom_event(
            "alice",
            &h.group,
            41201,
            item_tags.clone(),
            "{}".into(),
            "item-token".into(),
        )
        .await
        .unwrap();
    let completed = local_send_completed(&runtime, &h.group, "item-token").await;
    runtime.shutdown_and_close().await.unwrap();

    let reopened = MarmotApp::with_relay(h._dir.path(), "wss://relay.example")
        .with_test_relay_client(h.relay.clone());
    let runtime = MarmotAppRuntime::new(reopened.clone());
    let replay = runtime
        .submit_custom_event(
            "alice",
            &h.group,
            41201,
            item_tags.clone(),
            "{}".into(),
            "item-token".into(),
        )
        .await
        .unwrap();
    assert_eq!(replay, sent);
    assert_eq!(
        runtime
            .local_send_status("alice", &h.group, "item-token")
            .unwrap(),
        Some(crate::LocalSendStatus::Completed(completed))
    );
    assert!(
        runtime
            .submit_custom_event(
                "alice",
                &h.group,
                41202,
                item_tags.clone(),
                "{}".into(),
                "item-token".into(),
            )
            .await
            .is_err(),
        "a token reused with another kind is a changed request"
    );
    let storage = reopened.account_storage("alice").unwrap().app_storage();
    assert!(storage.next_local_submission().unwrap().is_none());
    let event = storage
        .app_message(&group_hex, &sent.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(event.kind, 41201);
    assert_eq!(event.tags, item_tags);
    runtime.shutdown_and_close().await.unwrap();
}

fn agent_item_tags(version: u64, state: &str, native: &str) -> Vec<Vec<String>> {
    vec![
        tag("v", &version.to_string()),
        tag("state", state),
        tag("title", "Running a command"),
        tag("harness", "codex"),
        tag("item_id", "call-1"),
        tag("seq", &(10 + version).to_string()),
        tag("fields", r#"{"type":"tool","body":{"command":"ls"}}"#),
        tag("turn", "turn-1"),
        vec![
            "native".to_owned(),
            "item/started".to_owned(),
            native.to_owned(),
        ],
    ]
}

/// The agent outbox contract: an item, each later version of it, and an answer
/// or a control are admitted by token, so a core that crashes after submitting
/// resubmits the same token and gets the same event, and nothing is sent twice.
/// The first version is as large as an agent event may be.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_events_are_crash_safe_by_token() {
    let h = History::new(0).await;
    let group_hex = hex::encode(h.group.as_slice());
    // A native message that brings the encoded inner event to the 64 KiB limit.
    let probe = crate::messages::build_inner_event(
        &crate::messages::AppMessageIntent::Custom {
            kind: 1201,
            tags: agent_item_tags(1, "running", ""),
            content: "Running `ls`".into(),
        },
        &"00".repeat(32),
        // As many digits as the admission's own `created_at`.
        crate::unix_now_seconds(),
    )
    .unwrap();
    let filler = cgka_traits::AGENT_EVENT_MAX_BYTES - probe.encode().unwrap().len();
    let first = agent_item_tags(1, "running", &"x".repeat(filler));
    let request = LocalMessageRequest {
        content: "Running `ls`".into(),
        tags: first.clone(),
        custom_kind: Some(1201),
        ..Default::default()
    };
    // Submitted, then the process stops before any worker publishes it.
    let (item, _) = h
        .app
        .admit_local_message("alice", &h.group, "item-token".into(), request, None)
        .unwrap();
    h.app.close_storage().unwrap();

    let reopened = MarmotApp::with_relay(h._dir.path(), "wss://relay.example")
        .with_test_relay_client(h.relay.clone());
    reopened
        .set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    let runtime = MarmotAppRuntime::new(reopened.clone());
    let replay = runtime
        .submit_custom_event(
            "alice",
            &h.group,
            1201,
            first.clone(),
            "Running `ls`".into(),
            "item-token".into(),
        )
        .await
        .unwrap();
    assert_eq!(replay, item);
    local_send_completed(&runtime, &h.group, "item-token").await;

    let edit_tags = agent_item_tags(2, "done", "{}");
    let edit = runtime
        .submit_tagged_edit_for_local_send(
            "alice",
            &h.group,
            "item-token".into(),
            "Ran `ls`".into(),
            edit_tags.clone(),
            "item-v2-token".into(),
        )
        .await
        .unwrap();
    let request_tags = vec![
        tag("p", &"ab".repeat(32)),
        tag("e", &item.message_id_hex),
        tag("details", r#"{"action":"interrupt"}"#),
    ];
    let control = runtime
        .submit_custom_event(
            "alice",
            &h.group,
            1202,
            request_tags.clone(),
            "Stop".into(),
            "control-token".into(),
        )
        .await
        .unwrap();
    local_send_completed(&runtime, &h.group, "item-v2-token").await;
    local_send_completed(&runtime, &h.group, "control-token").await;
    runtime.shutdown_and_close().await.unwrap();

    // Restart again without the core having recorded any of the three.
    let published = h.relay.published_event_ids().len();
    let reopened = MarmotApp::with_relay(h._dir.path(), "wss://relay.example")
        .with_test_relay_client(h.relay.clone());
    let runtime = MarmotAppRuntime::new(reopened.clone());
    let storage = reopened.account_storage("alice").unwrap().app_storage();
    assert_eq!(
        runtime
            .submit_custom_event(
                "alice",
                &h.group,
                1201,
                first,
                "Running `ls`".into(),
                "item-token".into(),
            )
            .await
            .unwrap(),
        item
    );
    assert_eq!(
        runtime
            .submit_tagged_edit_for_local_send(
                "alice",
                &h.group,
                "item-token".into(),
                "Ran `ls`".into(),
                edit_tags.clone(),
                "item-v2-token".into(),
            )
            .await
            .unwrap(),
        edit
    );
    assert_eq!(
        runtime
            .submit_custom_event(
                "alice",
                &h.group,
                1202,
                request_tags.clone(),
                "Stop".into(),
                "control-token".into(),
            )
            .await
            .unwrap(),
        control
    );
    assert!(storage.next_local_submission().unwrap().is_none());
    assert_eq!(
        h.relay.published_event_ids().len(),
        published,
        "a resubmitted token sends nothing new"
    );

    let item_event = storage
        .app_message(&group_hex, &item.message_id_hex)
        .unwrap()
        .unwrap();
    let encoded = cgka_traits::MarmotAppEvent::new(
        item_event.sender.clone(),
        item_event.recorded_at,
        item_event.kind,
        item_event.tags.clone(),
        item_event.plaintext.clone(),
    )
    .encode()
    .unwrap();
    assert_eq!(encoded.len(), cgka_traits::AGENT_EVENT_MAX_BYTES);
    let edit_event = storage
        .app_message(&group_hex, &edit.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(edit_event.kind, 1009);
    assert_eq!(edit_event.tags[0], tag("e", &item.message_id_hex));
    assert_eq!(&edit_event.tags[1..], edit_tags);
    let row = storage
        .timeline_message(&group_hex, &item.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(row.plaintext, "Ran `ls`");
    assert_eq!(row.agent_item.unwrap().version, 2);
    assert!(row.edit.is_none(), "a new version is not an edit to mark");
    assert_eq!(
        storage
            .app_message(&group_hex, &control.message_id_hex)
            .unwrap()
            .unwrap()
            .tags,
        request_tags
    );
    assert!(
        storage
            .timeline_message(&group_hex, &control.message_id_hex)
            .unwrap()
            .is_none(),
        "an answer or a control has no row"
    );
    // The worker sent the new version as the agent's own traffic, as it sent
    // the item, not as a person's edit.
    let actions = crate::tests::recorded_audit_rows(&reopened)
        .into_iter()
        .filter(|row| row["event"]["record_context"]["human_action"]["origin"] == "local_user")
        .map(|row| row["event"]["record_context"]["human_action"]["action"].clone())
        .collect::<Vec<_>>();
    assert!(actions.contains(&"send_custom_event".into()), "{actions:?}");
    assert!(!actions.contains(&"edit_message".into()), "{actions:?}");
    runtime.shutdown_and_close().await.unwrap();
}

/// A custom event limited to member accounts is sent while every member is
/// listed, and refused, not sent, while one is not: the engine checks the
/// list when it encrypts. The refusal settles the token and retracts the
/// local row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_event_to_members_is_refused_while_a_member_is_unlisted() {
    let h = History::new(0).await;
    let group_hex = hex::encode(h.group.as_slice());
    let runtime = MarmotAppRuntime::new(h.app.clone());
    let submit = |members: Vec<String>, token: &str| {
        runtime.submit_custom_event_to_members(
            "alice",
            &h.group,
            41201,
            vec![],
            format!("{{\"token\":\"{token}\"}}"),
            members,
            token.into(),
        )
    };
    submit(vec![h.account.clone()], "listed").await.unwrap();
    assert!(matches!(
        local_send_settled(&runtime, &h.group, "listed").await,
        crate::LocalSendStatus::Completed(_)
    ));

    let refused = submit(vec!["cc".repeat(32)], "unlisted").await.unwrap();
    assert_eq!(
        local_send_settled(&runtime, &h.group, "unlisted").await,
        crate::LocalSendStatus::RefusedNewMembers
    );
    let row = h
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .timeline_message(&group_hex, &refused.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(
        row.invalidation_status.as_deref(),
        Some(crate::LOCAL_PUBLISH_FAILED_REASON)
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// A send the engine took into its queue, which the worker recorded as
/// accepted pending, is settled as refused in the transaction that retires its
/// intent for a new member. Its row is retracted when the refusal is announced,
/// in one pass per group, or at the next account open if a crash came first;
/// a refused send takes no edit. While the engine holds the send, its status
/// names the event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_send_refused_for_a_new_member_is_settled_durably() {
    use cgka_traits::storage::OutboundIntentStorage;
    let h = History::new(0).await;
    let group_hex = hex::encode(h.group.as_slice());
    let storage = h.app.account_storage("alice").unwrap();
    let runtime = MarmotAppRuntime::new(h.app.clone());
    let refuse = |token: &str| {
        let (accepted, _) = h
            .app
            .admit_local_message(
                "alice",
                &h.group,
                token.into(),
                LocalMessageRequest {
                    content: format!("{{\"token\":\"{token}\"}}"),
                    only_to_members: Some(vec![h.account.clone()]),
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        let submission = storage
            .app_storage()
            .local_submission(&group_hex, token)
            .unwrap()
            .unwrap();
        // The engine takes the send into its queue, as it takes a send that
        // has to wait for convergence, and the worker records the answer.
        let record = cgka_traits::storage::QueuedOutboundIntent {
            id: cgka_traits::MessageId::new(accepted.message_id_hex.as_bytes().to_vec()),
            group_id: h.group.clone(),
            intent: cgka_traits::SendIntent::AppMessage {
                group_id: h.group.clone(),
                payload: submission.payload.clone().unwrap(),
                expected_epoch: None,
                only_to_members: None,
            },
            created_at_ms: 0,
            reissue_attempts: 0,
        };
        storage.put_queued_outbound_intent(&record).unwrap();
        assert_eq!(
            runtime.local_send_status("alice", &h.group, token).unwrap(),
            Some(crate::LocalSendStatus::EngineOwned {
                message_id_hex: accepted.message_id_hex.clone()
            }),
            "a send the engine holds names its event"
        );
        h.app
            .finish_local_message(
                "alice",
                &submission,
                &Ok(crate::SendSummary {
                    published: 0,
                    message_ids: vec![],
                    accept_disposition: cgka_traits::SendAcceptDisposition::AcceptedPending,
                    maintenance_disposition: cgka_traits::SendMaintenanceDisposition::Ready,
                }),
            )
            .unwrap();
        storage
            .retire_refused_queued_outbound_intent(&record, "app_message_new_members")
            .unwrap();
        assert_eq!(
            runtime.local_send_status("alice", &h.group, token).unwrap(),
            Some(crate::LocalSendStatus::RefusedNewMembers)
        );
        (record, accepted.message_id_hex)
    };
    let retracted = |message_id_hex: &str| {
        storage
            .app_storage()
            .timeline_message(&group_hex, message_id_hex)
            .unwrap()
            .unwrap()
            .invalidation_status
            .as_deref()
            == Some(crate::LOCAL_PUBLISH_FAILED_REASON)
    };

    let (_, crashed) = refuse("crashed");
    assert!(!retracted(&crashed), "no announcement reached the host");
    drop(h.app.client("alice").await.unwrap());
    assert!(retracted(&crashed), "the account open retracts the row");
    assert!(
        h.app
            .admit_local_message_with_edit_at(
                "alice",
                &h.group,
                "edit-of-crashed".into(),
                LocalMessageRequest {
                    content: "later version".into(),
                    ..Default::default()
                },
                None,
                Some("crashed".into()),
                crate::unix_now_seconds(),
            )
            .is_err(),
        "a refused send takes no edit"
    );

    // Two refused in one drain; its first announcement retracts both rows.
    let (announced, announced_id) = refuse("announced");
    let (_, also_refused) = refuse("also-refused");
    let refusal = cgka_traits::engine::GroupEvent::QueuedIntentRefused {
        group_id: h.group.clone(),
        intent_id: announced.id.clone(),
        intent_kind: "app_message".into(),
        reason: "app_message_new_members".into(),
        artifact: None,
        size_class: None,
    };
    // A chat-list refresh that fails takes the retraction back with it, so
    // the retried announcement retracts the rows and builds the update.
    let faults = projection_fault_connection(&h.app);
    faults
        .execute_batch(
            "CREATE TRIGGER fail_chat_list_update BEFORE UPDATE ON chat_list_rows
                BEGIN SELECT RAISE(FAIL, 'injected chat list'); END;",
        )
        .unwrap();
    assert!(
        h.app
            .projection_update_for_invalidation_event("alice", &refusal)
            .is_err()
    );
    assert!(
        !retracted(&announced_id),
        "the failed refresh retracted nothing"
    );
    faults
        .execute_batch("DROP TRIGGER fail_chat_list_update")
        .unwrap();
    assert!(
        h.app
            .projection_update_for_invalidation_event("alice", &refusal)
            .unwrap()
            .is_some()
    );
    assert!(retracted(&announced_id));
    assert!(retracted(&also_refused));
    runtime.shutdown_and_close().await.unwrap();
}

/// A raw connection to alice's account database, for installing failure
/// triggers beside the app's own connection.
fn projection_fault_connection(app: &MarmotApp) -> rusqlite::Connection {
    let path = app.account_storage_path("alice");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let key = app
        .sqlcipher_key("alice", &keys, &path, crate::SqlcipherDatabaseKind::Session)
        .unwrap();
    storage_sqlite::expect_uncounted_writes_for_test(&path);
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
}

/// A member-limited edit carries the item again in full, so it is refused,
/// not sent, while a member is unlisted, as the send it edits would be.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edit_to_members_is_refused_while_a_member_is_unlisted() {
    let h = History::new(0).await;
    let runtime = MarmotAppRuntime::new(h.app.clone());
    runtime
        .submit_text("alice", &h.group, "first".into(), "original".into())
        .await
        .unwrap();
    local_send_completed(&runtime, &h.group, "original").await;
    runtime
        .submit_tagged_edit_for_local_send_to_members(
            "alice",
            &h.group,
            "original".into(),
            "second".into(),
            vec![],
            vec!["cc".repeat(32)],
            "edit".into(),
        )
        .await
        .unwrap();
    assert_eq!(
        local_send_settled(&runtime, &h.group, "edit").await,
        crate::LocalSendStatus::RefusedNewMembers
    );
    runtime.shutdown_and_close().await.unwrap();
}
