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
    assert!(matches!(
        runtime
            .local_send_status("alice", &h.group, "edit-token")
            .unwrap(),
        Some(crate::LocalSendStatus::Queued)
    ));
    h.relay.release_publish();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                runtime
                    .local_send_status("alice", &h.group, "edit-token")
                    .unwrap(),
                Some(crate::LocalSendStatus::Completed(_))
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let row = h
        .app
        .account_storage("alice")
        .unwrap()
        .timeline_message(&hex::encode(h.group.as_slice()), &original.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(row.plaintext, "after revision");
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
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
            .local_submission(&group_hex, "edit-token")
            .unwrap()
            .is_none()
    );
    h.app.close_storage().unwrap();
}

#[tokio::test]
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

#[tokio::test]
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
            },
            None,
            Some("original-token".into()),
            crate::unix_now_seconds(),
        )
        .unwrap();
    let storage = h.app.account_storage("alice").unwrap();
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
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                runtime
                    .local_send_status("alice", &h.group, "edit-token")
                    .unwrap(),
                Some(crate::LocalSendStatus::Completed(_))
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        runtime
            .local_send_status("alice", &h.group, "original-token")
            .unwrap(),
        Some(crate::LocalSendStatus::Completed(_))
    ));
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                runtime
                    .local_send_status("alice", &h.group, "latest-edit-token")
                    .unwrap(),
                Some(crate::LocalSendStatus::Completed(_))
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let row = reopened
        .account_storage("alice")
        .unwrap()
        .timeline_message(&group_hex, &original.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(row.plaintext, "latest revision");
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
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
            },
            None,
            Some("original-token".into()),
            crate::unix_now_seconds(),
        )
        .unwrap();
    h.app
        .account_storage("alice")
        .unwrap()
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
            .next_local_submission()
            .unwrap()
            .is_none()
    );
    runtime.shutdown_and_close().await.unwrap();
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
    let completed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(crate::LocalSendStatus::Completed(summary)) = runtime
                .local_send_status("alice", &h.group, "restart-token")
                .unwrap()
            {
                break summary;
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
            },
            None,
        )
        .unwrap();
    assert_eq!(retry, accepted);
    assert!(update.is_none());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn rejected_submission_requires_a_new_token_after_restart() {
    let h = History::new(0).await;
    let request = LocalMessageRequest {
        content: "rejected attempt".into(),
        reply_to: None,
        attachments: vec![],
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
    let store = reopened.account_storage("alice").unwrap();
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

#[tokio::test]
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
    let store = h.app.account_storage("alice").unwrap();
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
