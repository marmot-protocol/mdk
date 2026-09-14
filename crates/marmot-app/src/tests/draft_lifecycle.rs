use super::*;

#[tokio::test]
async fn draft_send_acceptance_is_durable_before_relay_io_and_survives_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://draft.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("draft", &[]).await.unwrap();
    let hex = hex::encode(group.as_slice());
    app.save_message_draft("alice", &hex, "send this", None, vec![])
        .unwrap();
    let selected = app.selected_message_draft("alice", &hex).unwrap();
    let mut changes = app.subscribe_message_draft_changes();
    relay.block_next_publish();
    let mut sending =
        Box::pin(client.send_message_draft(&group, selected.revision.clone(), vec![]));
    tokio::select! {
        _=relay.wait_for_blocked_publish()=>{},
        result=&mut sending=>panic!("send completed before relay barrier: {result:?}"),
        _=tokio::time::sleep(Duration::from_secs(10))=>panic!("send did not reach relay barrier"),
    }
    assert!(
        app.selected_message_draft("alice", &hex)
            .unwrap()
            .draft
            .is_none()
    );
    let update = changes
        .try_recv()
        .expect("acceptance must notify before relay I/O completes");
    assert_eq!(update.account_label, "alice");
    assert_eq!(update.group_id_hex, hex);
    app.save_message_draft("alice", &hex, "new composer", None, vec![])
        .unwrap();
    let newer = app.selected_message_draft("alice", &hex).unwrap();
    drop(sending);
    assert_eq!(
        app.selected_message_draft("alice", &hex).unwrap().revision,
        newer.revision
    );
    relay.release_publish();
    client.retry_group_convergence(&group).await.unwrap();
    assert_eq!(
        app.selected_message_draft("alice", &hex).unwrap().revision,
        newer.revision
    );
}

#[tokio::test]
async fn editing_after_submission_preserves_the_newer_draft_and_sends_captured_content() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://draft.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("draft", &[]).await.unwrap();
    let hex = hex::encode(group.as_slice());
    let initial = app.selected_message_draft("alice", &hex).unwrap();
    let old = app
        .save_message_draft_if_revision("alice", &initial.revision, "old content", None, vec![])
        .unwrap();
    let mut edited = false;
    let result = client
        .send_message_draft_with_local_projection(&group, old.revision.clone(), vec![], |_| {
            if !edited {
                app.save_message_draft("alice", &hex, "new content", None, vec![])
                    .unwrap();
                edited = true;
            }
        })
        .await
        .unwrap();
    assert_eq!(result.published, 1);
    let newer = app.selected_message_draft("alice", &hex).unwrap();
    assert_eq!(newer.draft.unwrap().content, "new content");
    let timeline = app
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(hex.clone()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        timeline
            .messages
            .iter()
            .any(|m| m.plaintext == "old content")
    );
    assert!(
        !timeline
            .messages
            .iter()
            .any(|m| m.plaintext == "new content")
    );
    let mut changes = app.subscribe_message_draft_changes();
    assert!(matches!(
        client
            .send_message_draft(&group, old.revision, vec![])
            .await,
        Err(AppError::MessageDraftRevisionConflict)
    ));
    assert!(matches!(
        changes.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn draft_metadata_and_conditional_commands_remain_available_through_runtime() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://draft.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("draft", &[]).await.unwrap();
    let hex = hex::encode(group.as_slice());
    drop(client);
    let runtime = MarmotAppRuntime::new(app);
    let initial = runtime.selected_message_draft("alice", &hex).unwrap();
    let mut changes = runtime.subscribe_message_draft_changes();
    let saved = runtime
        .save_message_draft_if_revision(
            "alice",
            &initial.revision,
            "reply",
            Some(&"aa".repeat(32)),
            vec![],
        )
        .unwrap();
    assert_eq!(changes.try_recv().unwrap().group_id_hex, hex);
    let result = runtime
        .send_message_draft("alice", &group, saved.revision, vec![])
        .await
        .unwrap();
    assert_eq!(result.published, 1);
    assert!(
        runtime
            .selected_message_draft("alice", &hex)
            .unwrap()
            .draft
            .is_none()
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn attachment_draft_reply_validates_references_before_clearing() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://draft.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("media", &[]).await.unwrap();
    let hex = hex::encode(group.as_slice());
    let reply = "aa".repeat(32);
    app.save_message_draft(
        "alice",
        &hex,
        "caption",
        Some(&reply),
        vec![crate::MessageDraftAttachment {
            id: "image".into(),
            file_name: "a.png".into(),
            media_type: "image/png".into(),
            plaintext: vec![1, 2, 3],
            dim: None,
            thumbhash: None,
            duration_seconds: None,
            waveform_samples: vec![],
        }],
    )
    .unwrap();
    let selected = app.selected_message_draft("alice", &hex).unwrap();
    assert!(matches!(
        client
            .send_message_draft(&group, selected.revision.clone(), vec![])
            .await,
        Err(AppError::InvalidMessageDraft(_))
    ));
    let epoch = client.group_mls_state(&group).unwrap().epoch;
    let mut reference = MediaAttachmentReference {
        locators: vec![MediaLocator {
            kind: "blossom-v1".into(),
            value: format!("https://media.example/{}.bin", hex::encode([0x33_u8; 32])),
        }],
        ciphertext_sha256: hex::encode([0x33_u8; 32]),
        plaintext_sha256: hex::encode([0x11_u8; 32]),
        nonce_hex: hex::encode([0x22_u8; 12]),
        file_name: "a.png".into(),
        media_type: "image/png".into(),
        version: "encrypted-media-v2".into(),
        source_epoch: epoch + 1,
        dim: None,
        thumbhash: None,
    };
    assert!(matches!(
        client
            .send_message_draft(&group, selected.revision.clone(), vec![reference.clone()])
            .await,
        Err(AppError::MediaReferenceStaleEpoch { .. })
    ));
    assert_eq!(
        app.selected_message_draft("alice", &hex).unwrap().revision,
        selected.revision
    );
    for (file_name, media_type) in [("wrong.png", "image/png"), ("a.png", "video/mp4")] {
        let mut mismatched = reference.clone();
        mismatched.source_epoch = epoch;
        mismatched.file_name = file_name.into();
        mismatched.media_type = media_type.into();
        assert!(matches!(
            client
                .send_message_draft(&group, selected.revision.clone(), vec![mismatched])
                .await,
            Err(AppError::InvalidMessageDraft(_))
        ));
        assert_eq!(
            app.selected_message_draft("alice", &hex).unwrap().revision,
            selected.revision
        );
    }
    reference.source_epoch = epoch;
    let invalid = crate::messages::build_inner_event_with_media_reply(
        &AppMessageIntent::Media {
            attachments: vec![reference.clone()],
            caption: Some("caption".into()),
        },
        &"aa".repeat(32),
        1,
        Some("  "),
    )
    .unwrap_err();
    assert_eq!(invalid.privacy_safe_kind(), "invalid_app_message_payload");
    client
        .send_message_draft(&group, selected.revision, vec![reference])
        .await
        .unwrap();
    assert!(
        app.selected_message_draft("alice", &hex)
            .unwrap()
            .draft
            .is_none()
    );
    let messages = app.messages("alice").unwrap();
    let message = messages
        .iter()
        .find(|message| message.plaintext == "caption")
        .unwrap();
    assert!(
        message
            .tags
            .iter()
            .any(|tag| tag.first().map(String::as_str) == Some("imeta"))
    );
    assert!(message.tags.contains(&vec!["e".into(), reply.clone()]));
    assert!(message.tags.contains(&vec!["q".into(), reply]));
}

#[tokio::test]
async fn draft_conflict_and_missing_group_have_distinct_codes() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://draft.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("draft", &[]).await.unwrap();
    let hex = hex::encode(group.as_slice());
    let initial = app.selected_message_draft("alice", &hex).unwrap();
    app.save_message_draft("alice", &hex, "edit", None, vec![])
        .unwrap();
    let error = app
        .clear_message_draft_if_revision("alice", &initial.revision)
        .err()
        .unwrap();
    assert_eq!(error.privacy_safe_kind(), "message_draft_revision_conflict");
    let error = app
        .selected_message_draft("alice", "missing")
        .err()
        .unwrap();
    assert!(matches!(error, AppError::UnknownGroup(_)));
    app.draft_storage("alice")
        .unwrap()
        .delete_local_group_data(&hex)
        .unwrap();
    assert!(matches!(
        app.save_message_draft_if_revision("alice", &initial.revision, "", None, vec![]),
        Err(AppError::UnknownGroup(_))
    ));
    assert!(matches!(
        app.clear_message_draft_if_revision("alice", &initial.revision),
        Err(AppError::UnknownGroup(_))
    ));
    assert!(matches!(
        app.message_draft_attachment_if_revision("alice", &initial.revision, "missing"),
        Err(AppError::UnknownGroup(_))
    ));
}
