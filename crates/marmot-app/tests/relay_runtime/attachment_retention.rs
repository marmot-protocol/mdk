//! Actual generated upload/publication followed by canonical offline reads, not seeded sent rows.
use super::*;

/// Direct sends and Android's durable token route must both retain exact bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_outgoing_upload_is_local_after_confirmed_send_and_restart() {
    for (token_send, file_send) in [(false, false), (true, false), (true, true)] {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let bob_id = home.create_account("bob").unwrap().account_id_hex;
        let (_relay, app, url) = mock_app_with(&dir, |config| {
            config.with_attachment_acquisition_mode(
                marmot_app::AttachmentAcquisitionMode::HostManaged,
            )
        })
        .await;
        let blossom = mock_blossom().await;
        let mut bob = app.client("bob").await.unwrap();
        bob.publish_key_package().await.unwrap();
        let mut alice = app.client("alice").await.unwrap();
        let group = alice
            .create_group("outgoing retention", &["bob"])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        bob.sync().await.unwrap();
        drop(alice);
        drop(bob);
        let runtime = MarmotAppRuntime::new(app.clone());
        let mut events = runtime.subscribe();
        assert!(runtime.sign_in_account("bob").await.unwrap().running);
        let bodies = fixture_bodies();
        let tags = vec![vec!["turn".to_owned(), "fixture-turn".to_owned()]];
        let request = MediaUploadRequest {
            attachments: bodies
                .iter()
                .enumerate()
                .map(|(index, bytes)| MediaUploadAttachmentRequest {
                    file_name: format!("generated-{index}.bin"),
                    media_type: "application/octet-stream".into(),
                    plaintext: bytes.clone(),
                    dim: None,
                    thumbhash: None,
                })
                .collect(),
            caption: Some("generated fixture".into()),
            send: true,
            blossom_server: Some(blossom.url.clone()),
            message_tags: tags.clone(),
        };
        let paths = file_send.then(|| {
            bodies
                .iter()
                .enumerate()
                .map(|(index, bytes)| {
                    let path = dir.path().join(format!("fixture-input-{index}"));
                    fs_private::write_private(&path, bytes).unwrap();
                    path.to_str().unwrap().to_owned()
                })
                .collect::<Vec<_>>()
        });
        let started = Instant::now();
        let first = if token_send {
            let (first, second) = tokio::join!(
                submit_fixture_media(&runtime, &group, request.clone(), paths.as_deref()),
                submit_fixture_media(&runtime, &group, request.clone(), paths.as_deref()),
            );
            let first = first.unwrap();
            assert_eq!(first, second.unwrap());
            Some(first)
        } else {
            None
        };
        let id = if let Some((_, accepted)) = &first {
            accepted.as_ref().unwrap().message_id_hex.clone()
        } else {
            runtime
                .upload_media("alice", &group, request.clone())
                .await
                .unwrap()
                .sent
                .unwrap()
                .message_ids[0]
                .clone()
        };
        blossom.ledger.deny_reads.store(true, Ordering::SeqCst);
        let group_hex = hex::encode(group.as_slice());
        let source = timeout(Duration::from_secs(30), async {
            loop {
                if let Some(row) = runtime.timeline_message("alice", &group_hex, &id).unwrap()
                    && let Some(source) = row.source_message_id_hex
                {
                    assert!(row.tags.contains(&tags[0]));
                    break source;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let publish_ms = started.elapsed().as_secs_f64() * 1000.0;
        wait_for_event_within(&mut events, Duration::from_secs(30), |event| {
            matches!(event, MarmotAppEvent::MessageReceived(received)
                if received.account_id_hex == bob_id
                    && received.message.group_id == group
                    && received.message.message_id_hex == id)
        })
        .await;
        let received = app
            .timeline_message("bob", &group_hex, &id)
            .unwrap()
            .unwrap();
        assert!(received.tags.contains(&tags[0]));
        let targets = (0..bodies.len())
            .map(|attachment_index| marmot_app::AttachmentLocalTarget {
                message_id_hex: id.clone(),
                source_message_id_hex: source.clone(),
                attachment_index: attachment_index as u32,
            })
            .collect::<Vec<_>>();
        let started = Instant::now();
        // The account worker promotes the staged uploads once the send is
        // confirmed.
        timeout(Duration::from_secs(30), async {
            while runtime
                .attachment_local_assets("alice", &group, targets.clone())
                .await
                .unwrap()
                .iter()
                .any(Option::is_none)
            {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        check_local_bytes(&runtime, &group, &targets, &bodies).await;
        let local_ms = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(blossom.ledger.puts.load(Ordering::SeqCst), bodies.len());
        assert_eq!(
            blossom.ledger.uploaded_bytes.load(Ordering::SeqCst),
            bodies.iter().map(Vec::len).sum::<usize>() + 16 * bodies.len()
        );
        assert_eq!(blossom.ledger.gets.load(Ordering::SeqCst), 0);
        assert_eq!(blossom.ledger.heads.load(Ordering::SeqCst), 0);
        assert_eq!(blossom.ledger.response_bytes.load(Ordering::SeqCst), 0);
        runtime.shutdown_and_close().await.unwrap();
        drop(runtime);
        drop(app);
        // Local access needs neither a live relay worker nor automatic downloads.
        let reopened = MarmotApp::with_relay_and_config(
            dir.path(),
            url,
            MarmotAppConfig::white_noise()
                .with_allow_loopback_relay_endpoints(true)
                .with_allow_loopback_blob_endpoints(true),
        );
        let reopened = MarmotAppRuntime::new(reopened);
        let started = Instant::now();
        for _ in 0..10 {
            check_local_bytes(&reopened, &group, &targets, &bodies).await;
        }
        let restart_ten_ms = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(blossom.ledger.gets.load(Ordering::SeqCst), 0);
        assert_eq!(blossom.ledger.heads.load(Ordering::SeqCst), 0);
        assert_eq!(blossom.ledger.response_bytes.load(Ordering::SeqCst), 0);
        eprintln!(
            "ATTACHMENT_RETENTION {}",
            serde_json::json!({
                "token_send":token_send,"file_send":file_send,"plaintext_sizes":bodies.iter().map(Vec::len).collect::<Vec<_>>(),"put_requests":bodies.len(),"get_requests":0,"head_requests":0,
                "uploaded_ciphertext_bytes":bodies.iter().map(Vec::len).sum::<usize>()+16*bodies.len(),
                "downloaded_ciphertext_bytes":0,"publish_ms":publish_ms,"local_ms":local_ms,"restart_ten_reads_ms":restart_ten_ms,
            })
        );
        if let Some(first) = first {
            let same = submit_fixture_media(&reopened, &group, request.clone(), paths.as_deref())
                .await
                .unwrap();
            assert_eq!(same, first);
            let mut changed_tags = request.clone();
            changed_tags.message_tags[0][1] = "other-turn".to_owned();
            let conflict = submit_fixture_media(&reopened, &group, changed_tags, paths.as_deref())
                .await
                .unwrap_err();
            let mut changed_body = request.clone();
            changed_body.attachments[0].plaintext[0] ^= 1;
            if let Some(paths) = &paths {
                std::fs::write(&paths[0], &changed_body.attachments[0].plaintext).unwrap();
            }
            let body_conflict =
                submit_fixture_media(&reopened, &group, changed_body, paths.as_deref())
                    .await
                    .unwrap_err();
            for error in [conflict, body_conflict] {
                assert!(matches!(
                    error,
                    marmot_app::AppError::InvalidAppMessagePayload(message)
                        if message == "client token is already bound to another submission"
                ));
            }
            if let Some(paths) = &paths {
                std::fs::write(&paths[0], &request.attachments[0].plaintext).unwrap();
            }
            reopened
                .accounts()
                .deactivate_account("alice")
                .await
                .unwrap();
            let error = submit_fixture_media(&reopened, &group, request, paths.as_deref())
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                marmot_app::AppError::RelayDirectory(message) if message == "account is signed out"
            ));
            assert!(
                reopened
                    .local_send_status("alice", &group, "fixture-token")
                    .unwrap()
                    .is_some()
            );
            assert_eq!(blossom.ledger.puts.load(Ordering::SeqCst), bodies.len());
        }
        reopened.shutdown_and_close().await.unwrap();
        // Execute reads in a fresh native process while this fixture ledger remains alive.
        let probe = dir.path().join("generated-retention-probe.json");
        fs_private::write_private(&probe,serde_json::to_string(&serde_json::json!({"root":dir.path(),"group":group_hex,"message":id,"source":source})).unwrap().as_bytes()).unwrap();
        let exe = std::env::current_exe().unwrap();
        let result = tokio::task::spawn_blocking(move || {
            std::process::Command::new(exe)
                .args([
                    "--exact",
                    "attachment_retention::outgoing_retained_subprocess_probe",
                    "--nocapture",
                ])
                .env("MDK_ATTACHMENT_RETENTION_PROBE", probe)
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            result.status.success(),
            "fresh native process retained-byte probe failed"
        );
        assert_eq!(blossom.ledger.gets.load(Ordering::SeqCst), 0);
        assert_eq!(blossom.ledger.heads.load(Ordering::SeqCst), 0);
    }
}

/// Read both original source slots in bounded chunks and verify foreign-account isolation.
async fn check_local_bytes(
    runtime: &MarmotAppRuntime,
    group: &GroupId,
    targets: &[marmot_app::AttachmentLocalTarget],
    bodies: &[Vec<u8>],
) {
    let assets = runtime
        .attachment_local_assets("alice", group, targets.to_vec())
        .await
        .unwrap();
    for (asset, expected) in assets.into_iter().zip(bodies) {
        let asset = asset.expect("genuine outgoing source must be retained");
        let mut received = Vec::new();
        for offset in (0..expected.len()).step_by(64 * 1024) {
            let chunk = runtime
                .read_attachment_asset("alice", asset.reference.clone(), offset as u64, 64 * 1024)
                .await
                .unwrap()
                .unwrap();
            received.extend_from_slice(&chunk);
        }
        assert!(
            received == *expected,
            "retained generated content must match exactly"
        );
        assert!(
            runtime
                .read_attachment_asset("bob", asset.reference.clone(), 0, 4096)
                .await
                .unwrap()
                .is_none()
        );
    }
}

/// Child harness receives only generated source identity; reads without workers or network.
#[test]
fn outgoing_retained_subprocess_probe() {
    let Some(path) = std::env::var_os("MDK_ATTACHMENT_RETENTION_PROBE") else {
        return;
    };
    // This fresh process does not inherit its parent's fixture opt-in.
    storage_sqlite::relax_storage_for_test_process();
    let probe: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let app = MarmotApp::with_relay_and_config(
        probe["root"].as_str().unwrap(),
        "wss://relay.example",
        MarmotAppConfig::white_noise(),
    );
    let runtime = MarmotAppRuntime::new(app);
    let group = GroupId::new(hex::decode(probe["group"].as_str().unwrap()).unwrap());
    let bodies = fixture_bodies();
    let targets = (0..bodies.len())
        .map(|attachment_index| marmot_app::AttachmentLocalTarget {
            message_id_hex: probe["message"].as_str().unwrap().into(),
            source_message_id_hex: probe["source"].as_str().unwrap().into(),
            attachment_index: attachment_index as u32,
        })
        .collect::<Vec<_>>();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        check_local_bytes(&runtime, &group, &targets, &bodies).await;
        runtime.shutdown_and_close().await.unwrap();
    });
}

/// Exercise small documents and a generated eight-MiB payload within shipped limits.
fn fixture_bodies() -> Vec<Vec<u8>> {
    vec![
        vec![0x41; 1024],
        vec![0x72; 64 * 1024],
        vec![0x53; 8 * 1024 * 1024],
    ]
}

async fn submit_fixture_media(
    runtime: &MarmotAppRuntime,
    group: &GroupId,
    request: MediaUploadRequest,
    paths: Option<&[String]>,
) -> Result<
    (
        marmot_app::MediaUploadResult,
        Option<marmot_app::LocalSendAcceptance>,
    ),
    marmot_app::AppError,
> {
    let token = "fixture-token".to_owned();
    let Some(paths) = paths else {
        return runtime
            .upload_media_with_client_token("alice", group, request, token)
            .await;
    };
    let request = marmot_app::MediaFileUploadRequest {
        attachments: request
            .attachments
            .into_iter()
            .zip(paths)
            .map(
                |(attachment, path)| marmot_app::MediaFileUploadAttachmentRequest {
                    source_path: path.clone(),
                    expected_size: Some(attachment.plaintext.len() as u64),
                    file_name: attachment.file_name,
                    media_type: attachment.media_type,
                    dim: attachment.dim,
                    thumbhash: attachment.thumbhash,
                },
            )
            .collect(),
        caption: request.caption,
        send: request.send,
        blossom_server: request.blossom_server,
        message_tags: request.message_tags,
    };
    runtime
        .upload_media_files_with_client_token(
            "alice",
            group,
            request,
            std::sync::Arc::new(marmot_app::MediaFileTransferControl::default()),
            token,
        )
        .await
}
