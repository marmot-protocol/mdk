//! Actual generated upload/publication followed by canonical offline reads, not seeded sent rows.
use super::*;

/// Direct sends and Android's durable token route must both retain exact bytes.
#[tokio::test]
async fn genuine_outgoing_upload_is_local_after_confirmed_send_and_restart() {
    for token_send in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        home.create_account("bob").unwrap();
        let (_relay, app, url) = mock_app(&dir).await;
        let blossom = mock_blossom().await;
        let mut bob = app.client("bob").await.unwrap();
        bob.publish_key_package().await.unwrap();
        let mut alice = app.client("alice").await.unwrap();
        let group = alice
            .create_group("outgoing retention", &["bob"])
            .await
            .unwrap();
        bob.sync().await.unwrap();
        drop(alice);
        drop(bob);
        let runtime = MarmotAppRuntime::new(app.clone());
        let bodies = fixture_bodies();
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
            message_tags: Vec::new(),
        };
        let started = Instant::now();
        let id = if token_send {
            let (_, accepted) = runtime
                .upload_media_with_client_token("alice", &group, request, "fixture-token".into())
                .await
                .unwrap();
            accepted.unwrap().message_id_hex
        } else {
            runtime
                .upload_media("alice", &group, request)
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
                    break source;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let publish_ms = started.elapsed().as_secs_f64() * 1000.0;
        let targets = (0..bodies.len())
            .map(|attachment_index| marmot_app::AttachmentLocalTarget {
                message_id_hex: id.clone(),
                source_message_id_hex: source.clone(),
                attachment_index: attachment_index as u32,
            })
            .collect::<Vec<_>>();
        let started = Instant::now();
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
            MarmotAppConfig::default()
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
                "token_send":token_send,"plaintext_sizes":bodies.iter().map(Vec::len).collect::<Vec<_>>(),"put_requests":bodies.len(),"get_requests":0,"head_requests":0,
                "uploaded_ciphertext_bytes":bodies.iter().map(Vec::len).sum::<usize>()+16*bodies.len(),
                "downloaded_ciphertext_bytes":0,"publish_ms":publish_ms,"local_ms":local_ms,"restart_ten_reads_ms":restart_ten_ms,
            })
        );
        if token_send {
            check_failed_token_admission_releases_upload(&reopened, &group, &blossom, &bodies)
                .await;
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
    let probe: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let app = MarmotApp::with_relay_and_config(
        probe["root"].as_str().unwrap(),
        "wss://relay.example",
        MarmotAppConfig::default(),
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

/// A token conflict after PUT releases its unowned reservation, proven by an
/// immediately affordable second upload at the exact remaining quota.
async fn check_failed_token_admission_releases_upload(
    runtime: &MarmotAppRuntime,
    group: &GroupId,
    blossom: &MockBlossom,
    bodies: &[Vec<u8>],
) {
    runtime
        .set_attachment_download_policy(
            "alice",
            marmot_app::AttachmentDownloadPolicy {
                automatic: false,
                retained_bytes: bodies.iter().map(|b| b.len() as u64).sum::<u64>() + 1024,
                disk_reserve: 0,
                transfer_limit: 1024,
            },
        )
        .await
        .unwrap();
    let request = || MediaUploadRequest {
        attachments: vec![MediaUploadAttachmentRequest {
            file_name: "generated-conflict.bin".into(),
            media_type: "application/octet-stream".into(),
            plaintext: vec![0x39; 1024],
            dim: None,
            thumbhash: None,
        }],
        caption: Some("different generated submission".into()),
        send: true,
        blossom_server: Some(blossom.url.clone()),
        message_tags: Vec::new(),
    };
    let before = blossom.ledger.puts.load(Ordering::SeqCst);
    assert!(
        runtime
            .upload_media_with_client_token("alice", group, request(), "fixture-token".into())
            .await
            .is_err()
    );
    assert_eq!(blossom.ledger.puts.load(Ordering::SeqCst), before + 1);
    let mut request = request();
    request.send = false;
    assert!(runtime.upload_media("alice", group, request).await.is_ok());
    assert_eq!(blossom.ledger.puts.load(Ordering::SeqCst), before + 2);
    assert_eq!(blossom.ledger.gets.load(Ordering::SeqCst), 0);
    assert_eq!(blossom.ledger.heads.load(Ordering::SeqCst), 0);
}
