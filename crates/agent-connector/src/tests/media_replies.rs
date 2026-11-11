use super::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

#[path = "../../../marmot-app/tests/support/limited_relay.rs"]
mod limited_relay;

struct BlobServer {
    url: String,
    puts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for BlobServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn blob_server() -> BlobServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server_url = url.clone();
    let puts = Arc::new(AtomicUsize::new(0));
    let server_puts = puts.clone();
    let task = tokio::spawn(async move {
        let mut blobs = HashMap::<String, Vec<u8>>::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            let request = line
                .split_whitespace()
                .take(2)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let mut length = 0;
            loop {
                line.clear();
                stream.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            let (status, content_type, response) = match request[0].as_str() {
                "PUT" => {
                    assert_eq!(request[1], "/upload");
                    let hash = hex::encode(Sha256::digest(&body));
                    server_puts.fetch_add(1, Ordering::SeqCst);
                    let response = serde_json::to_vec(&serde_json::json!({
                        "url": format!("{server_url}/{hash}.bin"),
                        "sha256": hash, "size": body.len(),
                        "type": "application/octet-stream", "uploaded": 1,
                    }))
                    .unwrap();
                    blobs.insert(format!("/{hash}.bin"), body);
                    (201, "application/json", response)
                }
                "GET" => match blobs.get(&request[1]) {
                    Some(blob) => (200, "application/octet-stream", blob.clone()),
                    None => (404, "text/plain", b"missing".to_vec()),
                },
                "HEAD" => (404, "text/plain", Vec::new()),
                method => panic!("unexpected blob request {method}"),
            };
            let header = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&response).await.unwrap();
            stream.flush().await.unwrap();
        }
    });
    BlobServer { url, puts, task }
}

async fn received_media(app: &MarmotApp, label: &str, message_id: &str) -> AppMessageRecord {
    timeout(Duration::from_secs(30), async {
        loop {
            if let Some(message) = app
                .messages(label)
                .unwrap()
                .into_iter()
                .find(|row| row.message_id_hex == message_id)
            {
                return message;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("recipient did not receive the media message")
}

fn media_refs(message: &AppMessageRecord) -> Vec<marmot_app::MediaAttachmentReference> {
    message
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .map(|tag| {
            marmot_app::media_attachment_from_imeta_tag(tag, message.source_epoch, true).unwrap()
        })
        .collect()
}

async fn check_media_reply(
    runtime: &MarmotAppRuntime,
    account: &str,
    group: &GroupId,
    message: &AppMessageRecord,
    target: &str,
    expected: &[(&str, &[u8])],
) {
    for name in ["e", "q"] {
        assert_eq!(
            message
                .tags
                .iter()
                .filter(|tag| tag.first().map(String::as_str) == Some(name))
                .collect::<Vec<_>>(),
            vec![&vec![name.to_owned(), target.to_owned()]],
        );
    }
    let media = media_refs(message);
    assert_eq!(media.len(), expected.len());
    for (reference, (name, bytes)) in media.into_iter().zip(expected) {
        assert_eq!(reference.file_name.as_str(), *name);
        let downloaded = runtime
            .download_media(account, group, reference)
            .await
            .unwrap();
        assert_eq!(downloaded.plaintext.as_slice(), *bytes);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn media_replies_reach_recipient() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = blob_server().await;
    let (_relay, relay_url) = limited_relay::mock_relay().await;
    let socket = dir.path().join("dev/wn-agent.sock");
    let mut config = test_config(
        dir.path(),
        socket.clone(),
        vec![relay_url.clone()],
        false,
        false,
    );
    config.media_allowed_roots = vec![dir.path().to_owned()];
    let mut connector = AgentConnector::open(config).unwrap();
    // Only the fixture's HTTP/dial policy differs from the production runtime.
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        relay_url.clone(),
        marmot_app::MarmotAppConfig::default()
            .with_allow_loopback_blob_endpoints(true)
            .with_allow_loopback_relay_endpoints(true)
            .with_deployment(marmot_app::MarmotDeployment {
                new_group_media_endpoints: vec![blobs.url.clone()],
                ..marmot_app::MarmotDeployment::neutral()
            }),
    );
    connector.app = app.clone();
    connector.runtime = app.runtime();
    connector.inbound_catch_up = InboundCatchUpDriver::new(
        connector.runtime.clone(),
        connector.reconcile_telemetry.clone(),
    );
    let setup = AccountSetupRequest {
        default_relays: vec![crate::validation::endpoint(&relay_url)],
        bootstrap_relays: vec![crate::validation::endpoint(&relay_url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let agent = connector
        .runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap()
        .account;
    let human = connector
        .runtime
        .create_identity(setup)
        .await
        .unwrap()
        .account;
    let group = connector
        .runtime
        .create_group(
            &agent.label,
            "media replies",
            std::slice::from_ref(&human.account_id_hex),
            None,
        )
        .await
        .unwrap();
    accept_group_invite_retrying_busy(&connector.runtime, &human.label, &group).await;
    let group_hex = hex::encode(group.as_slice());
    let target = connector
        .runtime
        .send_message(&human.label, &group, b"send the attachments here".to_vec())
        .await
        .unwrap()
        .message_ids[0]
        .clone();
    let other = connector
        .runtime
        .send_message(&human.label, &group, b"a different message".to_vec())
        .await
        .unwrap()
        .message_ids[0]
        .clone();
    connector
        .runtime
        .save_message_draft(
            &agent.label,
            &group_hex,
            "keep my draft",
            Some(&other),
            Vec::new(),
        )
        .unwrap();
    connector.start().await.unwrap();
    let listener = bind_connector_socket(&socket).unwrap();
    let puts = blobs.puts.load(Ordering::SeqCst);
    let mut worker = tokio::process::Command::new("python3");
    worker
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../integrations/hermes/tests/marmot/media_reply_smoke.py"
        ))
        .args([
            socket.to_str().unwrap(),
            &agent.account_id_hex,
            &group_hex,
            &target,
            dir.path().to_str().unwrap(),
        ])
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .kill_on_drop(true);
    let serve = async {
        for _ in 0..6 {
            connector
                .serve_once(&listener)
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok::<_, String>(())
    };
    let drive = async {
        let output = worker.output().await.map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        Ok(output)
    };
    let ((), output) = timeout(CONTROL_RESPONSE_TIMEOUT, async {
        tokio::try_join!(serve, drive)
    })
    .await
    .unwrap()
    .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["dropped_response"], true);
    let ids = response["message_ids_hex"].as_array().unwrap();
    assert_eq!(ids.len(), 5);
    for (index, id) in ids.iter().enumerate() {
        let message = received_media(&app, &human.label, id.as_str().unwrap()).await;
        let first = if index == 4 { 0 } else { index };
        let name = format!("python-{first}.txt");
        let bytes = format!("python attachment {first}");
        let mut expected = vec![(name.as_str(), bytes.as_bytes())];
        if index == 4 {
            expected.push(("python-1.txt", b"python attachment 1"));
        }
        check_media_reply(
            &connector.runtime,
            &human.label,
            &group,
            &message,
            &target,
            &expected,
        )
        .await;
    }
    assert_eq!(
        blobs.puts.load(Ordering::SeqCst),
        puts + 6,
        "the lost-response retry must not upload again"
    );
    let contents = [
        b"first attachment".as_slice(),
        b"second attachment".as_slice(),
    ];
    let attachments = contents
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let path = dir.path().join(format!("{index}.txt"));
            std::fs::write(&path, bytes).unwrap();
            agent_control::AgentControlMediaUpload {
                path: path.to_string_lossy().into_owned(),
                media_type: "text/plain".into(),
                file_name: format!("{index}.txt"),
                dim: None,
                thumbhash: None,
            }
        })
        .collect::<Vec<_>>();
    let request =
        |caption: Option<&str>, reply: Option<&str>, key: &str| AgentControlRequest::SendMedia {
            account_id_hex: agent.account_id_hex.clone(),
            group_id_hex: group_hex.clone(),
            attachments: attachments.clone(),
            caption: caption.map(str::to_owned),
            reply_to_message_id_hex: reply.map(str::to_owned),
            idempotency_key: Some(key.into()),
        };
    for (index, caption) in [Some("ordered album"), None].into_iter().enumerate() {
        let key = format!("media-reply-{index}");
        let response = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "send",
            request(caption, Some(&target.to_uppercase()), &key),
        )
        .await
        .payload;
        let AgentControlResponse::FinalSent {
            ref message_ids_hex,
            ..
        } = response
        else {
            panic!("media send failed: {response:?}");
        };
        assert_eq!(message_ids_hex.len(), 1);
        let message = received_media(&app, &human.label, &message_ids_hex[0]).await;
        assert_eq!(message.plaintext, caption.unwrap_or_default());
        for name in ["e", "q"] {
            assert_eq!(
                message
                    .tags
                    .iter()
                    .filter(|tag| tag.first().map(String::as_str) == Some(name))
                    .collect::<Vec<_>>(),
                vec![&vec![name.to_owned(), target.clone()]]
            );
        }
        let media = media_refs(&message);
        assert_eq!(media.len(), contents.len());
        for (slot, reference) in media.into_iter().enumerate() {
            assert_eq!(reference.file_name, format!("{slot}.txt"));
            let downloaded = connector
                .runtime
                .download_media(&human.label, &group, reference)
                .await
                .unwrap();
            assert_eq!(downloaded.plaintext, contents[slot]);
        }
        let puts = blobs.puts.load(Ordering::SeqCst);
        let retry = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "retry",
            request(caption, Some(&target), &key),
        )
        .await
        .payload;
        assert_eq!(retry, response);
        assert_eq!(blobs.puts.load(Ordering::SeqCst), puts);
        let conflict = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "conflict",
            request(caption, Some(&other), &key),
        )
        .await
        .payload;
        assert!(
            matches!(conflict, AgentControlResponse::Error { code, retryable: false, .. } if code == "media_idempotency_conflict")
        );
        assert_eq!(blobs.puts.load(Ordering::SeqCst), puts);
    }
    for (index, reply) in [None, Some(serde_json::Value::Null)]
        .into_iter()
        .enumerate()
    {
        let mut wire =
            serde_json::to_value(request(None, None, &format!("plain-{index}"))).unwrap();
        if let Some(reply) = reply {
            wire["reply_to_message_id_hex"] = reply;
        }
        let response = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "plain",
            serde_json::from_value(wire).unwrap(),
        )
        .await
        .payload;
        let AgentControlResponse::FinalSent {
            message_ids_hex, ..
        } = response
        else {
            panic!("plain send failed: {response:?}");
        };
        let message = received_media(&app, &human.label, &message_ids_hex[0]).await;
        assert_eq!(reply_target_from_tags(&message.tags), None);
        assert_eq!(media_refs(&message).len(), 2);
    }
    let puts = blobs.puts.load(Ordering::SeqCst);
    for target in ["", "no hex", "ab", "abc"] {
        let response = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "invalid",
            request(None, Some(target), "invalid"),
        )
        .await
        .payload;
        assert!(
            matches!(response, AgentControlResponse::Error { code, retryable: false, .. } if code == "invalid_hex")
        );
    }
    assert_eq!(blobs.puts.load(Ordering::SeqCst), puts);
    let upload = connector
        .runtime
        .upload_media(
            &agent.label,
            &group,
            marmot_app::MediaUploadRequest {
                attachments: vec![marmot_app::MediaUploadAttachmentRequest {
                    file_name: "standalone.txt".into(),
                    media_type: "text/plain".into(),
                    plaintext: b"standalone attachment".to_vec(),
                    dim: None,
                    thumbhash: None,
                }],
                caption: None,
                message_tags: Vec::new(),
                send: false,
                blossom_server: None,
            },
        )
        .await
        .unwrap();
    let references = upload
        .attachments
        .into_iter()
        .map(|item| item.reference)
        .collect::<Vec<_>>();
    for invalid in ["not-hex".to_owned(), "ab".to_owned(), format!(" {target}")] {
        let error = connector
            .runtime
            .submit_media_attachments(
                &agent.label,
                &group,
                references.clone(),
                None,
                Some(invalid),
                "invalid-app-target".into(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, AppError::InvalidAppMessagePayload(message) if message.contains("media reply target"))
        );
    }
    let accepted = connector
        .runtime
        .submit_media_attachments(
            &agent.label,
            &group,
            references,
            None,
            Some(target.to_uppercase()),
            "standalone-media-reply".into(),
        )
        .await
        .unwrap();
    let standalone = received_media(&app, &human.label, &accepted.message_id_hex).await;
    assert_eq!(
        reply_target_from_tags(&standalone.tags).as_deref(),
        Some(target.as_str())
    );
    let downloaded = connector
        .runtime
        .download_media(&human.label, &group, media_refs(&standalone).remove(0))
        .await
        .unwrap();
    assert_eq!(downloaded.plaintext, b"standalone attachment");
    let durable_request = |message_tags| marmot_app::MediaUploadRequest {
        attachments: vec![marmot_app::MediaUploadAttachmentRequest {
            file_name: "durable.txt".into(),
            media_type: "text/plain".into(),
            plaintext: b"durable attachment".to_vec(),
            dim: None,
            thumbhash: None,
        }],
        caption: Some("durable reply".into()),
        message_tags,
        send: true,
        blossom_server: None,
    };
    let puts = blobs.puts.load(Ordering::SeqCst);
    for tags in [
        vec![vec!["e".into(), "not-hex".into()]],
        vec![vec!["q".into()]],
        vec![
            vec!["e".into(), target.clone()],
            vec!["q".into(), other.clone()],
        ],
    ] {
        let error = connector
            .runtime
            .upload_media_with_client_token(
                &agent.label,
                &group,
                durable_request(tags),
                "invalid-durable-reply".into(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, AppError::InvalidAppMessagePayload(_)));
    }
    assert_eq!(
        blobs.puts.load(Ordering::SeqCst),
        puts,
        "invalid reply metadata must fail before PUT"
    );
    let (uploaded, accepted) = connector
        .runtime
        .upload_media_with_client_token(
            &agent.label,
            &group,
            durable_request(vec![
                vec!["e".into(), target.to_uppercase()],
                vec!["q".into(), target.clone()],
            ]),
            "durable-media-reply".into(),
        )
        .await
        .unwrap();
    let accepted = accepted.unwrap();
    let message = received_media(&app, &human.label, &accepted.message_id_hex).await;
    check_media_reply(
        &connector.runtime,
        &human.label,
        &group,
        &message,
        &target,
        &[("durable.txt", b"durable attachment")],
    )
    .await;
    let references = uploaded
        .attachments
        .into_iter()
        .map(|item| item.reference)
        .collect::<Vec<_>>();
    let retry = connector
        .runtime
        .submit_media_attachments(
            &agent.label,
            &group,
            references.clone(),
            Some("durable reply".into()),
            Some(target.to_uppercase()),
            "durable-media-reply".into(),
        )
        .await
        .unwrap();
    assert_eq!(retry, accepted);
    let conflict = connector
        .runtime
        .submit_media_attachments(
            &agent.label,
            &group,
            references,
            Some("durable reply".into()),
            Some(other.clone()),
            "durable-media-reply".into(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(conflict, AppError::InvalidAppMessagePayload(message) if message == "client token is already bound to another submission")
    );

    let path = dir.path().join("durable-file.txt");
    std::fs::write(&path, b"file-backed attachment").unwrap();
    let file_request = |message_tags| marmot_app::MediaFileUploadRequest {
        attachments: vec![marmot_app::MediaFileUploadAttachmentRequest {
            source_path: path.to_string_lossy().into_owned(),
            expected_size: Some(22),
            file_name: "durable-file.txt".into(),
            media_type: "text/plain".into(),
            dim: None,
            thumbhash: None,
        }],
        caption: None,
        message_tags,
        send: true,
        blossom_server: None,
    };
    let puts = blobs.puts.load(Ordering::SeqCst);
    let invalid = connector
        .runtime
        .upload_media_files_with_client_token(
            &agent.label,
            &group,
            file_request(vec![vec!["q".into(), "not-hex".into()]]),
            Arc::new(marmot_app::MediaFileTransferControl::default()),
            "invalid-file-reply".into(),
        )
        .await
        .unwrap_err();
    assert!(matches!(invalid, AppError::InvalidAppMessagePayload(_)));
    assert_eq!(blobs.puts.load(Ordering::SeqCst), puts);
    let (_, accepted) = connector
        .runtime
        .upload_media_files_with_client_token(
            &agent.label,
            &group,
            file_request(vec![vec!["q".into(), target.to_uppercase()]]),
            Arc::new(marmot_app::MediaFileTransferControl::default()),
            "durable-file-reply".into(),
        )
        .await
        .unwrap();
    let message = received_media(&app, &human.label, &accepted.unwrap().message_id_hex).await;
    check_media_reply(
        &connector.runtime,
        &human.label,
        &group,
        &message,
        &target,
        &[("durable-file.txt", b"file-backed attachment")],
    )
    .await;
    let draft = connector
        .runtime
        .message_draft(&agent.label, &group_hex)
        .unwrap()
        .unwrap();
    assert_eq!(draft.content, "keep my draft");
    assert_eq!(
        draft.reply_to_message_id_hex.as_deref(),
        Some(other.as_str())
    );
    let replies = app
        .messages(&human.label)
        .unwrap()
        .into_iter()
        .filter(|message| {
            reply_target_from_tags(&message.tags).as_deref() == Some(target.as_str())
                && !media_refs(message).is_empty()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        replies.len(),
        10,
        "matching retries must not publish another album"
    );
    connector.runtime.shutdown_and_close().await.unwrap();
}
