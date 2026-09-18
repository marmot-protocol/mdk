use super::*;
use crate::media::attachment_resume::AttachmentResume;
use sha2::{Digest, Sha256};
use storage_sqlite::{ATTACHMENT_CHECKPOINT_BYTES, AttachmentPartialIdentity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn client_at(
    dir: &std::path::Path,
    reference: &crate::MediaAttachmentReference,
    create: bool,
) -> (AppClient, SqliteAccountStorage) {
    if create {
        AccountHome::open(dir).create_account("alice").unwrap();
    }
    let app = MarmotApp::with_relay_and_config(
        dir,
        "wss://relay.example",
        MarmotAppConfig {
            allow_loopback_blob_endpoints: true,
            attachment_acquisition: Some(crate::AttachmentAcquisitionPolicy::default()),
            ..Default::default()
        },
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let store = app.account_storage("alice").unwrap();
    if create {
        seed(&store, reference, false);
    }
    client.state.groups.retain(|g| g.group_id_hex != GROUP);
    client.state.groups.push(projection(reference));
    store
        .remember_encrypted_media_epoch_secret(
            GROUP,
            crate::GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
            3,
            &[7; 32],
        )
        .unwrap();
    (client, store)
}
fn claim(store: &SqliteAccountStorage) -> AttachmentAcquisition {
    let now = crate::unix_now_seconds();
    store.resume_attachment_acquisitions(now, 64).unwrap();
    admit_demands(store, now, true).unwrap();
    let asset = store.due_attachment_acquisitions(now, 1).unwrap().remove(0);
    store
        .claim_attachment_acquisition(&asset, now, now + 1200)
        .unwrap()
        .unwrap()
}
fn resume_context(
    store: &SqliteAccountStorage,
    job: &AttachmentAcquisition,
    dir: &std::path::Path,
    reference: &crate::MediaAttachmentReference,
) -> AttachmentResume {
    AttachmentResume {
        storage: store.clone(),
        job: job.clone(),
        ciphertext_digest: hex::decode(&reference.ciphertext_sha256)
            .unwrap()
            .try_into()
            .unwrap(),
        budget: 128 * 1024 * 1024,
        directory: dir.into(),
        disk_reserve: 0,
    }
}
async fn headers(socket: &mut tokio::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let byte = socket.read_u8().await.unwrap();
        bytes.push(byte);
        assert!(bytes.len() < 16384);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(bytes).unwrap().to_ascii_lowercase()
}
async fn respond(
    socket: &mut tokio::net::TcpStream,
    status: &str,
    extra: &str,
    body: &[u8],
    length: usize,
) {
    socket
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\nContent-Length: {length}\r\nConnection: close\r\n{extra}\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    socket.write_all(body).await.unwrap();
}
async fn listener_fixture(
    body: &[u8],
) -> (
    tokio::net::TcpListener,
    crate::MediaAttachmentReference,
    Vec<u8>,
) {
    let (mut reference, cipher) = crate::media::tests::attachment_worker_fixture(body);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    reference.locators = vec![crate::MediaLocator {
        kind: "blossom-v1".into(),
        value: format!(
            "http://{}/{}.bin",
            listener.local_addr().unwrap(),
            reference.ciphertext_sha256
        ),
    }];
    (listener, reference, cipher)
}

#[tokio::test]
async fn attachment_resume_interrupted_transfer_reopens_and_publishes_verified_bytes() {
    let plaintext = vec![42; 2 * ATTACHMENT_CHECKPOINT_BYTES];
    let (listener, reference, cipher) = listener_fixture(&plaintext).await;
    let prefix = ATTACHMENT_CHECKPOINT_BYTES + 123;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        assert!(!headers(&mut socket).await.contains("\r\nrange:"));
        respond(
            &mut socket,
            "200 OK",
            "ETag: \"v1\"\r\n",
            &cipher[..prefix],
            cipher.len(),
        )
        .await;
        drop(socket);
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = headers(&mut socket).await;
        assert!(
            request.contains(&format!("range: bytes={prefix}-\r\n")),
            "{request}"
        );
        assert!(request.contains("if-range: \"v1\"\r\n"));
        respond(
            &mut socket,
            "206 Partial Content",
            &format!(
                "ETag: \"v1\"\r\nContent-Range: bytes {prefix}-{}/{}\r\n",
                cipher.len() - 1,
                cipher.len()
            ),
            &cipher[prefix..],
            cipher.len() - prefix,
        )
        .await;
    });
    let dir = tempfile::tempdir().unwrap();
    let (client, store) = client_at(dir.path(), &reference, true).await;
    let old = claim(&store);
    let prepared = client
        .prepare_background_attachment_download(
            &GroupId::new(vec![0xab; 16]),
            reference.clone(),
            64 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        prepared
            .run_classified(resume_context(&store, &old, dir.path(), &reference))
            .await,
        Err(AttachmentDownloadFailure::Retry(_))
    ));
    assert_eq!(
        store
            .load_attachment_partial(&old, crate::unix_now_seconds(), 64 * 1024 * 1024, None)
            .unwrap()
            .unwrap()
            .bytes
            .len(),
        prefix
    );
    assert!(
        store
            .read_retained_attachment(&old.reference, crate::unix_now_seconds(), 0, 10)
            .unwrap()
            .is_none()
    );
    store.close().unwrap();
    drop(client);
    drop(store);
    let (client, store) = client_at(dir.path(), &reference, false).await;
    let job = claim(&store);
    let prepared = client
        .prepare_background_attachment_download(
            &GroupId::new(vec![0xab; 16]),
            reference.clone(),
            64 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    let result = prepared
        .run_classified(resume_context(&store, &job, dir.path(), &reference))
        .await
        .unwrap();
    assert_eq!(result.plaintext, plaintext);
    complete(&client, &job, Ok(result), 128 * 1024 * 1024).unwrap();
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        plaintext.len() as u64
    );
    assert!(
        store
            .load_attachment_partial(&job, crate::unix_now_seconds(), 64 * 1024 * 1024, None)
            .unwrap()
            .is_none()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn attachment_resume_validates_ranges_and_restarts_incompatible_responses() {
    for case in [
        "resume",
        "ignored",
        "changed",
        "unsatisfiable",
        "malformed",
        "unknown_total",
        "oversized",
        "corrupt",
        "weak",
        "unsafe_redirect",
        "chunked_oversized",
    ] {
        let (listener, reference, cipher) =
            listener_fixture(b"verified bytes from a resumed attachment").await;
        let saved = cipher[..8].to_vec();
        let total = cipher.len();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = headers(&mut socket).await;
            assert!(request.contains("range: bytes=8-\r\n"), "case={case}");
            match case {
                "ignored" => {
                    respond(&mut socket, "200 OK", "ETag: \"v1\"\r\n", &cipher, total).await
                }
                "changed" | "weak" | "unsatisfiable" | "unknown_total" | "malformed" => {
                    if case == "unsatisfiable" {
                        respond(&mut socket, "416 Range Not Satisfiable", "", &[], 0).await;
                    } else if case == "unknown_total" || case == "malformed" {
                        let range = if case == "unknown_total" {
                            format!("bytes 8-{}/*", total - 1)
                        } else {
                            format!("bytes 7-{}/{}", total - 1, total)
                        };
                        respond(
                            &mut socket,
                            "206 Partial Content",
                            &format!("ETag: \"v1\"\r\nContent-Range: {range}\r\n"),
                            &cipher[8..],
                            total - 8,
                        )
                        .await;
                    } else {
                        let tag = if case == "weak" { "W/\"v1\"" } else { "\"v2\"" };
                        respond(
                            &mut socket,
                            "206 Partial Content",
                            &format!(
                                "ETag: {tag}\r\nContent-Range: bytes 8-{}/{}\r\n",
                                total - 1,
                                total
                            ),
                            &cipher[8..],
                            total - 8,
                        )
                        .await;
                    }
                    drop(socket);
                    let (mut next, _) = listener.accept().await.unwrap();
                    assert!(!headers(&mut next).await.contains("\r\nrange:"));
                    respond(&mut next, "200 OK", "ETag: \"v2\"\r\n", &cipher, total).await;
                }
                "unsafe_redirect" => {
                    respond(
                        &mut socket,
                        "302 Found",
                        "Location: http://169.254.169.254/private\r\n",
                        &[],
                        0,
                    )
                    .await;
                }
                "chunked_oversized" => {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n100\r\n").await.unwrap();
                    socket.write_all(&[0; 256]).await.unwrap();
                    let _ = socket.write_all(b"\r\n0\r\n\r\n").await;
                }
                "oversized" => {
                    respond(
                        &mut socket,
                        "200 OK",
                        "ETag: \"v1\"\r\n",
                        &[],
                        70 * 1024 * 1024,
                    )
                    .await
                }
                _ => {
                    let begin = if case == "malformed" { 7 } else { 8 };
                    let mut rest = cipher[8..].to_vec();
                    if case == "corrupt" {
                        rest[0] ^= 1;
                    }
                    respond(
                        &mut socket,
                        "206 Partial Content",
                        &format!(
                            "ETag: \"v1\"\r\nContent-Range: bytes {begin}-{}/{}\r\n",
                            total - 1,
                            total
                        ),
                        &rest,
                        rest.len(),
                    )
                    .await;
                }
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let (client, store) = client_at(dir.path(), &reference, true).await;
        let job = claim(&store);
        let identity = AttachmentPartialIdentity {
            ciphertext_digest: hex::decode(&reference.ciphertext_sha256)
                .unwrap()
                .try_into()
                .unwrap(),
            locator_digest: Sha256::digest(reference.locators[0].value.as_bytes()).into(),
            etag: "\"v1\"".into(),
            total: total as u64,
        };
        store
            .checkpoint_attachment_partial(
                &job,
                &identity,
                0,
                &saved,
                crate::unix_now_seconds(),
                10000,
            )
            .unwrap();
        let prepared = client
            .prepare_background_attachment_download(
                &GroupId::new(vec![0xab; 16]),
                reference.clone(),
                if case == "chunked_oversized" {
                    128
                } else {
                    64 * 1024 * 1024
                },
            )
            .unwrap()
            .unwrap();
        let result = prepared
            .run_classified(resume_context(&store, &job, dir.path(), &reference))
            .await;
        if [
            "oversized",
            "corrupt",
            "chunked_oversized",
            "unsafe_redirect",
        ]
        .contains(&case)
        {
            assert!(
                matches!(result, Err(AttachmentDownloadFailure::Stop(_)))
                    || (case == "unsafe_redirect" && result.is_err()),
                "{case}"
            );
            assert!(
                store
                    .load_attachment_partial(
                        &job,
                        crate::unix_now_seconds(),
                        64 * 1024 * 1024,
                        None
                    )
                    .unwrap()
                    .is_none()
            );
        } else {
            assert_eq!(
                result.unwrap().plaintext,
                b"verified bytes from a resumed attachment",
                "{case}"
            );
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn attachment_resume_cancellation_keeps_only_committed_ciphertext() {
    let body = vec![17; ATTACHMENT_CHECKPOINT_BYTES * 2];
    let (listener, reference, cipher) = listener_fixture(&body).await;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        headers(&mut socket).await;
        respond(
            &mut socket,
            "200 OK",
            "ETag: \"v1\"\r\n",
            &cipher[..ATTACHMENT_CHECKPOINT_BYTES],
            cipher.len(),
        )
        .await;
        std::future::pending::<()>().await;
    });
    let dir = tempfile::tempdir().unwrap();
    let (client, store) = client_at(dir.path(), &reference, true).await;
    let job = claim(&store);
    let prepared = client
        .prepare_background_attachment_download(
            &GroupId::new(vec![0xab; 16]),
            reference.clone(),
            64 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    let task =
        tokio::spawn(prepared.run_classified(resume_context(&store, &job, dir.path(), &reference)));
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if store
                .load_attachment_partial(&job, crate::unix_now_seconds(), 64 * 1024 * 1024, None)
                .unwrap()
                .is_some_and(|p| p.bytes.len() == ATTACHMENT_CHECKPOINT_BYTES)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let next = claim(&store);
    assert_eq!(
        store
            .load_attachment_partial(&next, crate::unix_now_seconds(), 64 * 1024 * 1024, None)
            .unwrap()
            .unwrap()
            .bytes
            .len(),
        ATTACHMENT_CHECKPOINT_BYTES
    );
    assert!(
        store
            .read_retained_attachment(&next.reference, crate::unix_now_seconds(), 0, 10)
            .unwrap()
            .is_none()
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn attachment_resume_without_strong_validator_uses_full_download() {
    for etag in ["", "ETag: W/\"v1\"\r\n"] {
        let (listener, reference, cipher) =
            listener_fixture(b"requires a strong HTTP validator").await;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            headers(&mut socket).await;
            respond(&mut socket, "200 OK", etag, &cipher[..8], cipher.len()).await;
        });
        let dir = tempfile::tempdir().unwrap();
        let (client, store) = client_at(dir.path(), &reference, true).await;
        let job = claim(&store);
        let prepared = client
            .prepare_background_attachment_download(
                &GroupId::new(vec![0xab; 16]),
                reference.clone(),
                64 * 1024 * 1024,
            )
            .unwrap()
            .unwrap();
        assert!(
            prepared
                .run_classified(resume_context(&store, &job, dir.path(), &reference))
                .await
                .is_err()
        );
        assert!(
            store
                .load_attachment_partial(&job, crate::unix_now_seconds(), 64 * 1024 * 1024, None)
                .unwrap()
                .is_none()
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn attachment_resume_failover_does_not_mix_locator_validators() {
    let (listener, mut reference, cipher) =
        listener_fixture(b"only the complete authenticated object is usable").await;
    let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    reference.locators.push(crate::MediaLocator {
        kind: "blossom-v1".into(),
        value: format!(
            "http://{}/{}.bin",
            second.local_addr().unwrap(),
            reference.ciphertext_sha256
        ),
    });
    let total = cipher.len();
    let saved = cipher[..8].to_vec();
    let first_server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        assert!(headers(&mut socket).await.contains("range: bytes=8-\r\n"));
        respond(&mut socket, "404 Not Found", "", &[], 0).await;
    });
    let second_server = tokio::spawn(async move {
        let (mut socket, _) = second.accept().await.unwrap();
        let request = headers(&mut socket).await;
        assert!(!request.contains("\r\nrange:"));
        assert!(!request.contains("\r\nif-range:"));
        respond(&mut socket, "200 OK", "ETag: \"v1\"\r\n", &cipher, total).await;
    });
    let dir = tempfile::tempdir().unwrap();
    let (client, store) = client_at(dir.path(), &reference, true).await;
    let job = claim(&store);
    let identity = AttachmentPartialIdentity {
        ciphertext_digest: hex::decode(&reference.ciphertext_sha256)
            .unwrap()
            .try_into()
            .unwrap(),
        locator_digest: Sha256::digest(reference.locators[0].value.as_bytes()).into(),
        etag: "\"v1\"".into(),
        total: total as u64,
    };
    store
        .checkpoint_attachment_partial(&job, &identity, 0, &saved, crate::unix_now_seconds(), 10000)
        .unwrap();
    let prepared = client
        .prepare_background_attachment_download(
            &GroupId::new(vec![0xab; 16]),
            reference.clone(),
            64 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    let result = prepared
        .run_classified(resume_context(&store, &job, dir.path(), &reference))
        .await
        .unwrap();
    assert_eq!(
        result.plaintext,
        b"only the complete authenticated object is usable"
    );
    first_server.await.unwrap();
    second_server.await.unwrap();
}

#[tokio::test]
async fn attachment_resume_failed_fallback_preserves_prefix_across_reopen() {
    let (first, mut reference, cipher) =
        listener_fixture(b"preserve useful progress on the original locator").await;
    let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    reference.locators.push(crate::MediaLocator {
        kind: "blossom-v1".into(),
        value: format!(
            "http://{}/{}.bin",
            second.local_addr().unwrap(),
            reference.ciphertext_sha256
        ),
    });
    let total = cipher.len();
    let prefix = cipher[..8].to_vec();
    let a = tokio::spawn(async move {
        let (mut socket, _) = first.accept().await.unwrap();
        assert!(headers(&mut socket).await.contains("range: bytes=8-\r\n"));
        respond(&mut socket, "404 Not Found", "", &[], 0).await;
        drop(socket);
        let (mut socket, _) = first.accept().await.unwrap();
        assert!(headers(&mut socket).await.contains("range: bytes=8-\r\n"));
        respond(
            &mut socket,
            "206 Partial Content",
            &format!(
                "ETag: \"v1\"\r\nContent-Range: bytes 8-{}/{}\r\n",
                total - 1,
                total
            ),
            &cipher[8..],
            total - 8,
        )
        .await;
    });
    let b = tokio::spawn(async move {
        let (mut socket, _) = second.accept().await.unwrap();
        assert!(!headers(&mut socket).await.contains("\r\nrange:"));
        respond(&mut socket, "200 OK", "ETag: \"v1\"\r\n", &[], total).await;
        // Interrupted before a replacement checkpoint exists.
    });
    let dir = tempfile::tempdir().unwrap();
    let (client, store) = client_at(dir.path(), &reference, true).await;
    let job = claim(&store);
    let context = resume_context(&store, &job, dir.path(), &reference);
    assert!(
        store
            .checkpoint_attachment_partial(
                &job,
                &AttachmentPartialIdentity {
                    ciphertext_digest: context.ciphertext_digest,
                    locator_digest: Sha256::digest(reference.locators[0].value.as_bytes()).into(),
                    etag: "\"v1\"".into(),
                    total: total as u64,
                },
                0,
                &prefix,
                crate::unix_now_seconds(),
                10000
            )
            .unwrap()
    );
    let prepared = client
        .prepare_background_attachment_download(
            &GroupId::new(vec![0xab; 16]),
            reference.clone(),
            64 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        prepared.run_classified(context).await,
        Err(AttachmentDownloadFailure::Retry(_))
    ));
    store.close().unwrap();
    drop(client);
    drop(store);
    let (client, store) = client_at(dir.path(), &reference, false).await;
    let job = claim(&store);
    let prepared = client
        .prepare_background_attachment_download(
            &GroupId::new(vec![0xab; 16]),
            reference.clone(),
            64 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    let result = prepared
        .run_classified(resume_context(&store, &job, dir.path(), &reference))
        .await
        .unwrap();
    assert_eq!(
        result.plaintext,
        b"preserve useful progress on the original locator"
    );
    a.await.unwrap();
    b.await.unwrap();
}

#[tokio::test]
async fn attachment_resume_cleanup_error_preserves_terminal_integrity_failure() {
    let (listener, reference, mut cipher) =
        listener_fixture(b"must remain a terminal hash failure").await;
    let dir = tempfile::tempdir().unwrap();
    let (client, store) = client_at(dir.path(), &reference, true).await;
    let job = claim(&store);
    let closing = store.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        headers(&mut socket).await;
        closing.close().unwrap();
        cipher[0] ^= 1;
        respond(
            &mut socket,
            "200 OK",
            "ETag: \"v1\"\r\n",
            &cipher,
            cipher.len(),
        )
        .await;
    });
    let prepared = client
        .prepare_background_attachment_download(
            &GroupId::new(vec![0xab; 16]),
            reference.clone(),
            64 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        prepared
            .run_classified(resume_context(&store, &job, dir.path(), &reference))
            .await,
        Err(AttachmentDownloadFailure::Stop(_))
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn attachment_resume_complete_small_body_does_not_write_checkpoint() {
    let (listener, reference, cipher) = listener_fixture(b"small complete attachment").await;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        headers(&mut socket).await;
        respond(
            &mut socket,
            "200 OK",
            "ETag: \"v1\"\r\n",
            &cipher,
            cipher.len(),
        )
        .await;
    });
    let dir = tempfile::tempdir().unwrap();
    let (client, store) = client_at(dir.path(), &reference, true).await;
    let job = claim(&store);
    let mut context = resume_context(&store, &job, dir.path(), &reference);
    context.disk_reserve = u64::MAX; // Any unnecessary checkpoint would refuse.
    let prepared = client
        .prepare_background_attachment_download(
            &GroupId::new(vec![0xab; 16]),
            reference.clone(),
            64 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    let result = prepared.run_classified(context).await.unwrap();
    assert_eq!(result.plaintext, b"small complete attachment");
    assert!(
        store
            .load_attachment_partial(&job, crate::unix_now_seconds(), 64 * 1024 * 1024, None)
            .unwrap()
            .is_none()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn attachment_resume_disabled_acquisition_still_prunes_expired_checkpoints() {
    let (_dir, mut client, store, reference) = offline_fixture().await;
    let job = claim(&store);
    let earlier = crate::unix_now_seconds() - 86401;
    let identity = AttachmentPartialIdentity {
        ciphertext_digest: hex::decode(&reference.ciphertext_sha256)
            .unwrap()
            .try_into()
            .unwrap(),
        locator_digest: Sha256::digest(reference.locators[0].value.as_bytes()).into(),
        etag: "\"v1\"".into(),
        total: 10,
    };
    assert!(
        store
            .checkpoint_attachment_partial(&job, &identity, 0, b"abc", earlier, 100)
            .unwrap()
    );
    assert!(
        store
            .load_attachment_partial(&job, earlier, 10, None)
            .unwrap()
            .is_some()
    );
    client.app.config.attachment_acquisition = None;
    let (http, _rx) = context();
    schedule(
        &client,
        &RuntimeSharedServices::default(),
        &http,
        &mut Admission::default(),
    )
    .unwrap();
    assert!(
        store
            .load_attachment_partial(&job, earlier, 10, None)
            .unwrap()
            .is_none()
    );
}
