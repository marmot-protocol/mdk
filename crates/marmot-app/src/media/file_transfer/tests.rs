use super::*;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

fn fixture(directory: &Path, bytes: &[u8]) -> PrivateMediaFile {
    let mut file = PrivateMediaFile::create(directory).unwrap();
    file.file.write_all(bytes).unwrap();
    file.file.flush().unwrap();
    file.len = bytes.len() as u64;
    file.digest = Sha256::digest(bytes).into();
    file
}

fn bytes(file: &PrivateMediaFile) -> Vec<u8> {
    let mut result = Vec::new();
    file.reader().unwrap().read_to_end(&mut result).unwrap();
    result
}

#[test]
fn streaming_wire_matches_existing_aead_across_chunk_boundaries_and_versions() {
    let directory = tempfile::tempdir().unwrap();
    let secret = [9u8; 32];
    let nonce = [7u8; 12];
    for version in [
        super::super::EncryptedMediaVersion::V1,
        super::super::EncryptedMediaVersion::V2,
    ] {
        for len in [0, 1, 15, 16, 17, 65535, 65536, 65537, 131079] {
            let plain = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            let digest = Sha256::digest(&plain).into();
            let key = super::super::crypto::derive_media_file_key(
                &secret,
                version,
                &digest,
                "application/octet-stream",
                "test.bin",
            )
            .unwrap();
            let aad = super::super::crypto::media_aad(
                version,
                &digest,
                "application/octet-stream",
                "test.bin",
            );
            let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
            let expected = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &plain,
                        aad: &aad,
                    },
                )
                .unwrap();
            let source = fixture(directory.path(), &plain);
            let control = MediaFileTransferControl::default();
            let encrypted =
                encrypt_file(&source, directory.path(), &key, &nonce, &aad, &control).unwrap();
            assert_eq!(
                bytes(&encrypted),
                expected,
                "length {len}, version {version:?}"
            );
            assert_eq!(encrypted.len, len as u64 + 16);
            assert_eq!(
                encrypted.digest,
                <[u8; 32]>::from(Sha256::digest(&expected))
            );
            let decrypted = decrypt_file(
                &encrypted,
                directory.path(),
                &key,
                &nonce,
                &aad,
                digest,
                &control,
            )
            .unwrap();
            assert_eq!(bytes(&decrypted), plain);
        }
    }
}

#[test]
fn rejected_tag_never_returns_plaintext_and_cleans_private_partial() {
    let directory = tempfile::tempdir().unwrap();
    let source = fixture(directory.path(), b"sensitive test fixture");
    let key = [5u8; 32];
    let nonce = [8u8; 12];
    let control = MediaFileTransferControl::default();
    let mut encrypted = encrypt_file(
        &source,
        directory.path(),
        &key,
        &nonce,
        b"metadata",
        &control,
    )
    .unwrap();
    let last = *bytes(&encrypted).last().unwrap() ^ 1;
    encrypted.file.seek(SeekFrom::End(-1)).unwrap();
    encrypted.file.write_all(&[last]).unwrap();
    encrypted.file.flush().unwrap();
    // Rehash the corrupted bytes so the AEAD check, rather than the transport
    // hash check, is the boundary exercised here.
    encrypted.digest = Sha256::digest(bytes(&encrypted)).into();
    let before = std::fs::read_dir(directory.path()).unwrap().count();
    let outcome = decrypt_file(
        &encrypted,
        directory.path(),
        &key,
        &nonce,
        b"metadata",
        source.digest,
        &control,
    );
    assert!(outcome.is_err());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), before);
}

#[test]
fn ciphertext_digest_plaintext_digest_and_length_are_verified_independently() {
    let directory = tempfile::tempdir().unwrap();
    let source = fixture(directory.path(), b"test payload");
    let key = [5u8; 32];
    let nonce = [8u8; 12];
    let control = MediaFileTransferControl::default();
    let mut encrypted = encrypt_file(
        &source,
        directory.path(),
        &key,
        &nonce,
        b"metadata",
        &control,
    )
    .unwrap();
    assert!(
        decrypt_file(
            &encrypted,
            directory.path(),
            &key,
            &nonce,
            b"metadata",
            [0; 32],
            &control
        )
        .is_err()
    );
    let digest = encrypted.digest;
    encrypted.digest = [0; 32];
    assert!(
        decrypt_file(
            &encrypted,
            directory.path(),
            &key,
            &nonce,
            b"metadata",
            source.digest,
            &control
        )
        .is_err()
    );
    encrypted.digest = digest;
    encrypted.file.as_file().set_len(encrypted.len - 1).unwrap();
    assert!(
        decrypt_file(
            &encrypted,
            directory.path(),
            &key,
            &nonce,
            b"metadata",
            source.digest,
            &control
        )
        .is_err()
    );
}

#[test]
fn source_size_is_checked_and_cancelled_work_leaves_no_partial_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original");
    std::fs::write(&path, [3u8; 500]).unwrap();
    let staged = directory.path().join("staged");
    let control = MediaFileTransferControl::default();
    assert!(snapshot_source(&path, &staged, Some(501), &control).is_err());
    let source = snapshot_source(&path, &staged, Some(500), &control).unwrap();
    assert_eq!(source.len, 500);
    assert_eq!(bytes(&source), vec![3u8; 500]);
    assert_eq!(control.processed_bytes(), 500);
    control.advance(400);
    assert_eq!(control.processed_bytes(), 500);
    control.cancel();
    assert!(encrypt_file(&source, &staged, &[2; 32], &[4; 12], b"aad", &control).is_err());
    assert_eq!(std::fs::read_dir(&staged).unwrap().count(), 1);
    drop(source);
    assert_eq!(std::fs::read_dir(&staged).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn files_and_directories_are_private_and_symlink_sources_are_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source");
    std::fs::write(&path, b"test").unwrap();
    let link = directory.path().join("link");
    symlink(&path, &link).unwrap();
    let staged = directory.path().join("staged");
    let control = MediaFileTransferControl::default();
    assert!(snapshot_source(&link, &staged, None, &control).is_err());
    let source = snapshot_source(&path, &staged, None, &control).unwrap();
    assert_eq!(
        std::fs::metadata(source.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn sparse_oversized_source_is_rejected_before_copying_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized");
    File::create(&path)
        .unwrap()
        .set_len(MAX_FILE_MEDIA_CIPHERTEXT_BYTES)
        .unwrap();
    let staged = directory.path().join("staged");
    assert!(snapshot_source(&path, &staged, None, &MediaFileTransferControl::default()).is_err());
    assert!(!staged.exists());
}

#[test]
fn declared_batch_preflight_counts_every_aead_tag_before_preparation() {
    let item = |size| MediaFileUploadAttachmentRequest {
        source_path: "unused-private-source".into(),
        expected_size: size,
        file_name: "file.bin".into(),
        media_type: "application/octet-stream".into(),
        dim: None,
        thumbhash: None,
    };
    let mut request = MediaFileUploadRequest {
        attachments: vec![item(Some(MAX_FILE_MEDIA_CIPHERTEXT_BYTES / 2 - 16)); 2],
        caption: None,
        send: false,
        blossom_server: None,
        message_tags: vec![],
    };
    assert!(request.validate().is_ok());
    *request.attachments[1].expected_size.as_mut().unwrap() += 1;
    assert!(request.validate().is_err());
    request.attachments = vec![item(Some(MAX_FILE_MEDIA_CIPHERTEXT_BYTES - 16)), item(None)];
    assert!(
        request.validate().is_err(),
        "an unknown source still contributes an AEAD tag"
    );
}

/// Scripted Blossom PUT outcomes for fallback tests.
#[derive(Clone, Copy)]
enum Reply {
    Status(u16),
    Descriptor,
    DescriptorWithoutHash,
    DescriptorWrongSize,
}

/// One connection per scripted reply, in order. Every request body is read
/// completely and its SHA-256 reported, so tests can prove identical retries.
async fn scripted_upload_server(
    replies: Vec<Reply>,
) -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server_url = url.clone();
    let (bodies, received) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        for reply in replies {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut request = Vec::new();
            let mut buffer = [0u8; 16 * 1024];
            let end = loop {
                let count = socket.read(&mut buffer).await.unwrap();
                assert!(count > 0, "client closed before headers");
                request.extend_from_slice(&buffer[..count]);
                if let Some(i) = request.windows(4).position(|b| b == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..end]).to_string();
            assert!(headers.starts_with("PUT /upload "));
            let size = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                        .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                })
                .expect("fixed-length upload body");
            while request.len() < end + size {
                let count = socket.read(&mut buffer).await.unwrap();
                assert!(count > 0, "truncated upload body");
                request.extend_from_slice(&buffer[..count]);
            }
            let hash = hex::encode(Sha256::digest(&request[end..end + size]));
            let _ = bodies.send(hash.clone());
            let (status, body) = match reply {
                Reply::Status(status) => (status, String::new()),
                Reply::Descriptor => (200, serde_json::json!({"url": format!("{server_url}/{hash}"), "sha256": hash, "size": size}).to_string()),
                Reply::DescriptorWithoutHash => (200, serde_json::json!({"url": format!("{server_url}/{hash}"), "size": size}).to_string()),
                Reply::DescriptorWrongSize => (200, serde_json::json!({"url": format!("{server_url}/{hash}"), "sha256": hash, "size": size + 1}).to_string()),
            };
            let _ = socket
                .write_all(format!("HTTP/1.1 {status} Scripted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
                .await;
        }
    });
    (url, received)
}

fn file_request(path: &Path, size: u64) -> MediaFileUploadRequest {
    MediaFileUploadRequest {
        attachments: vec![MediaFileUploadAttachmentRequest {
            source_path: path.to_string_lossy().into_owned(),
            expected_size: Some(size),
            file_name: "generated.bin".into(),
            media_type: "application/octet-stream".into(),
            dim: None,
            thumbhash: None,
        }],
        caption: None,
        send: false,
        blossom_server: None,
        message_tags: Vec::new(),
    }
}

async fn upload_with(
    servers: &[String],
    request: MediaFileUploadRequest,
    staging: &Path,
    control: Arc<MediaFileTransferControl>,
) -> Result<(super::super::MediaUploadResult, Vec<PrivateMediaFile>), AppError> {
    let endpoints = servers
        .iter()
        .map(|base_url| crate::AppBlobEndpoint {
            locator_kind: "blossom-v1".into(),
            base_url: base_url.clone(),
        })
        .collect::<Vec<_>>();
    let allowed = ["blossom-v1".to_owned()];
    upload_files_retaining(
        request,
        42,
        &[7u8; 32],
        &nostr::prelude::Keys::generate(),
        super::super::MediaOperationPolicy {
            version: super::super::EncryptedMediaVersion::V2,
            default_endpoints: &endpoints,
            allowed_locator_kinds: &allowed,
            allow_loopback_http: true,
        },
        &super::super::BlossomHttpTransport::new(true),
        staging.to_path_buf(),
        control,
    )
    .await
}

fn generated_source(directory: &Path, len: usize) -> (PathBuf, Vec<u8>) {
    let path = directory.join("source.bin");
    let plain = (0..len).map(|i| (i % 253) as u8).collect::<Vec<_>>();
    std::fs::write(&path, &plain).unwrap();
    (path, plain)
}

fn staged_files(staging: &Path) -> usize {
    std::fs::read_dir(staging)
        .map(|entries| entries.count())
        .unwrap_or(0)
}

#[tokio::test]
async fn file_upload_fails_over_413_then_500_then_succeeds_with_identical_ciphertext() {
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("staging");
    let (path, plain) = generated_source(directory.path(), 3 * FILE_TRANSFER_BUFFER_BYTES + 5);
    let (too_large, mut first) = scripted_upload_server(vec![Reply::Status(413)]).await;
    let (broken, mut second) = scripted_upload_server(vec![Reply::Status(500)]).await;
    let (healthy, mut third) = scripted_upload_server(vec![Reply::Descriptor]).await;
    let control = Arc::new(MediaFileTransferControl::default());
    let (result, plaintext) = upload_with(
        &[too_large, broken, healthy.clone()],
        file_request(&path, plain.len() as u64),
        &staging,
        control.clone(),
    )
    .await
    .unwrap();
    let reference = &result.attachments[0].reference;
    assert!(reference.locators[0].value.starts_with(&healthy));
    let bodies = [
        first.recv().await.unwrap(),
        second.recv().await.unwrap(),
        third.recv().await.unwrap(),
    ];
    assert!(
        bodies
            .iter()
            .all(|hash| *hash == reference.ciphertext_sha256)
    );
    assert_eq!(
        reference.plaintext_sha256,
        hex::encode(Sha256::digest(&plain))
    );
    assert_eq!(
        result.attachments[0].encrypted_size_bytes,
        plain.len() as u64 + 16
    );
    assert_eq!(plaintext.len(), 1);
    assert_eq!(bytes(&plaintext[0]), plain);
    assert!(control.processed_bytes() >= plain.len() as u64);
    assert_eq!(
        staged_files(&staging),
        1,
        "only the retained plaintext snapshot remains"
    );
    drop(plaintext);
    assert_eq!(staged_files(&staging), 0);
}

#[tokio::test]
async fn file_upload_fails_over_missing_or_mismatched_descriptor_and_reports_all_failures() {
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("staging");
    let (path, plain) = generated_source(directory.path(), 1024);
    let (no_hash, _a) = scripted_upload_server(vec![Reply::DescriptorWithoutHash]).await;
    let (wrong_size, _b) = scripted_upload_server(vec![Reply::DescriptorWrongSize]).await;
    let (healthy, _c) = scripted_upload_server(vec![Reply::Descriptor]).await;
    let (result, plaintext) = upload_with(
        &[no_hash, wrong_size, healthy.clone()],
        file_request(&path, plain.len() as u64),
        &staging,
        Arc::default(),
    )
    .await
    .unwrap();
    assert!(
        result.attachments[0].reference.locators[0]
            .value
            .starts_with(&healthy)
    );
    drop(plaintext);

    let (first, _d) = scripted_upload_server(vec![Reply::Status(413)]).await;
    let (second, _e) = scripted_upload_server(vec![Reply::Status(500)]).await;
    let failure = upload_with(
        &[first, second],
        file_request(&path, plain.len() as u64),
        &staging,
        Arc::default(),
    )
    .await
    .err()
    .unwrap();
    assert!(
        matches!(&failure, AppError::BlobStore(detail) if detail.contains("server 1") && detail.contains("server 2")),
        "aggregate failure keeps per-server summaries"
    );
    assert_eq!(
        staged_files(&staging),
        0,
        "failed batches leave no private files"
    );
}

#[tokio::test]
async fn cancelled_or_invalid_file_requests_never_dial_and_leave_no_files() {
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("staging");
    let (path, plain) = generated_source(directory.path(), 2048);
    let (server, mut requests) = scripted_upload_server(vec![Reply::Descriptor]).await;
    let control = Arc::new(MediaFileTransferControl::default());
    control.cancel();
    assert!(
        upload_with(
            std::slice::from_ref(&server),
            file_request(&path, plain.len() as u64),
            &staging,
            control,
        )
        .await
        .is_err()
    );
    assert!(
        upload_with(
            std::slice::from_ref(&server),
            file_request(&path, plain.len() as u64 + 1),
            &staging,
            Arc::default(),
        )
        .await
        .is_err(),
        "a changed source length is refused before upload"
    );
    let mut missing = file_request(&path, plain.len() as u64);
    missing.attachments[0].source_path = directory
        .path()
        .join("absent")
        .to_string_lossy()
        .into_owned();
    assert!(
        upload_with(
            std::slice::from_ref(&server),
            missing,
            &staging,
            Arc::default()
        )
        .await
        .is_err()
    );
    assert!(
        requests.try_recv().is_err(),
        "no request reached the server"
    );
    assert_eq!(staged_files(&staging), 0);
}

#[test]
fn stale_snapshot_sweep_removes_only_old_private_snapshots() {
    let directory = tempfile::tempdir().unwrap();
    let fresh = PrivateMediaFile::create(directory.path()).unwrap();
    let stale = directory
        .path()
        .join(format!("{MEDIA_STAGING_PREFIX}stale"));
    std::fs::write(&stale, b"orphan").unwrap();
    let unrelated = directory.path().join("unrelated");
    std::fs::write(&unrelated, b"keep").unwrap();
    let old =
        std::time::SystemTime::now() - STALE_MEDIA_STAGING_AGE - std::time::Duration::from_secs(60);
    for path in [&stale, &unrelated] {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(old)
            .unwrap();
    }
    assert_eq!(sweep_stale_media_staging(directory.path()), 1);
    assert!(!stale.exists());
    assert!(unrelated.exists());
    assert!(fresh.path().exists(), "a live snapshot is never swept");
    assert_eq!(
        sweep_stale_media_staging(&directory.path().join("absent")),
        0
    );
}

#[test]
#[ignore = "opt-in large-file bounded-memory measurement; no whole-file test allocation"]
fn generated_758_mb_streaming_crypto_roundtrip() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("large");
    File::create(&path).unwrap().set_len(758_000_000).unwrap();
    let control = MediaFileTransferControl::default();
    let source = snapshot_source(&path, directory.path(), Some(758_000_000), &control).unwrap();
    let encrypted = encrypt_file(
        &source,
        directory.path(),
        &[5; 32],
        &[8; 12],
        b"large",
        &control,
    )
    .unwrap();
    let decrypted = decrypt_file(
        &encrypted,
        directory.path(),
        &[5; 32],
        &[8; 12],
        b"large",
        source.digest,
        &control,
    )
    .unwrap();
    assert_eq!(decrypted.len, 758_000_000);
    assert_eq!(decrypted.digest, source.digest);
}
