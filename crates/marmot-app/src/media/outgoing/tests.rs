use super::*;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use media_store::memory::MemoryCatalog;
use std::path::PathBuf;

fn store() -> (tempfile::TempDir, MemoryCatalog, MediaStore<MemoryCatalog>) {
    let directory = tempfile::tempdir().unwrap();
    let catalog = MemoryCatalog::default();
    let media = MediaStore::new(directory.path().join("media"), catalog.clone());
    (directory, catalog, media)
}

fn generated_source(directory: &Path, len: usize) -> (PathBuf, Vec<u8>) {
    let path = directory.join("source.bin");
    let plain = (0..len).map(|i| (i % 253) as u8).collect::<Vec<_>>();
    std::fs::write(&path, &plain).unwrap();
    (path, plain)
}

fn descriptor() -> OutgoingDescriptor {
    OutgoingDescriptor::new(
        "generated.bin".into(),
        "application/octet-stream",
        None,
        None,
        EncryptedMediaVersion::V2,
    )
    .unwrap()
}

/// Stages a generated file as slot `slot`'s upload.
fn stage_generated(
    catalog: &MemoryCatalog,
    media: &MediaStore<MemoryCatalog>,
    path: &Path,
    slot: u32,
) -> StagedSource {
    let control = Arc::new(MediaFileTransferControl::default());
    let source = HostSource::open(path, None, control).unwrap();
    let len = source.len();
    let (file, digest) = stage_host_source(media, &catalog.stage_target(slot), source).unwrap();
    descriptor().staged(file, len, digest)
}

fn wire_bytes(plain: &[u8], key: &[u8; 32], nonce: &[u8; 12], aad: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new_from_slice(key)
        .unwrap()
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .unwrap()
}

#[test]
fn encrypting_reader_matches_the_in_memory_cipher_across_chunk_boundaries() {
    let key = [9u8; 32];
    let nonce = [7u8; 12];
    for len in [0, 1, 15, 16, 17, 65535, 65536, 65537, 131079] {
        let plain = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let expected = wire_bytes(&plain, &key, &nonce, b"aad");
        // Large reads, and reads smaller than a tag, give the same bytes.
        for read_size in [FILE_TRANSFER_BUFFER_BYTES * 2, 7] {
            let mut reader =
                EncryptingReader::new(plain.as_slice(), len as u64, &key, &nonce, b"aad").unwrap();
            let mut wire = Vec::new();
            let mut buffer = vec![0; read_size];
            loop {
                let read = reader.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                wire.extend_from_slice(&buffer[..read]);
            }
            assert_eq!(wire, expected, "length {len}, reads of {read_size}");
        }
    }
}

#[test]
fn encrypting_reader_refuses_a_body_shorter_or_longer_than_declared() {
    let plain = [3u8; 100];
    let mut short = EncryptingReader::new(&plain[..], 101, &[1; 32], &[2; 12], b"").unwrap();
    assert!(std::io::copy(&mut short, &mut std::io::sink()).is_err());
    let mut long = EncryptingReader::new(&plain[..], 99, &[1; 32], &[2; 12], b"").unwrap();
    assert!(std::io::copy(&mut long, &mut std::io::sink()).is_err());
}

#[test]
fn host_sources_must_be_nonempty_regular_files_of_the_declared_length() {
    let directory = tempfile::tempdir().unwrap();
    let control = Arc::new(MediaFileTransferControl::default());
    let (path, _) = generated_source(directory.path(), 500);
    assert!(HostSource::open(&path, Some(501), control.clone()).is_err());
    assert_eq!(
        HostSource::open(&path, Some(500), control.clone())
            .unwrap()
            .len(),
        500
    );
    assert!(HostSource::open(directory.path(), None, control.clone()).is_err());
    let empty = directory.path().join("empty");
    std::fs::write(&empty, b"").unwrap();
    assert!(HostSource::open(&empty, None, control.clone()).is_err());
    let oversized = directory.path().join("oversized");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(MAX_FILE_MEDIA_CIPHERTEXT_BYTES)
        .unwrap();
    assert!(HostSource::open(&oversized, None, control.clone()).is_err());
    #[cfg(unix)]
    {
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(HostSource::open(&link, None, control.clone()).is_err());
    }
    control.cancel();
    assert!(HostSource::open(&path, None, control).is_err());
}

#[test]
fn staging_a_host_file_reports_progress_and_a_cancelled_one_keeps_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let (_store_dir, catalog, media) = store();
    let (path, plain) = generated_source(directory.path(), 3 * FILE_TRANSFER_BUFFER_BYTES + 5);
    let control = Arc::new(MediaFileTransferControl::default());
    let source = HostSource::open(&path, None, control.clone()).unwrap();
    let (file, digest) = stage_host_source(&media, &catalog.stage_target(0), source).unwrap();
    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&plain)));
    assert_eq!(control.processed_bytes(), plain.len() as u64);
    let mut staged = Vec::new();
    media
        .open_staged_reader(&file)
        .unwrap()
        .unwrap()
        .read_to_end(&mut staged)
        .unwrap();
    assert_eq!(staged, plain);

    let control = Arc::new(MediaFileTransferControl::default());
    let source = HostSource::open(&path, None, control.clone()).unwrap();
    control.cancel();
    assert!(stage_host_source(&media, &catalog.stage_target(1), source).is_err());
    assert_eq!(
        walk(&media_root(&_store_dir)),
        1,
        "only the first staged file is on disk"
    );
}

fn media_root(directory: &tempfile::TempDir) -> PathBuf {
    directory.path().join("media")
}

fn walk(path: &Path) -> usize {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| {
                    if entry.file_type().unwrap().is_dir() {
                        walk(&entry.path())
                    } else {
                        1
                    }
                })
                .sum()
        })
        .unwrap_or(0)
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

async fn upload_with(
    media: &MediaStore<MemoryCatalog>,
    servers: &[String],
    sources: Vec<StagedSource>,
    control: Arc<MediaFileTransferControl>,
) -> Result<MediaUploadResult, AppError> {
    let allowed = ["blossom-v1".to_owned()];
    upload_staged(
        media,
        sources,
        servers,
        42,
        &[7u8; 32],
        &nostr::prelude::Keys::generate(),
        MediaOperationPolicy {
            version: EncryptedMediaVersion::V2,
            default_endpoints: &[],
            allowed_locator_kinds: &allowed,
            allow_loopback_http: true,
        },
        &BlossomHttpTransport::new(true),
        control,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staged_upload_fails_over_413_then_500_then_succeeds_with_identical_ciphertext() {
    let directory = tempfile::tempdir().unwrap();
    let (_store_dir, catalog, media) = store();
    let (path, plain) = generated_source(directory.path(), 3 * FILE_TRANSFER_BUFFER_BYTES + 5);
    let staged = stage_generated(&catalog, &media, &path, 0);
    let file = staged.file;
    let (too_large, mut first) = scripted_upload_server(vec![Reply::Status(413)]).await;
    let (broken, mut second) = scripted_upload_server(vec![Reply::Status(500)]).await;
    let (healthy, mut third) = scripted_upload_server(vec![Reply::Descriptor]).await;
    let control = Arc::new(MediaFileTransferControl::default());
    let result = upload_with(
        &media,
        &[too_large, broken, healthy.clone()],
        vec![staged],
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
    let digest = <[u8; 32]>::from(Sha256::digest(&plain));
    assert_eq!(reference.plaintext_sha256, hex::encode(digest));
    // The streamed body is exactly the in-memory cipher's wire bytes.
    let key = super::super::crypto::derive_media_file_key(
        &[7u8; 32],
        EncryptedMediaVersion::V2,
        &digest,
        "application/octet-stream",
        "generated.bin",
    )
    .unwrap();
    let nonce: [u8; 12] = hex::decode(&reference.nonce_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let aad = super::super::crypto::media_aad(
        EncryptedMediaVersion::V2,
        &digest,
        "application/octet-stream",
        "generated.bin",
    );
    assert_eq!(
        reference.ciphertext_sha256,
        hex::encode(Sha256::digest(wire_bytes(&plain, &key, &nonce, &aad)))
    );
    assert_eq!(
        result.attachments[0].encrypted_size_bytes,
        plain.len() as u64 + 16
    );
    assert!(control.processed_bytes() >= 2 * plain.len() as u64);
    assert_eq!(
        media.file_state(&file).unwrap(),
        Some(FileState::Staged),
        "the staged body stays for promotion"
    );
    assert_eq!(
        walk(&media_root(&_store_dir)),
        1,
        "no ciphertext is written"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staged_upload_fails_over_missing_or_mismatched_descriptor_and_reports_all_failures() {
    let directory = tempfile::tempdir().unwrap();
    let (_store_dir, catalog, media) = store();
    let (path, _) = generated_source(directory.path(), 1024);
    let (no_hash, _a) = scripted_upload_server(vec![Reply::DescriptorWithoutHash]).await;
    let (wrong_size, _b) = scripted_upload_server(vec![Reply::DescriptorWrongSize]).await;
    let (healthy, _c) = scripted_upload_server(vec![Reply::Descriptor]).await;
    let result = upload_with(
        &media,
        &[no_hash, wrong_size, healthy.clone()],
        vec![stage_generated(&catalog, &media, &path, 0)],
        Arc::default(),
    )
    .await
    .unwrap();
    assert!(
        result.attachments[0].reference.locators[0]
            .value
            .starts_with(&healthy)
    );

    let (first, _d) = scripted_upload_server(vec![Reply::Status(413)]).await;
    let (second, _e) = scripted_upload_server(vec![Reply::Status(500)]).await;
    let failure = upload_with(
        &media,
        &[first, second],
        vec![stage_generated(&catalog, &media, &path, 1)],
        Arc::default(),
    )
    .await
    .err()
    .unwrap();
    assert!(
        matches!(&failure, AppError::BlobStore(detail) if detail.contains("server 1") && detail.contains("server 2")),
        "aggregate failure keeps per-server summaries"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_upload_or_a_lost_staged_file_never_dials() {
    let directory = tempfile::tempdir().unwrap();
    let (_store_dir, catalog, media) = store();
    let (path, _) = generated_source(directory.path(), 2048);
    let (server, mut requests) = scripted_upload_server(vec![Reply::Descriptor]).await;
    let control = Arc::new(MediaFileTransferControl::default());
    control.cancel();
    assert!(
        upload_with(
            &media,
            std::slice::from_ref(&server),
            vec![stage_generated(&catalog, &media, &path, 0)],
            control,
        )
        .await
        .is_err()
    );
    let lost = stage_generated(&catalog, &media, &path, 1);
    std::fs::remove_file(media.path(&lost.file)).unwrap();
    let file = lost.file;
    assert!(
        upload_with(
            &media,
            std::slice::from_ref(&server),
            vec![lost],
            Arc::default()
        )
        .await
        .is_err()
    );
    assert_eq!(media.file_state(&file).unwrap(), Some(FileState::Lost));
    assert!(
        requests.try_recv().is_err(),
        "no request reached the server"
    );
}

#[test]
fn a_full_disk_refuses_staging_with_the_storage_full_error() {
    let (_store_dir, catalog, media) = store();
    media.simulate_full_disk_for_test(true);
    let error = stage_body(
        &media,
        &catalog.stage_target(0),
        &mut &[1u8; 10][..],
        10,
        &|| false,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        AppError::Storage(cgka_traits::StorageError::Capacity(_))
    ));
}
