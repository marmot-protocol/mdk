use super::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use url::Url;

use super::blossom::{
    BlossomHttpTransport, DnsResolver, MAX_BLOSSOM_DESCRIPTOR_BYTES,
    MAX_ENCRYPTED_MEDIA_BLOB_BYTES, fetch_blossom_blob_with_transport, read_limited_blossom_body,
};
use super::host_safety::validate_blossom_fetch_url;

#[test]
fn encrypted_media_blob_limit_supports_large_application_artifacts() {
    assert_eq!(MAX_ENCRYPTED_MEDIA_BLOB_BYTES, 512 * 1024 * 1024);
}

#[test]
fn media_plaintext_limit_accounts_for_the_aead_tag_without_allocating_the_boundary() {
    let max_plaintext = MAX_ENCRYPTED_MEDIA_BLOB_BYTES - 16;
    assert!(validate_media_plaintext_len(max_plaintext).is_ok());
    assert!(validate_media_plaintext_len(max_plaintext + 1).is_err());
}

#[test]
fn media_upload_batch_enforces_the_same_aggregate_bound_as_the_connector() {
    let max_plaintext = MAX_ENCRYPTED_MEDIA_BLOB_BYTES - 16;
    assert!(validate_media_upload_batch_lengths([max_plaintext]).is_ok());
    assert!(validate_media_upload_batch_lengths([max_plaintext - 3, 3]).is_ok());
    assert!(validate_media_upload_batch_lengths([max_plaintext, 1]).is_err());
    assert!(validate_media_upload_batch_lengths([u64::MAX, 1]).is_err());
}

#[test]
fn in_place_encryption_is_wire_identical_to_the_previous_allocating_api() {
    let key = [0x11_u8; 32];
    let nonce = [0x22_u8; 12];
    let aad = b"encrypted-media compatibility";
    let plaintext = b"same key nonce aad and plaintext";
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let expected = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap();
    let mut actual = plaintext.to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(&nonce), aad, &mut actual)
        .unwrap();
    assert_eq!(actual, expected);
}

fn valid_imeta_tag() -> Vec<String> {
    vec![
        "imeta".to_owned(),
        "v encrypted-media-v1".to_owned(),
        format!(
            "locator blossom-v1 https://media.example/{}.bin",
            "11".repeat(32)
        ),
        format!("ciphertext_sha256 {}", "11".repeat(32)),
        format!("plaintext_sha256 {}", "22".repeat(32)),
        "nonce 333333333333333333333333".to_owned(),
        "m image/png".to_owned(),
        "filename diagram.png".to_owned(),
    ]
}

fn valid_hash() -> String {
    "11".repeat(32)
}

#[test]
fn chat_list_attachment_projection_is_bounded_and_typed() {
    let image = valid_imeta_tag();
    let mut video = valid_imeta_tag();
    video[6] = "m video/mp4".to_owned();
    video[7] = "filename clip.mp4".to_owned();
    let raw = serde_json::json!({ "imeta": [image, video] }).to_string();

    assert_eq!(
        classify_chat_list_attachments(Some(&raw)),
        (Some(ChatListAttachmentKind::Mixed), 2)
    );
}

#[test]
fn chat_list_attachment_projection_drops_malformed_siblings_safely() {
    let valid = valid_imeta_tag();
    let malformed = vec!["imeta".to_owned(), "m audio/mpeg".to_owned()];
    let raw = serde_json::json!({ "imeta": [malformed, valid] }).to_string();

    assert_eq!(
        classify_chat_list_attachments(Some(&raw)),
        (Some(ChatListAttachmentKind::Photo), 1)
    );
    assert_eq!(classify_chat_list_attachments(Some("{not-json")), (None, 0));
}

#[test]
fn encrypted_media_integrity_accepts_uppercase_hex() {
    let encrypted = b"encrypted media bytes";
    let uppercase_hash = hex::encode(Sha256::digest(encrypted)).to_ascii_uppercase();

    assert!(encrypted_media_hash_matches(encrypted, &uppercase_hash));
}

fn valid_v2_imeta_tag() -> Vec<String> {
    let mut tag = valid_imeta_tag();
    tag[1] = "v encrypted-media-v2".to_owned();
    tag
}

#[test]
fn encrypted_media_v2_media_type_profile_is_exact() {
    assert_eq!(
        canonical_media_type_v2("\t\n\u{000c}\r IMAGE/JPG ; charset=utf-8 ")
            .expect("the exact V2 trim set and alias are valid"),
        "image/jpeg"
    );
    assert!(canonical_media_type_v2("\u{000b}image/png").is_err());
    assert!(canonical_media_type_v2("\u{00a0}image/png").is_err());
    assert!(canonical_media_type_v2("image/png/extra").is_err());
    assert!(canonical_media_type_v2("image").is_err());
    assert!(canonical_media_type_v2(&format!("{}/{}", "a".repeat(64), "b".repeat(64))).is_err());
    assert_eq!(
        canonical_media_type_v2("application/vnd.test+json").unwrap(),
        "application/vnd.test+json"
    );
}

#[test]
fn encrypted_media_v2_reference_validation_is_version_specific() {
    let mut v2 = valid_v2_imeta_tag();
    v2[2] = "locator blossom-v1 http://10.0.0.1/blob".to_owned();
    media_attachment_from_imeta_tag(&v2, Some(7), false)
        .expect("V2 locator validity is independent of local destination policy");

    let mut noncanonical_m = v2.clone();
    noncanonical_m[6] = "m Image/JPG".to_owned();
    assert!(media_attachment_from_imeta_tag(&noncanonical_m, Some(7), false).is_err());

    let mut exact_filename = v2.clone();
    exact_filename[7] = "filename  ".to_owned();
    assert_eq!(
        media_attachment_from_imeta_tag(&exact_filename, Some(7), false)
            .expect("a nonempty V2 filename is preserved exactly")
            .file_name,
        " "
    );

    let mut too_long = v2.clone();
    too_long[7] = format!("filename {}", "a".repeat(256));
    assert!(media_attachment_from_imeta_tag(&too_long, Some(7), false).is_err());
    let mut nul = v2;
    nul[7] = "filename bad\0name".to_owned();
    assert!(media_attachment_from_imeta_tag(&nul, Some(7), false).is_err());
}

#[test]
fn outbound_media_never_crosses_group_version() {
    let v1 = media_attachment_from_imeta_tag(&valid_imeta_tag(), Some(1), false).unwrap();
    let v2 = media_attachment_from_imeta_tag(&valid_v2_imeta_tag(), Some(1), false).unwrap();
    let allowed = [BLOSSOM_LOCATOR_KIND_V1.to_owned()];
    assert!(
        v1.validate_outbound(EncryptedMediaVersion::V2, &allowed, false)
            .is_err()
    );
    assert!(
        v2.validate_outbound(EncryptedMediaVersion::V1, &allowed, false)
            .is_err()
    );
    assert!(
        v1.build_imeta_tag(EncryptedMediaVersion::V2, &allowed, false)
            .is_err()
    );
    assert!(
        v2.build_imeta_tag(EncryptedMediaVersion::V1, &allowed, false)
            .is_err()
    );
}

#[test]
fn checked_v1_builder_rejects_noncanonical_media_type_while_ingest_stays_tolerant() {
    let mut noncanonical = valid_imeta_tag();
    noncanonical[6] = "m Image/JPG; charset=utf-8".to_owned();
    let reference = media_attachment_from_imeta_tag(&noncanonical, Some(1), false)
        .expect("legacy V1 ingest still accepts a noncanonical m field");
    assert_eq!(reference.media_type, "Image/JPG; charset=utf-8");

    let allowed = [BLOSSOM_LOCATOR_KIND_V1.to_owned()];
    let err = reference
        .build_imeta_tag(EncryptedMediaVersion::V1, &allowed, false)
        .expect_err("checked outbound V1 builder must reject noncanonical m");
    assert!(
        err.to_string()
            .contains("media type is not canonical for encrypted-media-v1"),
        "unexpected error: {err}"
    );
}

#[test]
fn retained_media_version_selects_its_historical_component_cache() {
    assert_eq!(
        EncryptedMediaVersion::V1.component_id(),
        GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID
    );
    assert_eq!(
        EncryptedMediaVersion::V2.component_id(),
        GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID
    );
}

#[test]
fn checked_imeta_builder_preserves_version_and_present_empty_optional_fields() {
    let allowed = [BLOSSOM_LOCATOR_KIND_V1.to_owned()];
    let v1 = media_attachment_from_imeta_tag(&valid_imeta_tag(), Some(1), false).unwrap();
    let v1_tag = v1
        .build_imeta_tag(EncryptedMediaVersion::V1, &allowed, false)
        .unwrap();
    assert!(v1_tag.iter().any(|field| field == "v encrypted-media-v1"));

    let mut v2 = media_attachment_from_imeta_tag(&valid_v2_imeta_tag(), Some(2), false).unwrap();
    v2.dim = Some(String::new());
    v2.thumbhash = Some(" ".to_owned());
    let v2_tag = v2
        .build_imeta_tag(EncryptedMediaVersion::V2, &allowed, false)
        .unwrap();
    assert!(v2_tag.iter().any(|field| field == "v encrypted-media-v2"));
    assert!(v2_tag.iter().any(|field| field == "dim "));
    assert!(v2_tag.iter().any(|field| field == "thumbhash  "));

    let round_trip = media_attachment_from_imeta_tag(&v2_tag, Some(2), false).unwrap();
    assert_eq!(round_trip.version, ENCRYPTED_MEDIA_FORMAT_V2);
    assert_eq!(round_trip.dim.as_deref(), Some(""));
    assert_eq!(round_trip.thumbhash.as_deref(), Some(" "));
}

#[test]
fn encrypted_media_v2_kdf_and_aad_are_independent_from_v1() {
    let secret = [7_u8; 32];
    let hash = [0x22_u8; 32];
    let v1_key = derive_media_file_key(
        &secret,
        EncryptedMediaVersion::V1,
        &hash,
        "image/jpeg",
        " Photo.JPG ",
    )
    .unwrap();
    let v2_key = derive_media_file_key(
        &secret,
        EncryptedMediaVersion::V2,
        &hash,
        "image/jpeg",
        " Photo.JPG ",
    )
    .unwrap();
    assert_ne!(v1_key, v2_key);
    assert_eq!(
        hex::encode(v2_key),
        "5fcb5672b9cb2b3ac7915fd9c97697877837f7fb1312034486f400f601cd16b5"
    );
    assert_eq!(
        hex::encode(media_aad(
            EncryptedMediaVersion::V2,
            &hash,
            "image/jpeg",
            " Photo.JPG "
        )),
        "656e637279707465642d6d656469612d763200222222222222222222222222222222222222222222222222222222222222222200696d6167652f6a706567002050686f746f2e4a504720"
    );
}

#[test]
fn invalid_media_attachment_is_local_to_that_attachment() {
    let mut invalid = valid_v2_imeta_tag();
    invalid.retain(|field| !field.starts_with("nonce "));
    assert!(media_attachment_from_imeta_tag(&invalid, None, false).is_err());
    assert!(media_imeta_tags_are_valid(
        &[invalid, valid_v2_imeta_tag()],
        false
    ));
}

fn tag_with_locator(locator: String) -> Vec<String> {
    let mut tag = valid_imeta_tag();
    tag[2] = format!("locator blossom-v1 {locator}");
    tag
}

#[test]
fn imeta_parser_rejects_duplicate_single_occurrence_field() {
    // Baseline valid tag parses.
    assert!(media_attachment_from_imeta_tag(&valid_imeta_tag(), None, false).is_ok());
    // A duplicate of a single-occurrence field MUST be rejected, especially the
    // key/AAD-determining ones (m, filename, plaintext_sha256).
    for dup in [
        "m image/jpeg".to_owned(),
        "filename evil.png".to_owned(),
        format!("plaintext_sha256 {}", "44".repeat(32)),
        format!("ciphertext_sha256 {}", "55".repeat(32)),
        "nonce 444444444444444444444444".to_owned(),
    ] {
        let mut tag = valid_imeta_tag();
        tag.push(dup.clone());
        assert!(
            media_attachment_from_imeta_tag(&tag, None, false).is_err(),
            "duplicate field {dup:?} must be rejected"
        );
    }
    // A repeated `locator` is allowed (locator is one-or-more).
    let mut multi = valid_imeta_tag();
    multi.push(format!(
        "locator blossom-v1 https://media2.example/{}.bin",
        "11".repeat(32)
    ));
    assert!(media_attachment_from_imeta_tag(&multi, None, false).is_ok());
}

pub(super) fn spawn_http_responses(responses: Vec<Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("test server addr");
    thread::spawn(move || {
        for response in responses {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(&response);
            }
        }
    });
    format!("http://{addr}")
}

pub(super) fn spawn_http_response(response: Vec<u8>) -> String {
    spawn_http_responses(vec![response])
}

async fn spawn_keep_alive_http_server(
    body: &'static [u8],
    requests_expected: usize,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let server_accepted = accepted.clone();
    let server = tokio::spawn(async move {
        let (request_tx, mut request_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut requests = 0_usize;
        while requests < requests_expected {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted.unwrap();
                    server_accepted.fetch_add(1, Ordering::SeqCst);
                    let request_tx = request_tx.clone();
                    tokio::spawn(async move {
                        loop {
                            let mut request = Vec::new();
                            let mut buffer = [0_u8; 1024];
                            loop {
                                let read = stream.read(&mut buffer).await.unwrap();
                                if read == 0 {
                                    break;
                                }
                                request.extend_from_slice(&buffer[..read]);
                                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            if request.is_empty() {
                                break;
                            }
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                                body.len()
                            );
                            stream.write_all(response.as_bytes()).await.unwrap();
                            stream.write_all(body).await.unwrap();
                            let _ = request_tx.send(());
                        }
                    });
                }
                request = request_rx.recv() => {
                    if request.is_some() {
                        requests += 1;
                    }
                }
            }
        }
    });
    (url, accepted, server)
}

async fn spawn_stalled_http_server() -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await;
        std::future::pending::<()>().await;
    });
    (url, server)
}

fn spawn_roundtrip_blob_server() -> (String, mpsc::Receiver<(u64, String)>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upload test server");
    let addr = listener.local_addr().expect("upload test server addr");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept upload");
        let mut stream = BufReader::new(stream);
        let mut content_length = None;
        loop {
            let mut line = String::new();
            stream.read_line(&mut line).expect("read upload header");
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line
                .strip_prefix("content-length:")
                .or_else(|| line.strip_prefix("Content-Length:"))
            {
                content_length = Some(value.trim().parse::<u64>().expect("content length"));
            }
        }
        let content_length = content_length.expect("upload content length header");
        let mut remaining = content_length;
        let mut body = Vec::with_capacity(content_length as usize);
        let mut buffer = [0_u8; 64 * 1024];
        while remaining > 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            stream
                .read_exact(&mut buffer[..take])
                .expect("read complete upload body");
            body.extend_from_slice(&buffer[..take]);
            remaining -= take as u64;
        }
        let digest = hex::encode(Sha256::digest(&body));
        stream
            .get_mut()
            .write_all(&http_json_response("{}"))
            .expect("write upload descriptor");
        drop(stream);
        let (mut download, _) = listener.accept().expect("accept download");
        let mut request = [0_u8; 4096];
        let _ = download.read(&mut request).expect("read download request");
        download
            .write_all(&http_ok_response(&body))
            .expect("write encrypted blob");
        tx.send((content_length, digest))
            .expect("report upload body");
    });
    (format!("http://{addr}"), rx)
}

fn spawn_hashing_upload_response(response: Vec<u8>) -> (String, mpsc::Receiver<(u64, String)>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upload test server");
    let addr = listener.local_addr().expect("upload test server addr");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept upload");
        let mut stream = BufReader::new(stream);
        let mut content_length = None;
        loop {
            let mut line = String::new();
            stream.read_line(&mut line).expect("read upload header");
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line
                .strip_prefix("content-length:")
                .or_else(|| line.strip_prefix("Content-Length:"))
            {
                content_length = Some(value.trim().parse::<u64>().expect("content length"));
            }
        }
        let content_length = content_length.expect("upload content length header");
        let mut remaining = content_length;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        while remaining > 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            stream
                .read_exact(&mut buffer[..take])
                .expect("read complete upload body");
            hash.update(&buffer[..take]);
            remaining -= take as u64;
        }
        stream
            .get_mut()
            .write_all(&response)
            .expect("write upload response");
        tx.send((content_length, hex::encode(hash.finalize())))
            .expect("report upload body");
    });
    (format!("http://{addr}"), rx)
}

#[derive(Clone, Copy)]
enum SlowUploadIngest {
    PauseAfterFirstChunk(Duration),
    Continuous { delay_per_chunk: Duration },
}

fn spawn_slow_upload_response(ingest: SlowUploadIngest) -> (String, mpsc::Receiver<u64>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind slow upload test server");
    let addr = listener.local_addr().expect("slow upload test server addr");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept slow upload");
        let mut stream = BufReader::new(stream);
        let mut content_length = None;
        loop {
            let mut line = String::new();
            stream.read_line(&mut line).expect("read upload header");
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line
                .strip_prefix("content-length:")
                .or_else(|| line.strip_prefix("Content-Length:"))
            {
                content_length = Some(value.trim().parse::<u64>().expect("content length"));
            }
        }
        let content_length = content_length.expect("upload content length header");
        let mut received = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        while received < content_length {
            let take = (content_length - received).min(buffer.len() as u64) as usize;
            let Ok(count) = stream.read(&mut buffer[..take]) else {
                return;
            };
            if count == 0 {
                return;
            }
            received += count as u64;
            match ingest {
                SlowUploadIngest::PauseAfterFirstChunk(delay) if received == count as u64 => {
                    thread::sleep(delay);
                }
                SlowUploadIngest::Continuous { delay_per_chunk } => {
                    thread::sleep(delay_per_chunk);
                }
                SlowUploadIngest::PauseAfterFirstChunk(_) => {}
            }
        }
        stream
            .get_mut()
            .write_all(&http_json_response("{}"))
            .expect("write slow upload descriptor");
        tx.send(received).expect("report slow upload body");
    });
    (format!("http://{addr}"), rx)
}

pub(super) fn http_redirect_response(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

pub(super) fn http_ok_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn http_json_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn http_status_response(status: u16, reason: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

fn http_error_response(status: u16, reason: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let headers = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    format!(
        "HTTP/1.1 {status} {reason}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn blossom_endpoint(base_url: String) -> crate::AppBlobEndpoint {
    crate::AppBlobEndpoint {
        locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
        base_url,
    }
}

fn operation_policy<'a>(
    version: EncryptedMediaVersion,
    endpoints: &'a [crate::AppBlobEndpoint],
    allowed_locator_kinds: &'a [String],
    allow_loopback_http: bool,
) -> MediaOperationPolicy<'a> {
    MediaOperationPolicy {
        version,
        default_endpoints: endpoints,
        allowed_locator_kinds,
        allow_loopback_http,
    }
}

fn media_upload_request(blossom_server: Option<String>) -> MediaUploadRequest {
    MediaUploadRequest {
        attachments: vec![MediaUploadAttachmentRequest {
            file_name: "diagram.png".to_owned(),
            media_type: "image/png".to_owned(),
            plaintext: b"hello encrypted media".to_vec(),
            dim: None,
            thumbhash: None,
        }],
        caption: None,
        send: false,
        blossom_server,
    }
}

fn signing_keys() -> nostr::Keys {
    nostr::Keys::generate()
}

fn media_secret() -> [u8; 32] {
    [7_u8; 32]
}

fn http_not_found_response() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

#[tokio::test]
async fn upload_encrypted_media_falls_back_to_second_blossom_endpoint() {
    let failing = spawn_http_response(http_status_response(500, "Internal Server Error"));
    let succeeding = spawn_http_response(http_json_response("{}"));
    let endpoints = [
        blossom_endpoint(failing.clone()),
        blossom_endpoint(succeeding.clone()),
    ];
    let allowed = [BLOSSOM_LOCATOR_KIND_V1.to_owned()];
    let secret = media_secret();
    let keys = signing_keys();

    let result = upload_encrypted_media(
        media_upload_request(None),
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V1, &endpoints, &allowed, true),
    )
    .await
    .expect("second Blossom endpoint should absorb first endpoint failure");

    let locator = &result.attachments[0].reference.locators[0];
    assert_eq!(locator.kind, BLOSSOM_LOCATOR_KIND_V1);
    assert!(
        locator.value.starts_with(&format!("{succeeding}/")),
        "upload locator should come from fallback server, got {}",
        locator.value
    );
    assert!(
        !locator.value.starts_with(&failing),
        "upload must not use the failed server locator"
    );
}

#[tokio::test]
async fn blossom_fallback_reuses_the_identical_encrypted_body() {
    let (failing, first_body) =
        spawn_hashing_upload_response(http_status_response(500, "Internal Server Error"));
    let (succeeding, second_body) = spawn_hashing_upload_response(http_json_response("{}"));
    let endpoints = [blossom_endpoint(failing), blossom_endpoint(succeeding)];
    let allowed = [BLOSSOM_LOCATOR_KIND_V1.to_owned()];
    let secret = media_secret();
    let keys = signing_keys();

    upload_encrypted_media(
        media_upload_request(None),
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V1, &endpoints, &allowed, true),
    )
    .await
    .expect("second Blossom endpoint should accept the retry body");

    assert_eq!(first_body.recv().unwrap(), second_body.recv().unwrap());
}

#[tokio::test]
async fn blossom_upload_allows_response_gap_longer_than_read_timeout() {
    let (server, received) = spawn_slow_upload_response(SlowUploadIngest::PauseAfterFirstChunk(
        Duration::from_secs(16),
    ));
    let encrypted = bytes::Bytes::from(vec![0x5a; 40_405_416]);
    let encrypted_hash = hex::encode(Sha256::digest(&encrypted));

    upload_blossom_blob(
        &server,
        encrypted.clone(),
        &encrypted_hash,
        &signing_keys(),
        true,
    )
    .await
    .expect("a bounded upload may wait more than the response read timeout while sending");

    assert_eq!(received.recv().unwrap(), encrypted.len() as u64);
}

#[tokio::test]
async fn blossom_upload_allows_continuous_slow_body_ingest() {
    let (server, received) = spawn_slow_upload_response(SlowUploadIngest::Continuous {
        delay_per_chunk: Duration::from_millis(30),
    });
    let encrypted = bytes::Bytes::from(vec![0x5a; 40_405_416]);
    let encrypted_hash = hex::encode(Sha256::digest(&encrypted));

    upload_blossom_blob(
        &server,
        encrypted.clone(),
        &encrypted_hash,
        &signing_keys(),
        true,
    )
    .await
    .expect("continuous request-body progress may exceed the response read timeout");

    assert_eq!(received.recv().unwrap(), encrypted.len() as u64);
}

#[tokio::test]
async fn encrypted_media_round_trip_crosses_the_previous_64_mib_limit() {
    let (server, received) = spawn_roundtrip_blob_server();
    let endpoints = [blossom_endpoint(server)];
    let allowed = [BLOSSOM_LOCATOR_KIND_V1.to_owned()];
    let secret = media_secret();
    let keys = signing_keys();
    let plaintext_len = 64 * 1024 * 1024 + 1;
    let request = MediaUploadRequest {
        attachments: vec![MediaUploadAttachmentRequest {
            file_name: "release.apk".to_owned(),
            media_type: "application/vnd.android.package-archive".to_owned(),
            plaintext: vec![0x5a; plaintext_len],
            dim: None,
            thumbhash: None,
        }],
        caption: None,
        send: false,
        blossom_server: None,
    };

    let result = upload_encrypted_media(
        request,
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V2, &endpoints, &allowed, true),
    )
    .await
    .expect("payload above the previous limit should upload");

    let attachment = &result.attachments[0];
    let downloaded = download_encrypted_media(
        attachment.reference.clone(),
        &secret,
        &endpoints,
        &allowed,
        true,
    )
    .await
    .expect("payload above the previous limit should download and decrypt");
    let (received_len, received_hash) = received.recv().expect("upload body report");
    assert_eq!(received_len, plaintext_len as u64 + 16);
    assert_eq!(attachment.encrypted_size_bytes, received_len);
    assert_eq!(attachment.reference.ciphertext_sha256, received_hash);
    assert_eq!(downloaded.plaintext, vec![0x5a; plaintext_len]);
}

#[tokio::test]
async fn encrypted_media_v2_upload_emits_v2_and_fresh_nonces() {
    let server = spawn_http_responses(vec![http_json_response("{}"), http_json_response("{}")]);
    let endpoints = [blossom_endpoint(server)];
    let allowed = [BLOSSOM_LOCATOR_KIND_V1.to_owned()];
    let secret = media_secret();
    let keys = signing_keys();
    let mut request = media_upload_request(None);
    request.attachments[0].file_name = " Diagram.PNG ".to_owned();
    request.attachments[0].media_type = " IMAGE/JPG ; charset=utf-8".to_owned();

    let first = upload_encrypted_media(
        request.clone(),
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V2, &endpoints, &allowed, true),
    )
    .await
    .unwrap();
    let second = upload_encrypted_media(
        request,
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V2, &endpoints, &allowed, true),
    )
    .await
    .unwrap();
    let first = &first.attachments[0].reference;
    let second = &second.attachments[0].reference;
    assert_eq!(first.version, ENCRYPTED_MEDIA_FORMAT_V2);
    assert_eq!(first.media_type, "image/jpeg");
    assert_eq!(first.file_name, " Diagram.PNG ");
    assert_ne!(first.nonce_hex, second.nonce_hex);
    assert_ne!(first.ciphertext_sha256, second.ciphertext_sha256);
}

#[tokio::test]
async fn blossom_upload_rejects_oversized_descriptor_before_buffering() {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_BLOSSOM_DESCRIPTOR_BYTES + 1
    );
    let server = spawn_http_response(response.into_bytes());
    let encrypted = b"encrypted bytes";
    let encrypted_hash = hex::encode(Sha256::digest(encrypted));

    let error = upload_blossom_blob(
        &server,
        bytes::Bytes::from_static(encrypted),
        &encrypted_hash,
        &signing_keys(),
        true,
    )
    .await
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "blob store request failed: upload descriptor exceeds size limit"
    );
}

#[tokio::test]
async fn profile_image_upload_rejects_non_raster_and_oversized_inputs_before_network() {
    let signer = signing_keys();
    let svg = upload_profile_image(
        b"<svg/>",
        "image/svg+xml",
        Some("https://blossom.example"),
        &signer,
    )
    .await
    .unwrap_err();
    assert_eq!(
        svg.to_string(),
        "blob store request failed: profile image must be JPEG, PNG, WebP, or GIF"
    );

    let oversized = vec![0_u8; MAX_PROFILE_IMAGE_BYTES + 1];
    let error = upload_profile_image(
        &oversized,
        "image/png",
        Some("https://blossom.example"),
        &signer,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "blob store request failed: profile image exceeds 10 MiB limit"
    );
}

#[tokio::test]
async fn profile_image_upload_rejects_empty_inputs_before_network() {
    let error = upload_profile_image(
        &[],
        "image/jpeg",
        Some("https://blossom.example"),
        &signing_keys(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "blob store request failed: profile image cannot be empty"
    );
}

#[tokio::test]
async fn profile_image_upload_rejects_mismatched_raster_bytes_before_network() {
    let error = upload_profile_image(
        b"<svg/>",
        "image/png",
        Some("https://blossom.example"),
        &signing_keys(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "blob store request failed: profile image bytes do not match the declared media type"
    );
}

#[tokio::test]
async fn profile_image_upload_uses_media_extension_and_accepts_test_loopback_policy() {
    let png_header = b"\x89PNG\r\n\x1a\n";
    let server = spawn_http_response(http_json_response("{}"));
    let url = upload_profile_image_with_policy(
        png_header,
        " IMAGE/PNG ; charset=binary",
        Some(&server),
        &signing_keys(),
        true,
    )
    .await
    .expect("profile upload should accept the explicit test loopback policy");

    assert!(url.ends_with(".png"), "unexpected profile image URL: {url}");
    assert!(!url.ends_with(".bin"));
}

#[tokio::test]
async fn profile_image_upload_rejects_cross_site_descriptor_url() {
    let png_header = b"\x89PNG\r\n\x1a\n";
    let hash = hex::encode(Sha256::digest(png_header));
    let descriptor = serde_json::json!({
        "url": format!("https://attacker.example/{hash}.png"),
        "sha256": hash,
    });
    let server = spawn_http_response(http_json_response(&descriptor.to_string()));
    let error = upload_profile_image_with_policy(
        png_header,
        "image/png",
        Some(&server),
        &signing_keys(),
        true,
    )
    .await
    .unwrap_err();

    assert!(
        error.to_string().contains("unsafe upload descriptor host"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn upload_encrypted_media_reports_all_blossom_endpoint_failures() {
    let first = spawn_http_response(http_status_response(500, "Internal Server Error"));
    let second = spawn_http_response(http_status_response(502, "Bad Gateway"));
    let endpoints = [
        blossom_endpoint(first.clone()),
        blossom_endpoint(second.clone()),
    ];
    let secret = media_secret();
    let keys = signing_keys();

    let err = upload_encrypted_media(
        media_upload_request(None),
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V1, &endpoints, &[], true),
    )
    .await
    .expect_err("all failing endpoints should aggregate their failures");

    let AppError::BlobStore(message) = err else {
        panic!("expected aggregated BlobStore error");
    };
    assert!(
        message.contains("upload failed for all Blossom servers"),
        "unexpected error: {message}"
    );
    assert!(message.contains("server 1: upload returned HTTP 500"));
    assert!(message.contains("server 2: upload returned HTTP 502"));
    assert!(
        !message.contains(&first) && !message.contains(&second),
        "aggregated error must not embed Blossom server URLs: {message}"
    );
}

#[tokio::test]
async fn upload_encrypted_media_preserves_privacy_safe_blossom_rejection_reason() {
    let rejecting = spawn_http_response(http_error_response(
        415,
        "Unsupported Media Type",
        &[],
        "upload rejected: unsupported media type application/octet-stream",
    ));
    let endpoints = [blossom_endpoint(rejecting)];
    let secret = media_secret();
    let keys = signing_keys();

    let error = upload_encrypted_media(
        media_upload_request(None),
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V1, &endpoints, &[], true),
    )
    .await
    .expect_err("the server rejection should fail the upload");

    assert_eq!(
        error.to_string(),
        "blob store request failed: upload failed for all Blossom servers: server 1: upload returned HTTP 415: upload rejected: unsupported media type application/octet-stream"
    );
}

#[tokio::test]
async fn upload_encrypted_media_drops_sensitive_blossom_rejection_reason() {
    let secret_value = "11".repeat(32);
    let rejecting = spawn_http_response(http_error_response(
        403,
        "Forbidden",
        &[(
            "X-Reason",
            &format!("blob https://media.example/{secret_value} is forbidden"),
        )],
        "",
    ));
    let endpoints = [blossom_endpoint(rejecting)];
    let secret = media_secret();
    let keys = signing_keys();

    let error = upload_encrypted_media(
        media_upload_request(None),
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V1, &endpoints, &[], true),
    )
    .await
    .expect_err("the server rejection should fail the upload");
    let message = error.to_string();

    assert!(message.contains("upload returned HTTP 403"));
    assert!(!message.contains("media.example"));
    assert!(!message.contains(&secret_value));
}

#[tokio::test]
async fn upload_encrypted_media_drops_punctuated_hash_rejection_reason() {
    let secret_value = "11".repeat(32);
    let rejecting = spawn_http_response(http_error_response(
        409,
        "Conflict",
        &[(
            "X-Reason",
            &format!("duplicate-blob-{secret_value}-already-exists"),
        )],
        "",
    ));
    let endpoints = [blossom_endpoint(rejecting)];
    let secret = media_secret();
    let keys = signing_keys();

    let error = upload_encrypted_media(
        media_upload_request(None),
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V1, &endpoints, &[], true),
    )
    .await
    .expect_err("the server rejection should fail the upload");
    let message = error.to_string();

    assert!(message.contains("upload returned HTTP 409"));
    assert!(!message.contains(&secret_value));
}

#[tokio::test]
async fn upload_encrypted_media_drops_uuid_rejection_reason() {
    let rejecting = spawn_http_response(http_error_response(
        403,
        "Forbidden",
        &[(
            "X-Reason",
            "upload id 123e4567-e89b-12d3-a456-426614174000 already used",
        )],
        "",
    ));
    let endpoints = [blossom_endpoint(rejecting)];
    let secret = media_secret();
    let keys = signing_keys();

    let error = upload_encrypted_media(
        media_upload_request(None),
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V1, &endpoints, &[], true),
    )
    .await
    .expect_err("the server rejection should fail the upload");
    let message = error.to_string();

    assert!(message.contains("upload returned HTTP 403"));
    assert!(!message.contains("123e4567"));
}

#[tokio::test]
async fn upload_encrypted_media_drops_non_http_url_scheme_rejection_reason() {
    let rejecting = spawn_http_response(http_error_response(
        403,
        "Forbidden",
        &[("X-Reason", "denied, use relay wss://relay.example instead")],
        "",
    ));
    let endpoints = [blossom_endpoint(rejecting)];
    let secret = media_secret();
    let keys = signing_keys();

    let error = upload_encrypted_media(
        media_upload_request(None),
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V1, &endpoints, &[], true),
    )
    .await
    .expect_err("the server rejection should fail the upload");
    let message = error.to_string();

    assert!(message.contains("upload returned HTTP 403"));
    assert!(!message.contains("relay.example"));
}

#[test]
fn built_in_blossom_endpoints_are_ciphertext_compatible_fallbacks() {
    assert_eq!(DEFAULT_BLOSSOM_SERVER_URL, DEFAULT_BLOSSOM_SERVER_URLS[0]);
    assert_eq!(
        DEFAULT_BLOSSOM_SERVER_URLS,
        [
            "https://blossom.divine.video",
            "https://blossom.ditto.pub",
            "https://cdn.hzrd149.com",
        ]
    );
    assert!(!DEFAULT_BLOSSOM_SERVER_URLS.contains(&"https://blossom.primal.net"));
}

#[tokio::test]
async fn explicit_blossom_server_override_skips_default_endpoint_failover() {
    let override_server = spawn_http_response(http_status_response(500, "Internal Server Error"));
    let default_server = spawn_http_response(http_json_response("{}"));
    let endpoints = [blossom_endpoint(default_server.clone())];
    let secret = media_secret();
    let keys = signing_keys();

    let err = upload_encrypted_media(
        media_upload_request(Some(override_server.clone())),
        42,
        &secret,
        &keys,
        operation_policy(EncryptedMediaVersion::V1, &endpoints, &[], true),
    )
    .await
    .expect_err("explicit override must remain a single-server bypass");

    let AppError::BlobStore(message) = err else {
        panic!("expected single override BlobStore error");
    };
    assert!(message.contains("server 1: upload returned HTTP 500"));
    assert!(
        !message.contains("server 2") && !message.contains(&default_server),
        "override failure should not include default endpoint fallback: {message}"
    );
}

#[test]
fn imeta_parser_rejects_legacy_version_even_when_later_current_version_present() {
    let mut tag = valid_imeta_tag();
    tag.insert(1, "v legacy-media-v0".to_owned());

    assert!(media_attachment_from_imeta_tag(&tag, None, false).is_err());
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_rejects_duplicate_current_version_fields() {
    let mut tag = valid_imeta_tag();
    tag.insert(1, "v encrypted-media-v1".to_owned());

    assert!(media_attachment_from_imeta_tag(&tag, None, false).is_err());
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn out_of_policy_locator_kind_is_kept_not_dropped_on_ingest() {
    // PR #328 review Finding 2 (the reviewer's "delayed old media message
    // rejected after a policy update" regression): ingest is purely
    // structural, so a structurally well-formed locator whose kind is NOT in
    // the group's current `allowed_locator_kinds` MUST NOT invalidate the
    // reference or drop the containing kind-9 message. Media is authenticated
    // by its hashes + AEAD independent of the locator, so an out-of-policy
    // locator cannot forge content; it only becomes unfetchable at download
    // time. (The ingest parser no longer takes a policy at all.)
    let mut tag = valid_imeta_tag();
    // A non-blossom locator that is not in any default policy. It is
    // structurally well-formed (parseable URL), so ingest keeps it.
    tag.insert(2, "locator ipfs-v1 ipfs://bafybeigdyrexample".to_owned());

    let reference = media_attachment_from_imeta_tag(&tag, None, false)
        .expect("an out-of-policy but well-formed locator must not drop the message");
    assert_eq!(reference.locators.len(), 2);
    assert!(media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn structurally_malformed_reference_is_rejected_on_ingest() {
    // PR #328 review Finding 2: structural malformation (here a non-hex
    // ciphertext hash) still invalidates the reference and drops the message,
    // exactly as before. The "never drop" rule applies only to locator-kind
    // policy, never to structural integrity.
    let mut tag = valid_imeta_tag();
    // Replace the valid `ciphertext_sha256` with a non-hex value.
    let bad = tag
        .iter_mut()
        .find(|field| field.starts_with("ciphertext_sha256 "))
        .expect("fixture has a ciphertext_sha256 field");
    *bad = "ciphertext_sha256 not-a-valid-hash".to_owned();

    assert!(media_attachment_from_imeta_tag(&tag, None, false).is_err());
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_rejects_non_https_media_locator() {
    let tag = tag_with_locator(format!("http://media.example/{}.bin", valid_hash()));
    let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

    assert!(err.to_string().contains("scheme must be https"));
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn locator_with_unparseable_url_is_rejected_on_ingest() {
    // A locator value that does not parse as a URL is structural malformation
    // and MUST invalidate the reference even though the kind is `blossom-v1`.
    let mut tag = valid_imeta_tag();
    let locator = tag
        .iter_mut()
        .find(|field| field.starts_with("locator "))
        .expect("fixture has a locator field");
    *locator = "locator blossom-v1 not a url".to_owned();

    assert!(media_attachment_from_imeta_tag(&tag, None, false).is_err());
}

fn blossom_reference() -> MediaAttachmentReference {
    let mut reference = loopback_reference();
    reference.locators = vec![MediaLocator {
        kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
        // The blossom locator URL must carry the ciphertext hash (= the
        // reference's `ciphertext_sha256`, `11`*32) per the merged blossom
        // content-hash binding.
        value: format!("https://media.example/{}.bin", "11".repeat(32)),
    }];
    reference
}

#[test]
fn media_fetch_candidates_deduplicate_non_adjacent_fallback_urls() {
    let mut reference = blossom_reference();
    let duplicate_url = reference.locators[0].value.clone();
    reference.locators.push(MediaLocator {
        kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
        value: format!("https://other.example/{}.bin", reference.ciphertext_sha256),
    });
    let fallback = [crate::AppBlobEndpoint {
        locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
        base_url: "https://media.example".to_owned(),
    }];

    let candidates = encrypted_media_fetch_candidates(&reference, &fallback);

    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0], duplicate_url);
}

#[test]
fn outbound_validation_rejects_blossom_reference_when_policy_disallows_blossom() {
    // PR #328 review Finding 1: the sender MUST NOT emit a `blossom-v1`
    // reference to a group whose policy does not allow `blossom-v1`, since
    // receivers would treat the locator as unfetchable. A non-empty policy
    // that omits `blossom-v1` must fail outbound validation.
    let reference = blossom_reference();
    let allowed = vec!["ipfs-v1".to_owned()];
    assert!(
        reference
            .validate_outbound(EncryptedMediaVersion::V1, &allowed, false)
            .is_err(),
        "a blossom reference must be rejected when the policy omits blossom-v1"
    );
    // The same reference is valid against a policy that does allow blossom-v1.
    let allowed = vec![BLOSSOM_LOCATOR_KIND_V1.to_owned()];
    reference
        .validate_outbound(EncryptedMediaVersion::V1, &allowed, false)
        .expect("a blossom reference is valid when the policy allows blossom-v1");
}

#[test]
fn canonical_media_type_trims_ascii_whitespace_only() {
    // ASCII whitespace on the edges is stripped per the V1 algorithm.
    assert_eq!(
        canonical_media_type_v1("  image/png \t").expect("ascii-trimmed type is valid"),
        "image/png",
    );

    // A leading U+00A0 (non-breaking space) is Unicode whitespace but NOT
    // ASCII whitespace, so it MUST be preserved: trimming it would derive a
    // different file_key/AAD than a spec-conformant peer that keeps it.
    let canonical =
        canonical_media_type_v1("\u{00A0}image/png").expect("non-empty MIME type is valid");
    assert_eq!(canonical, "\u{00A0}image/png");
    assert!(canonical.starts_with('\u{00A0}'));
}

#[test]
fn is_loopback_http_endpoint_classifies_only_cleartext_loopback() {
    // Cleartext loopback hosts are loopback-HTTP endpoints.
    assert!(is_loopback_http_endpoint("http://127.0.0.1:8080/up"));
    assert!(is_loopback_http_endpoint("http://localhost:3000"));
    assert!(is_loopback_http_endpoint("http://sub.localhost/blob"));
    assert!(is_loopback_http_endpoint("http://[::1]:8080"));
    // HTTPS (even to loopback) and routable HTTP hosts are not.
    assert!(!is_loopback_http_endpoint("https://127.0.0.1:8080"));
    assert!(!is_loopback_http_endpoint("http://media.example/blob"));
    assert!(!is_loopback_http_endpoint("https://blossom.example"));
    assert!(!is_loopback_http_endpoint("not a url"));
}

fn loopback_reference() -> MediaAttachmentReference {
    MediaAttachmentReference {
        locators: vec![MediaLocator {
            kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
            value: format!("http://127.0.0.1:8080/{}.bin", "11".repeat(32)),
        }],
        ciphertext_sha256: "11".repeat(32),
        plaintext_sha256: "22".repeat(32),
        nonce_hex: "33".repeat(12),
        file_name: "diagram.png".to_owned(),
        media_type: "image/png".to_owned(),
        version: ENCRYPTED_MEDIA_VERSION.to_owned(),
        source_epoch: 0,
        dim: None,
        thumbhash: None,
    }
}

#[test]
fn loopback_locator_validation_follows_runtime_flag_not_build_profile() {
    // Issue #341 regression: the runtime `allow_loopback_http` flag (driven by
    // `MarmotAppConfig::allow_loopback_blob_endpoints`) is now the SOLE
    // authority for accepting a cleartext-`http` loopback `blossom-v1` locator,
    // replacing the old compile-time `cfg!(debug_assertions)` gate. The
    // reference carries a hash-bearing loopback URL so it clears the Blossom
    // content-hash binding and the loopback host is the only thing under test.
    // Outcome must depend on the flag in EVERY build profile (this test runs
    // under `debug_assertions`, where the old gate would have force-allowed it).
    let reference = loopback_reference();
    assert!(
        reference.validate(false).is_err(),
        "a loopback-HTTP blossom locator must be rejected when the flag is off",
    );
    reference
        .validate(true)
        .expect("a loopback-HTTP blossom locator must be accepted when the flag is on");

    // The same authority must hold on the ingest parser path
    // (`media_attachment_from_imeta_tag` / `media_imeta_tags_are_valid`).
    let tag = reference.imeta_tag();
    let tags = std::slice::from_ref(&tag);
    assert!(
        media_attachment_from_imeta_tag(&tag, None, false).is_err(),
        "ingest must reject a loopback-HTTP blossom locator when the flag is off",
    );
    assert!(!media_imeta_tags_are_valid(tags, false));
    media_attachment_from_imeta_tag(&tag, None, true)
        .expect("ingest must accept a loopback-HTTP blossom locator when the flag is on");
    assert!(media_imeta_tags_are_valid(tags, true));
}

#[tokio::test]
async fn production_config_does_not_fetch_loopback_endpoint() {
    // With the dev/test gate off, a loopback-HTTP locator is dropped from the
    // candidate set, so no GET is issued and the fetch fails as "no supported
    // locators" rather than attempting to reach the local host.
    let reference = loopback_reference();
    let err = fetch_encrypted_media_blob(&reference, &[], &[], false)
        .await
        .expect_err("loopback-only reference must be unfetchable in production");
    match err {
        AppError::InvalidEncryptedMedia(message) => {
            assert!(
                message.contains("no supported locators"),
                "expected unfetchable error, got: {message}"
            );
        }
        other => panic!("expected InvalidEncryptedMedia, got {other:?}"),
    }
}

#[tokio::test]
async fn loopback_fallback_endpoint_is_skipped_in_production() {
    // The same gate applies to remote-admin policy fallback endpoints. With
    // no supported locator on the message, a loopback-HTTP fallback is the
    // only candidate; in production it is filtered out, so the fetch fails as
    // unfetchable instead of GETting the local host.
    let mut reference = loopback_reference();
    // Drop the message-carried locator so the loopback fallback is the only
    // candidate under test, keeping one policy-allowed-but-unsupported
    // locator so the reference stays structurally valid.
    reference.locators.clear();
    reference.locators.push(MediaLocator {
        kind: "ipfs-v1".to_owned(),
        value: "ipfs://bafyexample".to_owned(),
    });
    let fallback = [crate::AppBlobEndpoint {
        locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
        base_url: "http://127.0.0.1:8080".to_owned(),
    }];
    let err = fetch_encrypted_media_blob(&reference, &fallback, &[], false)
        .await
        .expect_err("loopback fallback must be unfetchable in production");
    match err {
        AppError::InvalidEncryptedMedia(message) => assert!(
            message.contains("no supported locators"),
            "expected unfetchable error, got: {message}"
        ),
        other => panic!("expected InvalidEncryptedMedia, got {other:?}"),
    }
    // The loopback fallback would survive the candidate filter only when the
    // dev/test gate is on; assert the classifier agrees so the gate stays the
    // single decision point.
    assert!(is_loopback_http_endpoint(&blossom_blob_url(
        &fallback[0].base_url,
        &reference.ciphertext_sha256,
    )));
}

#[tokio::test]
async fn out_of_policy_blossom_locator_is_unfetchable_not_a_hard_error() {
    // PR #328 review Finding 2: when the group's CURRENT policy does not allow
    // `blossom-v1`, a blossom locator is out of policy and this client cannot
    // fetch it. The fetch MUST degrade to the unfetchable outcome ("no
    // supported locators") rather than a hard error that looks like content
    // corruption. The reference itself stays structurally valid and the
    // message was already delivered at ingest.
    let mut reference = loopback_reference();
    // Use a routable https locator so loopback gating is not what skips it;
    // the only reason it is unfetchable is the out-of-policy locator kind.
    reference.locators = vec![MediaLocator {
        kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
        value: format!("https://media.example/{}.bin", "11".repeat(32)),
    }];
    // A non-empty policy that allows only a non-blossom kind: blossom is out
    // of policy, so there is no fetchable locator for this client.
    let allowed = vec!["ipfs-v1".to_owned()];
    let err = fetch_encrypted_media_blob(&reference, &[], &allowed, true)
        .await
        .expect_err("an out-of-policy blossom locator must be unfetchable");
    match err {
        AppError::InvalidEncryptedMedia(message) => assert!(
            message.contains("no supported locators"),
            "expected unfetchable error, got: {message}"
        ),
        other => panic!("expected InvalidEncryptedMedia, got {other:?}"),
    }
    // The reference is still structurally valid: out-of-policy is a
    // fetchability concern, not a structural one.
    reference
        .validate(false)
        .expect("an out-of-policy reference is still structurally valid");
}

#[test]
fn imeta_parser_rejects_private_ip_media_locator() {
    let tag = tag_with_locator(format!("https://10.0.0.5/{}.bin", valid_hash()));
    let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

    assert!(err.to_string().contains("public unicast"));
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_rejects_ipv6_transition_prefix_media_locators() {
    for locator in [
        // 6to4 wraps 10.0.0.5 in the two segments after 2002::/16.
        format!("https://[2002:a00:5::]/{}.bin", valid_hash()),
        // Teredo carries the obfuscated client IPv4 in the low 32 bits: !10.0.0.5.
        format!(
            "https://[2001:0:4136:e378:8000:63bf:f5ff:fffa]/{}.bin",
            valid_hash()
        ),
    ] {
        let tag = tag_with_locator(locator);
        let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

        assert!(err.to_string().contains("public unicast"));
        assert!(!media_imeta_tags_are_valid(&[tag], false));
    }
}

#[test]
fn imeta_parser_rejects_ipv6_documentation_3fff_media_locator() {
    // 3fff::/20 (RFC 9637) is documentation space that sits inside global-unicast
    // 2000::/3, so it must be rejected explicitly (canonical unsafe-host set).
    let tag = tag_with_locator(format!("https://[3fff::1]/{}.bin", valid_hash()));
    let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

    assert!(err.to_string().contains("public unicast"));
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_accepts_public_ipv6_media_locator() {
    let tag = tag_with_locator(format!("https://[2606:4700::]/{}.bin", valid_hash()));

    assert!(media_attachment_from_imeta_tag(&tag, None, false).is_ok());
    assert!(media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_rejects_locator_without_content_hash() {
    let tag = tag_with_locator("https://media.example/download.bin".to_owned());
    let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

    assert!(
        err.to_string()
            .contains("must include the encrypted blob hash")
    );
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn imeta_parser_rejects_locator_hash_mismatch() {
    let tag = tag_with_locator(format!("https://media.example/{}.bin", "33".repeat(32)));
    let err = media_attachment_from_imeta_tag(&tag, None, false).unwrap_err();

    assert!(err.to_string().contains("hash does not match"));
    assert!(!media_imeta_tags_are_valid(&[tag], false));
}

#[test]
fn media_fetch_url_policy_allows_loopback_http_only_when_explicitly_enabled() {
    let url = Url::parse(&format!("http://127.0.0.1:3000/{}.bin", valid_hash())).unwrap();

    assert!(validate_blossom_fetch_url(&url, true).is_ok());
    assert!(validate_blossom_fetch_url(&url, false).is_err());
}

#[test]
fn blossom_redirect_validation_allows_same_registrable_domain() {
    let current = Url::parse(&format!("https://blossom.primal.net/{}.bin", valid_hash())).unwrap();
    let next = Url::parse(&format!(
        "https://r2a.primal.net/uploads/{}.bin",
        valid_hash()
    ))
    .unwrap();

    super::blossom::validate_blossom_redirect_target(&current, &next, false)
        .expect("same registrable domain redirect must be allowed");
}

#[test]
fn blossom_redirect_validation_rejects_cross_scheme_private_ip_and_cross_domain() {
    let current = Url::parse(&format!("https://media.example/{}.bin", valid_hash())).unwrap();
    for (next, expected) in [
        (
            format!("http://media.example/{}.bin", valid_hash()),
            "scheme must be https",
        ),
        (
            format!("https://10.0.0.5/{}.bin", valid_hash()),
            "public unicast",
        ),
        (
            format!("https://cdn.attacker.net/{}.bin", valid_hash()),
            "same host or registrable domain",
        ),
    ] {
        let next = Url::parse(&next).unwrap();
        let err = super::blossom::validate_blossom_redirect_target(&current, &next, false)
            .expect_err("unsafe redirect must be rejected");
        assert!(
            err.to_string().contains(expected),
            "expected {expected:?}, got {err}"
        );
    }
}

fn blob_reference_for_servers(body: &[u8], servers: &[String]) -> MediaAttachmentReference {
    let hash = hex::encode(Sha256::digest(body));
    let mut reference = blossom_reference();
    reference.ciphertext_sha256 = hash.clone();
    reference.locators = servers
        .iter()
        .map(|server| MediaLocator {
            kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
            value: format!("{server}/{hash}.bin"),
        })
        .collect();
    reference
}

#[tokio::test]
async fn repeated_same_origin_downloads_reuse_one_vetted_connection() {
    let (server_url, accepted, server) = spawn_keep_alive_http_server(b"hello", 2).await;
    let transport =
        BlossomHttpTransport::for_test(true, Duration::from_secs(60), Duration::from_secs(1));
    let url = format!("{server_url}/{}.bin", valid_hash());

    assert_eq!(
        fetch_blossom_blob_with_transport(&url, &transport)
            .await
            .unwrap(),
        b"hello"
    );
    assert_eq!(
        fetch_blossom_blob_with_transport(&url, &transport)
            .await
            .unwrap(),
        b"hello"
    );
    server.await.unwrap();

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "compatible same-origin downloads should reuse the vetted connection"
    );
}

#[tokio::test]
async fn concurrent_same_origin_client_setup_resolves_and_vets_once() {
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver_resolutions = resolutions.clone();
    let resolver: DnsResolver = Arc::new(move |_domain, port| {
        resolver_resolutions.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            Ok(vec![format!("1.1.1.1:{port}").parse().unwrap()])
        })
    });
    let transport = BlossomHttpTransport::for_test_with_resolver(
        false,
        Duration::from_secs(60),
        Duration::from_secs(1),
        resolver,
    );
    let url = Url::parse(&format!("https://media.example/{}.bin", valid_hash())).unwrap();

    let clients = futures::future::join_all((0..4).map(|_| transport.client_for_url(&url))).await;

    assert!(clients.into_iter().all(|client| client.is_ok()));
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        1,
        "concurrent setup for one origin should share resolution and vetting"
    );
}

#[tokio::test]
async fn separate_download_transports_do_not_share_connections() {
    let (server_url, accepted, server) = spawn_keep_alive_http_server(b"hello", 2).await;
    let first =
        BlossomHttpTransport::for_test(true, Duration::from_secs(60), Duration::from_secs(1));
    let second =
        BlossomHttpTransport::for_test(true, Duration::from_secs(60), Duration::from_secs(1));
    let url = format!("{server_url}/{}.bin", valid_hash());

    fetch_blossom_blob_with_transport(&url, &first)
        .await
        .unwrap();
    fetch_blossom_blob_with_transport(&url, &second)
        .await
        .unwrap();
    server.await.unwrap();

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "account-scoped transports must not share connection pools"
    );
}

#[tokio::test]
async fn expired_origin_lease_is_resolved_and_vetted_again() {
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver_resolutions = resolutions.clone();
    let resolver: DnsResolver = Arc::new(move |_domain, port| {
        let attempt = resolver_resolutions.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let ip = if attempt == 0 { "1.1.1.1" } else { "127.0.0.1" };
            Ok(vec![format!("{ip}:{port}").parse().unwrap()])
        })
    });
    let transport = BlossomHttpTransport::for_test_with_resolver(
        false,
        Duration::ZERO,
        Duration::from_secs(1),
        resolver,
    );
    let url = Url::parse(&format!("https://media.example/{}.bin", valid_hash())).unwrap();

    transport
        .client_for_url(&url)
        .await
        .expect("first public address set should be accepted");
    let error = transport
        .client_for_url(&url)
        .await
        .expect_err("expired lease must reject the newly resolved loopback address");

    assert_eq!(resolutions.load(Ordering::SeqCst), 2);
    assert!(error.to_string().contains("public unicast"));
}

#[tokio::test]
async fn stalled_first_locator_reaches_healthy_fallback_within_startup_bound() {
    let body = b"healthy ciphertext";
    let (stalled_url, stalled_server) = spawn_stalled_http_server().await;
    let healthy_url = spawn_http_response(http_ok_response(body));
    let reference = blob_reference_for_servers(body, &[stalled_url, healthy_url]);
    let transport =
        BlossomHttpTransport::for_test(true, Duration::from_secs(60), Duration::from_millis(500));
    let allowed = [BLOSSOM_LOCATOR_KIND_V1.to_owned()];

    let downloaded = tokio::time::timeout(
        Duration::from_secs(2),
        fetch_encrypted_media_blob_with_transport(&reference, &[], &allowed, &transport),
    )
    .await
    .expect("healthy fallback must be reached promptly")
    .expect("healthy fallback must succeed");
    stalled_server.abort();

    assert_eq!(downloaded, body);
}

#[tokio::test]
async fn corrupt_first_locator_does_not_prevent_integrity_valid_fallback() {
    let body = b"integrity-valid ciphertext";
    let corrupt_url = spawn_http_response(http_ok_response(b"corrupt"));
    let healthy_url = spawn_http_response(http_ok_response(body));
    let reference = blob_reference_for_servers(body, &[corrupt_url, healthy_url]);
    let transport =
        BlossomHttpTransport::for_test(true, Duration::from_secs(60), Duration::from_secs(1));
    let allowed = [BLOSSOM_LOCATOR_KIND_V1.to_owned()];

    let downloaded =
        fetch_encrypted_media_blob_with_transport(&reference, &[], &allowed, &transport)
            .await
            .expect("corrupt first candidate must fall through to the healthy locator");

    assert_eq!(downloaded, body);
}

#[tokio::test]
async fn fetch_blossom_blob_follows_hashless_redirect_targets() {
    let final_server = spawn_http_response(http_ok_response(b"hello"));
    let final_url = format!("{final_server}/signed/opaque-key?X-Amz-Signature=test");
    let redirecting_server = spawn_http_response(http_redirect_response(&final_url));
    let url = format!("{redirecting_server}/{}.bin", valid_hash());

    let bytes = fetch_blossom_blob(&url, true)
        .await
        .expect("valid redirect should fetch final blob");

    assert_eq!(bytes, b"hello");
}

#[tokio::test]
async fn fetch_blossom_blob_rejects_redirect_chain_over_limit() {
    let responses = (0..6)
        .map(|idx| http_redirect_response(&format!("/hop-{idx}/{}.bin", valid_hash())))
        .collect::<Vec<_>>();
    let server = spawn_http_responses(responses);
    let url = format!("{server}/{}.bin", valid_hash());
    let err = fetch_blossom_blob(&url, true).await.unwrap_err();

    assert!(err.to_string().contains("exceeded 5 hops"));
}

#[tokio::test]
async fn fetch_blossom_blob_rejects_redirect_without_location() {
    let server = spawn_http_response(
        b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    );
    let url = format!("{server}/{}.bin", valid_hash());
    let err = fetch_blossom_blob(&url, true).await.unwrap_err();

    assert!(
        err.to_string()
            .contains("redirect response did not include Location")
    );
}

#[tokio::test]
async fn fetch_blossom_blob_reports_terminal_status_after_redirect() {
    let server = spawn_http_responses(vec![
        http_redirect_response("/missing-opaque-key"),
        http_not_found_response(),
    ]);
    let url = format!("{server}/{}.bin", valid_hash());
    let err = fetch_blossom_blob(&url, true).await.unwrap_err();

    assert!(
        err.to_string().contains("download returned HTTP 404"),
        "expected terminal status, got: {err}"
    );
}

#[tokio::test]
async fn fetch_blossom_blob_follows_redirect_target_with_different_path_hash() {
    let final_server = spawn_http_response(http_ok_response(b"hello"));
    let final_url = format!("{final_server}/{}.bin", "22".repeat(32));
    let redirecting_server = spawn_http_response(http_redirect_response(&final_url));
    let url = format!("{redirecting_server}/{}.bin", valid_hash());

    let bytes = fetch_blossom_blob(&url, true)
        .await
        .expect("redirect target path hash is not authoritative for content integrity");

    assert_eq!(bytes, b"hello");
}

#[tokio::test]
async fn fetch_blossom_blob_rejects_oversized_content_length() {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_ENCRYPTED_MEDIA_BLOB_BYTES + 1
    );
    let server = spawn_http_response(response.into_bytes());
    let url = format!("{server}/{}.bin", valid_hash());
    let err = fetch_blossom_blob(&url, true).await.unwrap_err();

    assert!(err.to_string().contains("download exceeds"));
}

#[tokio::test]
async fn limited_body_reader_rejects_chunked_body_over_cap() {
    let server = spawn_http_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nabcdef\r\n0\r\n\r\n"
            .to_vec(),
    );
    let response = reqwest::Client::new()
        .get(format!("{server}/{}.bin", valid_hash()))
        .send()
        .await
        .expect("fetch chunked test body");
    let err = read_limited_blossom_body(response, 5).await.unwrap_err();

    assert!(err.to_string().contains("download exceeds 5 bytes"));
}

/// Load the shared golden imeta fixture file used by marmot-app, marmot-uniffi,
/// and wn-cli agreement tests.
fn shared_media_fixture_cases(file: &str) -> Vec<serde_json::Value> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/encrypted-media")
        .join(file);
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read media fixture {}: {err}", path.display())),
    )
    .expect("media fixture file is valid JSON");
    doc["cases"].as_array().expect("fixture cases").clone()
}

fn fixture_tag(case: &serde_json::Value) -> Vec<String> {
    case["tag"]
        .as_array()
        .expect("fixture tag")
        .iter()
        .map(|field| field.as_str().expect("fixture tag field").to_owned())
        .collect()
}

/// `null`/absent means the optional wire field is absent; `""` (or any string)
/// means it is present with exactly that value. The distinction is part of the
/// fixture contract because build -> parse must not collapse it.
fn fixture_optional(value: &serde_json::Value, key: &str) -> Option<String> {
    match &value[key] {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        other => panic!("fixture optional field {key} must be null or string, got {other}"),
    }
}

fn assert_shared_media_fixture_file(file: &str) {
    let cases = shared_media_fixture_cases(file);
    assert!(!cases.is_empty(), "{file} must contain cases");
    for case in cases {
        let name = case["name"].as_str().expect("fixture case name");
        let tag = fixture_tag(&case);
        let source_epoch = case["source_epoch"].as_u64().expect("fixture source_epoch");
        let result = media_attachment_from_imeta_tag(&tag, Some(source_epoch), false);
        if case["valid"].as_bool().expect("fixture valid flag") {
            let reference = result
                .unwrap_or_else(|err| panic!("{file}/{name} must parse as a valid tag: {err}"));
            let expected = &case["expected"];
            assert_eq!(
                reference.version,
                expected["version"].as_str().unwrap(),
                "{file}/{name} version"
            );
            let expected_locators: Vec<MediaLocator> = expected["locators"]
                .as_array()
                .unwrap()
                .iter()
                .map(|locator| MediaLocator {
                    kind: locator["kind"].as_str().unwrap().to_owned(),
                    value: locator["value"].as_str().unwrap().to_owned(),
                })
                .collect();
            assert_eq!(
                reference.locators, expected_locators,
                "{file}/{name} locators"
            );
            assert_eq!(
                reference.ciphertext_sha256,
                expected["ciphertext_sha256"].as_str().unwrap(),
                "{file}/{name} ciphertext_sha256"
            );
            assert_eq!(
                reference.plaintext_sha256,
                expected["plaintext_sha256"].as_str().unwrap(),
                "{file}/{name} plaintext_sha256"
            );
            assert_eq!(
                reference.nonce_hex,
                expected["nonce_hex"].as_str().unwrap(),
                "{file}/{name} nonce_hex"
            );
            assert_eq!(
                reference.media_type,
                expected["media_type"].as_str().unwrap(),
                "{file}/{name} media_type"
            );
            assert_eq!(
                reference.file_name,
                expected["file_name"].as_str().unwrap(),
                "{file}/{name} file_name"
            );
            assert_eq!(
                reference.source_epoch, source_epoch,
                "{file}/{name} source_epoch"
            );
            assert_eq!(
                reference.dim,
                fixture_optional(expected, "dim"),
                "{file}/{name} dim absent-vs-present-empty"
            );
            assert_eq!(
                reference.thumbhash,
                fixture_optional(expected, "thumbhash"),
                "{file}/{name} thumbhash absent-vs-present-empty"
            );
            // Exact wire round-trip through the checked outbound builder: the
            // group-version gate and locator policy accept the reference, and
            // the rebuilt tag is byte-identical to the golden fixture.
            let version = EncryptedMediaVersion::parse(&reference.version).unwrap();
            let allowed: Vec<String> = reference
                .locators
                .iter()
                .map(|locator| locator.kind.clone())
                .collect();
            let rebuilt = reference
                .build_imeta_tag(version, &allowed, false)
                .unwrap_or_else(|err| panic!("{file}/{name} must rebuild: {err}"));
            assert_eq!(rebuilt, tag, "{file}/{name} exact round-trip");
        } else {
            let err = result.expect_err(&format!("{file}/{name} must be rejected"));
            let needle = case["error_contains"].as_str().expect("error_contains");
            assert!(
                err.to_string().contains(needle),
                "{file}/{name} error must mention {needle:?}, got: {err}"
            );
        }
    }
}

#[test]
fn shared_golden_v1_fixtures_parse_validate_and_round_trip_exactly() {
    assert_shared_media_fixture_file("imeta-v1.json");
}

#[test]
fn shared_golden_v2_fixtures_parse_validate_and_round_trip_exactly() {
    assert_shared_media_fixture_file("imeta-v2.json");
}
