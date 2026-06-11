use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use cgka_engine::account_identity_proof::ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE;
use cgka_engine::key_package::key_package_metadata;
use cgka_traits::TransportEndpoint;
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION,
    STREAM_TAG,
};
use cgka_traits::engine::KeyPackage;
use marmot_account::AccountHome;
use marmot_app::{
    AccountRelayListBootstrap, AccountSetupRequest, AppMessageQuery, AuditLogSettings,
    AuditLogTrackerConfig, AuditLogUploadSource, MarmotApp, MarmotAppConfig, MarmotAppEvent,
    MarmotAppRuntime, MediaAttachmentReference, MediaLocator, MediaUploadAttachmentRequest,
    MediaUploadRequest, NotificationWakeSource, PushPlatform, RuntimeMessageUpdate,
    TimelineMessageQuery, UserDirectorySearch, UserProfileMetadata, tag_value,
};
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::Client as NostrSdkClient;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, oneshot};
use tokio::time::{Duration, sleep, timeout};
use transport_nostr_adapter::{KIND_MARMOT_KEY_PACKAGE, NostrRelayClient, NostrSdkRelayClient};
use transport_nostr_peeler::NostrTransportEvent;

const AUDIT_TRACKER_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const AUDIT_TRACKER_NON_BLOCKING_TIMEOUT: Duration = Duration::from_secs(5);

async fn mock_relay() -> (MockRelay, String) {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    (relay, url)
}

async fn mock_app(dir: &tempfile::TempDir) -> (MockRelay, MarmotApp, String) {
    let (relay, url) = mock_relay().await;
    let app = MarmotApp::with_relay(dir.path(), url.clone());
    (relay, app, url)
}

#[derive(Clone)]
struct MockBlossom {
    url: String,
    blobs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

struct CapturedAuditUpload {
    method: String,
    path: String,
    authorization: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

async fn capture_delayed_audit_upload(
    listener: TcpListener,
    tx: oneshot::Sender<CapturedAuditUpload>,
    release: oneshot::Receiver<()>,
) {
    let Ok((mut stream, _peer)) = listener.accept().await else {
        return;
    };
    let Some(captured) = read_captured_audit_upload(&mut stream).await else {
        return;
    };
    let _ = tx.send(captured);

    let _ = release.await;
    write_http_response(&mut stream, 204, "text/plain", b"").await;
}

async fn capture_delayed_audit_upload_with_overlap_probe(
    listener: TcpListener,
    tx: oneshot::Sender<CapturedAuditUpload>,
    overlap_tx: oneshot::Sender<()>,
    mut release: oneshot::Receiver<()>,
) {
    let Ok((mut stream, _peer)) = listener.accept().await else {
        return;
    };
    let Some(captured) = read_captured_audit_upload(&mut stream).await else {
        return;
    };
    let _ = tx.send(captured);

    tokio::select! {
        _ = &mut release => {
            write_http_response(&mut stream, 204, "text/plain", b"").await;
        }
        accepted = listener.accept() => {
            if let Ok((mut second, _peer)) = accepted {
                let _ = read_captured_audit_upload(&mut second).await;
                let _ = overlap_tx.send(());
                write_http_response(&mut second, 204, "text/plain", b"").await;
            }
            let _ = release.await;
            write_http_response(&mut stream, 204, "text/plain", b"").await;
        }
    }
}

async fn read_captured_audit_upload(stream: &mut TcpStream) -> Option<CapturedAuditUpload> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let read = match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => read,
        };
        request.extend_from_slice(&buffer[..read]);
        if let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
    };
    let headers = String::from_utf8_lossy(&request[..header_end]).to_string();
    let content_length = header_value(&headers, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default();
    while request.len() < header_end + content_length {
        let read = match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => read,
        };
        request.extend_from_slice(&buffer[..read]);
    }

    let request_line = headers.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let body = request[header_end..header_end + content_length].to_vec();
    Some(CapturedAuditUpload {
        method,
        path,
        authorization: header_value(&headers, "authorization"),
        content_type: header_value(&headers, "content-type"),
        body,
    })
}

impl MockBlossom {
    async fn blob(&self, hash_hex: &str) -> Option<Vec<u8>> {
        self.blobs.lock().await.get(hash_hex).cloned()
    }
}

async fn mock_blossom() -> MockBlossom {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let blobs = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
    let server_blobs = blobs.clone();
    let server_url = url.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            let blobs = server_blobs.clone();
            let server_url = server_url.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                let header_end = loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if let Some(offset) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break offset + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&request[..header_end]).to_string();
                let mut lines = headers.lines();
                let request_line = lines.next().unwrap_or_default();
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_owned();
                let path = parts.next().unwrap_or_default().to_owned();
                let mut content_length = 0_usize;
                let mut x_sha256 = None;
                let mut authorization = None;
                for line in lines {
                    let Some((name, value)) = line.split_once(':') else {
                        continue;
                    };
                    match name.to_ascii_lowercase().as_str() {
                        "content-length" => {
                            content_length = value.trim().parse().unwrap_or_default();
                        }
                        "x-sha-256" => x_sha256 = Some(value.trim().to_owned()),
                        "authorization" => authorization = Some(value.trim().to_owned()),
                        _ => {}
                    }
                }
                while request.len() < header_end + content_length {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                let body = request[header_end..header_end + content_length].to_vec();
                match (method.as_str(), path.as_str()) {
                    ("PUT", "/upload") => {
                        assert!(
                            authorization
                                .as_deref()
                                .is_some_and(|value| value.starts_with("Nostr "))
                        );
                        let encrypted_hash = hex::encode(Sha256::digest(&body));
                        assert_eq!(x_sha256.as_deref(), Some(encrypted_hash.as_str()));
                        blobs
                            .lock()
                            .await
                            .insert(encrypted_hash.clone(), body.clone());
                        let descriptor = serde_json::json!({
                            "url": format!("{server_url}/{encrypted_hash}.bin"),
                            "sha256": encrypted_hash,
                            "size": body.len(),
                            "type": "application/octet-stream",
                            "uploaded": 1_u64,
                        })
                        .to_string();
                        write_http_response(
                            &mut stream,
                            201,
                            "application/json",
                            descriptor.as_bytes(),
                        )
                        .await;
                    }
                    ("GET", blob_path) => {
                        let hash = blob_path
                            .trim_start_matches('/')
                            .split_once('.')
                            .map(|(hash, _)| hash)
                            .unwrap_or_else(|| blob_path.trim_start_matches('/'));
                        let blob = blobs.lock().await.get(hash).cloned();
                        if let Some(blob) = blob {
                            write_http_response(
                                &mut stream,
                                200,
                                "application/octet-stream",
                                &blob,
                            )
                            .await;
                        } else {
                            write_http_response(&mut stream, 404, "text/plain", b"not found").await;
                        }
                    }
                    _ => {
                        write_http_response(&mut stream, 404, "text/plain", b"not found").await;
                    }
                }
            });
        }
    });
    MockBlossom { url, blobs }
}

async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        404 => "Not Found",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
}

fn endpoint(url: &str) -> TransportEndpoint {
    TransportEndpoint(url.to_owned())
}

async fn publish_nostr_event_at(
    home: &AccountHome,
    label: &str,
    relay_url: &str,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
    created_at: u64,
) {
    let keys = home.load_signing_keys(label).unwrap();
    let mut event =
        NostrTransportEvent::new_unsigned(keys.public_key().to_hex(), kind, tags, content);
    event.created_at = created_at;
    let relay_client = NostrSdkRelayClient::new(NostrSdkClient::builder().signer(keys).build());
    relay_client
        .publish_event(&[endpoint(relay_url)], &event, 1)
        .await
        .unwrap();
}

async fn publish_account_relay_lists_at(
    home: &AccountHome,
    label: &str,
    relay_url: &str,
    declared_relay_url: &str,
    created_at: u64,
) {
    for (kind, tag_name) in [(10002, "r"), (10050, "relay")] {
        publish_nostr_event_at(
            home,
            label,
            relay_url,
            kind,
            vec![vec![tag_name.to_owned(), declared_relay_url.to_owned()]],
            String::new(),
            created_at,
        )
        .await;
    }
}

async fn publish_key_package_at(
    home: &AccountHome,
    label: &str,
    relay_url: &str,
    key_package: &KeyPackage,
    slot_id: &str,
    created_at: u64,
) {
    let account_id = home.account(label).unwrap().account_id_hex;
    let metadata = key_package_metadata(key_package).unwrap();
    publish_nostr_event_at(
        home,
        label,
        relay_url,
        KIND_MARMOT_KEY_PACKAGE,
        vec![
            vec!["d".to_owned(), slot_id.to_owned()],
            vec!["mls_protocol_version".to_owned(), "1.0".to_owned()],
            vec!["i".to_owned(), metadata.key_package_ref_hex],
            vec!["mls_ciphersuite".to_owned(), "0x0001".to_owned()],
            vec![
                "mls_extensions".to_owned(),
                "0x0006".to_owned(),
                format!("0x{ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE:04x}"),
                "0x000a".to_owned(),
            ],
            vec![
                "mls_proposals".to_owned(),
                "0x0008".to_owned(),
                "0x000a".to_owned(),
            ],
            vec![
                "app_components".to_owned(),
                "0x8006".to_owned(),
                "0x8008".to_owned(),
            ],
        ],
        BASE64_STANDARD.encode(key_package.bytes()),
        created_at,
    )
    .await;
    assert_eq!(metadata.credential_identity_hex, account_id);
}

async fn publish_follow_list_at(
    home: &AccountHome,
    label: &str,
    relay_url: &str,
    follows: &[String],
    created_at: u64,
) {
    let tags = follows
        .iter()
        .map(|follow| vec!["p".to_owned(), follow.clone()])
        .collect::<Vec<_>>();
    publish_nostr_event_at(home, label, relay_url, 3, tags, String::new(), created_at).await;
}

async fn publish_profile_at(
    home: &AccountHome,
    label: &str,
    relay_url: &str,
    name: &str,
    created_at: u64,
) {
    publish_nostr_event_at(
        home,
        label,
        relay_url,
        0,
        Vec::new(),
        serde_json::json!({ "name": name }).to_string(),
        created_at,
    )
    .await;
}

fn test_unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn assert_two_word_pseudonym(value: &str) {
    let words = value.split(' ').collect::<Vec<_>>();
    assert_eq!(words.len(), 2, "expected two words: {value}");
    for word in words {
        let mut chars = word.chars();
        assert!(
            chars.next().is_some_and(|ch| ch.is_ascii_uppercase()),
            "word should start uppercase: {word}"
        );
        assert!(
            chars.all(|ch| ch.is_ascii_lowercase()),
            "word should be title-cased ASCII: {word}"
        );
    }
}

fn sqlite_file_requires_key_for_test(path: &Path) -> bool {
    rusqlite::Connection::open(path)
        .and_then(|conn| {
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            })
        })
        .is_err()
}

#[tokio::test]
async fn app_runtime_create_identity_bootstraps_managed_account_and_key_package() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();

    assert!(created.account.local_signing);
    assert!(created.relay_lists.complete);
    assert!(created.key_package_bytes.is_some_and(|bytes| bytes > 0));
    let directory_entry = app
        .directory_entry_for_account_id(&created.account.account_id_hex)
        .unwrap()
        .expect("directory entry");
    let profile = directory_entry.profile.expect("created identity profile");
    let profile_name = profile.name.as_deref().expect("profile name");
    assert_eq!(profile.display_name.as_deref(), Some(profile_name));
    assert_two_word_pseudonym(profile_name);
    assert_eq!(
        runtime
            .accounts()
            .managed_accounts()
            .unwrap()
            .into_iter()
            .filter(|account| account.account_id_hex == created.account.account_id_hex)
            .count(),
        1
    );
    let relay_health = runtime.shared_services().relay_plane().relay_health().await;
    assert!(
        relay_health.directory_completed_fetches > 0,
        "identity setup should use the runtime shared relay plane for directory discovery"
    );

    let fetched = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();
    assert_eq!(
        fetched.key_package.bytes().len(),
        created.key_package_bytes.unwrap()
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_reuses_initial_key_package_when_republishing() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let first = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    let republished_bytes = runtime
        .publish_key_package(&created.account.account_id_hex)
        .await
        .unwrap();
    let second = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    assert_eq!(republished_bytes, first.key_package.bytes().len());
    assert_eq!(second.key_package.bytes(), first.key_package.bytes());
    assert_eq!(second.key_package_id, first.key_package_id);
    assert_eq!(second.key_package_ref_hex, first.key_package_ref_hex);
    assert!(!first.key_package_id.is_empty());
    assert!(!second.key_package_id.is_empty());
    assert!(!first.key_package_ref_hex.is_empty());
    assert!(!second.key_package_ref_hex.is_empty());
    assert!(!first.key_package_event_id.is_empty());
    assert!(!second.key_package_event_id.is_empty());

    runtime.shutdown().await;
}

#[tokio::test]
async fn key_package_fetch_rejects_future_event_and_keeps_cached_package() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let cached = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();
    let future_created_at = test_unix_now_seconds() + 600;
    publish_key_package_at(
        &home,
        &created.account.label,
        &url,
        &cached.key_package,
        "future-pin",
        future_created_at,
    )
    .await;

    let fetched = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    assert_eq!(fetched.key_package, cached.key_package);
    assert_eq!(fetched.key_package_id, cached.key_package_id);
    assert_eq!(fetched.key_package_event_id, cached.key_package_event_id);
    assert!(
        fetched.created_at < future_created_at,
        "future-dated KeyPackage should not replace cached package"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_can_rotate_key_package_on_request() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let first = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    let rotated_bytes = runtime
        .rotate_key_package(&created.account.account_id_hex)
        .await
        .unwrap();
    let rotated = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();
    runtime
        .publish_key_package(&created.account.account_id_hex)
        .await
        .unwrap();
    let republished = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    assert_eq!(rotated_bytes, rotated.key_package.bytes().len());
    assert_eq!(rotated.key_package_id, first.key_package_id);
    assert_ne!(rotated.key_package_ref_hex, first.key_package_ref_hex);
    assert_eq!(republished.key_package.bytes(), rotated.key_package.bytes());
    assert_eq!(republished.key_package_id, rotated.key_package_id);
    assert_eq!(republished.key_package_ref_hex, rotated.key_package_ref_hex);
    assert!(!rotated.key_package_id.is_empty());
    assert!(!republished.key_package_id.is_empty());
    assert!(!rotated.key_package_ref_hex.is_empty());
    assert!(!republished.key_package_ref_hex.is_empty());

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_rotate_publishes_key_package_to_nip65_outbox_relays() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("bob").unwrap();
    let (_relay, app, url) = mock_app(&dir).await;

    app.publish_account_relay_list_kind("bob", "nip65", vec![endpoint(&url)], vec![endpoint(&url)])
        .await
        .unwrap();
    let complete = app
        .publish_account_relay_list_kind("bob", "inbox", vec![endpoint(&url)], vec![endpoint(&url)])
        .await
        .unwrap();
    assert!(complete.complete);
    assert!(complete.missing.is_empty());

    let runtime = MarmotAppRuntime::new(app.clone());
    let bob = home.account("bob").unwrap().account_id_hex;
    let rotated_bytes = runtime.rotate_key_package("bob").await.unwrap();
    let fetched = app
        .fetch_latest_key_package_for_account_id(&bob, vec![endpoint(&url)])
        .await
        .unwrap();

    // KeyPackages publish to and are fetched from the account's NIP-65 outbox
    // relays; there is no dedicated KeyPackage relay list.
    assert_eq!(fetched.relay_lists.nip65.relays, vec![url]);
    assert_eq!(fetched.key_package.bytes().len(), rotated_bytes);

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_replaces_invalid_cached_key_package_when_republishing() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let cache_path = dir
        .path()
        .join("key-packages")
        .join(format!("{}.json", created.account.label));
    std::fs::write(
        &cache_path,
        serde_json::json!({
            "account_label": created.account.label,
            "account_id_hex": created.account.account_id_hex,
            "key_package_id": "legacy-invalid",
            "key_package_hex": "010203",
        })
        .to_string(),
    )
    .unwrap();

    let republished_bytes = runtime
        .publish_key_package(&created.account.account_id_hex)
        .await
        .unwrap();
    let cache: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();

    assert!(republished_bytes > 3);
    assert_ne!(cache["key_package_id"], "legacy-invalid");
    assert_ne!(cache["key_package_hex"], "010203");

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_executes_group_and_message_intents_on_managed_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "runtime intents",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined_group, .. }
                if account_id_hex == &bob_id && joined_group == &group_id
        )
    })
    .await;

    runtime
        .send_message(
            &alice.account.account_id_hex,
            &group_id,
            b"hello through runtime intents".to_vec(),
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "hello through runtime intents"
        )
    })
    .await;

    let stream_id = [0x44; 32];
    runtime
        .start_agent_text_stream(
            &alice.account.account_id_hex,
            &group_id,
            &stream_id,
            123,
            vec!["quic://127.0.0.1:4450".to_owned()],
        )
        .await
        .unwrap();
    let stream_event = wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::AgentStreamStarted(stream)
                if stream.account_id_hex == bob_id
                    && stream.message.group_id == group_id
                    && stream.message.kind == cgka_traits::MARMOT_APP_EVENT_KIND_AGENT_STREAM_START
                    && tag_value(&stream.message.tags, STREAM_TAG)
                        == Some(hex::encode(stream_id).as_str())
        )
    })
    .await;
    let MarmotAppEvent::AgentStreamStarted(stream_event) = stream_event else {
        panic!("expected agent stream start event");
    };
    let group_id_hex = hex::encode(group_id.as_slice());
    let stream_id_hex = hex::encode(stream_id);
    let stream_crypto = runtime
        .agent_text_stream_crypto_for_start_event(
            Some(&bob.account.account_id_hex),
            Some(group_id_hex.as_str()),
            Some(stream_id_hex.as_str()),
            &stream_event.message.message_id_hex,
        )
        .await
        .unwrap();
    assert_eq!(stream_crypto.account_id_hex, bob.account.account_id_hex);
    assert_eq!(stream_crypto.group_id, group_id);
    assert_eq!(stream_crypto.stream_id, stream_id.to_vec());

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_schedules_audit_tracker_update_after_managed_send() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "runtime audit tracker",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let server = tokio::spawn(capture_delayed_audit_upload(listener, tx, release_rx));
    runtime
        .set_audit_log_tracker_config(AuditLogTrackerConfig {
            endpoint: Some(format!("http://{addr}/api/v1/audit-logs/")),
            authorization_bearer_token: Some("goggles_runtime_secret".to_owned()),
            source: AuditLogUploadSource {
                account_label: Some("Alice".to_owned()),
                device_label: Some("Alice iPhone".to_owned()),
                platform: Some("ios".to_owned()),
                app_version: Some("2026.6.8".to_owned()),
            },
        })
        .unwrap();

    let send_runtime = runtime.clone();
    let send_account = alice.account.account_id_hex.clone();
    let send_group_id = group_id.clone();
    let send = tokio::spawn(async move {
        send_runtime
            .send_message(
                &send_account,
                &send_group_id,
                b"send should not wait for audit tracker".to_vec(),
            )
            .await
    });

    let captured = timeout(AUDIT_TRACKER_REQUEST_TIMEOUT, rx)
        .await
        .expect("audit tracker should receive background upload")
        .unwrap();
    timeout(AUDIT_TRACKER_NON_BLOCKING_TIMEOUT, send)
        .await
        .expect("send should finish before tracker response is released")
        .unwrap()
        .unwrap();

    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/api/v1/audit-logs/");
    assert_eq!(
        captured.authorization.as_deref(),
        Some("Bearer goggles_runtime_secret")
    );
    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/x-ndjson")
    );
    assert!(!captured.body.is_empty());

    let _ = release_tx.send(());
    server.await.unwrap();
    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_schedules_audit_tracker_update_after_create_group_welcome() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let server = tokio::spawn(capture_delayed_audit_upload(listener, tx, release_rx));
    runtime
        .set_audit_log_tracker_config(AuditLogTrackerConfig {
            endpoint: Some(format!("http://{addr}/api/v1/audit-logs/")),
            authorization_bearer_token: Some("goggles_welcome_secret".to_owned()),
            source: AuditLogUploadSource::default(),
        })
        .unwrap();

    let create_runtime = runtime.clone();
    let create_account = alice.account.account_id_hex.clone();
    let members = vec![bob.account.account_id_hex.clone()];
    let create = tokio::spawn(async move {
        create_runtime
            .create_group(&create_account, "runtime audit welcome", &members, None)
            .await
    });

    let captured = timeout(AUDIT_TRACKER_REQUEST_TIMEOUT, rx)
        .await
        .expect("audit tracker should receive welcome-triggered upload")
        .unwrap();
    timeout(AUDIT_TRACKER_NON_BLOCKING_TIMEOUT, create)
        .await
        .expect("create_group should finish before tracker response is released")
        .unwrap()
        .unwrap();

    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/api/v1/audit-logs/");
    assert_eq!(
        captured.authorization.as_deref(),
        Some("Bearer goggles_welcome_secret")
    );
    assert!(!captured.body.is_empty());

    let _ = release_tx.send(());
    server.await.unwrap();
    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_schedules_audit_tracker_update_after_inbound_welcome() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let bob_id = home.account("bob").unwrap().account_id_hex;

    let (_relay, app, _url) = mock_app(&dir).await;
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let mut bob_setup = app.client("bob").await.unwrap();
    bob_setup.publish_key_package().await.unwrap();
    drop(bob_setup);

    let runtime = MarmotAppRuntime::new(app.clone());
    let mut events = runtime.subscribe();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let server = tokio::spawn(capture_delayed_audit_upload(listener, tx, release_rx));
    runtime
        .set_audit_log_tracker_config(AuditLogTrackerConfig {
            endpoint: Some(format!("http://{addr}/api/v1/audit-logs/")),
            authorization_bearer_token: Some("goggles_inbound_secret".to_owned()),
            source: AuditLogUploadSource::default(),
        })
        .unwrap();
    runtime.start().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice
        .create_group("runtime inbound audit", &["bob"])
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined_group, .. }
                if account_id_hex == &bob_id && joined_group == &group_id
        )
    })
    .await;

    let captured = timeout(Duration::from_secs(5), rx)
        .await
        .expect("audit tracker should receive inbound-triggered upload")
        .unwrap();
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/api/v1/audit-logs/");
    assert_eq!(
        captured.authorization.as_deref(),
        Some("Bearer goggles_inbound_secret")
    );
    assert!(!captured.body.is_empty());

    let _ = release_tx.send(());
    server.await.unwrap();
    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_coalesces_audit_tracker_updates_while_upload_is_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "runtime audit coalesce",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let (overlap_tx, overlap_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let server = tokio::spawn(capture_delayed_audit_upload_with_overlap_probe(
        listener, tx, overlap_tx, release_rx,
    ));
    runtime
        .set_audit_log_tracker_config(AuditLogTrackerConfig {
            endpoint: Some(format!("http://{addr}/api/v1/audit-logs/")),
            authorization_bearer_token: Some("goggles_coalesce_secret".to_owned()),
            source: AuditLogUploadSource::default(),
        })
        .unwrap();

    runtime
        .send_message(
            &alice.account.account_id_hex,
            &group_id,
            b"first upload remains in flight".to_vec(),
        )
        .await
        .unwrap();
    let captured = timeout(AUDIT_TRACKER_REQUEST_TIMEOUT, rx)
        .await
        .expect("audit tracker should receive the first upload")
        .unwrap();
    assert_eq!(captured.method, "POST");

    runtime
        .send_message(
            &alice.account.account_id_hex,
            &group_id,
            b"second trigger should coalesce".to_vec(),
        )
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_secs(1), overlap_rx).await.is_err(),
        "audit tracker uploader should not start an overlapping upload"
    );

    let _ = release_tx.send(());
    server.await.unwrap();
    runtime.shutdown().await;
}

#[tokio::test]
async fn push_registration_settings_accept_apns_fcm_and_redact_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let account = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap()
        .account;
    let server_pubkey = nostr::Keys::generate().public_key().to_hex();

    let settings = app
        .set_local_notifications_enabled(&account.account_id_hex, true)
        .unwrap();
    assert!(settings.local_notifications_enabled);
    assert!(!settings.native_push_enabled);

    let apns = app
        .upsert_push_registration(
            &account.account_id_hex,
            PushPlatform::Apns,
            "00aaff",
            &server_pubkey,
            Some(url.clone()),
        )
        .unwrap();
    assert_eq!(apns.platform, PushPlatform::Apns);
    assert!(apns.token_fingerprint.starts_with("sha256:"));
    assert!(!format!("{apns:?}").contains("00aaff"));

    let fcm = app
        .upsert_push_registration(
            &account.account_id_hex,
            PushPlatform::Fcm,
            "opaque-fcm-registration-token",
            &server_pubkey,
            Some(url),
        )
        .unwrap();
    assert_eq!(fcm.platform, PushPlatform::Fcm);
    assert!(!format!("{fcm:?}").contains("opaque-fcm-registration-token"));
    assert_eq!(
        app.push_registration(&account.account_id_hex)
            .unwrap()
            .unwrap()
            .token_fingerprint,
        fcm.token_fingerprint
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn push_token_gossip_register_replace_and_remove_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "push lifecycle",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    let server_pubkey = nostr::Keys::generate().public_key().to_hex();

    app.set_native_push_enabled(&bob.account.account_id_hex, true)
        .unwrap();
    let first = app
        .upsert_push_registration(
            &bob.account.account_id_hex,
            PushPlatform::Fcm,
            "first-fcm-token",
            &server_pubkey,
            Some(url.clone()),
        )
        .unwrap();
    runtime
        .share_push_registration(&bob.account.account_id_hex)
        .await
        .unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let alice_view = runtime
        .group_push_debug_info(&alice.account.account_id_hex, &group_id)
        .await
        .unwrap();
    assert_eq!(alice_view.active_token_count, 1);
    assert_eq!(
        alice_view.tokens[0].token_fingerprint,
        first.token_fingerprint
    );

    let second = app
        .upsert_push_registration(
            &bob.account.account_id_hex,
            PushPlatform::Fcm,
            "second-fcm-token",
            &server_pubkey,
            Some(url),
        )
        .unwrap();
    runtime
        .share_push_registration(&bob.account.account_id_hex)
        .await
        .unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let alice_view = runtime
        .group_push_debug_info(&alice.account.account_id_hex, &group_id)
        .await
        .unwrap();
    assert_eq!(alice_view.active_token_count, 1);
    assert_eq!(
        alice_view.tokens[0].token_fingerprint,
        second.token_fingerprint
    );

    runtime
        .remove_push_registration(&bob.account.account_id_hex, second)
        .await
        .unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let alice_view = runtime
        .group_push_debug_info(&alice.account.account_id_hex, &group_id)
        .await
        .unwrap();
    assert_eq!(alice_view.active_token_count, 0);

    runtime.shutdown().await;
}

#[tokio::test]
async fn removed_member_triggers_local_push_token_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup.clone()).await.unwrap();
    let carol = runtime.create_identity(setup).await.unwrap();
    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "removal cleanup",
            &[
                bob.account.account_id_hex.clone(),
                carol.account.account_id_hex.clone(),
            ],
            None,
        )
        .await
        .unwrap();
    let server_pubkey = nostr::Keys::generate().public_key().to_hex();

    for member in [&bob, &carol] {
        app.set_native_push_enabled(&member.account.account_id_hex, true)
            .unwrap();
        app.upsert_push_registration(
            &member.account.account_id_hex,
            PushPlatform::Fcm,
            &format!("token-{}", &member.account.account_id_hex[..8]),
            &server_pubkey,
            Some(url.clone()),
        )
        .unwrap();
        runtime
            .share_push_registration(&member.account.account_id_hex)
            .await
            .unwrap();
    }
    runtime.catch_up_accounts().await.unwrap();

    let bob_view_before = runtime
        .group_push_debug_info(&bob.account.account_id_hex, &group_id)
        .await
        .unwrap();
    assert!(
        bob_view_before
            .tokens
            .iter()
            .any(|t| t.member_id_hex == carol.account.account_id_hex),
        "bob should see carol's token before removal"
    );

    runtime
        .remove_members(
            &alice.account.account_id_hex,
            &group_id,
            std::slice::from_ref(&carol.account.account_id_hex),
        )
        .await
        .unwrap();
    runtime.catch_up_accounts().await.unwrap();

    let bob_view_after = runtime
        .group_push_debug_info(&bob.account.account_id_hex, &group_id)
        .await
        .unwrap();
    assert!(
        bob_view_after
            .tokens
            .iter()
            .all(|t| t.member_id_hex != carol.account.account_id_hex),
        "MemberRemoved engine event should drop carol's tokens from bob's projection"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn concurrent_wake_collection_and_foreground_subscription_share_notification_key() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "concurrent wake",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();

    app.set_local_notifications_enabled(&bob.account.account_id_hex, true)
        .unwrap();
    runtime.catch_up_accounts().await.unwrap();

    let mut subscription = runtime.subscribe_notifications().unwrap();
    let bob_ref = bob.account.account_id_hex.clone();

    let runtime_for_wake = runtime.clone();
    let wake_handle = tokio::spawn(async move {
        runtime_for_wake
            .collect_notifications_after_wake(8_000, NotificationWakeSource::ApnsNse)
            .await
    });
    tokio::time::sleep(Duration::from_millis(250)).await;

    runtime
        .send_message(
            &alice.account.account_id_hex,
            &group_id,
            b"hello over both consumers".to_vec(),
        )
        .await
        .unwrap();

    let wake = wake_handle.await.unwrap();
    let mut subscription_updates = Vec::new();
    let drain_deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < drain_deadline {
        match timeout(Duration::from_millis(250), subscription.recv()).await {
            Ok(Some(update)) => subscription_updates.push(update),
            Ok(None) => break,
            Err(_) if !subscription_updates.is_empty() => break,
            Err(_) => continue,
        }
    }

    let wake_keys: Vec<String> = wake
        .notifications
        .iter()
        .filter(|update| update.account_ref == bob_ref)
        .map(|update| update.notification_key.clone())
        .collect();
    let sub_keys: Vec<String> = subscription_updates
        .iter()
        .filter(|update| update.account_ref == bob_ref)
        .map(|update| update.notification_key.clone())
        .collect();
    assert!(
        !wake_keys.is_empty(),
        "wake collection should produce at least one update"
    );
    assert!(
        !sub_keys.is_empty(),
        "subscription should produce at least one update"
    );
    let wake_unique: std::collections::HashSet<_> = wake_keys.iter().cloned().collect();
    assert_eq!(
        wake_unique.len(),
        wake_keys.len(),
        "wake collection must dedup updates by notification_key within a single call"
    );
    let sub_unique: std::collections::HashSet<_> = sub_keys.iter().cloned().collect();
    let common = wake_unique.intersection(&sub_unique).count();
    assert!(
        common > 0,
        "at least one notification_key must appear in both consumers (stable identity across wake + subscription)"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn message_send_succeeds_when_notification_trigger_publish_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "push failure",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    let server_pubkey = nostr::Keys::generate().public_key().to_hex();

    app.set_native_push_enabled(&bob.account.account_id_hex, true)
        .unwrap();
    app.upsert_push_registration(
        &bob.account.account_id_hex,
        PushPlatform::Fcm,
        "failing-relay-token",
        &server_pubkey,
        Some("not-a-relay-url".to_owned()),
    )
    .unwrap();
    runtime
        .share_push_registration(&bob.account.account_id_hex)
        .await
        .unwrap();
    runtime.catch_up_accounts().await.unwrap();

    let summary = runtime
        .send_message(
            &alice.account.account_id_hex,
            &group_id,
            b"delivery must not depend on push".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(summary.published, 1);
    assert_eq!(summary.message_ids.len(), 1);

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_marks_welcome_joined_groups_pending_until_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let bob_id = bob.account.account_id_hex.clone();
    let bob_label = bob.account.label.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "pending invite",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined_group, .. }
                if account_id_hex == &bob_id && joined_group == &group_id
        )
    })
    .await;

    let group_id_hex = hex::encode(group_id.as_slice());
    let pending = app.group(&bob_label, &group_id_hex).unwrap().unwrap();
    assert!(pending.pending_confirmation);
    assert!(!pending.archived);
    assert!(pending.via_welcome_message_id_hex.is_some());
    assert_eq!(
        pending.welcomer_account_id_hex.as_deref(),
        Some(alice.account.account_id_hex.as_str())
    );

    let accepted = runtime
        .accept_group_invite(&bob.account.account_id_hex, &group_id)
        .await
        .unwrap();
    assert!(!accepted.pending_confirmation);
    assert!(!accepted.archived);

    let reloaded = app.group(&bob_label, &group_id_hex).unwrap().unwrap();
    assert!(!reloaded.pending_confirmation);
    assert!(!reloaded.archived);

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_declines_pending_invite_by_leaving_and_archiving() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let bob_id = bob.account.account_id_hex.clone();
    let bob_label = bob.account.label.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "declined invite",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined_group, .. }
                if account_id_hex == &bob_id && joined_group == &group_id
        )
    })
    .await;

    let group_id_hex = hex::encode(group_id.as_slice());
    let pending = app.group(&bob_label, &group_id_hex).unwrap().unwrap();
    assert!(pending.pending_confirmation);

    let declined = runtime
        .decline_group_invite(&bob.account.account_id_hex, &group_id)
        .await
        .unwrap();
    assert_eq!(declined.summary.published, 1);
    assert!(!declined.group.pending_confirmation);
    assert!(declined.group.archived);

    let reloaded = app.group(&bob_label, &group_id_hex).unwrap().unwrap();
    assert!(!reloaded.pending_confirmation);
    assert!(reloaded.archived);
    assert!(
        !app.visible_groups(&bob_label)
            .unwrap()
            .iter()
            .any(|group| group.group_id_hex == group_id_hex)
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_emits_live_messages_for_local_accounts_without_manual_sync() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let bob_id = home.account("bob").unwrap().account_id_hex;

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob_setup = app.client("bob").await.unwrap();
    bob_setup.publish_key_package().await.unwrap();
    drop(bob_setup);

    let runtime = MarmotAppRuntime::new(app.clone());
    let mut events = runtime.subscribe();
    runtime.start().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("live", &["bob"]).await.unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined_group, .. }
                if account_id_hex == &bob_id && joined_group == &group_id
        )
    })
    .await;

    alice
        .send(&group_id, b"hello through the app runtime")
        .await
        .unwrap();
    let received = wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "hello through the app runtime"
        )
    })
    .await;

    assert!(matches!(received, MarmotAppEvent::MessageReceived(_)));
    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_starts_directory_subscriptions_for_known_users() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app);
    runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();

    runtime.start().await.unwrap();

    let health = runtime.shared_services().relay_plane().relay_health().await;
    assert_eq!(health.directory_active_subscriptions, 1);
    assert_eq!(health.directory_completed_subscription_syncs, 1);
    runtime.shutdown().await;
}

#[tokio::test]
async fn directory_sync_worker_ingests_profile_metadata_events() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();

    runtime.start().await.unwrap();
    publish_profile_at(
        &AccountHome::open(dir.path()),
        &setup.account.label,
        &url,
        "sync-alice",
        test_unix_now_seconds(),
    )
    .await;

    timeout(Duration::from_secs(5), async {
        loop {
            let name = app
                .directory_entry_for_account_id(&setup.account.account_id_hex)
                .unwrap()
                .and_then(|entry| entry.profile)
                .and_then(|profile| profile.name);
            if name.as_deref() == Some("sync-alice") {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("directory profile ingested");
    runtime.shutdown().await;
}

#[tokio::test]
async fn directory_sync_worker_admits_follow_list_users() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let followed = format!("{:064x}", 77);

    runtime.start().await.unwrap();
    publish_follow_list_at(
        &AccountHome::open(dir.path()),
        &setup.account.label,
        &url,
        std::slice::from_ref(&followed),
        test_unix_now_seconds(),
    )
    .await;

    timeout(Duration::from_secs(5), async {
        loop {
            if app
                .directory_entry_for_account_id(&followed)
                .unwrap()
                .is_some()
            {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("followed user admitted");
    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_message_subscription_returns_snapshot_then_live_updates() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "message subscriptions",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined_group, .. }
                if account_id_hex == &bob_id && joined_group == &group_id
        )
    })
    .await;

    runtime
        .send_message(
            &alice.account.account_id_hex,
            &group_id,
            b"already projected".to_vec(),
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "already projected"
        )
    })
    .await;

    let group_id_hex = hex::encode(group_id.as_slice());
    let mut subscription = runtime
        .subscribe_messages(
            &bob.account.account_id_hex,
            AppMessageQuery {
                group_id_hex: Some(group_id_hex),
                limit: Some(10),
            },
        )
        .unwrap();
    assert_eq!(subscription.snapshot.len(), 1);
    assert_eq!(subscription.snapshot[0].plaintext, "already projected");

    runtime
        .send_message(
            &alice.account.account_id_hex,
            &group_id,
            b"live through runtime subscription".to_vec(),
        )
        .await
        .unwrap();
    let update = wait_for_message_update(&mut subscription, |update| {
        matches!(
            update,
            RuntimeMessageUpdate::Message(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "live through runtime subscription"
        )
    })
    .await;
    assert!(matches!(update, RuntimeMessageUpdate::Message(_)));

    runtime.shutdown().await;
}

async fn wait_for_event<F>(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    mut matches_event: F,
) -> MarmotAppEvent
where
    F: FnMut(&MarmotAppEvent) -> bool,
{
    timeout(Duration::from_secs(5), async {
        loop {
            let event = events.recv().await.unwrap();
            if matches_event(&event) {
                return event;
            }
        }
    })
    .await
    .expect("runtime event")
}

async fn wait_for_message_update<F>(
    subscription: &mut marmot_app::RuntimeMessagesSubscription,
    mut matches_update: F,
) -> RuntimeMessageUpdate
where
    F: FnMut(&RuntimeMessageUpdate) -> bool,
{
    timeout(Duration::from_secs(5), async {
        loop {
            let update = subscription.recv().await.expect("message update");
            if matches_update(&update) {
                return update;
            }
        }
    })
    .await
    .expect("runtime message update")
}

async fn wait_for_timeline_update<F>(
    subscription: &mut marmot_app::RuntimeTimelineMessagesSubscription,
    mut matches_update: F,
) -> marmot_app::RuntimeTimelineMessageUpdate
where
    F: FnMut(&marmot_app::RuntimeTimelineMessageUpdate) -> bool,
{
    timeout(Duration::from_secs(5), async {
        loop {
            let update = subscription.recv().await.expect("timeline update");
            if matches_update(&update) {
                return update;
            }
        }
    })
    .await
    .expect("runtime timeline update")
}

#[tokio::test]
async fn app_runtime_chat_and_group_state_subscriptions_stream_projection_updates() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();

    let mut bob_chats = runtime
        .subscribe_chats(&bob.account.account_id_hex, false)
        .unwrap();
    assert!(bob_chats.snapshot.is_empty());

    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "runtime chats",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let chat = wait_for_chat_update(&mut bob_chats, |chat| chat.group_id_hex == group_id_hex).await;
    assert_eq!(chat.profile.name, "runtime chats");

    let mut group_state = runtime
        .subscribe_group_state(&bob.account.account_id_hex, &group_id_hex)
        .unwrap();
    assert_eq!(group_state.snapshot.group_id_hex, group_id_hex);

    runtime
        .update_group_profile(
            &alice.account.account_id_hex,
            &group_id,
            Some("renamed runtime chat".to_owned()),
            None,
        )
        .await
        .unwrap();
    let updated = wait_for_group_state_update(&mut group_state, |group| {
        group.profile.name == "renamed runtime chat"
    })
    .await;
    assert_eq!(updated.group_id_hex, group_id_hex);

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_timeline_subscription_reopen_keeps_local_sent_message() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();

    let group_id = runtime
        .create_group(
            &alice_id,
            "runtime timeline",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let query = TimelineMessageQuery {
        group_id_hex: Some(group_id_hex.clone()),
        ..TimelineMessageQuery::default()
    };
    let mut timeline = runtime
        .subscribe_timeline_messages(&alice_id, query.clone())
        .unwrap();
    assert!(timeline.snapshot.messages.is_empty());

    runtime
        .send_message(&alice_id, &group_id, b"persist through reopen".to_vec())
        .await
        .unwrap();
    let update = wait_for_timeline_update(&mut timeline, |update| {
        matches!(
            update,
            marmot_app::RuntimeTimelineMessageUpdate::Projection(projection)
                if projection.update.timeline_messages.iter().any(|message| {
                    message.direction == "sent" && message.plaintext == "persist through reopen"
                })
        )
    })
    .await;
    assert!(matches!(
        update,
        marmot_app::RuntimeTimelineMessageUpdate::Projection(_)
    ));
    drop(timeline);

    let reopened = runtime
        .subscribe_timeline_messages(&alice_id, query)
        .unwrap();
    assert_eq!(reopened.snapshot.messages.len(), 1);
    assert_eq!(reopened.snapshot.messages[0].direction, "sent");
    assert_eq!(reopened.snapshot.messages[0].sender, alice_id);
    assert_eq!(
        reopened.snapshot.messages[0].plaintext,
        "persist through reopen"
    );

    runtime.shutdown().await;
}

async fn wait_for_chat_update<F>(
    subscription: &mut marmot_app::RuntimeChatsSubscription,
    mut matches_update: F,
) -> marmot_app::AppGroupRecord
where
    F: FnMut(&marmot_app::AppGroupRecord) -> bool,
{
    timeout(Duration::from_secs(5), async {
        loop {
            let update = subscription.recv().await.expect("chat update");
            if matches_update(&update) {
                return update;
            }
        }
    })
    .await
    .expect("runtime chat update")
}

async fn wait_for_group_state_update<F>(
    subscription: &mut marmot_app::RuntimeGroupStateSubscription,
    mut matches_update: F,
) -> marmot_app::AppGroupRecord
where
    F: FnMut(&marmot_app::AppGroupRecord) -> bool,
{
    timeout(Duration::from_secs(5), async {
        loop {
            let update = subscription.recv().await.expect("group state update");
            if matches_update(&update) {
                return update;
            }
        }
    })
    .await
    .expect("runtime group state update")
}

#[tokio::test]
async fn relay_app_runtime_exchanges_messages_without_lab() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let alice_id = home.account("alice").unwrap().account_id_hex;

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("general", &["bob"]).await.unwrap();

    let joined = bob.sync().await.unwrap();
    assert_eq!(joined.joined_groups, vec![group_id.clone()]);

    alice
        .send(&group_id, b"hello from app runtime")
        .await
        .unwrap();

    let received = bob.sync().await.unwrap();
    assert_eq!(received.messages.len(), 1);
    assert_eq!(received.messages[0].sender, alice_id);
    assert_eq!(
        received.messages[0].sender_display_name.as_deref(),
        Some("alice")
    );
    assert_eq!(received.messages[0].group_id, group_id);
    assert_eq!(received.messages[0].plaintext, "hello from app runtime");
}

#[tokio::test]
async fn relay_app_runtime_publishes_member_leave() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("departures", &["bob"]).await.unwrap();
    bob.sync().await.unwrap();

    let leave = bob.leave_group(&group_id).await.unwrap();
    assert_eq!(leave.published, 1);

    let alice_sync = alice.sync().await.unwrap();
    assert!(alice_sync.events.iter().any(|event| matches!(
        event,
        cgka_traits::GroupEvent::GroupStateChanged {
            group_id: removed_group,
            change:
                cgka_traits::GroupStateChange::MemberRemoved { .. }
                | cgka_traits::GroupStateChange::MemberLeft { .. },
            ..
        } if removed_group == &group_id
    )));

    // The authenticated departure is synthesized into alice's timeline as a
    // durable kind-1210 group system row (no kind-1210 message is sent).
    let alice_timeline = MarmotApp::with_relay(dir.path(), url)
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group_id.as_slice())),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    let has_departure_row = alice_timeline.messages.iter().any(|message| {
        message.kind == cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
            && (message.plaintext.contains("member_left")
                || message.plaintext.contains("member_removed"))
    });
    assert!(
        has_departure_row,
        "alice's timeline should contain a kind-1210 departure row; got {:?}",
        alice_timeline.messages
    );
}

#[tokio::test]
async fn relay_app_runtime_synthesizes_system_row_for_own_invite() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    home.create_account("carol").unwrap();

    let (_relay, app, url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();
    let mut carol = app.client("carol").await.unwrap();
    carol.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("ops", &["bob"]).await.unwrap();

    // Own action: alice invites carol post-creation. The confirmed commit
    // synthesizes a kind-1210 member_added row in alice's own timeline.
    alice.invite_members(&group_id, &["carol"]).await.unwrap();

    let alice_timeline = MarmotApp::with_relay(dir.path(), url)
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group_id.as_slice())),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    let has_added_row = alice_timeline.messages.iter().any(|message| {
        message.kind == cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
            && message.plaintext.contains("member_added")
    });
    assert!(
        has_added_row,
        "alice's own invite should synthesize a member_added row; got {:?}",
        alice_timeline.messages
    );
}

#[tokio::test]
async fn relay_app_runtime_synthesizes_rows_for_multi_member_invite() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    home.create_account("carol").unwrap();
    home.create_account("dave").unwrap();

    let (_relay, app, url) = mock_app(&dir).await;
    for label in ["bob", "carol", "dave"] {
        let mut client = app.client(label).await.unwrap();
        client.publish_key_package().await.unwrap();
    }

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("ops", &["bob"]).await.unwrap();

    // One commit invites two members, so two member_added rows must both persist
    // — previously they collided on the unique source index and one was dropped.
    alice
        .invite_members(&group_id, &["carol", "dave"])
        .await
        .unwrap();

    let alice_timeline = MarmotApp::with_relay(dir.path(), url)
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group_id.as_slice())),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    let added_rows = alice_timeline
        .messages
        .iter()
        .filter(|message| {
            message.kind == cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
                && message.plaintext.contains("member_added")
        })
        .count();
    assert_eq!(
        added_rows, 2,
        "both invited members should get a row; got {:?}",
        alice_timeline.messages
    );
}

#[tokio::test]
async fn relay_app_runtime_projects_typed_reactions_and_deletes() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("updates", &["bob"]).await.unwrap();
    bob.sync().await.unwrap();

    let sent = alice
        .send(&group_id, b"message with lifecycle")
        .await
        .unwrap();
    let target_message_id = sent.message_ids[0].clone();
    bob.sync().await.unwrap();

    bob.react_to_message(&group_id, &target_message_id, "+")
        .await
        .unwrap();
    let reaction = alice.sync().await.unwrap();
    assert_eq!(reaction.messages.len(), 1);
    // A reaction is a kind-7 event whose content is the emoji and whose `e` tag
    // references the reacted-to message.
    assert_eq!(reaction.messages[0].plaintext, "+");
    assert_eq!(reaction.messages[0].kind, MARMOT_APP_EVENT_KIND_REACTION);
    assert_eq!(
        tag_value(&reaction.messages[0].tags, "e"),
        Some(target_message_id.as_str())
    );

    let empty_reaction = bob
        .react_to_message(&group_id, &target_message_id, "")
        .await
        .unwrap_err();
    assert!(empty_reaction.to_string().contains("non-empty emoji"));

    bob.delete_message(&group_id, &target_message_id)
        .await
        .unwrap();
    let deletion = alice.sync().await.unwrap();
    // A delete is a kind-5 tombstone with empty content and an `e` tag.
    assert_eq!(deletion.messages[0].plaintext, "");
    assert_eq!(deletion.messages[0].kind, MARMOT_APP_EVENT_KIND_DELETE);
    assert_eq!(
        tag_value(&deletion.messages[0].tags, "e"),
        Some(target_message_id.as_str())
    );

    bob.send_media_attachments(
        &group_id,
        vec![
            MediaAttachmentReference {
                locators: vec![MediaLocator {
                    kind: "blossom-v1".to_owned(),
                    value: "https://media.example/diagram.png".to_owned(),
                }],
                ciphertext_sha256: hex::encode([0x11_u8; 32]),
                plaintext_sha256: hex::encode([0x42_u8; 32]),
                nonce_hex: hex::encode([0x24_u8; 12]),
                file_name: "diagram.png".to_owned(),
                media_type: "image/png".to_owned(),
                version: "encrypted-media-v1".to_owned(),
                source_epoch: 0,
                dim: Some("800x600".to_owned()),
                thumbhash: Some("1QcSHQRnh493V4dIh4eXh1h4kJUI".to_owned()),
            },
            MediaAttachmentReference {
                locators: vec![MediaLocator {
                    kind: "blossom-v1".to_owned(),
                    value: "https://media.example/audio.ogg".to_owned(),
                }],
                ciphertext_sha256: hex::encode([0x12_u8; 32]),
                plaintext_sha256: hex::encode([0x43_u8; 32]),
                nonce_hex: hex::encode([0x25_u8; 12]),
                file_name: "audio.ogg".to_owned(),
                media_type: "audio/ogg".to_owned(),
                version: "encrypted-media-v1".to_owned(),
                source_epoch: 0,
                dim: None,
                thumbhash: None,
            },
        ],
        Some("launch diagram".to_owned()),
    )
    .await
    .unwrap();
    let media = alice.sync().await.unwrap();
    // Media is a kind-9 chat: content is the caption, attachment is an `imeta`.
    assert_eq!(media.messages[0].plaintext, "launch diagram");
    assert_eq!(media.messages[0].kind, MARMOT_APP_EVENT_KIND_CHAT);
    let imeta_tags: Vec<_> = media.messages[0]
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .collect();
    assert_eq!(imeta_tags.len(), 2);
    let imeta = imeta_tags[0];
    assert!(
        imeta
            .iter()
            .any(|field| field == "locator blossom-v1 https://media.example/diagram.png")
    );
    assert!(imeta.iter().any(|field| field == "m image/png"));
    assert!(imeta.iter().any(|field| field == "filename diagram.png"));
    assert!(
        imeta
            .iter()
            .any(|field| field == "nonce 242424242424242424242424")
    );
    assert!(imeta.iter().any(|field| field == "v encrypted-media-v1"));
    assert!(imeta.iter().any(|field| field.starts_with("thumbhash ")));
    assert!(imeta.iter().all(|field| !field.starts_with("blurhash ")));
    assert!(
        imeta_tags[1]
            .iter()
            .any(|field| field == "filename audio.ogg")
    );

    let bad_media = bob
        .send_media_attachments(
            &group_id,
            vec![MediaAttachmentReference {
                locators: vec![MediaLocator {
                    kind: "blossom-v1".to_owned(),
                    value: "https://media.example/diagram.png".to_owned(),
                }],
                ciphertext_sha256: hex::encode([0x11_u8; 32]),
                plaintext_sha256: "not-hex".to_owned(),
                nonce_hex: hex::encode([0x24_u8; 12]),
                file_name: "diagram.png".to_owned(),
                media_type: "image/png".to_owned(),
                version: "encrypted-media-v1".to_owned(),
                source_epoch: 0,
                dim: None,
                thumbhash: None,
            }],
            None,
        )
        .await
        .unwrap_err();
    assert!(bad_media.to_string().contains("media plaintext_sha256"));
}

#[tokio::test]
async fn relay_app_runtime_creates_default_agent_text_stream_group() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let alice_id = home.account("alice").unwrap().account_id_hex;

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("agent", &["bob"]).await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());

    let alice_group = app.group("alice", &group_id_hex).unwrap().unwrap();
    assert!(alice_group.agent_text_stream.required);
    assert_eq!(alice_group.agent_text_stream.component_id, 0x8006);
    assert_eq!(
        alice_group.agent_text_stream.component,
        "marmot.group.agent-text-stream.quic.v1"
    );
    assert_eq!(
        alice_group.agent_text_stream.required_member_roles,
        vec!["receive".to_owned()]
    );
    assert_eq!(
        alice_group.agent_text_stream.allowed_member_roles,
        vec!["receive".to_owned(), "send".to_owned()]
    );
    assert_eq!(
        alice_group.agent_text_stream.data_hex,
        "010300001000000000000000"
    );

    bob.sync().await.unwrap();
    let bob_group = app.group("bob", &group_id_hex).unwrap().unwrap();
    assert!(bob_group.agent_text_stream.required);

    alice.send(&group_id, b"write a summary").await.unwrap();
    let prompt = bob.sync().await.unwrap();
    assert_eq!(prompt.messages.len(), 1);
    assert_eq!(prompt.messages[0].sender, alice_id);
    assert_eq!(
        prompt.messages[0].sender_display_name.as_deref(),
        Some("alice")
    );
    assert_eq!(prompt.messages[0].plaintext, "write a summary");

    let alice_secret = alice.agent_text_stream_exporter_secret(&group_id).unwrap();
    let bob_secret = bob.agent_text_stream_exporter_secret(&group_id).unwrap();
    let repeated_alice_secret = alice.agent_text_stream_exporter_secret(&group_id).unwrap();

    assert_eq!(alice_secret, bob_secret);
    assert_eq!(alice_secret, repeated_alice_secret);
}

#[tokio::test]
async fn encrypted_media_upload_sends_ciphertext_and_download_decrypts_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let blossom = mock_blossom().await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("media", &["bob"]).await.unwrap();
    bob.sync().await.unwrap();
    let group_state = alice.group_mls_state(&group_id).unwrap();
    assert!(
        group_state.required_app_components.contains(&0x8008),
        "encrypted media v1 is a required app component"
    );

    let plaintext = b"marmot encrypted media tracer bullet".to_vec();
    let second_plaintext = b"second attachment in the same message".to_vec();
    let upload = alice
        .upload_media(
            &group_id,
            MediaUploadRequest {
                attachments: vec![
                    MediaUploadAttachmentRequest {
                        file_name: "note.txt".to_owned(),
                        media_type: "Text/Plain; charset=utf-8".to_owned(),
                        plaintext: plaintext.clone(),
                        dim: None,
                        thumbhash: Some("1QcSHQRnh493V4dIh4eXh1h4kJUI".to_owned()),
                    },
                    MediaUploadAttachmentRequest {
                        file_name: "clip.mp4".to_owned(),
                        media_type: "video/mp4".to_owned(),
                        plaintext: second_plaintext.clone(),
                        dim: Some("640x360".to_owned()),
                        thumbhash: None,
                    },
                ],
                caption: Some("secret note".to_owned()),
                send: true,
                blossom_server: Some(blossom.url.clone()),
            },
        )
        .await
        .unwrap();

    assert_eq!(upload.attachments.len(), 2);
    let reference = upload.attachments[0].reference.clone();
    let second_reference = upload.attachments[1].reference.clone();
    assert_eq!(reference.file_name, "note.txt");
    assert_eq!(reference.media_type, "text/plain");
    assert_eq!(reference.version, "encrypted-media-v1");
    assert_eq!(
        reference.plaintext_sha256,
        hex::encode(Sha256::digest(&plaintext))
    );
    assert_eq!(reference.nonce_hex.len(), 24);
    assert!(reference.thumbhash.is_some());
    assert_eq!(second_reference.file_name, "clip.mp4");
    assert_eq!(second_reference.media_type, "video/mp4");
    assert_eq!(
        second_reference.plaintext_sha256,
        hex::encode(Sha256::digest(&second_plaintext))
    );
    assert!(upload.sent.as_ref().is_some_and(|sent| sent.published > 0));

    let stored = blossom
        .blob(&reference.ciphertext_sha256)
        .await
        .expect("encrypted blob was uploaded");
    assert_ne!(stored, plaintext);
    assert_eq!(
        hex::encode(Sha256::digest(&stored)),
        reference.ciphertext_sha256
    );
    let second_stored = blossom
        .blob(&second_reference.ciphertext_sha256)
        .await
        .expect("second encrypted blob was uploaded");
    assert_ne!(second_stored, second_plaintext);

    let sync = bob.sync().await.unwrap();
    assert_eq!(sync.messages[0].plaintext, "secret note");
    let imeta_tags: Vec<_> = sync.messages[0]
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .collect();
    assert_eq!(imeta_tags.len(), 2);
    let imeta = imeta_tags[0];
    let second_imeta = imeta_tags[1];
    assert!(
        imeta
            .iter()
            .any(|field| field == &format!("locator blossom-v1 {}", reference.locators[0].value))
    );
    assert!(imeta.iter().any(|field| field == "m text/plain"));
    assert!(imeta.iter().any(|field| field == "filename note.txt"));
    assert!(imeta.iter().any(|field| field == "v encrypted-media-v1"));
    assert!(imeta.iter().any(|field| field.starts_with("thumbhash ")));
    assert!(imeta.iter().all(|field| !field.starts_with("blurhash ")));
    assert!(second_imeta.iter().any(
        |field| field == &format!("locator blossom-v1 {}", second_reference.locators[0].value)
    ));
    assert!(second_imeta.iter().any(|field| field == "m video/mp4"));
    assert!(
        second_imeta
            .iter()
            .any(|field| field == "filename clip.mp4")
    );

    let download = bob
        .download_media(&group_id, reference.clone())
        .await
        .unwrap();
    assert_eq!(download.plaintext, plaintext);
    assert_eq!(download.file_name, "note.txt");
    assert_eq!(download.media_type, "text/plain");
    let second_download = bob
        .download_media(&group_id, second_reference.clone())
        .await
        .unwrap();
    assert_eq!(second_download.plaintext, second_plaintext);
    assert_eq!(second_download.file_name, "clip.mp4");
    assert_eq!(second_download.media_type, "video/mp4");

    let repeat_plaintext = b"another alice upload in the same epoch".to_vec();
    let repeat_upload = alice
        .upload_media(
            &group_id,
            MediaUploadRequest {
                attachments: vec![MediaUploadAttachmentRequest {
                    file_name: "repeat.txt".to_owned(),
                    media_type: "text/plain".to_owned(),
                    plaintext: repeat_plaintext.clone(),
                    dim: None,
                    thumbhash: None,
                }],
                caption: None,
                send: false,
                blossom_server: Some(blossom.url.clone()),
            },
        )
        .await
        .unwrap();
    let repeat_reference = repeat_upload.attachments[0].reference.clone();
    assert_eq!(repeat_reference.source_epoch, reference.source_epoch);
    let repeat_download = bob
        .download_media(&group_id, repeat_reference)
        .await
        .unwrap();
    assert_eq!(repeat_download.plaintext, repeat_plaintext);

    let bob_plaintext = b"bob upload after caching alice media secret".to_vec();
    let bob_upload = bob
        .upload_media(
            &group_id,
            MediaUploadRequest {
                attachments: vec![MediaUploadAttachmentRequest {
                    file_name: "bob.txt".to_owned(),
                    media_type: "text/plain".to_owned(),
                    plaintext: bob_plaintext.clone(),
                    dim: None,
                    thumbhash: None,
                }],
                caption: None,
                send: false,
                blossom_server: Some(blossom.url.clone()),
            },
        )
        .await
        .unwrap();
    let bob_reference = bob_upload.attachments[0].reference.clone();
    assert_eq!(bob_reference.source_epoch, reference.source_epoch);

    alice.update_message_retention(&group_id, 60).await.unwrap();
    bob.sync().await.unwrap();
    let later_epoch_download = bob
        .download_media(&group_id, reference.clone())
        .await
        .unwrap();
    assert_eq!(later_epoch_download.plaintext, plaintext);
    let bob_download = alice
        .download_media(&group_id, bob_reference)
        .await
        .unwrap();
    assert_eq!(bob_download.plaintext, bob_plaintext);

    let third_plaintext = b"third media after the epoch update".to_vec();
    let third_upload = alice
        .upload_media(
            &group_id,
            MediaUploadRequest {
                attachments: vec![MediaUploadAttachmentRequest {
                    file_name: "third.txt".to_owned(),
                    media_type: "text/plain".to_owned(),
                    plaintext: third_plaintext.clone(),
                    dim: None,
                    thumbhash: None,
                }],
                caption: None,
                send: false,
                blossom_server: Some(blossom.url.clone()),
            },
        )
        .await
        .unwrap();
    let third_reference = third_upload.attachments[0].reference.clone();
    let third_download = bob
        .download_media(&group_id, third_reference)
        .await
        .unwrap();
    assert_eq!(third_download.plaintext, third_plaintext);
}

#[tokio::test]
async fn encrypted_media_endpoint_updates_are_full_replacement_and_admin_only() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice
        .create_group("media endpoints", &["bob"])
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    bob.sync().await.unwrap();

    let bob_error = bob
        .replace_encrypted_media_blob_endpoints(
            &group_id,
            vec![marmot_app::AppBlobEndpoint {
                locator_kind: "blossom-v1".to_owned(),
                base_url: "https://bob.example".to_owned(),
            }],
        )
        .await
        .unwrap_err();
    assert!(bob_error.to_string().contains("admin"));

    alice
        .replace_encrypted_media_blob_endpoints(
            &group_id,
            vec![marmot_app::AppBlobEndpoint {
                locator_kind: "blossom-v1".to_owned(),
                base_url: "https://media.example".to_owned(),
            }],
        )
        .await
        .unwrap();
    bob.sync().await.unwrap();

    let bob_group = app.group("bob", &group_id_hex).unwrap().unwrap();
    assert_eq!(
        bob_group.encrypted_media.allowed_locator_kinds,
        vec!["blossom-v1".to_owned()]
    );
    assert_eq!(bob_group.encrypted_media.default_blob_endpoints.len(), 1);
    assert_eq!(
        bob_group.encrypted_media.default_blob_endpoints[0].base_url,
        "https://media.example"
    );
}

#[tokio::test]
async fn relay_app_runtime_reopens_account_state() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("restart", &["bob"]).await.unwrap();
    assert!(bob.sync().await.unwrap().joined_groups.contains(&group_id));
    drop(alice);
    drop(bob);

    let reopened = MarmotApp::with_relay(dir.path(), url);
    let status = reopened.status("bob").unwrap();
    assert_eq!(status.account, "bob");
    assert_eq!(
        status.groups[0].group_id_hex,
        hex::encode(group_id.as_slice())
    );
    let account_storage_path = dir.path().join("accounts/bob/session.sqlite");
    assert!(account_storage_path.exists());
    let plain_open_result = rusqlite::Connection::open(&account_storage_path).and_then(|conn| {
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
    });
    assert!(plain_open_result.is_err());
    assert!(!dir.path().join("accounts/bob/app.sqlite3").exists());
    assert!(!dir.path().join("accounts/bob/app-state.json").exists());
}

#[tokio::test]
async fn relay_app_publishes_account_relay_lists_for_setup() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (_seed, app, seed_url) = mock_app(&dir).await;

    let status = app
        .publish_account_relay_lists(
            "alice",
            AccountRelayListBootstrap::new(
                vec![
                    TransportEndpoint("wss://relay1.example".into()),
                    TransportEndpoint("wss://relay2.example".into()),
                ],
                vec![endpoint(&seed_url)],
            ),
        )
        .await
        .unwrap();

    assert!(status.complete);
    assert_eq!(
        status.default_relays,
        vec![
            "wss://relay1.example".to_owned(),
            "wss://relay2.example".to_owned()
        ]
    );
    assert_eq!(status.bootstrap_relays, vec![seed_url.clone()]);
    assert_eq!(status.nip65.kind, 10002);
    assert_eq!(status.inbox.kind, 10050);

    let account_id = home.account("alice").unwrap().account_id_hex;
    let fetched = app
        .fetch_account_relay_list_status_for_account_id(&account_id, vec![endpoint(&seed_url)])
        .await
        .unwrap();
    assert_eq!(fetched, status);
}

#[tokio::test]
async fn relay_app_public_methods_read_and_update_each_account_relay_list() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (_seed, app, seed_url) = mock_app(&dir).await;
    let (_inbox_relay, inbox_url) = mock_relay().await;

    let status = app
        .set_account_nip65_relays(
            "alice",
            vec![endpoint(&seed_url)],
            vec![endpoint(&seed_url)],
        )
        .await
        .unwrap();
    assert_eq!(status.nip65.relays, vec![seed_url.clone()]);
    assert_eq!(
        app.account_nip65_relays("alice").unwrap(),
        vec![seed_url.clone()]
    );

    let status = app
        .set_account_inbox_relays(
            "alice",
            vec![endpoint(&inbox_url)],
            vec![endpoint(&seed_url)],
        )
        .await
        .unwrap();
    assert!(status.complete);
    assert_eq!(status.inbox.relays, vec![inbox_url.clone()]);
    assert_eq!(
        app.account_inbox_relays("alice").unwrap(),
        vec![inbox_url.clone()]
    );
}

#[tokio::test]
async fn relay_list_fetch_only_uses_requested_bootstrap_relays() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (seed_a, seed_a_url) = mock_relay().await;
    let (seed_b, seed_b_url) = mock_relay().await;
    let _relays = (seed_a, seed_b);
    let app = MarmotApp::with_relay(dir.path(), seed_a_url.clone());

    app.publish_account_relay_lists(
        "alice",
        AccountRelayListBootstrap::new(vec![endpoint(&seed_a_url)], vec![endpoint(&seed_a_url)]),
    )
    .await
    .unwrap();

    let account_id = home.account("alice").unwrap().account_id_hex;
    let missing_from_seed_b = app
        .fetch_account_relay_list_status_for_account_id(&account_id, vec![endpoint(&seed_b_url)])
        .await
        .unwrap();

    assert!(!missing_from_seed_b.complete);
    assert_eq!(missing_from_seed_b.missing, vec!["nip65", "inbox"]);
    assert_eq!(missing_from_seed_b.bootstrap_relays, vec![seed_b_url]);
}

#[tokio::test]
async fn relay_list_fetch_rejects_future_events_and_keeps_cached_lists() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (seed_a, seed_a_url) = mock_relay().await;
    let (seed_b, seed_b_url) = mock_relay().await;
    let _relays = (seed_a, seed_b);
    let app = MarmotApp::with_relay(dir.path(), seed_a_url.clone());

    let cached = app
        .publish_account_relay_lists(
            "alice",
            AccountRelayListBootstrap::new(
                vec![endpoint(&seed_a_url)],
                vec![endpoint(&seed_a_url)],
            ),
        )
        .await
        .unwrap();
    publish_account_relay_lists_at(
        &home,
        "alice",
        &seed_b_url,
        "wss://future.example",
        test_unix_now_seconds() + 600,
    )
    .await;

    let account_id = home.account("alice").unwrap().account_id_hex;
    let fetched = app
        .fetch_account_relay_list_status_for_account_id(&account_id, vec![endpoint(&seed_b_url)])
        .await
        .unwrap();

    assert_eq!(fetched, cached);
    let directory_entry = app
        .directory_entry_for_account_id(&account_id)
        .unwrap()
        .expect("cached directory entry");
    assert_eq!(directory_entry.relay_lists, cached);
}

#[tokio::test]
async fn relay_list_future_skew_is_configurable_at_app_instantiation() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (_seed, seed_url) = mock_relay().await;
    let app = MarmotApp::with_relays_and_config(
        dir.path(),
        vec![seed_url.clone()],
        MarmotAppConfig::default().with_directory_max_future_skew(Duration::from_secs(900)),
    );

    publish_account_relay_lists_at(
        &home,
        "alice",
        &seed_url,
        "wss://within-skew.example",
        test_unix_now_seconds() + 600,
    )
    .await;

    let account_id = home.account("alice").unwrap().account_id_hex;
    let fetched = app
        .fetch_account_relay_list_status_for_account_id(&account_id, vec![endpoint(&seed_url)])
        .await
        .unwrap();

    assert!(fetched.complete);
    assert_eq!(
        fetched.default_relays,
        vec!["wss://within-skew.example".to_owned()]
    );
}

#[tokio::test]
async fn directory_cache_is_durable_app_state_not_json_user_files() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (_seed, app, seed_url) = mock_app(&dir).await;
    let account_id = home.account("alice").unwrap().account_id_hex;

    app.publish_account_relay_lists(
        "alice",
        AccountRelayListBootstrap::new(vec![endpoint(&seed_url)], vec![endpoint(&seed_url)]),
    )
    .await
    .unwrap();

    let reopened = MarmotApp::with_relay(dir.path(), seed_url);
    let cached = reopened
        .directory_entry_for_account_id(&account_id)
        .unwrap()
        .expect("directory entry");

    assert_eq!(cached.account_id_hex, account_id);
    assert!(cached.relay_lists.complete);
    let cache_path = home.account_dir("alice").join("app-cache.sqlite3");
    assert!(cache_path.exists());
    assert!(sqlite_file_requires_key_for_test(&cache_path));
    assert!(!dir.path().join("app-cache.sqlite3").exists());
    assert!(!dir.path().join("directory/users").exists());
}

#[tokio::test]
async fn user_directory_refresh_precaches_follows_profiles_and_searches_by_radius() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    home.create_account("carol").unwrap();
    let alice_id = home.account("alice").unwrap().account_id_hex;
    let bob_id = home.account("bob").unwrap().account_id_hex;
    let carol_id = home.account("carol").unwrap().account_id_hex;
    let (_seed, app, seed_url) = mock_app(&dir).await;
    let bootstrap =
        AccountRelayListBootstrap::new(vec![endpoint(&seed_url)], vec![endpoint(&seed_url)]);

    app.publish_user_profile(
        "bob",
        UserProfileMetadata {
            name: Some("bob".into()),
            display_name: Some("Bob Builder".into()),
            about: Some("Can we fix it".into()),
            picture: None,
            nip05: Some("bob@example.test".into()),
            lud16: None,
            created_at: 0,
            source_relays: Vec::new(),
        },
        bootstrap.clone(),
    )
    .await
    .unwrap();
    app.publish_user_profile(
        "carol",
        UserProfileMetadata {
            name: Some("carol".into()),
            display_name: Some("Carol Singer".into()),
            about: None,
            picture: None,
            nip05: None,
            lud16: None,
            created_at: 0,
            source_relays: Vec::new(),
        },
        bootstrap.clone(),
    )
    .await
    .unwrap();
    app.publish_account_follow_list("alice", &[&bob_id], bootstrap.clone())
        .await
        .unwrap();
    app.publish_account_follow_list("bob", &[&carol_id], bootstrap.clone())
        .await
        .unwrap();

    let alice_refresh = app
        .refresh_user_directory_for_account_id(&alice_id, vec![endpoint(&seed_url)])
        .await
        .unwrap();
    assert_eq!(alice_refresh.follow_count, 1);
    assert_eq!(alice_refresh.profile_count, 1);

    let bob_refresh = app
        .refresh_user_directory_for_account_id(&bob_id, vec![endpoint(&seed_url)])
        .await
        .unwrap();
    assert_eq!(bob_refresh.follow_count, 1);
    assert_eq!(bob_refresh.profile_count, 1);

    let alice_record = app
        .directory_entry_for_account_id(&alice_id)
        .unwrap()
        .expect("alice directory record");
    assert_eq!(alice_record.account_id_hex, alice_id);
    assert!(alice_record.npub.starts_with("npub1"));
    assert_eq!(alice_record.local_account.as_ref().unwrap().label, "alice");
    assert_eq!(alice_record.follows, vec![bob_id.clone()]);

    let bob_record = app
        .directory_entry_for_account_id(&bob_id)
        .unwrap()
        .expect("bob directory record");
    assert_eq!(
        bob_record.profile.as_ref().unwrap().display_name.as_deref(),
        Some("Bob Builder")
    );

    let bob_results = app
        .search_user_directory(UserDirectorySearch {
            searcher_account_id_hex: alice_id.clone(),
            query: "builder".into(),
            radius_start: 0,
            radius_end: 1,
            limit: None,
        })
        .unwrap();
    assert_eq!(bob_results[0].account_id_hex, bob_id);
    assert_eq!(bob_results[0].radius, 1);

    let carol_too_close = app
        .search_user_directory(UserDirectorySearch {
            searcher_account_id_hex: alice_id.clone(),
            query: "carol".into(),
            radius_start: 0,
            radius_end: 1,
            limit: None,
        })
        .unwrap();
    assert!(carol_too_close.is_empty());

    let carol_results = app
        .search_user_directory(UserDirectorySearch {
            searcher_account_id_hex: alice_id,
            query: "carol".into(),
            radius_start: 0,
            radius_end: 2,
            limit: None,
        })
        .unwrap();
    assert_eq!(carol_results[0].account_id_hex, carol_id);
    assert_eq!(carol_results[0].radius, 2);
}

#[tokio::test]
async fn user_directory_refresh_rejects_future_follow_and_profile_events() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    home.create_account("carol").unwrap();
    let alice_id = home.account("alice").unwrap().account_id_hex;
    let bob_id = home.account("bob").unwrap().account_id_hex;
    let carol_id = home.account("carol").unwrap().account_id_hex;
    let (seed_a, seed_a_url) = mock_relay().await;
    let (seed_b, seed_b_url) = mock_relay().await;
    let _relays = (seed_a, seed_b);
    let app = MarmotApp::with_relay(dir.path(), seed_a_url.clone());
    let bootstrap =
        AccountRelayListBootstrap::new(vec![endpoint(&seed_a_url)], vec![endpoint(&seed_a_url)]);

    app.publish_user_profile(
        "bob",
        UserProfileMetadata {
            name: Some("Bob Builder".into()),
            ..UserProfileMetadata::default()
        },
        bootstrap.clone(),
    )
    .await
    .unwrap();
    app.publish_account_follow_list("alice", &[&bob_id], bootstrap)
        .await
        .unwrap();
    app.refresh_user_directory_for_account_id(&alice_id, vec![endpoint(&seed_a_url)])
        .await
        .unwrap();

    let future_created_at = test_unix_now_seconds() + 600;
    publish_follow_list_at(
        &home,
        "alice",
        &seed_b_url,
        std::slice::from_ref(&carol_id),
        future_created_at,
    )
    .await;
    publish_profile_at(&home, "bob", &seed_b_url, "Future Bob", future_created_at).await;

    let refresh = app
        .refresh_user_directory_for_account_id(&alice_id, vec![endpoint(&seed_b_url)])
        .await
        .unwrap();
    assert_eq!(refresh.follow_count, 1);
    assert_eq!(refresh.profile_count, 0);

    let alice_record = app
        .directory_entry_for_account_id(&alice_id)
        .unwrap()
        .expect("alice directory record");
    assert_eq!(alice_record.follows, vec![bob_id.clone()]);
    let bob_record = app
        .directory_entry_for_account_id(&bob_id)
        .unwrap()
        .expect("bob directory record");
    assert_eq!(
        bob_record.profile.as_ref().unwrap().name.as_deref(),
        Some("Bob Builder")
    );
}

#[tokio::test]
async fn account_storage_records_received_messages() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let alice_id = home.account("alice").unwrap().account_id_hex;

    let (_relay, app, url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("messages", &["bob"]).await.unwrap();
    let alice_groups = app.groups("alice").unwrap();
    assert_eq!(alice_groups[0].profile.component_id, 0x8001);
    assert_eq!(alice_groups[0].profile.component, "marmot.group.profile.v1");
    assert_eq!(alice_groups[0].profile.name, "messages");
    assert_eq!(alice_groups[0].image.component_id, 0x8002);
    assert_eq!(
        alice_groups[0].image.component,
        "marmot.group.blossom.image.v1"
    );
    assert!(!alice_groups[0].image.present);
    assert_eq!(alice_groups[0].admin_policy.component_id, 0x8003);
    assert_eq!(
        alice_groups[0].admin_policy.component,
        "marmot.group.admin-policy.v1"
    );
    assert_eq!(alice_groups[0].admin_policy.admins.len(), 1);
    bob.sync().await.unwrap();
    let bob_groups = app.groups("bob").unwrap();
    assert_eq!(bob_groups[0].profile.name, "messages");
    assert_eq!(bob_groups[0].admin_policy, alice_groups[0].admin_policy);

    alice
        .send(&group_id, b"persist this projection")
        .await
        .unwrap();
    let alice_messages = MarmotApp::with_relay(dir.path(), url.clone())
        .messages("alice")
        .unwrap();
    assert_eq!(alice_messages.len(), 1);
    assert_eq!(alice_messages[0].direction, "sent");
    assert_eq!(alice_messages[0].sender, alice_id);
    assert_eq!(alice_messages[0].plaintext, "persist this projection");
    let alice_timeline = MarmotApp::with_relay(dir.path(), url.clone())
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group_id.as_slice())),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    assert_eq!(alice_timeline.messages.len(), 1);
    assert_eq!(alice_timeline.messages[0].direction, "sent");
    assert_eq!(alice_timeline.messages[0].sender, alice_id);
    assert_eq!(
        alice_timeline.messages[0].plaintext,
        "persist this projection"
    );

    alice.sync().await.unwrap();
    let alice_messages = MarmotApp::with_relay(dir.path(), url.clone())
        .messages("alice")
        .unwrap();
    assert_eq!(alice_messages.len(), 1);
    let alice_timeline = MarmotApp::with_relay(dir.path(), url.clone())
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group_id.as_slice())),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    assert_eq!(alice_timeline.messages.len(), 1);
    assert_eq!(alice_timeline.messages[0].direction, "sent");
    assert_eq!(
        alice_timeline.messages[0].plaintext,
        "persist this projection"
    );

    bob.sync().await.unwrap();

    let messages = MarmotApp::with_relay(dir.path(), url)
        .messages("bob")
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].direction, "received");
    assert_eq!(messages[0].sender, alice_id);
    assert_eq!(messages[0].group_id_hex, hex::encode(group_id.as_slice()));
    assert_eq!(messages[0].plaintext, "persist this projection");
}

#[tokio::test]
async fn account_publishes_route_to_own_nip65_not_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let (_home, home_url) = mock_relay().await;
    let (_other, other_url) = mock_relay().await;
    let app = MarmotApp::with_relay(dir.path(), home_url.clone());
    let runtime = MarmotAppRuntime::new(app.clone());

    // The account's NIP-65 write relay is the home relay.
    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&home_url)],
            bootstrap_relays: vec![endpoint(&home_url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let id = created.account.account_id_hex.clone();
    let label = created.account.label.clone();

    let status = app.account_relay_list_status_for_account_id(&id).unwrap();
    assert!(
        status.nip65.relays.iter().any(|r| r == &home_url),
        "nip65 should include the home relay, got {:?}",
        status.nip65.relays
    );

    // Publish a distinct profile, passing the OTHER relay as bootstrap.
    // Outbox routing must send it to the account's NIP-65 (home), not other.
    app.publish_user_profile(
        &label,
        UserProfileMetadata {
            name: Some("OutboxTest".to_owned()),
            ..UserProfileMetadata::default()
        },
        AccountRelayListBootstrap::new(vec![endpoint(&other_url)], vec![endpoint(&other_url)]),
    )
    .await
    .unwrap();

    // The bootstrap relay must NOT have the profile (outbox ignored it).
    app.refresh_profile_for_account_id(&id, vec![endpoint(&other_url)])
        .await
        .unwrap();
    let from_other = app
        .directory_entry_for_account_id(&id)
        .unwrap()
        .and_then(|entry| entry.profile)
        .and_then(|profile| profile.name);
    assert_ne!(
        from_other.as_deref(),
        Some("OutboxTest"),
        "profile must not be on the bootstrap relay; outbox should target nip65"
    );

    // The account's NIP-65 (home) relay SHOULD have it.
    app.refresh_profile_for_account_id(&id, vec![endpoint(&home_url)])
        .await
        .unwrap();
    let from_home = app
        .directory_entry_for_account_id(&id)
        .unwrap()
        .and_then(|entry| entry.profile)
        .and_then(|profile| profile.name);
    assert_eq!(
        from_home.as_deref(),
        Some("OutboxTest"),
        "profile should be retrievable from the account's nip65 (home) relay"
    );
}
