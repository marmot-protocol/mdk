use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Once};

use cgka_engine::account_identity_proof::ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE;
use cgka_engine::key_package::key_package_metadata;
use cgka_traits::app_components::GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID;
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION,
    STREAM_TAG,
};
use cgka_traits::engine::KeyPackage;
use cgka_traits::{GroupId, TransportEndpoint};
use marmot_account::{AccountHome, AccountHomeError, AccountSecretStore, KeychainSecretStore};
use marmot_app::{
    AccountRelayListBootstrap, AccountSetupRequest, AppError, AppMessageQuery, AuditDataMode,
    AuditLogSettings, AuditLogTrackerConfig, AuditLogUploadSource, MarmotApp, MarmotAppConfig,
    MarmotAppEvent, MarmotAppRuntime, MediaAttachmentReference, MediaLocator,
    MediaUploadAttachmentRequest, MediaUploadRequest, MissingRelayListKind, NotificationWakeSource,
    PushPlatform, RetentionSweepStatus, RuntimeMessageUpdate, SelfMembership, SignOutOptions,
    TimelineMessageQuery, TimelinePagination, UserDirectorySearch, UserProfileMetadata, tag_value,
};
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use nostr_relay_builder::prelude::{BoxedFuture, PolicyResult, WritePolicy};
use nostr_relay_builder::{LocalRelay, MockRelay, RelayBuilder};
use nostr_sdk::prelude::{
    Alphabet, Client as NostrSdkClient, EventBuilder, Keys, Kind, SingleLetterTag, Tag, TagKind,
    Timestamp as NostrTimestamp,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio::time::{Duration, Instant, sleep, timeout};
use transport_nostr_adapter::{
    KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST, NostrRelayClient, NostrSdkRelayClient,
};
use transport_nostr_peeler::{NOSTR_GROUP_CONTENT_MIN_LEN, NostrTransportEvent};

const AUDIT_TRACKER_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const AUDIT_TRACKER_NON_BLOCKING_TIMEOUT: Duration = Duration::from_secs(5);

async fn mock_relay() -> (MockRelay, String) {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    (relay, url)
}

async fn mock_app(dir: &tempfile::TempDir) -> (MockRelay, MarmotApp, String) {
    let (relay, url) = mock_relay().await;
    // The test harness exercises encrypted-media upload/download against a
    // loopback MockBlossom server, which is exactly the dev/test scenario the
    // loopback-HTTP gate is for. Enable it so the act paths reach 127.0.0.1.
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        MarmotAppConfig::default()
            .with_allow_loopback_blob_endpoints(true)
            .with_allow_loopback_relay_endpoints(true),
    );
    (relay, app, url)
}

async fn accept_group_invite_retrying_busy(
    runtime: &MarmotAppRuntime,
    account_ref: &str,
    group_id: &GroupId,
) -> Result<marmot_app::AppGroupRecord, AppError> {
    timeout(Duration::from_secs(5), async {
        loop {
            match runtime.accept_group_invite(account_ref, group_id).await {
                Err(AppError::AccountWorkerBusy) => sleep(Duration::from_millis(10)).await,
                result => return result,
            }
        }
    })
    .await
    .map_err(|_| AppError::AccountWorkerResponseTimedOut)?
}

async fn group_message_blocking_app(
    dir: &tempfile::TempDir,
    gate: BlockNextGroupMessages,
) -> (LocalRelay, MarmotApp, String) {
    let relay = LocalRelay::new(RelayBuilder::default().write_policy(gate));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    (relay, app, url)
}

fn install_mock_keyring() {
    static KEYRING_INIT: Once = Once::new();
    KEYRING_INIT.call_once(|| {
        if keyring_core::get_default_store().is_none() {
            let store = keyring_core::mock::Store::new().expect("create mock keyring store");
            keyring_core::set_default_store(store);
        }
    });
}

/// Rejects kind-445 group messages while armed. Lets a test accept setup
/// traffic normally, then fail exactly one member's outbound publish window.
#[cfg(feature = "test-policy-overrides")]
#[derive(Debug)]
struct RejectGroupMessagesWhileArmed(Arc<AtomicBool>);

#[cfg(feature = "test-policy-overrides")]
impl WritePolicy for RejectGroupMessagesWhileArmed {
    fn admit_event<'a>(
        &'a self,
        event: &'a nostr::Event,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if self.0.load(Ordering::Relaxed) && event.kind == Kind::MlsGroupMessage {
                PolicyResult::Reject("injected group-message rejection".into())
            } else {
                PolicyResult::Accept
            }
        })
    }
}

#[derive(Debug)]
struct RejectDeletionEvents;

impl WritePolicy for RejectDeletionEvents {
    fn admit_event<'a>(
        &'a self,
        event: &'a nostr::Event,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if event.kind == Kind::EventDeletion {
                PolicyResult::Reject("injected deletion rejection".into())
            } else {
                PolicyResult::Accept
            }
        })
    }
}

#[derive(Debug)]
struct RejectKeyPackagesWhileArmed(Arc<AtomicBool>);

impl WritePolicy for RejectKeyPackagesWhileArmed {
    fn admit_event<'a>(
        &'a self,
        event: &'a nostr::Event,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if self.0.load(Ordering::Relaxed)
                && event.kind == Kind::Custom(KIND_MARMOT_KEY_PACKAGE as u16)
            {
                PolicyResult::Reject("injected key package rejection".into())
            } else {
                PolicyResult::Accept
            }
        })
    }
}

#[derive(Debug)]
struct BlockKeyPackagesWhileArmed {
    armed: Arc<AtomicBool>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[derive(Clone, Debug)]
struct BlockNextGroupMessages {
    remaining: Arc<AtomicUsize>,
    blocked: Arc<AtomicUsize>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

impl BlockNextGroupMessages {
    fn new() -> Self {
        Self {
            remaining: Arc::new(AtomicUsize::new(0)),
            blocked: Arc::new(AtomicUsize::new(0)),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        }
    }

    fn arm(&self, count: usize) {
        self.blocked.store(0, Ordering::SeqCst);
        self.remaining.store(count, Ordering::SeqCst);
    }

    async fn wait_for_blocked(&self, count: usize) {
        while self.blocked.load(Ordering::SeqCst) < count {
            self.entered.notified().await;
        }
    }

    fn release(&self) {
        self.release.notify_waiters();
    }
}

impl WritePolicy for BlockNextGroupMessages {
    fn admit_event<'a>(
        &'a self,
        event: &'a nostr::Event,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let should_block = event.kind == Kind::MlsGroupMessage
                && self
                    .remaining
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                        remaining.checked_sub(1)
                    })
                    .is_ok();
            if should_block {
                let released = self.release.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                self.blocked.fetch_add(1, Ordering::SeqCst);
                self.entered.notify_one();
                released.await;
            }
            PolicyResult::Accept
        })
    }
}

impl WritePolicy for BlockKeyPackagesWhileArmed {
    fn admit_event<'a>(
        &'a self,
        event: &'a nostr::Event,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if self.armed.load(Ordering::Relaxed)
                && event.kind == Kind::Custom(KIND_MARMOT_KEY_PACKAGE as u16)
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            PolicyResult::Accept
        })
    }
}

async fn deletion_rejecting_app(dir: &tempfile::TempDir) -> (LocalRelay, MarmotApp, String) {
    let relay = LocalRelay::new(RelayBuilder::default().write_policy(RejectDeletionEvents));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
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

/// Accept audit uploads in a loop, forwarding each request body over `bodies`
/// and answering 204 immediately. Unlike the gated `capture_delayed_*` helpers,
/// this drains a stream of uploads so a test can wait for the *one* whose body
/// carries a specific forensic row while ignoring earlier unrelated uploads.
async fn forward_audit_upload_bodies(
    listener: TcpListener,
    bodies: mpsc::UnboundedSender<Vec<u8>>,
) {
    loop {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };
        let Some(captured) = read_captured_audit_upload(&mut stream).await else {
            continue;
        };
        write_http_response(&mut stream, 204, "text/plain", b"").await;
        if bodies.send(captured.body).is_err() {
            return;
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

#[derive(Clone, Debug)]
// Mirrors `src/tests.rs::TestExternalAccountSigner`; keep both shims aligned
// when the `NostrSigner` or account-identity-proof signer traits change.
struct TestExternalAccountSigner {
    keys: nostr::Keys,
}

impl nostr::NostrSigner for TestExternalAccountSigner {
    fn backend(&self) -> nostr::signer::SignerBackend<'_> {
        self.keys.backend()
    }

    fn get_public_key(
        &self,
    ) -> nostr::util::BoxedFuture<'_, Result<nostr::PublicKey, nostr::SignerError>> {
        self.keys.get_public_key()
    }

    fn sign_event(
        &self,
        unsigned: nostr::UnsignedEvent,
    ) -> nostr::util::BoxedFuture<'_, Result<nostr::Event, nostr::SignerError>> {
        self.keys.sign_event(unsigned)
    }

    fn nip04_encrypt<'a>(
        &'a self,
        public_key: &'a nostr::PublicKey,
        content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, nostr::SignerError>> {
        self.keys.nip04_encrypt(public_key, content)
    }

    fn nip04_decrypt<'a>(
        &'a self,
        public_key: &'a nostr::PublicKey,
        encrypted_content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, nostr::SignerError>> {
        self.keys.nip04_decrypt(public_key, encrypted_content)
    }

    fn nip44_encrypt<'a>(
        &'a self,
        public_key: &'a nostr::PublicKey,
        content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, nostr::SignerError>> {
        self.keys.nip44_encrypt(public_key, content)
    }

    fn nip44_decrypt<'a>(
        &'a self,
        public_key: &'a nostr::PublicKey,
        payload: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, nostr::SignerError>> {
        self.keys.nip44_decrypt(public_key, payload)
    }
}

impl cgka_engine::account_identity_proof::AccountIdentityProofSigner for TestExternalAccountSigner {
    fn sign_account_identity_proof(
        &self,
        request: &cgka_engine::account_identity_proof::AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.keys.public_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match test signer".into());
        }
        let event = request.proof_event().and_then(|event| {
            event
                .sign_with_keys(&self.keys)
                .map_err(|err| err.to_string())
        })?;
        request.signature_from_signed_event(event)
    }
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

/// Publish an envelope-shaped undecryptable kind-445 probe with a fresh
/// ephemeral key, h-tagged to `nostr_group_id_hex`. Mirrors the probe publisher
/// in `next_event_backfill.rs`: real kind-445 senders always sign with a fresh
/// per-event key, and a zero-nonce marker body peels to a clean
/// `TransportDeferred` — the typed availability outcome the epoch-stall detector
/// counts toward arming a backfill. Distinct `marker`s yield distinct event ids,
/// hence distinct undecryptables at the group's one stalled epoch.
async fn publish_garbage_group_message(
    relay_url: &str,
    nostr_group_id_hex: &str,
    created_at: u64,
    marker: &str,
) {
    let mut envelope = vec![0u8; 12];
    envelope.extend_from_slice(format!("backfill-armed-probe:{marker}").as_bytes());
    assert!(envelope.len() >= NOSTR_GROUP_CONTENT_MIN_LEN);
    let ephemeral = Keys::generate();
    let signed = EventBuilder::new(Kind::MlsGroupMessage, BASE64_STANDARD.encode(envelope))
        .tags([Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::H)),
            [nostr_group_id_hex.to_owned()],
        )])
        .custom_created_at(NostrTimestamp::from_secs(created_at))
        .sign_with_keys(&ephemeral)
        .expect("sign ephemeral kind-445 test event");
    let transport_event =
        NostrTransportEvent::from_nostr_event(&signed).expect("dto from signed event");
    let relay_client = NostrSdkRelayClient::new(NostrSdkClient::builder().build());
    relay_client
        .publish_event(&[endpoint(relay_url)], &transport_event, 1)
        .await
        .expect("publish garbage kind-445 test event");
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
async fn import_with_stalled_discovery_endpoint_completes_within_the_advisory_cap() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());

    // A discovery endpoint that accepts TCP and then never speaks: the
    // advisory directory preflight against it can only end via its time cap.
    let stall = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stall_url = format!("ws://{}", stall.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = stall.accept().await {
            held.push(socket);
        }
    });

    use nostr::prelude::ToBech32;
    let secret = nostr::Keys::generate().secret_key().to_bech32().unwrap();
    let imported = timeout(
        Duration::from_secs(40),
        runtime.create_or_import_account(AccountSetupRequest {
            identity: None,
            import_nsec: Some(zeroize::Zeroizing::new(secret)),
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            discovery_relays: vec![endpoint(&url), endpoint(&stall_url)],
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
        }),
    )
    .await
    .expect("import must not hang on a stalled discovery endpoint")
    .expect("import should succeed without the advisory preflight");
    assert!(imported.account.local_signing);
    assert_eq!(
        runtime
            .shared_services()
            .relay_plane()
            .relay_health()
            .await
            .directory_failed_fetches,
        0,
        "a stalled peer must not fail a directory fetch that has one connected relay"
    );
    assert_eq!(
        runtime
            .shared_services()
            .app_performance_telemetry()
            .snapshot()
            .account_session_open
            .attempts,
        1,
        "nsec setup must use the worker-owned session instead of a one-shot open"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_private_key_import_recovers_orphaned_keychain_credential() {
    use nostr::prelude::ToBech32;

    install_mock_keyring();
    let dir = tempfile::tempdir().unwrap();
    let (_relay, url) = mock_relay().await;
    let keys = Keys::generate();
    let account_id = keys.public_key().to_hex();
    let secret = keys.secret_key().to_bech32().unwrap();
    let service_name = format!("com.marmot.test.runtime-orphan-{account_id}");
    let relay_endpoint = endpoint(&url);
    let setup = |secret: &str| AccountSetupRequest {
        identity: None,
        import_nsec: Some(zeroize::Zeroizing::new(secret.to_owned())),
        default_relays: vec![relay_endpoint.clone()],
        bootstrap_relays: vec![relay_endpoint.clone()],
        publish_missing_relay_lists: true,
        ..AccountSetupRequest::default()
    };
    let config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);

    let first_home = AccountHome::open_with_keychain(dir.path(), service_name.clone()).unwrap();
    let first_app = MarmotApp::with_relays_and_account_home_and_config(
        dir.path(),
        vec![url.clone()],
        first_home,
        config.clone(),
    );
    let first_runtime = MarmotAppRuntime::new(first_app.clone());
    let first = first_runtime
        .create_or_import_account(setup(&secret))
        .await
        .unwrap();
    assert_eq!(first.account.account_id_hex, account_id);
    assert!(matches!(
        first_runtime
            .create_or_import_account(setup(&secret))
            .await,
        Err(AppError::AccountHome(AccountHomeError::AccountExists(
            duplicate
        ))) if duplicate == account_id
    ));
    first_runtime.shutdown().await;
    drop(first_runtime);
    drop(first_app);

    std::fs::remove_dir_all(dir.path()).unwrap();
    std::fs::create_dir_all(dir.path()).unwrap();

    let recovered_home = AccountHome::open_with_keychain(dir.path(), service_name).unwrap();
    let recovered_app = MarmotApp::with_relays_and_account_home_and_config(
        dir.path(),
        vec![url],
        recovered_home.clone(),
        config,
    );
    let recovered_runtime = MarmotAppRuntime::new(recovered_app.clone());
    let recovered = recovered_runtime
        .create_or_import_account(setup(&secret))
        .await
        .expect("runtime import should recover the matching orphaned Keychain credential");

    assert_eq!(recovered.account.account_id_hex, account_id);
    assert_eq!(
        recovered_home.account(&account_id).unwrap(),
        recovered.account
    );
    assert_eq!(
        recovered_home
            .load_signing_keys(&account_id)
            .unwrap()
            .public_key(),
        keys.public_key()
    );

    recovered_runtime.shutdown().await;
}

#[tokio::test]
async fn failed_key_package_setup_retries_same_nsec_after_restart() {
    use nostr::prelude::ToBech32;

    let dir = tempfile::tempdir().unwrap();
    let rejecting = Arc::new(AtomicBool::new(true));
    let relay = LocalRelay::new(
        RelayBuilder::default().write_policy(RejectKeyPackagesWhileArmed(rejecting.clone())),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    let secret = Keys::generate().secret_key().to_bech32().unwrap();
    let account_id = AccountHome::account_id_for_secret(&secret).unwrap();
    let setup = |secret: &str| AccountSetupRequest {
        identity: None,
        import_nsec: Some(zeroize::Zeroizing::new(secret.to_owned())),
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_missing_relay_lists: true,
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };

    let first_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    let first_runtime = MarmotAppRuntime::new(first_app.clone());
    let error = first_runtime
        .create_or_import_account(setup(&secret))
        .await
        .expect_err("the first KeyPackage publish must be rejected");
    assert!(
        error.to_string().contains("key package publication failed"),
        "unexpected setup boundary: {error}"
    );
    let first_home = AccountHome::open(dir.path());
    let account = first_home.account(&account_id).unwrap();
    assert_eq!(
        first_home
            .account_setup_state(&account.label)
            .unwrap()
            .unwrap()
            .phase,
        marmot_account::AccountSetupPhase::KeyPackagePublicationStarted
    );
    assert!(
        first_home
            .account_dir(&account.label)
            .join("session.sqlite")
            .exists()
    );
    // Simulate the exact shape left by an older app build: the encrypted
    // lifecycle owns an exact pending publication, but setup predates the
    // durable journal introduced by this fix.
    std::fs::remove_file(
        first_home
            .account_dir(&account.label)
            .join(".account-setup.json"),
    )
    .unwrap();
    first_runtime.shutdown().await;
    drop(first_runtime);
    drop(first_app);

    rejecting.store(false, Ordering::Relaxed);
    let second_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config);
    let second_runtime = MarmotAppRuntime::new(second_app.clone());
    let retried = second_runtime
        .create_or_import_account(setup(&secret))
        .await
        .expect("the same nsec must resume after restart");
    assert_eq!(retried.account.account_id_hex, account_id);
    let second_home = AccountHome::open(dir.path());
    assert_eq!(second_home.accounts().unwrap().len(), 1);
    assert!(
        second_home
            .account_setup_state(&retried.account.label)
            .unwrap()
            .is_none(),
        "the setup journal is removed only after commit"
    );
    let lifecycle = second_runtime
        .key_package_maintenance_status(&account_id)
        .await
        .unwrap()
        .unwrap();
    assert!(lifecycle.current_key_package.is_some());
    assert!(lifecycle.pending_replacement.is_none());
    assert_eq!(lifecycle.stable_slot_id.len(), 64);
    second_runtime.shutdown().await;
}

#[tokio::test]
async fn failed_reactivation_key_package_publish_restores_signed_out_retry() {
    use nostr::prelude::ToBech32;

    let dir = tempfile::tempdir().unwrap();
    let rejecting = Arc::new(AtomicBool::new(false));
    let relay = LocalRelay::new(
        RelayBuilder::default().write_policy(RejectKeyPackagesWhileArmed(rejecting.clone())),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    let secret = Keys::generate().secret_key().to_bech32().unwrap();
    let account_id = AccountHome::account_id_for_secret(&secret).unwrap();
    let setup = |secret: &str| AccountSetupRequest {
        import_nsec: Some(zeroize::Zeroizing::new(secret.to_owned())),
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        discovery_relays: vec![endpoint(&url)],
        publish_missing_relay_lists: true,
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };

    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config);
    let runtime = MarmotAppRuntime::new(app.clone());
    let created = runtime
        .create_or_import_account(setup(&secret))
        .await
        .expect("initial import should publish its KeyPackage");
    runtime
        .sign_out(
            &created.account.label,
            SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();

    rejecting.store(true, Ordering::Relaxed);
    runtime
        .create_or_import_account(setup(&secret))
        .await
        .expect_err("reactivation must surface the rejected KeyPackage publication");
    assert!(
        AccountHome::open(dir.path())
            .account(&account_id)
            .unwrap()
            .signed_out,
        "failed reactivation must restore the durable signed-out marker"
    );

    rejecting.store(false, Ordering::Relaxed);
    let retried = runtime
        .create_or_import_account(setup(&secret))
        .await
        .expect("the same nsec must resume instead of returning AccountExists");
    assert_eq!(retried.account.account_id_hex, account_id);
    assert!(!retried.account.signed_out);
    runtime.shutdown().await;
}

#[tokio::test]
async fn failed_external_signer_reactivation_restores_signed_out_retry() {
    let dir = tempfile::tempdir().unwrap();
    let rejecting = Arc::new(AtomicBool::new(false));
    let relay = LocalRelay::new(
        RelayBuilder::default().write_policy(RejectKeyPackagesWhileArmed(rejecting.clone())),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    let keys = Keys::generate();
    let public_key = keys.public_key().to_hex();
    let setup = || AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        discovery_relays: vec![endpoint(&url)],
        publish_missing_relay_lists: true,
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };

    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    let runtime = MarmotAppRuntime::new(app);
    let created = runtime
        .login_external_signer(
            public_key.clone(),
            TestExternalAccountSigner { keys: keys.clone() },
            setup(),
        )
        .await
        .expect("initial external-signer login should publish its KeyPackage");
    runtime.shutdown().await;
    AccountHome::open(dir.path())
        .set_account_signed_out(&created.account.label, true)
        .unwrap();
    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config);
    let runtime = MarmotAppRuntime::new(app);

    rejecting.store(true, Ordering::Relaxed);
    runtime
        .login_external_signer(
            public_key.clone(),
            TestExternalAccountSigner { keys: keys.clone() },
            setup(),
        )
        .await
        .expect_err("external-signer reactivation must surface KeyPackage rejection");
    assert!(
        AccountHome::open(dir.path())
            .account(&public_key)
            .unwrap()
            .signed_out,
        "failed external-signer reactivation must restore signed-out state"
    );

    rejecting.store(false, Ordering::Relaxed);
    let retried = runtime
        .login_external_signer(
            public_key.clone(),
            TestExternalAccountSigner { keys },
            setup(),
        )
        .await
        .expect("external-signer reactivation retry must resume");
    assert_eq!(retried.account.account_id_hex, public_key);
    assert!(!retried.account.signed_out);
    runtime.shutdown().await;
}

#[tokio::test]
async fn failed_generated_identity_setup_resumes_same_identity_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let rejecting = Arc::new(AtomicBool::new(true));
    let relay = LocalRelay::new(
        RelayBuilder::default().write_policy(RejectKeyPackagesWhileArmed(rejecting.clone())),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    let setup = || AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_missing_relay_lists: true,
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };

    let first_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    let first_runtime = MarmotAppRuntime::new(first_app);
    first_runtime
        .create_identity(setup())
        .await
        .expect_err("the first generated identity KeyPackage publish must fail");
    let first_home = AccountHome::open(dir.path());
    let first_account = first_home.accounts().unwrap().into_iter().next().unwrap();
    assert_eq!(
        first_home
            .account_setup_state(&first_account.label)
            .unwrap()
            .unwrap()
            .kind,
        marmot_account::AccountSetupKind::GeneratedIdentity
    );
    first_runtime.shutdown().await;

    rejecting.store(false, Ordering::Relaxed);
    let second_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config);
    let second_runtime = MarmotAppRuntime::new(second_app);
    let retried = second_runtime
        .create_identity(setup())
        .await
        .expect("create-identity retry must resume the generated identity");
    assert_eq!(retried.account.account_id_hex, first_account.account_id_hex);
    assert_eq!(AccountHome::open(dir.path()).accounts().unwrap().len(), 1);
    second_runtime.shutdown().await;
}

#[tokio::test]
async fn failed_external_signer_setup_resumes_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let rejecting = Arc::new(AtomicBool::new(true));
    let relay = LocalRelay::new(
        RelayBuilder::default().write_policy(RejectKeyPackagesWhileArmed(rejecting.clone())),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    let keys = Keys::generate();
    let public_key = keys.public_key().to_hex();
    let setup = || AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_missing_relay_lists: true,
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };

    let first_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    let first_runtime = MarmotAppRuntime::new(first_app);
    first_runtime
        .login_external_signer(
            public_key.clone(),
            TestExternalAccountSigner { keys: keys.clone() },
            setup(),
        )
        .await
        .expect_err("the first external-signer KeyPackage publish must fail");
    let first_home = AccountHome::open(dir.path());
    assert_eq!(
        first_home
            .account_setup_state(&public_key)
            .unwrap()
            .unwrap()
            .phase,
        marmot_account::AccountSetupPhase::KeyPackagePublicationStarted
    );
    first_runtime.shutdown().await;

    rejecting.store(false, Ordering::Relaxed);
    let second_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config);
    let second_runtime = MarmotAppRuntime::new(second_app);
    let retried = second_runtime
        .login_external_signer(
            public_key.clone(),
            TestExternalAccountSigner { keys },
            setup(),
        )
        .await
        .expect("external-signer retry must resume its pending publication");
    assert_eq!(retried.account.account_id_hex, public_key);
    assert!(
        AccountHome::open(dir.path())
            .account_setup_state(&retried.account.label)
            .unwrap()
            .is_none()
    );
    second_runtime.shutdown().await;
}

#[tokio::test]
async fn cancelled_key_package_setup_resumes_exact_pending_attempt_after_restart() {
    use marmot_account::AccountSetupPhase;
    use nostr::prelude::ToBech32;

    let dir = tempfile::tempdir().unwrap();
    let armed = Arc::new(AtomicBool::new(true));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let relay = LocalRelay::new(
        RelayBuilder::default().write_policy(BlockKeyPackagesWhileArmed {
            armed: armed.clone(),
            entered: entered.clone(),
            release: release.clone(),
        }),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    let secret = Keys::generate().secret_key().to_bech32().unwrap();
    let account_id = AccountHome::account_id_for_secret(&secret).unwrap();
    let setup = |secret: &str| AccountSetupRequest {
        identity: None,
        import_nsec: Some(zeroize::Zeroizing::new(secret.to_owned())),
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_missing_relay_lists: true,
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };

    let first_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    let first_runtime = MarmotAppRuntime::new(first_app.clone());
    let attempt_runtime = first_runtime.clone();
    let first_setup = setup(&secret);
    let attempt =
        tokio::spawn(async move { attempt_runtime.create_or_import_account(first_setup).await });
    timeout(Duration::from_secs(10), entered.notified())
        .await
        .expect("KeyPackage publication must reach the blocking relay");
    attempt.abort();
    assert!(attempt.await.unwrap_err().is_cancelled());

    let first_home = AccountHome::open(dir.path());
    let account = first_home.account(&account_id).unwrap();
    assert_eq!(
        first_home
            .account_setup_state(&account.label)
            .unwrap()
            .unwrap()
            .phase,
        AccountSetupPhase::KeyPackagePublicationStarted
    );
    assert!(
        first_home
            .account_dir(&account.label)
            .join("session.sqlite")
            .exists()
    );

    armed.store(false, Ordering::Relaxed);
    release.notify_one();
    first_runtime.shutdown().await;
    drop(first_runtime);
    drop(first_app);

    let second_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config);
    let second_runtime = MarmotAppRuntime::new(second_app);
    let retried = second_runtime
        .create_or_import_account(setup(&secret))
        .await
        .expect("cancelled setup must resume without deleting local data");
    assert_eq!(retried.account.account_id_hex, account_id);
    let lifecycle = second_runtime
        .key_package_maintenance_status(&account_id)
        .await
        .unwrap()
        .unwrap();
    assert!(lifecycle.current_key_package.is_some());
    assert!(lifecycle.pending_replacement.is_none());
    second_runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_private_key_setup_rollback_preserves_only_recovered_keychain_secret() {
    use nostr::prelude::ToBech32;

    install_mock_keyring();
    let dir = tempfile::tempdir().unwrap();
    let (_relay, url) = mock_relay().await;
    let recovered_keys = Keys::generate();
    let recovered_account_id = recovered_keys.public_key().to_hex();
    let recovered_secret = recovered_keys.secret_key().to_bech32().unwrap();
    let recovered_service =
        format!("com.marmot.test.runtime-rollback-recovered-{recovered_account_id}");
    let config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    let successful_setup = AccountSetupRequest {
        identity: None,
        import_nsec: Some(zeroize::Zeroizing::new(recovered_secret.clone())),
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_missing_relay_lists: true,
        ..AccountSetupRequest::default()
    };

    let first_home =
        AccountHome::open_with_keychain(dir.path(), recovered_service.clone()).unwrap();
    let first_app = MarmotApp::with_relays_and_account_home_and_config(
        dir.path(),
        vec![url.clone()],
        first_home,
        config.clone(),
    );
    let first_runtime = MarmotAppRuntime::new(first_app.clone());
    first_runtime
        .create_or_import_account(AccountSetupRequest {
            identity: None,
            import_nsec: Some(zeroize::Zeroizing::new(recovered_secret.clone())),
            default_relays: successful_setup.default_relays.clone(),
            bootstrap_relays: successful_setup.bootstrap_relays.clone(),
            publish_missing_relay_lists: successful_setup.publish_missing_relay_lists,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    first_runtime.shutdown().await;
    drop(first_runtime);
    drop(first_app);

    std::fs::remove_dir_all(dir.path()).unwrap();
    std::fs::create_dir_all(dir.path()).unwrap();

    let recovered_home =
        AccountHome::open_with_keychain(dir.path(), recovered_service.clone()).unwrap();
    let recovered_app = MarmotApp::with_relays_and_account_home_and_config(
        dir.path(),
        vec![url.clone()],
        recovered_home.clone(),
        config.clone(),
    );
    let recovered_runtime = MarmotAppRuntime::new(recovered_app);
    assert!(matches!(
        recovered_runtime
            .create_or_import_account(AccountSetupRequest {
                identity: None,
                import_nsec: Some(zeroize::Zeroizing::new(recovered_secret)),
                ..AccountSetupRequest::default()
            })
            .await,
        Err(AppError::MissingDefaultRelays)
    ));
    assert!(recovered_home.accounts().unwrap().is_empty());
    assert!(
        KeychainSecretStore::new(recovered_service)
            .unwrap()
            .has_secret_for_account_id(&recovered_account_id)
            .unwrap(),
        "rollback must retain the exact Keychain credential that predated setup"
    );

    let new_keys = Keys::generate();
    let new_account_id = new_keys.public_key().to_hex();
    let new_service = format!("com.marmot.test.runtime-rollback-new-{new_account_id}");
    let new_dir = tempfile::tempdir().unwrap();
    let new_home = AccountHome::open_with_keychain(new_dir.path(), new_service.clone()).unwrap();
    let new_app = MarmotApp::with_relays_and_account_home_and_config(
        new_dir.path(),
        vec![url],
        new_home.clone(),
        config,
    );
    let new_runtime = MarmotAppRuntime::new(new_app);
    assert!(matches!(
        new_runtime
            .create_or_import_account(AccountSetupRequest {
                identity: None,
                import_nsec: Some(zeroize::Zeroizing::new(
                    new_keys.secret_key().to_bech32().unwrap(),
                )),
                ..AccountSetupRequest::default()
            })
            .await,
        Err(AppError::MissingDefaultRelays)
    ));
    assert!(new_home.accounts().unwrap().is_empty());
    assert!(
        !KeychainSecretStore::new(new_service)
            .unwrap()
            .has_secret_for_account_id(&new_account_id)
            .unwrap(),
        "rollback must still delete a signing credential created by failed setup"
    );

    recovered_runtime.shutdown().await;
    new_runtime.shutdown().await;
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
        relay_health.directory_completed_fetches <= 1,
        "generated setup must not add synchronous relay-list/follow-list refetches; observed {} directory fetches",
        relay_health.directory_completed_fetches,
    );
    assert_eq!(
        runtime
            .shared_services()
            .app_performance_telemetry()
            .snapshot()
            .account_session_open
            .attempts,
        1,
        "setup must open the worker-owned session exactly once"
    );
    assert!(
        dir.path()
            .join("key-packages")
            .join(format!(
                "{}.capability-refresh-v1-relay-scan-complete",
                created.account.label
            ))
            .exists(),
        "a generated account must persist the guaranteed-empty cutover scan marker before opening"
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
    assert_eq!(
        app.fetch_current_follow_list_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap(),
        Some(Vec::new()),
        "a new identity should publish a kind-3 event with no p tags"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn account_creation_succeeds_with_one_unreachable_bootstrap_relay() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, live_url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app);
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unreachable_url = format!("ws://{}", unused.local_addr().unwrap());
    drop(unused);

    let created = timeout(
        Duration::from_secs(20),
        runtime.create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&live_url), endpoint(&unreachable_url)],
            bootstrap_relays: vec![endpoint(&live_url), endpoint(&unreachable_url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("one unreachable relay must not multiply setup deadlines")
    .expect("one acknowledged relay is sufficient for account setup");

    assert!(created.relay_lists.complete);
    assert!(created.key_package_bytes.is_some());
    runtime.shutdown().await;
}

#[tokio::test]
async fn runtime_profile_publish_preserves_unknown_kind0_fields() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let bootstrap = AccountRelayListBootstrap::new(vec![endpoint(&url)], vec![endpoint(&url)]);

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();

    runtime
        .publish_user_profile(
            &created.account.label,
            UserProfileMetadata {
                name: Some("first".to_owned()),
                display_name: Some("First".to_owned()),
                banner: Some("https://example.test/banner.png".to_owned()),
                extra: std::collections::BTreeMap::from([
                    (
                        "website".to_owned(),
                        serde_json::json!("https://example.test"),
                    ),
                    ("bot".to_owned(), serde_json::json!(false)),
                ]),
                ..UserProfileMetadata::default()
            },
            bootstrap.clone(),
        )
        .await
        .unwrap();

    let updated = runtime
        .publish_user_profile(
            &created.account.label,
            UserProfileMetadata {
                name: Some("second".to_owned()),
                about: Some("known-field edit".to_owned()),
                banner: Some("https://example.test/banner.png".to_owned()),
                ..UserProfileMetadata::default()
            },
            bootstrap,
        )
        .await
        .unwrap();

    assert_eq!(updated.name.as_deref(), Some("second"));
    assert_eq!(updated.about.as_deref(), Some("known-field edit"));
    assert_eq!(
        updated.extra.get("website"),
        Some(&serde_json::json!("https://example.test"))
    );
    assert_eq!(
        updated.banner.as_deref(),
        Some("https://example.test/banner.png")
    );
    assert_eq!(updated.extra.get("bot"), Some(&serde_json::json!(false)));

    let fetched = app
        .fetch_current_user_profile_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap()
        .expect("profile on relay");
    assert_eq!(fetched.name.as_deref(), Some("second"));
    assert_eq!(
        fetched.extra.get("website"),
        Some(&serde_json::json!("https://example.test"))
    );
    assert_eq!(
        fetched.banner.as_deref(),
        Some("https://example.test/banner.png")
    );
    assert_eq!(fetched.extra.get("bot"), Some(&serde_json::json!(false)));

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_republish_key_package_resends_exact_current_event() {
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
    let before = runtime
        .key_package_maintenance_status(&created.account.account_id_hex)
        .await
        .unwrap()
        .expect("initial publication must promote lifecycle state");
    let durable_before = runtime
        .durably_owned_key_packages(&created.account.account_id_hex)
        .await
        .unwrap()
        .len();

    let republished_bytes = runtime
        .publish_key_package(&created.account.account_id_hex)
        .await
        .unwrap();
    let after_republish = runtime
        .key_package_maintenance_status(&created.account.account_id_hex)
        .await
        .unwrap()
        .expect("republish must keep lifecycle state");
    let relay_after_republish = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    assert_eq!(republished_bytes, first.key_package.bytes().len());
    assert_eq!(
        relay_after_republish.key_package.bytes(),
        first.key_package.bytes()
    );
    assert_eq!(
        relay_after_republish.key_package_ref_hex,
        first.key_package_ref_hex
    );
    assert_eq!(
        relay_after_republish.key_package_event_id,
        first.key_package_event_id
    );
    assert_eq!(after_republish.stable_slot_id, before.stable_slot_id);
    assert_eq!(
        after_republish.current_key_package_ref,
        before.current_key_package_ref
    );
    assert_eq!(after_republish.authored_event_id, before.authored_event_id);
    assert_eq!(
        after_republish.authored_event_created_at,
        before.authored_event_created_at
    );
    assert_eq!(
        after_republish.authored_signed_event,
        before.authored_signed_event
    );
    assert_eq!(after_republish.phase, before.phase);
    assert_eq!(
        after_republish.retained_private_material.len(),
        before.retained_private_material.len()
    );
    assert!(after_republish.pending_replacement.is_none());
    assert_eq!(
        runtime
            .durably_owned_key_packages(&created.account.account_id_hex)
            .await
            .unwrap()
            .len(),
        durable_before,
        "republish must not mint or prune durable private bundles"
    );

    runtime.shutdown().await;
    drop(runtime);
    drop(app);

    let restarted_app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        MarmotAppConfig::default()
            .with_allow_loopback_blob_endpoints(true)
            .with_allow_loopback_relay_endpoints(true),
    );
    let restarted = MarmotAppRuntime::new(restarted_app.clone());
    restarted.reconcile_accounts().await.unwrap();

    let republished_after_restart_bytes = restarted
        .publish_key_package(&created.account.account_id_hex)
        .await
        .unwrap();
    let after_restart = restarted
        .key_package_maintenance_status(&created.account.account_id_hex)
        .await
        .unwrap()
        .expect("restart must retain lifecycle state");
    let relay_after_restart = restarted_app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    assert_eq!(
        republished_after_restart_bytes,
        first.key_package.bytes().len()
    );
    assert_eq!(
        relay_after_restart.key_package.bytes(),
        first.key_package.bytes()
    );
    assert_eq!(
        relay_after_restart.key_package_ref_hex,
        first.key_package_ref_hex
    );
    assert_eq!(
        relay_after_restart.key_package_event_id,
        first.key_package_event_id
    );
    assert_eq!(after_restart.stable_slot_id, before.stable_slot_id);
    assert_eq!(
        after_restart.current_key_package_ref,
        before.current_key_package_ref
    );
    assert_eq!(after_restart.authored_event_id, before.authored_event_id);
    assert_eq!(
        after_restart.authored_signed_event,
        before.authored_signed_event
    );
    assert_eq!(
        after_restart.retained_private_material.len(),
        before.retained_private_material.len()
    );
    assert_eq!(
        restarted
            .durably_owned_key_packages(&created.account.account_id_hex)
            .await
            .unwrap()
            .len(),
        durable_before,
        "restart republish must not mint or prune durable private bundles"
    );

    let rotated_bytes = restarted
        .rotate_key_package(&created.account.account_id_hex)
        .await
        .unwrap();
    let after_rotation = restarted
        .key_package_maintenance_status(&created.account.account_id_hex)
        .await
        .unwrap()
        .expect("rotation must promote lifecycle state");
    let relay_after_rotation = restarted_app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    assert_eq!(
        rotated_bytes,
        relay_after_rotation.key_package.bytes().len()
    );
    assert_eq!(after_rotation.stable_slot_id, before.stable_slot_id);
    assert_ne!(
        after_rotation.current_key_package_ref,
        before.current_key_package_ref
    );
    assert_ne!(after_rotation.authored_event_id, before.authored_event_id);
    assert_ne!(
        relay_after_rotation.key_package.bytes(),
        first.key_package.bytes()
    );
    assert_eq!(
        after_rotation.retained_private_material.len(),
        before.retained_private_material.len() + 1,
        "explicit rotation must retain the prior unconsumed private bundle"
    );

    restarted.shutdown().await;
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
async fn account_key_packages_reports_durable_ownership_merges_relay_echo_and_survives_restart() {
    use nostr::prelude::ToBech32;

    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let (relay, url) = mock_relay().await;
    let config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    let first_app = MarmotApp::with_relay_and_config(first_dir.path(), url.clone(), config.clone());
    let second_app = MarmotApp::with_relay_and_config(second_dir.path(), url.clone(), config);
    let first_runtime = MarmotAppRuntime::new(first_app.clone());
    let second_runtime = MarmotAppRuntime::new(second_app);
    let secret = Keys::generate().secret_key().to_bech32().unwrap();
    let setup = |secret: &str| AccountSetupRequest {
        identity: None,
        import_nsec: Some(zeroize::Zeroizing::new(secret.to_owned())),
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_missing_relay_lists: true,
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };

    let first = first_runtime
        .create_or_import_account(setup(&secret))
        .await
        .unwrap();
    second_runtime
        .create_or_import_account(setup(&secret))
        .await
        .unwrap();

    let before_rotation = first_runtime
        .account_key_packages(&first.account.account_id_hex, vec![endpoint(&url)])
        .await
        .unwrap();
    assert_eq!(
        before_rotation
            .iter()
            .filter(|package| package.local && package.relay)
            .count(),
        1,
        "this device's relay echo must merge with its durable local bundle"
    );
    assert_eq!(
        before_rotation
            .iter()
            .filter(|package| !package.local && package.relay)
            .count(),
        1,
        "the other device's package has no private material in this database"
    );

    first_runtime
        .publish_new_key_package(&first.account.account_id_hex)
        .await
        .unwrap();
    let fetched_ref = first_runtime
        .key_package_maintenance_status(&first.account.account_id_hex)
        .await
        .unwrap()
        .and_then(|lifecycle| lifecycle.current_key_package_ref)
        .map(hex::encode)
        .expect("rotation must promote a current locally owned package");
    let after_rotation = first_runtime
        .account_key_packages(&first.account.account_id_hex, vec![endpoint(&url)])
        .await
        .unwrap();
    let rotated = after_rotation
        .iter()
        .filter(|package| package.key_package_ref_hex == fetched_ref)
        .collect::<Vec<_>>();
    assert_eq!(rotated.len(), 1, "local and fetched copies must not split");
    assert!(rotated[0].local);
    assert!(rotated[0].relay);

    first_runtime
        .sign_out(
            &first.account.account_id_hex,
            SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    let while_signed_out = first_runtime
        .account_key_packages(&first.account.account_id_hex, vec![endpoint(&url)])
        .await
        .unwrap();
    let signed_out_rotated = while_signed_out
        .iter()
        .filter(|package| package.key_package_ref_hex == fetched_ref)
        .collect::<Vec<_>>();
    assert_eq!(signed_out_rotated.len(), 1);
    assert!(
        signed_out_rotated[0].local && signed_out_rotated[0].relay,
        "signed-out ownership must be read from durable storage without a worker"
    );

    first_runtime.shutdown().await;
    drop(first_runtime);
    drop(first_app);
    let reopened_app = MarmotApp::with_relay_and_config(
        first_dir.path(),
        url.clone(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let restarted = MarmotAppRuntime::new(reopened_app);
    restarted.reconcile_accounts().await.unwrap();
    let after_restart = restarted
        .account_key_packages(&first.account.account_id_hex, vec![endpoint(&url)])
        .await
        .unwrap();
    let restarted_rotated = after_restart
        .iter()
        .filter(|package| package.key_package_ref_hex == fetched_ref)
        .collect::<Vec<_>>();
    assert_eq!(restarted_rotated.len(), 1);
    assert!(restarted_rotated[0].local);
    assert!(restarted_rotated[0].relay);

    restarted.shutdown().await;
    second_runtime.shutdown().await;
    drop(relay);
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
async fn app_runtime_ignores_invalid_legacy_json_cache_when_publishing() {
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
    // Identity creation now returns at local readiness. Use a worker mutation
    // as a barrier so the asynchronous startup sync and open maintenance have
    // completed before this test injects a synthetic legacy cache file.
    runtime
        .pause_maintenance(&created.account.account_id_hex)
        .await
        .unwrap();
    runtime
        .resume_maintenance(&created.account.account_id_hex)
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
    let published = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();
    let cache: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();

    assert!(republished_bytes > 3);
    assert_eq!(published.key_package.bytes().len(), republished_bytes);
    assert_ne!(published.key_package_id, "legacy-invalid");
    assert_eq!(cache["key_package_id"], "legacy-invalid");
    assert_eq!(cache["key_package_hex"], "010203");

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
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    runtime.catch_up_accounts().await.unwrap();
    let account_sync_attempts = || {
        runtime
            .shared_services()
            .app_performance_telemetry()
            .snapshot()
            .account_sync
            .attempts
    };
    let sync_attempts_before_create = account_sync_attempts();

    // Gate the detached post-create catch-up behind a deterministic barrier:
    // the caller boundary must hold no matter how fast the worker is
    // scheduled, so the assertions below cannot race the catch-up.
    let catch_up_barrier = Arc::new(tokio::sync::Notify::new());
    runtime
        .shared_services()
        .set_create_group_catch_up_barrier(Some(catch_up_barrier.clone()));

    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "runtime intents",
            std::slice::from_ref(&bob.account.account_id_hex),
            Some("initial description".to_owned()),
        )
        .await
        .unwrap();
    assert_eq!(
        account_sync_attempts(),
        sync_attempts_before_create,
        "create_group must return before the repairable account-wide catch-up completes",
    );
    let alice_group = app
        .groups(&alice.account.label)
        .unwrap()
        .into_iter()
        .find(|group| group.group_id_hex == hex::encode(group_id.as_slice()))
        .expect("founder projection is queryable when create returns");
    assert_eq!(alice_group.profile.description, "initial description");
    assert_eq!(
        runtime
            .group_mls_state(&alice.account.account_id_hex, &group_id)
            .await
            .unwrap()
            .epoch,
        1,
        "one invited member should require only the founding epoch transition"
    );
    assert_eq!(
        account_sync_attempts(),
        sync_attempts_before_create,
        "the blocked catch-up must not touch account workers while the caller proceeds",
    );
    catch_up_barrier.notify_one();
    let catch_up_deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if account_sync_attempts() > sync_attempts_before_create {
            break;
        }
        assert!(
            std::time::Instant::now() < catch_up_deadline,
            "post-create catch-up must still complete in the background",
        );
        sleep(Duration::from_millis(25)).await;
    }
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined_group, .. }
                if account_id_hex == &bob_id && joined_group == &group_id
        )
    })
    .await;
    let bob_group = app
        .groups(&bob.account.label)
        .unwrap()
        .into_iter()
        .find(|group| group.group_id_hex == hex::encode(group_id.as_slice()))
        .expect("joiner projected the founding Welcome");
    assert_eq!(bob_group.profile.description, "initial description");

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
    assert_eq!(stream_crypto.policy_max_plaintext_frame_len, Some(4096));

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_delete_group_local_removes_projection_without_publishing_leave() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();
    let bob_id = bob.account.account_id_hex.clone();
    let bob_label = bob.account.label.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice_id,
            "local delete",
            std::slice::from_ref(&bob_id),
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
    accept_group_invite_retrying_busy(&runtime, &bob_id, &group_id)
        .await
        .unwrap();

    let second_group_id = runtime
        .create_group(
            &alice_id,
            "second local delete",
            std::slice::from_ref(&bob_id),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined_group, .. }
                if account_id_hex == &bob_id && joined_group == &second_group_id
        )
    })
    .await;
    accept_group_invite_retrying_busy(&runtime, &bob_id, &second_group_id)
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let second_group_id_hex = hex::encode(second_group_id.as_slice());
    let mut bob_chats = runtime.subscribe_chats(&bob_id, false).await.unwrap();
    assert!(
        bob_chats
            .snapshot
            .iter()
            .any(|group| group.group_id_hex == group_id_hex)
    );
    assert!(
        bob_chats
            .snapshot
            .iter()
            .any(|group| group.group_id_hex == second_group_id_hex)
    );

    runtime
        .send_message(&alice_id, &group_id, b"local rows must be wiped".to_vec())
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "local rows must be wiped"
        )
    })
    .await;

    runtime
        .initialize_chat_read_state(&bob_id, &group_id_hex)
        .unwrap();
    assert!(app.group(&bob_label, &group_id_hex).unwrap().is_some());
    assert!(
        !app.messages_with_query(
            &bob_label,
            AppMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                limit: None,
            },
        )
        .unwrap()
        .is_empty(),
        "fixture must contain group-scoped app events before the wipe"
    );
    assert!(
        !app.timeline_messages_with_query(
            &bob_label,
            TimelineMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages
        .is_empty(),
        "fixture must contain materialized timeline rows before the wipe"
    );

    assert!(
        runtime
            .delete_group_local(&bob_id, &group_id)
            .await
            .unwrap()
    );
    let deleted_chat = wait_for_chat_update(&mut bob_chats, |group| {
        group.group_id_hex == group_id_hex && group.archived
    })
    .await;
    assert!(deleted_chat.archived);
    assert!(
        runtime
            .delete_group_local(&bob_id, &second_group_id)
            .await
            .unwrap()
    );
    let second_deleted_chat = wait_for_chat_update(&mut bob_chats, |group| {
        group.group_id_hex == second_group_id_hex && group.archived
    })
    .await;
    assert!(second_deleted_chat.archived);

    assert!(app.group(&bob_label, &group_id_hex).unwrap().is_none());
    assert!(
        app.group(&bob_label, &second_group_id_hex)
            .unwrap()
            .is_none()
    );
    assert!(
        app.visible_groups(&bob_label)
            .unwrap()
            .iter()
            .all(|group| group.group_id_hex != group_id_hex)
    );
    assert!(
        app.messages_with_query(
            &bob_label,
            AppMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                limit: None,
            },
        )
        .unwrap()
        .is_empty()
    );
    assert!(
        app.timeline_messages_with_query(
            &bob_label,
            TimelineMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages
        .is_empty()
    );

    // Foreground/process recreation must not mistake the deliberately absent
    // projection for an engine/projection tear. Awaiting catch-up also replays
    // the relay's historical group delivery and proves that replay is inert.
    runtime.restart_account(&bob_id).await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    assert!(
        app.group(&bob_label, &group_id_hex).unwrap().is_none(),
        "restart reconciliation must preserve the local deletion"
    );
    assert!(
        app.group(&bob_label, &second_group_id_hex)
            .unwrap()
            .is_none(),
        "restart reconciliation must preserve every deleted group"
    );

    // A full routing rebuild for unrelated account activity must preserve the
    // hidden live routes that can receive a future resurrection message.
    runtime.publish_key_package(&bob_id).await.unwrap();

    // Authenticated MLS state changes are not chat activity and must not make
    // the local projection visible again. The following fresh chat also proves
    // that suppressing this event did not discard the hidden transport route.
    runtime
        .update_group_profile(
            &alice_id,
            &group_id,
            Some("renamed while locally deleted".to_owned()),
            None,
        )
        .await
        .unwrap();
    assert!(
        app.group(&bob_label, &group_id_hex).unwrap().is_none(),
        "non-chat group updates must preserve the local deletion"
    );

    // A causally newer chat message is the explicit resurrection edge. It may
    // arrive in the same wall-clock second because the frontier is the engine's
    // durable ingress order, not a sender-controlled timestamp.
    runtime
        .send_message(
            &alice_id,
            &group_id,
            b"fresh activity restores the projection".to_vec(),
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "fresh activity restores the projection"
        )
    })
    .await;
    assert!(
        app.group(&bob_label, &group_id_hex).unwrap().is_some(),
        "causally newer group activity must restore the app projection"
    );
    assert!(
        app.group(&bob_label, &second_group_id_hex)
            .unwrap()
            .is_none(),
        "fresh activity in one group must not clear another group's frontier"
    );

    let alice_members = runtime.group_members(&alice_id, &group_id).await.unwrap();
    assert!(
        alice_members
            .iter()
            .any(|member| member.member_id_hex == bob_id),
        "local delete must not publish an MLS leave visible to other members"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_serves_member_reads_before_initial_catch_up_completes() {
    // Regression: the account worker must answer read commands as soon as the
    // session is hydrated, WITHOUT blocking on the initial relay catch-up. On
    // iOS the runtime is rebuilt on every foreground resume, so each resume
    // re-runs worker startup; routing the conversation's `Members` read through
    // the catch-up made the first conversation opened take seconds.
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    // Alice creates a group with Bob. Waiting for Bob's GroupJoined guarantees
    // Bob received the welcome over the relay (an inbound delivery), so his
    // persisted transport cursor is advanced to ~now: his next worker startup
    // re-subscribes from there and the catch-up genuinely has to wait
    // (SDK_FIRST_SYNC_WAIT / drain) rather than short-circuiting.
    let group_id = runtime
        .create_group(&alice_id, "fast reads", std::slice::from_ref(&bob_id), None)
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined, .. }
                if account_id_hex == &bob_id && joined == &group_id
        )
    })
    .await;

    // `AccountSync` is recorded only when a worker's catch-up sync COMPLETES.
    let account_sync_attempts = || {
        runtime
            .shared_services()
            .app_performance_telemetry()
            .snapshot()
            .account_sync
            .attempts
    };
    let before_restart = account_sync_attempts();

    // Foreground-resume analog: tear down and rebuild Bob's worker.
    runtime.restart_account(&bob_id).await.unwrap();

    // Deterministic discriminator: in the fixed code `restart_account` returns
    // once the worker is hydrated and command-ready, BEFORE the background
    // catch-up completes — so no new `AccountSync` has been recorded yet. (The
    // catch-up has a >=250ms drain floor, so it cannot have finished in the
    // synchronous gap between `restart_account` returning and this read.) In the
    // pre-fix code, `restart_account`/`reconcile` blocked on the startup sync,
    // so a new `AccountSync` would already be recorded here. No `.await` runs
    // between `restart_account` and this read.
    assert_eq!(
        account_sync_attempts(),
        before_restart,
        "restart must become command-ready before the initial catch-up completes",
    );

    // The bounded chat-list companion read uses the same snapshot during the
    // detached catch-up, so batching does not reintroduce a readiness wait.
    let member_ids_page = timeout(
        Duration::from_secs(2),
        runtime.group_member_ids_page(&bob_id, std::slice::from_ref(&group_id)),
    )
    .await
    .expect("member-id page must not block on the initial catch-up")
    .unwrap();
    assert_eq!(member_ids_page.len(), 1);
    assert!(member_ids_page[0].member_ids_hex.contains(&alice_id));
    assert!(member_ids_page[0].member_ids_hex.contains(&bob_id));
    assert!(
        member_ids_page[0].admin_ids_hex.contains(&alice_id),
        "creator admin identifier must be present on the bounded page"
    );
    assert!(
        !member_ids_page[0].admin_ids_hex.contains(&bob_id),
        "invited member must not be reported as an admin"
    );
    assert_eq!(
        account_sync_attempts(),
        before_restart,
        "member-id page must complete before the initial catch-up finishes",
    );

    // The combined roster read is answered with a session-consistent group
    // record, member list, and MLS state while (or right after) catch-up runs.
    // During the catch-up window it comes from the post-hydration snapshot;
    // afterwards it comes from the live session. Either way it must not block.
    let roster = timeout(
        Duration::from_secs(2),
        runtime.group_roster(&bob_id, &group_id),
    )
    .await
    .expect("roster read must not block on the initial catch-up")
    .unwrap();
    assert_eq!(roster.roster_revision, roster.epoch.saturating_mul(3));
    assert_eq!(roster.self_membership, SelfMembership::Member);
    let roster_member_ids = roster
        .members
        .into_iter()
        .map(|member| member.member_id_hex)
        .collect::<std::collections::HashSet<_>>();
    assert!(
        roster_member_ids.contains(&alice_id) && roster_member_ids.contains(&bob_id),
        "snapshot/live roster read must report the full roster",
    );

    // The existing member-only read remains command-ready as well.
    let members = timeout(
        Duration::from_secs(2),
        runtime.group_members(&bob_id, &group_id),
    )
    .await
    .expect("member read must not block on the initial catch-up")
    .unwrap();
    let member_ids = members
        .into_iter()
        .map(|member| member.member_id_hex)
        .collect::<std::collections::HashSet<_>>();
    assert!(
        member_ids.contains(&alice_id) && member_ids.contains(&bob_id),
        "snapshot/live read must report the full roster",
    );

    // The catch-up is not dropped — it still runs in the background and records
    // its completion.
    let catch_up_deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if account_sync_attempts() > before_restart {
            break;
        }
        assert!(
            std::time::Instant::now() < catch_up_deadline,
            "background catch-up must still complete after readiness",
        );
        sleep(Duration::from_millis(25)).await;
    }

    runtime.shutdown().await;
}

#[tokio::test]
async fn group_roster_reports_left_after_local_leave_without_worker_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice_id,
            "roster leave",
            std::slice::from_ref(&bob_id),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined, .. }
                if account_id_hex == &bob_id && joined == &group_id
        )
    })
    .await;

    let revision_before_leave = runtime
        .group_roster(&bob_id, &group_id)
        .await
        .unwrap()
        .roster_revision;

    runtime.leave_group(&bob_id, &group_id).await.unwrap();

    let roster = runtime.group_roster(&bob_id, &group_id).await.unwrap();
    assert_eq!(
        roster.self_membership,
        SelfMembership::Left,
        "groupRoster must read storage-owned self_membership without restarting the worker"
    );
    assert_ne!(
        roster.roster_revision, revision_before_leave,
        "caller membership changes must invalidate the roster revision"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn group_roster_reports_removed_after_admin_eviction_without_worker_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice_id,
            "roster eviction",
            std::slice::from_ref(&bob_id),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined, .. }
                if account_id_hex == &bob_id && joined == &group_id
        )
    })
    .await;

    let revision_before_eviction = runtime
        .group_roster(&bob_id, &group_id)
        .await
        .unwrap()
        .roster_revision;

    runtime
        .remove_members(&alice_id, &group_id, std::slice::from_ref(&bob_id))
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupEvent(group_event)
                if group_event.account_id_hex == bob_id
                    && matches!(
                        &group_event.event,
                        cgka_traits::engine::GroupEvent::GroupStateChanged {
                            group_id: changed_group,
                            change:
                                cgka_traits::engine::GroupStateChange::MemberRemoved { member },
                            ..
                        } if changed_group == &group_id
                            && hex::encode(member.as_slice()) == bob_id
                    )
        )
    })
    .await;

    let roster = runtime.group_roster(&bob_id, &group_id).await.unwrap();
    assert_eq!(
        roster.self_membership,
        SelfMembership::Removed,
        "groupRoster must read storage-owned self_membership without restarting the worker"
    );
    assert_ne!(
        roster.roster_revision, revision_before_eviction,
        "observed eviction must invalidate the roster revision"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_schedules_audit_tracker_update_after_managed_send() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    app.set_audit_log_settings(AuditLogSettings {
        enabled: true,
        ..Default::default()
    })
    .unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
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
    app.set_audit_log_settings(AuditLogSettings {
        enabled: true,
        ..Default::default()
    })
    .unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
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
    app.set_audit_log_settings(AuditLogSettings {
        enabled: true,
        ..Default::default()
    })
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

    let group_id = runtime
        .create_group("alice", "runtime inbound audit", &["bob".to_owned()], None)
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

/// The epoch-stall backfill arms on a run of undecryptable traffic that carries
/// NO visible `SyncSummary` content, so the summary-gated audit-tracker schedule
/// never fires for it. The arm still records an `epoch_stall_backfill_armed`
/// forensic row, and the runtime worker must push it to the field tracker — a
/// passively-stalled account whose only traffic is undecryptable is exactly the
/// case the field-evidence loop needs to observe.
#[tokio::test]
async fn app_runtime_uploads_armed_backfill_row_without_visible_activity() {
    // Mirrors `EPOCH_STALL_BACKFILL_THRESHOLD` (crate-private): the distinct
    // undecryptable messages at one stalled epoch that arm a backfill.
    const BACKFILL_THRESHOLD: usize = 8;

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let bob_id = home.account("bob").unwrap().account_id_hex;

    let (_relay, app, url) = mock_app(&dir).await;
    app.set_audit_log_settings(AuditLogSettings {
        enabled: true,
        ..Default::default()
    })
    .unwrap();
    let mut bob_setup = app.client("bob").await.unwrap();
    bob_setup.publish_key_package().await.unwrap();
    drop(bob_setup);

    let runtime = MarmotAppRuntime::new(app.clone());
    let mut events = runtime.subscribe();
    let (body_tx, mut body_rx) = mpsc::unbounded_channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(forward_audit_upload_bodies(listener, body_tx));
    runtime
        .set_audit_log_tracker_config(AuditLogTrackerConfig {
            endpoint: Some(format!("http://{addr}/api/v1/audit-logs/")),
            authorization_bearer_token: Some("goggles_backfill_secret".to_owned()),
            source: AuditLogUploadSource::default(),
        })
        .unwrap();
    runtime.start().await.unwrap();

    // bob's managed worker joins the group so it holds a live subscription on
    // which the undecryptable probes below are delivered.
    let group_id = runtime
        .create_group(
            "alice",
            "runtime epoch backfill arm",
            &["bob".to_owned()],
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
    let nostr_group_id_hex = app
        .group("bob", &group_id_hex)
        .unwrap()
        .expect("bob's group projection")
        .nostr_routing
        .nostr_group_id_hex;

    // Arm bob's detector with exactly the threshold of distinct undecryptable
    // messages at his live epoch. Present-dated so they clear any since floor;
    // none yields visible summary content, so the summary-gated schedule stays
    // silent and only the armed-backfill schedule can deliver these rows.
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for arm in 0..BACKFILL_THRESHOLD {
        publish_garbage_group_message(&url, &nostr_group_id_hex, created_at, &format!("arm-{arm}"))
            .await;
    }

    // Wait, across uploads, for the one carrying the armed row. Earlier uploads
    // (e.g. the welcome-join schedule) are drained and ignored.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut carried_armed_row = false;
    while Instant::now() < deadline {
        match timeout(
            deadline.saturating_duration_since(Instant::now()),
            body_rx.recv(),
        )
        .await
        {
            Ok(Some(body)) => {
                if String::from_utf8_lossy(&body).contains("epoch_stall_backfill_armed") {
                    carried_armed_row = true;
                    break;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    assert!(
        carried_armed_row,
        "the runtime must push the epoch_stall_backfill_armed row to the audit \
         tracker even though the arming traffic produced no visible activity",
    );

    server.abort();
    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_coalesces_audit_tracker_updates_while_upload_is_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    app.set_audit_log_settings(AuditLogSettings {
        enabled: true,
        ..Default::default()
    })
    .unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
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
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
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
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
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
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
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
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
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
async fn overlapping_reciprocal_invites_deliver_both_incoming_welcomes() {
    let dir = tempfile::tempdir().unwrap();
    let gate = BlockNextGroupMessages::new();
    let (_relay, app, url) = group_message_blocking_app(&dir, gate.clone()).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = || AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup()).await.unwrap();
    let bob = runtime.create_identity(setup()).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();
    let bob_id = bob.account.account_id_hex.clone();
    let alice_group = runtime
        .create_group(&alice_id, "alice reciprocal invite", &[], None)
        .await
        .unwrap();
    let bob_group = runtime
        .create_group(&bob_id, "bob reciprocal invite", &[], None)
        .await
        .unwrap();
    let mut alice_events = runtime.subscribe();
    let mut bob_events = runtime.subscribe();

    gate.arm(2);
    let alice_runtime = runtime.clone();
    let alice_group_for_invite = alice_group.clone();
    let bob_id_for_invite = bob_id.clone();
    let alice_invite = tokio::spawn(async move {
        alice_runtime
            .invite_members(
                &alice_id,
                &alice_group_for_invite,
                std::slice::from_ref(&bob_id_for_invite),
            )
            .await
    });
    let bob_runtime = runtime.clone();
    let bob_group_for_invite = bob_group.clone();
    let alice_id_for_invite = alice.account.account_id_hex.clone();
    let bob_invite = tokio::spawn(async move {
        bob_runtime
            .invite_members(
                &bob_id,
                &bob_group_for_invite,
                std::slice::from_ref(&alice_id_for_invite),
            )
            .await
    });
    timeout(Duration::from_secs(10), gate.wait_for_blocked(2))
        .await
        .expect("both reciprocal invites should overlap at commit publication");
    gate.release();
    alice_invite
        .await
        .expect("alice invite task should not panic")
        .expect("alice invite should succeed");
    bob_invite
        .await
        .expect("bob invite task should not panic")
        .expect("bob invite should succeed");

    wait_for_event(&mut alice_events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id, .. }
                if account_id_hex == &alice.account.account_id_hex && group_id == &bob_group
        )
    })
    .await;
    wait_for_event(&mut bob_events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id, .. }
                if account_id_hex == &bob.account.account_id_hex && group_id == &alice_group
        )
    })
    .await;

    runtime.shutdown().await;
}

#[tokio::test]
async fn successful_invite_delivers_while_overlapping_invite_fails() {
    let dir = tempfile::tempdir().unwrap();
    let gate = BlockNextGroupMessages::new();
    let (_relay, app, url) = group_message_blocking_app(&dir, gate.clone()).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = || AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup().relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup()).await.unwrap();
    let missing_key_package_member = nostr::Keys::generate().public_key().to_hex();
    let alice_id = alice.account.account_id_hex.clone();
    let bob_id = bob.account.account_id_hex.clone();
    let alice_group = runtime
        .create_group(&alice_id, "successful overlap", &[], None)
        .await
        .unwrap();
    let bob_group = runtime
        .create_group(&bob_id, "failed overlap", &[], None)
        .await
        .unwrap();
    let mut bob_events = runtime.subscribe();

    gate.arm(1);
    let alice_runtime = runtime.clone();
    let alice_group_for_invite = alice_group.clone();
    let bob_id_for_invite = bob_id.clone();
    let successful_invite = tokio::spawn(async move {
        alice_runtime
            .invite_members(
                &alice_id,
                &alice_group_for_invite,
                std::slice::from_ref(&bob_id_for_invite),
            )
            .await
    });
    timeout(Duration::from_secs(10), gate.wait_for_blocked(1))
        .await
        .expect("successful invite should remain in flight at commit publication");

    let failed = runtime
        .invite_members(
            &bob_id,
            &bob_group,
            std::slice::from_ref(&missing_key_package_member),
        )
        .await;
    assert!(
        failed.is_err(),
        "invite without a published KeyPackage must fail"
    );
    gate.release();
    successful_invite
        .await
        .expect("successful invite task should not panic")
        .expect("alice invite should succeed");

    wait_for_event(&mut bob_events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id, .. }
                if account_id_hex == &bob.account.account_id_hex && group_id == &alice_group
        )
    })
    .await;

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
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
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

    let accepted =
        accept_group_invite_retrying_busy(&runtime, &bob.account.account_id_hex, &group_id)
            .await
            .unwrap();
    assert!(!accepted.pending_confirmation);
    assert!(!accepted.archived);

    // The accept path records its caller-visible phase on the runtime's
    // app-performance snapshot (mdk#1303). The retrying helper may have
    // logged busy rejections before this success, so assert the success side
    // only.
    let performance = runtime.app_performance_snapshot();
    assert!(
        performance.group_accept_invite.successes >= 1,
        "accept-invite phase must record the successful accept: {performance:?}"
    );

    let reloaded = app.group(&bob_label, &group_id_hex).unwrap().unwrap();
    assert!(!reloaded.pending_confirmation);
    assert!(!reloaded.archived);

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_readd_after_remove_resurfaces_removed_member_group() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();
    let bob_id = bob.account.account_id_hex.clone();
    let bob_label = bob.account.label.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice_id,
            "readd after remove",
            std::slice::from_ref(&bob_id),
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
    let first_pending = app.group(&bob_label, &group_id_hex).unwrap().unwrap();
    assert!(first_pending.pending_confirmation);
    let first_welcome_id = first_pending.via_welcome_message_id_hex.clone();
    accept_group_invite_retrying_busy(&runtime, &bob_id, &group_id)
        .await
        .unwrap();
    let accepted = app.group(&bob_label, &group_id_hex).unwrap().unwrap();
    assert!(!accepted.pending_confirmation);
    assert!(!accepted.archived);
    assert!(
        runtime
            .group_members(&bob_id, &group_id)
            .await
            .unwrap()
            .iter()
            .any(|member| member.member_id_hex == bob_id),
        "bob should be an active member after accepting the first invite"
    );

    runtime
        .remove_members(&alice_id, &group_id, std::slice::from_ref(&bob_id))
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupEvent(group_event)
                if group_event.account_id_hex == bob_id
                    && matches!(
                        &group_event.event,
                        cgka_traits::engine::GroupEvent::GroupStateChanged {
                            group_id: changed_group,
                            change:
                                cgka_traits::engine::GroupStateChange::MemberRemoved { member }
                                | cgka_traits::engine::GroupStateChange::MemberLeft { member },
                            ..
                        } if changed_group == &group_id
                            && hex::encode(member.as_slice()) == bob_id
                    )
        )
    })
    .await;
    assert!(
        !runtime
            .group_members(&bob_id, &group_id)
            .await
            .unwrap()
            .iter()
            .any(|member| member.member_id_hex == bob_id),
        "bob should be absent from his retained tombstoned record after removal"
    );

    assert!(
        runtime
            .delete_group_local(&bob_id, &group_id)
            .await
            .unwrap()
    );
    assert!(
        app.group(&bob_label, &group_id_hex).unwrap().is_none(),
        "local deletion should hide the retained removed-group projection"
    );

    runtime
        .invite_members(&alice_id, &group_id, std::slice::from_ref(&bob_id))
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

    let readded = app.group(&bob_label, &group_id_hex).unwrap().unwrap();
    assert!(readded.pending_confirmation);
    assert!(!readded.archived);
    assert_eq!(
        readded.welcomer_account_id_hex.as_deref(),
        Some(alice_id.as_str())
    );
    assert_ne!(
        readded.via_welcome_message_id_hex, first_welcome_id,
        "a genuine re-add should carry a fresh Welcome id"
    );
    assert!(
        app.visible_groups(&bob_label)
            .unwrap()
            .iter()
            .any(|group| group.group_id_hex == group_id_hex),
        "the re-added group should be visible instead of stuck in the removed state"
    );
    let bob_members = runtime.group_members(&bob_id, &group_id).await.unwrap();
    assert!(
        bob_members
            .iter()
            .any(|member| member.member_id_hex == bob_id),
        "bob should be a member again after the re-add; got {bob_members:?}"
    );

    accept_group_invite_retrying_busy(&runtime, &bob_id, &group_id)
        .await
        .unwrap();
    runtime
        .send_message(&bob_id, &group_id, b"hello after re-add".to_vec())
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == alice_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "hello after re-add"
        )
    })
    .await;

    runtime.shutdown().await;
}

// Regression test for mdk#178: an external `set_group_archived` must not
// be reverted by the long-lived account worker's stale in-memory snapshot when
// the next inbound delivery re-persists the worker's `AccountState`.
#[tokio::test]
async fn app_runtime_archive_survives_subsequent_inbound_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let bob_id = bob.account.account_id_hex.clone();
    let bob_label = bob.account.label.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "archive persistence",
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

    // Bob archives the chat. This must update the worker's authoritative
    // in-memory state, not just the database.
    let archived = runtime
        .set_group_archived(&bob.account.account_id_hex, &group_id_hex, true)
        .await
        .unwrap();
    assert!(archived.archived);
    assert!(
        app.group(&bob_label, &group_id_hex)
            .unwrap()
            .unwrap()
            .archived
    );

    // A subsequent inbound delivery causes Bob's worker to re-persist its
    // in-memory snapshot via `save_state`. Before the fix, the stale snapshot
    // (archived = false) would clobber the archive flag.
    runtime
        .send_message(
            &alice.account.account_id_hex,
            &group_id,
            b"delivery after archive".to_vec(),
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "delivery after archive"
        )
    })
    .await;

    // The archive flag must survive the delivery.
    let reloaded = app.group(&bob_label, &group_id_hex).unwrap().unwrap();
    assert!(
        reloaded.archived,
        "external archive must not be reverted by the worker's stale in-memory state"
    );
    assert!(
        !app.visible_groups(&bob_label)
            .unwrap()
            .iter()
            .any(|group| group.group_id_hex == group_id_hex),
        "archived chat must stay hidden from the visible chat list"
    );

    runtime.shutdown().await;
}

// Regression for the mdk#178 review: a local-signing account must NEVER
// fall back to a direct `MarmotApp::set_group_archived` write when the account
// worker is unavailable (e.g. a startup/reconcile failure). The direct write
// can race a freshly spawned worker holding the pre-archive snapshot and revert
// the flag again. Only non-local-signing accounts (which can never own a
// worker) are allowed the direct-write path. Here we make the worker
// unavailable by stopping the runtime and assert the toggle surfaces the error
// instead of silently persisting through the bypass.
#[tokio::test]
async fn app_runtime_archive_does_not_direct_write_when_worker_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let bob_id = bob.account.account_id_hex.clone();
    let bob_label = bob.account.label.clone();
    assert!(
        bob.account.local_signing,
        "this regression requires a local-signing account that owns a worker"
    );
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "archive bypass guard",
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
    assert!(
        !app.group(&bob_label, &group_id_hex)
            .unwrap()
            .unwrap()
            .archived
    );

    // Make the worker unavailable for the local-signing account. After shutdown
    // the runtime is stopping, so `worker_commands` fails before any worker
    // command can run.
    runtime.shutdown().await;

    // The archive toggle must propagate the worker error rather than taking the
    // old `Err(_) => direct write` fallback.
    let result = runtime
        .set_group_archived(&bob.account.account_id_hex, &group_id_hex, true)
        .await;
    assert!(
        result.is_err(),
        "local-signing archive toggle must surface the worker error, not direct-write the DB"
    );

    // Critically, the database must be untouched: the bypass path is exactly
    // what reintroduces the stale-snapshot revert this fix eliminates.
    assert!(
        !app.group(&bob_label, &group_id_hex)
            .unwrap()
            .unwrap()
            .archived,
        "archive must not be persisted via the direct-write bypass for a local-signing account"
    );
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
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
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
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupStateUpdated {
                account_id_hex,
                group_id: updated,
                ..
            } if account_id_hex == &bob_id && updated == &group_id
        ) || matches!(
            event,
            MarmotAppEvent::ProjectionUpdated(update)
                if update.account_id_hex == bob_id
                    && update.update.group_id_hex == group_id_hex
        )
    })
    .await;

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

    let group_id = runtime
        .create_group("alice", "live", &["bob".to_owned()], None)
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
            "alice",
            &group_id,
            b"hello through the app runtime".to_vec(),
        )
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

    let health = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let health = runtime.shared_services().relay_plane().relay_health().await;
            if health.directory_active_subscriptions == 1
                && health.directory_completed_subscription_syncs == 1
            {
                break health;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("directory subscriptions should complete asynchronously");
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
    // `create_identity` publishes a default profile (kind-0) for this account at
    // ~now, and the directory keeps only the *newer* of two profiles (ties go to
    // the cached copy, mdk#206). Stamp the test profile a minute ahead so
    // it deterministically wins regardless of how fast `start()` returns —
    // `start()` no longer blocks on the account worker's initial catch-up, so the
    // two profiles can otherwise land in the same wall-clock second and tie. The
    // offset must stay within `directory_max_future_skew` (5 min) or the event is
    // rejected as future-dated.
    publish_profile_at(
        &AccountHome::open(dir.path()),
        &setup.account.label,
        &url,
        "sync-alice",
        test_unix_now_seconds() + 60,
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
async fn directory_sync_worker_caches_follow_edges_without_promoting_follows() {
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

    // The local account's own contact list is ingested and its follow edges are
    // cached on the account's directory entry for bounded search, but the
    // followed pubkey must NOT be promoted into a known directory entry: doing
    // so would feed the unbounded transitive social-graph crawl (mdk#687).
    timeout(Duration::from_secs(5), async {
        loop {
            let cached_follow = app
                .directory_entry_for_account_id(&setup.account.account_id_hex)
                .unwrap()
                .is_some_and(|entry| entry.follows.contains(&followed));
            if cached_follow {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("follow edge cached on the account's own directory entry");

    assert!(
        app.directory_entry_for_account_id(&followed)
            .unwrap()
            .is_none(),
        "ingested follows must not be promoted into known directory entries"
    );
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
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
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
        .await
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
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();

    let mut bob_chats = runtime
        .subscribe_chats(&bob.account.account_id_hex, false)
        .await
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
        .await
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

/// A member send that lands while a peer's rename commit sits in the
/// convergence collection window folds that commit inside the send, so its
/// group events surface through the send's effects rather than the inbound
/// ingest or scheduled-convergence seams. The runtime must still broadcast
/// them: bob's group-state subscription has to observe the rename even though
/// his own send — not a receive — applied it.
///
/// This regression uses explicit test-policy overrides to create the precise
/// post-cutoff/pre-scheduler state. `update_group_profile` completes its
/// cross-account catch-up before returning, proving bob has ingested the
/// rename. The test then lets the 100ms engine cutoff elapse while holding the
/// scheduled worker for 60s. The send is therefore the only operation that can
/// move bob's durable row from the old name to the new one, and the
/// subscription must update within 5s, well before scheduled convergence can
/// provide an alternate broadcasting seam.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn group_state_subscription_observes_rename_applied_during_interleaved_send() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, url) = mock_relay().await;
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        MarmotAppConfig::default()
            .with_allow_loopback_blob_endpoints(true)
            .with_allow_loopback_relay_endpoints(true)
            .with_dev_settlement_quiescence_ms(100)
            .with_dev_scheduled_convergence_delay_ms(60_000),
    );
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice_id,
            "interleaved send",
            std::slice::from_ref(&bob_id),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined, .. }
                if account_id_hex == &bob_id && joined == &group_id
        )
    })
    .await;
    let group_id_hex = hex::encode(group_id.as_slice());

    let mut group_state = runtime
        .subscribe_group_state(&bob_id, &group_id_hex)
        .await
        .unwrap();

    let renamed = "renamed during retained send".to_owned();
    runtime
        .update_group_profile(&alice_id, &group_id, Some(renamed.clone()), None)
        .await
        .unwrap();
    assert_ne!(
        row_title(&app, &bob.account.label, &group_id_hex).as_deref(),
        Some(renamed.as_str()),
        "bob's completed catch-up must retain the rename without applying it"
    );
    sleep(Duration::from_millis(250)).await;
    assert_ne!(
        row_title(&app, &bob.account.label, &group_id_hex).as_deref(),
        Some(renamed.as_str()),
        "the test scheduler delay must hold the post-cutoff rename"
    );

    let summary = runtime
        .send_message(&bob_id, &group_id, b"bob interleaved".to_vec())
        .await
        .unwrap();
    assert!(
        summary.published > 0,
        "the interleaved send must publish rather than queue"
    );
    assert_eq!(
        row_title(&app, &bob.account.label, &group_id_hex).as_deref(),
        Some(renamed.as_str()),
        "the send must synchronously fold the retained rename"
    );

    // After a witnessed fold the retained input is consumed, so scheduled
    // convergence has nothing left to broadcast for this rename: only the
    // send-path observe/broadcast can satisfy this assertion.
    let updated =
        wait_for_group_state_update(&mut group_state, |group| group.profile.name == renamed).await;
    assert_eq!(updated.group_id_hex, group_id_hex);

    runtime.shutdown().await;
}

/// Same interleaving as
/// `group_state_subscription_observes_rename_applied_during_interleaved_send`,
/// but bob's own outbound publish is rejected by the relay. A send that folds
/// the retained rename commit has durably applied it before the publish
/// attempt, so the commit's group events must reach the subscription even
/// when the message itself hard-fails: the witnessed round requires the
/// injected publish error plus the immediate post-send row flip, and the
/// subscription assertion runs while the relay still rejects bob's publishes,
/// so the queued-drain seam stays blocked and cannot deliver the rename on a
/// build that drops send-applied events.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn group_state_subscription_observes_rename_applied_during_failed_send() {
    let dir = tempfile::tempdir().unwrap();
    let reject_armed = Arc::new(AtomicBool::new(false));
    let relay = LocalRelay::new(
        RelayBuilder::default().write_policy(RejectGroupMessagesWhileArmed(reject_armed.clone())),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        MarmotAppConfig::default()
            .with_allow_loopback_blob_endpoints(true)
            .with_allow_loopback_relay_endpoints(true)
            .with_dev_settlement_quiescence_ms(100)
            .with_dev_scheduled_convergence_delay_ms(60_000),
    );
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice_id,
            "failed send fold",
            std::slice::from_ref(&bob_id),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined, .. }
                if account_id_hex == &bob_id && joined == &group_id
        )
    })
    .await;
    let group_id_hex = hex::encode(group_id.as_slice());

    let mut group_state = runtime
        .subscribe_group_state(&bob_id, &group_id_hex)
        .await
        .unwrap();

    let renamed = "renamed during rejected send".to_owned();
    runtime
        .update_group_profile(&alice_id, &group_id, Some(renamed.clone()), None)
        .await
        .unwrap();
    assert_ne!(
        row_title(&app, &bob.account.label, &group_id_hex).as_deref(),
        Some(renamed.as_str()),
        "bob's completed catch-up must retain the rename without applying it"
    );
    sleep(Duration::from_millis(250)).await;
    assert_ne!(
        row_title(&app, &bob.account.label, &group_id_hex).as_deref(),
        Some(renamed.as_str()),
        "the test scheduler delay must hold the post-cutoff rename"
    );

    reject_armed.store(true, Ordering::Relaxed);
    let send_result = runtime
        .send_message(&bob_id, &group_id, b"bob rejected".to_vec())
        .await;
    assert!(
        matches!(send_result, Err(AppError::Publish(_))),
        "the folded send must reach the injected hard-publish failure"
    );
    assert_eq!(
        row_title(&app, &bob.account.label, &group_id_hex).as_deref(),
        Some(renamed.as_str()),
        "the failed send must still synchronously fold the retained rename"
    );

    // The relay still rejects bob's publishes here, so the queued-drain seam
    // cannot rescue the rename: only the send-path observe/broadcast of the
    // failed send can satisfy this assertion.
    let updated =
        wait_for_group_state_update(&mut group_state, |group| group.profile.name == renamed).await;
    assert_eq!(updated.group_id_hex, group_id_hex);
    reject_armed.store(false, Ordering::Relaxed);

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
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
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
        .await
        .unwrap();
    assert!(timeline.take_snapshot().messages.is_empty());

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
        .await
        .unwrap();
    let reopened_snapshot = reopened.take_snapshot();
    assert_eq!(reopened_snapshot.messages.len(), 1);
    assert_eq!(reopened_snapshot.messages[0].direction, "sent");
    assert_eq!(reopened_snapshot.messages[0].sender, alice_id);
    assert_eq!(
        reopened_snapshot.messages[0].plaintext,
        "persist through reopen"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_timeline_subscription_paginates_backwards_through_real_store() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();

    let group_id = runtime
        .create_group(
            &alice_id,
            "runtime pagination",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());

    // Five messages, oldest to newest. (Intra-second `timeline_at` ties are
    // possible, so the test asserts counts/flags/membership, not exact order.)
    for index in 0..5 {
        runtime
            .send_message(&alice_id, &group_id, format!("m{index}").into_bytes())
            .await
            .unwrap();
    }

    let full_query = TimelineMessageQuery {
        group_id_hex: Some(group_id_hex.clone()),
        ..TimelineMessageQuery::default()
    };
    timeout(Duration::from_secs(5), async {
        loop {
            let page = runtime
                .timeline_messages_with_query(&alice_id, full_query.clone())
                .unwrap();
            if page.messages.len() == 5 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("five messages materialized in the store");

    // Subscribe with a window of two: the snapshot holds the two newest, with
    // older history available and no gap to the head.
    let query = TimelineMessageQuery {
        group_id_hex: Some(group_id_hex.clone()),
        pagination: TimelinePagination {
            limit: Some(2),
            ..TimelinePagination::default()
        },
        ..TimelineMessageQuery::default()
    };
    let timeline = runtime
        .subscribe_timeline_messages(&alice_id, query)
        .await
        .unwrap();
    let snapshot = timeline.take_snapshot();
    assert_eq!(snapshot.messages.len(), 2);
    assert!(snapshot.has_more_before);
    assert!(!snapshot.has_more_after);

    // Page backward: the window grows to the four newest, still with older
    // history and no gap to the head.
    let page = timeline.paginate_backwards(2).await.unwrap();
    assert_eq!(page.messages.len(), 4);
    assert!(page.has_more_before);
    assert!(!page.has_more_after);
    assert!(timeline_plaintexts_unique(&page));

    // Page backward again: the whole history is loaded; no more older history.
    let page = timeline.paginate_backwards(2).await.unwrap();
    assert_eq!(page.messages.len(), 5);
    assert!(!page.has_more_before);
    assert!(!page.has_more_after);
    assert!(timeline_plaintexts_unique(&page));
    let loaded: std::collections::BTreeSet<String> = page
        .messages
        .iter()
        .map(|message| message.plaintext.clone())
        .collect();
    assert_eq!(
        loaded,
        ["m0", "m1", "m2", "m3", "m4"]
            .into_iter()
            .map(String::from)
            .collect()
    );

    // A further call past the start is a no-op.
    let page = timeline.paginate_backwards(2).await.unwrap();
    assert_eq!(page.messages.len(), 5);
    assert!(!page.has_more_before);

    runtime.shutdown().await;
}

fn timeline_plaintexts_unique(page: &marmot_app::TimelinePage) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    page.messages
        .iter()
        .all(|message| seen.insert(message.message_id_hex.clone()))
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

/// Current chat-list row title for one group, read fresh from the projection
/// (rebuilt on read after any state save). Used as the durable witness that a
/// group-state commit has been applied locally.
#[cfg(feature = "test-policy-overrides")]
fn row_title(app: &MarmotApp, label: &str, group_id_hex: &str) -> Option<String> {
    app.chat_list_row(label, group_id_hex)
        .unwrap()
        .map(|row| row.title)
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
async fn self_removal_suppresses_account_unread_while_peer_removal_preserves_it() {
    // mdk#573: the projection-only account unread aggregate must exclude
    // groups the local account left / was removed from, but a peer removal must
    // leave the observer's own unread untouched.
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice_account = home.create_account("alice").unwrap();
    let bob_account = home.create_account("bob").unwrap();
    let carol_account = home.create_account("carol").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();
    let mut carol = app.client("carol").await.unwrap();
    carol.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice
        .create_group("departures", &["bob", "carol"])
        .await
        .unwrap();
    bob.sync().await.unwrap();
    carol.sync().await.unwrap();

    let group_id_hex = hex::encode(group_id.as_slice());

    // Establish a read baseline on existing history for bob and carol, then send
    // a fresh message so it lands as unread for both observers. `timeline_at` is
    // second-granular and the read watermark is set from the baseline message's
    // timestamp, so the unread message must land in a strictly later second to
    // advance past the watermark; wait out the current second before sending it.
    alice.send(&group_id, b"baseline").await.unwrap();
    bob.sync().await.unwrap();
    carol.sync().await.unwrap();
    app.initialize_chat_read_state("bob", &group_id_hex)
        .unwrap();
    app.initialize_chat_read_state("carol", &group_id_hex)
        .unwrap();

    sleep(Duration::from_millis(1100)).await;
    alice.send(&group_id, b"unread one").await.unwrap();

    let unread_for = |account_id_hex: &str| {
        app.account_unread_summary()
            .unwrap()
            .into_iter()
            .find(|summary| summary.account_id_hex == account_id_hex)
            .map(|summary| summary.unread_count)
            .unwrap_or(0)
    };

    // Relay delivery is asynchronous, so a single `sync()` poll can return before
    // the message lands. Poll each observer until the expected unread state
    // materializes (bounded by a deadline) so the test is order-independent under
    // CI's serial `--test-threads=1` run.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        bob.sync().await.unwrap();
        carol.sync().await.unwrap();
        if unread_for(&bob_account.account_id_hex) == 1
            && unread_for(&carol_account.account_id_hex) == 1
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for bob and carol to each register one unread before any removal"
        );
        sleep(Duration::from_millis(50)).await;
    }
    let _ = &alice_account;

    // Alice removes carol. From carol's perspective this is a self-removal; from
    // bob's it is a peer removal.
    alice.remove_members(&group_id, &["carol"]).await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        bob.sync().await.unwrap();
        carol.sync().await.unwrap();
        // carol's self-removal must zero her summary; bob's peer-removal view must
        // leave his own unread untouched.
        if unread_for(&carol_account.account_id_hex) == 0
            && unread_for(&bob_account.account_id_hex) == 1
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for carol's self-removal to suppress while bob's count is preserved"
        );
        sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(
        unread_for(&carol_account.account_id_hex),
        0,
        "carol's self-removal must suppress her account unread total"
    );
    assert_eq!(
        unread_for(&bob_account.account_id_hex),
        1,
        "a peer removal must not suppress bob's own account unread total"
    );
}

#[tokio::test]
async fn local_leave_suppresses_account_unread_total() {
    // mdk#573 review follow-up: a locally initiated leave departs the
    // group just like an observed self-removal, but the leaver's own relay echo
    // is skipped, so `observe_account_device_effects` never fires for it. The
    // leave path itself must suppress the account unread aggregate, otherwise a
    // frozen unread row for the left group keeps inflating the leaver's total.
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob_account = home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("departures", &["bob"]).await.unwrap();
    bob.sync().await.unwrap();

    let group_id_hex = hex::encode(group_id.as_slice());

    // Establish a read baseline for bob, then send a fresh message in a strictly
    // later second so it advances past the second-granular read watermark and
    // lands as unread.
    alice.send(&group_id, b"baseline").await.unwrap();
    bob.sync().await.unwrap();
    app.initialize_chat_read_state("bob", &group_id_hex)
        .unwrap();

    sleep(Duration::from_millis(1100)).await;
    alice.send(&group_id, b"unread one").await.unwrap();

    let unread_for = |account_id_hex: &str| {
        app.account_unread_summary()
            .unwrap()
            .into_iter()
            .find(|summary| summary.account_id_hex == account_id_hex)
            .map(|summary| summary.unread_count)
            .unwrap_or(0)
    };

    // Poll until bob registers the unread before leaving.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        bob.sync().await.unwrap();
        if unread_for(&bob_account.account_id_hex) == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for bob to register one unread before leaving"
        );
        sleep(Duration::from_millis(50)).await;
    }

    // Bob leaves the group locally. No inbound sync observes his own departure,
    // so the leave path must suppress his account unread aggregate directly.
    bob.leave_group(&group_id).await.unwrap();

    assert_eq!(
        unread_for(&bob_account.account_id_hex),
        0,
        "a local leave must suppress the leaver's frozen account unread total"
    );

    // The same leave records the chat-list row as a voluntary `Left` (not an
    // involuntary `Removed`), end to end through the projection refresh, so the
    // chat list can label the departure.
    let bob_row = app
        .chat_list("bob", true)
        .unwrap()
        .into_iter()
        .find(|row| row.group_id_hex == group_id_hex)
        .expect("bob's chat-list row survives the leave");
    assert_eq!(bob_row.self_membership, SelfMembership::Left);
}

#[tokio::test]
async fn pending_leave_request_survives_a_cold_launch() {
    // The durable `LeaveRequest` is recorded before the leave publishes, but
    // nothing above the engine could see it, so a cold launch could not
    // rediscover the intent.
    //
    // The two states are orthogonal, and this pins that: `self_membership`
    // becomes `Left` as soon as the proposal publishes (the local classification
    // of a voluntary departure), while the request stays outstanding until some
    // member commits the SelfRemove — which in this two-party group alice never
    // does. So `Left` and a pending request coexist here, and a host must read
    // the pending flag rather than infer resolution from `Left`.
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice
        .create_group("pending departures", &["bob"])
        .await
        .unwrap();
    bob.sync().await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());

    // Nothing pending before the leave.
    assert_eq!(
        app.chat_list_row("bob", &group_id_hex)
            .unwrap()
            .expect("bob's row exists before the leave")
            .leave_requested_at_ms,
        None
    );

    bob.leave_group(&group_id).await.unwrap();
    drop(bob);
    drop(alice);

    // Alice has not committed the SelfRemove yet, so the request is still
    // outstanding even though the local projection optimistically reads `Left`.
    let row = app
        .chat_list_row("bob", &group_id_hex)
        .unwrap()
        .expect("bob's row survives the leave");
    let requested_at = row
        .leave_requested_at_ms
        .expect("the durable leave request must be visible on the chat-list row");
    assert!(
        requested_at > 0,
        "requested_at_ms should be a real clock reading"
    );
    // The documented coexistence, asserted rather than merely narrated: an
    // optimistic `Left` alongside an unresolved request. If a future change made
    // `Left` imply resolution, this is what would catch it.
    assert_eq!(
        row.self_membership,
        SelfMembership::Left,
        "a published leave classifies as Left immediately, while the request stays pending"
    );
    let group = app
        .group("bob", &group_id_hex)
        .unwrap()
        .expect("bob's group record survives the leave");
    assert_eq!(group.leave_requested_at_ms, Some(requested_at));

    // Cold launch: a fresh `MarmotApp` over the same directory, as if the process
    // had been terminated mid-leave. This is the case that was previously
    // unrecoverable.
    drop(app);
    let reopened = MarmotApp::with_relay_and_config(
        dir.path(),
        url,
        MarmotAppConfig::default()
            .with_allow_loopback_blob_endpoints(true)
            .with_allow_loopback_relay_endpoints(true),
    );
    assert_eq!(
        reopened
            .chat_list_row("bob", &group_id_hex)
            .unwrap()
            .expect("bob's row survives the reopen")
            .leave_requested_at_ms,
        Some(requested_at),
        "a cold launch must rediscover the pending leave intent"
    );
    assert_eq!(
        reopened
            .group("bob", &group_id_hex)
            .unwrap()
            .expect("bob's group record survives the reopen")
            .leave_requested_at_ms,
        Some(requested_at)
    );
    assert_eq!(
        reopened
            .pending_leave_requests("bob")
            .unwrap()
            .get(&group_id_hex),
        Some(&requested_at)
    );
}

#[tokio::test]
async fn open_backfill_preserves_unread_for_still_member_account() {
    // mdk#573 review follow-up (blocking finding 1): the one-time
    // open/upgrade backfill derives `self_membership` from current engine
    // state for rows that predate migration 0018. It must only suppress groups
    // the local account is no longer a member of — a still-member account that
    // reopens must keep its unread counted (uncertainty / membership never
    // suppresses). This exercises the open-path wiring + the no-op/idempotent
    // direction; the removed-roster direction is unit-tested over the pure
    // `local_account_removed_from_roster` decision.
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob_account = home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("backfill", &["bob"]).await.unwrap();
    bob.sync().await.unwrap();

    let group_id_hex = hex::encode(group_id.as_slice());

    // Establish a read baseline, then send a strictly-later unread message.
    alice.send(&group_id, b"baseline").await.unwrap();
    bob.sync().await.unwrap();
    app.initialize_chat_read_state("bob", &group_id_hex)
        .unwrap();
    sleep(Duration::from_millis(1100)).await;
    alice.send(&group_id, b"unread one").await.unwrap();

    let unread_for = |account_id_hex: &str| {
        app.account_unread_summary()
            .unwrap()
            .into_iter()
            .find(|summary| summary.account_id_hex == account_id_hex)
            .map(|summary| summary.unread_count)
            .unwrap_or(0)
    };

    // Poll until bob registers the unread.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        bob.sync().await.unwrap();
        if unread_for(&bob_account.account_id_hex) == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for bob to register one unread"
        );
        sleep(Duration::from_millis(50)).await;
    }

    // Reopen bob's account. `client()` runs the one-time backfill on open. Bob
    // is still a member, so the backfill must derive 'member' (no suppression)
    // and the unread stays counted.
    drop(bob);
    let _bob_reopened = app.client("bob").await.unwrap();
    assert_eq!(
        unread_for(&bob_account.account_id_hex),
        1,
        "open backfill must not suppress unread for an account still in the roster"
    );

    // A second reopen is gated by the once-only marker and likewise preserves
    // the count (idempotent, projection-only hot path).
    drop(_bob_reopened);
    let _bob_reopened_again = app.client("bob").await.unwrap();
    assert_eq!(
        unread_for(&bob_account.account_id_hex),
        1,
        "repeat open must remain a no-op for a still-member account"
    );
}

#[tokio::test]
async fn failed_send_keeps_read_marker_and_inbound_unread() {
    // mdk#338: the local-send projection recorded BEFORE publish must not
    // advance the per-group read marker. If it did, a hard publish failure
    // would leave the marker pointing at the invalidated own message and
    // silently mark older inbound unreads as read. Only the post-publish
    // success projection may advance the marker.
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob_account = home.create_account("bob").unwrap();

    let (relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("markers", &["bob"]).await.unwrap();
    bob.sync().await.unwrap();

    let group_id_hex = hex::encode(group_id.as_slice());
    let bob_row = || {
        app.chat_list_row("bob", &group_id_hex)
            .unwrap()
            .expect("bob's chat-list row exists after joining")
    };

    // Phase 1: a SUCCESSFUL own send must still advance bob's read marker to
    // his own event id — the marker advance is deferred to the post-publish
    // projection, so this guards that it still fires on success.
    let bob_success_id = bob
        .send(&group_id, b"bob success")
        .await
        .unwrap()
        .message_ids[0]
        .clone();
    assert_eq!(
        bob_row().last_read_message_id_hex.as_deref(),
        Some(bob_success_id.as_str()),
        "a successful own send must advance the sender's read marker to his own event"
    );

    // `timeline_at` is second-granular and the unread window is strictly after
    // the marker tuple, so each subsequent message must land in a strictly
    // later second to register past the previous watermark.
    sleep(Duration::from_millis(1100)).await;
    let read_baseline_id = alice
        .send(&group_id, b"baseline")
        .await
        .unwrap()
        .message_ids[0]
        .clone();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        bob.sync().await.unwrap();
        if bob_row().unread_count == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for bob to register alice's baseline as unread"
        );
        sleep(Duration::from_millis(50)).await;
    }
    app.mark_timeline_message_read("bob", &group_id_hex, &read_baseline_id)
        .unwrap();
    let row = bob_row();
    assert_eq!(
        row.last_read_message_id_hex.as_deref(),
        Some(read_baseline_id.as_str())
    );
    assert_eq!(row.unread_count, 0);

    sleep(Duration::from_millis(1100)).await;
    let inbound_unread_id = alice
        .send(&group_id, b"inbound unread")
        .await
        .unwrap()
        .message_ids[0]
        .clone();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        bob.sync().await.unwrap();
        if bob_row().unread_count == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for bob to register the inbound unread"
        );
        sleep(Duration::from_millis(50)).await;
    }

    // Hard publish failure: no relay left to accept bob's message. The failed
    // attempt can take up to the adapter's ~20s publish overall-wait
    // (SDK_RELAY_PUBLISH_OVERALL_WAIT) before it reports the failure.
    relay.shutdown();
    bob.send(&group_id, b"bob failure")
        .await
        .expect_err("send must fail once the relay is gone");

    let row = bob_row();
    assert_eq!(
        row.unread_count, 1,
        "a failed send must not mark inbound unreads as read"
    );
    assert_eq!(
        row.last_read_message_id_hex.as_deref(),
        Some(read_baseline_id.as_str()),
        "a failed send must leave the read marker untouched, never at the failed event"
    );
    assert_eq!(
        row.first_unread_message_id_hex.as_deref(),
        Some(inbound_unread_id.as_str()),
        "the first unread must still be alice's inbound message"
    );
    let account_unread = app
        .account_unread_summary()
        .unwrap()
        .into_iter()
        .find(|summary| summary.account_id_hex == bob_account.account_id_hex)
        .map(|summary| summary.unread_count)
        .unwrap_or(0);
    assert_eq!(
        account_unread, 1,
        "the account-level unread aggregate must survive the failed send"
    );
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
    assert!(
        !alice_sync.events.iter().any(|event| matches!(
            event,
            cgka_traits::GroupEvent::GroupStateChanged {
                group_id: removed_group,
                change:
                    cgka_traits::GroupStateChange::MemberRemoved { .. }
                    | cgka_traits::GroupStateChange::MemberLeft { .. },
                ..
            } if removed_group == &group_id
        )),
        "sync should observe the SelfRemove proposal and schedule convergence, not publish immediately"
    );

    sleep(Duration::from_millis(75)).await;
    let convergence = alice.retry_group_convergence(&group_id).await.unwrap();
    assert_eq!(convergence.published, 1);
    assert_eq!(alice.members(&group_id).unwrap().len(), 1);

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
async fn relay_app_runtime_synthesizes_system_row_for_retention_change() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let alice_id = home.account("alice").unwrap().account_id_hex;
    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("ops", &["bob"]).await.unwrap();
    bob.sync().await.unwrap();

    alice.update_message_retention(&group_id, 60).await.unwrap();

    let alice_timeline = MarmotApp::with_relay(dir.path(), url.clone())
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group_id.as_slice())),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    let retention_row = alice_timeline
        .messages
        .iter()
        .find(|message| {
            message.kind == cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
                && message.plaintext.contains("disappearing_timer_changed")
        })
        .unwrap_or_else(|| {
            panic!(
                "alice's timeline should contain a kind-1210 retention row; got {:?}",
                alice_timeline.messages
            )
        });
    let parsed =
        marmot_app::group_system_event_from_message(retention_row.kind, &retention_row.plaintext)
            .expect("typed group-system payload");

    assert_eq!(parsed.system_type, "disappearing_timer_changed");
    assert_eq!(
        parsed.actor_account_id_hex.as_deref(),
        Some(alice_id.as_str())
    );
    assert_eq!(parsed.old_retention_seconds, Some(0));
    assert_eq!(parsed.new_retention_seconds, Some(60));

    bob.sync().await.unwrap();
    let bob_timeline = MarmotApp::with_relay(dir.path(), url)
        .timeline_messages_with_query(
            "bob",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group_id.as_slice())),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    let bob_retention_row = bob_timeline
        .messages
        .iter()
        .find(|message| {
            message.kind == cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
                && message.plaintext.contains("disappearing_timer_changed")
        })
        .unwrap_or_else(|| {
            panic!(
                "bob's timeline should contain an inbound kind-1210 retention row; got {:?}",
                bob_timeline.messages
            )
        });
    let bob_parsed = marmot_app::group_system_event_from_message(
        bob_retention_row.kind,
        &bob_retention_row.plaintext,
    )
    .expect("typed group-system payload");

    assert_eq!(bob_parsed.system_type, "disappearing_timer_changed");
    assert_eq!(
        bob_parsed.actor_account_id_hex.as_deref(),
        Some(alice_id.as_str())
    );
    assert_eq!(bob_parsed.old_retention_seconds, Some(0));
    assert_eq!(bob_parsed.new_retention_seconds, Some(60));
}

#[tokio::test]
async fn app_runtime_retention_sweep_prunes_with_the_supplied_clock() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice
        .create_group("retention sweep", &["bob"])
        .await
        .unwrap();
    alice.update_message_retention(&group_id, 60).await.unwrap();
    alice
        .send(&group_id, b"expire through runtime")
        .await
        .unwrap();
    drop(alice);
    drop(bob);

    let runtime = MarmotAppRuntime::new(app);
    runtime.start().await.unwrap();
    let supplied_now_seconds = test_unix_now_seconds().saturating_add(120);
    let report = runtime
        .sweep_expired_retention("alice", supplied_now_seconds.saturating_mul(1_000))
        .await
        .unwrap();

    assert_eq!(report.groups.len(), 1);
    let outcome = &report.groups[0];
    assert_eq!(outcome.group_id_hex, hex::encode(group_id.as_slice()));
    assert_eq!(outcome.status, RetentionSweepStatus::Pruned);
    assert!(outcome.pruned_messages > 0);
    assert_eq!(outcome.failure_kind, None);

    runtime.shutdown().await;
}

#[tokio::test]
async fn relay_app_runtime_synthesizes_initial_retention_row_on_join() {
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

    let alice_id = home.account("alice").unwrap().account_id_hex;
    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("ops", &["bob"]).await.unwrap();
    bob.sync().await.unwrap();
    alice.update_message_retention(&group_id, 60).await.unwrap();
    bob.sync().await.unwrap();

    alice.invite_members(&group_id, &["carol"]).await.unwrap();
    carol.sync().await.unwrap();

    let carol_timeline = MarmotApp::with_relay(dir.path(), url)
        .timeline_messages_with_query(
            "carol",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group_id.as_slice())),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    let retention_row = carol_timeline
        .messages
        .iter()
        .find(|message| {
            message.kind == cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
                && message.plaintext.contains("disappearing_timer_changed")
        })
        .unwrap_or_else(|| {
            panic!(
                "carol's timeline should contain initial retention row on join; got {:?}",
                carol_timeline.messages
            )
        });
    let parsed =
        marmot_app::group_system_event_from_message(retention_row.kind, &retention_row.plaintext)
            .expect("typed group-system payload");

    assert_eq!(parsed.system_type, "disappearing_timer_changed");
    assert_eq!(
        parsed.actor_account_id_hex.as_deref(),
        Some(alice_id.as_str())
    );
    assert_eq!(parsed.old_retention_seconds, Some(0));
    assert_eq!(parsed.new_retention_seconds, Some(60));
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
                    value: format!("https://media.example/{}.bin", hex::encode([0x11_u8; 32])),
                }],
                ciphertext_sha256: hex::encode([0x11_u8; 32]),
                plaintext_sha256: hex::encode([0x42_u8; 32]),
                nonce_hex: hex::encode([0x24_u8; 12]),
                file_name: "diagram.png".to_owned(),
                media_type: "image/png".to_owned(),
                version: "encrypted-media-v2".to_owned(),
                source_epoch: 0,
                dim: Some("800x600".to_owned()),
                thumbhash: Some("1QcSHQRnh493V4dIh4eXh1h4kJUI".to_owned()),
            },
            MediaAttachmentReference {
                locators: vec![MediaLocator {
                    kind: "blossom-v1".to_owned(),
                    value: format!("https://media.example/{}.bin", hex::encode([0x12_u8; 32])),
                }],
                ciphertext_sha256: hex::encode([0x12_u8; 32]),
                plaintext_sha256: hex::encode([0x43_u8; 32]),
                nonce_hex: hex::encode([0x25_u8; 12]),
                file_name: "audio.ogg".to_owned(),
                media_type: "audio/ogg".to_owned(),
                version: "encrypted-media-v2".to_owned(),
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
    assert!(imeta.iter().any(|field| field
        == &format!(
            "locator blossom-v1 https://media.example/{}.bin",
            hex::encode([0x11_u8; 32])
        )));
    assert!(imeta.iter().any(|field| field == "m image/png"));
    assert!(imeta.iter().any(|field| field == "filename diagram.png"));
    assert!(
        imeta
            .iter()
            .any(|field| field == "nonce 242424242424242424242424")
    );
    assert!(imeta.iter().any(|field| field == "v encrypted-media-v2"));
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
                    value: format!("https://media.example/{}.bin", hex::encode([0x11_u8; 32])),
                }],
                ciphertext_sha256: hex::encode([0x11_u8; 32]),
                plaintext_sha256: "not-hex".to_owned(),
                nonce_hex: hex::encode([0x24_u8; 12]),
                file_name: "diagram.png".to_owned(),
                media_type: "image/png".to_owned(),
                version: "encrypted-media-v2".to_owned(),
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
        group_state
            .required_app_components
            .contains(&GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID),
        "encrypted media v2 is a required app component"
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
    assert_eq!(reference.version, "encrypted-media-v2");
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

    let optimistic_tag = alice
        .build_media_imeta_tag(&group_id, &reference)
        .await
        .expect("current group accepts its V2 upload reference");
    assert!(
        optimistic_tag
            .iter()
            .any(|field| field == "v encrypted-media-v2")
    );
    let mut wrong_version = reference.clone();
    wrong_version.version = "encrypted-media-v1".to_owned();
    let mismatch = alice
        .build_media_imeta_tag(&group_id, &wrong_version)
        .await
        .expect_err("current group must reject a V1 optimistic reference");
    assert!(mismatch.to_string().contains("requires encrypted-media-v2"));

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
    assert!(imeta.iter().any(|field| field == "v encrypted-media-v2"));
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
async fn retained_media_rehydrates_a_retired_current_epoch_before_the_group_advances() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let blossom = mock_blossom().await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice
        .create_group("retired media epoch", &["bob"])
        .await
        .unwrap();
    bob.sync().await.unwrap();
    alice.update_message_retention(&group_id, 2).await.unwrap();
    bob.sync().await.unwrap();

    let expired = alice
        .upload_media(
            &group_id,
            MediaUploadRequest {
                attachments: vec![MediaUploadAttachmentRequest {
                    file_name: "expired.txt".to_owned(),
                    media_type: "text/plain".to_owned(),
                    plaintext: b"expired media".to_vec(),
                    dim: None,
                    thumbhash: None,
                }],
                caption: None,
                send: true,
                blossom_server: Some(blossom.url.clone()),
            },
        )
        .await
        .unwrap();
    let expired_reference = expired.attachments[0].reference.clone();
    let expired_source_epoch = expired_reference.source_epoch;
    bob.sync().await.unwrap();

    sleep(Duration::from_secs(3)).await;
    let pruned = bob
        .secure_delete_expired_plaintext_for_group(&group_id)
        .unwrap();
    assert!(pruned.pruned_messages > 0);
    assert!(
        bob.download_media(&group_id, expired_reference.clone())
            .await
            .is_err(),
        "a retired source epoch must not be re-derived from live MLS state"
    );
    drop(bob);
    let mut bob = app.client("bob").await.unwrap();
    assert!(
        bob.download_media(&group_id, expired_reference)
            .await
            .is_err(),
        "a retired source epoch must stay unavailable after restart"
    );

    let retained_plaintext = b"retained after epoch retirement".to_vec();
    let retained = alice
        .upload_media(
            &group_id,
            MediaUploadRequest {
                attachments: vec![MediaUploadAttachmentRequest {
                    file_name: "retained.txt".to_owned(),
                    media_type: "text/plain".to_owned(),
                    plaintext: retained_plaintext.clone(),
                    dim: None,
                    thumbhash: None,
                }],
                caption: None,
                send: true,
                blossom_server: Some(blossom.url.clone()),
            },
        )
        .await
        .unwrap();
    let retained_reference = retained.attachments[0].reference.clone();
    assert_eq!(
        retained_reference.source_epoch, expired_source_epoch,
        "the retained message must reuse the retired epoch for this regression"
    );
    alice
        .update_group_profile(&group_id, Some("advanced after media"), None)
        .await
        .unwrap();

    bob.sync().await.unwrap();
    let download = bob
        .download_media(&group_id, retained_reference)
        .await
        .expect("retained media must preserve its source-epoch secret across the next commit");
    assert_eq!(download.plaintext, retained_plaintext);
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

    let initial_group = app.group("alice", &group_id_hex).unwrap().unwrap();
    let initial_endpoints = initial_group
        .encrypted_media
        .default_blob_endpoints
        .iter()
        .map(|endpoint| endpoint.base_url.as_str())
        .collect::<Vec<_>>();
    // Host builds may compile in MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS, so
    // expect whichever list the client actually embeds.
    let configured = marmot_app::MarmotServiceEndpoints::compiled().encrypted_media_blob_endpoints;
    let expected_endpoints = if configured.is_empty() {
        marmot_app::DEFAULT_BLOSSOM_SERVER_URLS
            .iter()
            .map(|endpoint| (*endpoint).to_owned())
            .collect::<Vec<_>>()
    } else {
        configured
    };
    assert_eq!(
        initial_endpoints
            .iter()
            .map(|endpoint| endpoint.trim_end_matches('/'))
            .collect::<Vec<_>>(),
        expected_endpoints
            .iter()
            .map(|endpoint| endpoint.trim_end_matches('/'))
            .collect::<Vec<_>>()
    );

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
        // WHATWG normalization (group-encrypted-media-v1.md) serializes an empty
        // path as `/`, so the stored canonical endpoint URL carries the slash.
        "https://media.example/"
    );
}

#[tokio::test]
async fn upload_media_errors_when_policy_has_no_blossom_endpoint() {
    // PR #328 review Finding 1: `upload_encrypted_media` always performs Blossom
    // upload semantics, so `upload_media` MUST select a `blossom-v1` policy
    // endpoint. A group whose policy lists only a non-Blossom endpoint has no
    // usable upload target, so the upload MUST fail early rather than push
    // Blossom bytes to the wrong backend.
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let blossom = mock_blossom().await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice
        .create_group("non-blossom media", &["bob"])
        .await
        .unwrap();
    bob.sync().await.unwrap();

    // Replace the default Blossom policy with one that serves only a non-Blossom
    // locator kind. `replace_encrypted_media_blob_endpoints` derives
    // `allowed_locator_kinds` from the endpoint kinds, so the resulting policy
    // allows `ipfs-v1` only and has no Blossom endpoint.
    alice
        .replace_encrypted_media_blob_endpoints(
            &group_id,
            vec![marmot_app::AppBlobEndpoint {
                locator_kind: "ipfs-v1".to_owned(),
                base_url: "https://ipfs.example".to_owned(),
            }],
        )
        .await
        .unwrap();

    let error = alice
        .upload_media(
            &group_id,
            MediaUploadRequest {
                attachments: vec![MediaUploadAttachmentRequest {
                    file_name: "note.txt".to_owned(),
                    media_type: "text/plain".to_owned(),
                    plaintext: b"bytes that must never be uploaded".to_vec(),
                    dim: None,
                    thumbhash: None,
                }],
                caption: None,
                // An explicit Blossom override is the dev escape hatch, but it
                // does not relax the requirement that the group policy actually
                // allow Blossom uploads; the chosen default endpoint must still
                // be a Blossom endpoint.
                send: false,
                blossom_server: Some(blossom.url.clone()),
            },
        )
        .await
        .expect_err("upload must fail when the group policy has no Blossom endpoint");
    assert!(
        error.to_string().contains("Blossom endpoint"),
        "expected a no-usable-Blossom-endpoint error, got: {error}"
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
async fn relay_app_nip65_getter_setter_round_trip_preserves_roles() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (_seed, app, seed_url) = mock_app(&dir).await;
    let read_only_url = "wss://read-only.example".to_owned();

    let status = app
        .publish_account_nip65_relay_set(
            "alice",
            vec![endpoint(&seed_url), endpoint(&read_only_url)],
            vec![endpoint(&seed_url)],
            vec![endpoint(&seed_url)],
        )
        .await
        .unwrap();
    assert_eq!(
        status.nip65.read_relays,
        vec![seed_url.clone(), read_only_url.clone()]
    );
    assert_eq!(status.nip65.write_relays, vec![seed_url.clone()]);

    let editable_relays = app.account_nip65_relays("alice").unwrap();
    assert_eq!(
        editable_relays,
        vec![seed_url.clone(), read_only_url.clone()]
    );
    let status = app
        .set_account_nip65_relays(
            "alice",
            editable_relays.into_iter().map(TransportEndpoint).collect(),
            vec![endpoint(&seed_url)],
        )
        .await
        .unwrap();

    assert_eq!(
        status.nip65.read_relays,
        vec![seed_url.clone(), read_only_url]
    );
    assert_eq!(status.nip65.write_relays, vec![seed_url]);
}

#[tokio::test]
async fn relay_list_fetch_only_uses_requested_bootstrap_relays_without_cache() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (seed_a, seed_a_url) = mock_relay().await;
    let (seed_b, seed_b_url) = mock_relay().await;
    let _relays = (seed_a, seed_b);
    let app = MarmotApp::with_relay(dir.path(), seed_a_url.clone());

    publish_account_relay_lists_at(
        &home,
        "alice",
        &seed_a_url,
        &seed_a_url,
        test_unix_now_seconds(),
    )
    .await;

    let account_id = home.account("alice").unwrap().account_id_hex;
    let missing_from_seed_b = app
        .fetch_account_relay_list_status_for_account_id(&account_id, vec![endpoint(&seed_b_url)])
        .await
        .unwrap();

    assert!(!missing_from_seed_b.complete);
    assert_eq!(
        missing_from_seed_b.missing,
        vec![MissingRelayListKind::Nip65, MissingRelayListKind::Inbox]
    );
    assert_eq!(missing_from_seed_b.bootstrap_relays, vec![seed_b_url]);
}

#[tokio::test]
async fn relay_list_empty_fetch_keeps_cached_lists() {
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
async fn import_ignores_retired_published_routes_without_rewriting_relay_lists() {
    use nostr::prelude::ToBech32;

    let publisher_dir = tempfile::tempdir().unwrap();
    let publisher_home = AccountHome::open(publisher_dir.path());
    let keys = Keys::generate();
    let secret_hex = keys.secret_key().to_secret_hex();
    let secret_nsec = keys.secret_key().to_bech32().unwrap();
    publisher_home
        .import_account("publisher", &secret_hex)
        .unwrap();

    let (_relay, relay_url) = mock_relay().await;
    publish_account_relay_lists_at(
        &publisher_home,
        "publisher",
        &relay_url,
        "wss://relay.damus.io",
        test_unix_now_seconds(),
    )
    .await;

    let app_dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay_and_config(
        app_dir.path(),
        relay_url.clone(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let runtime = MarmotAppRuntime::new(app.clone());
    let imported = runtime
        .create_or_import_account(AccountSetupRequest {
            import_nsec: Some(zeroize::Zeroizing::new(secret_nsec)),
            default_relays: vec![endpoint(&relay_url)],
            bootstrap_relays: vec![endpoint(&relay_url)],
            discovery_relays: vec![endpoint(&relay_url)],
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .expect("a retired published relay must not block account import");

    assert!(imported.relay_lists.complete);
    assert_eq!(
        imported.relay_lists.nip65.relays,
        vec!["wss://relay.damus.io"]
    );
    assert_eq!(
        imported.relay_lists.inbox.relays,
        vec!["wss://relay.damus.io"]
    );
    assert!(imported.key_package_bytes.is_some());
    assert_eq!(
        app.account_relay_list_status(&imported.account.label)
            .unwrap(),
        imported.relay_lists,
        "runtime filtering must not rewrite or hide the published relay lists"
    );

    runtime.shutdown().await;
}

#[tokio::test]
// External signers were a distinct reported failure mode: this intentionally
// pins `login_external_signer`, not only the shared routing helpers exercised
// by the nsec-import regression above.
async fn external_signer_login_ignores_retired_routes_without_rewriting_relay_lists() {
    let publisher_dir = tempfile::tempdir().unwrap();
    let publisher_home = AccountHome::open(publisher_dir.path());
    let keys = Keys::generate();
    publisher_home
        .import_account("publisher", &keys.secret_key().to_secret_hex())
        .unwrap();

    let (_relay, relay_url) = mock_relay().await;
    publish_account_relay_lists_at(
        &publisher_home,
        "publisher",
        &relay_url,
        "wss://relay.nostr.band",
        test_unix_now_seconds(),
    )
    .await;

    let app_dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay_and_config(
        app_dir.path(),
        relay_url.clone(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let runtime = MarmotAppRuntime::new(app.clone());
    let logged_in = runtime
        .login_external_signer(
            keys.public_key().to_hex(),
            TestExternalAccountSigner { keys },
            AccountSetupRequest {
                default_relays: vec![endpoint(&relay_url)],
                bootstrap_relays: vec![endpoint(&relay_url)],
                discovery_relays: vec![endpoint(&relay_url)],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            },
        )
        .await
        .expect("a retired published relay must not block external-signer login");

    assert!(logged_in.account.external_signing);
    assert!(!logged_in.account.local_signing);
    assert!(logged_in.relay_lists.complete);
    assert_eq!(
        logged_in.relay_lists.nip65.relays,
        vec!["wss://relay.nostr.band"]
    );
    assert_eq!(
        logged_in.relay_lists.inbox.relays,
        vec!["wss://relay.nostr.band"]
    );
    assert!(logged_in.key_package_bytes.is_some());
    assert_eq!(
        app.account_relay_list_status(&logged_in.account.label)
            .unwrap(),
        logged_in.relay_lists,
        "runtime filtering must not rewrite or hide external accounts' published relay lists"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn remote_key_package_fetch_falls_back_when_published_outbox_is_retired() {
    let publisher_dir = tempfile::tempdir().unwrap();
    let publisher_home = AccountHome::open(publisher_dir.path());
    let (_relay, publisher_app, relay_url) = mock_app(&publisher_dir).await;
    let publisher_runtime = MarmotAppRuntime::new(publisher_app.clone());
    let created = publisher_runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&relay_url)],
            bootstrap_relays: vec![endpoint(&relay_url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    publish_account_relay_lists_at(
        &publisher_home,
        &created.account.label,
        &relay_url,
        "wss://relay.damus.io",
        test_unix_now_seconds() + 1,
    )
    .await;

    let consumer_dir = tempfile::tempdir().unwrap();
    let consumer = MarmotApp::with_relay_and_config(
        consumer_dir.path(),
        relay_url.clone(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let fetched = consumer
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&relay_url)],
        )
        .await
        .expect("configured directory relays should recover a remote KeyPackage");

    assert_eq!(
        fetched.relay_lists.nip65.relays,
        vec!["wss://relay.damus.io"]
    );
    assert_eq!(
        fetched.key_package.bytes().len(),
        created.key_package_bytes.unwrap()
    );

    publisher_runtime.shutdown().await;
}

#[tokio::test]
async fn relay_list_edits_reject_retired_endpoints_in_every_input_role() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (_seed, app, seed_url) = mock_app(&dir).await;

    let inbox = app
        .set_account_inbox_relays(
            "alice",
            vec![endpoint(&seed_url), endpoint("wss://relay.nostr.band")],
            vec![endpoint(&seed_url)],
        )
        .await;
    assert!(
        matches!(inbox, Err(AppError::RelayDirectory(message)) if message.contains("account relay-list declaration") && message.contains("retired"))
    );

    let bootstrap = app
        .publish_account_relay_lists(
            "alice",
            AccountRelayListBootstrap::new(
                vec![endpoint(&seed_url)],
                vec![endpoint("wss://relay.damus.io")],
            ),
        )
        .await;
    assert!(
        matches!(bootstrap, Err(AppError::RelayDirectory(message)) if message.contains("account relay-list publication") && message.contains("retired"))
    );

    let nip65_read = app
        .publish_account_nip65_relay_set(
            "alice",
            vec![endpoint("wss://relay.nostr.band")],
            vec![endpoint(&seed_url)],
            vec![endpoint(&seed_url)],
        )
        .await;
    assert!(
        matches!(nip65_read, Err(AppError::RelayDirectory(message)) if message.contains("account NIP-65 read-relay declaration") && message.contains("retired"))
    );

    let nip65_write = app
        .publish_account_nip65_relay_set(
            "alice",
            vec![endpoint(&seed_url)],
            vec![endpoint("wss://relay.damus.io")],
            vec![endpoint(&seed_url)],
        )
        .await;
    assert!(
        matches!(nip65_write, Err(AppError::RelayDirectory(message)) if message.contains("account NIP-65 write-relay declaration") && message.contains("retired"))
    );
}

#[tokio::test]
async fn relay_list_all_read_fetch_clears_cached_write_targets() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (_seed, app, seed_url) = mock_app(&dir).await;

    let cached = app
        .publish_account_relay_lists(
            "alice",
            AccountRelayListBootstrap::new(vec![endpoint(&seed_url)], vec![endpoint(&seed_url)]),
        )
        .await
        .unwrap();
    assert_eq!(cached.nip65.relays, vec![seed_url.clone()]);

    publish_nostr_event_at(
        &home,
        "alice",
        &seed_url,
        KIND_NIP65_RELAY_LIST,
        vec![vec![
            "r".to_owned(),
            "wss://read-only.example".to_owned(),
            "read".to_owned(),
        ]],
        String::new(),
        test_unix_now_seconds() + 1,
    )
    .await;

    let account_id = home.account("alice").unwrap().account_id_hex;
    let fetched = app
        .fetch_account_relay_list_status_for_account_id(&account_id, vec![endpoint(&seed_url)])
        .await
        .unwrap();

    assert!(fetched.nip65.relays.is_empty());
    assert!(fetched.nip65.write_relays.is_empty());
    assert_eq!(fetched.nip65.read_relays, vec!["wss://read-only.example"]);
    assert_eq!(fetched.inbox, cached.inbox);
    assert_eq!(fetched.missing, vec![MissingRelayListKind::Nip65]);
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
        MarmotAppConfig::default()
            .with_directory_max_future_skew(Duration::from_secs(900))
            .with_allow_loopback_relay_endpoints(true),
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
            banner: None,
            nip05: Some("bob@example.test".into()),
            lud16: None,
            created_at: 0,
            source_relays: Vec::new(),
            extra: Default::default(),
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
            banner: None,
            nip05: None,
            lud16: None,
            created_at: 0,
            source_relays: Vec::new(),
            extra: Default::default(),
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
    let from_other = app
        .fetch_current_user_profile_for_account_id(&id, vec![endpoint(&other_url)])
        .await
        .unwrap()
        .and_then(|profile| profile.name);
    assert_ne!(
        from_other.as_deref(),
        Some("OutboxTest"),
        "profile must not be on the bootstrap relay; outbox should target nip65"
    );

    // The account's NIP-65 (home) relay SHOULD have it.
    let from_home = app
        .fetch_current_user_profile_for_account_id(&id, vec![endpoint(&home_url)])
        .await
        .unwrap()
        .and_then(|profile| profile.name);
    assert_eq!(
        from_home.as_deref(),
        Some("OutboxTest"),
        "profile should be retrievable from the account's nip65 (home) relay"
    );
}

#[tokio::test]
async fn app_runtime_sign_out_and_wipe_removes_account_and_deletes_key_package() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let home = AccountHome::open(dir.path());
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
    let account_id = created.account.account_id_hex.clone();

    // The initial KeyPackage was published to the relay during setup, so the
    // wipe's stage-2 discovery should find and delete at least one.
    let before = runtime
        .account_key_packages(&account_id, vec![endpoint(&url)])
        .await
        .unwrap();
    assert!(
        before.iter().any(|pkg| pkg.relay),
        "setup should leave a relay-published key package to delete"
    );

    let outcome = runtime.sign_out_and_wipe(&account_id).await.unwrap();

    // No groups joined, so nothing to leave and no leave failures.
    assert_eq!(outcome.groups_left, 0);
    assert!(outcome.group_leave_failures.is_empty());
    // The published key package is deleted with no per-relay failures.
    assert!(
        outcome.key_packages_deleted >= 1,
        "expected at least one relay key package deleted, got {}",
        outcome.key_packages_deleted
    );
    assert!(
        outcome.key_package_failures.is_empty(),
        "unexpected key package failures: {:?}",
        outcome.key_package_failures
    );
    // Local cleanup is the all-or-nothing stage and must complete.
    assert!(outcome.local_cleanup.completed);
    assert!(outcome.local_cleanup.reason.is_none());

    // The account is gone from both the runtime view and on-disk storage.
    assert!(
        runtime
            .accounts()
            .managed_accounts()
            .unwrap()
            .into_iter()
            .all(|account| account.account_id_hex != account_id),
        "wiped account must not remain managed"
    );
    assert!(
        home.accounts()
            .unwrap()
            .into_iter()
            .all(|account| account.account_id_hex != account_id),
        "wiped account directory must be removed"
    );

    // Stage 5 invariant: the account ref is no longer valid for any FFI call.
    assert!(runtime.accounts().resolve(&account_id).is_err());

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_delete_key_package_event_nip09_succeeds_and_clears_matching_cache() {
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
    let packages = runtime
        .account_key_packages(&created.account.account_id_hex, vec![endpoint(&url)])
        .await
        .unwrap();
    let relay_package = packages
        .iter()
        .find(|package| package.relay)
        .expect("setup should publish a relay key package");
    let event_id = relay_package.key_package_event_id.clone();
    let record_path = dir
        .path()
        .join("key-packages")
        .join(format!("{}.json", created.account.label));
    std::fs::create_dir_all(record_path.parent().unwrap()).unwrap();
    std::fs::write(
        &record_path,
        serde_json::json!({
            "account_label": created.account.label,
            "account_id_hex": created.account.account_id_hex,
            "key_package_id": "integration-slot",
            "key_package_ref_hex": "aa".repeat(32),
            "key_package_event_id": event_id,
            "published_at": 1,
            "key_package_hex": "00",
        })
        .to_string(),
    )
    .unwrap();
    assert!(
        record_path.exists(),
        "local publication metadata should exist before deletion"
    );

    let deleted = runtime
        .delete_key_package(
            &created.account.account_id_hex,
            &event_id,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();
    assert!(deleted >= 1);
    assert!(
        !record_path.exists(),
        "successful deletion must remove matching local publication metadata"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_wipe_reports_deletion_failure_and_still_removes_local_account() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = deletion_rejecting_app(&dir).await;
    let home = AccountHome::open(dir.path());
    let runtime = MarmotAppRuntime::new(app);
    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let account_id = created.account.account_id_hex;

    let outcome = runtime.sign_out_and_wipe(&account_id).await.unwrap();

    assert_eq!(outcome.key_packages_deleted, 0);
    assert!(!outcome.key_package_failures.is_empty());
    assert!(outcome.local_cleanup.completed);
    assert!(
        home.accounts()
            .unwrap()
            .into_iter()
            .all(|account| account.account_id_hex != account_id),
        "best-effort remote failure must not block destructive local cleanup"
    );
}

#[tokio::test]
async fn app_runtime_sign_out_and_wipe_leaves_pending_confirmation_groups() {
    // Regression for mdk#478: an incoming Welcome auto-joins MLS state
    // while the app keeps the invite `pending_confirmation` until accepted. A
    // destructive wipe must still leave such a group before destroying the
    // local MLS state — otherwise the account keeps a residual remote
    // membership it can never sign a leave for once its keys are gone.
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let bob_id = bob.account.account_id_hex.clone();
    let bob_label = bob.account.label.clone();
    let mut events = runtime.subscribe();

    // Alice invites Bob; Bob's runtime auto-joins the MLS group on the Welcome.
    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "pending wipe",
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

    // Bob has never accepted, so the projection is still pending confirmation,
    // yet the group is a real committed MLS membership.
    let group_id_hex = hex::encode(group_id.as_slice());
    let pending = app.group(&bob_label, &group_id_hex).unwrap().unwrap();
    assert!(
        pending.pending_confirmation,
        "Bob's auto-joined invite should still be pending confirmation"
    );

    // Wiping Bob must leave that pending group (stage 1) before wiping local
    // MLS state — exactly one group left, with no leave failure.
    let outcome = runtime.sign_out_and_wipe(&bob_id).await.unwrap();
    assert_eq!(
        outcome.groups_left, 1,
        "the pending-confirmation group must be left before the wipe"
    );
    assert!(
        outcome.group_leave_failures.is_empty(),
        "unexpected group leave failures: {:?}",
        outcome.group_leave_failures
    );
    // Local cleanup is the all-or-nothing stage and must complete.
    assert!(outcome.local_cleanup.completed);
    assert!(outcome.local_cleanup.reason.is_none());

    // The account is fully gone afterward.
    assert!(runtime.accounts().resolve(&bob_id).is_err());

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_sign_out_and_wipe_rejects_unknown_account() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, _url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app);

    // A ref that resolves to no account must error rather than report a
    // successful (empty) wipe.
    let missing = "0".repeat(64);
    assert!(runtime.sign_out_and_wipe(&missing).await.is_err());

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_sign_out_deletes_key_packages_but_keeps_local_state() {
    // mdk#477: a non-destructive sign-out must clean up the relay
    // KeyPackages (so strangers can't gift-wrap a Welcome while signed out)
    // while keeping ALL local state, so the same identity can be signed back
    // in. This is the reversible counterpart to `sign_out_and_wipe`.
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let home = AccountHome::open(dir.path());
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
    let account_id = created.account.account_id_hex.clone();

    // Setup published a KeyPackage to the relay, so the sign-out should find
    // and delete at least one.
    let before = runtime
        .account_key_packages(&account_id, vec![endpoint(&url)])
        .await
        .unwrap();
    assert!(
        before.iter().any(|pkg| pkg.relay),
        "setup should leave a relay-published key package to delete"
    );

    let outcome = runtime
        .sign_out(&account_id, SignOutOptions::default())
        .await
        .unwrap();

    // The published key package is deleted with no per-relay failures.
    assert!(
        outcome.key_packages_deleted >= 1,
        "expected at least one relay key package deleted, got {}",
        outcome.key_packages_deleted
    );
    assert!(
        outcome.key_package_failures.is_empty(),
        "unexpected key package failures: {:?}",
        outcome.key_package_failures
    );
    // Local teardown ran, persisted the signed-out marker, and never touches
    // on-disk account state.
    assert!(outcome.local_cleanup.completed);
    assert!(outcome.local_cleanup.reason.is_none());
    let signed_out_account = home.account(&account_id).unwrap();
    assert!(
        signed_out_account.signed_out,
        "non-destructive sign-out must persist a signed-out marker"
    );

    let managed_after_sign_out = runtime
        .accounts()
        .managed_accounts()
        .unwrap()
        .into_iter()
        .find(|account| account.account_id_hex == account_id)
        .expect("signed-out account should remain listed");
    assert!(managed_after_sign_out.signed_out);
    assert!(
        !managed_after_sign_out.running,
        "sign-out should stop the worker immediately"
    );

    // Regression for PR #496 review: routine reconcile/catch-up and foreground
    // restart must honor the durable signed-out marker instead of re-spawning
    // the worker and re-warming subscriptions without an explicit sign-in.
    runtime.catch_up_accounts().await.unwrap();
    runtime.restart_account(&account_id).await.unwrap();
    let managed_after_reconcile = runtime
        .accounts()
        .managed_accounts()
        .unwrap()
        .into_iter()
        .find(|account| account.account_id_hex == account_id)
        .expect("signed-out account should remain listed");
    assert!(managed_after_reconcile.signed_out);
    assert!(
        !managed_after_reconcile.running,
        "reconcile/restart must not reactivate a signed-out account"
    );

    let signed_in = runtime.sign_in_account(&account_id).await.unwrap();
    assert!(!signed_in.signed_out);
    assert!(signed_in.running);
    assert!(!home.account(&account_id).unwrap().signed_out);

    // Crucially, the account survives a non-destructive sign-out: it is still a
    // live record on disk and still resolvable for a later sign-in (unlike a
    // wipe, which removes it entirely).
    assert!(
        home.accounts()
            .unwrap()
            .into_iter()
            .any(|account| account.account_id_hex == account_id),
        "signed-out account directory must remain on disk"
    );
    assert!(
        runtime.accounts().resolve(&account_id).is_ok(),
        "signed-out account ref must stay valid for a later sign-in"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_sign_out_reports_deletion_failure_and_keeps_local_state() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = deletion_rejecting_app(&dir).await;
    let home = AccountHome::open(dir.path());
    let runtime = MarmotAppRuntime::new(app);
    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let account_id = created.account.account_id_hex;

    let outcome = runtime
        .sign_out(&account_id, SignOutOptions::default())
        .await
        .unwrap();

    assert_eq!(outcome.key_packages_deleted, 0);
    assert!(!outcome.key_package_failures.is_empty());
    assert!(outcome.local_cleanup.completed);
    assert!(home.account(&account_id).unwrap().signed_out);
    assert!(
        runtime.accounts().resolve(&account_id).is_ok(),
        "best-effort remote failure must keep the local account"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_sign_out_skips_key_package_deletion_when_disabled() {
    // With the toggle off, sign-out must NOT delete any relay KeyPackages and
    // must still keep all local state intact.
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let home = AccountHome::open(dir.path());
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
    let account_id = created.account.account_id_hex.clone();

    // Confirm a relay key package exists before signing out.
    let before = runtime
        .account_key_packages(&account_id, vec![endpoint(&url)])
        .await
        .unwrap();
    assert!(
        before.iter().any(|pkg| pkg.relay),
        "setup should leave a relay-published key package"
    );

    let outcome = runtime
        .sign_out(
            &account_id,
            SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();

    // No deletions attempted, no failures recorded.
    assert_eq!(outcome.key_packages_deleted, 0);
    assert!(outcome.key_package_failures.is_empty());
    assert!(outcome.local_cleanup.completed);

    // The relay key package is still retrievable (we did not delete it), and
    // the account survives on disk.
    let after = runtime
        .account_key_packages(&account_id, vec![endpoint(&url)])
        .await
        .unwrap();
    assert!(
        after.iter().any(|pkg| pkg.relay),
        "key package must remain published when deletion is disabled"
    );
    assert!(
        home.accounts()
            .unwrap()
            .into_iter()
            .any(|account| account.account_id_hex == account_id),
        "signed-out account directory must remain on disk"
    );
    assert!(runtime.accounts().resolve(&account_id).is_ok());

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_sign_out_rejects_unknown_account() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, _url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app);

    // A ref that resolves to no account must error rather than report a
    // successful (empty) sign-out.
    let missing = "0".repeat(64);
    assert!(
        runtime
            .sign_out(&missing, SignOutOptions::default())
            .await
            .is_err()
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn runtime_data_mode_toggle_rotates_live_recorder_with_boundary() {
    // Requirement #4: switching the audit data mode on a running account
    // rotates the live recorder so each file carries a single mode with a clear
    // `audit_data_mode_changed` boundary.
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    // Start in the default obfuscated posture, recording enabled.
    app.set_audit_log_settings(AuditLogSettings {
        enabled: true,
        ..Default::default()
    })
    .unwrap();

    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup).await.unwrap();

    // The live worker is recording in obfuscated mode.
    let before = app.audit_log_files().unwrap();
    let alice_before = before
        .iter()
        .find(|file| file.account_ref == alice.account.label)
        .expect("alice has a live audit file");
    let obfuscated_body = std::fs::read_to_string(&alice_before.path).unwrap();
    assert!(
        obfuscated_body
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .all(|event| event["audit_data_mode"] == "obfuscated_sensitive_data"),
        "every pre-toggle line is obfuscated"
    );

    // Toggle to full_data while recording stays on.
    let stored = runtime
        .set_audit_log_settings(AuditLogSettings {
            enabled: true,
            data_mode: AuditDataMode::FullData,
        })
        .await
        .unwrap();
    assert_eq!(stored.data_mode, AuditDataMode::FullData);

    // The rotated file is entirely full_data and carries the boundary row.
    let after = app.audit_log_files().unwrap();
    let alice_after = after
        .iter()
        .find(|file| file.account_ref == alice.account.label)
        .expect("alice still has a live audit file");
    let events = std::fs::read_to_string(&alice_after.path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .all(|event| event["audit_data_mode"] == "full_data"),
        "the rotated file must be entirely full_data"
    );
    let boundary = events
        .iter()
        .find(|event| event["kind"]["type"] == "audit_data_mode_changed")
        .expect("a mode-change boundary row is written on the fresh file");
    assert_eq!(
        boundary["kind"]["previous_mode"],
        "obfuscated_sensitive_data"
    );
    assert_eq!(boundary["kind"]["new_mode"], "full_data");
    assert_eq!(boundary["kind"]["recorder_restarted"], true);

    runtime.shutdown().await;
}

#[tokio::test]
async fn runtime_sync_emits_subscription_rebuild_and_sync_drain_audit_rows() {
    // A scripted sync produces the two forensic diagnostic rows a field export
    // relies on — the subscription rebuild's `since` floor + per-relay
    // registration, and the drain's cursor before/after — so the
    // persisted-cursor-vs-missed-`created_at` mismatch is evident in any export.
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    // Enable recording before the runtime starts so the live worker records.
    app.set_audit_log_settings(AuditLogSettings {
        enabled: true,
        ..Default::default()
    })
    .unwrap();

    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup).await.unwrap();
    // Force a completed sync so the rebuild + drain rows are flushed to disk.
    runtime.catch_up_accounts().await.unwrap();

    let files = app.audit_log_files().unwrap();
    let alice_file = files
        .iter()
        .find(|file| file.account_ref == alice.account.label)
        .expect("alice has a live audit file");
    let events = std::fs::read_to_string(&alice_file.path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();

    // subscription_rebuild: exact wire tag, the lookback recorded, and the mock
    // relay registered. A successful catch-up implies subscribe registered on
    // >= 1 relay (the adapter hard-errors on 0-of-N), so with the single mock
    // relay the SDK-backed plane must have marked it accepted.
    let rebuild = events
        .iter()
        .find(|event| event["kind"]["type"] == "subscription_rebuild")
        .expect("a subscription_rebuild row is emitted per rebuild");
    assert!(
        rebuild["kind"]["lookback_secs"].is_u64(),
        "rebuild records the lookback: {rebuild}"
    );
    let relay_results = rebuild["kind"]["relay_results"]
        .as_array()
        .expect("relay_results is an array");
    assert!(
        relay_results.iter().any(|entry| {
            entry["relay_url"]
                .as_str()
                .is_some_and(|relay_url| relay_url.contains("127.0.0.1"))
                && entry["accepted"] == true
        }),
        "the mock relay registered the subscription: {rebuild}"
    );

    // sync_drain: exact wire tag and scalar drain accounting present. A fresh
    // account drains no inbound 445s, so `deliveries` is 0 and the cursor
    // fields stay absent (no delivery advanced the cursor) — both valid.
    let drain = events
        .iter()
        .find(|event| event["kind"]["type"] == "sync_drain")
        .expect("a sync_drain row is emitted at the drain exit");
    assert!(drain["kind"]["duration_ms"].is_u64(), "{drain}");
    assert!(drain["kind"]["deliveries"].is_u64(), "{drain}");

    runtime.shutdown().await;
}

/// mdk#352 review follow-up: the welcome re-delivery surface is reachable end
/// to end through the runtime worker. A create whose welcome delivered leaves
/// nothing pending, and re-delivering an unknown welcome id is a clean error
/// (the failure-record + successful-redeliver paths are covered by the
/// storage-sqlite round-trip and marmot-account runtime tests).
#[tokio::test]
async fn app_runtime_exposes_welcome_redelivery_surface() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();

    let mut events = runtime.subscribe();
    let _group = runtime
        .create_group(
            &alice.account.account_id_hex,
            "welcome redelivery surface",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();

    // The welcome delivered over the live relay, so nothing is queued...
    assert!(
        runtime
            .pending_welcome_deliveries(&alice.account.account_id_hex)
            .await
            .unwrap()
            .is_empty(),
        "a delivered welcome must not queue a pending re-delivery"
    );
    // ...and no WelcomeDeliveryPending event is emitted on the happy path (the
    // worker still drained the empty queue without spuriously signaling).
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, MarmotAppEvent::WelcomeDeliveryPending { .. }),
            "a delivered welcome must not emit WelcomeDeliveryPending"
        );
    }

    // No welcome is stored under this id, so re-delivery is a clean error routed
    // through the worker command (not a panic or a lost request).
    let unknown_welcome_id = "ab".repeat(32);
    assert!(
        runtime
            .redeliver_welcome(&alice.account.account_id_hex, &unknown_welcome_id)
            .await
            .is_err(),
        "re-delivering an unknown welcome id must error cleanly"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn concurrent_leaves_report_already_requested_not_an_opaque_error() {
    // PR #1138 review (P1): `Marmot::leave_group` prechecks the pending flag, but
    // that read is not atomic with the send it guards. Two concurrent leaves — a
    // rapid double tap launching two async tasks — can both observe "not
    // pending". The account worker then serializes them, and the loser used to
    // receive `EngineError::InvalidTransition`, which flattens to an opaque error
    // at the UniFFI boundary: exactly what surfacing this state was meant to
    // remove. The classification is now made inside the engine, so the loser
    // learns the real reason by name no matter who wins the race.
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(&alice_id, "double tap", std::slice::from_ref(&bob_id), None)
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined, .. }
                if account_id_hex == &bob_id && joined == &group_id
        )
    })
    .await;

    // Both leaves are in flight before either worker command runs, so neither
    // can benefit from the other having recorded the request.
    let (first, second) = tokio::join!(
        runtime.leave_group(&bob_id, &group_id),
        runtime.leave_group(&bob_id, &group_id),
    );

    // Exactly one wins; the ordering is genuinely racy, so accept either.
    let (winner, loser) = match (&first, &second) {
        (Ok(_), Err(err)) => (&first, err),
        (Err(err), Ok(_)) => (&second, err),
        (a, b) => panic!("exactly one concurrent leave should succeed; got {a:?} and {b:?}"),
    };
    assert!(winner.is_ok());

    let engine_error = loser
        .as_engine_error()
        .unwrap_or_else(|| panic!("the losing leave should carry an engine error; got {loser:?}"));
    match engine_error {
        cgka_traits::error::EngineError::LeaveAlreadyRequested { group_id: refused } => {
            assert_eq!(
                *refused, group_id,
                "the error must name the group it refused"
            );
        }
        other => panic!(
            "the losing leave must be typed as already-requested, never an opaque \
             InvalidTransition; got {other:?}"
        ),
    }

    // The race resolved into one durable request, and it is visible to hosts.
    let group_id_hex = hex::encode(group_id.as_slice());
    assert!(
        app.chat_list_row(&bob.account.label, &group_id_hex)
            .unwrap()
            .expect("bob's row survives the leave")
            .leave_requested_at_ms
            .is_some(),
        "the winning leave leaves exactly one durable request behind"
    );
}

/// Convergence remediation-plan liveness guard: successive inbound commits,
/// each with a member send fired while the commit is still converging, must
/// keep settling promptly through the real worker scheduling path.
///
/// The queued mid-window path is asserted *opportunistically*: measured on
/// both a dev machine and CI, a healthy in-proc relay settles a linear
/// rename commit in well under one quiescence window, so the interval in
/// which a member send lands mid-window is a sub-300ms race that can be won
/// or lost systematically per machine (CI lost it 8/8 with no delay; a dev
/// machine lost it 12/12 with a 300ms delay). A round whose send does
/// report `published == 0` (durably queued, nothing on transport) gets the
/// hard latency assertion; rounds that publish directly still assert
/// liveness through the real worker scheduling path.
///
/// The deterministic queued-path and parking contracts live in the engine
/// tests (`cgka-engine/tests/distributed_convergence.rs`:
/// `pass_opens_while_app_message_intents_are_queued` and the reservation
/// suite), which fail outright against the pre-fix engine. Forcing the
/// queued path at this layer through public APIs would require a test-only
/// transport-pause or pass-phase diagnostics seam (PR-B candidate).
#[tokio::test]
async fn convergence_settles_across_generations_with_mid_window_queued_sends() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime
        .create_identity(setup.relay_options_only())
        .await
        .unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let alice_id = alice.account.account_id_hex.clone();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice_id,
            "settling liveness",
            std::slice::from_ref(&bob_id),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined, .. }
                if account_id_hex == &bob_id && joined == &group_id
        )
    })
    .await;
    let group_id_hex = hex::encode(group_id.as_slice());

    const ROUNDS: u32 = 3;
    for round in 0..ROUNDS {
        let renamed = format!("settling-round-{round}");
        runtime
            .update_group_profile(&alice_id, &group_id, Some(renamed.clone()), None)
            .await
            .unwrap();
        // Fire bob's send immediately: when it wins the race into bob's
        // collection window, `published == 0` marks the queued path and the
        // hard latency bound below applies.
        let text = format!("bob mid-window {round}");
        let send_accepted_at = Instant::now();
        let summary = runtime
            .send_message(&bob_id, &group_id, text.clone().into_bytes())
            .await
            .unwrap();
        let send_was_queued = summary.published == 0;

        // Wait on bob's *projection* (poll), not the group-state
        // subscription: the projection is the authoritative apply witness
        // here, and the subscription can stay silent for a rename when a
        // send interleaves (tracked separately; not this test's contract).
        timeout(Duration::from_secs(5), async {
            loop {
                let row = app
                    .chat_list_row(&bob.account.label, &group_id_hex)
                    .unwrap();
                if row.is_some_and(|row| row.title == renamed) {
                    return;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("bob applies the rename commit");
        wait_for_event(&mut events, |event| {
            matches!(
                event,
                MarmotAppEvent::MessageReceived(message)
                    if message.account_id_hex == alice_id
                        && message.message.group_id == group_id
                        && message.message.plaintext == text
            )
        })
        .await;

        if send_was_queued {
            let queued_send_latency = send_accepted_at.elapsed();
            // One settlement cycle plus drain: nominally ~1.1-1.4s (1000ms
            // quiescence + 100ms schedule margin + worker/publish slack). The
            // pre-fix drain deferred a queued app intent past the apply tick
            // whenever retained inbound was present, adding at least one more
            // full settlement cycle (>= ~2.2s nominal, more on a loaded
            // runner). 2.5s separates the classes with CI headroom.
            assert!(
                queued_send_latency < Duration::from_millis(2_500),
                "queued mid-window send must publish within one settlement \
                 cycle plus drain; took {queued_send_latency:?}"
            );
        }
    }

    runtime.shutdown().await;
}
