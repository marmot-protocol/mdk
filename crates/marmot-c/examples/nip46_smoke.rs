//! Real loopback NIP-46 smoke against the public C ABI. No public relay or keychain is used.
//! Run from the MDK workspace: cargo run -p marmot-c --example nip46_smoke
//! The fixture decrypts kind:24133 requests, signs with distinct user keys, and encrypts responses.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use marmot_c::commands::*;
use marmot_c::nip46::*;
use marmot_c::secret_store::{MarmotSecretStore, MarmotSecretStoreStatus};
use marmot_c::types::account::*;
use marmot_c::*;
use nostr::nips::{nip04, nip44};
use nostr::prelude::*;
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{Client, ClientNotification};
use serde_json::{Value, json};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinSet;

type Result<T, E = Box<dyn Error + Send + Sync>> = std::result::Result<T, E>;
const WAIT: Duration = Duration::from_secs(15);
const AUTH_URL: &str = "https://signer.example.invalid/approve/nip46-smoke";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignRequest {
    kind: Kind,
    content: String,
    tags: Tags,
    created_at: Timestamp,
}

fn c(value: &str) -> CString {
    CString::new(value).expect("fixture strings have no NUL")
}

fn take_string(value: *mut c_char) -> String {
    assert!(!value.is_null(), "successful C call returned NULL");
    let text = unsafe { CStr::from_ptr(value) }
        .to_str()
        .expect("UTF-8 C output")
        .to_owned();
    unsafe { marmot_string_free(value) };
    text
}

fn check(status: MarmotStatus, operation: &str) {
    if status != MarmotStatus::Ok {
        let error = marmot_last_error_message();
        let detail = if error.is_null() {
            String::new()
        } else {
            take_string(error)
        };
        panic!("{operation}: {status:?}: {detail}");
    }
}

// Ephemeral host key storage for local signing and namespaced device database secrets.
static SECRETS: Mutex<Vec<(String, String, String)>> = Mutex::new(Vec::new());
unsafe fn input(value: *const c_char) -> String {
    unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned()
}
unsafe extern "C" fn has_secret(_: *mut c_void, key: *const c_char, out: *mut u8) -> u32 {
    let key = unsafe { input(key) };
    let Ok(entries) = SECRETS.lock() else {
        return MarmotSecretStoreStatus::Failed as u32;
    };
    unsafe {
        out.write(u8::from(
            entries
                .iter()
                .any(|(label, account, _)| label == &key || account == &key),
        ))
    };
    MarmotSecretStoreStatus::Ok as u32
}
unsafe extern "C" fn write_secret(
    _: *mut c_void,
    label: *const c_char,
    account: *const c_char,
    secret: *const c_char,
) -> u32 {
    let (label, account, secret) = unsafe { (input(label), input(account), input(secret)) };
    let Ok(mut entries) = SECRETS.lock() else {
        return MarmotSecretStoreStatus::Failed as u32;
    };
    entries.retain(|(_, id, _)| id != &account);
    entries.push((label, account, secret));
    MarmotSecretStoreStatus::Ok as u32
}
unsafe extern "C" fn load_secret(
    _: *mut c_void,
    label: *const c_char,
    account: *const c_char,
    out: *mut *mut c_char,
) -> u32 {
    let (label, account) = unsafe { (input(label), input(account)) };
    let Ok(entries) = SECRETS.lock() else {
        return MarmotSecretStoreStatus::Failed as u32;
    };
    match entries
        .iter()
        .find(|(l, a, _)| l == &label || a == &account)
    {
        Some((_, _, secret)) => {
            let Ok(secret) = CString::new(secret.as_str()) else {
                return MarmotSecretStoreStatus::Failed as u32;
            };
            unsafe { out.write(secret.into_raw()) };
            MarmotSecretStoreStatus::Ok as u32
        }
        None => MarmotSecretStoreStatus::NotFound as u32,
    }
}
unsafe extern "C" fn remove_secret(
    _: *mut c_void,
    label: *const c_char,
    account: *const c_char,
) -> u32 {
    let (label, account) = unsafe { (input(label), input(account)) };
    let Ok(mut entries) = SECRETS.lock() else {
        return MarmotSecretStoreStatus::Failed as u32;
    };
    entries.retain(|(l, a, _)| l != &label && a != &account);
    MarmotSecretStoreStatus::Ok as u32
}
unsafe extern "C" fn free_secret(_: *mut c_void, value: *mut c_char) {
    drop(unsafe { CString::from_raw(value) });
}
fn host_store() -> MarmotSecretStore {
    MarmotSecretStore {
        user_data: ptr::null_mut(),
        has_secret_for_label: Some(has_secret),
        has_secret_for_account_id: Some(has_secret),
        write_secret: Some(write_secret),
        load_secret: Some(load_secret),
        remove_secret: Some(remove_secret),
        free_secret: Some(free_secret),
        destroy: None,
    }
}

#[derive(Clone, Copy)]
struct Handle(*mut MarmotClient);
// C client functions are explicitly thread-safe. Owner joins all callers before releasing it.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Handle {
    fn open(root: &tempfile::TempDir, relay: &str) -> Self {
        let root = c(root.path().to_str().expect("UTF-8 temporary path"));
        let relay = c(relay);
        let relays = [relay.as_ptr()];
        let store = host_store();
        let mut client = ptr::null_mut();
        check(
            unsafe {
                marmot_client_new_with_options(
                    root.as_ptr(),
                    relays.as_ptr(),
                    1,
                    MarmotRelayPolicy::AllowLoopback as u32,
                    &store,
                    &mut client,
                )
            },
            "client_new",
        );
        Self(client)
    }
    fn profile(self, account: &str, name: &str) -> MarmotStatus {
        let account = c(account);
        let name = c(name);
        let profile = MarmotUserProfileMetadata {
            name: name.as_ptr().cast_mut(),
            display_name: ptr::null_mut(),
            about: ptr::null_mut(),
            picture: ptr::null_mut(),
            banner: ptr::null_mut(),
            nip05: ptr::null_mut(),
            lud16: ptr::null_mut(),
        };
        let mut out = ptr::null_mut();
        let status = unsafe {
            marmot_publish_user_profile_using_account_relays(
                self.0,
                account.as_ptr(),
                &profile,
                &mut out,
            )
        };
        if !out.is_null() {
            unsafe { marmot_user_profile_metadata_free(out) };
        }
        status
    }
    fn keypackage(self, account: &str) {
        let account = c(account);
        let mut accepted = 0;
        check(
            unsafe { marmot_publish_new_key_package(self.0, account.as_ptr(), &mut accepted) },
            "publish keypackage",
        );
        assert!(accepted > 0, "loopback relay must accept the keypackage");
    }
}
struct ClientOwner(Handle);
impl Drop for ClientOwner {
    fn drop(&mut self) {
        check(
            unsafe { marmot_client_shutdown(self.0.0) },
            "client_shutdown",
        );
        unsafe { marmot_client_free(self.0.0) };
    }
}

struct Session(*mut MarmotNip46Session);
// Session requests/state/cancellation are safe across callers; owner never frees during a call.
unsafe impl Send for Session {}
unsafe impl Sync for Session {}
impl Session {
    fn new(client: Handle, config: &Value) -> Self {
        let config = c(&config.to_string());
        let mut session = ptr::null_mut();
        check(
            unsafe { marmot_nip46_new(client.0, config.as_ptr(), &mut session) },
            "nip46_new",
        );
        Self(session)
    }
    fn connect(&self) -> String {
        let mut out = ptr::null_mut();
        check(
            unsafe { marmot_nip46_connect(self.0, &mut out) },
            "nip46_connect",
        );
        take_string(out)
    }
    fn uri(&self) -> String {
        let mut out = ptr::null_mut();
        check(unsafe { marmot_nip46_uri(self.0, &mut out) }, "nip46_uri");
        take_string(out)
    }
    fn export(&self) -> Value {
        let mut out = ptr::null_mut();
        check(
            unsafe { marmot_nip46_export(self.0, &mut out) },
            "nip46_export",
        );
        serde_json::from_str(&take_string(out)).expect("descriptor JSON")
    }
    fn state(&self) -> Value {
        let mut out = ptr::null_mut();
        check(
            unsafe { marmot_nip46_state(self.0, &mut out) },
            "nip46_state",
        );
        serde_json::from_str(&take_string(out)).expect("state JSON")
    }
    fn login(&self, client: Handle, relay: &str, expected: PublicKey) -> String {
        let relay = c(relay);
        let relays = [relay.as_ptr()];
        // A listening socket without a websocket handshake makes discovery
        // incomplete. The signed NIP-65 outbox still answers authoritatively.
        let stalled = std::net::TcpListener::bind("127.0.0.1:0").expect("stalled directory socket");
        let stalled_url = c(&format!("ws://{}", stalled.local_addr().unwrap()));
        let bootstrap = [relay.as_ptr(), stalled_url.as_ptr()];
        let mut out = ptr::null_mut();
        check(
            unsafe {
                marmot_nip46_login(
                    client.0,
                    self.0,
                    relays.as_ptr(),
                    1,
                    bootstrap.as_ptr(),
                    bootstrap.len(),
                    ptr::null(),
                    0,
                    &mut out,
                )
            },
            "nip46_login",
        );
        assert!(!out.is_null());
        let summary = unsafe { &*out };
        assert!(summary.external_signing && !summary.local_signing && !summary.signed_out);
        let id = unsafe { input(summary.account_id_hex) };
        assert_eq!(id, expected.to_hex());
        unsafe { marmot_account_summary_free(out) };
        id
    }
    fn register(&self, client: Handle, account: &str) {
        let account = c(account);
        check(
            unsafe { marmot_nip46_register(client.0, account.as_ptr(), self.0) },
            "nip46_register",
        );
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        unsafe { marmot_nip46_free(self.0) };
    }
}

#[derive(Default)]
struct Evidence {
    requests: Vec<(String, String)>,
    signed: Vec<Event>,
    pending: HashSet<String>,
    peak_pending: usize,
    replies: Vec<String>,
    connect_secrets: Vec<String>,
}
#[derive(Clone, Debug, Default)]
struct RequestGate(Arc<Mutex<Option<String>>>);
impl nostr_relay_builder::builder::WritePolicy for RequestGate {
    fn admit_event<'a>(
        &'a self,
        event: &'a nostr_relay_builder::prelude::Event,
        _addr: &'a std::net::SocketAddr,
    ) -> nostr_relay_builder::prelude::BoxedFuture<'a, nostr_relay_builder::builder::PolicyResult>
    {
        Box::pin(async move {
            use nostr_relay_builder::builder::PolicyResult;
            if event.kind == nostr_relay_builder::prelude::Kind::NostrConnect
                && self.0.lock().unwrap().as_ref() == Some(&event.pubkey.to_hex())
            {
                return PolicyResult::Reject("blocked: signer request denied by relay".into());
            }
            PolicyResult::Accept
        })
    }
}
struct Controls {
    offline: AtomicBool,
    invalid_identity: AtomicBool,
    approval: AtomicBool,
    approval_sent: Notify,
    finish_approval: Notify,
    wrong_event: AtomicBool,
    evidence: Mutex<Evidence>,
}
impl Default for Controls {
    fn default() -> Self {
        Self {
            offline: AtomicBool::new(false),
            invalid_identity: AtomicBool::new(false),
            approval: AtomicBool::new(false),
            approval_sent: Notify::new(),
            finish_approval: Notify::new(),
            wrong_event: AtomicBool::new(false),
            evidence: Mutex::new(Evidence::default()),
        }
    }
}
struct Pairing {
    client: PublicKey,
    secret: String,
    author: Keys,
}
struct Fixture {
    bunker: Keys,
    user: Keys,
    client: Client,
    controls: Arc<Controls>,
    pairing: mpsc::Sender<Pairing>,
    task: tokio::task::JoinHandle<Result<()>>,
}

fn wire(author: &Keys, recipient: PublicKey, payload: &Value) -> Result<Event> {
    let encrypted = nip44::encrypt(
        author.secret_key(),
        &recipient,
        payload.to_string(),
        nip44::Version::V2,
    )?;
    Ok(EventBuilder::new(Kind::from(24133), encrypted)
        .tag(Tag::public_key(recipient))
        .finalize(author)?)
}
async fn publish(client: &Client, event: &Event) -> Result<()> {
    let output = client.send_event(event).await?;
    assert!(
        !output.success.is_empty(),
        "fixture event was not accepted by relay"
    );
    Ok(())
}
async fn sdk(relay: &str) -> Result<Client> {
    let client = Client::new();
    client.add_relay(relay).await?;
    let connected = client.try_connect().timeout(WAIT).await;
    assert!(
        !connected.success.is_empty(),
        "fixture must connect to its loopback relay"
    );
    Ok(client)
}

impl Fixture {
    async fn start(relay: &str, next_relay: Option<&str>) -> Result<Self> {
        let bunker = Keys::generate();
        let user = Keys::generate();
        assert_ne!(bunker.public_key(), user.public_key());
        let client = sdk(relay).await?;
        if let Some(next) = next_relay {
            client.add_relay(next).await?;
            let connected = client.try_connect().timeout(WAIT).await;
            assert!(
                connected
                    .success
                    .iter()
                    .any(|(url, _)| url.as_str() == next),
                "fixture must listen on the replacement relay"
            );
        }
        for (kind, tag) in [
            (Kind::RelayList, "r"),
            (Kind::InboxRelays, "relay"),
            (Kind::MlsKeyPackageRelays, "relay"),
        ] {
            // Each identity advertises an outbox but has no inbox list.
            if kind == Kind::InboxRelays {
                continue;
            }
            let event = EventBuilder::new(kind, "")
                .tag(Tag::parse([tag, relay])?)
                .finalize(&user)?;
            publish(&client, &event).await?;
        }
        let mut notifications = client.notifications();
        client
            .subscribe(
                Filter::new()
                    .kind(Kind::from(24133))
                    .pubkey(bunker.public_key()),
            )
            .await?;
        let controls = Arc::new(Controls::default());
        let control = controls.clone();
        let (pairing, mut pairings) = mpsc::channel::<Pairing>(8);
        let remote = bunker.clone();
        let signing = user.clone();
        let sender = client.clone();
        let relay = next_relay.unwrap_or(relay).to_owned();
        let task = tokio::spawn(async move {
            let mut responses = JoinSet::new();
            let mut known_clients = HashSet::new();
            let mut seen = HashSet::new();
            let mut secret_used = false;
            loop {
                tokio::select! {
                    Some(completed) = responses.join_next(), if !responses.is_empty() => { completed??; }
                    Some(pair) = pairings.recv() => {
                        // NIP-46 client-initiated pairing uses an unsolicited connect response.
                        let payload = json!({"id": format!("pair-{}", pair.author.public_key()), "result":pair.secret, "error":null});
                        publish(&sender, &wire(&pair.author, pair.client, &payload)?).await?;
                        if pair.author.public_key() == remote.public_key() { known_clients.insert(pair.client); }
                    }
                    notification = notifications.next() => {
                        let Some(notification) = notification else { break; };
                        let ClientNotification::Event { event, .. } = notification else { continue; };
                        event.verify()?;
                        if !seen.insert(event.id) { continue; }
                        let plaintext = nip44::decrypt(remote.secret_key(), &event.pubkey, &event.content)?;
                        let request: Value = serde_json::from_str(&plaintext)?;
                        let Some(method) = request["method"].as_str() else { continue; }; // pairing ack
                        let id = request["id"].as_str().ok_or("request without id")?.to_owned();
                        let params: Vec<String> = serde_json::from_value(request["params"].clone())?;
                        {
                            let mut evidence = control.evidence.lock().expect("evidence mutex");
                            assert!(!evidence.requests.iter().any(|(old, _)| old == &id), "request ids must be unique");
                            evidence.requests.push((id.clone(), method.to_owned()));
                            evidence.pending.insert(id.clone());
                            evidence.peak_pending = evidence.peak_pending.max(evidence.pending.len());
                        }
                        if control.offline.load(Ordering::SeqCst) { continue; }
                        let result = match method {
                            "connect" => {
                                assert_eq!(params.first(), Some(&remote.public_key().to_hex()), "connect must target the bunker key");
                                let permissions = params.get(2).ok_or("connect without permissions")?;
                                for required in ["sign_event:450", "sign_event:30443", "nip44_encrypt", "nip44_decrypt"] {
                                    assert!(permissions.split(',').any(|permission| permission == required), "missing signer permission {required}");
                                }
                                let metadata: Value = serde_json::from_str(params.get(3).ok_or("connect without client metadata")?)?;
                                assert!(metadata["name"].as_str().is_some(), "connect must identify the client");
                                let secret = params.get(1).cloned().unwrap_or_default();
                                control.evidence.lock().expect("evidence mutex").connect_secrets.push(secret.clone());
                                if !known_clients.contains(&event.pubkey) {
                                    assert_eq!(secret, "one-use-smoke", "bunker secret was not forwarded");
                                    assert!(!secret_used, "one-use bunker secret was replayed on restore");
                                    secret_used = true;
                                    known_clients.insert(event.pubkey);
                                }
                                "ack".to_owned()
                            }
                            "get_public_key" => if control.invalid_identity.swap(false, Ordering::SeqCst) { "invalid-fixture-public-key".to_owned() } else { signing.public_key().to_hex() },
                            "switch_relays" => json!([relay.clone()]).to_string(),
                            "ping" => "pong".to_owned(),
                            "logout" => { known_clients.remove(&event.pubkey); "ack".to_owned() }
                            "sign_event" => {
                                let request = match serde_json::from_str::<SignRequest>(params.first().ok_or("missing unsigned event")?) {
                                    Ok(request) => request,
                                    Err(_) => {
                                        let rejection = json!({"id":id,"result":null,"error":"invalid sign_event fields"});
                                        publish(&sender, &wire(&remote, event.pubkey, &rejection)?).await?;
                                        continue;
                                    }
                                };
                                let mut unsigned = UnsignedEvent {
                                    id: None,
                                    pubkey: signing.public_key(),
                                    kind: request.kind,
                                    content: request.content,
                                    tags: request.tags,
                                    created_at: request.created_at,
                                };
                                unsigned.id = Some(unsigned.compute_id());
                                let signed = if control.wrong_event.swap(false, Ordering::SeqCst) {
                                    EventBuilder::new(unsigned.kind, "fixture substituted content").finalize(&signing)?
                                } else {
                                    let signed = unsigned.clone().finalize(&signing)?;
                                    assert_eq!(signed.id, unsigned.compute_id());
                                    assert_eq!(signed.content, unsigned.content);
                                    assert_eq!(signed.tags, unsigned.tags);
                                    signed
                                };
                                signed.verify()?;
                                control.evidence.lock().expect("evidence mutex").signed.push(signed.clone());
                                signed.as_json()
                            }
                            "nip44_encrypt" => nip44::encrypt(signing.secret_key(), &PublicKey::parse(&params[0])?, &params[1], nip44::Version::V2)?,
                            "nip44_decrypt" => nip44::decrypt(signing.secret_key(), &PublicKey::parse(&params[0])?, &params[1])?,
                            "nip04_encrypt" => nip04::encrypt(signing.secret_key(), &PublicKey::parse(&params[0])?, &params[1])?,
                            "nip04_decrypt" => nip04::decrypt(signing.secret_key(), &PublicKey::parse(&params[0])?, &params[1])?,
                            other => return Err(format!("unsupported real signer method {other}").into()),
                        };
                        let approval = method == "sign_event" && control.approval.swap(false, Ordering::SeqCst);
                        let sender = sender.clone();
                        let remote = remote.clone();
                        let control = control.clone();
                        let recipient = event.pubkey;
                        responses.spawn(async move {
                            // Unknown-id and wrong-author replies must not complete the native pending request.
                            let stale = json!({"id": format!("stale-{id}"), "result":"not-the-request", "error":null});
                            publish(&sender, &wire(&remote, recipient, &stale)?).await?;
                            let attacker = Keys::generate();
                            let spoofed = json!({"id":id, "result":"spoofed-matching-id", "error":null});
                            publish(&sender, &wire(&attacker, recipient, &spoofed)?).await?;
                            if approval {
                                publish(&sender, &wire(&remote, recipient, &json!({"id":id,"result":"auth_url","error":AUTH_URL}))?).await?;
                                control.approval_sent.notify_one();
                                tokio::time::timeout(WAIT, control.finish_approval.notified()).await?;
                            }
                            if id == "smoke-slow" { tokio::time::sleep(Duration::from_millis(180)).await; }
                            if id == "smoke-fast" { tokio::time::sleep(Duration::from_millis(5)).await; }
                            let response = json!({"id":id,"result":result,"error":null});
                            publish(&sender, &wire(&remote, recipient, &response)?).await?;
                            let mut evidence = control.evidence.lock().expect("evidence mutex");
                            evidence.pending.remove(&id);
                            evidence.replies.push(id);
                            Ok::<_, Box<dyn Error + Send + Sync>>(())
                        });
                    }
                }
            }
            while let Some(completed) = responses.join_next().await {
                completed??;
            }
            Ok(())
        });
        Ok(Self {
            bunker,
            user,
            client,
            controls,
            pairing,
            task,
        })
    }
    async fn stop(self) -> Result<()> {
        self.client.shutdown().await;
        tokio::time::timeout(WAIT, self.task).await???;
        Ok(())
    }
}

// Probe data NIP-44 through actual signed/encrypted RPCs using the exported transport identity.
// MDK proof/keypackage/profile paths below use the native adapter; no chat/MLS secret is sent here.
async fn nip44_probe(relay: &str, descriptor: &Value, fixture: &Fixture) -> Result<()> {
    let keys = Keys::parse(
        descriptor["client_secret"]
            .as_str()
            .ok_or("missing exported client_secret")?,
    )?;
    let client = sdk(relay).await?;
    let mut notifications = client.notifications();
    client
        .subscribe(
            Filter::new()
                .kind(Kind::from(24133))
                .author(fixture.bunker.public_key())
                .pubkey(keys.public_key()),
        )
        .await?;
    let peer = Keys::generate();
    for (id, text) in [
        ("smoke-slow", "slow independent payload"),
        ("smoke-fast", "fast independent payload"),
    ] {
        let request =
            json!({"id":id, "method":"nip44_encrypt", "params":[peer.public_key().to_hex(),text]});
        publish(
            &client,
            &wire(&keys, fixture.bunker.public_key(), &request)?,
        )
        .await?;
    }
    let mut answers = HashMap::new();
    let deadline = tokio::time::Instant::now() + WAIT;
    while answers.len() < 2 {
        let notification = tokio::time::timeout_at(deadline, notifications.next())
            .await?
            .ok_or("probe notifications closed")?;
        let ClientNotification::Event { event, .. } = notification else {
            continue;
        };
        event.verify()?;
        assert_eq!(event.pubkey, fixture.bunker.public_key());
        let payload: Value = serde_json::from_str(&nip44::decrypt(
            keys.secret_key(),
            &event.pubkey,
            &event.content,
        )?)?;
        let id = payload["id"].as_str().ok_or("response without id")?;
        if id != "smoke-slow" && id != "smoke-fast" {
            continue;
        }
        let encrypted = payload["result"]
            .as_str()
            .ok_or("missing encryption result")?;
        let text = nip44::decrypt(peer.secret_key(), &fixture.user.public_key(), encrypted)?;
        let expected = if id == "smoke-slow" {
            "slow independent payload"
        } else {
            "fast independent payload"
        };
        assert_eq!(text, expected, "request/result correlation");
        answers.insert(id.to_owned(), encrypted.to_owned());
    }
    let inbound = nip44::encrypt(
        peer.secret_key(),
        &fixture.user.public_key(),
        "peer encrypted payload",
        nip44::Version::V2,
    )?;
    publish(&client, &wire(&keys, fixture.bunker.public_key(), &json!({"id":"smoke-decrypt","method":"nip44_decrypt","params":[peer.public_key().to_hex(),inbound]}))?).await?;
    loop {
        let notification = tokio::time::timeout_at(deadline, notifications.next())
            .await?
            .ok_or("probe notifications closed")?;
        let ClientNotification::Event { event, .. } = notification else {
            continue;
        };
        event.verify()?;
        assert_eq!(event.pubkey, fixture.bunker.public_key());
        let payload: Value = serde_json::from_str(&nip44::decrypt(
            keys.secret_key(),
            &event.pubkey,
            &event.content,
        )?)?;
        if payload["id"] == "smoke-decrypt" {
            assert_eq!(payload["result"], "peer encrypted payload");
            break;
        }
    }
    {
        let evidence = fixture.controls.evidence.lock().expect("evidence mutex");
        assert!(
            evidence.peak_pending >= 2,
            "fixture must observe interleaved in-flight requests"
        );
        let fast = evidence
            .replies
            .iter()
            .position(|id| id == "smoke-fast")
            .expect("fast response");
        let slow = evidence
            .replies
            .iter()
            .position(|id| id == "smoke-slow")
            .expect("slow response");
        assert!(fast < slow, "fixture must deliberately answer out of order");
    }
    client.shutdown().await;
    Ok(())
}

fn sign_out(client: Handle, account: &str) {
    let account = c(account);
    let mut out = ptr::null_mut();
    check(
        unsafe { marmot_sign_out(client.0, account.as_ptr(), 0, &mut out) },
        "MDK sign_out",
    );
    unsafe { marmot_sign_out_outcome_free(out) };
}

fn assert_accounts(
    client: Handle,
    local: &str,
    remote_a: &str,
    remote_b: &str,
    a_signed_out: bool,
) {
    let mut out = ptr::null_mut();
    check(
        unsafe { marmot_list_accounts(client.0, &mut out) },
        "list accounts",
    );
    let list = unsafe { &*out };
    let accounts = unsafe { std::slice::from_raw_parts(list.items, list.len) };
    assert_eq!(accounts.len(), 3);
    for (id, local_signing, signed_out) in [
        (local, true, false),
        (remote_a, false, a_signed_out),
        (remote_b, false, false),
    ] {
        let account = accounts
            .iter()
            .find(|account| unsafe { input(account.account_id_hex) } == id)
            .expect("expected account");
        assert_eq!(account.local_signing, local_signing);
        assert_eq!(account.external_signing, !local_signing);
        assert_eq!(account.signed_out, signed_out);
    }
    unsafe { marmot_account_summary_list_free(out) };
}

fn main() -> Result<()> {
    // Bound the entire executable, including blocking C calls, so regressions cannot hang CI.
    let (done, watchdog) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        if matches!(
            watchdog.recv_timeout(Duration::from_secs(180)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            eprintln!("FAIL nip46 smoke exceeded 180-second deadline");
            std::process::exit(1);
        }
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let request_gate = RequestGate::default();
    let relay = LocalRelay::new(
        RelayBuilder::default()
            .write_policy(request_gate.clone())
            .rate_limit(nostr_relay_builder::builder::RateLimit {
                notes_per_minute: 10_000,
                ..Default::default()
            }),
    );
    runtime.block_on(relay.run())?;
    let relay_url = runtime.block_on(relay.url()).to_string();
    assert!(
        relay_url.starts_with("ws://127.0.0.1:") || relay_url.starts_with("ws://localhost:"),
        "fixture must bind loopback only"
    );
    let replacement = LocalRelay::new(
        RelayBuilder::default()
            .write_policy(request_gate.clone())
            .rate_limit(nostr_relay_builder::builder::RateLimit {
                notes_per_minute: 10_000,
                ..Default::default()
            }),
    );
    runtime.block_on(replacement.run())?;
    let replacement_url = runtime.block_on(replacement.url()).to_string();
    let fixture_a = runtime.block_on(Fixture::start(&relay_url, Some(&replacement_url)))?;
    let fixture_b = runtime.block_on(Fixture::start(&relay_url, None))?;
    assert_ne!(fixture_a.bunker.public_key(), fixture_b.bunker.public_key());
    assert_ne!(fixture_a.user.public_key(), fixture_b.user.public_key());
    let root = tempfile::tempdir()?;
    let owner = ClientOwner(Handle::open(&root, &relay_url));
    let client = owner.0;

    let relay_c = c(&relay_url);
    let relays = [relay_c.as_ptr()];
    let mut local = ptr::null_mut();
    check(
        unsafe {
            marmot_create_identity(
                client.0,
                relays.as_ptr(),
                1,
                relays.as_ptr(),
                1,
                ptr::null(),
                0,
                &mut local,
            )
        },
        "local identity",
    );
    let local_id = unsafe { input((*local).account_id_hex) };
    assert!(unsafe { (*local).local_signing && !(*local).external_signing });
    unsafe { marmot_account_summary_free(local) };
    println!("PASS local C-ABI identity uses host secret store");

    let bunker_uri = format!(
        "bunker://{}?relay={}&secret=one-use-smoke",
        fixture_a.bunker.public_key(),
        relay_url.replace(':', "%3A").replace('/', "%2F")
    );
    let session_a = Session::new(client, &json!({"uri":bunker_uri}));
    let session_b = Session::new(
        client,
        &json!({"relays":[relay_url],"name":"White Noise Linux smoke"}),
    );
    let pairing_uri = session_b.uri();
    assert!(pairing_uri.starts_with("nostrconnect://"));
    let parsed = url::Url::parse(&pairing_uri)?;
    let pairing_client =
        PublicKey::parse(parsed.host_str().ok_or("pairing URI without client key")?)?;
    let pairing_secret = parsed
        .query_pairs()
        .find(|(name, _)| name == "secret")
        .ok_or("pairing URI without secret")?
        .1
        .into_owned();
    std::thread::scope(|scope| -> Result<()> {
        let completed = Arc::new(AtomicBool::new(false));
        let flag = completed.clone();
        let pairing_session = &session_b;
        let connecting = scope.spawn(move || {
            let id = pairing_session.connect();
            flag.store(true, Ordering::SeqCst);
            id
        });
        runtime.block_on(fixture_b.pairing.send(Pairing {
            client: pairing_client,
            secret: "spoofed-wrong-secret".into(),
            author: Keys::generate(),
        }))?;
        std::thread::sleep(Duration::from_millis(250));
        assert!(
            !completed.load(Ordering::SeqCst),
            "spoofed pairing completed connect"
        );
        assert_ne!(session_b.state()["state"], "ready");
        runtime.block_on(fixture_b.pairing.send(Pairing {
            client: pairing_client,
            secret: pairing_secret,
            author: fixture_b.bunker.clone(),
        }))?;
        fixture_a
            .controls
            .invalid_identity
            .store(true, Ordering::SeqCst);
        let mut invalid_user = ptr::null_mut();
        assert_eq!(
            unsafe { marmot_nip46_connect(session_a.0, &mut invalid_user) },
            MarmotStatus::InvalidArgument
        );
        assert!(invalid_user.is_null());
        assert_eq!(session_a.connect(), fixture_a.user.public_key().to_hex());
        assert_eq!(
            fixture_a
                .controls
                .evidence
                .lock()
                .expect("evidence mutex")
                .connect_secrets
                .iter()
                .filter(|secret| secret.as_str() == "one-use-smoke")
                .count(),
            1,
            "partial identity failure must not replay an acknowledged one-use secret"
        );
        assert_eq!(
            connecting.join().expect("connect worker"),
            fixture_b.user.public_key().to_hex()
        );
        Ok(())
    })?;
    println!(
        "PASS bunker import and nostrconnect pairing reject spoofed secret and pin user != bunker"
    );

    let account_a = session_a.login(client, &relay_url, fixture_a.user.public_key());
    let account_b = session_b.login(client, &relay_url, fixture_b.user.public_key());
    assert_accounts(client, &local_id, &account_a, &account_b, false);
    {
        let secrets = SECRETS.lock().expect("host store mutex");
        assert_eq!(
            secrets.len(),
            3,
            "local identity and two external database secrets belong in the host store"
        );
        assert_eq!(
            secrets
                .iter()
                .filter(|(label, _, _)| label == &local_id)
                .count(),
            1
        );
        assert_eq!(
            secrets
                .iter()
                .filter(|(label, _, _)| label.starts_with(".external-sqlcipher/"))
                .count(),
            2
        );
        for (_, _, secret) in secrets.iter() {
            assert_ne!(
                secret,
                &fixture_a.user.secret_key().to_secret_hex(),
                "remote account key entered local store"
            );
            assert_ne!(
                secret,
                &fixture_b.user.secret_key().to_secret_hex(),
                "remote account key entered local store"
            );
        }
    }
    fn check_database_secrets(path: &std::path::Path) -> Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            assert_ne!(
                entry.file_name(),
                ".external-sqlcipher-secret",
                "device database key written outside host secret store"
            );
            if entry.file_type()?.is_dir() {
                check_database_secrets(&entry.path())?;
            }
        }
        Ok(())
    }
    check_database_secrets(root.path())?;
    for fixture in [&fixture_a, &fixture_b] {
        let evidence = fixture.controls.evidence.lock().expect("evidence mutex");
        assert!(
            evidence
                .signed
                .iter()
                .any(|event| event.kind == Kind::from(450)),
            "native account identity proof must cross NIP46"
        );
        assert!(
            evidence
                .signed
                .iter()
                .any(|event| event.kind == Kind::from(30443)),
            "native keypackage must cross NIP46"
        );
        assert!(
            evidence
                .signed
                .iter()
                .any(|event| event.kind == Kind::InboxRelays),
            "missing inbox must bootstrap through NIP46"
        );
        assert!(
            !evidence
                .signed
                .iter()
                .any(|event| event.kind == Kind::RelayList),
            "an observed signed outbox must stay unchanged"
        );
        for event in &evidence.signed {
            event.verify()?;
            assert_eq!(event.pubkey, fixture.user.public_key());
        }
    }
    println!("PASS two external C-ABI accounts sign real MLS identity proofs and keypackages");
    println!(
        "PASS incomplete indexer does not veto authoritative outbox absence and remote-signed inbox bootstrap"
    );
    println!("PASS inbox bootstrap preserves the observed signed outbox");

    let export_a = session_a.export();
    let export_b = session_b.export();
    assert_ne!(export_a["client_secret"], export_b["client_secret"]);
    for (descriptor, fixture, expected_relay) in [
        (&export_a, &fixture_a, &replacement_url),
        (&export_b, &fixture_b, &relay_url),
    ] {
        assert_eq!(
            descriptor["user_public_key"],
            fixture.user.public_key().to_hex()
        );
        assert_eq!(
            descriptor["remote_signer_public_key"],
            fixture.bunker.public_key().to_hex()
        );
        assert_eq!(
            descriptor["relays"],
            json!([expected_relay]),
            "switch_relays must persist only this session's replacement transport"
        );
        runtime.block_on(nip44_probe(expected_relay, descriptor, fixture))?;
    }
    println!(
        "PASS signer relay migration persists independently of messaging and other signer relays"
    );
    println!(
        "PASS signed NIP44 wire roundtrips correlate reversed interleaved replies independently"
    );

    let request_author = Keys::parse(export_a["client_secret"].as_str().unwrap())?
        .public_key()
        .to_hex();
    *request_gate.0.lock().unwrap() = Some(request_author);
    let rejected = client.profile(&account_a, "relay-rejected-request");
    let detail = take_string(marmot_last_error_message());
    *request_gate.0.lock().unwrap() = None;
    assert_ne!(rejected, MarmotStatus::Ok);
    assert!(
        !detail.contains("signer request denied by relay") && !detail.contains(&replacement_url),
        "relay URLs and relay-supplied text must stay out of error details: {detail}"
    );
    check(
        client.profile(&account_a, "after-relay-rejection"),
        "same account recovers after relay rejection",
    );
    check(
        client.profile(&account_b, "other-after-relay-rejection"),
        "other signer remains usable",
    );
    println!("PASS relay rejection stays privacy-safe and the session recovers");

    fixture_a.controls.approval.store(true, Ordering::SeqCst);
    std::thread::scope(|scope| -> Result<()> {
        let waiting = scope.spawn(|| client.profile(&account_a, "approval-smoke"));
        runtime.block_on(async {
            tokio::time::timeout(WAIT, fixture_a.controls.approval_sent.notified()).await
        })?;
        // Delivery to the native actor can follow the fixture's successful relay acknowledgement.
        let deadline = std::time::Instant::now() + WAIT;
        loop {
            let state = session_a.state();
            if state["state"] == "approval" {
                assert_eq!(state["auth_url"], AUTH_URL);
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "auth_url intermediate was not surfaced"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        check(
            client.profile(&account_b, "other-session-during-approval"),
            "other account while approval pending",
        );
        check(
            client.profile(&local_id, "local-during-approval"),
            "local account while approval pending",
        );
        fixture_a.controls.finish_approval.notify_one();
        check(
            waiting.join().expect("approval worker"),
            "approval final result",
        );
        assert_eq!(session_a.state()["state"], "ready");
        Ok(())
    })?;
    println!("PASS auth_url remains intermediate; local and second remote account stay usable");

    fixture_a.controls.wrong_event.store(true, Ordering::SeqCst);
    assert_ne!(
        client.profile(&account_a, "must-not-accept-substituted-event"),
        MarmotStatus::Ok,
        "valid signature on wrong event must be rejected"
    );
    check(
        client.profile(&account_b, "after-other-signer-bad-result"),
        "other account after substituted event",
    );
    println!(
        "PASS native adapter rejects validly signed substituted event without poisoning other account"
    );

    // Free is a transport disconnect, not logout; encrypted-vault descriptor can reconnect.
    drop(session_a);
    drop(session_b);
    drop(owner);
    let owner = ClientOwner(Handle::open(&root, &relay_url));
    let client = owner.0;
    let pending_a = Session::new(client, &export_a);
    let session_b = Session::new(client, &export_b);
    fixture_a.controls.offline.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    check(
        unsafe { marmot_client_start(client.0) },
        "local startup with offline signer",
    );
    assert!(
        started.elapsed() < WAIT,
        "offline signer blocked local startup"
    );
    check(
        client.profile(&local_id, "local-after-cold-restart"),
        "local after cold restart",
    );
    assert_eq!(session_b.connect(), account_b);
    session_b.register(client, &account_b);
    check(
        client.profile(&account_b, "remote-after-cold-restart"),
        "other remote after cold restart",
    );
    fixture_a.controls.offline.store(false, Ordering::SeqCst);
    drop(pending_a);
    println!(
        "PASS cold restart reopens encrypted account databases; offline signer does not block local/other remote accounts"
    );
    let mut wrong_pin = export_a.clone();
    wrong_pin["user_public_key"] = json!(fixture_b.user.public_key().to_hex());
    let mismatched = Session::new(client, &wrong_pin);
    let mut wrong_user = ptr::null_mut();
    assert_eq!(
        unsafe { marmot_nip46_connect(mismatched.0, &mut wrong_user) },
        MarmotStatus::ExternalSignerMismatch,
        "restored user identity must remain pinned"
    );
    assert!(wrong_user.is_null());
    drop(mismatched);
    let session_a = Session::new(client, &export_a);
    assert_eq!(session_a.connect(), account_a);
    session_a.register(client, &account_a);
    client.keypackage(&account_a);
    let secrets = fixture_a
        .controls
        .evidence
        .lock()
        .expect("evidence mutex")
        .connect_secrets
        .clone();
    assert_eq!(
        secrets
            .iter()
            .filter(|secret| secret.as_str() == "one-use-smoke")
            .count(),
        1,
        "restore must not consume bunker secret twice"
    );
    println!(
        "PASS export/free/restore/register preserves pinned identity without replaying one-use bunker secret"
    );

    // Interrupt only one transport; its account must not borrow the other session's signer.
    unsafe { marmot_nip46_cancel(session_a.0) };
    assert_ne!(
        client.profile(&account_a, "cancelled-session"),
        MarmotStatus::Ok
    );
    check(
        client.profile(&account_b, "survives-other-cancel"),
        "other remote after cancellation",
    );
    check(
        client.profile(&local_id, "survives-other-cancel"),
        "local after cancellation",
    );
    drop(session_a);
    let session_a = Session::new(client, &export_a);
    assert_eq!(session_a.connect(), account_a);
    session_a.register(client, &account_a);
    sign_out(client, &account_a);
    // No acknowledgement: local credentials must still be revoked, bounded by native timeout.
    fixture_a.controls.offline.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let courtesy_status = unsafe { marmot_nip46_logout(session_a.0) };
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "logout must be bounded without remote acknowledgement"
    );
    assert_eq!(
        courtesy_status,
        MarmotStatus::Timeout,
        "offline signer cannot acknowledge logout"
    );
    assert_eq!(session_a.state()["state"], "logged_out");
    let mut rejected = ptr::null_mut();
    assert_ne!(
        unsafe { marmot_nip46_export(session_a.0, &mut rejected) },
        MarmotStatus::Ok,
        "revoked client secret must no longer export"
    );
    assert!(rejected.is_null());
    check(
        client.profile(&account_b, "survives-other-logout"),
        "other remote after logout",
    );
    check(
        client.profile(&local_id, "survives-other-logout"),
        "local after logout",
    );
    assert_accounts(client, &local_id, &account_a, &account_b, true);
    println!(
        "PASS one-session cancel and unacknowledged logout preserve local/other remote accounts"
    );

    drop(session_a);
    drop(session_b);
    drop(owner);
    runtime.block_on(fixture_a.stop())?;
    runtime.block_on(fixture_b.stop())?;
    drop(relay);
    drop(replacement);
    done.send(())?;
    watchdog.join().expect("watchdog worker");
    println!(
        "PASS nip46 smoke complete (real loopback websocket relay, distinct bunker/user/client keys)"
    );
    Ok(())
}
