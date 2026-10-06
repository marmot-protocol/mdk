//! NIP-46 C sessions. Each session has an independently driven transport, so
//! synchronous MLS identity-proof callbacks never depend on the calling runtime.

use crate::memory::{self, CFree, required_str, str_array};
use crate::status::{set_last_error, status_from_error};
use crate::types::account::MarmotAccountSummary;
use crate::{MarmotClient, MarmotStatus, client_ref, ffi_guard, preflight_out_ptr};
use futures::{Stream, StreamExt};
use marmot_uniffi::{
    ExternalAccountSignerFfi, Marmot, MarmotKitError, conversions::RelayEndpointPolicyFfi,
};
use nostr::nips::{nip44, nip46::NostrConnectUri};
use nostr::prelude::*;
use nostr_sdk::prelude::{Client, ClientNotification};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ffi::c_char,
    pin::Pin,
    sync::{Arc, Mutex, Weak, mpsc as sync_mpsc},
    thread,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use zeroize::{Zeroize, Zeroizing};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PAYLOAD: usize = 2 * 1024 * 1024;
const PERMS: &str = "sign_event:450,sign_event:30443,sign_event:13,sign_event:22242,sign_event:10002,sign_event:10050,sign_event:5,sign_event:0,sign_event:3,sign_event:10000,sign_event:24242,sign_event:451,nip44_encrypt,nip44_decrypt,nip04_decrypt";

type Notifications = Pin<Box<dyn Stream<Item = ClientNotification> + Send>>;
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Serialize)]
struct SignRequest<'a> {
    kind: Kind,
    content: &'a str,
    tags: &'a Tags,
    created_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Error {
    Invalid,
    Unavailable,
    RelayPublish(String),
    Rejected,
    Mismatch,
    Timeout,
    Cancelled,
    LoggedOut,
    Unsupported,
}
impl Error {
    fn detail(&self) -> std::borrow::Cow<'static, str> {
        match self {
            Self::Invalid => "invalid NIP-46 configuration or protocol response".into(),
            Self::Unavailable => "remote signer unavailable".into(),
            Self::RelayPublish(detail) => std::borrow::Cow::Owned(detail.clone()),
            Self::Rejected => "remote signer rejected the request".into(),
            Self::Mismatch => "remote signer public key or signed event mismatch".into(),
            Self::Timeout => "remote signer request timed out".into(),
            Self::Cancelled => "remote signer request cancelled".into(),
            Self::LoggedOut => "remote signer session logged out".into(),
            Self::Unsupported => "remote signer does not support the method".into(),
        }
    }
    fn status(self) -> MarmotStatus {
        set_last_error(self.detail().as_ref());
        match self {
            Self::Invalid => MarmotStatus::InvalidArgument,
            Self::Timeout => MarmotStatus::Timeout,
            Self::Rejected | Self::Cancelled => MarmotStatus::ExternalSignerRejected,
            Self::Mismatch => MarmotStatus::ExternalSignerMismatch,
            _ => MarmotStatus::ExternalSignerUnavailable,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    user_public_key: Option<String>,
    #[serde(default)]
    remote_signer_public_key: Option<String>,
}
impl Drop for Config {
    fn drop(&mut self) {
        if let Some(secret) = &mut self.client_secret {
            secret.zeroize();
        }
        if let Some(uri) = &mut self.uri {
            uri.zeroize();
        }
    }
}

struct Credentials {
    keys: Option<Keys>,
    remote: Option<PublicKey>,
    user: Option<PublicKey>,
    relays: Vec<RelayUrl>,
    uri: String,
    secret: Option<Zeroizing<String>>,
    client_pairing: bool,
    name: String,
    verified: bool,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.uri.zeroize();
    }
}

#[derive(Clone, Serialize)]
struct State {
    state: &'static str,
    detail: std::borrow::Cow<'static, str>,
    auth_url: Option<String>,
}
struct Session {
    owner: Weak<Marmot>,
    credentials: Mutex<Credentials>,
    state: Mutex<State>,
    commands: mpsc::Sender<Command>,
    cancel: watch::Sender<bool>,
}
struct Command {
    operation: Operation,
    deadline: Instant,
    reply: sync_mpsc::SyncSender<Result<Value>>,
}
enum Operation {
    Connect,
    Rpc(&'static str, Vec<String>),
    Logout,
}

/// Opaque per-account remote signer. Free before its creating client. Cancellation
/// is thread-safe; free must not race an in-flight call on this handle.
pub struct MarmotNip46Session {
    inner: Arc<Session>,
    worker: Option<thread::JoinHandle<()>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn checked_relays(owner: &Marmot, relays: Vec<String>) -> Result<Vec<RelayUrl>> {
    if relays.is_empty() || relays.len() > 16 {
        return Err(Error::Invalid);
    }
    let mut checked = Vec::with_capacity(relays.len());
    for classification in owner.classify_relay_endpoints(relays) {
        if !matches!(classification.policy, RelayEndpointPolicyFfi::Allowed) {
            return Err(Error::Invalid);
        }
        let relay = RelayUrl::parse(&classification.normalized_endpoint.ok_or(Error::Invalid)?)
            .map_err(|_| Error::Invalid)?;
        if !checked.contains(&relay) {
            checked.push(relay);
        }
    }
    Ok(checked)
}

impl Session {
    fn spawn(owner: Arc<Marmot>, mut config: Config) -> Result<MarmotNip46Session> {
        let keys = match config.client_secret.as_deref() {
            Some(secret) => Keys::new(SecretKey::from_hex(secret).map_err(|_| Error::Invalid)?),
            None => Keys::generate(),
        };
        let name = config
            .name
            .take()
            .unwrap_or_else(|| "White Noise Linux".into());
        let user = config
            .user_public_key
            .as_deref()
            .map(PublicKey::from_hex)
            .transpose()
            .map_err(|_| Error::Invalid)?;
        let restored_remote = config
            .remote_signer_public_key
            .as_deref()
            .map(PublicKey::from_hex)
            .transpose()
            .map_err(|_| Error::Invalid)?;
        if user.is_some() != restored_remote.is_some()
            || (user.is_some() && config.client_secret.is_none())
        {
            return Err(Error::Invalid);
        }
        let (remote, relays, uri, secret, client_pairing) = if let Some(remote) = restored_remote {
            // Durable credentials deliberately have no one-use bunker secret.
            let relays = checked_relays(&owner, std::mem::take(&mut config.relays))?;
            let uri = NostrConnectUri::Bunker {
                remote_signer_public_key: remote,
                relays: relays.clone(),
                secret: None,
            }
            .to_string();
            (Some(remote), relays, uri, None, false)
        } else if let Some(uri) = config.uri.take() {
            let parsed = NostrConnectUri::parse(&uri).map_err(|_| Error::Invalid)?;
            let NostrConnectUri::Bunker {
                remote_signer_public_key,
                relays,
                secret,
            } = parsed
            else {
                return Err(Error::Invalid);
            };
            let relays = checked_relays(&owner, relays.iter().map(ToString::to_string).collect())?;
            (
                Some(remote_signer_public_key),
                relays,
                uri,
                secret.map(Zeroizing::new),
                false,
            )
        } else {
            let relays = checked_relays(&owner, std::mem::take(&mut config.relays))?;
            let secret = Zeroizing::new(Keys::generate().public_key().to_hex());
            let mut uri = url::Url::parse(&format!("nostrconnect://{}", keys.public_key()))
                .map_err(|_| Error::Invalid)?;
            {
                let mut query = uri.query_pairs_mut();
                for relay in &relays {
                    query.append_pair("relay", relay.as_str());
                }
                query
                    .append_pair("secret", secret.as_str())
                    .append_pair("perms", PERMS)
                    .append_pair("name", &name);
            }
            (None, relays, uri.to_string(), Some(secret), true)
        };
        let (commands, receiver) = mpsc::channel(32);
        let (cancel, cancellation) = watch::channel(false);
        let session = Arc::new(Self {
            owner: Arc::downgrade(&owner),
            credentials: Mutex::new(Credentials {
                keys: Some(keys),
                remote,
                user,
                relays,
                uri,
                secret,
                client_pairing,
                name,
                verified: false,
            }),
            state: Mutex::new(State {
                state: "unavailable",
                detail: "remote signer not connected".into(),
                auth_url: None,
            }),
            commands,
            cancel,
        });
        let transport = session.clone();
        let worker = thread::Builder::new()
            .name("nip46-transport".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => {
                        runtime.block_on(run_transport(transport, receiver, cancellation))
                    }
                    Err(_) => transport.set_state(
                        "unavailable",
                        "remote signer transport could not start",
                        None,
                    ),
                }
            })
            .map_err(|_| Error::Unavailable)?;
        Ok(MarmotNip46Session {
            inner: session,
            worker: Some(worker),
        })
    }

    fn set_state(
        &self,
        state: &'static str,
        detail: impl Into<std::borrow::Cow<'static, str>>,
        auth_url: Option<String>,
    ) {
        let mut current = lock(&self.state);
        // A late remote reply must never revive a cancelled or logged-out handle.
        if matches!(current.state, "cancelled" | "logged_out")
            && !matches!(state, "cancelled" | "logged_out")
        {
            return;
        }
        *current = State {
            state,
            detail: detail.into(),
            auth_url,
        };
    }
    fn cancel(&self) {
        self.cancel.send_replace(true);
        self.set_state("cancelled", Error::Cancelled.detail(), None);
    }
    fn call(&self, operation: Operation, timeout: Duration) -> Result<Value> {
        if *self.cancel.borrow() {
            return Err(Error::Cancelled);
        }
        if lock(&self.credentials).keys.is_none() {
            return Err(Error::LoggedOut);
        }
        let (reply, response) = sync_mpsc::sync_channel(1);
        self.commands
            .try_send(Command {
                operation,
                deadline: Instant::now() + timeout,
                reply,
            })
            .map_err(|_| Error::Unavailable)?;
        // Only this calling thread blocks. The independent session actor continues
        // driving relay IO even during synchronous kind-450 proof signing.
        match response.recv_timeout(timeout + Duration::from_secs(1)) {
            Ok(result) => result,
            Err(sync_mpsc::RecvTimeoutError::Timeout) => {
                self.cancel();
                Err(Error::Timeout)
            }
            Err(sync_mpsc::RecvTimeoutError::Disconnected) => Err(Error::Unavailable),
        }
    }
    fn pinned_user(&self) -> Result<PublicKey> {
        lock(&self.credentials).user.ok_or(Error::Unavailable)
    }
    /// `ExternalSignerUnavailable.account` is the account id, never a detail;
    /// it stays empty before pairing pins a user.
    fn signer_error(&self, error: Error) -> MarmotKitError {
        match error {
            Error::Rejected | Error::Cancelled => MarmotKitError::ExternalSignerRejected,
            Error::Mismatch => MarmotKitError::ExternalSignerMismatch,
            _ => MarmotKitError::ExternalSignerUnavailable {
                account: self
                    .pinned_user()
                    .map(|user| user.to_hex())
                    .unwrap_or_default(),
            },
        }
    }
    fn export(&self) -> Result<String> {
        let data = lock(&self.credentials);
        let keys = data.keys.as_ref().ok_or(Error::LoggedOut)?;
        let user = data.user.ok_or(Error::Unavailable)?;
        let remote = data.remote.ok_or(Error::Unavailable)?;
        let secret = Zeroizing::new(keys.secret_key().to_secret_hex());
        Ok(json!({ "client_secret":secret.as_str(), "user_public_key":user.to_hex(), "remote_signer_public_key":remote.to_hex(), "relays":data.relays.iter().map(ToString::to_string).collect::<Vec<_>>(), "name":data.name }).to_string())
    }
    fn clear_keys(&self) {
        let mut data = lock(&self.credentials);
        data.keys = None;
        data.secret = None;
        data.uri.zeroize();
        data.verified = false;
        drop(data);
        self.cancel.send_replace(true);
        self.set_state("logged_out", "remote signer session logged out", None);
    }
    fn rpc_string(
        &self,
        method: &'static str,
        params: Vec<String>,
    ) -> std::result::Result<String, MarmotKitError> {
        self.call(Operation::Rpc(method, params), REQUEST_TIMEOUT)
            .and_then(|value| value.as_str().map(ToOwned::to_owned).ok_or(Error::Invalid))
            .map_err(|error| self.signer_error(error))
    }
}

impl ExternalAccountSignerFfi for Session {
    fn public_key(&self) -> std::result::Result<String, MarmotKitError> {
        if *self.cancel.borrow() || lock(&self.credentials).keys.is_none() {
            return Err(self.signer_error(Error::Cancelled));
        }
        // Identity lookup is offline: MDK compares this pinned user identity.
        // Worker activation can request a fresh proof; its first signing
        // operation re-verifies the user remotely on the independent transport.
        self.pinned_user()
            .map(|key| key.to_hex())
            .map_err(|error| self.signer_error(error))
    }
    fn sign_event(
        &self,
        unsigned_event_json: String,
    ) -> std::result::Result<String, MarmotKitError> {
        let unsigned = UnsignedEvent::from_json(&unsigned_event_json)
            .map_err(|_| self.signer_error(Error::Invalid))?;
        let expected_user = self
            .pinned_user()
            .map_err(|error| self.signer_error(error))?;
        if unsigned.pubkey != expected_user {
            return Err(self.signer_error(Error::Mismatch));
        }
        // NIP-46 sends only these fields. Keep the SDK's id and pinned pubkey
        // locally to verify that the returned event is exactly the requested one.
        let request = SignRequest {
            kind: unsigned.kind,
            content: &unsigned.content,
            tags: &unsigned.tags,
            created_at: unsigned.created_at,
        };
        let payload =
            serde_json::to_string(&request).map_err(|_| self.signer_error(Error::Invalid))?;
        let result = self.rpc_string("sign_event", vec![payload])?;
        let event = Event::from_json(&result).map_err(|_| self.signer_error(Error::Invalid))?;
        if event.pubkey != expected_user
            || event.kind != unsigned.kind
            || event.created_at != unsigned.created_at
            || event.content != unsigned.content
            || event.tags != unsigned.tags
            || unsigned.id.is_some_and(|id| id != event.id)
        {
            return Err(self.signer_error(Error::Mismatch));
        }
        event
            .verify()
            .map_err(|_| self.signer_error(Error::Mismatch))?;
        Ok(result)
    }
    fn nip04_encrypt(
        &self,
        public_key: String,
        content: String,
    ) -> std::result::Result<String, MarmotKitError> {
        self.rpc_string("nip04_encrypt", vec![public_key, content])
    }
    fn nip04_decrypt(
        &self,
        public_key: String,
        encrypted_content: String,
    ) -> std::result::Result<String, MarmotKitError> {
        self.rpc_string("nip04_decrypt", vec![public_key, encrypted_content])
    }
    fn nip44_encrypt(
        &self,
        public_key: String,
        content: String,
    ) -> std::result::Result<String, MarmotKitError> {
        self.rpc_string("nip44_encrypt", vec![public_key, content])
    }
    fn nip44_decrypt(
        &self,
        public_key: String,
        payload: String,
    ) -> std::result::Result<String, MarmotKitError> {
        self.rpc_string("nip44_decrypt", vec![public_key, payload])
    }
}

struct Transport {
    client: Client,
    notifications: Notifications,
    configured: Vec<RelayUrl>,
}
impl Transport {
    fn new() -> Self {
        let client = Client::default();
        let notifications = client.notifications();
        Self {
            client,
            notifications,
            configured: Vec::new(),
        }
    }
    async fn configure(&mut self, session: &Session) -> Result<()> {
        let (relays, public_key) = {
            let data = lock(&session.credentials);
            (
                data.relays.clone(),
                data.keys.as_ref().ok_or(Error::LoggedOut)?.public_key(),
            )
        };
        if self.configured == relays {
            return Ok(());
        }
        for relay in &relays {
            self.client
                .add_relay(relay.clone())
                .await
                .map_err(|_| Error::Unavailable)?;
        }
        self.client.connect().and_wait(Duration::from_secs(5)).await;
        self.client
            .subscribe(
                Filter::new()
                    .kind(Kind::NostrConnect)
                    .pubkey(public_key)
                    .since(Timestamp::from(
                        Timestamp::now().as_secs().saturating_sub(300),
                    )),
            )
            .await
            .map_err(|_| Error::Unavailable)?;
        for relay in &self.configured {
            if !relays.contains(relay) {
                self.client
                    .remove_relay(relay.clone())
                    .await
                    .map_err(|_| Error::Unavailable)?;
            }
        }
        self.configured = relays;
        Ok(())
    }
    async fn send(&self, keys: &Keys, remote: PublicKey, payload: Value) -> Result<()> {
        let encrypted = nip44::encrypt(
            keys.secret_key(),
            &remote,
            payload.to_string(),
            nip44::Version::V2,
        )
        .map_err(|_| Error::Invalid)?;
        let event = EventBuilder::new(Kind::NostrConnect, encrypted)
            .tag(remote)
            .finalize(keys)
            .map_err(|_| Error::Invalid)?;
        // Relay URLs and relay-supplied text stay out of error details.
        let output = self.client.send_event(&event).await.map_err(|_| {
            Error::RelayPublish("NIP-46 request relay publication failed".to_owned())
        })?;
        if output.success.is_empty() {
            return Err(Error::RelayPublish(format!(
                "NIP-46 request rejected by {} relay(s)",
                output.failed.len()
            )));
        }
        Ok(())
    }
    async fn next_payload(
        &mut self,
        keys: &Keys,
        expected: Option<PublicKey>,
    ) -> Result<(PublicKey, Value)> {
        while let Some(notification) = self.notifications.next().await {
            if let ClientNotification::Event { event, .. } = notification
                && let Some(payload) = validated_payload(&event, keys, expected)
            {
                return Ok((event.pubkey, payload));
            }
        }
        Err(Error::Unavailable)
    }
    async fn rpc(
        &mut self,
        session: &Session,
        method: &'static str,
        params: Vec<String>,
    ) -> Result<Value> {
        let (keys, remote) = {
            let data = lock(&session.credentials);
            (
                data.keys.clone().ok_or(Error::LoggedOut)?,
                data.remote.ok_or(Error::Unavailable)?,
            )
        };
        let id = Keys::generate().public_key().to_hex();
        self.send(
            &keys,
            remote,
            json!({"id":id,"method":method,"params":params}),
        )
        .await?;
        loop {
            let (_, payload) = self.next_payload(&keys, Some(remote)).await?;
            match matching_response(&payload, &id) {
                Response::Ignore => continue,
                Response::Approval(url) => {
                    session.set_state("approval", "remote signer approval required", Some(url))
                }
                Response::Complete(result) => return result,
            }
        }
    }
    async fn connect(&mut self, session: &Session) -> Result<Value> {
        let verified = lock(&session.credentials).verified;
        if !verified {
            session.set_state("connecting", "connecting to remote signer", None);
        }
        self.configure(session).await?;
        if verified {
            return Ok(Value::String(session.pinned_user()?.to_hex()));
        }
        let (user, remote, pairing) = {
            let data = lock(&session.credentials);
            (data.user, data.remote, data.client_pairing)
        };
        if user.is_none() {
            if pairing && remote.is_none() {
                let (keys, secret) = {
                    let data = lock(&session.credentials);
                    (
                        data.keys.clone().ok_or(Error::LoggedOut)?,
                        data.secret.clone().ok_or(Error::Invalid)?,
                    )
                };
                loop {
                    let (author, payload) = self.next_payload(&keys, None).await?;
                    if pairing_response(&payload, secret.as_str()) {
                        let mut data = lock(&session.credentials);
                        data.remote = Some(author);
                        data.secret = None;
                        break;
                    }
                }
            } else if !pairing {
                let (remote, secret, name) = {
                    let data = lock(&session.credentials);
                    (
                        data.remote.ok_or(Error::Invalid)?,
                        data.secret
                            .as_ref()
                            .map(|secret| secret.to_string())
                            .unwrap_or_default(),
                        data.name.clone(),
                    )
                };
                let ack = self
                    .rpc(
                        session,
                        "connect",
                        vec![
                            remote.to_hex(),
                            secret.clone(),
                            PERMS.into(),
                            json!({"name":name}).to_string(),
                        ],
                    )
                    .await?;
                if ack.as_str() != Some("ack")
                    && (secret.is_empty() || ack.as_str() != Some(secret.as_str()))
                {
                    return Err(Error::Invalid);
                }
                lock(&session.credentials).secret = None;
            }
        }
        let response = self.rpc(session, "get_public_key", Vec::new()).await?;
        let public_key = PublicKey::from_hex(response.as_str().ok_or(Error::Invalid)?)
            .map_err(|_| Error::Invalid)?;
        {
            let mut data = lock(&session.credentials);
            if data.user.is_some_and(|user| user != public_key) {
                return Err(Error::Mismatch);
            }
            data.user = Some(public_key);
        }
        match self.rpc(session, "switch_relays", Vec::new()).await {
            Ok(result) => {
                let result = if let Value::String(value) = &result {
                    serde_json::from_str::<Value>(value).map_err(|_| Error::Invalid)?
                } else {
                    result
                };
                if !result.is_null() {
                    let relays: Vec<String> =
                        serde_json::from_value(result).map_err(|_| Error::Invalid)?;
                    let relays = checked_relays(
                        session.owner.upgrade().ok_or(Error::Unavailable)?.as_ref(),
                        relays,
                    )?;
                    lock(&session.credentials).relays = relays;
                    self.configure(session).await?;
                }
            }
            // Older NIP-46 servers predate switch_relays. Only an explicit
            // unsupported-method response leaves the existing policy-checked set.
            Err(Error::Unsupported) => {}
            Err(error) => return Err(error),
        }
        lock(&session.credentials).verified = true;
        session.set_state("ready", "remote signer connected", None);
        Ok(Value::String(public_key.to_hex()))
    }
}

fn validated_payload(event: &Event, keys: &Keys, expected: Option<PublicKey>) -> Option<Value> {
    if event.kind != Kind::NostrConnect
        || event.content.len() > MAX_PAYLOAD
        || expected.is_some_and(|author| author != event.pubkey)
        || !event.tags.public_keys().any(|key| key == keys.public_key())
        || event.verify().is_err()
    {
        return None;
    }
    let plaintext =
        Zeroizing::new(nip44::decrypt(keys.secret_key(), &event.pubkey, &event.content).ok()?);
    serde_json::from_str(&plaintext).ok()
}
fn pairing_response(payload: &Value, secret: &str) -> bool {
    payload.get("method").is_none()
        && payload.get("id").and_then(Value::as_str).is_some()
        && payload.get("result").and_then(Value::as_str) == Some(secret)
        && payload.get("error").is_none_or(Value::is_null)
}
enum Response {
    Ignore,
    Approval(String),
    Complete(Result<Value>),
}
fn matching_response(payload: &Value, id: &str) -> Response {
    if payload.get("method").is_some() || payload.get("id").and_then(Value::as_str) != Some(id) {
        return Response::Ignore;
    }
    if payload.get("result").and_then(Value::as_str) == Some("auth_url") {
        let Some(raw) = payload.get("error").and_then(Value::as_str) else {
            return Response::Complete(Err(Error::Invalid));
        };
        let Ok(url) = url::Url::parse(raw) else {
            return Response::Complete(Err(Error::Invalid));
        };
        if !matches!(url.scheme(), "https" | "http")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Response::Complete(Err(Error::Invalid));
        }
        return Response::Approval(url.to_string());
    }
    if let Some(error) = payload.get("error").filter(|error| !error.is_null()) {
        let Some(error) = error.as_str() else {
            return Response::Complete(Err(Error::Invalid));
        };
        let error = error.to_ascii_lowercase();
        return Response::Complete(Err(
            if error.contains("unsupported")
                || error.contains("unknown method")
                || error.contains("not supported")
            {
                Error::Unsupported
            } else {
                Error::Rejected
            },
        ));
    }
    Response::Complete(payload.get("result").cloned().ok_or(Error::Invalid))
}

async fn run_transport(
    session: Arc<Session>,
    mut commands: mpsc::Receiver<Command>,
    mut cancel: watch::Receiver<bool>,
) {
    let mut transport = Transport::new();
    loop {
        let command = tokio::select! {
            biased;
            _ = cancel.changed() => break,
            command = commands.recv() => match command { Some(command) => command, None => break },
        };
        let deadline = tokio::time::Instant::from_std(command.deadline);
        let future = async {
            match command.operation {
                Operation::Connect => transport.connect(&session).await,
                Operation::Rpc(method, params) => {
                    transport.connect(&session).await?;
                    transport.rpc(&session, method, params).await
                }
                Operation::Logout => {
                    transport.configure(&session).await?;
                    let result = transport.rpc(&session, "logout", Vec::new()).await?;
                    if result.as_str() != Some("ack") {
                        return Err(Error::Invalid);
                    }
                    Ok(result)
                }
            }
        };
        let result = tokio::select! {
            biased;
            _ = cancel.changed() => Err(Error::Cancelled),
            result = tokio::time::timeout_at(deadline, future) => result.unwrap_or(Err(Error::Timeout)),
        };
        match &result {
            Ok(_) => session.set_state("ready", "remote signer connected", None),
            Err(Error::Cancelled) => {
                session.set_state("cancelled", Error::Cancelled.detail(), None)
            }
            Err(error) => {
                lock(&session.credentials).verified = false;
                session.set_state("unavailable", error.detail(), None);
            }
        }
        // Receiver timeouts are cancellation, so the reply may already be gone.
        let _ = command.reply.send(result);
        if *cancel.borrow() {
            break;
        }
    }
    commands.close();
    while let Ok(command) = commands.try_recv() {
        let _ = command.reply.send(Err(Error::Cancelled));
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), transport.client.disconnect()).await;
}

unsafe fn session_ref<'a>(
    session: *const MarmotNip46Session,
) -> std::result::Result<&'a MarmotNip46Session, MarmotStatus> {
    if session.is_null() {
        set_last_error("NIP-46 session was NULL");
        return Err(MarmotStatus::NullPointer);
    }
    Ok(unsafe { &*session })
}
unsafe fn string_out(out: *mut *mut c_char, result: Result<String>) -> MarmotStatus {
    match result {
        Ok(value) => {
            unsafe { out.write(memory::owned_c_string(value)) };
            MarmotStatus::Ok
        }
        Err(error) => error.status(),
    }
}

/// Create an offline session from a bunker URI, client pairing config, or durable
/// export. The creating client must outlive the session. Client communication keys
/// remain session-local; persist them through the host's encrypted vault export.
/// # Safety
/// Client and config must be valid for the call; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_new(
    client: *const MarmotClient,
    config_json: *const c_char,
    out: *mut *mut MarmotNip46Session,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let client = match unsafe { client_ref(client) } {
            Ok(client) => client,
            Err(status) => return status,
        };
        let config = match unsafe { required_str(config_json) } {
            Ok(config) => Zeroizing::new(config),
            Err(status) => return status,
        };
        let config: Config = match serde_json::from_str(&config) {
            Ok(config) => config,
            Err(_) => return Error::Invalid.status(),
        };
        match Session::spawn(client.marmot.clone(), config) {
            Ok(session) => {
                unsafe { out.write(memory::boxed(session)) };
                MarmotStatus::Ok
            }
            Err(error) => error.status(),
        }
    })
}

/// Get the pairing URI without network IO. Treat this string as a credential.
/// # Safety
/// Session must be live; out writable. Free string with marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_uri(
    session: *const MarmotNip46Session,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        let data = lock(&session.inner.credentials);
        let result = if data.keys.is_none() {
            Err(Error::LoggedOut)
        } else {
            Ok(data.uri.clone())
        };
        unsafe { string_out(out, result) }
    })
}

/// Connect, pin get_public_key, and adopt policy-checked switch_relays. Run off UI.
/// # Safety
/// Session must be live; out writable. Returned user hex uses marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_connect(
    session: *const MarmotNip46Session,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        let result = session
            .inner
            .call(Operation::Connect, REQUEST_TIMEOUT)
            .and_then(|value| value.as_str().map(ToOwned::to_owned).ok_or(Error::Invalid));
        unsafe { string_out(out, result) }
    })
}

/// Export restart credentials. Store ONLY in an encrypted vault; never log them.
/// # Safety
/// Session must be live; out writable. Free with marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_export(
    session: *const MarmotNip46Session,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        unsafe { string_out(out, session.inner.export()) }
    })
}

/// Set up an external account using the verified stable signer instance.
/// inbox_relays sets kind-10050 independently; NULL/0 uses default_relays.
/// # Safety
/// All pointers must be valid for the call; relay arrays follow ordinary C ABI
/// str-array ownership. Out summary is freed with marmot_account_summary_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_login(
    client: *const MarmotClient,
    session: *const MarmotNip46Session,
    default_relays: *const *const c_char,
    default_len: usize,
    bootstrap_relays: *const *const c_char,
    bootstrap_len: usize,
    inbox_relays: *const *const c_char,
    inbox_len: usize,
    out: *mut *mut MarmotAccountSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let client = match unsafe { client_ref(client) } {
            Ok(client) => client,
            Err(status) => return status,
        };
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        if !Weak::ptr_eq(&Arc::downgrade(&client.marmot), &session.inner.owner) {
            return Error::Invalid.status();
        }
        let defaults = match unsafe { str_array(default_relays, default_len) } {
            Ok(relays) => relays,
            Err(status) => return status,
        };
        let bootstrap = match unsafe { str_array(bootstrap_relays, bootstrap_len) } {
            Ok(relays) => relays,
            Err(status) => return status,
        };
        let inbox = match unsafe { str_array(inbox_relays, inbox_len) } {
            Ok(relays) => relays,
            Err(status) => return status,
        };
        let user = match session.inner.call(Operation::Connect, REQUEST_TIMEOUT) {
            Ok(user) => match user.as_str() {
                Some(user) => user.to_owned(),
                None => return Error::Invalid.status(),
            },
            Err(error) => return error.status(),
        };
        let signer: Arc<dyn ExternalAccountSignerFfi> = session.inner.clone();
        match client.block_on(
            client
                .marmot
                .login_external_signer(user, signer, defaults, bootstrap, inbox),
        ) {
            Ok(summary) => {
                unsafe { out.write(memory::boxed(MarmotAccountSummary::from(summary))) };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}

/// Attach a pinned signer and activate its MDK worker. Identity lookup itself
/// is offline, but worker activation requests a fresh identity proof. Restore
/// handles before client_start, then run each account's connect/register on an
/// independent background worker after local startup; never run this on UI.
/// # Safety
/// Client, account_ref and session must be live and belong to the same client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_register(
    client: *const MarmotClient,
    account_ref: *const c_char,
    session: *const MarmotNip46Session,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(client) => client,
            Err(status) => return status,
        };
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        if !Weak::ptr_eq(&Arc::downgrade(&client.marmot), &session.inner.owner) {
            return Error::Invalid.status();
        }
        let account = match unsafe { required_str(account_ref) } {
            Ok(account) => account,
            Err(status) => return status,
        };
        if let Err(error) = session.inner.pinned_user() {
            return error.status();
        }
        let signer: Arc<dyn ExternalAccountSignerFfi> = session.inner.clone();
        match client.block_on(client.marmot.register_external_signer(account, signer)) {
            Ok(()) => MarmotStatus::Ok,
            Err(error) => status_from_error(&error),
        }
    })
}

/// Nonblocking state snapshot; no session keys or signer request payloads.
/// # Safety
/// Session must be live; out writable. Free with marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_state(
    session: *const MarmotNip46Session,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        let state = lock(&session.inner.state).clone();
        unsafe {
            string_out(
                out,
                serde_json::to_string(&state).map_err(|_| Error::Invalid),
            )
        }
    })
}

/// Permanently interrupt pending requests, including synchronous proof callbacks.
/// # Safety
/// Session must be NULL or live; may race other operations, but not free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_cancel(session: *const MarmotNip46Session) {
    memory::free_guard(|| {
        if let Some(session) = unsafe { session.as_ref() } {
            session.inner.cancel();
        }
    });
}

/// Bounded courtesy logout. Local session keys are cleared even on timeout or
/// cancellation. Complete MDK signout first; delete the vault export regardless.
/// # Safety
/// Session must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_logout(session: *const MarmotNip46Session) -> MarmotStatus {
    ffi_guard(|| {
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        let result = session.inner.call(Operation::Logout, LOGOUT_TIMEOUT);
        session.inner.clear_keys();
        match result {
            Ok(_) => MarmotStatus::Ok,
            Err(error) => error.status(),
        }
    })
}

impl CFree for MarmotNip46Session {
    unsafe fn free_in_place(&mut self) {
        self.inner.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
/// Cancel and release transport without remote logout. Vault credentials remain
/// usable after restart. Registered callbacks become cancelled, never dangling.
/// # Safety
/// Session must be NULL or uniquely owned and no other call may be in flight.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_free(session: *mut MarmotNip46Session) {
    memory::free_guard(|| unsafe { memory::free_boxed(session) });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn keys(byte: u8) -> Keys {
        Keys::new(SecretKey::from_hex(&format!("{byte:02x}").repeat(32)).unwrap())
    }
    fn response(author: &Keys, client: &Keys, payload: Value) -> Event {
        let encrypted = nip44::encrypt(
            author.secret_key(),
            &client.public_key(),
            payload.to_string(),
            nip44::Version::V2,
        )
        .unwrap();
        EventBuilder::new(Kind::NostrConnect, encrypted)
            .tag(client.public_key())
            .finalize(author)
            .unwrap()
    }
    #[test]
    fn response_pins_author() {
        let client = keys(1);
        let remote = keys(2);
        let attacker = keys(3);
        let payload = json!({"id":"request-a","result":"ack"});
        let spoof = response(&attacker, &client, payload.clone());
        assert!(validated_payload(&spoof, &client, Some(remote.public_key())).is_none());
        let valid = response(&remote, &client, payload.clone());
        assert_eq!(
            validated_payload(&valid, &client, Some(remote.public_key())),
            Some(payload)
        );
    }
    #[test]
    fn auth_url_continues_request() {
        let auth = json!({"id":"a","result":"auth_url","error":"https://signer.example/approve"});
        assert!(matches!(
            matching_response(&auth, "a"),
            Response::Approval(_)
        ));
        assert!(matches!(
            matching_response(&json!({"id":"b","result":"signed"}), "a"),
            Response::Ignore
        ));
        assert!(
            matches!(matching_response(&json!({"id":"a","result":"signed"}), "a"), Response::Complete(Ok(Value::String(value))) if value == "signed")
        );
    }
    #[test]
    fn pairing_validates_secret() {
        let client = keys(1);
        let remote = keys(2);
        let wrong = json!({"id":"pair","result":"wrong-secret"});
        assert!(!pairing_response(&wrong, "pairing-secret"));
        let payload = json!({"id":"pair","result":"pairing-secret"});
        let mut event = response(&remote, &client, payload.clone());
        assert!(pairing_response(
            &validated_payload(&event, &client, None).unwrap(),
            "pairing-secret"
        ));
        event.content.push('x');
        assert!(validated_payload(&event, &client, None).is_none());
    }
    #[test]
    fn responses_isolate_sessions() {
        let alice = keys(1);
        let bob = keys(2);
        let remote = keys(3);
        let event = response(&remote, &alice, json!({"id":"a","result":"ack"}));
        assert!(validated_payload(&event, &alice, Some(remote.public_key())).is_some());
        assert!(validated_payload(&event, &bob, Some(remote.public_key())).is_none());
        assert!(matches!(
            matching_response(&json!({"id":"a","result":"ack"}), "b"),
            Response::Ignore
        ));
    }
}
