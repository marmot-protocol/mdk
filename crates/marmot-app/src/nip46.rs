//! App-owned NIP-46 sessions. Transport runs independently of account runtimes.

mod protocol;
#[cfg(test)]
mod tests;
mod transport;

use crate::MarmotApp;
use marmot_account::{AccountHome, Nip46Removal, Nip46SessionRecord};
use marmot_session::{AccountIdentityProofRequest, AccountIdentityProofSigner};
use nostr::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, Weak, mpsc as sync_mpsc},
    thread,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use transport_nostr::RelaySafetyPolicy;
use transport_nostr_adapter::network_proxy;
use transport_nostr_peeler::{MarmotNostrSigner, MarmotSignerError, SignerFuture};
use zeroize::{Zeroize, Zeroizing};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PAYLOAD: usize = 2 * 1024 * 1024;
const MAX_PENDING: usize = 32;
const PERMISSION_VERSION: u32 = 1;
// Proofs (450), KeyPackages (30443), NIP-59 seals (13), relay AUTH (22242),
// relay lists (10002/10050), deletions (5), profiles/follows (0/3), mute lists
// (10000), Blossom authorization (24242), push-owner proofs (451), and backup
// pointers (30078). NIP-44 serves seals, mute lists, and backup pointers.
const GRANTS: &[&str] = &[
    "sign_event:450",
    "sign_event:30443",
    "sign_event:13",
    "sign_event:22242",
    "sign_event:10002",
    "sign_event:10050",
    "sign_event:5",
    "sign_event:0",
    "sign_event:3",
    "sign_event:10000",
    "sign_event:24242",
    "sign_event:451",
    "sign_event:30078",
    "nip44_encrypt",
    "nip44_decrypt",
];
type Result<T, E = Nip46Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Nip46Error {
    #[error("invalid NIP-46 configuration or protocol response")]
    Invalid,
    #[error("invalid NIP-46 process proxy configuration")]
    ProxyConfig,
    #[error("remote signer unavailable")]
    Unavailable,
    #[error("NIP-46 relay publication failed")]
    RelayPublish,
    #[error("remote signer rejected the request")]
    Rejected,
    #[error("remote signer identity or signed event mismatch")]
    Mismatch,
    #[error("remote signer request timed out")]
    Timeout,
    #[error("remote signer request cancelled")]
    Cancelled,
    #[error("remote signer session logged out")]
    LoggedOut,
    #[error("remote signer method unsupported")]
    Unsupported,
    #[error("NIP-46 permissions require explicit approval")]
    PermissionApprovalRequired,
    #[error("NIP-46 credential storage failed")]
    Storage,
    #[error("remote signer request queue full")]
    Busy,
    #[error("remote signer disconnected")]
    Disconnected,
    #[error("no matching active NIP-46 request")]
    RequestNotFound,
}
impl Nip46Error {
    fn signer_message(&self) -> String {
        if matches!(self, Self::Rejected | Self::Cancelled) {
            crate::EXTERNAL_SIGNER_REJECTED.to_owned()
        } else {
            self.to_string()
        }
    }
    fn signer_error(self) -> MarmotSignerError {
        MarmotSignerError::new(self.signer_message())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Nip46State {
    Unavailable,
    PermissionApproval,
    Connecting,
    Ready,
    Approval,
    Disconnected,
    Cancelled,
    LoggedOut,
    Reconnecting,
    Listening,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46Permissions {
    pub version: u32,
    pub grants: Vec<String>,
}

impl Nip46Permissions {
    fn is_current(&self) -> bool {
        self.version == PERMISSION_VERSION
            && self
                .grants
                .iter()
                .map(String::as_str)
                .eq(GRANTS.iter().copied())
    }
}

fn random_nonce() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nip46Status {
    pub state: Nip46State,
    pub last_error: Option<Nip46Error>,
    pub auth_url: Option<String>,
    pub request_id: Option<String>,
    pub generation: u64,
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
    // An export is untrusted input, not proof of approval in this app instance.
    #[serde(default)]
    permission_version: Option<u32>,
    #[serde(default)]
    permissions: Option<Vec<String>>,
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

struct Data {
    keys: Option<Keys>,
    remote: Option<PublicKey>,
    user: Option<PublicKey>,
    relays: Vec<RelayUrl>,
    secret: Option<Zeroizing<String>>,
    client_pairing: bool,
    pairing_established: bool,
    name: String,
    approved: Option<Nip46Permissions>,
    reviewed: bool,
    verified: bool,
    status: Nip46Status,
    pending: HashMap<String, watch::Sender<bool>>,
    active: Option<String>,
    account: Option<String>,
}
struct Shared {
    data: Mutex<Data>,
    owner: Weak<()>,
    home: AccountHome,
    relay_policy: RelaySafetyPolicy,
}
struct Core {
    shared: Arc<Shared>,
    commands: mpsc::Sender<Command>,
    control: watch::Sender<u64>,
    close_registry: Arc<crate::close_registry::CloseRegistry>,
    close_key: String,
}
impl Drop for Core {
    fn drop(&mut self) {
        self.stop(Nip46State::Cancelled, Nip46Error::Cancelled);
        self.close_registry.close(&self.close_key);
    }
}

#[derive(Clone)]
pub struct Nip46Session {
    core: Arc<Core>,
}
impl fmt::Debug for Nip46Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nip46Session")
            .field("status", &self.status().state)
            .finish_non_exhaustive()
    }
}

struct Command {
    id: String,
    generation: u64,
    operation: Operation,
    deadline: Instant,
    cancellation: watch::Receiver<bool>,
    reply: sync_mpsc::SyncSender<Result<Reply>>,
}
enum Operation {
    Listen,
    Connect,
    Sign(UnsignedEvent, String),
    Crypto(&'static str, Vec<String>),
    Ping,
    Logout,
}

#[derive(Debug, PartialEq)]
enum Reply {
    Text(String),
    Signed(Event),
    Complete,
}

impl Reply {
    fn into_string(self) -> Result<String> {
        match self {
            Self::Text(text) => Ok(text),
            _ => Err(Nip46Error::Invalid),
        }
    }

    fn into_event(self) -> Result<Event> {
        match self {
            Self::Signed(event) => Ok(event),
            _ => Err(Nip46Error::Invalid),
        }
    }
}

struct PendingCall {
    core: Arc<Core>,
    id: String,
    cancellation: watch::Sender<bool>,
}

impl Drop for PendingCall {
    fn drop(&mut self) {
        self.cancellation.send_replace(true);
        lock(&self.core.shared.data).pending.remove(&self.id);
    }
}

fn wait_response(response: sync_mpsc::Receiver<Result<Reply>>, timeout: Duration) -> Result<Reply> {
    match response.recv_timeout(timeout + Duration::from_secs(1)) {
        Ok(result) => result,
        Err(sync_mpsc::RecvTimeoutError::Timeout) => Err(Nip46Error::Timeout),
        Err(sync_mpsc::RecvTimeoutError::Disconnected) => Err(Nip46Error::Unavailable),
    }
}

#[derive(Serialize)]
struct SignRequest<'a> {
    kind: Kind,
    content: &'a str,
    tags: &'a Tags,
    created_at: Timestamp,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Shared {
    fn renew_offer(data: &mut Data) {
        if data.client_pairing && !data.pairing_established && data.keys.is_some() {
            data.remote = None;
            data.user = None;
            data.secret = Some(Zeroizing::new(random_nonce()));
        }
    }
    fn check(data: &Data, generation: u64) -> Result<()> {
        match data.status.state {
            Nip46State::LoggedOut => return Err(Nip46Error::LoggedOut),
            Nip46State::Cancelled => return Err(Nip46Error::Cancelled),
            _ => {}
        }
        if data.status.generation != generation {
            return Err(Nip46Error::Disconnected);
        }
        if data.keys.is_none() {
            return Err(Nip46Error::LoggedOut);
        }
        Ok(())
    }
    fn record(data: &Data) -> Result<(Keys, Nip46SessionRecord)> {
        let keys = data.keys.as_ref().ok_or(Nip46Error::LoggedOut)?;
        let user = data.user.ok_or(Nip46Error::Unavailable)?;
        let remote = data.remote.ok_or(Nip46Error::Unavailable)?;
        let approved = data
            .approved
            .as_ref()
            .ok_or(Nip46Error::PermissionApprovalRequired)?;
        Ok((
            keys.clone(),
            Nip46SessionRecord {
                version: 1,
                user_public_key: user.to_hex(),
                remote_signer_public_key: remote.to_hex(),
                client_public_key: keys.public_key().to_hex(),
                relays: data.relays.iter().map(ToString::to_string).collect(),
                name: data.name.clone(),
                permission_version: approved.version,
                permissions: approved.grants.clone(),
            },
        ))
    }
    fn persist(&self, data: &Data) -> Result<()> {
        if let Some(account) = &data.account {
            let (keys, record) = Self::record(data)?;
            self.home
                .store_nip46_session(account, &keys, &record)
                .map_err(|_| Nip46Error::Storage)?;
        }
        Ok(())
    }
    fn set_request(&self, generation: u64, id: &str) -> Result<()> {
        let mut data = lock(&self.data);
        Self::check(&data, generation)?;
        data.status.request_id = Some(id.to_owned());
        data.status.auth_url = None;
        Ok(())
    }
}
impl Core {
    fn stop(&self, state: Nip46State, error: Nip46Error) {
        let mut data = lock(&self.shared.data);
        if data.status.state == Nip46State::LoggedOut {
            return;
        }
        if data.status.state == Nip46State::Cancelled && state != Nip46State::LoggedOut {
            return;
        }
        data.status.generation = data.status.generation.wrapping_add(1);
        data.verified = false;
        Shared::renew_offer(&mut data);
        data.status.state = state;
        data.status.last_error = Some(error);
        data.status.auth_url = None;
        data.status.request_id = None;
        for sender in data.pending.values() {
            sender.send_replace(true);
        }
        self.control.send_replace(data.status.generation);
    }
}

impl Nip46Session {
    pub fn new(app: &MarmotApp, config_json: &str) -> Result<Self> {
        if config_json.len() > 64 * 1024 {
            return Err(Nip46Error::Invalid);
        }
        let config: Config = serde_json::from_str(config_json).map_err(|_| Nip46Error::Invalid)?;
        let relay_policy =
            RelaySafetyPolicy::with_allow_loopback(app.config.allow_loopback_relay_endpoints);
        let data = protocol::parse_config(config, &relay_policy)?;
        let client_public_key = data
            .keys
            .as_ref()
            .ok_or(Nip46Error::LoggedOut)?
            .public_key();
        {
            let sessions = lock(&app.nip46_sessions);
            if sessions
                .values()
                .any(|session| session.client_public_key().ok() == Some(client_public_key))
            {
                return Err(Nip46Error::Busy);
            }
        }
        Self::spawn(app, data, relay_policy)
    }
    fn spawn(app: &MarmotApp, data: Data, relay_policy: RelaySafetyPolicy) -> Result<Self> {
        let _admission = app
            .begin_storage_open("remote signer")
            .map_err(|_| Nip46Error::Unavailable)?;
        let proxy = network_proxy::socks5_proxy().map_err(|_| Nip46Error::ProxyConfig)?;
        let shared = Arc::new(Shared {
            data: Mutex::new(data),
            owner: Arc::downgrade(&app.nip46_owner),
            home: app.account_home.clone(),
            relay_policy,
        });
        let (commands, receiver) = mpsc::channel(MAX_PENDING);
        let (control, changes) = watch::channel(0);
        let close_key = format!("nip46:{}", random_nonce());
        let core = Arc::new(Core {
            shared: shared.clone(),
            commands,
            control,
            close_registry: app.close_registry.clone(),
            close_key: close_key.clone(),
        });
        let session = Self { core };
        let closer = Arc::downgrade(&session.core);
        app.close_registry.register(close_key, move || {
            if let Some(core) = closer.upgrade() {
                core.stop(Nip46State::Cancelled, Nip46Error::Cancelled);
            }
        });
        thread::Builder::new()
            .name("nip46-transport".into())
            .spawn(move || {
                // The actor must keep running while a caller synchronously signs an MLS proof.
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => {
                        runtime.block_on(transport::run(shared, receiver, changes, proxy))
                    }
                    Err(_) => {
                        let mut data = lock(&shared.data);
                        data.status.state = Nip46State::Unavailable;
                        data.status.last_error = Some(Nip46Error::Unavailable);
                    }
                }
            })
            .map_err(|_| Nip46Error::Unavailable)?;
        Ok(session)
    }
    pub(crate) fn restore(app: &MarmotApp, keys: Keys, record: Nip46SessionRecord) -> Result<Self> {
        let account = {
            let _admission = app
                .begin_storage_open("remote signer")
                .map_err(|_| Nip46Error::Unavailable)?;
            let account = app
                .account_home
                .account(&record.user_public_key)
                .map_err(|_| Nip46Error::Storage)?;
            let (stored_keys, stored_record) = app
                .account_home
                .load_nip46_session(&account.label)
                .map_err(|_| Nip46Error::Storage)?
                .ok_or(Nip46Error::Storage)?;
            if stored_keys.public_key() != keys.public_key() || stored_record != record {
                return Err(Nip46Error::Mismatch);
            }
            account
        };
        let relay_policy =
            RelaySafetyPolicy::with_allow_loopback(app.config.allow_loopback_relay_endpoints);
        let mut data = protocol::restore_data(keys, record, &relay_policy)?;
        data.account = Some(account.label);
        Self::spawn(app, data, relay_policy)
    }
    pub fn belongs_to(&self, app: &MarmotApp) -> bool {
        self.core
            .shared
            .owner
            .ptr_eq(&Arc::downgrade(&app.nip46_owner))
    }
    pub(crate) fn same_session(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.core, &other.core)
    }
    pub fn permissions() -> Nip46Permissions {
        Nip46Permissions {
            version: PERMISSION_VERSION,
            grants: GRANTS.iter().map(|grant| (*grant).to_owned()).collect(),
        }
    }
    pub fn review_permissions(&self) -> Nip46Permissions {
        lock(&self.core.shared.data).reviewed = true;
        Self::permissions()
    }
    pub fn approve_permissions(&self, version: u32, grants: Vec<String>) -> Result<()> {
        let approval = Nip46Permissions { version, grants };
        let mut data = lock(&self.core.shared.data);
        Shared::check(&data, data.status.generation)?;
        if !data.reviewed || !approval.is_current() {
            return Err(Nip46Error::PermissionApprovalRequired);
        }
        let previous = data.approved.replace(approval);
        if let Err(error) = self.core.shared.persist(&data) {
            data.approved = previous;
            return Err(error);
        }
        if data.status.state == Nip46State::PermissionApproval {
            data.status.state = Nip46State::Unavailable;
            data.status.last_error = None;
        }
        Ok(())
    }
    pub fn status(&self) -> Nip46Status {
        lock(&self.core.shared.data).status.clone()
    }
    pub fn state_json(&self) -> Result<String> {
        let status = self.status();
        let mut value = serde_json::to_value(&status).map_err(|_| Nip46Error::Invalid)?;
        value["detail"] = Value::String(
            status
                .last_error
                .map(|error| error.to_string())
                .unwrap_or_default(),
        );
        serde_json::to_string(&value).map_err(|_| Nip46Error::Invalid)
    }
    pub fn uri(&self) -> Result<String> {
        let data = lock(&self.core.shared.data);
        Shared::check(&data, data.status.generation)?;
        if !data
            .approved
            .as_ref()
            .is_some_and(Nip46Permissions::is_current)
        {
            return Err(Nip46Error::PermissionApprovalRequired);
        }
        protocol::uri(&data)
    }
    pub(crate) fn bind_account(&self, account_ref: &str) -> Result<()> {
        let mut data = lock(&self.core.shared.data);
        Shared::check(&data, data.status.generation)?;
        let account = self
            .core
            .shared
            .home
            .account(account_ref)
            .map_err(|_| Nip46Error::Storage)?;
        if data
            .account
            .as_deref()
            .is_some_and(|bound| bound != account.label)
        {
            return Err(Nip46Error::Mismatch);
        }
        if !data.verified && data.account.is_none() {
            return Err(Nip46Error::Unavailable);
        }
        let (keys, record) = Shared::record(&data)?;
        self.core
            .shared
            .home
            .store_nip46_session(&account.label, &keys, &record)
            .map_err(|_| Nip46Error::Storage)?;
        data.account = Some(account.label);
        Ok(())
    }
    pub fn export(&self) -> Result<String> {
        let data = lock(&self.core.shared.data);
        Shared::check(&data, data.status.generation)?;
        let (keys, record) = Shared::record(&data)?;
        let secret = Zeroizing::new(keys.secret_key().to_secret_hex());
        Ok(json!({"client_secret":secret.as_str(),"user_public_key":record.user_public_key,"remote_signer_public_key":record.remote_signer_public_key,"relays":record.relays,"name":record.name,"permission_version":record.permission_version,"permissions":record.permissions}).to_string())
    }
    pub fn connect(&self) -> Result<String> {
        self.call(Operation::Connect, REQUEST_TIMEOUT)?
            .into_string()
    }
    pub async fn connect_async(&self) -> Result<String> {
        self.call_async(Operation::Connect, REQUEST_TIMEOUT)
            .await?
            .into_string()
    }
    pub async fn pairing_offer(&self) -> Result<String> {
        self.call_async(Operation::Listen, REQUEST_TIMEOUT)
            .await?
            .into_string()
    }
    pub fn ping(&self) -> Result<()> {
        self.call(Operation::Ping, REQUEST_TIMEOUT).map(|_| ())
    }
    pub async fn ping_async(&self) -> Result<()> {
        self.call_async(Operation::Ping, REQUEST_TIMEOUT)
            .await
            .map(|_| ())
    }
    pub fn disconnect(&self) {
        self.core
            .stop(Nip46State::Disconnected, Nip46Error::Disconnected);
    }
    pub fn cancel(&self) {
        self.core.stop(Nip46State::Cancelled, Nip46Error::Cancelled);
    }
    pub fn cancel_request(&self, request_id: &str) -> Result<()> {
        let mut data = lock(&self.core.shared.data);
        let operation = if data.status.request_id.as_deref() == Some(request_id) {
            data.active.as_deref().unwrap_or(request_id)
        } else {
            request_id
        };
        let cancellation = data
            .pending
            .get(operation)
            .ok_or(Nip46Error::RequestNotFound)?;
        if *cancellation.borrow() {
            return Err(Nip46Error::RequestNotFound);
        }
        cancellation.send_replace(true);
        if data.status.request_id.as_deref() == Some(request_id) {
            data.status.request_id = None;
            data.status.auth_url = None;
        }
        Ok(())
    }
    pub fn complete_auth(&self, request_id: &str) -> Result<()> {
        let mut data = lock(&self.core.shared.data);
        Shared::check(&data, data.status.generation)?;
        if data.status.request_id.as_deref() != Some(request_id) || data.status.auth_url.is_none() {
            return Err(Nip46Error::RequestNotFound);
        }
        // A UI acknowledgement is not a signer response and cannot complete the RPC.
        data.status.auth_url = None;
        Ok(())
    }
    pub fn logout(&self) -> Result<()> {
        let result = self.call(Operation::Logout, LOGOUT_TIMEOUT).map(|_| ());
        self.erase_local()?;
        result
    }
    pub fn erase_local(&self) -> Result<()> {
        let mut data = lock(&self.core.shared.data);
        let removal = data
            .account
            .as_ref()
            .map(|account| {
                self.core
                    .shared
                    .home
                    .remove_nip46_session(account, Nip46Removal::IncludingOrphaned)
            })
            .transpose()
            .map_err(|_| Nip46Error::Storage);
        data.keys = None;
        data.secret = None;
        data.verified = false;
        data.status.generation = data.status.generation.wrapping_add(1);
        data.status.state = Nip46State::LoggedOut;
        data.status.auth_url = None;
        data.status.request_id = None;
        data.status.last_error = removal.as_ref().err().cloned();
        for sender in data.pending.values() {
            sender.send_replace(true);
        }
        self.core.control.send_replace(data.status.generation);
        removal?;
        Ok(())
    }
    pub fn public_key(&self) -> Result<PublicKey> {
        let data = lock(&self.core.shared.data);
        Shared::check(&data, data.status.generation)?;
        data.user.ok_or(Nip46Error::Unavailable)
    }
    pub(crate) fn client_public_key(&self) -> Result<PublicKey> {
        lock(&self.core.shared.data)
            .keys
            .as_ref()
            .map(Keys::public_key)
            .ok_or(Nip46Error::LoggedOut)
    }
    fn start_call(
        &self,
        operation: Operation,
        timeout: Duration,
    ) -> Result<(sync_mpsc::Receiver<Result<Reply>>, PendingCall)> {
        let id = random_nonce();
        let (cancellation, cancelled) = watch::channel(false);
        let (reply, response) = sync_mpsc::sync_channel(1);
        {
            let mut data = lock(&self.core.shared.data);
            Shared::check(&data, data.status.generation)?;
            if !data
                .approved
                .as_ref()
                .is_some_and(Nip46Permissions::is_current)
            {
                return Err(Nip46Error::PermissionApprovalRequired);
            }
            if data.status.state == Nip46State::Disconnected
                && !matches!(
                    operation,
                    Operation::Listen | Operation::Connect | Operation::Logout
                )
            {
                return Err(Nip46Error::Disconnected);
            }
            if data.pending.len() >= MAX_PENDING {
                return Err(Nip46Error::Busy);
            }
            let generation = data.status.generation;
            self.core
                .commands
                .try_send(Command {
                    id: id.clone(),
                    generation,
                    operation,
                    deadline: Instant::now() + timeout,
                    cancellation: cancelled,
                    reply,
                })
                .map_err(|_| Nip46Error::Busy)?;
            data.pending.insert(id.clone(), cancellation.clone());
        }
        Ok((
            response,
            PendingCall {
                core: self.core.clone(),
                id,
                cancellation,
            },
        ))
    }
    fn call(&self, operation: Operation, timeout: Duration) -> Result<Reply> {
        let (response, _pending) = self.start_call(operation, timeout)?;
        wait_response(response, timeout)
    }
    async fn call_async(&self, operation: Operation, timeout: Duration) -> Result<Reply> {
        let (response, _pending) = self.start_call(operation, timeout)?;
        tokio::task::spawn_blocking(move || wait_response(response, timeout))
            .await
            .map_err(|_| Nip46Error::Unavailable)?
    }
    fn sign_operation(&self, unsigned: UnsignedEvent) -> Result<Operation> {
        if unsigned.pubkey != self.public_key()? {
            return Err(Nip46Error::Mismatch);
        }
        let permission = format!("sign_event:{}", unsigned.kind.as_u16());
        if !GRANTS.contains(&permission.as_str()) {
            return Err(Nip46Error::Unsupported);
        }
        let request = SignRequest {
            kind: unsigned.kind,
            content: &unsigned.content,
            tags: &unsigned.tags,
            created_at: unsigned.created_at,
        };
        let payload = serde_json::to_string(&request).map_err(|_| Nip46Error::Invalid)?;
        if payload.len() > MAX_PAYLOAD {
            return Err(Nip46Error::Invalid);
        }
        Ok(Operation::Sign(unsigned, payload))
    }
    fn sign(&self, unsigned: UnsignedEvent) -> Result<Event> {
        let operation = self.sign_operation(unsigned)?;
        self.call(operation, REQUEST_TIMEOUT)?.into_event()
    }
    fn crypto<'a>(
        &'a self,
        method: &'static str,
        key: &'a PublicKey,
        content: &'a str,
    ) -> SignerFuture<'a, std::result::Result<String, MarmotSignerError>> {
        Box::pin(async move {
            if content.len() > MAX_PAYLOAD {
                return Err(Nip46Error::Invalid.signer_error());
            }
            self.call_async(
                Operation::Crypto(method, vec![key.to_hex(), content.to_owned()]),
                REQUEST_TIMEOUT,
            )
            .await
            .and_then(Reply::into_string)
            .map_err(Nip46Error::signer_error)
        })
    }
}
impl MarmotNostrSigner for Nip46Session {
    fn get_public_key(
        &self,
    ) -> SignerFuture<'_, std::result::Result<PublicKey, MarmotSignerError>> {
        Box::pin(async move { self.public_key().map_err(Nip46Error::signer_error) })
    }
    fn sign_event(
        &self,
        unsigned: UnsignedEvent,
    ) -> SignerFuture<'_, std::result::Result<Event, MarmotSignerError>> {
        Box::pin(async move {
            let operation = self
                .sign_operation(unsigned)
                .map_err(Nip46Error::signer_error)?;
            let result = self
                .call_async(operation, REQUEST_TIMEOUT)
                .await
                .map_err(Nip46Error::signer_error)?;
            result.into_event().map_err(Nip46Error::signer_error)
        })
    }
    fn nip04_encrypt<'a>(
        &'a self,
        _: &'a PublicKey,
        _: &'a str,
    ) -> SignerFuture<'a, std::result::Result<String, MarmotSignerError>> {
        Box::pin(async { Err(MarmotSignerError::new(Nip46Error::Unsupported.to_string())) })
    }
    fn nip04_decrypt<'a>(
        &'a self,
        _: &'a PublicKey,
        _: &'a str,
    ) -> SignerFuture<'a, std::result::Result<String, MarmotSignerError>> {
        Box::pin(async { Err(MarmotSignerError::new(Nip46Error::Unsupported.to_string())) })
    }
    fn nip44_encrypt<'a>(
        &'a self,
        key: &'a PublicKey,
        content: &'a str,
    ) -> SignerFuture<'a, std::result::Result<String, MarmotSignerError>> {
        self.crypto("nip44_encrypt", key, content)
    }
    fn nip44_decrypt<'a>(
        &'a self,
        key: &'a PublicKey,
        payload: &'a str,
    ) -> SignerFuture<'a, std::result::Result<String, MarmotSignerError>> {
        self.crypto("nip44_decrypt", key, payload)
    }
}
impl AccountIdentityProofSigner for Nip46Session {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> std::result::Result<[u8; 64], String> {
        let unsigned = request
            .proof_event()
            .map_err(|_| Nip46Error::Invalid.to_string())?;
        let event = self
            .sign(unsigned)
            .map_err(|error| error.signer_message())?;
        request
            .signature_from_signed_event(event)
            .map_err(|_| Nip46Error::Mismatch.to_string())
    }
}
