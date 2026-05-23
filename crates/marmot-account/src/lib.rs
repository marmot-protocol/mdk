//! Thin account-device orchestration for Marmot.
//!
//! This crate is intentionally small. It owns the app-level coordination that
//! sits above `AccountDeviceSession`: transport account activation, transport
//! routing, KeyPackage publication, and publish confirmation or rollback.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cgka_session::{
    AccountDeviceSession, CreateGroupEffects, IngestEffects, PublishWork, QueuedIntentRef,
    SessionEffects, SessionError,
};
use cgka_traits::AppComponentId;
use cgka_traits::engine::{CreateGroupRequest, GroupEvent, KeyPackage, SendIntent};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::group::{Group, Member};
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::{
    GroupId, MemberId, Timestamp, TransportAccountActivation, TransportAdapter,
    TransportAdapterError, TransportDelivery, TransportEndpoint, TransportGroupSubscription,
    TransportGroupSync, TransportPublishReport, TransportPublishRequest, TransportPublishTarget,
};
use serde::{Deserialize, Serialize};

const TRACE_TARGET: &str = "marmot_account::runtime";

pub type AccountResult<T> = Result<T, AccountError>;

pub type AccountHomeResult<T> = Result<T, AccountHomeError>;

const ACCOUNT_RECORD_FILE: &str = "account.json";
const ACCOUNT_SECRET_FILE: &str = "secret.json";
const LOCAL_FILE_SECRET_BACKEND: &str = "local-dev-file";
pub const DEFAULT_KEYCHAIN_SERVICE_NAME: &str = "com.marmot.darkmatter";

#[derive(Clone)]
pub struct AccountHome {
    root: PathBuf,
    secret_store: Arc<dyn AccountSecretStore>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSummary {
    pub label: String,
    pub account_id_hex: String,
    pub local_signing: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountHomeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error("account already exists: {0}")]
    AccountExists(String),
    #[error("unknown account: {0}")]
    UnknownAccount(String),
    #[error("invalid nsec or secret key")]
    InvalidSecretKey,
    #[error("invalid Nostr public key")]
    InvalidPublicKey,
    #[error("invalid account label: {0}")]
    InvalidAccountLabel(String),
    #[error("stored account id does not match stored secret key")]
    AccountIdMismatch,
    #[error("unsupported account secret storage backend: {0}")]
    UnsupportedSecretBackend(String),
    #[error("account secret store is not initialized: {0}")]
    SecretStoreNotInitialized(String),
    #[error("account secret store is unavailable: {0}")]
    SecretStoreUnavailable(String),
    #[error("account secret store operation failed: {0}")]
    SecretStore(String),
    #[error("account secret was not found")]
    SecretNotFound(String),
    #[error("account secret store service name cannot be empty")]
    EmptySecretStoreService,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredAccountSecret {
    #[serde(default = "stored_secret_version")]
    version: u32,
    #[serde(default = "stored_secret_backend")]
    backend: String,
    secret_key_hex: String,
}

pub trait AccountSecretStore: Send + Sync {
    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool>;
    fn write_secret(&self, account: &AccountSummary, keys: &nostr::Keys) -> AccountHomeResult<()>;
    fn load_secret(&self, account: &AccountSummary) -> AccountHomeResult<nostr::Keys>;
    fn remove_secret(&self, account: &AccountSummary) -> AccountHomeResult<()>;
}

#[derive(Clone, Debug)]
pub struct LocalFileSecretStore {
    root: PathBuf,
}

impl LocalFileSecretStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    fn secret_path(&self, label: &str) -> PathBuf {
        self.root
            .join("accounts")
            .join(label)
            .join(ACCOUNT_SECRET_FILE)
    }
}

impl AccountSecretStore for LocalFileSecretStore {
    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
        Ok(self.secret_path(label).exists())
    }

    fn write_secret(&self, account: &AccountSummary, keys: &nostr::Keys) -> AccountHomeResult<()> {
        write_secret_json(
            self.secret_path(&account.label),
            &StoredAccountSecret {
                version: stored_secret_version(),
                backend: stored_secret_backend(),
                secret_key_hex: keys.secret_key().to_secret_hex(),
            },
        )
    }

    fn load_secret(&self, account: &AccountSummary) -> AccountHomeResult<nostr::Keys> {
        let secret: StoredAccountSecret = read_json(self.secret_path(&account.label))?;
        if secret.backend != LOCAL_FILE_SECRET_BACKEND {
            return Err(AccountHomeError::UnsupportedSecretBackend(secret.backend));
        }
        nostr::Keys::parse(&secret.secret_key_hex).map_err(|_| AccountHomeError::InvalidSecretKey)
    }

    fn remove_secret(&self, account: &AccountSummary) -> AccountHomeResult<()> {
        let path = self.secret_path(&account.label);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeychainSecretStore {
    service_name: String,
}

impl KeychainSecretStore {
    pub fn new(service_name: impl Into<String>) -> AccountHomeResult<Self> {
        let service_name = service_name.into().trim().to_owned();
        if service_name.is_empty() {
            return Err(AccountHomeError::EmptySecretStoreService);
        }
        initialize_keyring_store()?;
        Ok(Self { service_name })
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    fn entry_for_account(&self, account_id_hex: &str) -> AccountHomeResult<keyring_core::Entry> {
        keyring_core::Entry::new(&self.service_name, account_id_hex).map_err(map_keyring_error)
    }
}

impl AccountSecretStore for KeychainSecretStore {
    fn has_secret_for_label(&self, _label: &str) -> AccountHomeResult<bool> {
        Ok(false)
    }

    fn write_secret(&self, account: &AccountSummary, keys: &nostr::Keys) -> AccountHomeResult<()> {
        self.entry_for_account(&account.account_id_hex)?
            .set_password(&keys.secret_key().to_secret_hex())
            .map_err(map_keyring_error)
    }

    fn load_secret(&self, account: &AccountSummary) -> AccountHomeResult<nostr::Keys> {
        match self
            .entry_for_account(&account.account_id_hex)?
            .get_password()
        {
            Ok(secret_key) => {
                nostr::Keys::parse(&secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)
            }
            Err(keyring_core::Error::NoEntry) => Err(AccountHomeError::SecretNotFound(
                account.account_id_hex.clone(),
            )),
            Err(err) => Err(map_keyring_error(err)),
        }
    }

    fn remove_secret(&self, account: &AccountSummary) -> AccountHomeResult<()> {
        match self
            .entry_for_account(&account.account_id_hex)?
            .delete_credential()
        {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => Err(map_keyring_error(err)),
        }
    }
}

fn stored_secret_version() -> u32 {
    1
}

fn stored_secret_backend() -> String {
    LOCAL_FILE_SECRET_BACKEND.to_owned()
}

impl AccountHome {
    pub fn open(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        Self {
            secret_store: Arc::new(LocalFileSecretStore::new(&root)),
            root,
        }
    }

    pub fn open_with_keychain(
        root: impl AsRef<Path>,
        service_name: impl Into<String>,
    ) -> AccountHomeResult<Self> {
        let secret_store = Arc::new(KeychainSecretStore::new(service_name)?);
        Ok(Self::open_with_secret_store(root, secret_store))
    }

    pub fn open_with_default_keychain(root: impl AsRef<Path>) -> AccountHomeResult<Self> {
        Self::open_with_keychain(root, DEFAULT_KEYCHAIN_SERVICE_NAME)
    }

    pub fn open_with_secret_store(
        root: impl AsRef<Path>,
        secret_store: Arc<dyn AccountSecretStore>,
    ) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            secret_store,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn account_dir(&self, label: &str) -> PathBuf {
        self.accounts_dir().join(label)
    }

    pub fn create_account(&self, label: &str) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::Keys::generate();
        self.write_signing_account_for_label(label, &keys)
    }

    pub fn create_nostr_account(&self) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::Keys::generate();
        self.write_signing_account(&keys)
    }

    pub fn import_account(
        &self,
        label: &str,
        secret_key: &str,
    ) -> AccountHomeResult<AccountSummary> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        self.write_signing_account_for_label(label, &keys)
    }

    pub fn import_nostr_account(&self, secret_key: &str) -> AccountHomeResult<AccountSummary> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        self.write_signing_account(&keys)
    }

    pub fn add_public_account(&self, public_key: &str) -> AccountHomeResult<AccountSummary> {
        let account_id_hex = Self::account_id_for_public_key(public_key)?;
        if self.account_record_path(&account_id_hex).exists() {
            return Err(AccountHomeError::AccountExists(account_id_hex));
        }
        let account = AccountSummary {
            label: account_id_hex.clone(),
            account_id_hex,
            local_signing: false,
        };
        self.write_account_record(&account)?;
        Ok(account)
    }

    pub fn account_id_for_secret(secret_key: &str) -> AccountHomeResult<String> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        Ok(keys.public_key().to_hex())
    }

    pub fn account_id_for_public_key(public_key: &str) -> AccountHomeResult<String> {
        nostr::PublicKey::parse(public_key)
            .map(|pubkey| pubkey.to_hex())
            .map_err(|_| AccountHomeError::InvalidPublicKey)
    }

    pub fn account(&self, account_ref: &str) -> AccountHomeResult<AccountSummary> {
        if validate_account_label(account_ref).is_ok() {
            let path = self.account_record_path(account_ref);
            if path.exists() {
                return read_json(path);
            }
        }

        let account_id = Self::account_id_for_public_key(account_ref)
            .map_err(|_| AccountHomeError::UnknownAccount(account_ref.to_owned()))?;
        let path = self.account_record_path(&account_id);
        if !path.exists() {
            return Err(AccountHomeError::UnknownAccount(account_ref.to_owned()));
        }
        read_json(path)
    }

    pub fn accounts(&self) -> AccountHomeResult<Vec<AccountSummary>> {
        let dir = self.accounts_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut accounts = Vec::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path().join(ACCOUNT_RECORD_FILE);
            if path.exists() {
                accounts.push(read_json(path)?);
            }
        }
        accounts.sort_by(|a: &AccountSummary, b| a.account_id_hex.cmp(&b.account_id_hex));
        Ok(accounts)
    }

    pub fn remove_account(&self, account_ref: &str) -> AccountHomeResult<()> {
        let account = self.account(account_ref)?;
        self.secret_store.remove_secret(&account)?;
        match fs::remove_dir_all(self.account_dir(&account.label)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    pub fn load_signing_keys(&self, account_ref: &str) -> AccountHomeResult<nostr::Keys> {
        let account = self.account(account_ref)?;
        if !account.local_signing {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex));
        }
        let keys = self.secret_store.load_secret(&account)?;
        if keys.public_key().to_hex() != account.account_id_hex {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        Ok(keys)
    }

    fn write_signing_account(&self, keys: &nostr::Keys) -> AccountHomeResult<AccountSummary> {
        let label = keys.public_key().to_hex();
        self.write_signing_account_for_label(&label, keys)
    }

    fn write_signing_account_for_label(
        &self,
        label: &str,
        keys: &nostr::Keys,
    ) -> AccountHomeResult<AccountSummary> {
        let label = label.to_owned();
        validate_account_label(&label)?;
        if self.account_record_path(&label).exists()
            || self.secret_store.has_secret_for_label(&label)?
        {
            return Err(AccountHomeError::AccountExists(label));
        }
        let account = AccountSummary {
            label,
            account_id_hex: keys.public_key().to_hex(),
            local_signing: true,
        };
        self.secret_store.write_secret(&account, keys)?;
        if let Err(err) = self.write_account_record(&account) {
            let _ = self.secret_store.remove_secret(&account);
            return Err(err);
        }
        Ok(account)
    }

    fn write_account_record(&self, account: &AccountSummary) -> AccountHomeResult<()> {
        validate_account_label(&account.label)?;
        write_json(self.account_record_path(&account.label), account)
    }

    fn accounts_dir(&self) -> PathBuf {
        self.root.join("accounts")
    }

    fn account_record_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(ACCOUNT_RECORD_FILE)
    }
}

fn initialize_keyring_store() -> AccountHomeResult<()> {
    static KEYRING_STORE_INIT: Mutex<()> = Mutex::new(());
    let _guard = KEYRING_STORE_INIT.lock().map_err(|_| {
        AccountHomeError::SecretStoreUnavailable("keyring init lock poisoned".into())
    })?;
    if keyring_core::get_default_store().is_some() {
        return Ok(());
    }
    initialize_platform_keyring_store()
}

fn initialize_platform_keyring_store() -> AccountHomeResult<()> {
    #[cfg(test)]
    {
        set_default_keyring_store(keyring_core::mock::Store::new(), "mock")
    }

    #[cfg(all(not(test), target_os = "macos"))]
    {
        set_default_keyring_store(
            apple_native_keyring_store::keychain::Store::new(),
            "macOS Keychain",
        )
    }

    #[cfg(all(not(test), target_os = "ios"))]
    {
        set_default_keyring_store(
            apple_native_keyring_store::protected::Store::new(),
            "iOS protected-data",
        )
    }

    #[cfg(all(not(test), target_os = "windows"))]
    {
        set_default_keyring_store(windows_native_keyring_store::Store::new(), "Windows")
    }

    #[cfg(all(
        not(test),
        any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        )
    ))]
    {
        set_default_keyring_store(
            zbus_secret_service_keyring_store::Store::new(),
            "Secret Service",
        )
    }

    #[cfg(all(not(test), target_os = "android"))]
    {
        set_default_keyring_store(android_native_keyring_store::Store::new(), "Android")
    }

    #[cfg(all(
        not(test),
        not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "windows",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "android",
        ))
    ))]
    {
        Err(AccountHomeError::SecretStoreUnavailable(
            "no platform credential store is available for this target OS".into(),
        ))
    }
}

fn set_default_keyring_store<S>(
    store: keyring_core::Result<Arc<S>>,
    store_name: &str,
) -> AccountHomeResult<()>
where
    S: keyring_core::api::CredentialStoreApi + Send + Sync + 'static,
{
    let store = store.map_err(|err| {
        AccountHomeError::SecretStoreUnavailable(format!(
            "failed to create {store_name} credential store: {err}"
        ))
    })?;
    keyring_core::set_default_store(store);
    Ok(())
}

fn map_keyring_error(err: keyring_core::Error) -> AccountHomeError {
    match err {
        keyring_core::Error::NoDefaultStore => {
            AccountHomeError::SecretStoreNotInitialized(err.to_string())
        }
        keyring_core::Error::NoStorageAccess(inner) => {
            AccountHomeError::SecretStoreUnavailable(format_storage_access_error(inner.as_ref()))
        }
        other => AccountHomeError::SecretStore(other.to_string()),
    }
}

fn format_storage_access_error(inner: &dyn std::error::Error) -> String {
    if cfg!(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )) {
        format!(
            "platform keyring is not available: {inner}. Make sure a Secret Service provider is running and unlocked."
        )
    } else {
        format!("platform keyring is not available: {inner}")
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> AccountHomeResult<T> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> AccountHomeResult<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn write_secret_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> AccountHomeResult<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    write_private_file(path, &bytes)?;
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> AccountHomeResult<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> AccountHomeResult<()> {
    fs::write(path, bytes)?;
    Ok(())
}

fn validate_account_label(label: &str) -> AccountHomeResult<()> {
    if label.is_empty()
        || label == "."
        || label == ".."
        || label.contains('/')
        || label.contains('\\')
    {
        return Err(AccountHomeError::InvalidAccountLabel(label.to_owned()));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error(transparent)]
    Transport(#[from] TransportAdapterError),
    #[error(transparent)]
    TransportRouting(#[from] TransportRoutingError),
    #[error(transparent)]
    KeyPackage(#[from] KeyPackagePublishError),
    #[error("transport delivery was addressed to a different account")]
    WrongAccountDelivery,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackagePublication {
    pub account_id: MemberId,
    pub key_package: KeyPackage,
    pub endpoints: Vec<TransportEndpoint>,
}

#[derive(Debug, thiserror::Error)]
#[error("key package publication failed: {0}")]
pub struct KeyPackagePublishError(pub String);

#[async_trait]
pub trait KeyPackagePublisher: Send + Sync {
    async fn publish_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<(), KeyPackagePublishError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopKeyPackagePublisher;

#[async_trait]
impl KeyPackagePublisher for NoopKeyPackagePublisher {
    async fn publish_key_package(
        &self,
        _publication: KeyPackagePublication,
    ) -> Result<(), KeyPackagePublishError> {
        Ok(())
    }
}

pub trait TransportRoutingPolicy: Send + Sync {
    fn local_inbox_endpoints(&self) -> Vec<TransportEndpoint>;
    fn key_package_endpoints(&self) -> Vec<TransportEndpoint>;
    fn group_subscriptions(&self) -> Vec<TransportGroupSubscription>;
    fn publish_target(
        &self,
        message: &TransportMessage,
    ) -> Result<TransportPublishTarget, TransportRoutingError>;
    fn required_acks(&self, target: &TransportPublishTarget) -> usize;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportRoutingError {
    #[error("missing inbox route for recipient")]
    MissingInboxRoute,
    #[error("missing group route for transport group id")]
    MissingGroupRoute,
}

#[derive(Clone, Debug)]
pub struct StaticTransportRouting {
    local_inbox_endpoints: Vec<TransportEndpoint>,
    key_package_endpoints: Vec<TransportEndpoint>,
    inbox_routes: HashMap<MemberId, Vec<TransportEndpoint>>,
    group_routes: Vec<TransportGroupSubscription>,
    required_acks: usize,
}

impl StaticTransportRouting {
    pub fn new(local_inbox_endpoints: Vec<TransportEndpoint>) -> Self {
        Self {
            key_package_endpoints: local_inbox_endpoints.clone(),
            local_inbox_endpoints,
            inbox_routes: HashMap::new(),
            group_routes: Vec::new(),
            required_acks: 1,
        }
    }

    pub fn key_package_endpoints(mut self, endpoints: Vec<TransportEndpoint>) -> Self {
        self.key_package_endpoints = endpoints;
        self
    }

    pub fn required_acks(mut self, required_acks: usize) -> Self {
        self.required_acks = required_acks;
        self
    }

    pub fn with_inbox_route(
        mut self,
        account_id: MemberId,
        endpoints: Vec<TransportEndpoint>,
    ) -> Self {
        self.inbox_routes.insert(account_id, endpoints);
        self
    }

    pub fn with_group_route(
        mut self,
        group_id: GroupId,
        transport_group_id: Vec<u8>,
        endpoints: Vec<TransportEndpoint>,
    ) -> Self {
        self.group_routes.push(TransportGroupSubscription {
            group_id,
            transport_group_id,
            endpoints,
        });
        self
    }
}

impl TransportRoutingPolicy for StaticTransportRouting {
    fn local_inbox_endpoints(&self) -> Vec<TransportEndpoint> {
        self.local_inbox_endpoints.clone()
    }

    fn key_package_endpoints(&self) -> Vec<TransportEndpoint> {
        self.key_package_endpoints.clone()
    }

    fn group_subscriptions(&self) -> Vec<TransportGroupSubscription> {
        self.group_routes.clone()
    }

    fn publish_target(
        &self,
        message: &TransportMessage,
    ) -> Result<TransportPublishTarget, TransportRoutingError> {
        match &message.envelope {
            TransportEnvelope::Welcome { recipient } => {
                let endpoints = self
                    .inbox_routes
                    .get(recipient)
                    .cloned()
                    .ok_or(TransportRoutingError::MissingInboxRoute)?;
                Ok(TransportPublishTarget::Inbox {
                    recipient: recipient.clone(),
                    endpoints,
                })
            }
            TransportEnvelope::GroupMessage { transport_group_id } => {
                let route = self
                    .group_routes
                    .iter()
                    .find(|route| route.transport_group_id == *transport_group_id)
                    .cloned()
                    .ok_or(TransportRoutingError::MissingGroupRoute)?;
                Ok(TransportPublishTarget::Group {
                    group_id: route.group_id,
                    transport_group_id: route.transport_group_id,
                    endpoints: route.endpoints,
                })
            }
        }
    }

    fn required_acks(&self, _target: &TransportPublishTarget) -> usize {
        self.required_acks
    }
}

pub struct AccountDeviceRuntime<A, R = StaticTransportRouting, K = NoopKeyPackagePublisher> {
    session: AccountDeviceSession,
    adapter: A,
    routing: R,
    key_packages: K,
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    pub fn new(session: AccountDeviceSession, adapter: A, routing: R, key_packages: K) -> Self {
        Self {
            session,
            adapter,
            routing,
            key_packages,
        }
    }

    pub fn session(&self) -> &AccountDeviceSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut AccountDeviceSession {
        &mut self.session
    }

    pub fn group_record(&self, group_id: &GroupId) -> AccountResult<Group> {
        Ok(self.session.group_record(group_id)?)
    }

    pub fn admin_pubkeys(&self, group_id: &GroupId) -> AccountResult<Vec<[u8; 32]>> {
        Ok(self.session.admin_pubkeys(group_id)?)
    }

    pub fn app_component(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<Option<Vec<u8>>> {
        Ok(self.session.app_component(group_id, component_id)?)
    }

    pub fn safe_export_secret(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<cgka_traits::SecretBytes> {
        Ok(self.session.safe_export_secret(group_id, component_id)?)
    }

    pub async fn activate_transport(&self, since: Option<Timestamp>) -> AccountResult<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "activate_transport",
            inbox_endpoint_count = self.routing.local_inbox_endpoints().len(),
            group_subscription_count = self.routing.group_subscriptions().len(),
            "activating account transport"
        );
        self.adapter
            .activate_account(TransportAccountActivation {
                account_id: self.session.self_id(),
                inbox_endpoints: self.routing.local_inbox_endpoints(),
                group_subscriptions: self.routing.group_subscriptions(),
                since,
            })
            .await?;
        Ok(())
    }

    pub async fn sync_transport_groups(&self, since: Option<Timestamp>) -> AccountResult<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "sync_transport_groups",
            group_subscription_count = self.routing.group_subscriptions().len(),
            "syncing account group subscriptions"
        );
        self.adapter
            .sync_account_groups(TransportGroupSync {
                account_id: self.session.self_id(),
                group_subscriptions: self.routing.group_subscriptions(),
                since,
            })
            .await?;
        Ok(())
    }

    pub async fn publish_fresh_key_package(&mut self) -> AccountResult<KeyPackage> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "publish_fresh_key_package",
            endpoint_count = self.routing.key_package_endpoints().len(),
            "publishing fresh key package"
        );
        let key_package = self.session.fresh_key_package().await?;
        self.key_packages
            .publish_key_package(KeyPackagePublication {
                account_id: self.session.self_id(),
                key_package: key_package.clone(),
                endpoints: self.routing.key_package_endpoints(),
            })
            .await?;
        Ok(key_package)
    }

    pub async fn create_group(
        &mut self,
        request: CreateGroupRequest,
    ) -> AccountResult<(GroupId, AccountDeviceEffects)> {
        let CreateGroupEffects { group_id, effects } = self.session.create_group(request).await?;
        let effects = self.publish_session_effects(effects).await?;
        Ok((group_id, effects))
    }

    pub async fn send(&mut self, intent: SendIntent) -> AccountResult<AccountDeviceEffects> {
        let effects = self.session.send(intent).await?;
        self.publish_session_effects(effects).await
    }

    pub async fn advance_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<AccountDeviceEffects> {
        let effects = self.session.advance_convergence(group_id).await?;
        self.publish_session_effects(effects).await
    }

    pub fn members(&self, group_id: &GroupId) -> AccountResult<Vec<Member>> {
        Ok(self.session.members(group_id)?)
    }

    pub async fn ingest_delivery(
        &mut self,
        delivery: TransportDelivery,
    ) -> AccountResult<AccountIngestEffects> {
        if delivery.account_id != self.session.self_id() {
            return Err(AccountError::WrongAccountDelivery);
        }
        let IngestEffects { outcome, effects } = self.session.ingest(delivery.message).await?;
        let effects = self.publish_session_effects(effects).await?;
        Ok(AccountIngestEffects { outcome, effects })
    }

    pub async fn publish_session_effects(
        &mut self,
        effects: SessionEffects,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        let mut queue = VecDeque::new();
        output.absorb_session_effects(effects, &mut queue);

        while let Some(work) = queue.pop_front() {
            match work {
                PublishWork::ApplicationMessage { msg } | PublishWork::Proposal { msg } => {
                    self.publish_one(msg, &mut output).await?;
                }
                PublishWork::GroupCreated { welcomes, pending } => {
                    self.publish_pending(welcomes, pending, &mut output, &mut queue)
                        .await?;
                }
                PublishWork::GroupEvolution {
                    msg,
                    welcomes,
                    pending,
                } => {
                    self.publish_group_evolution(msg, welcomes, pending, &mut output, &mut queue)
                        .await?;
                }
                PublishWork::AutoPublish { msg, pending } => {
                    self.publish_pending(vec![msg], pending, &mut output, &mut queue)
                        .await?;
                }
            }
        }

        Ok(output)
    }

    async fn publish_pending(
        &mut self,
        messages: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
    ) -> AccountResult<()> {
        let mut all_published = true;
        for message in messages {
            all_published &= self.publish_one(message, output).await?;
        }

        if all_published {
            let effects = self.session.confirm_published(pending).await?;
            output
                .pending
                .push(PendingResolution::Confirmed { pending });
            output.absorb_session_effects(effects, queue);
        } else {
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
        }
        Ok(())
    }

    async fn publish_group_evolution(
        &mut self,
        commit: TransportMessage,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
    ) -> AccountResult<()> {
        if self.publish_one(commit, output).await? {
            let effects = self.session.confirm_published(pending).await?;
            output
                .pending
                .push(PendingResolution::Confirmed { pending });
            output.absorb_session_effects(effects, queue);

            for welcome in welcomes {
                self.publish_one(welcome, output).await?;
            }
        } else {
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
        }
        Ok(())
    }

    async fn publish_one(
        &self,
        message: TransportMessage,
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<bool> {
        let message_id = message.id.clone();
        let target = match self.routing.publish_target(&message) {
            Ok(target) => target,
            Err(e) => {
                output.failures.push(PublishFailure {
                    message_id,
                    reason: e.to_string(),
                });
                return Ok(false);
            }
        };
        let required_acks = self.routing.required_acks(&target);
        let report = match self
            .adapter
            .publish(TransportPublishRequest {
                account_id: self.session.self_id(),
                message,
                target,
                required_acks,
            })
            .await
        {
            Ok(report) => report,
            Err(e) => {
                output.failures.push(PublishFailure {
                    message_id,
                    reason: e.to_string(),
                });
                return Ok(false);
            }
        };
        let published = report.met_required_acks();
        if !published {
            output.failures.push(PublishFailure {
                message_id: report.message_id.clone(),
                reason: "insufficient publish acknowledgements".into(),
            });
        }
        output.reports.push(report);
        Ok(published)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountDeviceEffects {
    pub events: Vec<GroupEvent>,
    pub queued: Vec<QueuedIntentRef>,
    pub reports: Vec<TransportPublishReport>,
    pub failures: Vec<PublishFailure>,
    pub pending: Vec<PendingResolution>,
}

impl AccountDeviceEffects {
    fn absorb_session_effects(
        &mut self,
        effects: SessionEffects,
        queue: &mut VecDeque<PublishWork>,
    ) {
        self.events.extend(effects.events);
        self.queued.extend(effects.queued);
        queue.extend(effects.publish);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountIngestEffects {
    pub outcome: IngestOutcome,
    pub effects: AccountDeviceEffects,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishFailure {
    pub message_id: cgka_traits::MessageId,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingResolution {
    Confirmed { pending: PendingStateRef },
    RolledBack { pending: PendingStateRef },
}
