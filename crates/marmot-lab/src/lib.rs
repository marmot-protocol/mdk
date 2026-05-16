//! Local Marmot end-to-end lab.
//!
//! This crate is intentionally a lab harness, not production application code.
//! It runs real `AccountDeviceSession`s, the real Nostr peeler, and the real
//! Nostr transport adapter over either a deterministic file relay or an actual
//! `nostr-relay-builder` mock relay reached through `nostr-sdk`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_session::{AccountDeviceSession, SessionConfig};
use cgka_traits::engine::{CreateGroupRequest, GroupEvent, KeyPackage, SendIntent};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::{
    GroupId, MemberId, Timestamp, TransportAdapter, TransportAdapterError, TransportEndpoint,
    TransportEndpointReceipt, TransportGroupSubscription, TransportPublishTarget,
};
use marmot_account::{
    AccountDeviceRuntime, AccountHome, AccountHomeError, AccountSummary, KeyPackagePublication,
    KeyPackagePublishError, KeyPackagePublisher, TransportRoutingError, TransportRoutingPolicy,
};
use nostr_sdk::prelude::Client as NostrSdkClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_sqlite::SqlCipherKey;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use transport_nostr_adapter::{
    NostrPublishOutcome, NostrRelayClient, NostrRelayEvent, NostrSdkRelayClient,
    NostrTransportAdapter,
};
use transport_nostr_peeler::{NostrMlsPeeler, NostrTransportEvent};

const ACCOUNT_STATE_FILE: &str = "state.json";
const ACCOUNT_PROFILE_DIR: &str = "accounts";
const KEY_PACKAGE_DIR: &str = "key_packages";
const EVENT_DIR: &str = "events";
const SDK_FIRST_SYNC_WAIT: Duration = Duration::from_millis(750);
const SDK_DRAIN_WAIT: Duration = Duration::from_millis(50);

type LabRuntime =
    AccountDeviceRuntime<NostrTransportAdapter, LabTransportRouting, FileKeyPackagePublisher>;

#[derive(Clone, Debug)]
pub struct Lab {
    root: PathBuf,
    relay: LabRelay,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LabRelay {
    File,
    Sdk { url: String },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub joined_groups: Vec<GroupId>,
    pub messages: Vec<(String, GroupId, String)>,
    pub events: Vec<GroupEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendSummary {
    pub published: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestartSmokeSummary {
    pub group_id: GroupId,
    pub messages: Vec<(String, GroupId, String)>,
}

#[derive(Debug, thiserror::Error)]
pub enum LabError {
    #[error(transparent)]
    Account(#[from] marmot_account::AccountError),
    #[error(transparent)]
    Session(#[from] cgka_session::SessionError),
    #[error(transparent)]
    Storage(#[from] cgka_traits::storage::StorageError),
    #[error(transparent)]
    Transport(#[from] TransportAdapterError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    AccountHome(#[from] AccountHomeError),
    #[error("unknown account: {0}")]
    UnknownAccount(String),
    #[error("no published key package for account: {0}")]
    MissingKeyPackage(String),
    #[error("unknown local group: {0}")]
    UnknownGroup(String),
    #[error("publish failed: {0}")]
    Publish(String),
    #[error("lab invariant failed: {0}")]
    Invariant(String),
}

#[derive(Clone)]
struct AccountProfile {
    label: String,
    account_id_hex: String,
    inbox_endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AccountState {
    label: String,
    #[serde(default)]
    seen_events: Vec<String>,
    #[serde(default)]
    groups: Vec<GroupRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct GroupRecord {
    group_id_hex: String,
    endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeyPackageRecord {
    account_label: String,
    account_id_hex: String,
    key_package_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RelayEventRecord {
    endpoints: Vec<TransportEndpoint>,
    event: NostrTransportEvent,
    required_acks: usize,
}

struct OpenLabAccount {
    runtime: LabRuntime,
    adapter: NostrTransportAdapter,
    routing: LabTransportRouting,
    state: AccountState,
    notification_forwarder: Option<JoinHandle<()>>,
}

pub struct LabClient {
    lab: Lab,
    runtime: LabRuntime,
    adapter: NostrTransportAdapter,
    routing: LabTransportRouting,
    state: AccountState,
    notification_forwarder: Option<JoinHandle<()>>,
}

impl Lab {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            relay: LabRelay::File,
        }
    }

    pub fn with_sdk_relay(root: impl AsRef<Path>, relay_url: impl Into<String>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            relay: LabRelay::Sdk {
                url: relay_url.into(),
            },
        }
    }

    pub async fn init_account(&self, label: &str) -> Result<MemberId, LabError> {
        let keys = deterministic_nostr_keys(label.as_bytes());
        self.ensure_layout()?;
        let account = match self.account_home().account(label) {
            Ok(account) => account,
            Err(AccountHomeError::UnknownAccount(_)) => self
                .account_home()
                .import_account(label, &keys.secret_key().to_secret_hex())?,
            Err(err) => return Err(err.into()),
        };
        self.ensure_account_state(label)?;
        Ok(MemberId::new(hex::decode(account.account_id_hex)?))
    }

    pub async fn client(&self, label: &str) -> Result<LabClient, LabError> {
        self.ensure_account(label).await?;
        let open = self.open_account(label)?;
        open.runtime.activate_transport(None).await?;
        open.runtime.sync_transport_groups(None).await?;
        Ok(LabClient {
            lab: self.clone(),
            runtime: open.runtime,
            adapter: open.adapter,
            routing: open.routing,
            state: open.state,
            notification_forwarder: open.notification_forwarder,
        })
    }

    pub async fn restart_smoke(&self) -> Result<RestartSmokeSummary, LabError> {
        self.init_account("alice").await?;
        self.init_account("bob").await?;

        let mut alice = self.client("alice").await?;
        let mut bob = self.client("bob").await?;
        bob.publish_key_package().await?;

        let group_id = alice.create_group("restart-smoke", &["bob"]).await?;
        let joined = bob.sync().await?;
        if !joined.joined_groups.contains(&group_id) {
            return Err(LabError::Invariant(format!(
                "bob did not join restart-smoke group {} before restart",
                hex::encode(group_id.as_slice())
            )));
        }

        drop(alice);
        drop(bob);

        let mut bob = self.client("bob").await?;
        let mut alice = self.client("alice").await?;
        alice
            .send(&group_id, b"hello after marmot-lab restart")
            .await?;

        let received = bob.sync().await?;
        let expected = (
            "alice".to_string(),
            group_id.clone(),
            "hello after marmot-lab restart".to_string(),
        );
        if !received.messages.contains(&expected) {
            return Err(LabError::Invariant(format!(
                "bob did not receive restart-smoke message for group {}",
                hex::encode(group_id.as_slice())
            )));
        }

        Ok(RestartSmokeSummary {
            group_id,
            messages: received.messages,
        })
    }

    pub fn status(&self, label: &str) -> Result<serde_json::Value, LabError> {
        let account = self.account_home().account(label)?;
        self.ensure_account_state(label)?;
        let state = self.load_state(label)?;
        Ok(serde_json::json!({
            "label": state.label,
            "transport": self.transport_label(),
            "account_id": account.account_id_hex,
            "inbox_endpoint": self.account_inbox_endpoint(label).0,
            "groups": state.groups,
            "seen_events": state.seen_events.len(),
        }))
    }

    fn open_account(&self, label: &str) -> Result<OpenLabAccount, LabError> {
        let state = self.load_state(label)?;
        let keys = self.account_home().load_signing_keys(label)?;
        let account_id = MemberId::new(keys.public_key().to_bytes());
        let peeler =
            NostrMlsPeeler::new(keys.public_key().to_hex()).with_welcome_signer(keys.clone());
        let session = AccountDeviceSession::open(
            SessionConfig::new(
                self.account_dir(label).join("session.sqlite"),
                self.sqlcipher_key(label, &keys)?,
                account_id.as_slice().to_vec(),
                Box::new(peeler),
            )
            .convergence_policy(CanonicalizationPolicy {
                stable_quiescence_ms: 0,
                ..CanonicalizationPolicy::default()
            }),
        )?;

        let (adapter, notification_forwarder) = match &self.relay {
            LabRelay::File => {
                let relay_client = Arc::new(FileRelayClient {
                    root: self.relay_dir(),
                });
                (NostrTransportAdapter::new(relay_client), None)
            }
            LabRelay::Sdk { .. } => {
                let client = NostrSdkClient::builder().signer(keys).build();
                let relay_client = NostrSdkRelayClient::new(client);
                let adapter = NostrTransportAdapter::new(Arc::new(relay_client.clone()));
                let forwarder = relay_client.spawn_notification_forwarder(adapter.clone());
                (adapter, Some(forwarder))
            }
        };

        let key_packages = FileKeyPackagePublisher {
            root: self.relay_dir(),
            account_label: label.to_owned(),
        };
        let routing = self.routing_for(&state)?;
        let runtime =
            AccountDeviceRuntime::new(session, adapter.clone(), routing.clone(), key_packages);
        Ok(OpenLabAccount {
            runtime,
            adapter,
            routing,
            state,
            notification_forwarder,
        })
    }

    fn routing_for(&self, state: &AccountState) -> Result<LabTransportRouting, LabError> {
        let mut inbox_routes = HashMap::new();
        for profile in self.profiles()? {
            inbox_routes.insert(
                MemberId::new(hex::decode(profile.account_id_hex)?),
                vec![TransportEndpoint(profile.inbox_endpoint)],
            );
        }

        let mut group_routes = Vec::new();
        for group in &state.groups {
            let group_id = GroupId::new(hex::decode(&group.group_id_hex)?);
            group_routes.push(group_subscription(
                &group_id,
                TransportEndpoint(group.endpoint.clone()),
            ));
        }

        Ok(LabTransportRouting::new(LabRoutingState {
            local_inbox_endpoints: vec![self.account_inbox_endpoint(&state.label)],
            key_package_endpoints: vec![self.key_package_endpoint()],
            inbox_routes,
            group_routes,
            required_acks: 1,
        }))
    }

    async fn ensure_account(&self, label: &str) -> Result<(), LabError> {
        match self.account_home().account(label) {
            Ok(_) => self.ensure_account_state(label)?,
            Err(AccountHomeError::UnknownAccount(_)) => {
                self.init_account(label).await?;
            }
            Err(err) => return Err(err.into()),
        }
        Ok(())
    }

    fn ensure_layout(&self) -> Result<(), LabError> {
        fs::create_dir_all(self.relay_dir().join(ACCOUNT_PROFILE_DIR))?;
        fs::create_dir_all(self.relay_dir().join(KEY_PACKAGE_DIR))?;
        fs::create_dir_all(self.relay_dir().join(EVENT_DIR))?;
        Ok(())
    }

    fn latest_key_package(&self, label: &str) -> Result<KeyPackage, LabError> {
        let path = self
            .relay_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.json"));
        if !path.exists() {
            return Err(LabError::MissingKeyPackage(label.to_owned()));
        }
        let record: KeyPackageRecord = read_json(path)?;
        Ok(KeyPackage(hex::decode(record.key_package_hex)?))
    }

    fn profiles(&self) -> Result<Vec<AccountProfile>, LabError> {
        self.account_home()
            .accounts()?
            .into_iter()
            .map(|account| Ok(self.profile_for_account(account)))
            .collect()
    }

    fn profiles_by_id(&self) -> Result<HashMap<String, String>, LabError> {
        Ok(self
            .profiles()?
            .into_iter()
            .map(|profile| (profile.account_id_hex, profile.label))
            .collect())
    }

    fn relay_events(&self) -> Result<Vec<RelayEventRecord>, LabError> {
        let dir = self.relay_dir().join(EVENT_DIR);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut paths = fs::read_dir(dir)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        paths
            .into_iter()
            .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
            .map(read_json)
            .collect()
    }

    fn load_state(&self, label: &str) -> Result<AccountState, LabError> {
        let path = self.state_path(label);
        if !path.exists() {
            return Err(LabError::UnknownAccount(label.to_owned()));
        }
        read_json(path)
    }

    fn save_state(&self, state: &AccountState) -> Result<(), LabError> {
        write_json(self.state_path(&state.label), state)
    }

    fn ensure_account_state(&self, label: &str) -> Result<(), LabError> {
        if !self.state_path(label).exists() {
            write_json(
                self.state_path(label),
                &AccountState {
                    label: label.to_owned(),
                    seen_events: Vec::new(),
                    groups: Vec::new(),
                },
            )?;
        }
        Ok(())
    }

    fn profile_for_account(&self, account: AccountSummary) -> AccountProfile {
        AccountProfile {
            inbox_endpoint: self.account_inbox_endpoint(&account.label).0,
            label: account.label,
            account_id_hex: account.account_id_hex,
        }
    }

    fn sqlcipher_key(&self, label: &str, keys: &nostr::Keys) -> Result<SqlCipherKey, LabError> {
        if keys.secret_key().to_secret_hex()
            == deterministic_nostr_keys(label.as_bytes())
                .secret_key()
                .to_secret_hex()
        {
            return Ok(SqlCipherKey::new(format!(
                "marmot-lab-local-db-key-v1::{label}"
            ))?);
        }

        let mut hasher = Sha256::new();
        hasher.update(b"darkmatter-cli-sqlcipher-key-v1");
        hasher.update(label.as_bytes());
        hasher.update(keys.public_key().to_bytes());
        hasher.update(keys.secret_key().to_secret_bytes());
        Ok(SqlCipherKey::new(hex::encode(hasher.finalize()))?)
    }

    fn account_inbox_endpoint(&self, label: &str) -> TransportEndpoint {
        match &self.relay {
            LabRelay::File => TransportEndpoint(format!("marmot-lab://inbox/{label}")),
            LabRelay::Sdk { url } => TransportEndpoint(url.clone()),
        }
    }

    fn group_endpoint(&self, group_id: &GroupId) -> TransportEndpoint {
        match &self.relay {
            LabRelay::File => TransportEndpoint(format!(
                "marmot-lab://group/{}",
                hex::encode(group_id.as_slice())
            )),
            LabRelay::Sdk { url } => TransportEndpoint(url.clone()),
        }
    }

    fn key_package_endpoint(&self) -> TransportEndpoint {
        match &self.relay {
            LabRelay::File => TransportEndpoint("marmot-lab://key-packages".into()),
            LabRelay::Sdk { url } => TransportEndpoint(url.clone()),
        }
    }

    fn transport_label(&self) -> &'static str {
        match self.relay {
            LabRelay::File => "file",
            LabRelay::Sdk { .. } => "sdk-mock",
        }
    }

    fn account_dir(&self, label: &str) -> PathBuf {
        self.account_home().account_dir(label)
    }

    fn state_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(ACCOUNT_STATE_FILE)
    }

    fn relay_dir(&self) -> PathBuf {
        self.root.join("relay")
    }

    fn account_home(&self) -> AccountHome {
        AccountHome::open(&self.root)
    }
}

impl LabClient {
    pub async fn publish_key_package(&mut self) -> Result<KeyPackage, LabError> {
        self.runtime.activate_transport(None).await?;
        Ok(self.runtime.publish_fresh_key_package().await?)
    }

    pub async fn create_group(
        &mut self,
        name: &str,
        member_labels: &[&str],
    ) -> Result<GroupId, LabError> {
        let mut members = Vec::with_capacity(member_labels.len());
        for member in member_labels {
            members.push(self.lab.latest_key_package(member)?);
        }

        let (group_id, effects) = self
            .runtime
            .create_group(CreateGroupRequest {
                name: name.to_owned(),
                description: String::new(),
                members,
                required_features: Vec::new(),
                app_components: vec![],
                initial_admins: Vec::new(),
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.add_group(&group_id)?;
        self.runtime.sync_transport_groups(None).await?;
        self.lab.save_state(&self.state)?;
        Ok(group_id)
    }

    pub async fn send(
        &mut self,
        group_id: &GroupId,
        payload: &[u8],
    ) -> Result<SendSummary, LabError> {
        if !self
            .state
            .groups
            .iter()
            .any(|group| group.group_id_hex == hex::encode(group_id.as_slice()))
        {
            return Err(LabError::UnknownGroup(hex::encode(group_id.as_slice())));
        }

        self.runtime.sync_transport_groups(None).await?;
        let effects = self
            .runtime
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: payload.to_vec(),
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        Ok(SendSummary {
            published: effects.reports.len(),
        })
    }

    pub async fn sync(&mut self) -> Result<SyncSummary, LabError> {
        self.runtime.sync_transport_groups(None).await?;
        match self.lab.relay {
            LabRelay::File => self.sync_file_relay().await,
            LabRelay::Sdk { .. } => self.sync_sdk_relay().await,
        }
    }

    async fn sync_file_relay(&mut self) -> Result<SyncSummary, LabError> {
        let profiles = self.lab.profiles_by_id()?;
        let mut summary = SyncSummary::default();
        let mut seen = self
            .state
            .seen_events
            .iter()
            .cloned()
            .collect::<HashSet<_>>();

        for record in self.lab.relay_events()? {
            if seen.contains(&record.event.id) {
                continue;
            }

            let mut delivered_total = 0;
            for endpoint in &record.endpoints {
                let delivered = self
                    .adapter
                    .handle_relay_event(NostrRelayEvent {
                        endpoint: endpoint.clone(),
                        subscription_id: Some(format!("file-relay:{}", record.event.id)),
                        event: record.event.clone(),
                    })
                    .await?;
                delivered_total += delivered;
            }

            for _ in 0..delivered_total {
                let delivery = self
                    .adapter
                    .receive()
                    .await?
                    .ok_or_else(|| LabError::Publish("adapter delivery queue closed".into()))?;
                self.ingest_delivery(delivery, &profiles, &mut summary)
                    .await?;
            }

            seen.insert(record.event.id.clone());
            self.state.seen_events.push(record.event.id);
        }

        self.lab.save_state(&self.state)?;
        Ok(summary)
    }

    async fn sync_sdk_relay(&mut self) -> Result<SyncSummary, LabError> {
        let profiles = self.lab.profiles_by_id()?;
        let mut summary = SyncSummary::default();
        let mut first_wait = true;

        loop {
            let wait = if first_wait {
                SDK_FIRST_SYNC_WAIT
            } else {
                SDK_DRAIN_WAIT
            };
            first_wait = false;

            let delivery = match timeout(wait, self.adapter.receive()).await {
                Ok(Ok(Some(delivery))) => delivery,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            };
            self.state
                .seen_events
                .push(hex::encode(delivery.message.id.as_slice()));
            self.ingest_delivery(delivery, &profiles, &mut summary)
                .await?;
        }

        self.lab.save_state(&self.state)?;
        Ok(summary)
    }

    async fn ingest_delivery(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
        profiles: &HashMap<String, String>,
        summary: &mut SyncSummary,
    ) -> Result<(), LabError> {
        let effects = self.runtime.ingest_delivery(delivery).await?;
        fail_if_publish_failed(&effects.effects.failures)?;
        for event in &effects.effects.events {
            let before = self.state.groups.len();
            observe_event(&mut self.state, profiles, summary, event, &self.lab);
            if self.state.groups.len() != before {
                self.refresh_group_routes()?;
                self.runtime.sync_transport_groups(None).await?;
            }
        }
        Ok(())
    }

    fn add_group(&mut self, group_id: &GroupId) -> Result<(), LabError> {
        let endpoint = self.lab.group_endpoint(group_id);
        add_group(&mut self.state, group_id, endpoint.clone());
        self.routing
            .add_group(group_subscription(group_id, endpoint));
        Ok(())
    }

    fn refresh_group_routes(&mut self) -> Result<(), LabError> {
        for group in &self.state.groups {
            let group_id = GroupId::new(hex::decode(&group.group_id_hex)?);
            self.routing.add_group(group_subscription(
                &group_id,
                TransportEndpoint(group.endpoint.clone()),
            ));
        }
        Ok(())
    }
}

impl Drop for LabClient {
    fn drop(&mut self) {
        if let Some(handle) = self.notification_forwarder.take() {
            handle.abort();
        }
    }
}

#[derive(Clone)]
struct LabTransportRouting {
    inner: Arc<RwLock<LabRoutingState>>,
}

#[derive(Clone, Debug)]
struct LabRoutingState {
    local_inbox_endpoints: Vec<TransportEndpoint>,
    key_package_endpoints: Vec<TransportEndpoint>,
    inbox_routes: HashMap<MemberId, Vec<TransportEndpoint>>,
    group_routes: Vec<TransportGroupSubscription>,
    required_acks: usize,
}

impl LabTransportRouting {
    fn new(state: LabRoutingState) -> Self {
        Self {
            inner: Arc::new(RwLock::new(state)),
        }
    }

    fn add_group(&self, group: TransportGroupSubscription) {
        let mut state = self.inner.write().expect("lab routing lock poisoned");
        if state
            .group_routes
            .iter()
            .any(|existing| existing.group_id == group.group_id)
        {
            return;
        }
        state.group_routes.push(group);
    }
}

impl TransportRoutingPolicy for LabTransportRouting {
    fn local_inbox_endpoints(&self) -> Vec<TransportEndpoint> {
        self.inner
            .read()
            .expect("lab routing lock poisoned")
            .local_inbox_endpoints
            .clone()
    }

    fn key_package_endpoints(&self) -> Vec<TransportEndpoint> {
        self.inner
            .read()
            .expect("lab routing lock poisoned")
            .key_package_endpoints
            .clone()
    }

    fn group_subscriptions(&self) -> Vec<TransportGroupSubscription> {
        self.inner
            .read()
            .expect("lab routing lock poisoned")
            .group_routes
            .clone()
    }

    fn publish_target(
        &self,
        message: &TransportMessage,
    ) -> Result<TransportPublishTarget, TransportRoutingError> {
        let state = self.inner.read().expect("lab routing lock poisoned");
        match &message.envelope {
            TransportEnvelope::Welcome { recipient } => {
                let endpoints = state
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
                let route = state
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
        self.inner
            .read()
            .expect("lab routing lock poisoned")
            .required_acks
    }
}

#[derive(Clone)]
struct FileKeyPackagePublisher {
    root: PathBuf,
    account_label: String,
}

#[async_trait]
impl KeyPackagePublisher for FileKeyPackagePublisher {
    async fn publish_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<(), KeyPackagePublishError> {
        let dir = self.root.join(KEY_PACKAGE_DIR);
        fs::create_dir_all(&dir).map_err(|e| KeyPackagePublishError(e.to_string()))?;
        write_json(
            dir.join(format!("{}.json", self.account_label)),
            &KeyPackageRecord {
                account_label: self.account_label.clone(),
                account_id_hex: hex::encode(publication.account_id.as_slice()),
                key_package_hex: hex::encode(publication.key_package.0),
            },
        )
        .map_err(|e| KeyPackagePublishError(e.to_string()))
    }
}

#[derive(Clone)]
struct FileRelayClient {
    root: PathBuf,
}

#[async_trait]
impl NostrRelayClient for FileRelayClient {
    async fn subscribe(
        &self,
        _subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe(
        &self,
        _subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        let dir = self.root.join(EVENT_DIR);
        fs::create_dir_all(&dir).map_err(|e| TransportAdapterError::Backend(e.to_string()))?;
        let record = RelayEventRecord {
            endpoints: endpoints.to_vec(),
            event: event.clone(),
            required_acks,
        };
        let file = dir.join(format!("{}-{}.json", event.created_at, event.id));
        write_json(file, &record).map_err(|e| TransportAdapterError::Backend(e.to_string()))?;
        Ok(NostrPublishOutcome {
            accepted: endpoints
                .iter()
                .cloned()
                .map(|endpoint| TransportEndpointReceipt {
                    endpoint,
                    accepted_at: Some(Timestamp(event.created_at)),
                })
                .collect(),
            failed: Vec::new(),
        })
    }
}

fn observe_event(
    state: &mut AccountState,
    profiles: &HashMap<String, String>,
    summary: &mut SyncSummary,
    event: &GroupEvent,
    lab: &Lab,
) {
    match event {
        GroupEvent::GroupJoined { group_id, .. } | GroupEvent::GroupCreated { group_id } => {
            add_group(state, group_id, lab.group_endpoint(group_id));
            summary.joined_groups.push(group_id.clone());
        }
        GroupEvent::MessageReceived {
            group_id,
            sender,
            payload,
        } => {
            let sender_hex = hex::encode(sender.as_slice());
            let sender_label = profiles.get(&sender_hex).cloned().unwrap_or(sender_hex);
            let payload = String::from_utf8_lossy(payload).to_string();
            summary
                .messages
                .push((sender_label, group_id.clone(), payload));
        }
        _ => {}
    }
    summary.events.push(event.clone());
}

fn add_group(state: &mut AccountState, group_id: &GroupId, endpoint: TransportEndpoint) {
    let group_id_hex = hex::encode(group_id.as_slice());
    if state
        .groups
        .iter()
        .any(|group| group.group_id_hex == group_id_hex)
    {
        return;
    }
    state.groups.push(GroupRecord {
        group_id_hex,
        endpoint: endpoint.0,
    });
}

fn group_subscription(
    group_id: &GroupId,
    endpoint: TransportEndpoint,
) -> TransportGroupSubscription {
    TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: group_id.as_slice().to_vec(),
        endpoints: vec![endpoint],
    }
}

fn fail_if_publish_failed(failures: &[marmot_account::PublishFailure]) -> Result<(), LabError> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(LabError::Publish(
            failures
                .iter()
                .map(|failure| failure.reason.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        ))
    }
}

fn deterministic_nostr_keys(seed: &[u8]) -> nostr::Keys {
    let mut counter = 0_u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"marmot-lab-deterministic-nostr-key-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let secret = hasher.finalize();
        if let Ok(keys) = nostr::Keys::parse(&hex::encode(secret)) {
            return keys;
        }
        counter = counter
            .checked_add(1)
            .expect("deterministic Nostr key search exhausted");
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> Result<T, LabError> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> Result<(), LabError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}
