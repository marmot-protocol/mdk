//! First app runtime bridge for Marmot.
//!
//! This crate wires `AccountHome` into the concrete local runtime pieces needed by
//! early app surfaces: encrypted session storage, Nostr MLS peeling, Nostr
//! transport publishing, and relay-backed app projections.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cgka_engine::{
    FeatureRegistry,
    account_identity_proof::{
        ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE, AccountIdentityProofRequest,
        AccountIdentityProofSigner,
    },
    canonicalization::CanonicalizationPolicy,
    key_package::{is_last_resort_key_package, key_package_metadata},
};
use cgka_session::{AccountDeviceSession, SessionConfig};
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_EXPORTER_LABEL, AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN,
    AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE, AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE,
    AGENT_TEXT_STREAM_QUIC_SEND_FEATURE, AGENT_TEXT_STREAM_ROLE_FANOUT,
    AGENT_TEXT_STREAM_ROLE_RECEIVE, AGENT_TEXT_STREAM_ROLE_SEND, AgentTextStreamKeyContextV1,
    AgentTextStreamQuicPolicyV1,
};
use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT, AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, AppComponentData,
    NostrRoutingV1, decode_nostr_routing_v1, default_group_components, encode_component_vectors,
    encode_nostr_routing_v1, encode_quic_varint,
};
pub use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT as AGENT_TEXT_STREAM_COMPONENT,
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID as AGENT_TEXT_STREAM_COMPONENT_ID,
    GROUP_ADMIN_POLICY_COMPONENT, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_BLOSSOM_IMAGE_COMPONENT,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_MESSAGE_RETENTION_COMPONENT,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT, GROUP_PROFILE_COMPONENT_ID,
    NOSTR_ROUTING_COMPONENT, NOSTR_ROUTING_COMPONENT_ID,
};
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION,
    MarmotAppEvent as MarmotInnerEvent, QUOTE_REF_TAG, STREAM_BROKER_TAG, STREAM_CHUNKS_TAG,
    STREAM_FINAL_KIND_TAG, STREAM_HASH_TAG, STREAM_ROUTE_TAG, STREAM_START_TAG, STREAM_TAG,
    STREAM_TYPE_TAG,
};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CreateGroupRequest, GroupEvent, KeyPackage, SendIntent};
use cgka_traits::group::Group;
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::{
    GroupId, MemberId, MessageId, SecretBytes, TransportAdapter, TransportAdapterError,
    TransportEndpoint, TransportGroupSubscription, TransportPublishTarget,
};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use marmot_account::{
    AccountDeviceRuntime, AccountHome, AccountHomeError, AccountSummary, KeyPackagePublication,
    KeyPackagePublishError, KeyPackagePublisher, TransportRoutingError, TransportRoutingPolicy,
};
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::{
    STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD,
};
use nostr::{EventBuilder, JsonUtil, Kind, Tag, Timestamp as NostrTimestamp, ToBech32};
use nostr_sdk::prelude::{Client as NostrSdkClient, PublicKey};
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_sqlite::SqlCipherKey;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_MARMOT_KEY_PACKAGE_RELAY_LIST,
    KIND_NIP65_RELAY_LIST, NostrAccountRelayListKind, NostrAccountRelayListPublication,
    NostrKeyPackagePublication, NostrKeyPackagePublisher, NostrRelayClient, NostrSdkRelayClient,
};
use transport_nostr_peeler::{NostrMlsPeeler, NostrTransportEvent};
use transport_quic_broker::{
    BrokerServerTrust, SubscribeTextFromBroker, subscribe_text_from_broker_with_updates,
};
use transport_quic_stream::AgentTextStreamCrypto;
use url::Url;

mod agent_streams;
mod directory_cache;
mod projection;
mod relay_plane;

pub use agent_streams::{
    AgentStreamDelta, AgentStreamUpdate, AgentStreamWatchCompletion, AgentStreamWatchManager,
    AgentStreamWatchReport, AgentStreamWatchStart,
};
pub use relay_plane::{MarmotRelayPlane, MarmotRelayPlaneAccountAdapter, RelayPlaneHealth};

use directory_cache::DirectoryCache;
use projection::AccountProjectionDb;
use relay_plane::{DirectoryEventQuery, DirectoryRelayEventRecord as RelayEventRecord};

const ACCOUNT_APP_DB_FILE: &str = "app.sqlite3";
const APP_CACHE_DB_FILE: &str = "app-cache.sqlite3";
const SESSION_DB_FILE: &str = "session.sqlite";
const SQLCIPHER_SALT_SUFFIX: &str = ".salt";
const SQLCIPHER_SALT_LEN: usize = 32;
const SQLCIPHER_KEY_LEN: usize = 32;
const KEY_PACKAGE_DIR: &str = "key-packages";
const SDK_FIRST_SYNC_WAIT: Duration = Duration::from_millis(750);
const SDK_DRAIN_WAIT: Duration = Duration::from_millis(250);
const APP_RUNTIME_ACCOUNT_READY_WAIT: Duration = Duration::from_secs(45);
const APP_RUNTIME_RELAY_REBUILD_LOOKBACK: Duration = Duration::from_secs(120);
const ACCOUNT_WORKER_RECONNECT_BASE_DELAY: Duration = Duration::from_secs(2);
const ACCOUNT_WORKER_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(60);
const ACCOUNT_WORKER_RECONNECT_JITTER_MAX_MS: u64 = 500;
const APP_RUNTIME_SUBSCRIPTION_BUFFER: usize = 1024;
const AGENT_STREAM_START_LOOKBACK_LIMIT: usize = 200;
const USER_DIRECTORY_SEARCH_MAX_VISITED: usize = 8192;
const USER_DIRECTORY_SEARCH_MAX_FRONTIER: usize = 4096;
const DEFAULT_DIRECTORY_MAX_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);
pub const DEFAULT_BLOSSOM_SERVER_URL: &str = "https://blossom.primal.net";
const ENCRYPTED_MEDIA_VERSION: &str = "mip04-v2";
const ENCRYPTED_MEDIA_EXPORTER_LABEL: &str = "marmot/encrypted-media";
const BLOSSOM_UPLOAD_AUTH_TTL: Duration = Duration::from_secs(10 * 60);
const BLOSSOM_UPLOAD_CONTENT_TYPE: &str = "application/octet-stream";
const DIRECTORY_FUTURE_CREATED_AT_CLEANUP_MARKER: &str =
    ".marmot-directory-future-created-at-cleanup-v1";
/// Value of the `stream-type` tag on an agent text stream start event.
const STREAM_TYPE_TEXT: &str = "text";
/// Value of the `route` tag on a brokered QUIC agent text stream start event.
const STREAM_ROUTE_QUIC: &str = "quic";
/// `final-kind` tag value: the kind of the eventual stream-final chat message.
const STREAM_FINAL_KIND_CHAT: &str = "9";
pub(crate) const MAX_SEEN_EVENT_IDS: usize = 16_384;
const KIND_NOSTR_METADATA: u64 = 0;
const KIND_NOSTR_CONTACT_LIST: u64 = 3;
const DEFAULT_PROFILE_ADJECTIVES: &[&str] = &[
    "Agile", "Angry", "Brave", "Bright", "Calm", "Clever", "Cosmic", "Daring", "Electric",
    "Gentle", "Golden", "Happy", "Hidden", "Jolly", "Kind", "Lucky", "Majestic", "Mellow",
    "Mighty", "Nimble", "Noble", "Quiet", "Rapid", "Sage", "Silver", "Sunny", "Swift", "Vivid",
    "Witty", "Wondrous", "Young", "Zesty",
];
const DEFAULT_PROFILE_NOUNS: &[&str] = &[
    "Antelope", "Badger", "Bear", "Beaver", "Bison", "Bobcat", "Cougar", "Dolphin", "Eagle",
    "Falcon", "Finch", "Fox", "Gecko", "Heron", "Jaguar", "Koala", "Llama", "Lynx", "Moose",
    "Narwhal", "Otter", "Owl", "Panda", "Puffin", "Raven", "Robin", "Seal", "Swan", "Tiger",
    "Turtle", "Wolf", "Yak",
];

type AppRuntime = AccountDeviceRuntime<
    MarmotRelayPlaneAccountAdapter,
    AppTransportRouting,
    AppKeyPackagePublisher,
>;

#[derive(Clone)]
pub struct MarmotApp {
    root: PathBuf,
    relay_urls: Vec<String>,
    account_home: AccountHome,
    relay_plane: MarmotRelayPlane,
    config: MarmotAppConfig,
}

#[derive(Clone)]
pub struct MarmotAppRuntime {
    events: broadcast::Sender<MarmotAppEvent>,
    shared: RuntimeSharedServices,
    accounts: AccountManager,
}

#[derive(Clone)]
pub struct AccountManager {
    app: MarmotApp,
    events: broadcast::Sender<MarmotAppEvent>,
    shared: RuntimeSharedServices,
    workers: Arc<Mutex<HashMap<String, ManagedAccountWorker>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarmotAppConfig {
    pub directory_max_future_skew: Duration,
}

impl Default for MarmotAppConfig {
    fn default() -> Self {
        Self {
            directory_max_future_skew: DEFAULT_DIRECTORY_MAX_FUTURE_SKEW,
        }
    }
}

impl MarmotAppConfig {
    pub fn with_directory_max_future_skew(mut self, skew: Duration) -> Self {
        self.directory_max_future_skew = skew;
        self
    }
}

#[derive(Clone)]
pub struct RuntimeSharedServices {
    relay_plane: MarmotRelayPlane,
    agent_streams: AgentStreamWatchManager,
}

impl Default for RuntimeSharedServices {
    fn default() -> Self {
        Self {
            relay_plane: MarmotRelayPlane::runtime_default(APP_RUNTIME_RELAY_REBUILD_LOOKBACK),
            agent_streams: AgentStreamWatchManager::default(),
        }
    }
}

impl RuntimeSharedServices {
    fn for_app(app: &MarmotApp) -> Self {
        Self {
            relay_plane: app.relay_plane.clone(),
            agent_streams: AgentStreamWatchManager::default(),
        }
    }

    pub fn relay_plane(&self) -> &MarmotRelayPlane {
        &self.relay_plane
    }

    pub fn agent_streams(&self) -> AgentStreamWatchManager {
        self.agent_streams.clone()
    }
}

struct ManagedAccountWorker {
    handle: JoinHandle<()>,
    commands: mpsc::Sender<AccountWorkerCommand>,
    shutdown: oneshot::Sender<()>,
}

impl ManagedAccountWorker {
    fn stop(self) {
        let _ = self.shutdown.send(());
        self.handle.abort();
    }
}

struct AccountWorkerRuntime {
    app: MarmotApp,
    account_label: String,
    account_id_hex: String,
    relay_plane: MarmotRelayPlane,
    events: broadcast::Sender<MarmotAppEvent>,
}

enum AccountWorkerCommand {
    CatchUp {
        respond: oneshot::Sender<Result<(), String>>,
    },
    CreateGroup {
        name: String,
        members: Vec<String>,
        description: Option<String>,
        respond: oneshot::Sender<Result<GroupId, AppError>>,
    },
    Members {
        group_id: GroupId,
        respond: oneshot::Sender<Result<Vec<AppGroupMemberRecord>, AppError>>,
    },
    GroupMlsState {
        group_id: GroupId,
        respond: oneshot::Sender<Result<AppGroupMlsState, AppError>>,
    },
    SafeExportSecret {
        group_id: GroupId,
        component_id: cgka_traits::AppComponentId,
        respond: oneshot::Sender<Result<SecretBytes, AppError>>,
    },
    ExporterSecret {
        group_id: GroupId,
        label: String,
        length: usize,
        respond: oneshot::Sender<Result<SecretBytes, AppError>>,
    },
    InviteMembers {
        group_id: GroupId,
        members: Vec<String>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    RemoveMembers {
        group_id: GroupId,
        members: Vec<String>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    LeaveGroup {
        group_id: GroupId,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    PromoteAdmin {
        group_id: GroupId,
        member_ref: String,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    DemoteAdmin {
        group_id: GroupId,
        member_ref: String,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    SelfDemoteAdmin {
        group_id: GroupId,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    UpdateGroupProfile {
        group_id: GroupId,
        name: Option<String>,
        description: Option<String>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    UpdateMessageRetention {
        group_id: GroupId,
        disappearing_message_secs: u64,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    SendMessage {
        group_id: GroupId,
        payload: Vec<u8>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    SendAppEvent {
        group_id: GroupId,
        intent: AppMessageIntent,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    UploadMedia {
        group_id: GroupId,
        request: MediaUploadRequest,
        respond: oneshot::Sender<Result<MediaUploadResult, AppError>>,
    },
    DownloadMedia {
        group_id: GroupId,
        reference: MediaReference,
        respond: oneshot::Sender<Result<MediaDownloadResult, AppError>>,
    },
    StartAgentTextStream {
        group_id: GroupId,
        stream_id: Vec<u8>,
        quic_candidates: Vec<String>,
        respond: oneshot::Sender<Result<(MarmotInnerEvent, SendSummary), AppError>>,
    },
    FinishAgentTextStream {
        group_id: GroupId,
        request: AgentTextStreamFinishRequest,
        respond: oneshot::Sender<Result<(MarmotInnerEvent, SendSummary), AppError>>,
    },
    RetryGroupConvergence {
        group_id: GroupId,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    PublishKeyPackage {
        respond: oneshot::Sender<Result<usize, AppError>>,
    },
    RotateKeyPackage {
        respond: oneshot::Sender<Result<usize, AppError>>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedAccount {
    pub label: String,
    pub account_id_hex: String,
    pub local_signing: bool,
    pub running: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountSetupRequest {
    pub identity: Option<String>,
    pub default_relays: Vec<TransportEndpoint>,
    pub bootstrap_relays: Vec<TransportEndpoint>,
    pub publish_missing_relay_lists: bool,
    pub publish_initial_key_package: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountSetupResult {
    pub account: AccountSummary,
    pub relay_lists: AccountRelayListStatus,
    pub key_package_bytes: Option<usize>,
    pub profile: Option<UserProfileMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentTextStreamFinishRequest {
    pub stream_id: Vec<u8>,
    /// Hex-encoded MLS message id of the kind-1200 stream-start event. Carried
    /// on the kind-9 stream-final as the `["stream-start", <start_event_id>]`
    /// tag (`spec/features/agent-text-streams-quic.md:310-318`).
    pub start_event_id: String,
    pub final_text_or_reference: String,
    pub transcript_hash: [u8; 32],
    pub chunk_count: u64,
    pub finished_at: u64,
}

/// A media attachment carried as a NIP-92 `imeta` tag on a kind-9 chat event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaReference {
    pub url: String,
    pub file_hash_hex: String,
    pub nonce_hex: String,
    pub file_name: String,
    pub media_type: String,
    pub version: String,
}

impl MediaReference {
    fn validate(&self) -> Result<(), AppError> {
        let hash = hex::decode(&self.file_hash_hex)
            .map_err(|_| AppError::InvalidAppMessagePayload("media hash must be hex".into()))?;
        if hash.len() != 32 {
            return Err(AppError::InvalidAppMessagePayload(
                "media hash must be 32 bytes".into(),
            ));
        }
        let nonce = hex::decode(&self.nonce_hex)
            .map_err(|_| AppError::InvalidAppMessagePayload("media nonce must be hex".into()))?;
        if nonce.len() != 12 {
            return Err(AppError::InvalidAppMessagePayload(
                "media nonce must be 12 bytes".into(),
            ));
        }
        if self.url.trim().is_empty() {
            return Err(AppError::InvalidAppMessagePayload(
                "media URL cannot be empty".into(),
            ));
        }
        if self.file_name.trim().is_empty() {
            return Err(AppError::InvalidAppMessagePayload(
                "media file name cannot be empty".into(),
            ));
        }
        if self.media_type.trim().is_empty() {
            return Err(AppError::InvalidAppMessagePayload(
                "media type cannot be empty".into(),
            ));
        }
        if self.version != "mip04-v2" {
            return Err(AppError::InvalidAppMessagePayload(
                "media version must be mip04-v2".into(),
            ));
        }
        Ok(())
    }

    /// NIP-92 `imeta` tag fields for this attachment.
    fn imeta_tag(&self) -> Vec<String> {
        vec![
            "imeta".to_owned(),
            format!("url {}", self.url),
            format!("m {}", self.media_type),
            format!("filename {}", self.file_name),
            format!("x {}", self.file_hash_hex),
            format!("n {}", self.nonce_hex),
            format!("v {}", self.version),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaUploadRequest {
    pub file_name: String,
    pub media_type: String,
    pub plaintext: Vec<u8>,
    pub caption: Option<String>,
    pub send: bool,
    pub blossom_server: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaUploadResult {
    pub reference: MediaReference,
    pub encrypted_hash_hex: String,
    pub encrypted_size_bytes: u64,
    pub sent: Option<SendSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaDownloadResult {
    pub plaintext: Vec<u8>,
    pub file_name: String,
    pub media_type: String,
    pub size_bytes: u64,
}

/// A structured outgoing app message, resolved into a [`MarmotInnerEvent`] by
/// the account worker (which owns the authoring account id and the clock).
#[derive(Clone, Debug, PartialEq, Eq)]
enum AppMessageIntent {
    Chat {
        content: String,
    },
    Reaction {
        target_message_id: String,
        emoji: String,
    },
    Unreact {
        target_message_id: String,
    },
    Reply {
        target_message_id: String,
        text: String,
    },
    Delete {
        target_message_id: String,
    },
    Media {
        reference: MediaReference,
        caption: Option<String>,
    },
    StreamStart {
        stream_id: Vec<u8>,
        quic_candidates: Vec<String>,
    },
    StreamFinal {
        request: AgentTextStreamFinishRequest,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppStatus {
    pub account: String,
    pub account_id_hex: String,
    pub transport: String,
    pub groups: Vec<AppGroupRecord>,
    pub seen_events: usize,
    pub group_count: usize,
    pub message_count: usize,
    pub projections: AppProjectionStatus,
    pub relay_lists: AccountRelayListStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppProjectionStatus {
    pub account: AppDatabaseStatus,
    pub shared: AppDatabaseStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppDatabaseStatus {
    pub path: String,
    pub exists: bool,
    pub encrypted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRelayListStatus {
    pub complete: bool,
    pub missing: Vec<String>,
    pub default_relays: Vec<String>,
    pub bootstrap_relays: Vec<String>,
    pub nip65: AccountRelayListState,
    pub inbox: AccountRelayListState,
    pub key_package: AccountRelayListState,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRelayListState {
    pub kind: u64,
    pub relays: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRelayListBootstrap {
    pub default_relays: Vec<TransportEndpoint>,
    pub bootstrap_relays: Vec<TransportEndpoint>,
}

impl AccountRelayListBootstrap {
    pub fn new(
        default_relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Self {
        let bootstrap_relays = if bootstrap_relays.is_empty() {
            default_relays.clone()
        } else {
            bootstrap_relays
        };
        Self {
            default_relays,
            bootstrap_relays,
        }
    }
}

impl AccountRelayListStatus {
    fn empty() -> Self {
        let mut status = Self {
            complete: false,
            missing: Vec::new(),
            default_relays: Vec::new(),
            bootstrap_relays: Vec::new(),
            nip65: AccountRelayListState {
                kind: KIND_NIP65_RELAY_LIST,
                relays: Vec::new(),
            },
            inbox: AccountRelayListState {
                kind: KIND_MARMOT_INBOX_RELAY_LIST,
                relays: Vec::new(),
            },
            key_package: AccountRelayListState {
                kind: KIND_MARMOT_KEY_PACKAGE_RELAY_LIST,
                relays: Vec::new(),
            },
        };
        status.refresh();
        status
    }

    fn refresh(&mut self) {
        self.default_relays = self.nip65.relays.clone();
        self.missing = Vec::new();
        if self.nip65.relays.is_empty() {
            self.missing.push("nip65".into());
        }
        if self.inbox.relays.is_empty() {
            self.missing.push("inbox".into());
        }
        if self.key_package.relays.is_empty() {
            self.missing.push("key_package".into());
        }
        self.complete = self.missing.is_empty();
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub joined_groups: Vec<GroupId>,
    pub messages: Vec<ReceivedMessage>,
    pub events: Vec<GroupEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedMessage {
    pub message_id_hex: String,
    pub sender: String,
    pub sender_display_name: Option<String>,
    pub group_id: GroupId,
    /// Displayed text for the inner app event (its `content`).
    pub plaintext: String,
    /// Nostr `kind` of the inner Marmot app event.
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    pub tags: Vec<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeMessageReceived {
    pub account_id_hex: String,
    pub account_label: String,
    pub message: ReceivedMessage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeGroupEvent {
    pub account_id_hex: String,
    pub account_label: String,
    pub event: GroupEvent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAccountError {
    pub account_id_hex: String,
    pub account_label: String,
    pub message: String,
}

/// A kind-1200 agent-text-stream **start** observed in a group. The inner
/// event's stream metadata lives on `message.tags`; clients use it to open the
/// ephemeral QUIC preview. The eventual kind-9 stream-final flows as a normal
/// [`RuntimeMessageUpdate::Message`] carrying `stream`/`stream-start` tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAgentStreamMessage {
    pub account_id_hex: String,
    pub account_label: String,
    pub message: ReceivedMessage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeMessageUpdate {
    Message(RuntimeMessageReceived),
    AgentStreamStarted(RuntimeAgentStreamMessage),
}

impl RuntimeMessageUpdate {
    pub fn account_id_hex(&self) -> &str {
        match self {
            Self::Message(update) => &update.account_id_hex,
            Self::AgentStreamStarted(update) => &update.account_id_hex,
        }
    }

    pub fn message(&self) -> &ReceivedMessage {
        match self {
            Self::Message(update) => &update.message,
            Self::AgentStreamStarted(update) => &update.message,
        }
    }
}

pub struct RuntimeMessagesSubscription {
    pub snapshot: Vec<AppMessageRecord>,
    updates: mpsc::Receiver<RuntimeMessageUpdate>,
}

impl RuntimeMessagesSubscription {
    pub async fn recv(&mut self) -> Option<RuntimeMessageUpdate> {
        self.updates.recv().await
    }
}

pub struct RuntimeChatsSubscription {
    pub snapshot: Vec<AppGroupRecord>,
    updates: mpsc::Receiver<AppGroupRecord>,
}

impl RuntimeChatsSubscription {
    pub async fn recv(&mut self) -> Option<AppGroupRecord> {
        self.updates.recv().await
    }
}

pub struct RuntimeGroupStateSubscription {
    pub snapshot: AppGroupRecord,
    updates: mpsc::Receiver<AppGroupRecord>,
}

impl RuntimeGroupStateSubscription {
    pub async fn recv(&mut self) -> Option<AppGroupRecord> {
        self.updates.recv().await
    }
}

/// One update from watching a live agent text stream over QUIC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeAgentStreamUpdate {
    /// An incremental text delta. `text` is the new fragment, not the full text.
    Chunk { seq: u64, text: String },
    /// The stream closed cleanly; `text` is the complete transcript.
    Finished {
        text: String,
        transcript_hash_hex: String,
        chunk_count: u64,
    },
    /// The watch failed (connection/broker error).
    Failed { message: String },
}

#[derive(Clone, Debug, Default)]
pub struct AgentStreamWatchOptions {
    /// Watch a specific stream id; `None` watches the latest stream in the group.
    pub stream_id_hex: Option<String>,
    /// DER cert for a self-signed broker; `None` uses platform trust.
    pub server_cert_der: Option<Vec<u8>>,
    /// Loopback-only insecure trust, for local testing.
    pub insecure_local: bool,
}

/// A live agent-text-stream watch. Drains chunk/finished/failed updates from a
/// background QUIC subscription task.
pub struct RuntimeAgentStreamWatch {
    pub stream_id_hex: String,
    updates: mpsc::Receiver<RuntimeAgentStreamUpdate>,
    abort: tokio::task::AbortHandle,
}

impl RuntimeAgentStreamWatch {
    pub async fn recv(&mut self) -> Option<RuntimeAgentStreamUpdate> {
        self.updates.recv().await
    }
}

impl Drop for RuntimeAgentStreamWatch {
    fn drop(&mut self) {
        // Cancel the background QUIC subscriber so dropping the watch handle
        // doesn't leak a task driving a (possibly hung) broker connection.
        self.abort.abort();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarmotAppEvent {
    GroupJoined {
        account_id_hex: String,
        account_label: String,
        group_id: GroupId,
    },
    GroupStateUpdated {
        account_id_hex: String,
        account_label: String,
        group_id: GroupId,
    },
    MessageReceived(RuntimeMessageReceived),
    AgentStreamStarted(RuntimeAgentStreamMessage),
    GroupEvent(RuntimeGroupEvent),
    AccountError(RuntimeAccountError),
}

impl MarmotAppRuntime {
    pub fn new(app: MarmotApp) -> Self {
        let (events, _) = broadcast::channel(1024);
        let shared = RuntimeSharedServices::for_app(&app);
        let accounts = AccountManager::new(app, events.clone(), shared.clone());
        Self {
            events,
            shared,
            accounts,
        }
    }

    pub fn open(app: MarmotApp) -> Self {
        Self::new(app)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MarmotAppEvent> {
        self.events.subscribe()
    }

    pub fn display_name_for_account_id(&self, account_id_hex: &str) -> Option<String> {
        self.accounts
            .app
            .display_name_for_account_id(account_id_hex)
            .ok()
            .flatten()
    }

    pub fn subscribe_messages(
        &self,
        account_ref: &str,
        query: AppMessageQuery,
    ) -> Result<RuntimeMessagesSubscription, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let group_id_hex = query.group_id_hex.clone();
        let mut events = self.events.subscribe();
        let snapshot = self.messages_with_query(&account.account_id_hex, query)?;
        let mut seen_message_ids = snapshot
            .iter()
            .filter_map(|message| {
                if message.message_id_hex.is_empty() {
                    None
                } else {
                    Some(message.message_id_hex.clone())
                }
            })
            .collect::<HashSet<_>>();
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = match events.recv().await {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                let Some(update) = runtime_message_update_from_event(event) else {
                    continue;
                };
                if update.account_id_hex() != account_id_hex {
                    continue;
                }
                let message = update.message();
                if group_id_hex.as_deref()
                    != Some(hex::encode(message.group_id.as_slice()).as_str())
                    && group_id_hex.is_some()
                {
                    continue;
                }
                if !message.message_id_hex.is_empty()
                    && !seen_message_ids.insert(message.message_id_hex.clone())
                {
                    continue;
                }
                if updates_tx.send(update).await.is_err() {
                    return;
                }
            }
        });
        Ok(RuntimeMessagesSubscription {
            snapshot,
            updates: updates_rx,
        })
    }

    pub fn subscribe_chats(
        &self,
        account_ref: &str,
        include_archived: bool,
    ) -> Result<RuntimeChatsSubscription, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let account_label = account.label.clone();
        let app = self.accounts.app.clone();
        let mut events = self.events.subscribe();
        let snapshot = if include_archived {
            app.groups(&account_label)?
        } else {
            app.visible_groups(&account_label)?
        };
        let mut seen_groups = snapshot
            .iter()
            .map(app_group_record_fingerprint)
            .collect::<HashSet<_>>();
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = match events.recv().await {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                let Some((event_account_id_hex, group_id)) = runtime_group_event_route(&event)
                else {
                    continue;
                };
                if event_account_id_hex != account_id_hex {
                    continue;
                }
                let group_id_hex = hex::encode(group_id.as_slice());
                let app_for_lookup = app.clone();
                let account_label_for_lookup = account_label.clone();
                let group = match blocking_app_task(move || {
                    app_for_lookup.group(&account_label_for_lookup, &group_id_hex)
                })
                .await
                {
                    Ok(Some(group)) => group,
                    Ok(None) | Err(_) => continue,
                };
                if !include_archived && group.archived {
                    continue;
                }
                if !seen_groups.insert(app_group_record_fingerprint(&group)) {
                    continue;
                }
                if updates_tx.send(group).await.is_err() {
                    return;
                }
            }
        });
        Ok(RuntimeChatsSubscription {
            snapshot,
            updates: updates_rx,
        })
    }

    pub fn subscribe_group_state(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<RuntimeGroupStateSubscription, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let account_label = account.label.clone();
        let app = self.accounts.app.clone();
        let group_id_hex = normalize_group_id_hex_app(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let mut events = self.events.subscribe();
        let snapshot = app
            .group(&account_label, &group_id_hex)?
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
        let mut last_fingerprint = app_group_record_fingerprint(&snapshot);
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = match events.recv().await {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                let Some((event_account_id_hex, event_group_id)) =
                    runtime_group_event_route(&event)
                else {
                    continue;
                };
                if event_account_id_hex != account_id_hex || event_group_id != &group_id {
                    continue;
                }
                let app_for_lookup = app.clone();
                let account_label_for_lookup = account_label.clone();
                let group_id_hex_for_lookup = group_id_hex.clone();
                let group = match blocking_app_task(move || {
                    app_for_lookup.group(&account_label_for_lookup, &group_id_hex_for_lookup)
                })
                .await
                {
                    Ok(Some(group)) => group,
                    Ok(None) | Err(_) => continue,
                };
                let fingerprint = app_group_record_fingerprint(&group);
                if fingerprint == last_fingerprint {
                    continue;
                }
                last_fingerprint = fingerprint;
                if updates_tx.send(group).await.is_err() {
                    return;
                }
            }
        });
        Ok(RuntimeGroupStateSubscription {
            snapshot,
            updates: updates_rx,
        })
    }

    /// Watch a live agent text stream over the brokered QUIC channel. Resolves
    /// the latest `Start` payload for the group (or a specific `stream_id`),
    /// connects to the broker named in its `quic://` candidate, and streams
    /// incremental text chunks until the stream finishes. Must be called from
    /// within a tokio runtime (it spawns the QUIC subscriber task).
    pub async fn watch_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        options: AgentStreamWatchOptions,
    ) -> Result<RuntimeAgentStreamWatch, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let app = self.accounts.app.clone();
        let account_ref_for_query = account_ref.to_owned();
        let messages = blocking_app_task(move || {
            app.messages_with_query(
                &account_ref_for_query,
                AppMessageQuery {
                    group_id_hex: Some(group_id_hex),
                    limit: Some(AGENT_STREAM_START_LOOKBACK_LIMIT),
                },
            )
        })
        .await?;
        let (start_message_id_hex, start, sender_hex) =
            latest_agent_stream_start(messages, options.stream_id_hex.as_deref())?;
        if start_message_id_hex.is_empty() {
            // The latest start hasn't been echoed back with a message id yet, so
            // we can't reference it to the broker; surface that rather than
            // forwarding a zero-length MessageId.
            return Err(AppError::AgentStreamStartNotConfirmed);
        }
        if start.route != STREAM_ROUTE_QUIC {
            return Err(AppError::AgentStreamUnsupportedRoute);
        }
        let candidates = parse_quic_candidates(&start.quic_candidates)?;
        let server_cert_der = options.server_cert_der;
        let insecure_local = options.insecure_local;
        let stream_id = hex::decode(&start.stream_id_hex)?;
        let stream_id_hex = start.stream_id_hex.clone();
        let start_event_id = MessageId::new(hex::decode(&start_message_id_hex)?);
        let account = self.accounts.app.account_home().account(account_ref)?;
        let group_state = self.group_mls_state(&account.label, group_id).await?;
        let stream_secret = self
            .agent_text_stream_exporter_secret(&account.label, group_id)
            .await?;
        let crypto = AgentTextStreamCrypto::new(
            stream_secret,
            AgentTextStreamKeyContextV1::new(
                group_id.clone(),
                stream_id.clone(),
                cgka_traits::EpochId(group_state.epoch),
                MemberId::new(hex::decode(sender_hex)?),
                start_event_id.clone(),
            ),
        );

        let (updates_tx, updates_rx) = mpsc::channel(1024);
        let handle = tokio::spawn(async move {
            let final_update = watch_broker_candidates(
                candidates,
                server_cert_der,
                insecure_local,
                stream_id,
                start_event_id,
                Some(crypto),
                updates_tx.clone(),
            )
            .await;
            let _ = updates_tx.send(final_update).await;
        });
        Ok(RuntimeAgentStreamWatch {
            stream_id_hex,
            updates: updates_rx,
            abort: handle.abort_handle(),
        })
    }

    pub fn accounts(&self) -> AccountManager {
        self.accounts.clone()
    }

    pub fn shared_services(&self) -> RuntimeSharedServices {
        self.shared.clone()
    }

    pub async fn start(&self) -> Result<(), AppError> {
        self.reconcile_accounts().await
    }

    pub async fn reconcile_accounts(&self) -> Result<(), AppError> {
        self.accounts.reconcile().await
    }

    pub async fn restart_account(&self, account_id_hex: &str) -> Result<(), AppError> {
        self.accounts.restart_account(account_id_hex).await
    }

    pub async fn catch_up_accounts(&self) -> Result<(), AppError> {
        self.accounts.catch_up_accounts().await
    }

    pub async fn create_group(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
    ) -> Result<GroupId, AppError> {
        self.accounts
            .create_group(account_ref, name, members, description)
            .await
    }

    pub async fn group_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        self.accounts.group_members(account_ref, group_id).await
    }

    pub async fn group_mls_state(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupMlsState, AppError> {
        self.accounts.group_mls_state(account_ref, group_id).await
    }

    pub async fn safe_export_secret(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        component_id: cgka_traits::AppComponentId,
    ) -> Result<SecretBytes, AppError> {
        self.accounts
            .safe_export_secret(account_ref, group_id, component_id)
            .await
    }

    pub async fn agent_text_stream_exporter_secret(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SecretBytes, AppError> {
        self.accounts
            .exporter_secret(account_ref, group_id, AGENT_TEXT_STREAM_EXPORTER_LABEL, 32)
            .await
    }

    pub async fn invite_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        members: &[String],
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .invite_members(account_ref, group_id, members)
            .await
    }

    pub async fn remove_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        members: &[String],
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .remove_members(account_ref, group_id, members)
            .await
    }

    pub async fn leave_group(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.accounts.leave_group(account_ref, group_id).await
    }

    pub async fn update_group_profile(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .update_group_profile(account_ref, group_id, name, description)
            .await
    }

    pub async fn update_message_retention(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        disappearing_message_secs: u64,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .update_message_retention(account_ref, group_id, disappearing_message_secs)
            .await
    }

    pub async fn promote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .promote_admin(account_ref, group_id, member_ref)
            .await
    }

    pub async fn demote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .demote_admin(account_ref, group_id, member_ref)
            .await
    }

    pub async fn self_demote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.accounts.self_demote_admin(account_ref, group_id).await
    }

    pub async fn send_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        payload: Vec<u8>,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_message(account_ref, group_id, payload)
            .await
    }

    pub async fn react_to_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        target_message_id: &str,
        emoji: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Reaction {
                    target_message_id: target_message_id.to_owned(),
                    emoji: emoji.to_owned(),
                },
            )
            .await
    }

    pub async fn unreact_from_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        target_message_id: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Unreact {
                    target_message_id: target_message_id.to_owned(),
                },
            )
            .await
    }

    pub async fn reply_to_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        target_message_id: &str,
        text: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Reply {
                    target_message_id: target_message_id.to_owned(),
                    text: text.to_owned(),
                },
            )
            .await
    }

    pub async fn delete_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        target_message_id: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Delete {
                    target_message_id: target_message_id.to_owned(),
                },
            )
            .await
    }

    /// Send a media attachment as a kind-9 chat carrying a NIP-92 `imeta` tag.
    pub async fn send_media_reference(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        reference: MediaReference,
        caption: Option<String>,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Media { reference, caption },
            )
            .await
    }

    pub async fn upload_media(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        request: MediaUploadRequest,
    ) -> Result<MediaUploadResult, AppError> {
        self.accounts
            .upload_media(account_ref, group_id, request)
            .await
    }

    pub async fn download_media(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        reference: MediaReference,
    ) -> Result<MediaDownloadResult, AppError> {
        self.accounts
            .download_media(account_ref, group_id, reference)
            .await
    }

    pub async fn retry_group_convergence(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .retry_group_convergence(account_ref, group_id)
            .await
    }

    /// Anchor a kind-1200 agent text stream start. The `created_at` argument is
    /// retained for call-site stability; the worker stamps the inner event with
    /// its own clock so the canonical id matches the authoring time. Returns the
    /// built inner event (its tags carry the stream id, route, and brokers).
    pub async fn start_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        stream_id: &[u8],
        _created_at: u64,
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.accounts
            .start_agent_text_stream(account_ref, group_id, stream_id.to_vec(), quic_candidates)
            .await
    }

    /// Send the kind-9 stream-final chat carrying `stream`/`stream-hash`/
    /// `stream-chunks` tags. Returns the built inner event.
    pub async fn finish_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        request: AgentTextStreamFinishRequest,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.accounts
            .finish_agent_text_stream(account_ref, group_id, request)
            .await
    }

    pub async fn publish_key_package(&self, account_ref: &str) -> Result<usize, AppError> {
        self.accounts.publish_key_package(account_ref).await
    }

    pub async fn rotate_key_package(&self, account_ref: &str) -> Result<usize, AppError> {
        self.accounts.rotate_key_package(account_ref).await
    }

    pub async fn publish_user_profile(
        &self,
        account_ref: &str,
        profile: UserProfileMetadata,
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<UserProfileMetadata, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .publish_user_profile(&account.label, profile.clone(), bootstrap)
            .await?;
        self.accounts
            .app
            .remember_directory_profile(&account.account_id_hex, &profile)?;
        Ok(profile)
    }

    pub async fn publish_account_follow_list(
        &self,
        account_ref: &str,
        follows: &[String],
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<(), AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let follow_refs = follows.iter().map(String::as_str).collect::<Vec<_>>();
        self.accounts
            .app
            .publish_account_follow_list(&account.label, &follow_refs, bootstrap)
            .await
    }

    pub async fn refresh_user_directory_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<UserDirectoryRefresh, AppError> {
        self.accounts
            .app
            .refresh_user_directory_for_account_id(account_id_hex, bootstrap_relays)
            .await
    }

    pub async fn publish_account_relay_list_kind(
        &self,
        account_ref: &str,
        relay_type: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .publish_account_relay_list_kind(&account.label, relay_type, relays, bootstrap_relays)
            .await
    }

    pub fn account_nip65_relays(&self, account_ref: &str) -> Result<Vec<String>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts.app.account_nip65_relays(&account.label)
    }

    pub fn account_inbox_relays(&self, account_ref: &str) -> Result<Vec<String>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts.app.account_inbox_relays(&account.label)
    }

    pub fn account_key_package_relays(&self, account_ref: &str) -> Result<Vec<String>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts.app.account_key_package_relays(&account.label)
    }

    pub async fn set_account_nip65_relays(
        &self,
        account_ref: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .set_account_nip65_relays(&account.label, relays, bootstrap_relays)
            .await
    }

    pub async fn set_account_inbox_relays(
        &self,
        account_ref: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .set_account_inbox_relays(&account.label, relays, bootstrap_relays)
            .await
    }

    pub async fn set_account_key_package_relays(
        &self,
        account_ref: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .set_account_key_package_relays(&account.label, relays, bootstrap_relays)
            .await
    }

    pub fn messages_with_query(
        &self,
        account_ref: &str,
        query: AppMessageQuery,
    ) -> Result<Vec<AppMessageRecord>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts.app.messages_with_query(&account.label, query)
    }

    pub async fn create_identity(
        &self,
        mut request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        request.identity = None;
        self.accounts.create_or_import_account(request).await
    }

    pub async fn login(
        &self,
        identity: impl Into<String>,
        mut request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        request.identity = Some(identity.into());
        self.accounts.create_or_import_account(request).await
    }

    pub async fn create_or_import_account(
        &self,
        request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        self.accounts.create_or_import_account(request).await
    }

    pub async fn shutdown(&self) {
        self.accounts.shutdown().await;
        self.shared.relay_plane.shutdown().await;
    }
}

impl AccountManager {
    fn new(
        app: MarmotApp,
        events: broadcast::Sender<MarmotAppEvent>,
        shared: RuntimeSharedServices,
    ) -> Self {
        Self {
            app,
            events,
            shared,
            workers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn managed_accounts(&self) -> Result<Vec<ManagedAccount>, AppError> {
        let running = self
            .workers
            .try_lock()
            .ok()
            .map(|workers| workers.keys().cloned().collect::<HashSet<_>>())
            .unwrap_or_default();
        Ok(self
            .app
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.local_signing)
            .map(|account| ManagedAccount {
                running: running.contains(&account.account_id_hex),
                label: account.label,
                account_id_hex: account.account_id_hex,
                local_signing: account.local_signing,
            })
            .collect())
    }

    pub fn resolve(&self, account_ref: &str) -> Result<AccountSummary, AppError> {
        Ok(self.app.account_home().account(account_ref)?)
    }

    pub async fn reconcile(&self) -> Result<(), AppError> {
        let accounts = self
            .app
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.local_signing)
            .collect::<Vec<_>>();
        let active_account_ids = accounts
            .iter()
            .map(|account| account.account_id_hex.clone())
            .collect::<HashSet<_>>();

        let existing_account_ids = {
            let mut workers = self.workers.lock().await;
            let stale_account_ids = workers
                .iter()
                .filter_map(|(account_id, worker)| {
                    if active_account_ids.contains(account_id) && !worker.handle.is_finished() {
                        None
                    } else {
                        Some(account_id.clone())
                    }
                })
                .collect::<Vec<_>>();
            for account_id in stale_account_ids {
                if let Some(worker) = workers.remove(&account_id) {
                    worker.stop();
                }
            }
            workers.keys().cloned().collect::<HashSet<_>>()
        };

        let pending = accounts
            .into_iter()
            .filter(|account| !existing_account_ids.contains(&account.account_id_hex))
            .collect::<Vec<_>>();

        let mut ready_receivers = Vec::new();
        {
            let mut workers = self.workers.lock().await;
            for account in pending {
                if workers.contains_key(&account.account_id_hex) {
                    continue;
                }
                let (ready_tx, ready_rx) = oneshot::channel();
                let (shutdown_tx, shutdown_rx) = oneshot::channel();
                let (command_tx, command_rx) = mpsc::channel(8);
                let handle = spawn_app_runtime_account_worker(
                    AccountWorkerRuntime {
                        app: self.app.clone(),
                        account_label: account.label.clone(),
                        account_id_hex: account.account_id_hex.clone(),
                        relay_plane: self.shared.relay_plane().clone(),
                        events: self.events.clone(),
                    },
                    command_rx,
                    ready_tx,
                    shutdown_rx,
                );
                workers.insert(
                    account.account_id_hex,
                    ManagedAccountWorker {
                        handle,
                        commands: command_tx,
                        shutdown: shutdown_tx,
                    },
                );
                ready_receivers.push(ready_rx);
            }
        }
        for ready in ready_receivers {
            match timeout(APP_RUNTIME_ACCOUNT_READY_WAIT, ready).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(message))) => return Err(AppError::BlockingTask(message)),
                Ok(Err(_closed)) => return Err(AppError::TransportClosed),
                Err(_elapsed) => {
                    return Err(AppError::BlockingTask(
                        "account worker startup timed out".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub async fn restart_account(&self, account_id_hex: &str) -> Result<(), AppError> {
        {
            let mut workers = self.workers.lock().await;
            if let Some(worker) = workers.remove(account_id_hex) {
                worker.stop();
            }
        }
        self.reconcile().await
    }

    pub async fn catch_up_accounts(&self) -> Result<(), AppError> {
        self.reconcile().await?;
        let commands = {
            let workers = self.workers.lock().await;
            workers
                .values()
                .map(|worker| worker.commands.clone())
                .collect::<Vec<_>>()
        };
        for command in commands {
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::CatchUp { respond })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            match timeout(APP_RUNTIME_ACCOUNT_READY_WAIT, response).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(message))) => return Err(AppError::RelayDirectory(message)),
                Ok(Err(_)) => return Err(AppError::TransportClosed),
                Err(_) => {
                    return Err(AppError::RelayDirectory(
                        "account worker catch-up timed out".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub async fn create_group(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
    ) -> Result<GroupId, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::CreateGroup {
                name: name.to_owned(),
                members: members.to_vec(),
                description,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let group_id = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        Ok(group_id)
    }

    pub async fn group_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::Members {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn group_mls_state(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupMlsState, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::GroupMlsState {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn safe_export_secret(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        component_id: cgka_traits::AppComponentId,
    ) -> Result<SecretBytes, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SafeExportSecret {
                group_id: group_id.clone(),
                component_id,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn exporter_secret(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> Result<SecretBytes, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ExporterSecret {
                group_id: group_id.clone(),
                label: label.to_owned(),
                length,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn invite_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        members: &[String],
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::InviteMembers {
                group_id: group_id.clone(),
                members: members.to_vec(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        Ok(summary)
    }

    pub async fn remove_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        members: &[String],
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RemoveMembers {
                group_id: group_id.clone(),
                members: members.to_vec(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        Ok(summary)
    }

    pub async fn leave_group(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::LeaveGroup {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        Ok(summary)
    }

    pub async fn update_message_retention(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        disappearing_message_secs: u64,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UpdateMessageRetention {
                group_id: group_id.clone(),
                disappearing_message_secs,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        Ok(summary)
    }

    pub async fn promote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::PromoteAdmin {
                group_id: group_id.clone(),
                member_ref: member_ref.to_owned(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        Ok(summary)
    }

    pub async fn demote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DemoteAdmin {
                group_id: group_id.clone(),
                member_ref: member_ref.to_owned(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        Ok(summary)
    }

    pub async fn self_demote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SelfDemoteAdmin {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        Ok(summary)
    }

    pub async fn update_group_profile(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UpdateGroupProfile {
                group_id: group_id.clone(),
                name,
                description,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        Ok(summary)
    }

    pub async fn send_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        payload: Vec<u8>,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SendMessage {
                group_id: group_id.clone(),
                payload,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    async fn send_app_event(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        intent: AppMessageIntent,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SendAppEvent {
                group_id: group_id.clone(),
                intent,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    async fn upload_media(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        request: MediaUploadRequest,
    ) -> Result<MediaUploadResult, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UploadMedia {
                group_id: group_id.clone(),
                request,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    async fn download_media(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        reference: MediaReference,
    ) -> Result<MediaDownloadResult, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DownloadMedia {
                group_id: group_id.clone(),
                reference,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    async fn start_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        stream_id: Vec<u8>,
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::StartAgentTextStream {
                group_id: group_id.clone(),
                stream_id,
                quic_candidates,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    async fn finish_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        request: AgentTextStreamFinishRequest,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::FinishAgentTextStream {
                group_id: group_id.clone(),
                request,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn retry_group_convergence(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RetryGroupConvergence {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        Ok(summary)
    }

    pub async fn publish_key_package(&self, account_ref: &str) -> Result<usize, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::PublishKeyPackage { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn rotate_key_package(&self, account_ref: &str) -> Result<usize, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RotateKeyPackage { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    async fn worker_commands(
        &self,
        account_ref: &str,
    ) -> Result<mpsc::Sender<AccountWorkerCommand>, AppError> {
        let account = self.resolve(account_ref)?;
        if !account.local_signing {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex).into());
        }
        self.reconcile().await?;
        let workers = self.workers.lock().await;
        workers
            .get(&account.account_id_hex)
            .map(|worker| worker.commands.clone())
            .ok_or_else(|| {
                AppError::RelayDirectory(
                    "managed account worker is not running for local signing account".into(),
                )
            })
    }

    pub async fn create_or_import_account(
        &self,
        request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        let imports_private_key = request.identity.as_deref().is_some_and(is_nostr_secret);
        let creates_new_private_key = request.identity.is_none();
        let directory_bootstrap_relays = directory_bootstrap_relays_for_setup(&request);
        let account = match self.create_nostr_account(request.identity.clone()) {
            Ok(account) => account,
            Err(err) => return Err(err),
        };

        let relay_lists = match self
            .setup_relay_lists_for_account(
                &account,
                &request,
                imports_private_key,
                creates_new_private_key,
            )
            .await
        {
            Ok(relay_lists) => relay_lists,
            Err(err) => {
                return self.rollback_account_after_setup_failure(&account.label, err);
            }
        };

        let profile = if creates_new_private_key && account.local_signing {
            match self
                .publish_default_profile_for_account(&account, &request)
                .await
            {
                Ok(profile) => Some(profile),
                Err(err) => {
                    return self.rollback_account_after_setup_failure(&account.label, err);
                }
            }
        } else {
            None
        };

        let key_package_bytes = if request.publish_initial_key_package && account.local_signing {
            match self.publish_initial_key_package_for_account(&account).await {
                Ok(bytes) => Some(bytes),
                Err(err) => {
                    return self.rollback_account_after_setup_failure(&account.label, err);
                }
            }
        } else {
            None
        };

        let _ = self
            .app
            .refresh_user_directory_for_account_id(
                &account.account_id_hex,
                directory_bootstrap_relays.clone(),
            )
            .await;
        self.reconcile().await?;

        Ok(AccountSetupResult {
            account,
            relay_lists,
            key_package_bytes,
            profile,
        })
    }

    async fn publish_default_profile_for_account(
        &self,
        account: &AccountSummary,
        request: &AccountSetupRequest,
    ) -> Result<UserProfileMetadata, AppError> {
        let pseudonym = default_profile_pseudonym(&account.account_id_hex);
        let profile = UserProfileMetadata {
            name: Some(pseudonym.clone()),
            display_name: Some(pseudonym),
            created_at: unix_now_seconds(),
            ..UserProfileMetadata::default()
        };
        self.app
            .publish_user_profile(
                &account.label,
                profile.clone(),
                AccountRelayListBootstrap::new(
                    request.default_relays.clone(),
                    request.bootstrap_relays.clone(),
                ),
            )
            .await?;
        self.app
            .remember_directory_profile(&account.account_id_hex, &profile)?;
        Ok(profile)
    }

    async fn setup_relay_lists_for_account(
        &self,
        account: &AccountSummary,
        request: &AccountSetupRequest,
        imports_private_key: bool,
        creates_new_private_key: bool,
    ) -> Result<AccountRelayListStatus, AppError> {
        if account.local_signing {
            if creates_new_private_key && request.default_relays.is_empty() {
                return Err(AppError::MissingDefaultRelays);
            }
            if imports_private_key
                && request.default_relays.is_empty()
                && request.bootstrap_relays.is_empty()
            {
                return Err(AppError::MissingDefaultRelays);
            }
            if imports_private_key
                && (!request.default_relays.is_empty() || !request.bootstrap_relays.is_empty())
            {
                let bootstrap = AccountRelayListBootstrap::new(
                    request.default_relays.clone(),
                    request.bootstrap_relays.clone(),
                );
                let current_status = self
                    .app
                    .fetch_account_relay_list_status_for_account_id(
                        &account.account_id_hex,
                        bootstrap.bootstrap_relays.clone(),
                    )
                    .await?;
                if current_status.complete {
                    Ok(current_status)
                } else if !request.publish_missing_relay_lists || request.default_relays.is_empty()
                {
                    Err(AppError::MissingRelayLists(current_status.missing.clone()))
                } else {
                    self.app
                        .publish_missing_account_relay_lists_from_status(
                            &account.label,
                            bootstrap,
                            current_status,
                        )
                        .await
                }
            } else {
                self.publish_relay_lists_for_new_account(&account.label, request)
                    .await
            }
        } else {
            let bootstrap_relays = directory_bootstrap_relays_for_setup(request);
            if bootstrap_relays.is_empty() {
                return Err(AppError::MissingDefaultRelays);
            }
            self.app
                .fetch_account_relay_list_status_for_account_id(
                    &account.account_id_hex,
                    bootstrap_relays,
                )
                .await
        }
    }

    async fn publish_relay_lists_for_new_account(
        &self,
        label: &str,
        request: &AccountSetupRequest,
    ) -> Result<AccountRelayListStatus, AppError> {
        if request.default_relays.is_empty() && request.bootstrap_relays.is_empty() {
            return self.app.account_relay_list_status(label);
        }
        if request.default_relays.is_empty() {
            return Err(AppError::MissingDefaultRelays);
        }
        self.app
            .publish_account_relay_lists(
                label,
                AccountRelayListBootstrap::new(
                    request.default_relays.clone(),
                    request.bootstrap_relays.clone(),
                ),
            )
            .await
    }

    async fn publish_initial_key_package_for_account(
        &self,
        account: &AccountSummary,
    ) -> Result<usize, AppError> {
        self.app.status(&account.label)?;
        let mut client = self.app.client(&account.label).await?;
        let key_package = client.publish_key_package().await?;
        Ok(key_package.bytes().len())
    }

    fn create_nostr_account(&self, identity: Option<String>) -> Result<AccountSummary, AppError> {
        let account_home = self.app.account_home();
        match identity {
            Some(value) if is_nostr_secret(&value) => {
                Ok(account_home.import_nostr_account(&value)?)
            }
            Some(value) => Ok(account_home.add_public_account(&value)?),
            None => Ok(account_home.create_nostr_account()?),
        }
    }

    fn rollback_account_after_setup_failure<T>(
        &self,
        account: &str,
        source: AppError,
    ) -> Result<T, AppError> {
        match self.app.account_home().remove_account(account) {
            Ok(()) => Err(source),
            Err(rollback) => Err(AppError::RelayDirectory(format!(
                "failed to roll back account after setup failure: {source}; rollback error: {rollback}"
            ))),
        }
    }

    pub async fn shutdown(&self) {
        let mut workers = self.workers.lock().await;
        for (_, worker) in workers.drain() {
            worker.stop();
        }
    }
}

fn remember_seen_event(state: &mut AccountState, event_id: String) {
    if !state.seen_events.contains(&event_id) {
        state.seen_events.push(event_id);
        prune_seen_events(&mut state.seen_events);
    }
}

pub(crate) fn prune_seen_events(seen_events: &mut Vec<String>) {
    let overflow = seen_events.len().saturating_sub(MAX_SEEN_EVENT_IDS);
    if overflow > 0 {
        seen_events.drain(0..overflow);
    }
}

fn refresh_seen_lookup_if_needed(seen: &mut HashSet<String>, state: &AccountState) {
    if seen.len() > MAX_SEEN_EVENT_IDS {
        *seen = state.seen_events.iter().cloned().collect();
    }
}

fn is_nostr_secret(value: &str) -> bool {
    value.starts_with("nsec")
}

fn directory_bootstrap_relays_for_setup(request: &AccountSetupRequest) -> Vec<TransportEndpoint> {
    if request.bootstrap_relays.is_empty() {
        request.default_relays.clone()
    } else {
        request.bootstrap_relays.clone()
    }
}

async fn account_worker_response<T>(
    response: oneshot::Receiver<Result<T, AppError>>,
) -> Result<T, AppError> {
    response.await.map_err(|_| AppError::TransportClosed)?
}

async fn blocking_app_task<T>(
    task: impl FnOnce() -> Result<T, AppError> + Send + 'static,
) -> Result<T, AppError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|err| AppError::BlockingTask(err.to_string()))?
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppMessageRecord {
    pub message_id_hex: String,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    /// Nostr `kind` of the inner Marmot app event (9 chat, 7 reaction, …).
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Vec<String>>,
    pub recorded_at: u64,
    pub received_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppMessageQuery {
    pub group_id_hex: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendSummary {
    pub published: usize,
    pub message_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedKeyPackage {
    pub account_id_hex: String,
    pub key_package: KeyPackage,
    pub key_package_id: String,
    pub key_package_event_id: String,
    pub created_at: u64,
    pub source_relays: Vec<String>,
    pub relay_lists: AccountRelayListStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDirectoryRecord {
    pub account_id_hex: String,
    pub npub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_account: Option<UserDirectoryLocalAccount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<UserProfileMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub follows: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub follow_source_relays: Vec<String>,
    pub relay_lists: AccountRelayListStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_package: Option<DirectoryKeyPackage>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDirectoryLocalAccount {
    pub label: String,
    pub local_signing: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserProfileMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_relays: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDirectoryRefresh {
    pub account_id_hex: String,
    pub follow_count: usize,
    pub profile_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDirectorySearch {
    pub searcher_account_id_hex: String,
    pub query: String,
    pub radius_start: u8,
    pub radius_end: u8,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDirectorySearchResult {
    pub account_id_hex: String,
    pub npub: String,
    pub radius: u8,
    pub matched_field: String,
    pub match_quality: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<UserProfileMetadata>,
}

impl UserDirectorySearch {
    fn validate(&self) -> Result<(), AppError> {
        if self.radius_start > self.radius_end {
            return Err(AppError::InvalidDirectorySearch(
                "radius_start must be less than or equal to radius_end".into(),
            ));
        }
        parse_account_id_hex(&self.searcher_account_id_hex)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryKeyPackage {
    pub key_package_id: String,
    #[serde(default)]
    pub key_package_event_id: String,
    pub key_package_hex: String,
    pub created_at: u64,
    pub source_relays: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupRecord {
    pub group_id_hex: String,
    pub endpoint: String,
    pub nostr_routing: AppGroupNostrRoutingComponent,
    pub profile: AppGroupProfileComponent,
    pub image: AppGroupImageComponent,
    pub admin_policy: AppGroupAdminPolicyComponent,
    #[serde(default)]
    pub message_retention: AppGroupMessageRetentionComponent,
    #[serde(default)]
    pub agent_text_stream: AppAgentTextStreamComponent,
    #[serde(default)]
    pub archived: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupMemberRecord {
    pub member_id_hex: String,
    pub account: Option<String>,
    pub local: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupMlsState {
    pub group_id_hex: String,
    pub epoch: u64,
    pub member_count: usize,
    pub required_app_components: Vec<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupProfileComponent {
    pub component_id: u16,
    pub component: String,
    pub name: String,
    pub description: String,
    pub data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupImageComponent {
    pub component_id: u16,
    pub component: String,
    pub present: bool,
    pub image_hash_hex: String,
    pub image_key_hex: String,
    pub image_nonce_hex: String,
    pub image_upload_key_hex: String,
    pub media_type: Option<String>,
    pub data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupAdminPolicyComponent {
    pub component_id: u16,
    pub component: String,
    pub admins: Vec<String>,
    pub data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupMessageRetentionComponent {
    pub component_id: u16,
    pub component: String,
    pub disappearing_message_secs: u64,
    pub data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupNostrRoutingComponent {
    pub component_id: u16,
    pub component: String,
    pub nostr_group_id_hex: String,
    pub relays: Vec<String>,
    pub data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppAgentTextStreamComponent {
    pub component_id: u16,
    pub component: String,
    pub required: bool,
    pub required_member_roles: Vec<String>,
    pub allowed_member_roles: Vec<String>,
    pub max_plaintext_frame_len: u32,
    pub replay_ttl_secs: u32,
    pub padding_bucket_bytes: u16,
    pub data_hex: String,
}

impl Default for AppAgentTextStreamComponent {
    fn default() -> Self {
        Self::disabled()
    }
}

impl Default for AppGroupMessageRetentionComponent {
    fn default() -> Self {
        Self::disabled()
    }
}

impl AppGroupRecord {
    fn new(
        group_id_hex: String,
        nostr_routing: AppGroupNostrRoutingComponent,
        profile_name: String,
        profile_description: String,
        image: AppGroupImageInput,
        admin_policy: AppGroupAdminPolicyComponent,
        message_retention: AppGroupMessageRetentionComponent,
    ) -> Self {
        let endpoint = nostr_routing.relays.first().cloned().unwrap_or_default();
        Self {
            group_id_hex,
            endpoint,
            nostr_routing,
            profile: AppGroupProfileComponent::new(profile_name, profile_description),
            image: AppGroupImageComponent::new(image),
            admin_policy,
            message_retention,
            agent_text_stream: AppAgentTextStreamComponent::disabled(),
            archived: false,
        }
    }

    fn from_group(
        group_id: &GroupId,
        nostr_routing: AppGroupNostrRoutingComponent,
        group: Option<&Group>,
        admin_policy: AppGroupAdminPolicyComponent,
        message_retention: AppGroupMessageRetentionComponent,
        agent_text_stream: AppAgentTextStreamComponent,
    ) -> Self {
        let (profile_name, profile_description) = group
            .map(|group| (group.name.clone(), group.description.clone()))
            .unwrap_or_default();
        let mut record = Self::new(
            hex::encode(group_id.as_slice()),
            nostr_routing,
            profile_name,
            profile_description,
            AppGroupImageInput::default(),
            admin_policy,
            message_retention,
        );
        record.agent_text_stream = agent_text_stream;
        record
    }

    fn refresh_from_group(
        &mut self,
        nostr_routing: AppGroupNostrRoutingComponent,
        group: Option<&Group>,
        admin_policy: AppGroupAdminPolicyComponent,
        message_retention: AppGroupMessageRetentionComponent,
        agent_text_stream: AppAgentTextStreamComponent,
    ) {
        self.endpoint = nostr_routing.relays.first().cloned().unwrap_or_default();
        self.nostr_routing = nostr_routing;
        self.admin_policy = admin_policy;
        self.message_retention = message_retention;
        self.agent_text_stream = agent_text_stream;
        if let Some(group) = group {
            self.profile =
                AppGroupProfileComponent::new(group.name.clone(), group.description.clone());
        }
    }
}

impl AppGroupProfileComponent {
    fn new(name: String, description: String) -> Self {
        let data = encode_component_vectors(&[name.as_bytes(), description.as_bytes()]);
        Self {
            component_id: GROUP_PROFILE_COMPONENT_ID,
            component: GROUP_PROFILE_COMPONENT.to_owned(),
            name,
            description,
            data_hex: hex::encode(data),
        }
    }
}

impl AppGroupImageComponent {
    fn new(input: AppGroupImageInput) -> Self {
        let present = !input.image_hash_hex.is_empty()
            || !input.image_key_hex.is_empty()
            || !input.image_nonce_hex.is_empty()
            || !input.image_upload_key_hex.is_empty()
            || input.media_type.is_some();
        let image_hash = hex::decode(&input.image_hash_hex).unwrap_or_default();
        let image_key = hex::decode(&input.image_key_hex).unwrap_or_default();
        let image_nonce = hex::decode(&input.image_nonce_hex).unwrap_or_default();
        let image_upload_key = hex::decode(&input.image_upload_key_hex).unwrap_or_default();
        let media_type_bytes = input.media_type.as_deref().unwrap_or("").as_bytes();
        let data = encode_component_vectors(&[
            image_hash.as_slice(),
            image_key.as_slice(),
            image_nonce.as_slice(),
            image_upload_key.as_slice(),
            media_type_bytes,
        ]);
        Self {
            component_id: GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
            component: GROUP_BLOSSOM_IMAGE_COMPONENT.to_owned(),
            present,
            image_hash_hex: input.image_hash_hex,
            image_key_hex: input.image_key_hex,
            image_nonce_hex: input.image_nonce_hex,
            image_upload_key_hex: input.image_upload_key_hex,
            media_type: input.media_type,
            data_hex: hex::encode(data),
        }
    }
}

impl AppGroupAdminPolicyComponent {
    fn new(mut admins: Vec<[u8; 32]>) -> Self {
        admins.sort();
        admins.dedup();
        let mut admin_bytes = Vec::with_capacity(admins.len() * 32);
        for admin in &admins {
            admin_bytes.extend_from_slice(admin);
        }
        let mut data = Vec::new();
        encode_quic_varint(admin_bytes.len() as u64, &mut data);
        data.extend_from_slice(&admin_bytes);
        Self {
            component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
            component: GROUP_ADMIN_POLICY_COMPONENT.to_owned(),
            admins: admins.iter().map(hex::encode).collect(),
            data_hex: hex::encode(data),
        }
    }

    fn to_app_component_data(&self) -> Result<AppComponentData, AppError> {
        Ok(AppComponentData {
            component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
            data: hex::decode(&self.data_hex)?,
        })
    }
}

impl AppGroupMessageRetentionComponent {
    fn new(disappearing_message_secs: u64) -> Self {
        Self {
            component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
            component: GROUP_MESSAGE_RETENTION_COMPONENT.to_owned(),
            disappearing_message_secs,
            data_hex: hex::encode(disappearing_message_secs.to_be_bytes()),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() != 8 {
            return Self {
                component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
                component: GROUP_MESSAGE_RETENTION_COMPONENT.to_owned(),
                disappearing_message_secs: 0,
                data_hex: hex::encode(bytes),
            };
        }
        let mut value = [0_u8; 8];
        value.copy_from_slice(bytes);
        Self::new(u64::from_be_bytes(value))
    }

    fn disabled() -> Self {
        Self::new(0)
    }

    fn to_app_component_data(&self) -> Result<AppComponentData, AppError> {
        Ok(AppComponentData {
            component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
            data: hex::decode(&self.data_hex)?,
        })
    }
}

impl AppGroupNostrRoutingComponent {
    fn new(routing: NostrRoutingV1) -> Result<Self, AppError> {
        let data = encode_nostr_routing_v1(&routing).map_err(AppError::InvalidNostrRouting)?;
        Ok(Self {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            component: NOSTR_ROUTING_COMPONENT.to_owned(),
            nostr_group_id_hex: hex::encode(routing.nostr_group_id),
            relays: routing.relays,
            data_hex: hex::encode(data),
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        let routing = decode_nostr_routing_v1(bytes).map_err(AppError::InvalidNostrRouting)?;
        Self::new(routing)
    }

    fn subscription(&self, group_id: &GroupId) -> Result<TransportGroupSubscription, AppError> {
        Ok(TransportGroupSubscription {
            group_id: group_id.clone(),
            transport_group_id: hex::decode(&self.nostr_group_id_hex)?,
            endpoints: self.relays.iter().cloned().map(TransportEndpoint).collect(),
        })
    }
}

impl AppAgentTextStreamComponent {
    fn from_bytes(bytes: &[u8]) -> Self {
        match AgentTextStreamQuicPolicyV1::decode_component_state(bytes) {
            Ok(policy) => Self::from_policy(policy, bytes.to_vec()),
            Err(_) => Self {
                component_id: AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
                component: AGENT_TEXT_STREAM_QUIC_COMPONENT.to_owned(),
                required: true,
                required_member_roles: Vec::new(),
                allowed_member_roles: Vec::new(),
                max_plaintext_frame_len: 0,
                replay_ttl_secs: 0,
                padding_bucket_bytes: 0,
                data_hex: hex::encode(bytes),
            },
        }
    }

    fn from_policy(policy: AgentTextStreamQuicPolicyV1, data: Vec<u8>) -> Self {
        Self {
            component_id: AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
            component: AGENT_TEXT_STREAM_QUIC_COMPONENT.to_owned(),
            required: true,
            required_member_roles: role_names(policy.required_member_roles),
            allowed_member_roles: role_names(policy.allowed_member_roles),
            max_plaintext_frame_len: policy.max_plaintext_frame_len,
            replay_ttl_secs: policy.replay_ttl_secs,
            padding_bucket_bytes: policy.padding_bucket_bytes,
            data_hex: hex::encode(data),
        }
    }

    fn disabled() -> Self {
        Self {
            component_id: AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
            component: AGENT_TEXT_STREAM_QUIC_COMPONENT.to_owned(),
            required: false,
            required_member_roles: Vec::new(),
            allowed_member_roles: Vec::new(),
            max_plaintext_frame_len: 0,
            replay_ttl_secs: 0,
            padding_bucket_bytes: 0,
            data_hex: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AppGroupImageInput {
    image_hash_hex: String,
    image_key_hex: String,
    image_nonce_hex: String,
    image_upload_key_hex: String,
    media_type: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Account(#[from] marmot_account::AccountError),
    #[error(transparent)]
    AccountHome(#[from] AccountHomeError),
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
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error("no published key package for account")]
    MissingKeyPackage(String),
    #[error("unknown local group")]
    UnknownGroup(String),
    #[error("no agent text stream start found for this group")]
    AgentStreamMissingStart,
    #[error("agent text stream start has no confirmed message id yet")]
    AgentStreamStartNotConfirmed,
    #[error("unsupported agent text stream route (only brokered QUIC is supported)")]
    AgentStreamUnsupportedRoute,
    #[error("agent text stream start has no usable quic:// candidate")]
    AgentStreamMissingCandidate,
    #[error("invalid quic candidate: {0}")]
    AgentStreamInvalidCandidate(String),
    #[error("publish failed: {0}")]
    Publish(String),
    #[error("default relays are required to publish account relay lists")]
    MissingDefaultRelays,
    #[error("missing account relay lists: {0:?}")]
    MissingRelayLists(Vec<String>),
    #[error("relay directory fetch failed: {0}")]
    RelayDirectory(String),
    #[error("invalid Nostr public key")]
    InvalidPublicKey,
    #[error("invalid Marmot KeyPackage event: {0}")]
    InvalidKeyPackageEvent(String),
    #[error("no directory entry for account")]
    MissingDirectoryEntry(String),
    #[error("invalid user directory search: {0}")]
    InvalidDirectorySearch(String),
    #[error("invalid group profile: {0}")]
    InvalidGroupProfile(String),
    #[error("invalid Nostr routing component: {0}")]
    InvalidNostrRouting(String),
    #[error("invalid agent text stream policy: {0}")]
    InvalidAgentTextStreamPolicy(String),
    #[error("invalid encrypted media: {0}")]
    InvalidEncryptedMedia(String),
    #[error("blob store request failed: {0}")]
    BlobStore(String),
    #[error("invalid app message payload: {0}")]
    InvalidAppMessagePayload(String),
    #[error("SQLCipher key derivation failed: {0}")]
    SqlcipherKeyDerivation(String),
    #[error("blocking app task failed: {0}")]
    BlockingTask(String),
    #[error("no matching reaction by this account to retract")]
    ReactionNotFound,
    #[error("transport event stream closed")]
    TransportClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SqlcipherDatabaseKind {
    Session,
    AccountProjection,
    DirectoryCache,
}

impl SqlcipherDatabaseKind {
    fn hkdf_info_label(self) -> &'static [u8] {
        match self {
            Self::Session => b"marmot-app/session-sqlcipher-key/v2",
            Self::AccountProjection => b"marmot-app/account-projection-sqlcipher-key/v2",
            Self::DirectoryCache => b"marmot-app/directory-cache-sqlcipher-key/v2",
        }
    }

    fn legacy_hash_label(self) -> &'static [u8] {
        match self {
            Self::Session | Self::AccountProjection => b"marmot-app-sqlcipher-key-v1",
            Self::DirectoryCache => b"marmot-app-directory-cache-sqlcipher-key-v1",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AccountState {
    label: String,
    #[serde(default)]
    seen_events: Vec<String>,
    #[serde(default)]
    last_transport_timestamp: Option<u64>,
    #[serde(default)]
    groups: Vec<AppGroupRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AppMessageProjection {
    message_id_hex: String,
    direction: String,
    group_id_hex: String,
    sender: String,
    plaintext: String,
    kind: u64,
    tags: Vec<Vec<String>>,
    recorded_at: Option<u64>,
}

#[derive(Clone)]
struct AccountProfile {
    label: String,
    account_id_hex: String,
    inbox_endpoints: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeyPackageRecord {
    account_label: String,
    account_id_hex: String,
    #[serde(default)]
    key_package_id: String,
    #[serde(default)]
    key_package_event_id: String,
    key_package_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FetchedFollowList {
    follows: Vec<String>,
    source_relays: Vec<String>,
}

struct OpenAppAccount {
    runtime: AppRuntime,
    adapter: MarmotRelayPlaneAccountAdapter,
    routing: AppTransportRouting,
    state: AccountState,
}

pub struct AppClient {
    app: MarmotApp,
    runtime: AppRuntime,
    adapter: MarmotRelayPlaneAccountAdapter,
    routing: AppTransportRouting,
    relay_plane: MarmotRelayPlane,
    state: AccountState,
}

impl MarmotApp {
    pub fn with_relay(root: impl AsRef<Path>, relay_url: impl Into<String>) -> Self {
        Self::with_relays(root, vec![relay_url.into()])
    }

    pub fn with_relay_and_config(
        root: impl AsRef<Path>,
        relay_url: impl Into<String>,
        config: MarmotAppConfig,
    ) -> Self {
        Self::with_relays_and_config(root, vec![relay_url.into()], config)
    }

    pub fn with_relays(root: impl AsRef<Path>, relay_urls: Vec<String>) -> Self {
        Self::with_relays_and_config(root, relay_urls, MarmotAppConfig::default())
    }

    pub fn with_relays_and_config(
        root: impl AsRef<Path>,
        relay_urls: Vec<String>,
        config: MarmotAppConfig,
    ) -> Self {
        let root = root.as_ref().to_path_buf();
        Self {
            account_home: AccountHome::open(&root),
            root,
            relay_urls,
            relay_plane: MarmotRelayPlane::runtime_default(APP_RUNTIME_RELAY_REBUILD_LOOKBACK),
            config,
        }
    }

    pub fn with_relays_and_account_home(
        root: impl AsRef<Path>,
        relay_urls: Vec<String>,
        account_home: AccountHome,
    ) -> Self {
        Self::with_relays_and_account_home_and_config(
            root,
            relay_urls,
            account_home,
            MarmotAppConfig::default(),
        )
    }

    pub fn with_relays_and_account_home_and_config(
        root: impl AsRef<Path>,
        relay_urls: Vec<String>,
        account_home: AccountHome,
        config: MarmotAppConfig,
    ) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            relay_urls,
            account_home,
            relay_plane: MarmotRelayPlane::runtime_default(APP_RUNTIME_RELAY_REBUILD_LOOKBACK),
            config,
        }
    }

    pub fn runtime(&self) -> MarmotAppRuntime {
        MarmotAppRuntime::new(self.clone())
    }

    pub async fn client(&self, label: &str) -> Result<AppClient, AppError> {
        self.client_with_relay_plane(label, &MarmotRelayPlane::full_history())
            .await
    }

    async fn runtime_client(
        &self,
        label: &str,
        relay_plane: &MarmotRelayPlane,
    ) -> Result<AppClient, AppError> {
        self.client_with_relay_plane(label, relay_plane).await
    }

    async fn client_with_relay_plane(
        &self,
        label: &str,
        relay_plane: &MarmotRelayPlane,
    ) -> Result<AppClient, AppError> {
        let app = self.clone();
        let label = label.to_owned();
        let relay_plane_for_open = relay_plane.clone();
        let relay_plane_for_rebuild = relay_plane.clone();
        let open = blocking_app_task(move || {
            app.ensure_account_state(&label)?;
            app.open_account(&label, &relay_plane_for_open)
        })
        .await?;
        let rebuild_since =
            relay_plane_for_rebuild.subscription_rebuild_since(open.state.last_transport_timestamp);
        open.runtime.activate_transport(rebuild_since).await?;
        open.runtime.sync_transport_groups(rebuild_since).await?;
        Ok(AppClient {
            app: self.clone(),
            runtime: open.runtime,
            adapter: open.adapter,
            routing: open.routing,
            relay_plane: relay_plane.clone(),
            state: open.state,
        })
    }

    pub fn status(&self, label: &str) -> Result<AppStatus, AppError> {
        let account = self.account_home().account(label)?;
        self.ensure_account_state(label)?;
        let state = self.load_state(label)?;
        let message_count = self.account_projection(label)?.message_count()?;
        Ok(AppStatus {
            account: state.label,
            account_id_hex: account.account_id_hex.clone(),
            transport: self.transport_label().to_owned(),
            group_count: state.groups.len(),
            message_count,
            projections: self.projection_status(label),
            groups: state.groups,
            seen_events: state.seen_events.len(),
            relay_lists: self.account_relay_list_status_for_account_id(&account.account_id_hex)?,
        })
    }

    pub async fn publish_account_relay_lists(
        &self,
        label: &str,
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<AccountRelayListStatus, AppError> {
        self.publish_selected_account_relay_lists(
            label,
            bootstrap,
            &[
                NostrAccountRelayListKind::Nip65,
                NostrAccountRelayListKind::Inbox,
                NostrAccountRelayListKind::KeyPackage,
            ],
        )
        .await
    }

    pub async fn publish_missing_account_relay_lists(
        &self,
        label: &str,
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<AccountRelayListStatus, AppError> {
        let current = self.account_relay_list_status(label)?;
        self.publish_missing_account_relay_lists_from_status(label, bootstrap, current)
            .await
    }

    pub async fn publish_missing_account_relay_lists_from_status(
        &self,
        label: &str,
        bootstrap: AccountRelayListBootstrap,
        current: AccountRelayListStatus,
    ) -> Result<AccountRelayListStatus, AppError> {
        let missing = current
            .missing
            .iter()
            .filter_map(|name| match name.as_str() {
                "nip65" => Some(NostrAccountRelayListKind::Nip65),
                "inbox" => Some(NostrAccountRelayListKind::Inbox),
                "key_package" => Some(NostrAccountRelayListKind::KeyPackage),
                _ => None,
            })
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(current);
        }
        self.publish_selected_account_relay_lists(label, bootstrap, &missing)
            .await
    }

    async fn ensure_local_account_relay_lists(
        &self,
        label: &str,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.account_home().account(label)?;
        let status = self.account_relay_list_status_for_account_id(&account.account_id_hex)?;
        if status.complete {
            return Ok(status);
        }
        let default_relays = self.relay_endpoints();
        if default_relays.is_empty() {
            return Err(AppError::MissingRelayLists(status.missing));
        }
        self.publish_missing_account_relay_lists_from_status(
            label,
            AccountRelayListBootstrap::new(default_relays.clone(), default_relays),
            status,
        )
        .await
    }

    pub async fn publish_account_relay_list_kind(
        &self,
        label: &str,
        list_kind: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let list_kind = match list_kind {
            "nip65" => NostrAccountRelayListKind::Nip65,
            "inbox" => NostrAccountRelayListKind::Inbox,
            "key_package" | "key-package" => NostrAccountRelayListKind::KeyPackage,
            other => {
                return Err(AppError::RelayDirectory(format!(
                    "unsupported relay list type: {other}"
                )));
            }
        };
        self.publish_selected_account_relay_lists(
            label,
            AccountRelayListBootstrap::new(relays, bootstrap_relays),
            &[list_kind],
        )
        .await
    }

    pub fn account_nip65_relays(&self, label: &str) -> Result<Vec<String>, AppError> {
        Ok(self.account_relay_list_status(label)?.nip65.relays)
    }

    pub fn account_inbox_relays(&self, label: &str) -> Result<Vec<String>, AppError> {
        Ok(self.account_relay_list_status(label)?.inbox.relays)
    }

    pub fn account_key_package_relays(&self, label: &str) -> Result<Vec<String>, AppError> {
        Ok(self.account_relay_list_status(label)?.key_package.relays)
    }

    pub async fn set_account_nip65_relays(
        &self,
        label: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        self.set_account_relay_list_kind(
            label,
            NostrAccountRelayListKind::Nip65,
            relays,
            bootstrap_relays,
        )
        .await
    }

    pub async fn set_account_inbox_relays(
        &self,
        label: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        self.set_account_relay_list_kind(
            label,
            NostrAccountRelayListKind::Inbox,
            relays,
            bootstrap_relays,
        )
        .await
    }

    pub async fn set_account_key_package_relays(
        &self,
        label: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        self.set_account_relay_list_kind(
            label,
            NostrAccountRelayListKind::KeyPackage,
            relays,
            bootstrap_relays,
        )
        .await
    }

    async fn set_account_relay_list_kind(
        &self,
        label: &str,
        list_kind: NostrAccountRelayListKind,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        self.publish_selected_account_relay_lists(
            label,
            AccountRelayListBootstrap::new(relays, bootstrap_relays),
            &[list_kind],
        )
        .await
    }

    async fn publish_selected_account_relay_lists(
        &self,
        label: &str,
        bootstrap: AccountRelayListBootstrap,
        list_kinds: &[NostrAccountRelayListKind],
    ) -> Result<AccountRelayListStatus, AppError> {
        if bootstrap.default_relays.is_empty() {
            return Err(AppError::MissingDefaultRelays);
        }
        let keys = self.account_home().load_signing_keys(label)?;
        let account_id = MemberId::new(keys.public_key().to_bytes().to_vec());
        let account_id_hex = keys.public_key().to_hex();
        // Outbox routing: publish relay-list events to the account's own NIP-65
        // write relays; fall back to the bootstrap/seed relays on first publish
        // (no NIP-65 yet). The declared list (content) is `default_relays`, but
        // the relays we publish *through* must be reachable — the account's own
        // relays or the seed, never the (possibly not-yet-reachable) declared set.
        let endpoints = self.outbox_endpoints(
            &account_id_hex,
            publish_endpoints_from_bootstrap(&bootstrap),
        );
        let relay_client = self.relay_client_for_endpoints(&keys, &endpoints);
        for list_kind in list_kinds {
            let publication = NostrAccountRelayListPublication {
                account_id: account_id.clone(),
                list_kind: *list_kind,
                relays: bootstrap.default_relays.clone(),
                publish_endpoints: endpoints.clone(),
            };
            let event = publication.to_event()?;
            relay_client.publish_event(&endpoints, &event, 1).await?;
        }
        self.fetch_account_relay_list_status_for_account_id(&account_id_hex, endpoints)
            .await
    }

    pub async fn fetch_account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| AppError::InvalidPublicKey)?;
        let account_id_hex = public_key.to_hex();
        let bootstrap_relays = self.directory_source_relays(&bootstrap_relays);
        let freshness = self.directory_freshness();
        let records = self
            .relay_plane
            .fetch_directory_events(
                bootstrap_relays.clone(),
                relay_list_queries(account_id_hex.clone()),
            )
            .await
            .map_err(|e| AppError::RelayDirectory(format!("fetch relay lists: {e}")))?;
        let selection = fresh_relay_list_status_from_records(&account_id_hex, records, freshness);
        let mut status = selection.value;
        if selection.rejected_future {
            let cached = self.account_relay_list_status_for_account_id(&account_id_hex)?;
            if relay_lists_have_any_relays(&cached) {
                if !relay_lists_have_any_relays(&status) {
                    return Ok(cached);
                }
                fill_missing_relay_lists_from_cached(&mut status, &cached);
            }
        }
        if status.bootstrap_relays.is_empty() {
            status.bootstrap_relays = bootstrap_relays
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect();
        }
        self.remember_directory_relay_lists(&account_id_hex, &status)?;
        Ok(status)
    }

    pub async fn fetch_latest_key_package_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<FetchedKeyPackage, AppError> {
        let has_explicit_bootstrap_relays = !bootstrap_relays.is_empty();
        let mut relay_lists = if has_explicit_bootstrap_relays {
            self.fetch_account_relay_list_status_for_account_id(account_id_hex, bootstrap_relays)
                .await?
        } else {
            self.account_relay_list_status_for_account_id(account_id_hex)?
        };
        if !has_explicit_bootstrap_relays && relay_lists.key_package.relays.is_empty() {
            let source_relays = self.directory_source_relays(&[]);
            if !source_relays.is_empty() {
                relay_lists = self
                    .fetch_account_relay_list_status_for_account_id(account_id_hex, source_relays)
                    .await?;
            }
        }
        self.remember_directory_relay_lists(account_id_hex, &relay_lists)?;
        if relay_lists.key_package.relays.is_empty() {
            return Err(AppError::MissingRelayLists(vec!["key_package".into()]));
        }

        let source_relays = relay_lists
            .key_package
            .relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        let records = self
            .fetch_key_package_events_for_account_id(account_id_hex, &source_relays)
            .await?;
        let cached_entry = self.directory_entry_for_account_id(account_id_hex)?;
        let mut fetched = fresh_or_cached_key_package(
            account_id_hex,
            latest_fresh_key_package_from_records(
                account_id_hex,
                records,
                self.directory_freshness(),
            )?,
            cached_entry,
        )?;
        fetched.relay_lists = relay_lists;
        self.remember_directory_key_package(&fetched)?;
        Ok(fetched)
    }

    pub async fn refresh_directory_entry_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<UserDirectoryRecord, AppError> {
        let status = if bootstrap_relays.is_empty() {
            self.account_relay_list_status_for_account_id(account_id_hex)?
        } else {
            self.fetch_account_relay_list_status_for_account_id(account_id_hex, bootstrap_relays)
                .await?
        };
        self.remember_directory_relay_lists(account_id_hex, &status)?;
        self.directory_entry_for_account_id(account_id_hex)?
            .ok_or_else(|| AppError::MissingDirectoryEntry(account_id_hex.to_owned()))
    }

    pub fn directory_entry_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        let caches = self.directory_caches()?;
        Self::directory_entry_from_caches(&caches, &account_id_hex)
    }

    pub async fn refresh_user_directory_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<UserDirectoryRefresh, AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        self.remember_directory_user(&account_id_hex)?;
        let follow_list = self
            .fetch_follow_list_for_account_id(&account_id_hex, &bootstrap_relays)
            .await?;
        self.remember_directory_follow_list(&account_id_hex, &follow_list)?;

        let profile_count = self
            .refresh_directory_profiles(&follow_list.follows, &bootstrap_relays)
            .await?;

        Ok(UserDirectoryRefresh {
            account_id_hex,
            follow_count: follow_list.follows.len(),
            profile_count,
        })
    }

    /// Outbox routing for account-scoped events. Prefers the account's own
    /// declared NIP-65 write relays (read from the local relay-list cache, no
    /// network), so e.g. republishing your relay lists / profile goes to *your*
    /// relays rather than whatever defaults the caller passed. Falls back to
    /// `fallback` only when the account has no NIP-65 list yet (cold start).
    fn outbox_endpoints(
        &self,
        account_id_hex: &str,
        fallback: Vec<TransportEndpoint>,
    ) -> Vec<TransportEndpoint> {
        let nip65 = self
            .account_relay_list_status_for_account_id(account_id_hex)
            .map(|status| status.nip65.relays)
            .unwrap_or_default();
        if nip65.is_empty() {
            fallback
        } else {
            nip65.into_iter().map(TransportEndpoint).collect()
        }
    }

    pub async fn publish_user_profile(
        &self,
        label: &str,
        profile: UserProfileMetadata,
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<(), AppError> {
        let keys = self.account_home().load_signing_keys(label)?;
        let endpoints = self.outbox_endpoints(
            &keys.public_key().to_hex(),
            publish_endpoints_from_bootstrap(&bootstrap),
        );
        let content = serde_json::to_string(&profile_content_json(&profile))?;
        let event = NostrTransportEvent::new_unsigned(
            keys.public_key().to_hex(),
            KIND_NOSTR_METADATA,
            Vec::new(),
            content,
        );
        self.relay_client_for_endpoints(&keys, &endpoints)
            .publish_event(&endpoints, &event, 1)
            .await?;
        Ok(())
    }

    pub async fn publish_account_follow_list(
        &self,
        label: &str,
        follows: &[&str],
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<(), AppError> {
        let keys = self.account_home().load_signing_keys(label)?;
        let endpoints = self.outbox_endpoints(
            &keys.public_key().to_hex(),
            publish_endpoints_from_bootstrap(&bootstrap),
        );
        let tags = follows
            .iter()
            .map(|follow| {
                parse_account_id_hex(follow).map(|account_id| vec!["p".to_owned(), account_id])
            })
            .collect::<Result<Vec<_>, _>>()?;
        let event = NostrTransportEvent::new_unsigned(
            keys.public_key().to_hex(),
            KIND_NOSTR_CONTACT_LIST,
            tags,
            String::new(),
        );
        self.relay_client_for_endpoints(&keys, &endpoints)
            .publish_event(&endpoints, &event, 1)
            .await?;
        Ok(())
    }

    pub fn search_user_directory(
        &self,
        search: UserDirectorySearch,
    ) -> Result<Vec<UserDirectorySearchResult>, AppError> {
        search.validate()?;
        let records =
            self.directory_search_records(&search.searcher_account_id_hex, search.radius_end)?;
        let query = search.query.trim().to_lowercase();
        if query.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        for (record, radius) in records {
            if radius < search.radius_start || radius > search.radius_end {
                continue;
            }
            let Some(search_match) = user_record_match(&record, &query) else {
                continue;
            };
            results.push(UserDirectorySearchResult {
                account_id_hex: record.account_id_hex.clone(),
                npub: record.npub.clone(),
                radius,
                matched_field: search_match.field,
                match_quality: search_match.quality,
                profile: record.profile.clone(),
            });
        }
        results.sort_by(|a, b| {
            a.radius
                .cmp(&b.radius)
                .then_with(|| {
                    match_quality_rank(&a.match_quality).cmp(&match_quality_rank(&b.match_quality))
                })
                .then_with(|| field_rank(&a.matched_field).cmp(&field_rank(&b.matched_field)))
                .then_with(|| a.account_id_hex.cmp(&b.account_id_hex))
        });
        if let Some(limit) = search.limit {
            results.truncate(limit);
        }
        Ok(results)
    }

    pub fn messages(&self, label: &str) -> Result<Vec<AppMessageRecord>, AppError> {
        self.messages_with_query(label, AppMessageQuery::default())
    }

    pub fn messages_with_query(
        &self,
        label: &str,
        query: AppMessageQuery,
    ) -> Result<Vec<AppMessageRecord>, AppError> {
        self.ensure_account_state(label)?;
        self.account_projection(label)?.messages(query)
    }

    pub fn groups(&self, label: &str) -> Result<Vec<AppGroupRecord>, AppError> {
        self.ensure_account_state(label)?;
        Ok(self.load_state(label)?.groups)
    }

    pub fn visible_groups(&self, label: &str) -> Result<Vec<AppGroupRecord>, AppError> {
        Ok(self
            .groups(label)?
            .into_iter()
            .filter(|group| !group.archived)
            .collect())
    }

    pub fn group(
        &self,
        label: &str,
        group_id_hex: &str,
    ) -> Result<Option<AppGroupRecord>, AppError> {
        Ok(self
            .groups(label)?
            .into_iter()
            .find(|group| group.group_id_hex == group_id_hex))
    }

    pub fn set_group_archived(
        &self,
        label: &str,
        group_id_hex: &str,
        archived: bool,
    ) -> Result<AppGroupRecord, AppError> {
        self.ensure_account_state(label)?;
        let mut state = self.load_state(label)?;
        let group = state
            .groups
            .iter_mut()
            .find(|group| group.group_id_hex == group_id_hex)
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.to_owned()))?;
        group.archived = archived;
        let group = group.clone();
        self.save_state(&state)?;
        Ok(group)
    }

    pub fn account_relay_list_status(
        &self,
        label: &str,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.account_home().account(label)?;
        self.account_relay_list_status_for_account_id(&account.account_id_hex)
    }

    pub fn account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> Result<AccountRelayListStatus, AppError> {
        Ok(self
            .directory_entry_for_account_id(account_id_hex)?
            .map(|entry| entry.relay_lists)
            .unwrap_or_else(AccountRelayListStatus::empty))
    }

    async fn fetch_key_package_events_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: &[TransportEndpoint],
    ) -> Result<Vec<RelayEventRecord>, AppError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| AppError::InvalidPublicKey)?;
        let source_relays = self.directory_source_relays(source_relays);
        self.relay_plane
            .fetch_directory_events(
                source_relays,
                vec![DirectoryEventQuery::new(
                    KIND_MARMOT_KEY_PACKAGE,
                    vec![public_key.to_hex()],
                    12,
                )],
            )
            .await
            .map_err(|e| AppError::RelayDirectory(format!("fetch key packages: {e}")))
    }

    async fn fetch_follow_list_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: &[TransportEndpoint],
    ) -> Result<FetchedFollowList, AppError> {
        let records = self
            .fetch_events_for_account_ids(
                &[account_id_hex.to_owned()],
                KIND_NOSTR_CONTACT_LIST,
                source_relays,
            )
            .await?;
        let selection =
            latest_follow_list_from_records(account_id_hex, records, self.directory_freshness());
        if let Some(follow_list) = selection.value {
            return Ok(follow_list);
        }
        if selection.rejected_future
            && let Some(entry) = self.directory_entry_for_account_id(account_id_hex)?
        {
            return Ok(FetchedFollowList {
                follows: entry.follows,
                source_relays: entry.follow_source_relays,
            });
        }
        Ok(FetchedFollowList {
            follows: Vec::new(),
            source_relays: source_relays
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect(),
        })
    }

    async fn refresh_directory_profiles(
        &self,
        account_ids: &[String],
        source_relays: &[TransportEndpoint],
    ) -> Result<usize, AppError> {
        if account_ids.is_empty() {
            return Ok(0);
        }
        let records = self
            .fetch_events_for_account_ids(account_ids, KIND_NOSTR_METADATA, source_relays)
            .await?;
        let profiles =
            latest_fresh_profiles_from_records(records, self.directory_freshness()).value;
        for account_id in account_ids {
            self.remember_directory_user(account_id)?;
        }
        for (account_id, profile) in &profiles {
            self.remember_directory_profile(account_id, profile)?;
        }
        Ok(profiles.len())
    }

    /// Fetch and cache a single account's own Nostr kind:0 profile from
    /// relays. Unlike `refresh_user_directory_for_account_id` (which refreshes
    /// the account's *follows'* profiles), this targets the account itself, so
    /// its display name / avatar become locally available right away.
    pub async fn refresh_profile_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: Vec<TransportEndpoint>,
    ) -> Result<(), AppError> {
        self.refresh_directory_profiles(&[account_id_hex.to_owned()], &source_relays)
            .await?;
        Ok(())
    }

    async fn fetch_events_for_account_ids(
        &self,
        account_ids: &[String],
        kind: u64,
        source_relays: &[TransportEndpoint],
    ) -> Result<Vec<RelayEventRecord>, AppError> {
        let source_relays = self.directory_source_relays(source_relays);
        let account_ids = account_ids
            .iter()
            .map(|account_id| parse_account_id_hex(account_id))
            .collect::<Result<Vec<_>, _>>()?;
        let limit = (account_ids.len() * 4).max(1);
        self.relay_plane
            .fetch_directory_events(
                source_relays,
                vec![DirectoryEventQuery::new(kind, account_ids, limit)],
            )
            .await
            .map_err(|e| AppError::RelayDirectory(format!("fetch user directory events: {e}")))
    }

    fn directory_freshness(&self) -> DirectoryFreshness {
        DirectoryFreshness::from_now(self.config.directory_max_future_skew)
    }

    fn directory_source_relays(
        &self,
        source_relays: &[TransportEndpoint],
    ) -> Vec<TransportEndpoint> {
        if !source_relays.is_empty() {
            return source_relays.to_vec();
        }
        self.relay_endpoints()
    }

    fn open_account(
        &self,
        label: &str,
        relay_plane: &MarmotRelayPlane,
    ) -> Result<OpenAppAccount, AppError> {
        let state = self.load_state(label)?;
        let keys = self.account_home().load_signing_keys(label)?;
        let account_id = MemberId::new(keys.public_key().to_bytes());
        let peeler = NostrMlsPeeler::new().with_welcome_signer(keys.clone());
        let session_path = self.account_dir(label).join(SESSION_DB_FILE);
        let session_key =
            self.sqlcipher_key(label, &keys, &session_path, SqlcipherDatabaseKind::Session)?;
        let session = AccountDeviceSession::open(
            SessionConfig::new(
                session_path,
                session_key,
                account_id.as_slice().to_vec(),
                Box::new(peeler),
            )
            .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
                keys: keys.clone(),
            }))
            .feature_registry(app_feature_registry())
            .supported_app_components(self.supported_app_component_ids())
            .convergence_policy(CanonicalizationPolicy {
                settlement_quiescence_ms: 0,
                ..CanonicalizationPolicy::default()
            }),
        )?;

        let publish_client = self.relay_client_for_endpoints(&keys, &self.relay_endpoints());
        let adapter = relay_plane.account_adapter(account_id.clone(), publish_client);

        let key_packages = AppKeyPackagePublisher {
            app: self.clone(),
            account_label: label.to_owned(),
            keys: keys.clone(),
            app_components: self.supported_app_component_tags(),
        };
        let routing = self.routing_for(&state)?;
        let runtime =
            AccountDeviceRuntime::new(session, adapter.clone(), routing.clone(), key_packages);
        Ok(OpenAppAccount {
            runtime,
            adapter,
            routing,
            state,
        })
    }

    fn routing_for(&self, state: &AccountState) -> Result<AppTransportRouting, AppError> {
        let mut inbox_routes = HashMap::new();
        for profile in self.profiles()? {
            inbox_routes.insert(
                MemberId::new(hex::decode(profile.account_id_hex)?),
                profile
                    .inbox_endpoints
                    .into_iter()
                    .map(TransportEndpoint)
                    .collect(),
            );
        }
        for entry in self.directory_entries()? {
            if entry.relay_lists.inbox.relays.is_empty() {
                continue;
            }
            inbox_routes
                .entry(MemberId::new(hex::decode(entry.account_id_hex)?))
                .or_insert_with(|| {
                    entry
                        .relay_lists
                        .inbox
                        .relays
                        .into_iter()
                        .map(TransportEndpoint)
                        .collect()
                });
        }

        let account = self.account_home().account(&state.label)?;
        let relay_lists = self.account_relay_list_status_for_account_id(&account.account_id_hex)?;
        let mut group_routes = Vec::new();
        for group in &state.groups {
            let group_id = GroupId::new(hex::decode(&group.group_id_hex)?);
            group_routes.push(group.nostr_routing.subscription(&group_id)?);
        }

        Ok(AppTransportRouting::new(AppRoutingState {
            local_inbox_endpoints: self.account_inbox_endpoints(&state.label, &relay_lists),
            key_package_endpoints: self.key_package_endpoints(&relay_lists),
            inbox_routes,
            group_routes,
            required_acks: 1,
        }))
    }

    fn latest_key_package(&self, label: &str) -> Result<KeyPackage, AppError> {
        let path = self
            .key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.json"));
        if !path.exists() {
            return Err(AppError::MissingKeyPackage(label.to_owned()));
        }
        let record: KeyPackageRecord = read_json(path)?;
        key_package_from_hex_with_optional_source(
            &record.key_package_hex,
            &record.key_package_event_id,
        )
    }

    async fn publish_cached_key_package(
        &self,
        label: &str,
        key_package: KeyPackage,
    ) -> Result<KeyPackage, AppError> {
        let keys = self.account_home().load_signing_keys(label)?;
        let account_id_hex = keys.public_key().to_hex();
        let relay_lists = self.account_relay_list_status_for_account_id(&account_id_hex)?;
        if relay_lists.key_package.relays.is_empty() {
            return Err(AppError::MissingRelayLists(vec!["key_package".into()]));
        }
        let publisher = AppKeyPackagePublisher {
            app: self.clone(),
            account_label: label.to_owned(),
            keys: keys.clone(),
            app_components: self.supported_app_component_tags(),
        };
        publisher
            .publish_key_package(KeyPackagePublication {
                account_id: MemberId::new(keys.public_key().to_bytes().to_vec()),
                key_package: key_package.clone(),
                endpoints: self.key_package_endpoints(&relay_lists),
            })
            .await
            .map_err(|err| AppError::Publish(err.to_string()))?;
        Ok(key_package)
    }

    async fn member_key_package(&self, member_ref: &str) -> Result<KeyPackage, AppError> {
        // Local accounts: cache files are keyed by the account's canonical
        // label, so resolve the ref (which may be an npub or hex pubkey)
        // before looking up the cached key package. Using the raw ref here
        // would miss the file when inviting a local account by npub.
        if let Ok(account) = self.account_home().account(member_ref) {
            return self.latest_key_package(&account.label);
        }
        let account_id = PublicKey::parse(member_ref)
            .map_err(|_| AppError::MissingKeyPackage(member_ref.to_owned()))?
            .to_hex();
        if let Some(entry) = self.directory_entry_for_account_id(&account_id)? {
            if let Some(key_package) = entry.key_package {
                return validated_cached_key_package(&account_id, &key_package);
            }
            if !entry.relay_lists.key_package.relays.is_empty() {
                let source_relays = entry
                    .relay_lists
                    .key_package
                    .relays
                    .iter()
                    .cloned()
                    .map(TransportEndpoint)
                    .collect::<Vec<_>>();
                let records = self
                    .fetch_key_package_events_for_account_id(&account_id, &source_relays)
                    .await?;
                let mut fetched = fresh_or_cached_key_package(
                    &account_id,
                    latest_fresh_key_package_from_records(
                        &account_id,
                        records,
                        self.directory_freshness(),
                    )?,
                    Some(entry.clone()),
                )?;
                fetched.relay_lists = entry.relay_lists;
                self.remember_directory_key_package(&fetched)?;
                return Ok(fetched.key_package);
            }
        }

        let fetched = self
            .fetch_latest_key_package_for_account_id(&account_id, Vec::new())
            .await?;
        Ok(fetched.key_package)
    }

    fn member_id(&self, member_ref: &str) -> Result<MemberId, AppError> {
        if let Ok(account) = self.account_home().account(member_ref) {
            return Ok(MemberId::new(hex::decode(account.account_id_hex)?));
        }
        let account_id = PublicKey::parse(member_ref)
            .map_err(|_| AppError::InvalidPublicKey)?
            .to_hex();
        Ok(MemberId::new(hex::decode(account_id)?))
    }

    fn profiles(&self) -> Result<Vec<AccountProfile>, AppError> {
        self.account_home()
            .accounts()?
            .into_iter()
            .map(|account| Ok(self.profile_for_account(account)))
            .collect()
    }

    fn directory_entries(&self) -> Result<Vec<UserDirectoryRecord>, AppError> {
        let mut entries_by_id = BTreeMap::new();
        for cache in self.directory_caches()? {
            for entry in cache.entries()? {
                entries_by_id
                    .entry(entry.account_id_hex.clone())
                    .or_insert(entry);
            }
        }
        Ok(entries_by_id.into_values().collect())
    }

    fn directory_search_records(
        &self,
        searcher_account_id_hex: &str,
        radius_end: u8,
    ) -> Result<Vec<(UserDirectoryRecord, u8)>, AppError> {
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let mut frontier = vec![parse_account_id_hex(searcher_account_id_hex)?];
        let caches = self.directory_caches()?;

        for radius in 0..=radius_end {
            let mut next = Vec::new();
            frontier.sort();
            frontier.dedup();

            for account_id in frontier {
                if seen.len() >= USER_DIRECTORY_SEARCH_MAX_VISITED {
                    return Ok(records);
                }
                if !seen.insert(account_id.clone()) {
                    continue;
                }

                let Some(record) = Self::directory_entry_from_caches(&caches, &account_id)? else {
                    continue;
                };
                if radius < radius_end {
                    for follow in &record.follows {
                        if next.len() >= USER_DIRECTORY_SEARCH_MAX_FRONTIER {
                            break;
                        }
                        if !seen.contains(follow) {
                            next.push(follow.clone());
                        }
                    }
                }
                records.push((record, radius));
            }

            frontier = next;
        }

        Ok(records)
    }

    fn directory_entry_from_caches(
        caches: &[DirectoryCache],
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        for cache in caches {
            if let Some(entry) = cache.entry(account_id_hex)? {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    fn profiles_by_id(&self) -> Result<HashMap<String, String>, AppError> {
        Ok(self
            .profiles()?
            .into_iter()
            .map(|profile| (profile.account_id_hex, profile.label))
            .collect())
    }

    fn display_names_by_id(&self) -> Result<HashMap<String, String>, AppError> {
        let mut names = self.profiles_by_id()?;
        for entry in self.directory_entries()? {
            let Some(name) = display_name_for_profile(entry.profile.as_ref()) else {
                continue;
            };
            names.insert(entry.account_id_hex, name);
        }
        Ok(names)
    }

    fn display_name_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<String>, AppError> {
        if let Some(entry) = self.directory_entry_for_account_id(account_id_hex)?
            && let Some(name) = display_name_for_profile(entry.profile.as_ref())
        {
            return Ok(Some(name));
        }
        Ok(self
            .account_home()
            .accounts()?
            .into_iter()
            .find(|account| account.account_id_hex == account_id_hex)
            .map(|account| account.label))
    }

    fn load_state(&self, label: &str) -> Result<AccountState, AppError> {
        self.ensure_account_state(label)?;
        self.account_projection(label)?.load_state(label)
    }

    fn save_state(&self, state: &AccountState) -> Result<(), AppError> {
        let mut projection = self.account_projection(&state.label)?;
        projection.save_state(state)
    }

    fn ensure_account_state(&self, label: &str) -> Result<(), AppError> {
        self.account_home().account(label)?;
        self.account_projection(label)?.ensure_account(label)?;
        Ok(())
    }

    fn profile_for_account(&self, account: AccountSummary) -> AccountProfile {
        let relay_lists = self
            .account_relay_list_status_for_account_id(&account.account_id_hex)
            .unwrap_or_else(|_| AccountRelayListStatus::empty());
        let label = self
            .directory_entry_for_account_id(&account.account_id_hex)
            .ok()
            .flatten()
            .and_then(|entry| display_name_for_profile(entry.profile.as_ref()))
            .unwrap_or(account.label.clone());
        AccountProfile {
            inbox_endpoints: self
                .account_inbox_endpoints(&account.label, &relay_lists)
                .into_iter()
                .map(|endpoint| endpoint.0)
                .collect(),
            label,
            account_id_hex: account.account_id_hex,
        }
    }

    fn sqlcipher_key(
        &self,
        label: &str,
        keys: &nostr::Keys,
        db_path: &Path,
        kind: SqlcipherDatabaseKind,
    ) -> Result<SqlCipherKey, AppError> {
        let salt = self.sqlcipher_salt(label, keys, db_path, kind)?;
        Ok(SqlCipherKey::new(derive_sqlcipher_key_material(
            label, keys, &salt, kind,
        )?)?)
    }

    fn sqlcipher_salt(
        &self,
        label: &str,
        keys: &nostr::Keys,
        db_path: &Path,
        kind: SqlcipherDatabaseKind,
    ) -> Result<[u8; SQLCIPHER_SALT_LEN], AppError> {
        let salt_path = sqlcipher_salt_path(db_path);
        if salt_path.exists() {
            return read_sqlcipher_salt(&salt_path);
        }

        let mut salt = [0_u8; SQLCIPHER_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        write_sqlcipher_salt(&salt_path, &salt)?;

        if db_path.exists() {
            let legacy_key = SqlCipherKey::new(legacy_sqlcipher_key_material(label, keys, kind))?;
            let new_key =
                SqlCipherKey::new(derive_sqlcipher_key_material(label, keys, &salt, kind)?)?;
            if let Err(err) = rekey_legacy_sqlcipher_database(db_path, &legacy_key, &new_key) {
                let _ = fs::remove_file(&salt_path);
                return Err(err);
            }
        }

        Ok(salt)
    }

    fn account_inbox_endpoints(
        &self,
        label: &str,
        relay_lists: &AccountRelayListStatus,
    ) -> Vec<TransportEndpoint> {
        if !relay_lists.inbox.relays.is_empty() {
            return relay_lists
                .inbox
                .relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect();
        }
        let _ = label;
        self.relay_endpoints()
    }

    fn key_package_endpoints(
        &self,
        relay_lists: &AccountRelayListStatus,
    ) -> Vec<TransportEndpoint> {
        if !relay_lists.key_package.relays.is_empty() {
            return relay_lists
                .key_package
                .relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect();
        }
        self.relay_endpoints()
    }

    fn transport_label(&self) -> &'static str {
        "relay"
    }

    fn account_dir(&self, label: &str) -> PathBuf {
        self.account_home().account_dir(label)
    }

    fn account_projection_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(ACCOUNT_APP_DB_FILE)
    }

    fn account_projection(&self, label: &str) -> Result<AccountProjectionDb, AppError> {
        let keys = self.account_home().load_signing_keys(label)?;
        let path = self.account_projection_path(label);
        let key = self.sqlcipher_key(
            label,
            &keys,
            &path,
            SqlcipherDatabaseKind::AccountProjection,
        )?;
        AccountProjectionDb::open(path, &key)
    }

    fn projection_status(&self, label: &str) -> AppProjectionStatus {
        let account_path = self.account_projection_path(label);
        let shared_path = self.directory_cache_path(label);
        AppProjectionStatus {
            account: AppDatabaseStatus {
                path: account_path.display().to_string(),
                exists: account_path.exists(),
                encrypted: sqlite_file_requires_key(&account_path),
            },
            shared: AppDatabaseStatus {
                path: shared_path.display().to_string(),
                exists: shared_path.exists(),
                encrypted: sqlite_file_requires_key(&shared_path),
            },
        }
    }

    fn relay_endpoints(&self) -> Vec<TransportEndpoint> {
        self.relay_urls
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect()
    }

    fn key_package_cache_dir(&self) -> PathBuf {
        self.root.clone()
    }

    fn remember_directory_relay_lists(
        &self,
        account_id_hex: &str,
        relay_lists: &AccountRelayListStatus,
    ) -> Result<(), AppError> {
        let mut entry = self
            .directory_entry_for_account_id(account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(account_id_hex));
        entry.account_id_hex = account_id_hex.to_owned();
        entry.relay_lists = relay_lists.clone();
        self.save_directory_entry(&entry)
    }

    fn remember_directory_key_package(&self, fetched: &FetchedKeyPackage) -> Result<(), AppError> {
        let mut entry = self
            .directory_entry_for_account_id(&fetched.account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(&fetched.account_id_hex));
        entry.account_id_hex = fetched.account_id_hex.clone();
        entry.relay_lists = fetched.relay_lists.clone();
        entry.key_package = Some(DirectoryKeyPackage {
            key_package_id: fetched.key_package_id.clone(),
            key_package_event_id: fetched.key_package_event_id.clone(),
            key_package_hex: hex::encode(fetched.key_package.bytes()),
            created_at: fetched.created_at,
            source_relays: fetched.source_relays.clone(),
        });
        self.save_directory_entry(&entry)
    }

    fn remember_directory_user(&self, account_id_hex: &str) -> Result<(), AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        let entry = self
            .directory_entry_for_account_id(&account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(&account_id_hex));
        self.save_directory_entry(&entry)
    }

    fn remember_directory_follow_list(
        &self,
        account_id_hex: &str,
        follow_list: &FetchedFollowList,
    ) -> Result<(), AppError> {
        let mut entry = self
            .directory_entry_for_account_id(account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(account_id_hex));
        entry.follows = follow_list.follows.clone();
        entry.follow_source_relays = follow_list.source_relays.clone();
        self.save_directory_entry(&entry)?;
        for follow in &follow_list.follows {
            self.remember_directory_user(follow)?;
        }
        Ok(())
    }

    fn remember_directory_profile(
        &self,
        account_id_hex: &str,
        profile: &UserProfileMetadata,
    ) -> Result<(), AppError> {
        let mut entry = self
            .directory_entry_for_account_id(account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(account_id_hex));
        entry.profile = Some(profile.clone());
        self.save_directory_entry(&entry)
    }

    fn save_directory_entry(&self, entry: &UserDirectoryRecord) -> Result<(), AppError> {
        let entry = self.hydrate_directory_record(entry.clone())?;
        for cache in self.directory_caches()? {
            cache.put(&entry)?;
        }
        Ok(())
    }

    fn directory_cache_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(APP_CACHE_DB_FILE)
    }

    fn legacy_directory_cache_path(&self) -> PathBuf {
        self.root.join(APP_CACHE_DB_FILE)
    }

    fn directory_cache_for_account(
        &self,
        account: &AccountSummary,
    ) -> Result<DirectoryCache, AppError> {
        self.clean_future_dated_directory_caches_for_all_accounts_once()?;
        let keys = self.account_home().load_signing_keys(&account.label)?;
        let path = self.directory_cache_path(&account.label);
        let key = self.sqlcipher_key(
            &account.label,
            &keys,
            &path,
            SqlcipherDatabaseKind::DirectoryCache,
        )?;
        DirectoryCache::open(path, &key)
    }

    fn directory_caches(&self) -> Result<Vec<DirectoryCache>, AppError> {
        let accounts = self
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.local_signing)
            .collect::<Vec<_>>();
        self.clean_future_dated_directory_caches_once(&accounts)?;
        let legacy_path = self.legacy_directory_cache_path();
        let legacy_entries = DirectoryCache::open_legacy_plaintext(legacy_path.clone())?
            .map(|cache| cache.entries())
            .transpose()?;

        let mut caches = Vec::with_capacity(accounts.len());
        for account in accounts {
            let cache = self.directory_cache_for_account(&account)?;
            if let Some(entries) = &legacy_entries {
                for entry in entries {
                    cache.put(&self.hydrate_directory_record(entry.clone())?)?;
                }
            }
            caches.push(cache);
        }

        if legacy_entries.is_some() {
            remove_sqlite_file_set(&legacy_path)?;
        }

        Ok(caches)
    }

    fn clean_future_dated_directory_caches_once(
        &self,
        accounts: &[AccountSummary],
    ) -> Result<(), AppError> {
        let marker_path = self.root.join(DIRECTORY_FUTURE_CREATED_AT_CLEANUP_MARKER);
        if marker_path.exists() {
            return Ok(());
        }
        fs::create_dir_all(&self.root)?;
        remove_sqlite_file_set(&self.legacy_directory_cache_path())?;
        for account in accounts {
            remove_sqlite_file_set(&self.directory_cache_path(&account.label))?;
        }
        fs::write(marker_path, b"done\n")?;
        Ok(())
    }

    fn clean_future_dated_directory_caches_for_all_accounts_once(&self) -> Result<(), AppError> {
        let accounts = self
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.local_signing)
            .collect::<Vec<_>>();
        self.clean_future_dated_directory_caches_once(&accounts)
    }

    fn empty_directory_record(&self, account_id_hex: &str) -> UserDirectoryRecord {
        UserDirectoryRecord {
            account_id_hex: account_id_hex.to_owned(),
            npub: npub_for_account_id_lossy(account_id_hex),
            local_account: self.local_account_for_id(account_id_hex),
            profile: None,
            follows: Vec::new(),
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        }
    }

    fn hydrate_directory_record(
        &self,
        mut entry: UserDirectoryRecord,
    ) -> Result<UserDirectoryRecord, AppError> {
        entry.account_id_hex = parse_account_id_hex(&entry.account_id_hex)?;
        entry.npub = npub_for_account_id(&entry.account_id_hex)?;
        entry.local_account = self.local_account_for_id(&entry.account_id_hex);
        entry.follows = normalize_account_ids(entry.follows)?;
        entry.follow_source_relays.sort();
        entry.follow_source_relays.dedup();
        Ok(entry)
    }

    fn local_account_for_id(&self, account_id_hex: &str) -> Option<UserDirectoryLocalAccount> {
        self.account_home()
            .accounts()
            .ok()?
            .into_iter()
            .find(|account| account.account_id_hex == account_id_hex)
            .map(|account| UserDirectoryLocalAccount {
                label: account.label,
                local_signing: account.local_signing,
            })
    }

    fn relay_client_for_endpoints(
        &self,
        keys: &nostr::Keys,
        endpoints: &[TransportEndpoint],
    ) -> Arc<dyn NostrRelayClient> {
        let _ = endpoints;
        let client = NostrSdkClient::builder().signer(keys.clone()).build();
        Arc::new(NostrSdkRelayClient::new(client))
    }

    fn account_home(&self) -> AccountHome {
        self.account_home.clone()
    }

    fn supported_app_component_ids(&self) -> Vec<u16> {
        let mut components = default_group_components();
        components.insert(NOSTR_ROUTING_COMPONENT_ID);
        components.insert(AGENT_TEXT_STREAM_QUIC_COMPONENT_ID);
        components.into_iter().collect()
    }

    fn supported_app_component_tags(&self) -> Vec<String> {
        self.supported_app_component_ids()
            .into_iter()
            .map(|id| format!("0x{id:04x}"))
            .collect()
    }

    fn new_nostr_routing(&self) -> Result<NostrRoutingV1, AppError> {
        let mut nostr_group_id = [0_u8; 32];
        OsRng.fill_bytes(&mut nostr_group_id);
        let relays = self.relay_urls.clone();
        NostrRoutingV1::new(nostr_group_id, relays).map_err(AppError::InvalidNostrRouting)
    }
}

fn spawn_app_runtime_account_worker(
    runtime: AccountWorkerRuntime,
    commands: mpsc::Receiver<AccountWorkerCommand>,
    ready: oneshot::Sender<Result<(), String>>,
    shutdown: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let worker_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("account worker runtime");
        worker_runtime.block_on(run_app_runtime_account_worker(
            runtime, commands, ready, shutdown,
        ));
    })
}

async fn run_app_runtime_account_worker(
    runtime: AccountWorkerRuntime,
    mut commands: mpsc::Receiver<AccountWorkerCommand>,
    ready: oneshot::Sender<Result<(), String>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let AccountWorkerRuntime {
        app,
        account_label,
        account_id_hex,
        relay_plane,
        events,
    } = runtime;
    let mut client = match app.runtime_client(&account_label, &relay_plane).await {
        Ok(client) => client,
        Err(err) => {
            let message = format!("runtime startup failed: {err}");
            publish_app_runtime_account_error(
                &events,
                &account_id_hex,
                &account_label,
                message.clone(),
            );
            let _ = ready.send(Err(message));
            return;
        }
    };

    match client.sync().await {
        Ok(summary) => {
            publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
        }
        Err(err) => {
            publish_app_runtime_account_error(
                &events,
                &account_id_hex,
                &account_label,
                format!("runtime startup receive failed: {err}"),
            );
        }
    }
    let _ = ready.send(Ok(()));
    let mut reconnect_backoff = AccountWorkerReconnectBackoff::default();

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                return;
            }
            command = commands.recv() => {
                match command {
                    Some(AccountWorkerCommand::CatchUp { respond }) => {
                        let result = match client.sync().await {
                            Ok(summary) => {
                                publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
                                Ok(())
                            }
                            Err(err) => {
                                let message = format!("runtime catch-up failed: {err}");
                                publish_app_runtime_account_error(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    message.clone(),
                                );
                                Err(message)
                            }
                        };
                        let _ = respond.send(result);
                    }
                        Some(AccountWorkerCommand::CreateGroup {
                            name,
                            members,
                            description,
                            respond,
                        }) => {
                            let result = async {
                                let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
                                let group_id = client.create_group(&name, &member_refs).await?;
                                if description.is_some() {
                                    client
                                        .update_group_profile(&group_id, None, description.as_deref())
                                        .await?;
                                }
                                Ok(group_id)
                            }
                            .await;
                            if let Ok(group_id) = &result {
                                publish_app_runtime_group_state_updated(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    group_id,
                                );
                            }
                            let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::Members { group_id, respond }) => {
                        let result = client.members(&group_id);
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::GroupMlsState { group_id, respond }) => {
                        let result = client.group_mls_state(&group_id);
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::UpdateMessageRetention {
                        group_id,
                        disappearing_message_secs,
                        respond,
                    }) => {
                        let result = client
                            .update_message_retention(&group_id, disappearing_message_secs)
                            .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::SafeExportSecret {
                        group_id,
                        component_id,
                        respond,
                    }) => {
                        let result = client.safe_export_secret(&group_id, component_id);
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::ExporterSecret {
                        group_id,
                        label,
                        length,
                        respond,
                    }) => {
                        let result = client.exporter_secret(&group_id, &label, length);
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::InviteMembers {
                        group_id,
                        members,
                        respond,
                    }) => {
                        let result = async {
                            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
                            client.invite_members(&group_id, &member_refs).await
                        }
                        .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::RemoveMembers {
                        group_id,
                        members,
                        respond,
                    }) => {
                        let result = async {
                            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
                            client.remove_members(&group_id, &member_refs).await
                        }
                        .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::LeaveGroup { group_id, respond }) => {
                        let result = client.leave_group(&group_id).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::PromoteAdmin {
                        group_id,
                        member_ref,
                        respond,
                    }) => {
                        let result = client.promote_admin(&group_id, &member_ref).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::DemoteAdmin {
                        group_id,
                        member_ref,
                        respond,
                    }) => {
                        let result = client.demote_admin(&group_id, &member_ref).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::SelfDemoteAdmin { group_id, respond }) => {
                        let result = client.self_demote_admin(&group_id).await;
                        let _ = respond.send(result);
                    }
                        Some(AccountWorkerCommand::UpdateGroupProfile {
                            group_id,
                            name,
                            description,
                            respond,
                        }) => {
                            let result = client
                                .update_group_profile(&group_id, name.as_deref(), description.as_deref())
                                .await;
                            if result.is_ok() {
                                publish_app_runtime_group_state_updated(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    &group_id,
                                );
                            }
                            let _ = respond.send(result);
                        }
                    Some(AccountWorkerCommand::SendMessage {
                        group_id,
                        payload,
                        respond,
                    }) => {
                        let result = client.send(&group_id, &payload).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::SendAppEvent {
                        group_id,
                        intent,
                        respond,
                    }) => {
                        let result = client
                            .send_app_event(&group_id, intent)
                            .await
                            .map(|(_event, summary)| summary);
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::UploadMedia {
                        group_id,
                        request,
                        respond,
                    }) => {
                        let result = client.upload_media(&group_id, request).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::DownloadMedia {
                        group_id,
                        reference,
                        respond,
                    }) => {
                        let result = client.download_media(&group_id, reference).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::StartAgentTextStream {
                        group_id,
                        stream_id,
                        quic_candidates,
                        respond,
                    }) => {
                        let result = client
                            .start_agent_text_stream(&group_id, &stream_id, quic_candidates)
                            .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::FinishAgentTextStream {
                        group_id,
                        request,
                        respond,
                    }) => {
                        let result = client.finish_agent_text_stream(&group_id, request).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::RetryGroupConvergence { group_id, respond }) => {
                        let result = client.retry_group_convergence(&group_id).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::PublishKeyPackage { respond }) => {
                        let result = async {
                            let key_package = client.publish_key_package().await?;
                            Ok(key_package.bytes().len())
                        }
                        .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::RotateKeyPackage { respond }) => {
                        let result = async {
                            let key_package = client.rotate_key_package().await?;
                            Ok(key_package.bytes().len())
                        }
                        .await;
                        let _ = respond.send(result);
                    }
                    None => return,
                }
            }
            result = client.next_event() => {
                match result {
                    Ok(summary) => {
                        reconnect_backoff.reset();
                        publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
                    }
                    Err(err) => {
                        publish_app_runtime_account_error(
                            &events,
                            &account_id_hex,
                            &account_label,
                            format!("runtime receive failed: {err}"),
                        );
                        tokio::time::sleep(reconnect_backoff.next_delay()).await;
                        match app.runtime_client(&account_label, &relay_plane).await {
                            Ok(reopened) => {
                                client = reopened;
                            }
                            Err(setup_err) => {
                                publish_app_runtime_account_error(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    format!("runtime restart failed: {setup_err}"),
                                );
                                tokio::time::sleep(reconnect_backoff.next_delay()).await;
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct AccountWorkerReconnectBackoff {
    base: Duration,
    max: Duration,
    next: Duration,
}

impl Default for AccountWorkerReconnectBackoff {
    fn default() -> Self {
        Self::new(
            ACCOUNT_WORKER_RECONNECT_BASE_DELAY,
            ACCOUNT_WORKER_RECONNECT_MAX_DELAY,
        )
    }
}

impl AccountWorkerReconnectBackoff {
    fn new(base: Duration, max: Duration) -> Self {
        let base = std::cmp::min(base, max);
        Self {
            base,
            max,
            next: base,
        }
    }

    fn reset(&mut self) {
        self.next = self.base;
    }

    fn next_delay(&mut self) -> Duration {
        self.next_delay_with_jitter(account_worker_reconnect_jitter())
    }

    fn next_delay_with_jitter(&mut self, jitter: Duration) -> Duration {
        let delay = std::cmp::min(self.next.saturating_add(jitter), self.max);
        self.next = std::cmp::min(self.next.saturating_mul(2), self.max);
        delay
    }
}

fn account_worker_reconnect_jitter() -> Duration {
    let jitter_ms = OsRng.next_u64() % (ACCOUNT_WORKER_RECONNECT_JITTER_MAX_MS + 1);
    Duration::from_millis(jitter_ms)
}

fn publish_app_runtime_summary(
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    summary: &SyncSummary,
) {
    for group_id in &summary.joined_groups {
        let _ = events.send(MarmotAppEvent::GroupJoined {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            group_id: group_id.clone(),
        });
    }
    for message in &summary.messages {
        // A kind-1200 start is an open-preview signal, not a timeline message,
        // so it is emitted only as `AgentStreamStarted`. Everything else
        // (chat/reply/media/reaction/delete/stream-final) is a timeline message.
        if let Some(event) = agent_stream_runtime_event(account_id_hex, account_label, message) {
            let _ = events.send(event);
        } else {
            let _ = events.send(MarmotAppEvent::MessageReceived(RuntimeMessageReceived {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
                message: message.clone(),
            }));
        }
    }
    for event in &summary.events {
        let _ = events.send(MarmotAppEvent::GroupEvent(RuntimeGroupEvent {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            event: event.clone(),
        }));
    }
}

fn publish_app_runtime_group_state_updated(
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    group_id: &GroupId,
) {
    let _ = events.send(MarmotAppEvent::GroupStateUpdated {
        account_id_hex: account_id_hex.to_owned(),
        account_label: account_label.to_owned(),
        group_id: group_id.clone(),
    });
}

/// Emit a runtime `AgentStreamStarted` for a kind-1200 start event. Kind-9
/// stream-final messages are normal timeline messages and do not fire here.
fn agent_stream_runtime_event(
    account_id_hex: &str,
    account_label: &str,
    message: &ReceivedMessage,
) -> Option<MarmotAppEvent> {
    if message.kind != MARMOT_APP_EVENT_KIND_AGENT_STREAM_START {
        return None;
    }
    Some(MarmotAppEvent::AgentStreamStarted(
        RuntimeAgentStreamMessage {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            message: message.clone(),
        },
    ))
}

struct ParsedQuicCandidate {
    authority: String,
    server_name: String,
}

struct ResolvedQuicCandidate {
    broker_addr: SocketAddr,
    server_name: String,
}

/// A kind-1200 agent text stream start, projected from its inner-event tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamStartView {
    pub stream_id_hex: String,
    pub route: String,
    pub quic_candidates: Vec<String>,
}

impl StreamStartView {
    /// Read the stream start view from a kind-1200 event's tags. Returns `None`
    /// if the event is not a stream start or is missing the `stream` tag.
    pub fn from_event(kind: u64, tags: &[Vec<String>]) -> Option<Self> {
        if kind != MARMOT_APP_EVENT_KIND_AGENT_STREAM_START {
            return None;
        }
        let stream_id_hex = tag_value(tags, STREAM_TAG)?.to_owned();
        let route = tag_value(tags, STREAM_ROUTE_TAG)
            .unwrap_or(STREAM_ROUTE_QUIC)
            .to_owned();
        let quic_candidates = tag_values(tags, STREAM_BROKER_TAG)
            .into_iter()
            .map(str::to_owned)
            .collect();
        Some(Self {
            stream_id_hex,
            route,
            quic_candidates,
        })
    }
}

/// Find the most recent kind-1200 stream start in a group's message history,
/// optionally constrained to a specific `stream_id`.
fn latest_agent_stream_start(
    messages: Vec<AppMessageRecord>,
    stream_id_hex: Option<&str>,
) -> Result<(String, StreamStartView, String), AppError> {
    messages
        .into_iter()
        .rev()
        .find_map(|message| {
            let start = StreamStartView::from_event(message.kind, &message.tags)?;
            if stream_id_hex.is_none_or(|stream_id| stream_id == start.stream_id_hex) {
                Some((message.message_id_hex, start, message.sender))
            } else {
                None
            }
        })
        .ok_or(AppError::AgentStreamMissingStart)
}

fn parse_quic_candidate(candidate: &str) -> Result<ParsedQuicCandidate, AppError> {
    let trimmed = candidate.trim();
    let Some(rest) = trimmed.strip_prefix("quic://") else {
        return Err(AppError::AgentStreamInvalidCandidate(trimmed.to_owned()));
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(AppError::AgentStreamInvalidCandidate(trimmed.to_owned()));
    }
    let server_name = candidate_server_name(authority)?;
    Ok(ParsedQuicCandidate {
        authority: authority.to_owned(),
        server_name,
    })
}

fn parse_quic_candidates(candidates: &[String]) -> Result<Vec<ParsedQuicCandidate>, AppError> {
    let parsed = candidates
        .iter()
        .filter(|candidate| candidate.trim().starts_with("quic://"))
        .filter_map(|candidate| parse_quic_candidate(candidate).ok())
        .collect::<Vec<_>>();
    if parsed.is_empty() {
        return Err(AppError::AgentStreamMissingCandidate);
    }
    Ok(parsed)
}

fn candidate_server_name(authority: &str) -> Result<String, AppError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, _)) = rest.split_once(']') else {
            return Err(AppError::AgentStreamInvalidCandidate(authority.to_owned()));
        };
        return Ok(host.to_owned());
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| AppError::AgentStreamInvalidCandidate(authority.to_owned()))
}

async fn watch_broker_candidates(
    candidates: Vec<ParsedQuicCandidate>,
    server_cert_der: Option<Vec<u8>>,
    insecure_local: bool,
    stream_id: Vec<u8>,
    start_event_id: MessageId,
    crypto: Option<AgentTextStreamCrypto>,
    updates_tx: mpsc::Sender<RuntimeAgentStreamUpdate>,
) -> RuntimeAgentStreamUpdate {
    let mut last_error = None;
    for candidate in candidates {
        match resolve_broker_addr(&candidate.authority).await {
            Ok(broker_addr) => {
                let resolved = ResolvedQuicCandidate {
                    broker_addr,
                    server_name: candidate.server_name,
                };
                let trust = broker_trust_for_addr(
                    resolved.broker_addr,
                    server_cert_der.clone(),
                    insecure_local,
                );
                let config = SubscribeTextFromBroker {
                    broker_addr: resolved.broker_addr,
                    server_name: resolved.server_name,
                    trust,
                    stream_id: stream_id.clone(),
                    start_event_id: start_event_id.clone(),
                    crypto: crypto.clone(),
                };
                let chunk_tx = updates_tx.clone();
                match subscribe_text_from_broker_with_updates(config, |chunk| {
                    // Non-blocking: if the consumer falls behind we drop a
                    // delta; the Finished update carries the full transcript
                    // for reconcile.
                    if let Err(mpsc::error::TrySendError::Full(_)) =
                        chunk_tx.try_send(RuntimeAgentStreamUpdate::Chunk {
                            seq: chunk.seq,
                            text: chunk.text.clone(),
                        })
                    {
                        tracing::warn!(
                            target: "marmot_app::agent_stream",
                            method = "watch_agent_text_stream",
                            "dropping live agent text stream delta; consumer is behind",
                        );
                    }
                })
                .await
                {
                    Ok(received) => {
                        return RuntimeAgentStreamUpdate::Finished {
                            text: received.text,
                            transcript_hash_hex: hex::encode(received.transcript_hash),
                            chunk_count: received.chunk_count,
                        };
                    }
                    Err(err) => last_error = Some(err.to_string()),
                }
            }
            Err(err) => last_error = Some(err.to_string()),
        }
    }
    RuntimeAgentStreamUpdate::Failed {
        message: last_error.unwrap_or_else(|| AppError::AgentStreamMissingCandidate.to_string()),
    }
}

async fn resolve_broker_addr(authority: &str) -> Result<SocketAddr, AppError> {
    let mut addrs = tokio::net::lookup_host(authority)
        .await
        .map_err(|_| AppError::AgentStreamInvalidCandidate(authority.to_owned()))?;
    addrs
        .next()
        .ok_or_else(|| AppError::AgentStreamInvalidCandidate(authority.to_owned()))
}

fn broker_trust_for_addr(
    broker_addr: SocketAddr,
    server_cert_der: Option<Vec<u8>>,
    insecure_local: bool,
) -> BrokerServerTrust {
    if insecure_local && broker_addr.ip().is_loopback() {
        return BrokerServerTrust::InsecureLocal;
    }
    server_cert_der
        .map(BrokerServerTrust::CertificateDer)
        .unwrap_or(BrokerServerTrust::Platform)
}

fn runtime_message_update_from_event(event: MarmotAppEvent) -> Option<RuntimeMessageUpdate> {
    match event {
        // Every delivered timeline message (chat, reply, media, reaction,
        // delete, stream-final) flows as a `Message`. The kind-1200 stream start
        // arrives as its own `AgentStreamStarted` event below, never here.
        MarmotAppEvent::MessageReceived(message) => Some(RuntimeMessageUpdate::Message(message)),
        MarmotAppEvent::AgentStreamStarted(message) => {
            Some(RuntimeMessageUpdate::AgentStreamStarted(message))
        }
        MarmotAppEvent::GroupJoined { .. }
        | MarmotAppEvent::GroupStateUpdated { .. }
        | MarmotAppEvent::GroupEvent(_)
        | MarmotAppEvent::AccountError(_) => None,
    }
}

fn runtime_group_event_route(event: &MarmotAppEvent) -> Option<(&str, &GroupId)> {
    match event {
        MarmotAppEvent::GroupJoined {
            account_id_hex,
            group_id,
            ..
        }
        | MarmotAppEvent::GroupStateUpdated {
            account_id_hex,
            group_id,
            ..
        } => Some((account_id_hex, group_id)),
        MarmotAppEvent::GroupEvent(group_event) => Some((
            &group_event.account_id_hex,
            group_id_from_event(&group_event.event),
        )),
        MarmotAppEvent::MessageReceived(_)
        | MarmotAppEvent::AgentStreamStarted(_)
        | MarmotAppEvent::AccountError(_) => None,
    }
}

fn group_id_from_event(event: &GroupEvent) -> &GroupId {
    match event {
        GroupEvent::GroupCreated { group_id }
        | GroupEvent::GroupJoined { group_id, .. }
        | GroupEvent::MessageReceived { group_id, .. }
        | GroupEvent::AppMessageInvalidated { group_id, .. }
        | GroupEvent::MemberAdded { group_id, .. }
        | GroupEvent::MemberRemoved { group_id, .. }
        | GroupEvent::EpochChanged { group_id, .. }
        | GroupEvent::ForkRecovered { group_id, .. }
        | GroupEvent::GroupUnrecoverable { group_id } => group_id,
    }
}

fn app_group_record_fingerprint(group: &AppGroupRecord) -> String {
    serde_json::to_string(group).unwrap_or_else(|_| group.group_id_hex.clone())
}

fn publish_app_runtime_account_error(
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    message: String,
) {
    let _ = events.send(MarmotAppEvent::AccountError(RuntimeAccountError {
        account_id_hex: account_id_hex.to_owned(),
        account_label: account_label.to_owned(),
        message,
    }));
}

impl AppClient {
    async fn sync_runtime_groups(&self) -> Result<(), AppError> {
        let rebuild_since = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp);
        self.runtime.sync_transport_groups(rebuild_since).await?;
        Ok(())
    }

    pub async fn publish_key_package(&mut self) -> Result<KeyPackage, AppError> {
        self.app
            .ensure_local_account_relay_lists(&self.state.label)
            .await?;
        self.refresh_routing()?;
        self.runtime.activate_transport(None).await?;
        match self.app.latest_key_package(&self.state.label) {
            Ok(key_package) if is_last_resort_key_package(&key_package).unwrap_or(false) => {
                self.app
                    .publish_cached_key_package(&self.state.label, key_package)
                    .await
            }
            Ok(_) => Ok(self.runtime.publish_fresh_key_package().await?),
            Err(AppError::MissingKeyPackage(_)) => {
                Ok(self.runtime.publish_fresh_key_package().await?)
            }
            Err(err) => Err(err),
        }
    }

    pub async fn rotate_key_package(&mut self) -> Result<KeyPackage, AppError> {
        self.app
            .ensure_local_account_relay_lists(&self.state.label)
            .await?;
        self.refresh_routing()?;
        self.runtime.activate_transport(None).await?;
        Ok(self.runtime.publish_fresh_key_package().await?)
    }

    pub async fn create_group(
        &mut self,
        name: &str,
        member_refs: &[&str],
    ) -> Result<GroupId, AppError> {
        validate_group_profile(name, "")?;
        let mut members = Vec::with_capacity(member_refs.len());
        for member in member_refs {
            members.push(self.app.member_key_package(member).await?);
        }
        self.refresh_routing()?;
        let nostr_routing = self.app.new_nostr_routing()?;
        let nostr_routing_bytes =
            encode_nostr_routing_v1(&nostr_routing).map_err(AppError::InvalidNostrRouting)?;
        let mut app_components = vec![AppComponentData {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            data: nostr_routing_bytes,
        }];
        app_components.push(
            AgentTextStreamQuicPolicyV1::user_to_agent_default()
                .to_app_component_data()
                .map_err(|err| AppError::InvalidAgentTextStreamPolicy(err.to_string()))?,
        );

        let (group_id, effects) = self
            .runtime
            .create_group(CreateGroupRequest {
                name: name.to_owned(),
                description: String::new(),
                members,
                required_features: Vec::new(),
                app_components,
                initial_admins: Vec::new(),
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.add_group(&group_id)?;
        self.sync_runtime_groups().await?;
        self.app.save_state(&self.state)?;
        Ok(group_id)
    }

    pub fn members(&self, group_id: &GroupId) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        self.ensure_group(group_id)?;
        let profiles = self.app.profiles_by_id()?;
        Ok(self
            .runtime
            .members(group_id)?
            .into_iter()
            .map(|member| {
                let member_id_hex = hex::encode(member.id.as_slice());
                let account = profiles.get(&member_id_hex).cloned();
                AppGroupMemberRecord {
                    member_id_hex,
                    local: account.is_some(),
                    account,
                }
            })
            .collect())
    }

    pub fn group_mls_state(&self, group_id: &GroupId) -> Result<AppGroupMlsState, AppError> {
        self.ensure_group(group_id)?;
        let group = self.runtime.group_record(group_id)?;
        Ok(AppGroupMlsState {
            group_id_hex: hex::encode(group_id.as_slice()),
            epoch: group.epoch.0,
            member_count: group.members.len(),
            required_app_components: group
                .required_capabilities
                .app_components
                .ids
                .iter()
                .copied()
                .collect(),
        })
    }

    pub fn safe_export_secret(
        &mut self,
        group_id: &GroupId,
        component_id: cgka_traits::AppComponentId,
    ) -> Result<SecretBytes, AppError> {
        self.ensure_group(group_id)?;
        Ok(self.runtime.safe_export_secret(group_id, component_id)?)
    }

    pub fn agent_text_stream_exporter_secret(
        &self,
        group_id: &GroupId,
    ) -> Result<SecretBytes, AppError> {
        self.exporter_secret(group_id, AGENT_TEXT_STREAM_EXPORTER_LABEL, 32)
    }

    fn exporter_secret(
        &self,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> Result<SecretBytes, AppError> {
        self.ensure_group(group_id)?;
        Ok(self.runtime.exporter_secret(group_id, label, length)?)
    }

    fn encrypted_media_exporter_secret(&self, group_id: &GroupId) -> Result<SecretBytes, AppError> {
        self.exporter_secret(group_id, ENCRYPTED_MEDIA_EXPORTER_LABEL, 32)
    }

    pub async fn invite_members(
        &mut self,
        group_id: &GroupId,
        member_refs: &[&str],
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let mut key_packages = Vec::with_capacity(member_refs.len());
        for member in member_refs {
            key_packages.push(self.app.member_key_package(member).await?);
        }
        self.refresh_routing()?;

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages,
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.prune_plaintext_retention_for_group(group_id)?;
        self.app.save_state(&self.state)?;
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn remove_members(
        &mut self,
        group_id: &GroupId,
        member_refs: &[&str],
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let mut members = Vec::with_capacity(member_refs.len());
        for member in member_refs {
            members.push(self.app.member_id(member)?);
        }

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::RemoveMembers {
                group_id: group_id.clone(),
                members,
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.app.save_state(&self.state)?;
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn leave_group(&mut self, group_id: &GroupId) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.app.save_state(&self.state)?;
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn promote_admin(
        &mut self,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let mut admins = self.runtime.admin_pubkeys(group_id)?;
        admins.push(admin_pubkey_from_member_id(
            &self.app.member_id(member_ref)?,
        )?);
        self.update_admin_policy(group_id, admins).await
    }

    pub async fn demote_admin(
        &mut self,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let target = admin_pubkey_from_member_id(&self.app.member_id(member_ref)?)?;
        let mut admins = self.runtime.admin_pubkeys(group_id)?;
        admins.retain(|admin| admin != &target);
        self.update_admin_policy(group_id, admins).await
    }

    pub async fn self_demote_admin(&mut self, group_id: &GroupId) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let account = self.app.account_home().account(&self.state.label)?;
        let local = admin_pubkey_from_account_id_hex(&account.account_id_hex)?;
        let mut admins = self.runtime.admin_pubkeys(group_id)?;
        admins.retain(|admin| admin != &local);
        self.update_admin_policy(group_id, admins).await
    }

    async fn update_admin_policy(
        &mut self,
        group_id: &GroupId,
        admins: Vec<[u8; 32]>,
    ) -> Result<SendSummary, AppError> {
        let component = AppGroupAdminPolicyComponent::new(admins).to_app_component_data()?;

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::UpdateAppComponents {
                group_id: group_id.clone(),
                updates: vec![component],
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.app.save_state(&self.state)?;
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn update_message_retention(
        &mut self,
        group_id: &GroupId,
        disappearing_message_secs: u64,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let component = AppGroupMessageRetentionComponent::new(disappearing_message_secs)
            .to_app_component_data()?;

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::UpdateAppComponents {
                group_id: group_id.clone(),
                updates: vec![component],
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.prune_plaintext_retention_for_group(group_id)?;
        self.app.save_state(&self.state)?;
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn send(
        &mut self,
        group_id: &GroupId,
        payload: &[u8],
    ) -> Result<SendSummary, AppError> {
        // The transport-facing `send` carries plain UTF-8 chat text; structured
        // payloads use `send_app_event` with a typed intent.
        let content = String::from_utf8(payload.to_vec()).map_err(|_| {
            AppError::InvalidAppMessagePayload("chat message must be valid UTF-8".into())
        })?;
        let (_event, summary) = self
            .send_app_event(group_id, AppMessageIntent::Chat { content })
            .await?;
        Ok(summary)
    }

    /// Build, encrypt, send, and project the inner Marmot app event for `intent`.
    /// Returns the built event so callers (agent-stream start/finish) can surface
    /// its tags. The authoring account id and clock are resolved here so the
    /// inner `pubkey` always equals the MLS-authenticated sender.
    async fn send_app_event(
        &mut self,
        group_id: &GroupId,
        intent: AppMessageIntent,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.ensure_group(group_id)?;
        let sender = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        // NIP-25 has no native un-react: a kind-7 reaction is retracted with a
        // kind-5 delete of that reaction event. Resolve the user's own reaction
        // event id from the projection before building the tombstone.
        let intent = match intent {
            AppMessageIntent::Unreact { target_message_id } => {
                let reaction_id =
                    self.own_reaction_event_id(group_id, &sender, &target_message_id)?;
                AppMessageIntent::Delete {
                    target_message_id: reaction_id,
                }
            }
            other => other,
        };
        let event = build_inner_event(&intent, &sender, unix_now_seconds())?;
        let payload = encode_inner_event(&event)?;

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload,
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        let group_id_hex = hex::encode(group_id.as_slice());
        let app_event_id = event.id.clone();
        let projection = self.app.account_projection(&self.state.label)?;
        projection.record_message(&AppMessageProjection {
            message_id_hex: app_event_id.clone(),
            direction: "sent".to_owned(),
            group_id_hex: group_id_hex.clone(),
            sender: sender.clone(),
            plaintext: event.content.clone(),
            kind: event.kind,
            tags: event.tags.clone(),
            recorded_at: None,
        })?;
        self.prune_plaintext_retention_for_group(group_id)?;
        self.app.save_state(&self.state)?;
        Ok((
            event,
            SendSummary {
                published: effects.reports.len(),
                message_ids: vec![app_event_id],
            },
        ))
    }

    /// Most recent kind-7 reaction this account authored that targets
    /// `target_message_id`, identified by its own message id. Used to build the
    /// kind-5 retraction for an un-react.
    fn own_reaction_event_id(
        &self,
        group_id: &GroupId,
        sender: &str,
        target_message_id: &str,
    ) -> Result<String, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let messages =
            self.app
                .account_projection(&self.state.label)?
                .messages(AppMessageQuery {
                    group_id_hex: Some(group_id_hex),
                    limit: None,
                })?;
        messages
            .into_iter()
            .rev()
            .find(|message| {
                message.kind == MARMOT_APP_EVENT_KIND_REACTION
                    && message.sender == sender
                    && tag_value(&message.tags, EVENT_REF_TAG) == Some(target_message_id)
                    && !message.message_id_hex.is_empty()
            })
            .map(|message| message.message_id_hex)
            .ok_or(AppError::ReactionNotFound)
    }

    pub async fn react_to_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
        emoji: &str,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Reaction {
                    target_message_id: target_message_id.to_owned(),
                    emoji: emoji.to_owned(),
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn unreact_from_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Unreact {
                    target_message_id: target_message_id.to_owned(),
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn delete_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Delete {
                    target_message_id: target_message_id.to_owned(),
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn reply_to_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
        text: &str,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Reply {
                    target_message_id: target_message_id.to_owned(),
                    text: text.to_owned(),
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn send_media_reference(
        &mut self,
        group_id: &GroupId,
        reference: MediaReference,
        caption: Option<String>,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(group_id, AppMessageIntent::Media { reference, caption })
            .await?;
        Ok(summary)
    }

    pub async fn upload_media(
        &mut self,
        group_id: &GroupId,
        request: MediaUploadRequest,
    ) -> Result<MediaUploadResult, AppError> {
        self.ensure_group(group_id)?;
        self.sync_runtime_groups().await?;
        let exporter_secret = self.encrypted_media_exporter_secret(group_id)?;
        let keys = self
            .app
            .account_home()
            .load_signing_keys(&self.state.label)?;
        let should_send = request.send;
        let caption = request.caption.clone();
        let mut result = upload_encrypted_media(request, exporter_secret.as_ref(), &keys).await?;
        if should_send {
            result.sent = Some(
                self.send_media_reference(group_id, result.reference.clone(), caption)
                    .await?,
            );
        }
        Ok(result)
    }

    pub async fn download_media(
        &mut self,
        group_id: &GroupId,
        reference: MediaReference,
    ) -> Result<MediaDownloadResult, AppError> {
        self.ensure_group(group_id)?;
        self.sync_runtime_groups().await?;
        let exporter_secret = self.encrypted_media_exporter_secret(group_id)?;
        download_encrypted_media(reference, exporter_secret.as_ref()).await
    }

    pub async fn start_agent_text_stream(
        &mut self,
        group_id: &GroupId,
        stream_id: &[u8],
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.send_app_event(
            group_id,
            AppMessageIntent::StreamStart {
                stream_id: stream_id.to_vec(),
                quic_candidates,
            },
        )
        .await
    }

    pub async fn finish_agent_text_stream(
        &mut self,
        group_id: &GroupId,
        request: AgentTextStreamFinishRequest,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.send_app_event(group_id, AppMessageIntent::StreamFinal { request })
            .await
    }

    pub async fn retry_group_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;

        self.sync_runtime_groups().await?;
        let effects = self.runtime.advance_convergence(group_id).await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.prune_plaintext_retention_for_group(group_id)?;
        self.app.save_state(&self.state)?;
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn update_group_profile(
        &mut self,
        group_id: &GroupId,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<SendSummary, AppError> {
        if name.is_none() && description.is_none() {
            return Err(AppError::InvalidGroupProfile(
                "name or description is required".into(),
            ));
        }
        validate_group_profile(name.unwrap_or(""), description.unwrap_or(""))?;
        self.ensure_group(group_id)?;

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::UpdateGroupData {
                group_id: group_id.clone(),
                name: name.map(ToOwned::to_owned),
                description: description.map(ToOwned::to_owned),
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        let message_ids = effects
            .reports
            .iter()
            .map(|report| hex::encode(report.message_id.as_slice()))
            .collect::<Vec<_>>();
        let group_metadata = self.runtime.group_record(group_id).ok();
        let admin_policy = self.admin_policy_for_group(group_id);
        let message_retention = self.message_retention_for_group(group_id);
        let agent_text_stream = self.agent_text_stream_for_group(group_id);
        let nostr_routing = self.nostr_routing_for_group(group_id)?;
        add_group(
            &mut self.state,
            group_id,
            nostr_routing,
            group_metadata.as_ref(),
            admin_policy,
            message_retention,
            agent_text_stream,
        );
        self.app.save_state(&self.state)?;
        Ok(SendSummary {
            published: effects.reports.len(),
            message_ids,
        })
    }

    pub async fn sync(&mut self) -> Result<SyncSummary, AppError> {
        let rebuild_since = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp);
        self.runtime.activate_transport(rebuild_since).await?;
        self.sync_runtime_groups().await?;
        self.sync_sdk_relay().await
    }

    pub async fn next_event(&mut self) -> Result<SyncSummary, AppError> {
        let display_names = self.app.display_names_by_id()?;
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let mut seen = self
            .state
            .seen_events
            .iter()
            .cloned()
            .collect::<HashSet<_>>();

        loop {
            let delivery = self
                .adapter
                .receive()
                .await?
                .ok_or(AppError::TransportClosed)?;
            let event_id = hex::encode(delivery.message.id.as_slice());
            if is_own_relay_echo(&delivery, &local_account_id_hex, &seen) {
                continue;
            }
            if seen.contains(&event_id) {
                continue;
            }
            seen.insert(event_id.clone());
            remember_seen_event(&mut self.state, event_id);
            refresh_seen_lookup_if_needed(&mut seen, &self.state);

            let mut summary = SyncSummary::default();
            self.ingest_delivery(delivery, &display_names, &mut summary)
                .await?;
            self.app.save_state(&self.state)?;
            if summary.joined_groups.is_empty()
                && summary.messages.is_empty()
                && summary.events.is_empty()
            {
                continue;
            }
            return Ok(summary);
        }
    }

    async fn sync_sdk_relay(&mut self) -> Result<SyncSummary, AppError> {
        let display_names = self.app.display_names_by_id()?;
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let mut summary = SyncSummary::default();
        let mut seen = self
            .state
            .seen_events
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
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
            let event_id = hex::encode(delivery.message.id.as_slice());
            if is_own_relay_echo(&delivery, &local_account_id_hex, &seen) {
                continue;
            }
            if seen.contains(&event_id) {
                continue;
            }
            seen.insert(event_id.clone());
            remember_seen_event(&mut self.state, event_id);
            refresh_seen_lookup_if_needed(&mut seen, &self.state);
            self.ingest_delivery(delivery, &display_names, &mut summary)
                .await?;
        }

        self.app.save_state(&self.state)?;
        Ok(summary)
    }

    async fn ingest_delivery(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
        display_names: &HashMap<String, String>,
        summary: &mut SyncSummary,
    ) -> Result<(), AppError> {
        let source_message_id_hex = hex::encode(delivery.message.id.as_slice());
        let source_recorded_at = delivery.message.timestamp.0;
        let effects = self.runtime.ingest_delivery(delivery).await?;
        fail_if_publish_failed(&effects.effects.failures)?;
        self.remember_transport_cursor(source_recorded_at);
        for event in &effects.effects.events {
            let before = self.state.groups.len();
            let group_metadata =
                event_group_id(event).and_then(|group_id| self.runtime.group_record(group_id).ok());
            let group_projection = event_group_id(event)
                .map(|group_id| {
                    Ok::<_, AppError>(EventGroupProjection {
                        nostr_routing: self.nostr_routing_for_group(group_id)?,
                        group_metadata: group_metadata.as_ref(),
                        admin_policy: self
                            .runtime
                            .admin_pubkeys(group_id)
                            .map(AppGroupAdminPolicyComponent::new)
                            .unwrap_or_else(|_| AppGroupAdminPolicyComponent::new(Vec::new())),
                        message_retention: self.message_retention_for_group(group_id),
                        agent_text_stream: self.agent_text_stream_for_group(group_id),
                    })
                })
                .transpose()?;
            if let Some(message) = observe_event(
                &mut self.state,
                display_names,
                summary,
                event,
                group_projection.as_ref(),
                &source_message_id_hex,
            ) {
                self.app
                    .account_projection(&self.state.label)?
                    .record_message(&AppMessageProjection {
                        message_id_hex: message.message_id_hex.clone(),
                        direction: "received".to_owned(),
                        group_id_hex: hex::encode(message.group_id.as_slice()),
                        sender: message.sender.clone(),
                        plaintext: message.plaintext.clone(),
                        kind: message.kind,
                        tags: message.tags.clone(),
                        recorded_at: Some(source_recorded_at),
                    })?;
                self.prune_plaintext_retention_for_group(&message.group_id)?;
            }
            if self.state.groups.len() != before {
                self.refresh_group_routes()?;
                self.sync_runtime_groups().await?;
            }
        }
        Ok(())
    }

    fn ensure_group(&self, group_id: &GroupId) -> Result<(), AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        if self
            .state
            .groups
            .iter()
            .any(|group| group.group_id_hex == group_id_hex)
        {
            Ok(())
        } else {
            Err(AppError::UnknownGroup(group_id_hex))
        }
    }

    fn refresh_group(&mut self, group_id: &GroupId) {
        let group_metadata = self.runtime.group_record(group_id).ok();
        let admin_policy = self.admin_policy_for_group(group_id);
        let message_retention = self.message_retention_for_group(group_id);
        let agent_text_stream = self.agent_text_stream_for_group(group_id);
        let Ok(nostr_routing) = self.nostr_routing_for_group(group_id) else {
            return;
        };
        add_group(
            &mut self.state,
            group_id,
            nostr_routing,
            group_metadata.as_ref(),
            admin_policy,
            message_retention,
            agent_text_stream,
        );
    }

    fn add_group(&mut self, group_id: &GroupId) -> Result<(), AppError> {
        let group_metadata = self.runtime.group_record(group_id).ok();
        let admin_policy = self.admin_policy_for_group(group_id);
        let message_retention = self.message_retention_for_group(group_id);
        let agent_text_stream = self.agent_text_stream_for_group(group_id);
        let nostr_routing = self.nostr_routing_for_group(group_id)?;
        add_group(
            &mut self.state,
            group_id,
            nostr_routing.clone(),
            group_metadata.as_ref(),
            admin_policy,
            message_retention,
            agent_text_stream,
        );
        self.routing
            .add_group(nostr_routing.subscription(group_id)?);
        Ok(())
    }

    fn admin_policy_for_group(&self, group_id: &GroupId) -> AppGroupAdminPolicyComponent {
        self.runtime
            .admin_pubkeys(group_id)
            .map(AppGroupAdminPolicyComponent::new)
            .unwrap_or_else(|_| AppGroupAdminPolicyComponent::new(Vec::new()))
    }

    fn message_retention_for_group(&self, group_id: &GroupId) -> AppGroupMessageRetentionComponent {
        self.runtime
            .app_component(group_id, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .ok()
            .flatten()
            .map(|bytes| AppGroupMessageRetentionComponent::from_bytes(&bytes))
            .unwrap_or_else(AppGroupMessageRetentionComponent::disabled)
    }

    fn prune_plaintext_retention_for_group(&self, group_id: &GroupId) -> Result<(), AppError> {
        let retention = self.message_retention_for_group(group_id);
        if retention.disappearing_message_secs == 0 {
            return Ok(());
        }
        let cutoff = unix_now_seconds().saturating_sub(retention.disappearing_message_secs);
        self.app
            .account_projection(&self.state.label)?
            .prune_group_messages_before(&hex::encode(group_id.as_slice()), cutoff)?;
        Ok(())
    }

    fn agent_text_stream_for_group(&self, group_id: &GroupId) -> AppAgentTextStreamComponent {
        self.runtime
            .app_component(group_id, AGENT_TEXT_STREAM_QUIC_COMPONENT_ID)
            .ok()
            .flatten()
            .map(|bytes| AppAgentTextStreamComponent::from_bytes(&bytes))
            .unwrap_or_else(AppAgentTextStreamComponent::disabled)
    }

    fn refresh_group_routes(&mut self) -> Result<(), AppError> {
        for group in &self.state.groups {
            let group_id = GroupId::new(hex::decode(&group.group_id_hex)?);
            self.routing
                .add_group(group.nostr_routing.subscription(&group_id)?);
        }
        Ok(())
    }

    fn refresh_routing(&mut self) -> Result<(), AppError> {
        let routing = self.app.routing_for(&self.state)?;
        self.routing.replace(routing.snapshot());
        Ok(())
    }

    fn remember_transport_cursor(&mut self, timestamp: u64) {
        self.state.last_transport_timestamp = Some(
            self.state
                .last_transport_timestamp
                .map(|current| current.max(timestamp))
                .unwrap_or(timestamp),
        );
    }

    fn remember_published_reports(&mut self, effects: &marmot_account::AccountDeviceEffects) {
        for report in &effects.reports {
            let event_id = hex::encode(report.message_id.as_slice());
            remember_seen_event(&mut self.state, event_id);
        }
    }

    fn nostr_routing_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<AppGroupNostrRoutingComponent, AppError> {
        let bytes = self
            .runtime
            .app_component(group_id, NOSTR_ROUTING_COMPONENT_ID)?
            .ok_or_else(|| {
                AppError::InvalidNostrRouting(
                    "group is missing marmot.transport.nostr.routing.v1".into(),
                )
            })?;
        AppGroupNostrRoutingComponent::from_bytes(&bytes)
    }
}

fn is_own_relay_echo(
    delivery: &cgka_traits::TransportDelivery,
    local_account_id_hex: &str,
    known_event_ids: &HashSet<String>,
) -> bool {
    let event_id = hex::encode(delivery.message.id.as_slice());
    if !known_event_ids.contains(&event_id) {
        return false;
    }
    NostrTransportEvent::from_transport_message(&delivery.message)
        .ok()
        .is_some_and(|event| event.pubkey == local_account_id_hex)
}

fn app_feature_registry() -> FeatureRegistry {
    let mut registry = FeatureRegistry::new();
    registry.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03 SelfRemove group departure",
        },
    );
    for (feature, description) in [
        (
            AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE.clone(),
            "receive QUIC-backed agent text stream previews",
        ),
        (
            AGENT_TEXT_STREAM_QUIC_SEND_FEATURE.clone(),
            "send QUIC-backed agent text stream frames",
        ),
        (
            AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE.clone(),
            "fan out QUIC-backed agent text stream frames",
        ),
    ] {
        registry.register(
            feature,
            CapabilityRequirement {
                requires: Capability::AppComponent(AGENT_TEXT_STREAM_QUIC_COMPONENT_ID),
                level: RequirementLevel::Optional,
                description,
            },
        );
    }
    registry
}

fn role_names(mask: u8) -> Vec<String> {
    let mut roles = Vec::new();
    if mask & AGENT_TEXT_STREAM_ROLE_RECEIVE != 0 {
        roles.push("receive".to_owned());
    }
    if mask & AGENT_TEXT_STREAM_ROLE_SEND != 0 {
        roles.push("send".to_owned());
    }
    if mask & AGENT_TEXT_STREAM_ROLE_FANOUT != 0 {
        roles.push("fanout".to_owned());
    }
    roles
}

#[derive(Clone)]
struct AppTransportRouting {
    inner: Arc<RwLock<AppRoutingState>>,
}

#[derive(Clone, Debug)]
struct AppRoutingState {
    local_inbox_endpoints: Vec<TransportEndpoint>,
    key_package_endpoints: Vec<TransportEndpoint>,
    inbox_routes: HashMap<MemberId, Vec<TransportEndpoint>>,
    group_routes: Vec<TransportGroupSubscription>,
    required_acks: usize,
}

impl AppTransportRouting {
    fn new(state: AppRoutingState) -> Self {
        Self {
            inner: Arc::new(RwLock::new(state)),
        }
    }

    fn add_group(&self, group: TransportGroupSubscription) {
        let mut state = self.write();
        if state
            .group_routes
            .iter()
            .any(|existing| existing.group_id == group.group_id)
        {
            return;
        }
        state.group_routes.push(group);
    }

    fn snapshot(&self) -> AppRoutingState {
        self.read().clone()
    }

    fn replace(&self, state: AppRoutingState) {
        *self.write() = state;
    }

    fn read(&self) -> RwLockReadGuard<'_, AppRoutingState> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, AppRoutingState> {
        self.inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl TransportRoutingPolicy for AppTransportRouting {
    fn local_inbox_endpoints(&self) -> Vec<TransportEndpoint> {
        self.read().local_inbox_endpoints.clone()
    }

    fn key_package_endpoints(&self) -> Vec<TransportEndpoint> {
        self.read().key_package_endpoints.clone()
    }

    fn group_subscriptions(&self) -> Vec<TransportGroupSubscription> {
        self.read().group_routes.clone()
    }

    fn publish_target(
        &self,
        message: &TransportMessage,
    ) -> Result<TransportPublishTarget, TransportRoutingError> {
        let state = self.read();
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
        self.read().required_acks
    }
}

#[derive(Clone)]
struct AppKeyPackagePublisher {
    app: MarmotApp,
    account_label: String,
    keys: nostr::Keys,
    app_components: Vec<String>,
}

#[derive(Clone)]
struct NostrAccountIdentityProofSigner {
    keys: nostr::Keys,
}

impl AccountIdentityProofSigner for NostrAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.keys.public_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match local Nostr key".into());
        }
        let message = nostr::secp256k1::Message::from_digest(request.signing_digest());
        Ok(self.keys.sign_schnorr(&message).serialize())
    }
}

#[async_trait]
impl KeyPackagePublisher for AppKeyPackagePublisher {
    async fn publish_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<(), KeyPackagePublishError> {
        let metadata = key_package_metadata(&publication.key_package)
            .map_err(|e| KeyPackagePublishError(e.to_string()))?;
        if metadata.credential_identity_hex != hex::encode(publication.account_id.as_slice()) {
            return Err(KeyPackagePublishError(
                "KeyPackage credential identity does not match publication account".into(),
            ));
        }
        let mut slot_id = [0_u8; 32];
        OsRng.fill_bytes(&mut slot_id);
        let key_package_id = hex::encode(slot_id);
        let relay_client = self
            .app
            .relay_client_for_endpoints(&self.keys, &publication.endpoints);
        let nostr_publication = NostrKeyPackagePublication {
            account_id: publication.account_id.clone(),
            key_package: publication.key_package.clone(),
            key_package_slot_id: key_package_id.clone(),
            key_package_ref: metadata.key_package_ref_hex,
            mls_ciphersuite: "0x0001".into(),
            mls_extensions: vec![
                "0x0006".into(),
                format!("0x{ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE:04x}"),
                "0x000a".into(),
            ],
            mls_proposals: vec!["0x0008".into(), "0x000a".into()],
            app_components: self.app_components.clone(),
            publish_endpoints: publication.endpoints.clone(),
        };
        let outcome = NostrKeyPackagePublisher::new(relay_client)
            .publish_key_package(&nostr_publication)
            .await
            .map_err(|e| KeyPackagePublishError(e.to_string()))?;
        let key_package_event_id = outcome
            .message_id
            .map(|message_id| hex::encode(message_id.as_slice()))
            .unwrap_or_default();

        let dir = self.app.key_package_cache_dir().join(KEY_PACKAGE_DIR);
        fs::create_dir_all(&dir).map_err(|e| KeyPackagePublishError(e.to_string()))?;
        write_json(
            dir.join(format!("{}.json", self.account_label)),
            &KeyPackageRecord {
                account_label: self.account_label.clone(),
                account_id_hex: hex::encode(publication.account_id.as_slice()),
                key_package_id,
                key_package_event_id,
                key_package_hex: hex::encode(publication.key_package.bytes()),
            },
        )
        .map_err(|e| KeyPackagePublishError(e.to_string()))
    }
}

fn relay_list_status_from_records(
    account_id_hex: &str,
    mut records: Vec<RelayEventRecord>,
) -> AccountRelayListStatus {
    sort_directory_records(&mut records);
    let mut status = AccountRelayListStatus::empty();
    for record in records {
        if record.event.pubkey != account_id_hex {
            continue;
        }
        let relays = relays_from_relay_list_event(&record.event);
        if relays.is_empty() {
            continue;
        }
        match record.event.kind {
            KIND_NIP65_RELAY_LIST => status.nip65.relays = relays,
            KIND_MARMOT_INBOX_RELAY_LIST => status.inbox.relays = relays,
            KIND_MARMOT_KEY_PACKAGE_RELAY_LIST => status.key_package.relays = relays,
            _ => continue,
        }
        push_unique_strings(
            &mut status.bootstrap_relays,
            record
                .endpoints
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect::<Vec<_>>(),
        );
    }
    status.refresh();
    status
}

fn fresh_relay_list_status_from_records(
    account_id_hex: &str,
    mut records: Vec<RelayEventRecord>,
    freshness: DirectoryFreshness,
) -> DirectorySelection<AccountRelayListStatus> {
    let mut rejected_future = false;
    records.retain(|record| {
        if record.event.pubkey != account_id_hex
            || !matches!(
                record.event.kind,
                KIND_NIP65_RELAY_LIST
                    | KIND_MARMOT_INBOX_RELAY_LIST
                    | KIND_MARMOT_KEY_PACKAGE_RELAY_LIST
            )
        {
            return true;
        }
        let accepted = freshness.accepts(record);
        rejected_future |= !accepted;
        accepted
    });
    DirectorySelection {
        value: relay_list_status_from_records(account_id_hex, records),
        rejected_future,
    }
}

fn relay_list_queries(account_id_hex: String) -> Vec<DirectoryEventQuery> {
    [
        KIND_NIP65_RELAY_LIST,
        KIND_MARMOT_INBOX_RELAY_LIST,
        KIND_MARMOT_KEY_PACKAGE_RELAY_LIST,
    ]
    .into_iter()
    .map(|kind| DirectoryEventQuery::new(kind, vec![account_id_hex.clone()], 12))
    .collect()
}

fn latest_key_package_from_records(
    account_id_hex: &str,
    mut records: Vec<RelayEventRecord>,
) -> Result<FetchedKeyPackage, AppError> {
    sort_directory_records(&mut records);
    let mut latest = None;
    for record in records {
        if record.event.kind != KIND_MARMOT_KEY_PACKAGE || record.event.pubkey != account_id_hex {
            continue;
        }
        latest = Some(key_package_from_record(record)?);
    }
    latest.ok_or_else(|| AppError::MissingKeyPackage(account_id_hex.to_owned()))
}

fn latest_fresh_key_package_from_records(
    account_id_hex: &str,
    mut records: Vec<RelayEventRecord>,
    freshness: DirectoryFreshness,
) -> Result<DirectorySelection<Option<FetchedKeyPackage>>, AppError> {
    let mut rejected_future = false;
    records.retain(|record| {
        if record.event.kind != KIND_MARMOT_KEY_PACKAGE || record.event.pubkey != account_id_hex {
            return true;
        }
        let accepted = freshness.accepts(record);
        rejected_future |= !accepted;
        accepted
    });
    match latest_key_package_from_records(account_id_hex, records) {
        Ok(value) => Ok(DirectorySelection {
            value: Some(value),
            rejected_future,
        }),
        Err(AppError::MissingKeyPackage(_)) => Ok(DirectorySelection {
            value: None,
            rejected_future,
        }),
        Err(err) => Err(err),
    }
}

fn cached_key_package_from_entry(
    entry: UserDirectoryRecord,
) -> Result<Option<FetchedKeyPackage>, AppError> {
    let Some(key_package) = entry.key_package else {
        return Ok(None);
    };
    let decoded = validated_cached_key_package(&entry.account_id_hex, &key_package)?;
    Ok(Some(FetchedKeyPackage {
        account_id_hex: entry.account_id_hex,
        key_package: decoded,
        key_package_id: key_package.key_package_id,
        key_package_event_id: key_package.key_package_event_id,
        created_at: key_package.created_at,
        source_relays: key_package.source_relays,
        relay_lists: entry.relay_lists,
    }))
}

fn validated_cached_key_package(
    account_id_hex: &str,
    key_package: &DirectoryKeyPackage,
) -> Result<KeyPackage, AppError> {
    let decoded = key_package_from_hex_with_optional_source(
        &key_package.key_package_hex,
        &key_package.key_package_event_id,
    )?;
    let metadata = key_package_metadata(&decoded)
        .map_err(|e| AppError::InvalidKeyPackageEvent(e.to_string()))?;
    if metadata.credential_identity_hex != account_id_hex {
        return Err(AppError::InvalidKeyPackageEvent(
            "cached KeyPackage credential identity does not match directory account".into(),
        ));
    }
    Ok(decoded)
}

fn key_package_from_hex_with_optional_source(
    key_package_hex: &str,
    event_id_hex: &str,
) -> Result<KeyPackage, AppError> {
    let bytes = hex::decode(key_package_hex)?;
    if event_id_hex.is_empty() {
        return Ok(KeyPackage::new(bytes));
    }
    Ok(KeyPackage::with_source_event_id(
        bytes,
        key_package_event_id_from_hex(event_id_hex)?,
    ))
}

fn key_package_event_id_from_hex(event_id_hex: &str) -> Result<MessageId, AppError> {
    let bytes = hex::decode(event_id_hex)?;
    if bytes.len() != 32 {
        return Err(AppError::InvalidKeyPackageEvent(format!(
            "KeyPackage event id must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(MessageId::new(bytes))
}

fn relay_lists_have_any_relays(status: &AccountRelayListStatus) -> bool {
    !status.nip65.relays.is_empty()
        || !status.inbox.relays.is_empty()
        || !status.key_package.relays.is_empty()
}

fn fill_missing_relay_lists_from_cached(
    status: &mut AccountRelayListStatus,
    cached: &AccountRelayListStatus,
) {
    if status.nip65.relays.is_empty() {
        status.nip65.relays = cached.nip65.relays.clone();
    }
    if status.inbox.relays.is_empty() {
        status.inbox.relays = cached.inbox.relays.clone();
    }
    if status.key_package.relays.is_empty() {
        status.key_package.relays = cached.key_package.relays.clone();
    }
    if status.bootstrap_relays.is_empty() {
        status.bootstrap_relays = cached.bootstrap_relays.clone();
    }
    status.refresh();
}

fn fresh_or_cached_key_package(
    account_id_hex: &str,
    selection: DirectorySelection<Option<FetchedKeyPackage>>,
    cached_entry: Option<UserDirectoryRecord>,
) -> Result<FetchedKeyPackage, AppError> {
    if let Some(fetched) = selection.value {
        return Ok(fetched);
    }
    if selection.rejected_future
        && let Some(cached) = cached_entry
            .map(cached_key_package_from_entry)
            .transpose()?
            .flatten()
    {
        return Ok(cached);
    }
    Err(AppError::MissingKeyPackage(account_id_hex.to_owned()))
}

fn key_package_from_record(record: RelayEventRecord) -> Result<FetchedKeyPackage, AppError> {
    let event = record.event;
    require_key_package_tag(&event, "mls_protocol_version", |value| value == "1.0")?;
    let key_package_id = event
        .tag_value("d")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::InvalidKeyPackageEvent("missing d tag".into()))?
        .to_owned();
    let key_package_ref = event
        .tag_value("i")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::InvalidKeyPackageEvent("missing i tag".into()))?
        .to_owned();
    require_key_package_tag(&event, "mls_ciphersuite", |value| !value.is_empty())?;
    require_multi_value_key_package_tag(&event, "mls_extensions")?;
    require_multi_value_key_package_tag_contains(
        &event,
        "mls_extensions",
        &format!("0x{ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE:04x}"),
    )?;
    require_multi_value_key_package_tag(&event, "mls_proposals")?;
    require_multi_value_key_package_tag(&event, "app_components")?;
    let key_package_bytes = BASE64_STANDARD
        .decode(event.content.as_bytes())
        .map_err(|e| AppError::InvalidKeyPackageEvent(format!("invalid base64 content: {e}")))?;
    if key_package_bytes.is_empty() {
        return Err(AppError::InvalidKeyPackageEvent(
            "empty key package content".into(),
        ));
    }
    let key_package = KeyPackage::with_source_event_id(
        key_package_bytes,
        key_package_event_id_from_hex(&event.id)?,
    );
    let metadata = key_package_metadata(&key_package)
        .map_err(|e| AppError::InvalidKeyPackageEvent(e.to_string()))?;
    if metadata.credential_identity_hex != event.pubkey {
        return Err(AppError::InvalidKeyPackageEvent(
            "transport author does not match KeyPackage credential identity".into(),
        ));
    }
    if metadata.key_package_ref_hex != key_package_ref {
        return Err(AppError::InvalidKeyPackageEvent(
            "i tag does not match decoded KeyPackageRef".into(),
        ));
    }
    let mut source_relays = Vec::new();
    push_unique_strings(
        &mut source_relays,
        record
            .endpoints
            .into_iter()
            .map(|endpoint| endpoint.0)
            .collect::<Vec<_>>(),
    );
    Ok(FetchedKeyPackage {
        account_id_hex: event.pubkey,
        key_package,
        key_package_id,
        key_package_event_id: event.id,
        created_at: event.created_at,
        source_relays,
        relay_lists: AccountRelayListStatus::empty(),
    })
}

fn require_key_package_tag(
    event: &NostrTransportEvent,
    name: &str,
    predicate: impl FnOnce(&str) -> bool,
) -> Result<(), AppError> {
    match event.tag_value(name) {
        Some(value) if predicate(value) => Ok(()),
        Some(value) => Err(AppError::InvalidKeyPackageEvent(format!(
            "invalid {name} tag: {value}"
        ))),
        None => Err(AppError::InvalidKeyPackageEvent(format!(
            "missing {name} tag"
        ))),
    }
}

fn require_multi_value_key_package_tag(
    event: &NostrTransportEvent,
    name: &str,
) -> Result<(), AppError> {
    let Some(tag) = event
        .tags
        .iter()
        .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
    else {
        return Err(AppError::InvalidKeyPackageEvent(format!(
            "missing {name} tag"
        )));
    };
    if tag.iter().skip(1).any(|value| !value.trim().is_empty()) {
        Ok(())
    } else {
        Err(AppError::InvalidKeyPackageEvent(format!(
            "empty {name} tag"
        )))
    }
}

fn require_multi_value_key_package_tag_contains(
    event: &NostrTransportEvent,
    name: &str,
    required: &str,
) -> Result<(), AppError> {
    let Some(tag) = event
        .tags
        .iter()
        .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
    else {
        return Err(AppError::InvalidKeyPackageEvent(format!(
            "missing {name} tag"
        )));
    };
    if tag
        .iter()
        .skip(1)
        .any(|value| value.eq_ignore_ascii_case(required))
    {
        Ok(())
    } else {
        Err(AppError::InvalidKeyPackageEvent(format!(
            "{name} tag missing required value {required}"
        )))
    }
}

fn publish_endpoints_from_bootstrap(
    bootstrap: &AccountRelayListBootstrap,
) -> Vec<TransportEndpoint> {
    if bootstrap.bootstrap_relays.is_empty() {
        bootstrap.default_relays.clone()
    } else {
        bootstrap.bootstrap_relays.clone()
    }
}

fn profile_content_json(profile: &UserProfileMetadata) -> serde_json::Value {
    let mut value = serde_json::Map::new();
    if let Some(name) = profile.name.as_ref().filter(|value| !value.is_empty()) {
        value.insert("name".to_owned(), serde_json::Value::String(name.clone()));
    }
    if let Some(display_name) = profile
        .display_name
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        value.insert(
            "display_name".to_owned(),
            serde_json::Value::String(display_name.clone()),
        );
    }
    if let Some(about) = profile.about.as_ref().filter(|value| !value.is_empty()) {
        value.insert("about".to_owned(), serde_json::Value::String(about.clone()));
    }
    if let Some(picture) = profile.picture.as_ref().filter(|value| !value.is_empty()) {
        value.insert(
            "picture".to_owned(),
            serde_json::Value::String(picture.clone()),
        );
    }
    if let Some(nip05) = profile.nip05.as_ref().filter(|value| !value.is_empty()) {
        value.insert("nip05".to_owned(), serde_json::Value::String(nip05.clone()));
    }
    if let Some(lud16) = profile.lud16.as_ref().filter(|value| !value.is_empty()) {
        value.insert("lud16".to_owned(), serde_json::Value::String(lud16.clone()));
    }
    serde_json::Value::Object(value)
}

fn display_name_for_profile(profile: Option<&UserProfileMetadata>) -> Option<String> {
    let profile = profile?;
    profile
        .display_name
        .as_deref()
        .or(profile.name.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn default_profile_pseudonym(account_id_hex: &str) -> String {
    let digest = Sha256::digest(account_id_hex.as_bytes());
    let adjective_index =
        u16::from_be_bytes([digest[0], digest[1]]) as usize % DEFAULT_PROFILE_ADJECTIVES.len();
    let noun_index =
        u16::from_be_bytes([digest[2], digest[3]]) as usize % DEFAULT_PROFILE_NOUNS.len();
    format!(
        "{} {}",
        DEFAULT_PROFILE_ADJECTIVES[adjective_index], DEFAULT_PROFILE_NOUNS[noun_index]
    )
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryFreshness {
    max_created_at: u64,
}

impl DirectoryFreshness {
    fn from_now(max_future_skew: Duration) -> Self {
        Self {
            max_created_at: unix_now_seconds().saturating_add(max_future_skew.as_secs()),
        }
    }

    fn accepts(self, record: &RelayEventRecord) -> bool {
        record.event.created_at <= self.max_created_at
    }
}

#[derive(Debug)]
struct DirectorySelection<T> {
    value: T,
    rejected_future: bool,
}

fn sort_directory_records(records: &mut [RelayEventRecord]) {
    records.sort_by(|a, b| {
        a.event
            .created_at
            .cmp(&b.event.created_at)
            .then_with(|| a.event.id.cmp(&b.event.id))
    });
}

fn latest_follow_list_from_records(
    account_id_hex: &str,
    mut records: Vec<RelayEventRecord>,
    freshness: DirectoryFreshness,
) -> DirectorySelection<Option<FetchedFollowList>> {
    let mut rejected_future = false;
    records.retain(|record| {
        if record.event.kind != KIND_NOSTR_CONTACT_LIST || record.event.pubkey != account_id_hex {
            return true;
        }
        let accepted = freshness.accepts(record);
        rejected_future |= !accepted;
        accepted
    });
    sort_directory_records(&mut records);
    let value = records.into_iter().rev().find_map(|record| {
        if record.event.kind == KIND_NOSTR_CONTACT_LIST && record.event.pubkey == account_id_hex {
            Some(follow_list_from_record(record))
        } else {
            None
        }
    });
    DirectorySelection {
        value,
        rejected_future,
    }
}

fn follow_list_from_record(record: RelayEventRecord) -> FetchedFollowList {
    let mut follows = record
        .event
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|name| name == "p"))
        .filter_map(|tag| tag.get(1))
        .filter_map(|value| parse_account_id_hex(value).ok())
        .collect::<Vec<_>>();
    follows.sort();
    follows.dedup();
    FetchedFollowList {
        follows,
        source_relays: source_relays_from_record(&record),
    }
}

fn latest_profiles_from_records(
    mut records: Vec<RelayEventRecord>,
) -> HashMap<String, UserProfileMetadata> {
    sort_directory_records(&mut records);
    let mut profiles = HashMap::new();
    for record in records {
        if record.event.kind == KIND_NOSTR_METADATA
            && let Some(profile) = profile_from_record(record)
        {
            profiles.insert(profile.0, profile.1);
        }
    }
    profiles
}

fn latest_fresh_profiles_from_records(
    mut records: Vec<RelayEventRecord>,
    freshness: DirectoryFreshness,
) -> DirectorySelection<HashMap<String, UserProfileMetadata>> {
    let mut rejected_future = false;
    records.retain(|record| {
        if record.event.kind != KIND_NOSTR_METADATA {
            return true;
        }
        let accepted = freshness.accepts(record);
        rejected_future |= !accepted;
        accepted
    });
    DirectorySelection {
        value: latest_profiles_from_records(records),
        rejected_future,
    }
}

fn profile_from_record(record: RelayEventRecord) -> Option<(String, UserProfileMetadata)> {
    let content = serde_json::from_str::<serde_json::Value>(&record.event.content).ok()?;
    Some((
        record.event.pubkey.clone(),
        UserProfileMetadata {
            name: string_field(&content, "name"),
            display_name: string_field(&content, "display_name")
                .or_else(|| string_field(&content, "displayName")),
            about: string_field(&content, "about"),
            picture: string_field(&content, "picture"),
            nip05: string_field(&content, "nip05"),
            lud16: string_field(&content, "lud16"),
            created_at: record.event.created_at,
            source_relays: source_relays_from_record(&record),
        },
    ))
}

/// Defensive cap on any single ingested profile field. Nostr kind:0 content
/// is attacker-controlled (anyone can publish any metadata to a relay), so we
/// bound each field to keep a malicious multi-megabyte value from bloating the
/// directory cache and downstream consumers. 4096 chars is generous for any
/// legitimate name/about/url. Char-based (not byte) truncation keeps the
/// result valid UTF-8.
const MAX_PROFILE_FIELD_CHARS: usize = 4096;

fn string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(MAX_PROFILE_FIELD_CHARS).collect())
}

fn source_relays_from_record(record: &RelayEventRecord) -> Vec<String> {
    let mut relays = record
        .endpoints
        .iter()
        .map(|endpoint| endpoint.0.clone())
        .collect::<Vec<_>>();
    relays.sort();
    relays.dedup();
    relays
}

#[derive(Clone, Debug)]
struct UserRecordMatch {
    field: String,
    quality: String,
}

fn user_record_match(record: &UserDirectoryRecord, query: &str) -> Option<UserRecordMatch> {
    let mut candidates = vec![
        ("npub", record.npub.as_str()),
        ("pubkey", record.account_id_hex.as_str()),
    ];
    if let Some(profile) = &record.profile {
        if let Some(name) = profile.name.as_deref() {
            candidates.push(("name", name));
        }
        if let Some(nip05) = profile.nip05.as_deref() {
            candidates.push(("nip05", nip05));
        }
        if let Some(display_name) = profile.display_name.as_deref() {
            candidates.push(("display_name", display_name));
        }
        if let Some(about) = profile.about.as_deref() {
            candidates.push(("about", about));
        }
    }

    candidates
        .into_iter()
        .filter_map(|(field, value)| {
            let value = value.to_lowercase();
            let quality = if value == query {
                "exact"
            } else if value.starts_with(query) {
                "prefix"
            } else if value.contains(query) {
                "contains"
            } else {
                return None;
            };
            Some(UserRecordMatch {
                field: field.to_owned(),
                quality: quality.to_owned(),
            })
        })
        .min_by(|a, b| {
            match_quality_rank(&a.quality)
                .cmp(&match_quality_rank(&b.quality))
                .then_with(|| field_rank(&a.field).cmp(&field_rank(&b.field)))
        })
}

fn match_quality_rank(quality: &str) -> u8 {
    match quality {
        "exact" => 0,
        "prefix" => 1,
        "contains" => 2,
        _ => 3,
    }
}

fn field_rank(field: &str) -> u8 {
    match field {
        "name" => 0,
        "nip05" => 1,
        "display_name" => 2,
        "about" => 3,
        "npub" => 4,
        "pubkey" => 5,
        _ => 6,
    }
}

fn parse_account_id_hex(value: &str) -> Result<String, AppError> {
    PublicKey::parse(value)
        .map(|pubkey| pubkey.to_hex())
        .map_err(|_| AppError::InvalidPublicKey)
}

fn normalize_group_id_hex_app(value: &str) -> Result<String, AppError> {
    let normalized = value.trim().to_ascii_lowercase();
    let bytes = hex::decode(&normalized)?;
    if bytes.is_empty() {
        return Err(AppError::UnknownGroup(value.to_owned()));
    }
    Ok(normalized)
}

fn admin_pubkey_from_account_id_hex(account_id_hex: &str) -> Result<[u8; 32], AppError> {
    let bytes = hex::decode(parse_account_id_hex(account_id_hex)?)?;
    bytes.try_into().map_err(|_| AppError::InvalidPublicKey)
}

fn admin_pubkey_from_member_id(member_id: &MemberId) -> Result<[u8; 32], AppError> {
    member_id
        .as_slice()
        .try_into()
        .map_err(|_| AppError::InvalidPublicKey)
}

fn normalize_account_ids(values: Vec<String>) -> Result<Vec<String>, AppError> {
    let mut values = values
        .into_iter()
        .map(|value| parse_account_id_hex(&value))
        .collect::<Result<Vec<_>, _>>()?;
    values.sort();
    values.dedup();
    Ok(values)
}

/// Convert a hex Nostr public key (account id) into its `npub…` bech32 form.
/// Public so embedders (FFI/UI) can render npubs instead of raw hex.
pub fn npub_for_account_id(account_id_hex: &str) -> Result<String, AppError> {
    PublicKey::parse(account_id_hex)
        .map_err(|_| AppError::InvalidPublicKey)?
        .to_bech32()
        .map_err(|_| AppError::InvalidPublicKey)
}

/// Normalize any public-key reference (npub bech32 or hex) into canonical
/// hex account id. Public so embedders can resolve scanned/typed npubs.
pub fn account_id_hex_from_ref(reference: &str) -> Result<String, AppError> {
    Ok(PublicKey::parse(reference)
        .map_err(|_| AppError::InvalidPublicKey)?
        .to_hex())
}

fn npub_for_account_id_lossy(account_id_hex: &str) -> String {
    npub_for_account_id(account_id_hex).unwrap_or_else(|_| account_id_hex.to_owned())
}

fn sqlite_file_requires_key(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    Connection::open(path)
        .and_then(|conn| {
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            })
        })
        .is_err()
}

fn sqlcipher_salt_path(db_path: &Path) -> PathBuf {
    let Some(file_name) = db_path.file_name() else {
        return db_path.with_extension("salt");
    };
    let mut salt_file_name = file_name.to_os_string();
    salt_file_name.push(SQLCIPHER_SALT_SUFFIX);
    db_path.with_file_name(salt_file_name)
}

fn read_sqlcipher_salt(path: &Path) -> Result<[u8; SQLCIPHER_SALT_LEN], AppError> {
    let raw = fs::read_to_string(path)?;
    let bytes = hex::decode(raw.trim())?;
    bytes.try_into().map_err(|_| {
        AppError::SqlcipherKeyDerivation(format!("invalid salt length in {}", path.display()))
    })
}

fn write_sqlcipher_salt(path: &Path, salt: &[u8; SQLCIPHER_SALT_LEN]) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, hex::encode(salt))?;
    Ok(())
}

fn derive_sqlcipher_key_material(
    label: &str,
    keys: &nostr::Keys,
    salt: &[u8; SQLCIPHER_SALT_LEN],
    kind: SqlcipherDatabaseKind,
) -> Result<String, AppError> {
    let secret = keys.secret_key().to_secret_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &secret);
    let mut info = Vec::new();
    encode_hkdf_part(&mut info, b"marmot-app-sqlcipher-key");
    encode_hkdf_part(&mut info, kind.hkdf_info_label());
    encode_hkdf_part(&mut info, label.as_bytes());
    encode_hkdf_part(&mut info, keys.public_key().to_bytes().as_slice());
    let mut output = [0_u8; SQLCIPHER_KEY_LEN];
    hkdf.expand(&info, &mut output)
        .map_err(|_| AppError::SqlcipherKeyDerivation("HKDF output length rejected".into()))?;
    Ok(hex::encode(output))
}

fn legacy_sqlcipher_key_material(
    label: &str,
    keys: &nostr::Keys,
    kind: SqlcipherDatabaseKind,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.legacy_hash_label());
    hasher.update(label.as_bytes());
    hasher.update(keys.public_key().to_bytes());
    hasher.update(keys.secret_key().to_secret_bytes());
    hex::encode(hasher.finalize())
}

fn encode_hkdf_part(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn rekey_legacy_sqlcipher_database(
    db_path: &Path,
    legacy_key: &SqlCipherKey,
    new_key: &SqlCipherKey,
) -> Result<(), AppError> {
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "key", legacy_key.as_secret_str())?;
    let _: i64 = conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
    conn.pragma_update(None, "rekey", new_key.as_secret_str())?;
    Ok(())
}

fn remove_sqlite_file_set(path: &Path) -> Result<(), AppError> {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        match fs::remove_file(candidate) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn relays_from_relay_list_event(event: &NostrTransportEvent) -> Vec<String> {
    let tag_name = match event.kind {
        KIND_NIP65_RELAY_LIST => "r",
        KIND_MARMOT_INBOX_RELAY_LIST | KIND_MARMOT_KEY_PACKAGE_RELAY_LIST => "relay",
        _ => return Vec::new(),
    };
    let mut relays = Vec::new();
    for tag in &event.tags {
        if tag.first().is_some_and(|name| name == tag_name)
            && let Some(value) = tag.get(1).filter(|value| !value.trim().is_empty())
        {
            push_unique_strings(&mut relays, [value.clone()]);
        }
    }
    relays
}

fn push_unique_strings(values: &mut Vec<String>, candidates: impl IntoIterator<Item = String>) {
    for candidate in candidates {
        if !values.contains(&candidate) {
            values.push(candidate);
        }
    }
}

struct EventGroupProjection<'a> {
    nostr_routing: AppGroupNostrRoutingComponent,
    group_metadata: Option<&'a Group>,
    admin_policy: AppGroupAdminPolicyComponent,
    message_retention: AppGroupMessageRetentionComponent,
    agent_text_stream: AppAgentTextStreamComponent,
}

/// Strictly decode the inner Marmot app event from MLS plaintext and bind it to
/// the MLS-authenticated sender. Returns `None` (rejecting the message) when the
/// canonical id does not match or the inner `pubkey` is not the authenticated
/// sender — both are integrity failures that must not reach the timeline.
fn decode_received_event(
    payload: &[u8],
    sender_hex: &str,
    sender_display_name: Option<String>,
    group_id: &GroupId,
    _source_message_id_hex: &str,
) -> Option<ReceivedMessage> {
    let event = match MarmotInnerEvent::decode(payload) {
        Ok(event) => event,
        Err(_) => {
            tracing::warn!(
                target: "marmot_app::ingest",
                method = "decode_received_event",
                "rejecting MLS application message: inner app event failed strict decode",
            );
            return None;
        }
    };
    if event.validate_sender(sender_hex).is_err() {
        tracing::warn!(
            target: "marmot_app::ingest",
            method = "decode_received_event",
            "rejecting MLS application message: inner author is not the authenticated sender",
        );
        return None;
    }
    if event.kind == MARMOT_APP_EVENT_KIND_CHAT
        && event
            .tags
            .iter()
            .any(|tag| tag.first().map(String::as_str) == Some("imeta"))
        && !media_imeta_is_valid(&event.tags)
    {
        tracing::warn!(
            target: "marmot_app::ingest",
            method = "decode_received_event",
            "rejecting MLS application message: invalid encrypted media reference",
        );
        return None;
    }
    Some(ReceivedMessage {
        message_id_hex: event.id,
        sender: sender_hex.to_owned(),
        sender_display_name,
        group_id: group_id.clone(),
        plaintext: event.content,
        kind: event.kind,
        tags: event.tags,
    })
}

fn media_imeta_is_valid(tags: &[Vec<String>]) -> bool {
    let Some(imeta) = tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("imeta"))
    else {
        return true;
    };
    let fields = imeta
        .iter()
        .skip(1)
        .filter_map(|field| field.split_once(' '))
        .collect::<HashMap<_, _>>();
    let required = ["url", "m", "filename", "x", "n", "v"];
    if required
        .iter()
        .any(|name| fields.get(name).is_none_or(|value| value.trim().is_empty()))
    {
        return false;
    }
    if fields.get("v") != Some(&"mip04-v2") {
        return false;
    }
    match hex::decode(fields["x"]) {
        Ok(hash) if hash.len() == 32 => {}
        _ => return false,
    }
    match hex::decode(fields["n"]) {
        Ok(nonce) if nonce.len() == 12 => {}
        _ => return false,
    }
    true
}

fn observe_event(
    state: &mut AccountState,
    display_names: &HashMap<String, String>,
    summary: &mut SyncSummary,
    event: &GroupEvent,
    group_projection: Option<&EventGroupProjection<'_>>,
    source_message_id_hex: &str,
) -> Option<ReceivedMessage> {
    match event {
        GroupEvent::GroupJoined { group_id, .. } | GroupEvent::GroupCreated { group_id } => {
            if let Some(projection) = group_projection {
                add_group(
                    state,
                    group_id,
                    projection.nostr_routing.clone(),
                    projection.group_metadata,
                    projection.admin_policy.clone(),
                    projection.message_retention.clone(),
                    projection.agent_text_stream.clone(),
                );
            }
            summary.joined_groups.push(group_id.clone());
            summary.events.push(event.clone());
            None
        }
        GroupEvent::MessageReceived {
            group_id,
            sender,
            payload,
        } => {
            if let Some(projection) = group_projection {
                add_group(
                    state,
                    group_id,
                    projection.nostr_routing.clone(),
                    projection.group_metadata,
                    projection.admin_policy.clone(),
                    projection.message_retention.clone(),
                    projection.agent_text_stream.clone(),
                );
            }
            let sender_hex = hex::encode(sender.as_slice());
            let sender_display_name = display_names.get(&sender_hex).cloned();
            // The MLS layer authenticated `sender`; the inner Nostr-shaped event
            // must (1) carry a valid canonical id and (2) name `sender` as its
            // author. Reject anything that fails either check rather than
            // rendering an unauthenticated or tampered payload.
            let Some(message) = decode_received_event(
                payload,
                &sender_hex,
                sender_display_name,
                group_id,
                source_message_id_hex,
            ) else {
                summary.events.push(event.clone());
                return None;
            };
            summary.messages.push(message.clone());
            summary.events.push(event.clone());
            Some(message)
        }
        _ => {
            if let (Some(group_id), Some(projection)) = (event_group_id(event), group_projection) {
                add_group(
                    state,
                    group_id,
                    projection.nostr_routing.clone(),
                    projection.group_metadata,
                    projection.admin_policy.clone(),
                    projection.message_retention.clone(),
                    projection.agent_text_stream.clone(),
                );
            }
            summary.events.push(event.clone());
            None
        }
    }
}

fn event_group_id(event: &GroupEvent) -> Option<&GroupId> {
    match event {
        GroupEvent::GroupCreated { group_id }
        | GroupEvent::GroupJoined { group_id, .. }
        | GroupEvent::MessageReceived { group_id, .. }
        | GroupEvent::AppMessageInvalidated { group_id, .. }
        | GroupEvent::MemberAdded { group_id, .. }
        | GroupEvent::MemberRemoved { group_id, .. }
        | GroupEvent::EpochChanged { group_id, .. }
        | GroupEvent::ForkRecovered { group_id, .. }
        | GroupEvent::GroupUnrecoverable { group_id } => Some(group_id),
    }
}

fn add_group(
    state: &mut AccountState,
    group_id: &GroupId,
    nostr_routing: AppGroupNostrRoutingComponent,
    group_metadata: Option<&Group>,
    admin_policy: AppGroupAdminPolicyComponent,
    message_retention: AppGroupMessageRetentionComponent,
    agent_text_stream: AppAgentTextStreamComponent,
) {
    let group_id_hex = hex::encode(group_id.as_slice());
    if let Some(existing) = state
        .groups
        .iter_mut()
        .find(|group| group.group_id_hex == group_id_hex)
    {
        existing.refresh_from_group(
            nostr_routing,
            group_metadata,
            admin_policy,
            message_retention,
            agent_text_stream,
        );
        return;
    }
    state.groups.push(AppGroupRecord::from_group(
        group_id,
        nostr_routing,
        group_metadata,
        admin_policy,
        message_retention,
        agent_text_stream,
    ));
}

fn fail_if_publish_failed(failures: &[marmot_account::PublishFailure]) -> Result<(), AppError> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(AppError::Publish(
            failures
                .iter()
                .map(|failure| failure.reason.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        ))
    }
}

fn send_summary_from_effects(effects: &marmot_account::AccountDeviceEffects) -> SendSummary {
    SendSummary {
        published: effects.reports.len(),
        message_ids: effects
            .reports
            .iter()
            .map(|report| hex::encode(report.message_id.as_slice()))
            .collect(),
    }
}

#[derive(Debug, Deserialize)]
struct BlossomBlobDescriptor {
    url: Option<String>,
    sha256: Option<String>,
}

async fn upload_encrypted_media(
    request: MediaUploadRequest,
    exporter_secret: &[u8],
    signing_keys: &nostr::Keys,
) -> Result<MediaUploadResult, AppError> {
    if request.plaintext.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "media plaintext cannot be empty".into(),
        ));
    }
    let file_name = request.file_name.trim().to_owned();
    if file_name.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "media file name cannot be empty".into(),
        ));
    }
    let media_type = canonical_media_type(&request.media_type)?;
    let plaintext_hash: [u8; 32] = Sha256::digest(&request.plaintext).into();
    let file_hash_hex = hex::encode(plaintext_hash);
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let file_key =
        derive_media_file_key(exporter_secret, &plaintext_hash, &media_type, &file_name)?;
    let aad = media_aad(&plaintext_hash, &media_type, &file_name);
    let cipher = ChaCha20Poly1305::new_from_slice(&file_key)
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid media key length".into()))?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &request.plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::InvalidEncryptedMedia("media encryption failed".into()))?;
    let encrypted_hash_hex = hex::encode(Sha256::digest(&encrypted));
    let server = request
        .blossom_server
        .as_deref()
        .unwrap_or(DEFAULT_BLOSSOM_SERVER_URL);
    let url = upload_blossom_blob(server, &encrypted, &encrypted_hash_hex, signing_keys).await?;
    let reference = MediaReference {
        url,
        file_hash_hex,
        nonce_hex: hex::encode(nonce),
        file_name,
        media_type,
        version: ENCRYPTED_MEDIA_VERSION.to_owned(),
    };
    reference.validate()?;
    Ok(MediaUploadResult {
        reference,
        encrypted_hash_hex,
        encrypted_size_bytes: encrypted.len() as u64,
        sent: None,
    })
}

async fn download_encrypted_media(
    reference: MediaReference,
    exporter_secret: &[u8],
) -> Result<MediaDownloadResult, AppError> {
    reference.validate()?;
    let encrypted = fetch_blossom_blob(&reference.url).await?;
    let expected_encrypted_hash =
        blossom_content_hash_from_url(&reference.url).ok_or_else(|| {
            AppError::InvalidEncryptedMedia("media URL must include encrypted blob hash".into())
        })?;
    let actual_encrypted_hash = hex::encode(Sha256::digest(&encrypted));
    if actual_encrypted_hash != expected_encrypted_hash {
        return Err(AppError::InvalidEncryptedMedia(
            "encrypted blob hash does not match media URL".into(),
        ));
    }
    let plaintext_hash = media_hash_from_reference(&reference)?;
    let media_type = canonical_media_type(&reference.media_type)?;
    let nonce = media_nonce_from_reference(&reference)?;
    let file_key = derive_media_file_key(
        exporter_secret,
        &plaintext_hash,
        &media_type,
        &reference.file_name,
    )?;
    let aad = media_aad(&plaintext_hash, &media_type, &reference.file_name);
    let cipher = ChaCha20Poly1305::new_from_slice(&file_key)
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid media key length".into()))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &encrypted,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::InvalidEncryptedMedia("media decryption failed".into()))?;
    let actual_plaintext_hash: [u8; 32] = Sha256::digest(&plaintext).into();
    if actual_plaintext_hash != plaintext_hash {
        return Err(AppError::InvalidEncryptedMedia(
            "media plaintext hash does not match reference".into(),
        ));
    }
    Ok(MediaDownloadResult {
        size_bytes: plaintext.len() as u64,
        plaintext,
        file_name: reference.file_name,
        media_type,
    })
}

fn canonical_media_type(value: &str) -> Result<String, AppError> {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type.is_empty() || !media_type.contains('/') {
        return Err(AppError::InvalidEncryptedMedia(
            "media type must be a MIME type".into(),
        ));
    }
    Ok(match media_type.as_str() {
        "image/jpg" => "image/jpeg".to_owned(),
        other => other.to_owned(),
    })
}

fn media_hash_from_reference(reference: &MediaReference) -> Result<[u8; 32], AppError> {
    hex::decode(&reference.file_hash_hex)?
        .try_into()
        .map_err(|_| AppError::InvalidEncryptedMedia("media hash must be 32 bytes".into()))
}

fn media_nonce_from_reference(reference: &MediaReference) -> Result<[u8; 12], AppError> {
    hex::decode(&reference.nonce_hex)?
        .try_into()
        .map_err(|_| AppError::InvalidEncryptedMedia("media nonce must be 12 bytes".into()))
}

fn derive_media_file_key(
    exporter_secret: &[u8],
    file_hash: &[u8; 32],
    media_type: &str,
    file_name: &str,
) -> Result<[u8; 32], AppError> {
    let hkdf = Hkdf::<Sha256>::from_prk(exporter_secret).map_err(|_| {
        AppError::InvalidEncryptedMedia("invalid encrypted-media exporter secret".into())
    })?;
    let mut key = [0_u8; 32];
    hkdf.expand(&media_key_info(file_hash, media_type, file_name), &mut key)
        .map_err(|_| AppError::InvalidEncryptedMedia("media key derivation failed".into()))?;
    Ok(key)
}

fn media_key_info(file_hash: &[u8; 32], media_type: &str, file_name: &str) -> Vec<u8> {
    let mut info = Vec::with_capacity(
        ENCRYPTED_MEDIA_VERSION.len() + 1 + 32 + 1 + media_type.len() + 1 + file_name.len() + 4,
    );
    info.extend_from_slice(ENCRYPTED_MEDIA_VERSION.as_bytes());
    info.push(0);
    info.extend_from_slice(file_hash);
    info.push(0);
    info.extend_from_slice(media_type.as_bytes());
    info.push(0);
    info.extend_from_slice(file_name.as_bytes());
    info.push(0);
    info.extend_from_slice(b"key");
    info
}

fn media_aad(file_hash: &[u8; 32], media_type: &str, file_name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        ENCRYPTED_MEDIA_VERSION.len() + 1 + 32 + 1 + media_type.len() + 1 + file_name.len(),
    );
    aad.extend_from_slice(ENCRYPTED_MEDIA_VERSION.as_bytes());
    aad.push(0);
    aad.extend_from_slice(file_hash);
    aad.push(0);
    aad.extend_from_slice(media_type.as_bytes());
    aad.push(0);
    aad.extend_from_slice(file_name.as_bytes());
    aad
}

async fn upload_blossom_blob(
    server: &str,
    encrypted: &[u8],
    encrypted_hash_hex: &str,
    signing_keys: &nostr::Keys,
) -> Result<String, AppError> {
    let (upload_url, server_host) = blossom_upload_endpoint(server)?;
    let authorization =
        blossom_authorization_header(signing_keys, &server_host, encrypted_hash_hex)?;
    let response = reqwest::Client::new()
        .put(upload_url)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::CONTENT_TYPE, BLOSSOM_UPLOAD_CONTENT_TYPE)
        .header("X-SHA-256", encrypted_hash_hex)
        .body(encrypted.to_vec())
        .send()
        .await
        .map_err(reqwest_blob_error)?;
    if !response.status().is_success() {
        return Err(AppError::BlobStore(format!(
            "upload returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let descriptor = response
        .json::<BlossomBlobDescriptor>()
        .await
        .map_err(|_| AppError::BlobStore("upload returned an invalid descriptor".into()))?;
    if let Some(sha256) = descriptor.sha256.as_deref()
        && sha256.to_ascii_lowercase() != encrypted_hash_hex
    {
        return Err(AppError::BlobStore(
            "upload descriptor hash did not match encrypted blob".into(),
        ));
    }
    let url = descriptor
        .url
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| blossom_blob_url(server, encrypted_hash_hex));
    let content_hash = blossom_content_hash_from_url(&url).ok_or_else(|| {
        AppError::BlobStore("upload descriptor URL did not include encrypted blob hash".into())
    })?;
    if content_hash != encrypted_hash_hex {
        return Err(AppError::BlobStore(
            "upload descriptor URL hash did not match encrypted blob".into(),
        ));
    }
    Ok(url)
}

async fn fetch_blossom_blob(url: &str) -> Result<Vec<u8>, AppError> {
    let url = Url::parse(url)
        .map_err(|_| AppError::InvalidEncryptedMedia("media URL is invalid".into()))?;
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(reqwest_blob_error)?;
    if !response.status().is_success() {
        return Err(AppError::BlobStore(format!(
            "download returned HTTP {}",
            response.status().as_u16()
        )));
    }
    Ok(response.bytes().await.map_err(reqwest_blob_error)?.to_vec())
}

fn blossom_upload_endpoint(server: &str) -> Result<(Url, String), AppError> {
    let mut url = Url::parse(server.trim())
        .map_err(|_| AppError::BlobStore("invalid Blossom server URL".into()))?;
    match url.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(AppError::BlobStore(
                "Blossom server URL must be http or https".into(),
            ));
        }
    }
    let host = url
        .host_str()
        .ok_or_else(|| AppError::BlobStore("Blossom server URL is missing a host".into()))?
        .to_ascii_lowercase();
    url.set_path("upload");
    url.set_query(None);
    url.set_fragment(None);
    Ok((url, host))
}

fn blossom_blob_url(server: &str, encrypted_hash_hex: &str) -> String {
    match Url::parse(server.trim()) {
        Ok(mut url) => {
            url.set_path(&format!("{encrypted_hash_hex}.bin"));
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => format!(
            "{}/{}.bin",
            server.trim_end_matches('/'),
            encrypted_hash_hex
        ),
    }
}

fn blossom_content_hash_from_url(url: &str) -> Option<String> {
    let url = Url::parse(url).ok()?;
    let last = url.path_segments()?.next_back()?;
    let hash = last.split_once('.').map(|(hash, _)| hash).unwrap_or(last);
    if hash.len() == 64 && hex::decode(hash).is_ok() {
        Some(hash.to_ascii_lowercase())
    } else {
        None
    }
}

fn blossom_authorization_header(
    keys: &nostr::Keys,
    server_host: &str,
    encrypted_hash_hex: &str,
) -> Result<String, AppError> {
    let now = unix_now_seconds();
    let expiration = now + BLOSSOM_UPLOAD_AUTH_TTL.as_secs();
    let tags = [
        Tag::parse(["t", "upload"]),
        Tag::parse(["expiration", &expiration.to_string()]),
        Tag::parse(["x", encrypted_hash_hex]),
        Tag::parse(["server", server_host]),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|err| AppError::BlobStore(format!("failed to build Blossom auth tag: {err}")))?;
    let event = EventBuilder::new(Kind::Custom(24242), "Upload Blob")
        .tags(tags)
        .custom_created_at(NostrTimestamp::from(now))
        .sign_with_keys(keys)
        .map_err(|err| AppError::BlobStore(format!("failed to sign Blossom auth: {err}")))?;
    Ok(format!(
        "Nostr {}",
        BASE64_URL_SAFE_NO_PAD.encode(event.as_json())
    ))
}

fn reqwest_blob_error(err: reqwest::Error) -> AppError {
    if let Some(status) = err.status() {
        AppError::BlobStore(format!("HTTP {}", status.as_u16()))
    } else if err.is_timeout() {
        AppError::BlobStore("request timed out".into())
    } else if err.is_connect() {
        AppError::BlobStore("connection failed".into())
    } else if err.is_decode() {
        AppError::BlobStore("invalid response body".into())
    } else {
        AppError::BlobStore("request failed".into())
    }
}

/// Build the inner Marmot app event for `intent`, authored by `sender_pubkey_hex`
/// at `created_at`. `Unreact` must be resolved to a `Delete` of the reaction
/// event id before this is called (see [`AccountWorker`]'s unreact handling).
fn build_inner_event(
    intent: &AppMessageIntent,
    sender_pubkey_hex: &str,
    created_at: u64,
) -> Result<MarmotInnerEvent, AppError> {
    let event = |kind, tags, content| {
        MarmotInnerEvent::new(
            sender_pubkey_hex.to_owned(),
            created_at,
            kind,
            tags,
            content,
        )
    };
    match intent {
        AppMessageIntent::Chat { content } => Ok(event(
            MARMOT_APP_EVENT_KIND_CHAT,
            Vec::new(),
            content.clone(),
        )),
        AppMessageIntent::Reaction {
            target_message_id,
            emoji,
        } => {
            validate_message_ref(target_message_id)?;
            if emoji.trim().is_empty() {
                return Err(AppError::InvalidAppMessagePayload(
                    "reaction add requires a non-empty emoji".into(),
                ));
            }
            Ok(event(
                MARMOT_APP_EVENT_KIND_REACTION,
                vec![event_ref_tag(target_message_id)],
                emoji.clone(),
            ))
        }
        AppMessageIntent::Reply {
            target_message_id,
            text,
        } => {
            validate_message_ref(target_message_id)?;
            if text.trim().is_empty() {
                return Err(AppError::InvalidAppMessagePayload(
                    "reply requires non-empty text".into(),
                ));
            }
            Ok(event(
                MARMOT_APP_EVENT_KIND_CHAT,
                vec![
                    event_ref_tag(target_message_id),
                    vec![QUOTE_REF_TAG.to_owned(), target_message_id.clone()],
                ],
                text.clone(),
            ))
        }
        AppMessageIntent::Unreact { .. } | AppMessageIntent::Delete { .. } => {
            // `Unreact` is mapped to a `Delete` of the reaction event id by the
            // worker before reaching here; both encode as a kind-5 tombstone.
            let target_message_id = match intent {
                AppMessageIntent::Delete { target_message_id }
                | AppMessageIntent::Unreact { target_message_id } => target_message_id,
                _ => unreachable!(),
            };
            validate_message_ref(target_message_id)?;
            Ok(event(
                MARMOT_APP_EVENT_KIND_DELETE,
                vec![event_ref_tag(target_message_id)],
                String::new(),
            ))
        }
        AppMessageIntent::Media { reference, caption } => {
            reference.validate()?;
            Ok(event(
                MARMOT_APP_EVENT_KIND_CHAT,
                vec![reference.imeta_tag()],
                caption.clone().unwrap_or_default(),
            ))
        }
        AppMessageIntent::StreamStart {
            stream_id,
            quic_candidates,
        } => {
            let stream_id_hex = hex::encode(stream_id);
            if stream_id.len() != AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN {
                return Err(AppError::InvalidAppMessagePayload(
                    "agent text stream id must be 32 bytes".into(),
                ));
            }
            let brokers: Vec<&String> = quic_candidates
                .iter()
                .filter(|candidate| !candidate.trim().is_empty())
                .collect();
            if brokers.is_empty() {
                return Err(AppError::AgentStreamMissingCandidate);
            }
            let mut tags = vec![
                vec![STREAM_TAG.to_owned(), stream_id_hex],
                vec![STREAM_TYPE_TAG.to_owned(), STREAM_TYPE_TEXT.to_owned()],
                vec![
                    STREAM_FINAL_KIND_TAG.to_owned(),
                    STREAM_FINAL_KIND_CHAT.to_owned(),
                ],
                vec![STREAM_ROUTE_TAG.to_owned(), STREAM_ROUTE_QUIC.to_owned()],
            ];
            tags.extend(
                brokers
                    .into_iter()
                    .map(|candidate| vec![STREAM_BROKER_TAG.to_owned(), candidate.clone()]),
            );
            Ok(event(
                MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
                tags,
                String::new(),
            ))
        }
        AppMessageIntent::StreamFinal { request } => {
            if request.stream_id.len() != AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN {
                return Err(AppError::InvalidAppMessagePayload(
                    "agent text stream id must be 32 bytes".into(),
                ));
            }
            // spec/features/agent-text-streams-quic.md:310-318 — the stream-final
            // MUST carry the kind-1200 start event id so receivers can bind the
            // final message to the live preview stream.
            let start_event_id = hex::decode(&request.start_event_id).map_err(|_| {
                AppError::InvalidAppMessagePayload(
                    "agent text stream start event id must be 32-byte hex".into(),
                )
            })?;
            if start_event_id.len() != 32 {
                return Err(AppError::InvalidAppMessagePayload(
                    "agent text stream start event id must be 32-byte hex".into(),
                ));
            }
            let tags = vec![
                vec![STREAM_TAG.to_owned(), hex::encode(&request.stream_id)],
                vec![STREAM_START_TAG.to_owned(), request.start_event_id.clone()],
                vec![
                    STREAM_HASH_TAG.to_owned(),
                    hex::encode(request.transcript_hash),
                ],
                vec![
                    STREAM_CHUNKS_TAG.to_owned(),
                    request.chunk_count.to_string(),
                ],
            ];
            Ok(event(
                MARMOT_APP_EVENT_KIND_CHAT,
                tags,
                request.final_text_or_reference.clone(),
            ))
        }
    }
}

fn event_ref_tag(target_message_id: &str) -> Vec<String> {
    vec![EVENT_REF_TAG.to_owned(), target_message_id.to_owned()]
}

fn validate_message_ref(target_message_id: &str) -> Result<(), AppError> {
    if target_message_id.trim().is_empty() {
        return Err(AppError::InvalidAppMessagePayload(
            "target message id cannot be empty".into(),
        ));
    }
    Ok(())
}

/// Encode a built inner event into MLS application-message plaintext bytes.
fn encode_inner_event(event: &MarmotInnerEvent) -> Result<Vec<u8>, AppError> {
    event
        .encode()
        .map_err(|err| AppError::InvalidAppMessagePayload(err.to_string()))
}

/// True when an inner event is a kind-9 chat that finalizes an agent text
/// stream (it carries a `stream` tag plus a `stream-start` or `stream-hash`
/// tag). Such events flow as normal timeline messages, not start signals.
pub fn is_stream_final_event(kind: u64, tags: &[Vec<String>]) -> bool {
    kind == MARMOT_APP_EVENT_KIND_CHAT
        && tag_value(tags, STREAM_TAG).is_some()
        && (tag_value(tags, STREAM_START_TAG).is_some()
            || tag_value(tags, STREAM_HASH_TAG).is_some())
}

/// First value of the named tag (`tag[0] == name` → `tag[1]`).
pub fn tag_value<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
        .and_then(|tag| tag.get(1))
        .map(String::as_str)
}

/// All values of the named tag across every matching tag entry.
pub fn tag_values<'a>(tags: &'a [Vec<String>], name: &str) -> Vec<&'a str> {
    tags.iter()
        .filter(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
        .filter_map(|tag| tag.get(1))
        .map(String::as_str)
        .collect()
}

fn validate_group_profile(name: &str, description: &str) -> Result<(), AppError> {
    if name.len() > 256 {
        return Err(AppError::InvalidGroupProfile(
            "name must be at most 256 UTF-8 bytes".into(),
        ));
    }
    if description.len() > 4096 {
        return Err(AppError::InvalidGroupProfile(
            "description must be at most 4096 UTF-8 bytes".into(),
        ));
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> Result<T, AppError> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> Result<(), AppError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::Timestamp;

    fn relay_delivery(event_id: String, pubkey: String) -> cgka_traits::TransportDelivery {
        let event = NostrTransportEvent {
            id: event_id,
            pubkey,
            created_at: 1,
            kind: transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE,
            tags: vec![vec!["h".to_owned(), "aa".to_owned()]],
            content: "ciphertext".to_owned(),
            sig: None,
        };
        cgka_traits::TransportDelivery {
            account_id: MemberId::new(vec![0; 32]),
            group_id_hint: None,
            message: event.to_transport_message().unwrap(),
            received_at: cgka_traits::transport::Timestamp(1),
            source: cgka_traits::TransportDeliverySource {
                transport: cgka_traits::transport::TransportSource("nostr".to_owned()),
                plane: cgka_traits::TransportDeliveryPlane::Group,
                endpoint: None,
                subscription_id: None,
            },
        }
    }

    #[test]
    fn relay_list_discovery_builds_one_limited_query_per_required_kind() {
        let account_id_hex =
            "0000000000000000000000000000000000000000000000000000000000000001".to_owned();

        let queries = relay_list_queries(account_id_hex.clone());

        assert_eq!(queries.len(), 3);
        let kinds = queries
            .iter()
            .map(|query| {
                assert_eq!(query.authors, vec![account_id_hex.clone()]);
                assert_eq!(query.limit, 12);
                query.kind
            })
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                KIND_NIP65_RELAY_LIST,
                KIND_MARMOT_INBOX_RELAY_LIST,
                KIND_MARMOT_KEY_PACKAGE_RELAY_LIST
            ]
        );
    }

    #[test]
    fn directory_search_bounds_frontier_from_cached_follow_lists() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let cache = app.directory_cache_for_account(&account).unwrap();
        let follows = (0..USER_DIRECTORY_SEARCH_MAX_FRONTIER + 8)
            .map(|idx| format!("{:064x}", idx + 1))
            .collect::<Vec<_>>();

        cache
            .put(&UserDirectoryRecord {
                account_id_hex: account.account_id_hex.clone(),
                npub: npub_for_account_id_lossy(&account.account_id_hex),
                local_account: None,
                profile: None,
                follows: follows.clone(),
                follow_source_relays: Vec::new(),
                relay_lists: AccountRelayListStatus::empty(),
                key_package: None,
            })
            .unwrap();

        for follow in follows {
            cache
                .put(&UserDirectoryRecord {
                    account_id_hex: follow.clone(),
                    npub: npub_for_account_id_lossy(&follow),
                    local_account: None,
                    profile: Some(UserProfileMetadata {
                        name: Some("needle".into()),
                        display_name: None,
                        about: None,
                        picture: None,
                        nip05: None,
                        lud16: None,
                        created_at: 0,
                        source_relays: Vec::new(),
                    }),
                    follows: Vec::new(),
                    follow_source_relays: Vec::new(),
                    relay_lists: AccountRelayListStatus::empty(),
                    key_package: None,
                })
                .unwrap();
        }

        let results = app
            .search_user_directory(UserDirectorySearch {
                searcher_account_id_hex: account.account_id_hex,
                query: "needle".into(),
                radius_start: 1,
                radius_end: 1,
                limit: None,
            })
            .unwrap();

        assert_eq!(results.len(), USER_DIRECTORY_SEARCH_MAX_FRONTIER);
    }

    #[test]
    fn sqlcipher_keys_use_stable_per_database_salts() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let session_path = app.account_dir("alice").join(SESSION_DB_FILE);
        let projection_path = app.account_projection_path("alice");

        let session_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &session_path,
                SqlcipherDatabaseKind::Session,
            )
            .unwrap();
        let repeated_session_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &session_path,
                SqlcipherDatabaseKind::Session,
            )
            .unwrap();
        let projection_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();

        assert_eq!(
            session_key.as_secret_str(),
            repeated_session_key.as_secret_str()
        );
        assert_ne!(session_key.as_secret_str(), projection_key.as_secret_str());
        assert!(sqlcipher_salt_path(&session_path).exists());
        assert!(sqlcipher_salt_path(&projection_path).exists());
    }

    #[test]
    fn sqlcipher_key_migrates_legacy_database_to_salted_key() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let projection_path = app.account_projection_path("alice");
        fs::create_dir_all(projection_path.parent().unwrap()).unwrap();
        let legacy_key = SqlCipherKey::new(legacy_sqlcipher_key_material(
            "alice",
            &keys,
            SqlcipherDatabaseKind::AccountProjection,
        ))
        .unwrap();
        {
            let conn = Connection::open(&projection_path).unwrap();
            conn.pragma_update(None, "key", legacy_key.as_secret_str())
                .unwrap();
            conn.execute_batch(
                "CREATE TABLE marker (value TEXT NOT NULL);
                 INSERT INTO marker (value) VALUES ('kept');",
            )
            .unwrap();
        }

        let salted_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();

        assert!(sqlcipher_salt_path(&projection_path).exists());
        let conn = Connection::open(&projection_path).unwrap();
        conn.pragma_update(None, "key", salted_key.as_secret_str())
            .unwrap();
        let value: String = conn
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "kept");

        let conn = Connection::open(&projection_path).unwrap();
        conn.pragma_update(None, "key", legacy_key.as_secret_str())
            .unwrap();
        assert!(
            conn.query_row("SELECT value FROM marker", [], |row| row
                .get::<_, String>(0))
                .is_err()
        );
    }

    #[test]
    fn own_relay_echo_requires_known_event_id_not_just_pubkey() {
        let local_pubkey = "11".repeat(32);
        let known_event_id = "22".repeat(32);
        let new_cross_device_event_id = "33".repeat(32);
        let known_event_ids = HashSet::from([known_event_id.clone()]);

        let known_local_delivery = relay_delivery(known_event_id.clone(), local_pubkey.clone());
        assert!(is_own_relay_echo(
            &known_local_delivery,
            &local_pubkey,
            &known_event_ids
        ));

        let same_pubkey_new_event = relay_delivery(new_cross_device_event_id, local_pubkey.clone());
        assert!(!is_own_relay_echo(
            &same_pubkey_new_event,
            &local_pubkey,
            &known_event_ids
        ));

        let known_other_pubkey_delivery = relay_delivery(known_event_id, "44".repeat(32));
        assert!(!is_own_relay_echo(
            &known_other_pubkey_delivery,
            &local_pubkey,
            &known_event_ids
        ));
    }

    #[test]
    fn account_worker_is_spawned_on_blocking_pool() {
        let source = include_str!("lib.rs");

        assert!(source.contains("tokio::task::spawn_blocking(move ||"));
        assert!(source.contains("worker_runtime.block_on(run_app_runtime_account_worker"));
    }

    #[test]
    fn account_worker_reconnect_backoff_doubles_caps_and_resets() {
        let mut backoff =
            AccountWorkerReconnectBackoff::new(Duration::from_secs(2), Duration::from_secs(8));

        assert_eq!(
            backoff.next_delay_with_jitter(Duration::ZERO),
            Duration::from_secs(2)
        );
        assert_eq!(
            backoff.next_delay_with_jitter(Duration::ZERO),
            Duration::from_secs(4)
        );
        assert_eq!(
            backoff.next_delay_with_jitter(Duration::ZERO),
            Duration::from_secs(8)
        );
        assert_eq!(
            backoff.next_delay_with_jitter(Duration::from_secs(100)),
            Duration::from_secs(8)
        );
        backoff.reset();
        assert_eq!(
            backoff.next_delay_with_jitter(Duration::ZERO),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn app_transport_routing_recovers_from_poisoned_lock() {
        let routing = AppTransportRouting::new(AppRoutingState {
            local_inbox_endpoints: Vec::new(),
            key_package_endpoints: Vec::new(),
            inbox_routes: HashMap::new(),
            group_routes: Vec::new(),
            required_acks: 1,
        });
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = routing.inner.write().unwrap();
            panic!("poison app routing lock");
        }));

        routing.replace(AppRoutingState {
            local_inbox_endpoints: Vec::new(),
            key_package_endpoints: Vec::new(),
            inbox_routes: HashMap::new(),
            group_routes: Vec::new(),
            required_acks: 2,
        });

        assert_eq!(routing.snapshot().required_acks, 2);
    }

    #[test]
    fn relay_plane_rebuild_uses_persisted_cursor_with_bounded_overlap() {
        let relay_plane =
            MarmotRelayPlane::with_subscription_rebuild_lookback(Duration::from_secs(30));

        assert_eq!(
            relay_plane.subscription_rebuild_since(Some(1_700_000_000)),
            Some(Timestamp(1_699_999_970))
        );
        assert_eq!(
            relay_plane.subscription_rebuild_since(Some(20)),
            Some(Timestamp(0))
        );
        assert_eq!(relay_plane.subscription_rebuild_since(None), None);
        assert_eq!(
            MarmotRelayPlane::full_history().subscription_rebuild_since(Some(1_700_000_000)),
            None
        );
    }

    #[test]
    fn agent_stream_candidate_parser_skips_malformed_quic_candidates() {
        let candidates = vec![
            "quic://".to_owned(),
            "https://127.0.0.1:4450".to_owned(),
            "quic://127.0.0.1:4450".to_owned(),
        ];

        let parsed = parse_quic_candidates(&candidates).expect("valid fallback candidate");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].authority, "127.0.0.1:4450");
        assert_eq!(parsed[0].server_name, "127.0.0.1");
    }

    #[test]
    fn agent_stream_insecure_local_only_applies_to_loopback_brokers() {
        let loopback = "127.0.0.1:4450".parse().unwrap();
        let remote = "203.0.113.10:4450".parse().unwrap();

        assert!(matches!(
            broker_trust_for_addr(loopback, None, true),
            BrokerServerTrust::InsecureLocal
        ));
        assert!(matches!(
            broker_trust_for_addr(remote, None, true),
            BrokerServerTrust::Platform
        ));
        assert!(matches!(
            broker_trust_for_addr(remote, Some(vec![1, 2, 3]), true),
            BrokerServerTrust::CertificateDer(der) if der == vec![1, 2, 3]
        ));
    }

    #[test]
    fn remembered_seen_events_are_bounded_in_memory() {
        let mut state = AccountState {
            label: "alice".to_owned(),
            seen_events: Vec::new(),
            last_transport_timestamp: None,
            groups: Vec::new(),
        };
        let mut seen = HashSet::new();

        for index in 0..(MAX_SEEN_EVENT_IDS + 2) {
            let event_id = format!("event-{index:05}");
            seen.insert(event_id.clone());
            remember_seen_event(&mut state, event_id);
            refresh_seen_lookup_if_needed(&mut seen, &state);
        }

        assert_eq!(state.seen_events.len(), MAX_SEEN_EVENT_IDS);
        assert_eq!(seen.len(), MAX_SEEN_EVENT_IDS);
        assert!(!seen.contains("event-00000"));
        assert_eq!(
            state.seen_events.first().map(String::as_str),
            Some("event-00002")
        );
        let expected_last = format!("event-{:05}", MAX_SEEN_EVENT_IDS + 1);
        assert_eq!(
            state.seen_events.last().map(String::as_str),
            Some(expected_last.as_str())
        );
    }

    const SENDER_HEX: &str = "aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55";

    fn build(intent: AppMessageIntent) -> MarmotInnerEvent {
        build_inner_event(&intent, SENDER_HEX, 1_700_000_000).unwrap()
    }

    #[test]
    fn chat_intent_builds_kind_nine_with_no_tags() {
        let event = build(AppMessageIntent::Chat {
            content: "hello".to_owned(),
        });
        assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
        assert_eq!(event.content, "hello");
        assert!(event.tags.is_empty());
        assert_eq!(event.pubkey, SENDER_HEX);
    }

    #[test]
    fn reaction_intent_builds_kind_seven_with_e_tag() {
        let event = build(AppMessageIntent::Reaction {
            target_message_id: "abc123".to_owned(),
            emoji: "🔥".to_owned(),
        });
        assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_REACTION);
        assert_eq!(event.content, "🔥");
        assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("abc123"));
    }

    #[test]
    fn reaction_intent_rejects_empty_emoji() {
        let result = build_inner_event(
            &AppMessageIntent::Reaction {
                target_message_id: "abc123".to_owned(),
                emoji: "  ".to_owned(),
            },
            SENDER_HEX,
            1,
        );
        assert!(matches!(result, Err(AppError::InvalidAppMessagePayload(_))));
    }

    #[test]
    fn delete_intent_builds_empty_kind_five_with_e_tag() {
        let event = build(AppMessageIntent::Delete {
            target_message_id: "abc123".to_owned(),
        });
        assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_DELETE);
        assert_eq!(event.content, "");
        assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("abc123"));
    }

    #[test]
    fn reply_intent_builds_kind_nine_with_e_and_q_tags() {
        let event = build(AppMessageIntent::Reply {
            target_message_id: "parent".to_owned(),
            text: "sure".to_owned(),
        });
        assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
        assert_eq!(event.content, "sure");
        assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("parent"));
        assert_eq!(tag_value(&event.tags, QUOTE_REF_TAG), Some("parent"));
    }

    #[test]
    fn media_intent_builds_kind_nine_with_imeta_tag() {
        let event = build(AppMessageIntent::Media {
            reference: MediaReference {
                url: "https://media.example/a.png".to_owned(),
                file_hash_hex: hex::encode([0x11_u8; 32]),
                nonce_hex: hex::encode([0x22_u8; 12]),
                file_name: "a.png".to_owned(),
                media_type: "image/png".to_owned(),
                version: "mip04-v2".to_owned(),
            },
            caption: Some("cap".to_owned()),
        });
        assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
        assert_eq!(event.content, "cap");
        let imeta = event
            .tags
            .iter()
            .find(|tag| tag.first().map(String::as_str) == Some("imeta"))
            .unwrap();
        assert!(
            imeta
                .iter()
                .any(|field| field == "url https://media.example/a.png")
        );
        assert!(imeta.iter().any(|field| field == "m image/png"));
        assert!(!imeta.iter().any(|field| field.starts_with("size ")));
        assert!(imeta.iter().any(|field| field == "filename a.png"));
        assert!(
            imeta
                .iter()
                .any(|field| field == "n 222222222222222222222222")
        );
        assert!(imeta.iter().any(|field| field == "v mip04-v2"));
    }

    #[test]
    fn stream_start_intent_builds_kind_1200_with_broker_tags() {
        let event = build(AppMessageIntent::StreamStart {
            stream_id: vec![0xab; 32],
            quic_candidates: vec![
                "quic://broker.example:4450".to_owned(),
                "quic://[::1]:4450".to_owned(),
            ],
        });
        assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START);
        assert_eq!(event.content, "");
        let start = StreamStartView::from_event(event.kind, &event.tags).unwrap();
        assert_eq!(start.stream_id_hex, hex::encode([0xab; 32]));
        assert_eq!(start.route, STREAM_ROUTE_QUIC);
        assert_eq!(
            start.quic_candidates,
            vec![
                "quic://broker.example:4450".to_owned(),
                "quic://[::1]:4450".to_owned(),
            ]
        );
        assert_eq!(tag_value(&event.tags, STREAM_TYPE_TAG), Some("text"));
        assert_eq!(tag_value(&event.tags, STREAM_FINAL_KIND_TAG), Some("9"));
    }

    #[test]
    fn stream_start_intent_requires_a_broker() {
        let result = build_inner_event(
            &AppMessageIntent::StreamStart {
                stream_id: vec![0xab; 32],
                quic_candidates: vec!["   ".to_owned()],
            },
            SENDER_HEX,
            1,
        );
        assert!(matches!(result, Err(AppError::AgentStreamMissingCandidate)));
    }

    #[test]
    fn stream_final_intent_builds_kind_nine_stream_final() {
        let start_event_id = "aa".repeat(32);
        let event = build(AppMessageIntent::StreamFinal {
            request: AgentTextStreamFinishRequest {
                stream_id: vec![0xcd; 32],
                start_event_id: start_event_id.clone(),
                final_text_or_reference: "done".to_owned(),
                transcript_hash: [0xee; 32],
                chunk_count: 3,
                finished_at: 9,
            },
        });
        assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
        assert_eq!(event.content, "done");
        assert!(is_stream_final_event(event.kind, &event.tags));
        assert_eq!(
            tag_value(&event.tags, STREAM_TAG),
            Some(hex::encode([0xcd; 32]).as_str())
        );
        assert_eq!(
            tag_value(&event.tags, STREAM_START_TAG),
            Some(start_event_id.as_str())
        );
        assert_eq!(
            tag_value(&event.tags, STREAM_HASH_TAG),
            Some(hex::encode([0xee; 32]).as_str())
        );
        assert_eq!(tag_value(&event.tags, STREAM_CHUNKS_TAG), Some("3"));
    }

    #[test]
    fn received_event_decodes_when_id_and_sender_match() {
        let event = build(AppMessageIntent::Chat {
            content: "hi".to_owned(),
        });
        let bytes = event.encode().unwrap();
        let group_id = GroupId::new(vec![0x01]);
        let message = decode_received_event(&bytes, SENDER_HEX, None, &group_id, "msg1")
            .expect("valid event is accepted");
        assert_eq!(message.plaintext, "hi");
        assert_eq!(message.kind, MARMOT_APP_EVENT_KIND_CHAT);
        assert_eq!(message.sender, SENDER_HEX);
    }

    #[test]
    fn received_event_with_tampered_id_is_rejected() {
        let mut event = build(AppMessageIntent::Chat {
            content: "hi".to_owned(),
        });
        // Mutate the content without recomputing the id: the canonical id no
        // longer matches, so the strict decoder must reject it.
        event.content = "tampered".to_owned();
        let bytes = serde_json::to_vec(&event).unwrap();
        let group_id = GroupId::new(vec![0x01]);
        assert!(decode_received_event(&bytes, SENDER_HEX, None, &group_id, "msg1").is_none());
    }

    #[test]
    fn received_event_with_wrong_sender_is_rejected() {
        let event = build(AppMessageIntent::Chat {
            content: "hi".to_owned(),
        });
        let bytes = event.encode().unwrap();
        let group_id = GroupId::new(vec![0x01]);
        let other_sender = "bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66";
        // The inner pubkey is SENDER_HEX, but MLS authenticated `other_sender`.
        assert!(decode_received_event(&bytes, other_sender, None, &group_id, "msg1").is_none());
    }

    #[test]
    fn inner_event_id_matches_nostr_sdk_event_id() {
        use nostr::{EventId, Keys, Kind, Tag, Tags, Timestamp};

        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let created_at = 1_700_000_123_u64;
        let kind = MARMOT_APP_EVENT_KIND_CHAT;
        let tags = vec![
            vec![EVENT_REF_TAG.to_owned(), "parent-id".to_owned()],
            vec![QUOTE_REF_TAG.to_owned(), "parent-id".to_owned()],
        ];
        let content = "hello from marmot 🦫";

        // Our canonical id over the unsigned-event preimage.
        let ours =
            cgka_traits::canonical_event_id(&pubkey.to_hex(), created_at, kind, &tags, content);

        // The nostr SDK's NIP-01 id for the same {pubkey, created_at, kind,
        // tags, content}. If these diverge, external Nostr clients would reject
        // our inner event id.
        let sdk_tags = Tags::from_list(
            tags.iter()
                .map(|tag| Tag::parse(tag.clone()).unwrap())
                .collect(),
        );
        let theirs = EventId::new(
            &pubkey,
            &Timestamp::from(created_at),
            &Kind::from(kind as u16),
            &sdk_tags,
            content,
        );

        assert_eq!(ours, theirs.to_hex());
    }

    #[test]
    fn app_error_display_does_not_expose_group_or_account_ids() {
        let group_id = "aa".repeat(32);
        let account_id = "bb".repeat(32);
        let errors = [
            AppError::UnknownGroup(group_id.clone()).to_string(),
            AppError::MissingKeyPackage(account_id.clone()).to_string(),
            AppError::MissingDirectoryEntry(account_id.clone()).to_string(),
            AppError::AccountHome(AccountHomeError::SecretNotFound(account_id.clone())).to_string(),
        ];

        for error in errors {
            assert!(!error.contains(&group_id), "{error}");
            assert!(!error.contains(&account_id), "{error}");
        }
    }
}
