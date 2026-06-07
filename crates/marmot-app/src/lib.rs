//! First app runtime bridge for Marmot.
//!
//! This crate wires `AccountHome` into the concrete local runtime pieces needed by
//! early app surfaces: encrypted session storage, Nostr MLS peeling, Nostr
//! transport publishing, and relay-backed app projections.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cgka_engine::{
    FeatureRegistry,
    account_identity_proof::{
        ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE, AccountIdentityProofRequest,
        AccountIdentityProofSigner,
    },
    canonicalization::CanonicalizationPolicy,
    key_package::key_package_metadata,
};
use cgka_session::{AccountDeviceSession, SessionConfig};
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE, AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE,
    AGENT_TEXT_STREAM_QUIC_SEND_FEATURE,
};
pub use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT as AGENT_TEXT_STREAM_COMPONENT,
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID as AGENT_TEXT_STREAM_COMPONENT_ID,
    GROUP_ADMIN_POLICY_COMPONENT, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_BLOSSOM_IMAGE_COMPONENT,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_MESSAGE_RETENTION_COMPONENT,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT, GROUP_PROFILE_COMPONENT_ID,
    NOSTR_ROUTING_COMPONENT, NOSTR_ROUTING_COMPONENT_ID,
};
use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, NostrRoutingV1, default_group_components,
};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{GroupEvent, KeyPackage};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::{
    GroupId, MemberId, MessageId, TransportEndpoint, TransportGroupSubscription,
    TransportPublishTarget,
};
use hkdf::Hkdf;
use marmot_account::{
    AccountDeviceRuntime, AccountHome, AccountSummary, KeyPackagePublication,
    KeyPackagePublishError, KeyPackagePublisher, TransportRoutingError, TransportRoutingPolicy,
};
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use nostr_sdk::prelude::{Client as NostrSdkClient, PublicKey};
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_sqlite::{
    AccountGroupPushToken, AccountNotificationSettings, AccountPushRegistration,
    AccountStoredPushRegistration, PublicDirectoryUserRecord, SqlCipherKey, SqliteAccountStorage,
    SqliteSharedStorage, StoredAccountGroup, StoredAccountGroupComponent, StoredAccountState,
    StoredAppEvent, StoredAppMessageQuery, StoredAppMessageRecord, StoredAuditLogSettings,
    StoredRelayTelemetrySettings, TimelineProjectionUpdate,
};
use tokio_util::io::ReaderStream;
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
    NostrAccountRelayListKind, NostrAccountRelayListPublication, NostrKeyPackagePublication,
    NostrKeyPackagePublisher, NostrRelayClient, NostrSdkRelayClient,
};
use transport_nostr_peeler::{NostrMlsPeeler, NostrTransportEvent};

mod agent_streams;
mod client;
mod config;
mod directory;
mod error;
mod groups;
mod ids;
mod media;
mod messages;
mod notifications;
mod projection;
mod relay_plane;
mod relay_telemetry_export;
mod runtime;

pub(crate) use groups::AppGroupImageInput;
pub(crate) use runtime::blocking_app_task;
pub use runtime::{
    AccountManager, AccountSetupRequest, AccountSetupResult, AgentStreamWatchOptions,
    ChatListUpdateTrigger, ManagedAccount, MarmotAppEvent, MarmotAppRuntime, RuntimeAccountError,
    RuntimeAgentStreamMessage, RuntimeAgentStreamUpdate, RuntimeAgentStreamWatch,
    RuntimeChatListSubscription, RuntimeChatListUpdate, RuntimeChatsSubscription,
    RuntimeEventsSubscription, RuntimeGroupEvent, RuntimeGroupStateSubscription,
    RuntimeMessageReceived, RuntimeMessageUpdate, RuntimeMessagesSubscription,
    RuntimeNotificationsSubscription, RuntimeProjectionUpdate, RuntimeSharedServices,
    RuntimeTimelineMessageUpdate, RuntimeTimelineMessagesSubscription, StreamStartView,
};
pub use storage_sqlite::{TimelineMessageChange, TimelineRemoveReason, TimelineUpdateTrigger};

pub use agent_streams::{
    AgentStreamDelta, AgentStreamUpdate, AgentStreamWatchCompletion, AgentStreamWatchManager,
    AgentStreamWatchReport, AgentStreamWatchStart,
};
pub use client::AppClient;
pub use config::{
    MarmotAppConfig, RelayTelemetryExportConfig, RelayTelemetryResource,
    RelayTelemetryRuntimeConfig, RelayTelemetrySettings,
};
pub use error::AppError;
pub use groups::{
    AppAgentTextStreamComponent, AppGroupAdminPolicyComponent, AppGroupImageComponent,
    AppGroupMemberRecord, AppGroupMessageRetentionComponent, AppGroupMlsState,
    AppGroupNostrRoutingComponent, AppGroupProfileComponent, AppGroupRecord,
};
pub use ids::{account_id_hex_from_ref, npub_for_account_id};
pub use media::{
    DEFAULT_BLOSSOM_SERVER_URL, MediaDownloadResult, MediaReference, MediaUploadRequest,
    MediaUploadResult,
};
pub use messages::{is_stream_final_event, tag_value, tag_values};
pub use notifications::{
    BackgroundNotificationCollection, GroupPushDebugInfo, GroupPushTokenDebugEntry,
    GroupPushTokenRecord, KIND_MARMOT_NOTIFICATION_RUMOR, KIND_MARMOT_NOTIFICATION_SERVER_RELAYS,
    LocalPushRegistrationDebug, MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST,
    MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL, MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE,
    MIP05_ENCRYPTED_TOKEN_LEN, MIP05_VERSION, NotificationCollectionStatus, NotificationSettings,
    NotificationTrigger, NotificationUpdate, NotificationUser, NotificationWakeSource,
    PushPlatform, PushRegistration, build_notification_gift_wrap, build_notification_rumor_content,
    encrypted_mip05_token, parse_provider_token, push_token_fingerprint,
};
pub use relay_plane::{
    EngineReorgMetrics, MarmotRelayPlane, MarmotRelayPlaneAccountAdapter, RelayPlaneHealth,
    RelayRollupEntry, RelayTelemetryRollup, RelayTelemetrySnapshot,
};
pub use relay_telemetry_export::{
    ExportHistogram, ExportMetricPoint, ExportMetricValue, RelayExportError,
    RelayTelemetryExportBatch, RelayTelemetryExporter, build_export_batch, metric_names,
};
pub use storage_sqlite::{
    ChatListAvatar, ChatListMessagePreview, ChatListQuery, ChatListRow, TimelineMessageQuery,
    TimelineMessageRecord, TimelinePage, TimelinePagination, TimelineReactionSummary,
    TimelineReplyPreview, TimelineUserReaction,
};
pub use transport_nostr_adapter::{
    DurationHistogramSnapshot, HistogramBucket, NostrAdapterMetrics, RelayDeliverySpread,
    RelayDeliveryStats, RelayLabelResolution, RelayLatencyStats, RelaySyncSnapshot,
};

use directory::{DirectoryCache, DirectorySyncHandle, DirectorySyncPlan};
use ids::{normalize_account_ids, npub_for_account_id_lossy, parse_account_id_hex};
use projection::LegacyAccountProjectionDb;
use relay_plane::{DirectoryEventQuery, DirectoryRelayEventRecord as RelayEventRecord};

const LEGACY_ACCOUNT_APP_DB_FILE: &str = "app.sqlite3";
const LEGACY_ACCOUNT_PROJECTION_IMPORT_MARKER: &str = "legacy-account-projection-v1";
const APP_CACHE_DB_FILE: &str = "app-cache.sqlite3";
const SHARED_DB_FILE: &str = "shared.sqlite3";
const AUDIT_LOG_CONTENT_TYPE: &str = "application/x-ndjson";
const AUDIT_DEVICE_ID_FILE: &str = "audit-device-id";
const AUDIT_ID_BYTES: usize = 16;
const AUDIT_LOG_UPLOAD_MAX_BYTES: u64 = 64 * 1024 * 1024;
const AUDIT_LOG_UPLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const AUDIT_LOG_UPLOAD_TIMEOUT: Duration = Duration::from_secs(60);
static AUDIT_LOG_UPLOAD_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .connect_timeout(AUDIT_LOG_UPLOAD_CONNECT_TIMEOUT)
        .timeout(AUDIT_LOG_UPLOAD_TIMEOUT)
        .build()
        .expect("audit log upload client configuration should be valid")
});
const SESSION_DB_FILE: &str = "session.sqlite";
const SQLCIPHER_SALT_SUFFIX: &str = ".salt";
const SQLCIPHER_SALT_LEN: usize = 32;
const SQLCIPHER_KEY_LEN: usize = 32;
const KEY_PACKAGE_DIR: &str = "key-packages";
const SDK_FIRST_SYNC_WAIT: Duration = Duration::from_millis(750);
const SDK_DRAIN_WAIT: Duration = Duration::from_millis(250);
const APP_RUNTIME_ACCOUNT_READY_WAIT: Duration = Duration::from_secs(45);
const APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT: Duration = Duration::from_secs(5);
const APP_RUNTIME_RELAY_REBUILD_LOOKBACK: Duration = Duration::from_secs(120);
const ACCOUNT_WORKER_RECONNECT_BASE_DELAY: Duration = Duration::from_secs(2);
const ACCOUNT_WORKER_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(60);
const ACCOUNT_WORKER_RECONNECT_JITTER_MAX_MS: u64 = 500;
const APP_RUNTIME_SUBSCRIPTION_BUFFER: usize = 1024;
const AGENT_STREAM_START_LOOKBACK_LIMIT: usize = 200;
const USER_DIRECTORY_SEARCH_MAX_VISITED: usize = 8192;
const USER_DIRECTORY_SEARCH_MAX_FRONTIER: usize = 4096;
const DIRECTORY_FUTURE_CREATED_AT_CLEANUP_MARKER: &str =
    ".marmot-directory-future-created-at-cleanup-v1";
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
    directory_sync: Arc<RwLock<Option<DirectorySyncHandle>>>,
    account_storages: Arc<Mutex<HashMap<String, SqliteAccountStorage>>>,
    shared_storage: Arc<Mutex<Option<SqliteSharedStorage>>>,
    account_state_ready: Arc<Mutex<HashSet<String>>>,
    chat_list_projection_warmed: Arc<Mutex<HashSet<String>>>,
    chat_list_projection_stale: Arc<Mutex<HashSet<String>>>,
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
        self.complete = self.missing.is_empty();
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub joined_groups: Vec<GroupId>,
    pub messages: Vec<ReceivedMessage>,
    pub events: Vec<GroupEvent>,
    pub projection_updates: Vec<AppProjectionUpdate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedMessage {
    pub message_id_hex: String,
    pub source_message_id_hex: String,
    pub sender: String,
    pub sender_display_name: Option<String>,
    pub group_id: GroupId,
    /// Displayed text for the inner app event (its `content`).
    pub plaintext: String,
    /// Nostr `kind` of the inner Marmot app event.
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    pub tags: Vec<Vec<String>>,
    /// Source-event timestamp (seconds since epoch) for the MLS-delivered
    /// message. Clients should sort the timeline by this value so chronology
    /// reflects send time, not delivery time. Zero means the timestamp was
    /// unavailable at decode time.
    pub recorded_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogFile {
    pub account_ref: String,
    pub path: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub modified_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogUploadResult {
    pub path: String,
    pub status: u16,
    pub bytes_sent: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuditLogSettings {
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppProjectionUpdate {
    pub group_id_hex: String,
    pub timeline_messages: Vec<TimelineMessageRecord>,
    #[serde(default)]
    pub timeline_changes: Vec<TimelineMessageChange>,
    pub chat_list_row: Option<ChatListRow>,
    #[serde(default)]
    pub chat_list_trigger: ChatListUpdateTrigger,
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
pub struct GroupInviteDeclineResult {
    pub group: AppGroupRecord,
    pub summary: SendSummary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedKeyPackage {
    pub account_id_hex: String,
    pub key_package: KeyPackage,
    pub key_package_id: String,
    pub key_package_ref_hex: String,
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
    pub key_package_ref_hex: String,
    #[serde(default)]
    pub key_package_event_id: String,
    pub key_package_hex: String,
    pub created_at: u64,
    pub source_relays: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountKeyPackageRecord {
    pub account_label: Option<String>,
    pub account_id_hex: String,
    pub key_package_id: String,
    pub key_package_ref_hex: String,
    pub key_package_event_id: String,
    pub published_at: u64,
    pub key_package_bytes: usize,
    pub source_relays: Vec<String>,
    pub local: bool,
    pub relay: bool,
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
    source_message_id_hex: Option<String>,
    direction: String,
    group_id_hex: String,
    sender: String,
    plaintext: String,
    kind: u64,
    tags: Vec<Vec<String>>,
    recorded_at: Option<u64>,
}

fn stored_state_from_account_state(state: &AccountState) -> StoredAccountState {
    StoredAccountState {
        label: state.label.clone(),
        seen_events: state.seen_events.clone(),
        last_transport_timestamp: state.last_transport_timestamp,
        groups: state
            .groups
            .iter()
            .map(stored_group_from_app_group)
            .collect(),
    }
}

fn account_state_from_stored(stored: StoredAccountState) -> Result<AccountState, AppError> {
    Ok(AccountState {
        label: stored.label,
        seen_events: stored.seen_events,
        last_transport_timestamp: stored.last_transport_timestamp,
        groups: stored
            .groups
            .into_iter()
            .map(app_group_from_stored_group)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn stored_group_from_app_group(group: &AppGroupRecord) -> StoredAccountGroup {
    StoredAccountGroup {
        group_id_hex: group.group_id_hex.clone(),
        endpoint: group.endpoint.clone(),
        profile_name: group.profile.name.clone(),
        profile_description: group.profile.description.clone(),
        image_hash_hex: group.image.image_hash_hex.clone(),
        image_key_hex: group.image.image_key_hex.clone(),
        image_nonce_hex: group.image.image_nonce_hex.clone(),
        image_upload_key_hex: group.image.image_upload_key_hex.clone(),
        image_media_type: group.image.media_type.clone(),
        admin_keys_hex: group.admin_policy.admins.join(","),
        archived: group.archived,
        pending_confirmation: group.pending_confirmation,
        welcomer_account_id_hex: group.welcomer_account_id_hex.clone(),
        via_welcome_message_id_hex: group.via_welcome_message_id_hex.clone(),
        components: stored_components_from_app_group(group),
    }
}

fn stored_components_from_app_group(group: &AppGroupRecord) -> Vec<StoredAccountGroupComponent> {
    let mut components = vec![
        StoredAccountGroupComponent {
            component_id: group.profile.component_id,
            component_name: group.profile.component.clone(),
            component_data_hex: group.profile.data_hex.clone(),
        },
        StoredAccountGroupComponent {
            component_id: group.image.component_id,
            component_name: group.image.component.clone(),
            component_data_hex: group.image.data_hex.clone(),
        },
        StoredAccountGroupComponent {
            component_id: group.admin_policy.component_id,
            component_name: group.admin_policy.component.clone(),
            component_data_hex: group.admin_policy.data_hex.clone(),
        },
        StoredAccountGroupComponent {
            component_id: group.message_retention.component_id,
            component_name: group.message_retention.component.clone(),
            component_data_hex: group.message_retention.data_hex.clone(),
        },
        StoredAccountGroupComponent {
            component_id: group.nostr_routing.component_id,
            component_name: group.nostr_routing.component.clone(),
            component_data_hex: group.nostr_routing.data_hex.clone(),
        },
    ];
    if group.agent_text_stream.required {
        components.push(StoredAccountGroupComponent {
            component_id: group.agent_text_stream.component_id,
            component_name: group.agent_text_stream.component.clone(),
            component_data_hex: group.agent_text_stream.data_hex.clone(),
        });
    }
    components
}

fn app_group_from_stored_group(stored: StoredAccountGroup) -> Result<AppGroupRecord, AppError> {
    let routing_bytes = hex::decode(
        account_component_data_hex(&stored.components, NOSTR_ROUTING_COMPONENT_ID).ok_or_else(
            || AppError::InvalidNostrRouting("stored group is missing routing".into()),
        )?,
    )?;
    let retention =
        account_component_data_hex(&stored.components, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .map(hex::decode)
            .transpose()?
            .map(|bytes| AppGroupMessageRetentionComponent::from_bytes(&bytes))
            .unwrap_or_else(AppGroupMessageRetentionComponent::disabled);
    let mut group = AppGroupRecord::new(
        stored.group_id_hex,
        AppGroupNostrRoutingComponent::from_bytes(&routing_bytes)?,
        stored.profile_name,
        stored.profile_description,
        AppGroupImageInput {
            image_hash_hex: stored.image_hash_hex,
            image_key_hex: stored.image_key_hex,
            image_nonce_hex: stored.image_nonce_hex,
            image_upload_key_hex: stored.image_upload_key_hex,
            media_type: stored.image_media_type,
        },
        AppGroupAdminPolicyComponent::new(parse_admin_keys_hex(&stored.admin_keys_hex)),
        retention,
    );
    if let Some(agent_hex) =
        account_component_data_hex(&stored.components, AGENT_TEXT_STREAM_COMPONENT_ID)
        && !agent_hex.is_empty()
    {
        let agent_bytes = hex::decode(agent_hex)?;
        group.agent_text_stream = AppAgentTextStreamComponent::from_bytes(&agent_bytes);
    }
    group.archived = stored.archived;
    group.pending_confirmation = stored.pending_confirmation;
    group.welcomer_account_id_hex = stored.welcomer_account_id_hex;
    group.via_welcome_message_id_hex = stored.via_welcome_message_id_hex;
    Ok(group)
}

fn account_component_data_hex(
    components: &[StoredAccountGroupComponent],
    component_id: u16,
) -> Option<&str> {
    components
        .iter()
        .find(|component| component.component_id == component_id)
        .map(|component| component.component_data_hex.as_str())
}

fn parse_admin_keys_hex(value: &str) -> Vec<[u8; 32]> {
    value
        .split(',')
        .filter_map(|key| {
            let bytes = hex::decode(key).ok()?;
            let array: [u8; 32] = bytes.try_into().ok()?;
            Some(array)
        })
        .collect()
}

fn app_message_record_from_stored(record: StoredAppMessageRecord) -> AppMessageRecord {
    AppMessageRecord {
        message_id_hex: record.message_id_hex,
        direction: record.direction,
        group_id_hex: record.group_id_hex,
        sender: record.sender,
        plaintext: record.plaintext,
        kind: record.kind,
        tags: record.tags,
        recorded_at: record.recorded_at,
        received_at: record.received_at,
    }
}

fn stored_app_event_from_projection(
    message: &AppMessageProjection,
    received_at: u64,
) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: message.group_id_hex.clone(),
        message_id_hex: message.message_id_hex.clone(),
        source_message_id_hex: message.source_message_id_hex.clone(),
        direction: message.direction.clone(),
        sender: message.sender.clone(),
        plaintext: message.plaintext.clone(),
        kind: message.kind,
        tags: message.tags.clone(),
        recorded_at: message.recorded_at.unwrap_or(received_at),
        received_at,
    }
}

fn stored_app_event_from_message_record(record: &AppMessageRecord) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: record.group_id_hex.clone(),
        message_id_hex: record.message_id_hex.clone(),
        source_message_id_hex: None,
        direction: record.direction.clone(),
        sender: record.sender.clone(),
        plaintext: record.plaintext.clone(),
        kind: record.kind,
        tags: record.tags.clone(),
        recorded_at: record.recorded_at,
        received_at: record.received_at,
    }
}

fn notification_settings_from_account(
    settings: AccountNotificationSettings,
) -> NotificationSettings {
    NotificationSettings {
        account_ref: settings.account_label,
        account_id_hex: settings.account_id_hex,
        local_notifications_enabled: settings.local_notifications_enabled,
        native_push_enabled: settings.native_push_enabled,
    }
}

fn audit_account_ref_hex(account_id: &MemberId) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-audit-account-ref/v1");
    hasher.update(account_id.as_slice());
    let digest = hasher.finalize();
    hex::encode(&digest[..AUDIT_ID_BYTES])
}

fn audit_engine_id_hex(account_id: &MemberId, device_id_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-audit-engine-id/v2");
    hasher.update(account_id.as_slice());
    hasher.update(device_id_hex.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..AUDIT_ID_BYTES])
}

fn parse_audit_device_id_hex(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    let bytes = hex::decode(value).map_err(|_| {
        AppError::InvalidAuditLogFile("audit device id must be hex encoded".to_owned())
    })?;
    if bytes.len() != AUDIT_ID_BYTES {
        return Err(AppError::InvalidAuditLogFile(format!(
            "audit device id must be {AUDIT_ID_BYTES} bytes"
        )));
    }
    Ok(value.to_owned())
}

fn generate_audit_device_id_hex() -> String {
    let mut bytes = [0u8; AUDIT_ID_BYTES];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn generate_telemetry_install_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let encoded = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &encoded[0..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
        &encoded[20..32]
    )
}

fn audit_device_id_hex(account_dir: &Path) -> Result<String, AppError> {
    let path = account_dir.join(AUDIT_DEVICE_ID_FILE);
    match fs::read_to_string(&path) {
        Ok(value) => return parse_audit_device_id_hex(&value),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let device_id = generate_audit_device_id_hex();
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(device_id.as_bytes())?;
            file.write_all(b"\n")?;
            Ok(device_id)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            parse_audit_device_id_hex(&fs::read_to_string(&path)?)
        }
        Err(err) => Err(err.into()),
    }
}

fn relay_telemetry_settings_from_storage(
    settings: StoredRelayTelemetrySettings,
) -> RelayTelemetrySettings {
    RelayTelemetrySettings {
        export_enabled: settings.export_enabled,
        export_interval_seconds: settings.export_interval_seconds,
    }
}

fn relay_telemetry_settings_to_storage(
    settings: RelayTelemetrySettings,
) -> StoredRelayTelemetrySettings {
    StoredRelayTelemetrySettings {
        export_enabled: settings.export_enabled,
        export_interval_seconds: settings.export_interval_seconds,
    }
}

fn audit_log_settings_from_storage(settings: StoredAuditLogSettings) -> AuditLogSettings {
    AuditLogSettings {
        enabled: settings.enabled,
    }
}

fn audit_log_settings_to_storage(settings: AuditLogSettings) -> StoredAuditLogSettings {
    StoredAuditLogSettings {
        enabled: settings.enabled,
    }
}

fn normalize_relay_telemetry_settings(
    settings: RelayTelemetrySettings,
) -> Result<RelayTelemetrySettings, AppError> {
    settings
        .validate()
        .map_err(AppError::InvalidRelayTelemetrySettings)?;
    Ok(settings)
}

fn audit_log_file_name(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_string_lossy();
    (file_name.starts_with("audit-") && file_name.ends_with(".jsonl"))
        .then(|| file_name.into_owned())
}

fn system_time_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
}

fn validate_audit_upload_endpoint(endpoint: &str) -> Result<String, AppError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(AppError::AuditLogUpload(
            "forensic upload endpoint is empty".to_owned(),
        ));
    }
    if !config::endpoint_transport_allowed(endpoint) {
        return Err(AppError::AuditLogUpload(
            "forensic upload endpoint must be https, or loopback http for local testing".to_owned(),
        ));
    }
    Ok(endpoint.to_owned())
}

fn audit_log_reqwest_error(err: reqwest::Error) -> AppError {
    if let Some(status) = err.status() {
        AppError::AuditLogUpload(format!("HTTP {}", status.as_u16()))
    } else if err.is_timeout() {
        AppError::AuditLogUpload("request timed out".into())
    } else if err.is_connect() {
        AppError::AuditLogUpload("connection failed".into())
    } else if err.is_body() {
        AppError::AuditLogUpload("invalid response body".into())
    } else {
        AppError::AuditLogUpload("request failed".into())
    }
}

fn account_push_registration_from_app(registration: PushRegistration) -> AccountPushRegistration {
    AccountPushRegistration {
        account_label: registration.account_ref,
        account_id_hex: registration.account_id_hex,
        platform: registration.platform.platform_byte(),
        token_fingerprint: registration.token_fingerprint,
        server_pubkey_hex: registration.server_pubkey_hex,
        relay_hint: registration.relay_hint,
        created_at_ms: registration.created_at_ms,
        updated_at_ms: registration.updated_at_ms,
        last_shared_at_ms: registration.last_shared_at_ms,
    }
}

fn stored_push_registration_from_account(
    stored: AccountStoredPushRegistration,
) -> Result<notifications::StoredPushRegistration, AppError> {
    Ok(notifications::StoredPushRegistration {
        registration: PushRegistration {
            account_ref: stored.registration.account_label,
            account_id_hex: stored.registration.account_id_hex,
            platform: PushPlatform::from_platform_byte(stored.registration.platform)?,
            token_fingerprint: stored.registration.token_fingerprint,
            server_pubkey_hex: stored.registration.server_pubkey_hex,
            relay_hint: stored.registration.relay_hint,
            created_at_ms: stored.registration.created_at_ms,
            updated_at_ms: stored.registration.updated_at_ms,
            last_shared_at_ms: stored.registration.last_shared_at_ms,
        },
        token_bytes: stored.token_bytes,
    })
}

fn account_group_push_token_from_app(token: &GroupPushTokenRecord) -> AccountGroupPushToken {
    AccountGroupPushToken {
        group_id_hex: token.group_id_hex.clone(),
        member_id_hex: token.member_id_hex.clone(),
        leaf_index: token.leaf_index,
        platform: token.platform.platform_byte(),
        token_fingerprint: token.token_fingerprint.clone(),
        server_pubkey_hex: token.server_pubkey_hex.clone(),
        relay_hint: token.relay_hint.clone(),
        encrypted_token: token.encrypted_token.clone(),
        updated_at_ms: token.updated_at_ms,
    }
}

fn group_push_token_from_account(
    token: AccountGroupPushToken,
) -> Result<GroupPushTokenRecord, AppError> {
    Ok(GroupPushTokenRecord {
        group_id_hex: token.group_id_hex,
        member_id_hex: token.member_id_hex,
        leaf_index: token.leaf_index,
        platform: PushPlatform::from_platform_byte(token.platform)?,
        token_fingerprint: token.token_fingerprint,
        server_pubkey_hex: token.server_pubkey_hex,
        relay_hint: token.relay_hint,
        encrypted_token: token.encrypted_token,
        updated_at_ms: token.updated_at_ms,
    })
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
    key_package_ref_hex: String,
    #[serde(default)]
    key_package_event_id: String,
    #[serde(default)]
    published_at: u64,
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

impl MarmotApp {
    pub fn with_relay(root: impl AsRef<Path>, relay_url: impl Into<String>) -> Self {
        Self::with_relays(root, vec![relay_url.into()])
    }

    /// Snapshot the device-local relay telemetry of this app's relay plane.
    ///
    /// Aggregate and privacy-safe. Live numbers accumulate in the long-running
    /// daemon runtime; a standalone command queries its own (typically empty)
    /// relay plane.
    pub async fn relay_telemetry(&self) -> RelayTelemetrySnapshot {
        self.relay_plane.relay_telemetry().await
    }

    pub fn relay_telemetry_settings(&self) -> Result<RelayTelemetrySettings, AppError> {
        normalize_relay_telemetry_settings(relay_telemetry_settings_from_storage(
            self.shared_storage()?.relay_telemetry_settings()?,
        ))
    }

    pub fn set_relay_telemetry_settings(
        &self,
        settings: RelayTelemetrySettings,
    ) -> Result<RelayTelemetrySettings, AppError> {
        let settings = normalize_relay_telemetry_settings(settings)?;
        self.shared_storage()?
            .set_relay_telemetry_settings(&relay_telemetry_settings_to_storage(settings.clone()))?;
        Ok(settings)
    }

    pub fn relay_telemetry_export_config(&self) -> Result<RelayTelemetryExportConfig, AppError> {
        Ok(self.relay_telemetry_settings()?.export_config())
    }

    pub fn telemetry_install_id(&self) -> Result<String, AppError> {
        let storage = self.shared_storage()?;
        if let Some(install_id) = storage.telemetry_install_id()? {
            return Ok(install_id);
        }
        let install_id = generate_telemetry_install_id();
        storage.set_telemetry_install_id(&install_id)?;
        Ok(install_id)
    }

    pub fn audit_log_settings(&self) -> Result<AuditLogSettings, AppError> {
        Ok(audit_log_settings_from_storage(
            self.shared_storage()?.audit_log_settings()?,
        ))
    }

    pub fn set_audit_log_settings(
        &self,
        settings: AuditLogSettings,
    ) -> Result<AuditLogSettings, AppError> {
        self.shared_storage()?
            .set_audit_log_settings(&audit_log_settings_to_storage(settings.clone()))?;
        Ok(settings)
    }

    pub fn audit_log_files(&self) -> Result<Vec<AuditLogFile>, AppError> {
        let mut files = Vec::new();
        for account in self.account_home().accounts()? {
            let account_dir = self.account_dir(&account.label);
            if !account_dir.exists() {
                continue;
            }
            for entry in fs::read_dir(account_dir)? {
                let entry = entry?;
                let path = entry.path();
                let Some(file_name) = audit_log_file_name(&path) else {
                    continue;
                };
                let metadata = entry.metadata()?;
                if !metadata.is_file() {
                    continue;
                }
                files.push(AuditLogFile {
                    account_ref: account.label.clone(),
                    path: path.to_string_lossy().into_owned(),
                    file_name,
                    size_bytes: metadata.len(),
                    modified_at_ms: metadata.modified().ok().and_then(system_time_ms),
                });
            }
        }
        files.sort_by(|left, right| {
            left.account_ref
                .cmp(&right.account_ref)
                .then_with(|| left.file_name.cmp(&right.file_name))
        });
        Ok(files)
    }

    pub async fn post_audit_log_file(
        &self,
        path: &str,
        endpoint: &str,
    ) -> Result<AuditLogUploadResult, AppError> {
        let path = self.validate_audit_log_path(path)?;
        let endpoint = validate_audit_upload_endpoint(endpoint)?;
        let file = tokio::fs::File::open(&path).await?;
        let bytes_sent = file.metadata().await?.len();
        if bytes_sent > AUDIT_LOG_UPLOAD_MAX_BYTES {
            return Err(AppError::AuditLogUpload(format!(
                "audit log exceeds {} byte upload limit",
                AUDIT_LOG_UPLOAD_MAX_BYTES
            )));
        }
        let body = reqwest::Body::wrap_stream(ReaderStream::new(file));
        let response = AUDIT_LOG_UPLOAD_CLIENT
            .post(endpoint)
            .header(reqwest::header::CONTENT_TYPE, AUDIT_LOG_CONTENT_TYPE)
            .header(reqwest::header::CONTENT_LENGTH, bytes_sent)
            .body(body)
            .send()
            .await
            .map_err(audit_log_reqwest_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(AppError::AuditLogUpload(format!(
                "upload returned HTTP {}",
                status.as_u16()
            )));
        }
        Ok(AuditLogUploadResult {
            path: path.to_string_lossy().into_owned(),
            status: status.as_u16(),
            bytes_sent,
        })
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
            directory_sync: Arc::new(RwLock::new(None)),
            account_storages: Arc::new(Mutex::new(HashMap::new())),
            shared_storage: Arc::new(Mutex::new(None)),
            account_state_ready: Arc::new(Mutex::new(HashSet::new())),
            chat_list_projection_warmed: Arc::new(Mutex::new(HashSet::new())),
            chat_list_projection_stale: Arc::new(Mutex::new(HashSet::new())),
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
            directory_sync: Arc::new(RwLock::new(None)),
            account_storages: Arc::new(Mutex::new(HashMap::new())),
            shared_storage: Arc::new(Mutex::new(None)),
            account_state_ready: Arc::new(Mutex::new(HashSet::new())),
            chat_list_projection_warmed: Arc::new(Mutex::new(HashSet::new())),
            chat_list_projection_stale: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn runtime(&self) -> MarmotAppRuntime {
        MarmotAppRuntime::new(self.clone())
    }

    pub async fn client(&self, label: &str) -> Result<AppClient, AppError> {
        self.client_with_relay_plane(label, &MarmotRelayPlane::full_history(), None)
            .await
    }

    async fn runtime_client(
        &self,
        label: &str,
        relay_plane: &MarmotRelayPlane,
        lifecycle: runtime::RuntimeLifecycle,
    ) -> Result<AppClient, AppError> {
        self.client_with_relay_plane(label, relay_plane, Some(lifecycle))
            .await
    }

    async fn client_with_relay_plane(
        &self,
        label: &str,
        relay_plane: &MarmotRelayPlane,
        lifecycle: Option<runtime::RuntimeLifecycle>,
    ) -> Result<AppClient, AppError> {
        let app = self.clone();
        let label = label.to_owned();
        let relay_plane_for_open = relay_plane.clone();
        let relay_plane_for_rebuild = relay_plane.clone();
        let permit = lifecycle
            .as_ref()
            .map(runtime::RuntimeLifecycle::begin_account_open)
            .transpose()?;
        let open = blocking_app_task(move || {
            let _permit = permit;
            app.ensure_account_state(&label)?;
            app.open_account(&label, &relay_plane_for_open)
        })
        .await?;
        if let Some(lifecycle) = &lifecycle {
            lifecycle.ensure_running()?;
        }
        let rebuild_since =
            relay_plane_for_rebuild.subscription_rebuild_since(open.state.last_transport_timestamp);
        open.runtime.activate_transport(rebuild_since).await?;
        if let Some(lifecycle) = &lifecycle {
            lifecycle.ensure_running()?;
        }
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
        let message_count = self.account_storage(label)?.app_message_count()?;
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
        if !has_explicit_bootstrap_relays && relay_lists.nip65.relays.is_empty() {
            let source_relays = self.directory_source_relays(&[]);
            if !source_relays.is_empty() {
                relay_lists = self
                    .fetch_account_relay_list_status_for_account_id(account_id_hex, source_relays)
                    .await?;
            }
        }
        self.remember_directory_relay_lists(account_id_hex, &relay_lists)?;
        if relay_lists.nip65.relays.is_empty() {
            return Err(AppError::MissingRelayLists(vec!["nip65".into()]));
        }

        let source_relays = relay_lists
            .nip65
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
        let cached_entry = Self::directory_entry_from_caches(&caches, &account_id_hex)?
            .map(|entry| self.hydrate_directory_record(entry))
            .transpose()?;
        let shared_entry = self
            .shared_storage()?
            .public_directory_user(&account_id_hex)?
            .map(|record| self.hydrate_public_directory_record(record))
            .transpose()?;
        Ok(select_newer_directory_entry(cached_entry, shared_entry))
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
        Ok(self
            .account_storage(label)?
            .app_messages(StoredAppMessageQuery {
                group_id_hex: query.group_id_hex,
                limit: query.limit,
            })?
            .into_iter()
            .map(app_message_record_from_stored)
            .collect())
    }

    pub fn timeline_messages_with_query(
        &self,
        label: &str,
        query: TimelineMessageQuery,
    ) -> Result<TimelinePage, AppError> {
        let _span = tracing::debug_span!(
            target: "marmot_app::timeline",
            "timeline_messages_with_query",
            method = "timeline_messages_with_query"
        )
        .entered();
        self.ensure_account_state(label)?;
        Ok(self.account_storage(label)?.message_timeline(query)?)
    }

    pub fn chat_list(
        &self,
        label: &str,
        include_archived: bool,
    ) -> Result<Vec<ChatListRow>, AppError> {
        let account = self.account_home().account(label)?;
        self.ensure_account_state(&account.label)?;
        self.ensure_chat_list_projection(&account)?;
        let mut rows = self
            .account_storage(&account.label)?
            .chat_list_rows(ChatListQuery { include_archived })?;
        self.hydrate_chat_list_rows(&mut rows)?;
        Ok(rows)
    }

    pub fn chat_list_row(
        &self,
        label: &str,
        group_id_hex: &str,
    ) -> Result<Option<ChatListRow>, AppError> {
        let account = self.account_home().account(label)?;
        self.ensure_account_state(&account.label)?;
        self.ensure_chat_list_projection(&account)?;
        let mut row = self
            .account_storage(&account.label)?
            .chat_list_row(group_id_hex)?;
        self.hydrate_chat_list_row(row.as_mut())?;
        Ok(row)
    }

    fn refresh_chat_list_row(
        &self,
        label: &str,
        group_id_hex: &str,
    ) -> Result<Option<ChatListRow>, AppError> {
        let account = self.account_home().account(label)?;
        let mut row = self
            .account_storage(&account.label)?
            .refresh_chat_list_row(&account.account_id_hex, group_id_hex)?;
        self.hydrate_chat_list_row(row.as_mut())?;
        Ok(row)
    }

    pub fn initialize_chat_read_state(
        &self,
        label: &str,
        group_id_hex: &str,
    ) -> Result<Option<ChatListRow>, AppError> {
        let account = self.account_home().account(label)?;
        self.ensure_account_state(&account.label)?;
        let mut row = self
            .account_storage(&account.label)?
            .initialize_chat_read_state(&account.account_id_hex, group_id_hex)?;
        self.hydrate_chat_list_row(row.as_mut())?;
        Ok(row)
    }

    pub fn mark_timeline_message_read(
        &self,
        label: &str,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> Result<Option<ChatListRow>, AppError> {
        let account = self.account_home().account(label)?;
        self.ensure_account_state(&account.label)?;
        let mut row = self
            .account_storage(&account.label)?
            .mark_timeline_message_read(&account.account_id_hex, group_id_hex, message_id_hex)?;
        self.hydrate_chat_list_row(row.as_mut())?;
        Ok(row)
    }

    pub fn notification_settings(
        &self,
        account_ref: &str,
    ) -> Result<NotificationSettings, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(notification_settings_from_account(
            self.account_storage(&account.label)?
                .notification_settings(&account.label, &account.account_id_hex)?,
        ))
    }

    pub fn set_local_notifications_enabled(
        &self,
        account_ref: &str,
        enabled: bool,
    ) -> Result<NotificationSettings, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(notification_settings_from_account(
            self.account_storage(&account.label)?
                .set_local_notifications_enabled(
                    &account.label,
                    &account.account_id_hex,
                    enabled,
                )?,
        ))
    }

    pub fn set_native_push_enabled(
        &self,
        account_ref: &str,
        enabled: bool,
    ) -> Result<NotificationSettings, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        let storage = self.account_storage(&account.label)?;
        let settings = notification_settings_from_account(storage.set_native_push_enabled(
            &account.label,
            &account.account_id_hex,
            enabled,
        )?);
        if !enabled {
            let _ = storage.clear_push_registration(&account.label)?;
        }
        Ok(settings)
    }

    pub fn push_registration(
        &self,
        account_ref: &str,
    ) -> Result<Option<PushRegistration>, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .push_registration(&account.label)?
            .map(stored_push_registration_from_account)
            .transpose()?
            .map(|stored| stored.registration))
    }

    pub(crate) fn stored_push_registration(
        &self,
        account_ref: &str,
    ) -> Result<Option<notifications::StoredPushRegistration>, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .push_registration(&account.label)?
            .map(stored_push_registration_from_account)
            .transpose()
    }

    pub fn upsert_push_registration(
        &self,
        account_ref: &str,
        platform: PushPlatform,
        raw_token: &str,
        server_pubkey_hex: &str,
        relay_hint: Option<String>,
    ) -> Result<PushRegistration, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        let token_bytes = parse_provider_token(platform, raw_token)?;
        let server_pubkey = PublicKey::parse(server_pubkey_hex)
            .map_err(|_| AppError::InvalidPushServer("server pubkey must be valid".into()))?;
        let now = notifications::unix_now_ms();
        let registration = PushRegistration {
            account_ref: account.label.clone(),
            account_id_hex: account.account_id_hex.clone(),
            platform,
            token_fingerprint: push_token_fingerprint(platform, &token_bytes),
            server_pubkey_hex: server_pubkey.to_hex(),
            relay_hint: relay_hint.and_then(|relay| {
                let relay = relay.trim().to_owned();
                (!relay.is_empty()).then_some(relay)
            }),
            created_at_ms: now,
            updated_at_ms: now,
            last_shared_at_ms: None,
        };
        let stored = self
            .account_storage(&account.label)?
            .upsert_push_registration(
                account_push_registration_from_app(registration),
                token_bytes,
            )?;
        Ok(stored_push_registration_from_account(stored)?.registration)
    }

    pub fn clear_push_registration(&self, account_ref: &str) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .clear_push_registration(&account.label)?;
        Ok(())
    }

    pub(crate) fn mark_push_registration_shared(
        &self,
        account_ref: &str,
        shared_at_ms: i64,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .mark_push_registration_shared(&account.label, shared_at_ms)?;
        Ok(())
    }

    pub(crate) fn upsert_group_push_token(
        &self,
        account_ref: &str,
        token: &GroupPushTokenRecord,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .upsert_group_push_token(&account_group_push_token_from_app(token))?;
        Ok(())
    }

    pub(crate) fn group_push_tokens(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<Vec<GroupPushTokenRecord>, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .group_push_tokens(group_id_hex)?
            .into_iter()
            .map(group_push_token_from_account)
            .collect()
    }

    pub(crate) fn ingest_push_gossip_message(
        &self,
        account_ref: &str,
        message: &ReceivedMessage,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        let group_id_hex = hex::encode(message.group_id.as_slice());
        let storage = self.account_storage(&account.label)?;
        match notifications::parse_push_gossip(message.kind, &group_id_hex, &message.plaintext)? {
            notifications::PushGossipAction::Upsert(records) => {
                for record in records {
                    storage.upsert_group_push_token(&account_group_push_token_from_app(&record))?;
                }
            }
            notifications::PushGossipAction::Remove(removals) => {
                for removal in removals {
                    storage.remove_group_push_token(
                        &group_id_hex,
                        &removal.member_id_hex,
                        removal.platform.platform_byte(),
                        &removal.token_fingerprint,
                        &removal.server_pubkey_hex,
                    )?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn remove_group_push_tokens_for_member(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        member_id_hex: &str,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .remove_group_push_tokens_for_member(group_id_hex, member_id_hex)?;
        Ok(())
    }

    pub(crate) fn remove_stale_group_push_tokens(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        active_members: &[String],
    ) -> Result<usize, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .remove_stale_group_push_tokens(group_id_hex, active_members)?)
    }

    pub fn group_push_debug_info(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        active_members: &[String],
    ) -> Result<GroupPushDebugInfo, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        let storage = self.account_storage(&account.label)?;
        let settings = notification_settings_from_account(
            storage.notification_settings(&account.label, &account.account_id_hex)?,
        );
        let registration = storage
            .push_registration(&account.label)?
            .map(stored_push_registration_from_account)
            .transpose()?;
        let tokens = storage
            .group_push_tokens(group_id_hex)?
            .into_iter()
            .map(group_push_token_from_account)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(notifications::group_debug_info(
            settings,
            registration,
            tokens,
            &account.account_id_hex,
            active_members,
        ))
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
        // Optional forensic audit log. Enable `AuditLogSettings` before opening
        // an account session to record per-account/device JSONL at
        // `<account_dir>/audit-<engine_id>.jsonl`. Sensitive mode — raw values.
        // Temporary forensic measure; disable the setting and remove files when
        // done debugging.
        let mut session_config = SessionConfig::new(
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
        });
        let audit_log_enabled = match self.audit_log_settings() {
            Ok(settings) => settings.enabled,
            Err(e) => {
                tracing::warn!(
                    target: "marmot_app",
                    method = "open_account",
                    error = %e,
                    "failed to read forensic audit log settings; continuing without audit logging"
                );
                false
            }
        };
        if audit_log_enabled {
            let account_dir = self.account_dir(label);
            match audit_device_id_hex(&account_dir) {
                Ok(device_id_hex) => {
                    let account_ref_hex = audit_account_ref_hex(&account_id);
                    let engine_id_hex = audit_engine_id_hex(&account_id, &device_id_hex);
                    let audit_path = account_dir.join(format!("audit-{engine_id_hex}.jsonl"));
                    match marmot_forensics::JsonlRecorder::open_with_account_ref(
                        &audit_path,
                        engine_id_hex.clone(),
                        Some(account_ref_hex),
                    ) {
                        Ok(recorder) => {
                            session_config = session_config.recorder(Box::new(recorder));
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "marmot_app",
                                method = "open_account",
                                error = %e,
                                "failed to open forensic audit log; continuing without it"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "marmot_app",
                        method = "open_account",
                        error = %e,
                        "failed to prepare forensic audit identity; continuing without it"
                    );
                }
            }
        }
        let session = AccountDeviceSession::open(session_config)?;

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
        let path = self.key_package_record_path(label);
        if !path.exists() {
            return Err(AppError::MissingKeyPackage(label.to_owned()));
        }
        let record: KeyPackageRecord = read_json(path)?;
        key_package_from_hex_with_optional_source(
            &record.key_package_hex,
            &record.key_package_event_id,
        )
    }

    pub fn local_key_package_records(
        &self,
        label: &str,
    ) -> Result<Vec<AccountKeyPackageRecord>, AppError> {
        let path = self.key_package_record_path(label);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let record: KeyPackageRecord = read_json(path)?;
        Ok(vec![self.account_key_package_record_from_local(record)?])
    }

    pub async fn account_key_package_records(
        &self,
        label: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<Vec<AccountKeyPackageRecord>, AppError> {
        let keys = self.account_home().load_signing_keys(label)?;
        let account_id_hex = keys.public_key().to_hex();
        let mut packages = self.local_key_package_records(label)?;

        let has_explicit_bootstrap_relays = !bootstrap_relays.is_empty();
        let mut relay_lists = if has_explicit_bootstrap_relays {
            self.fetch_account_relay_list_status_for_account_id(&account_id_hex, bootstrap_relays)
                .await?
        } else {
            self.account_relay_list_status_for_account_id(&account_id_hex)?
        };
        // Discover the account's NIP-65 list via default relays when it is not
        // cached yet, mirroring fetch_latest_key_package_for_account_id. We never
        // pull KeyPackage events from arbitrary default relays: the source set is
        // always the account's own NIP-65 relays, and we fail closed when that
        // list is missing.
        if !has_explicit_bootstrap_relays && relay_lists.nip65.relays.is_empty() {
            let discovery_relays = self.directory_source_relays(&[]);
            if !discovery_relays.is_empty() {
                relay_lists = self
                    .fetch_account_relay_list_status_for_account_id(
                        &account_id_hex,
                        discovery_relays,
                    )
                    .await?;
            }
        }
        if relay_lists.nip65.relays.is_empty() {
            return Err(AppError::MissingRelayLists(vec!["nip65".into()]));
        }
        let source_relays = relay_lists
            .nip65
            .relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();

        if !source_relays.is_empty() {
            let mut relay_records = self
                .fetch_key_package_events_for_account_id(&account_id_hex, &source_relays)
                .await?;
            sort_directory_records(&mut relay_records);
            for record in relay_records {
                match key_package_from_record(record) {
                    Ok(fetched) => {
                        packages.push(account_key_package_record_from_fetched(fetched));
                    }
                    Err(err) => {
                        tracing::warn!(
                            target: "marmot_app::key_packages",
                            method = "account_key_package_records",
                            error = %err,
                            "skipping invalid key package event while listing account packages"
                        );
                    }
                }
            }
        }

        Ok(merge_key_package_records(packages))
    }

    pub async fn delete_key_package_event(
        &self,
        label: &str,
        event_id_hex: &str,
        source_relays: Vec<TransportEndpoint>,
    ) -> Result<usize, AppError> {
        let event_id_hex = parse_key_package_event_id_hex(event_id_hex)?;
        let keys = self.account_home().load_signing_keys(label)?;
        let account_id_hex = keys.public_key().to_hex();
        let mut endpoints = source_relays;
        if endpoints.is_empty() {
            let relay_lists = self.account_relay_list_status_for_account_id(&account_id_hex)?;
            endpoints = self.key_package_endpoints(&relay_lists);
        }
        if endpoints.is_empty() {
            return Err(AppError::MissingRelayLists(vec!["nip65".into()]));
        }

        let event = NostrTransportEvent::new_unsigned(
            account_id_hex,
            5,
            vec![
                vec!["e".into(), event_id_hex.clone()],
                vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
            ],
            String::new(),
        );
        let outcome = self
            .relay_client_for_endpoints(&keys, &endpoints)
            .publish_event(&endpoints, &event, 1)
            .await?;

        let path = self.key_package_record_path(label);
        if let Ok(record) = read_json::<KeyPackageRecord>(&path)
            && record.key_package_event_id == event_id_hex
        {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }

        Ok(outcome.accepted.len())
    }

    fn account_key_package_record_from_local(
        &self,
        record: KeyPackageRecord,
    ) -> Result<AccountKeyPackageRecord, AppError> {
        let source_relays = self
            .account_nip65_relays(&record.account_label)
            .unwrap_or_default();
        Ok(AccountKeyPackageRecord {
            account_label: Some(record.account_label),
            account_id_hex: record.account_id_hex,
            key_package_id: record.key_package_id,
            key_package_ref_hex: record.key_package_ref_hex,
            key_package_event_id: record.key_package_event_id,
            published_at: record.published_at,
            key_package_bytes: hex::decode(record.key_package_hex)?.len(),
            source_relays,
            local: true,
            relay: false,
        })
    }

    fn key_package_record_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.json"))
    }

    fn reusable_key_package_slot_id(&self, label: &str, account_id_hex: &str) -> Option<String> {
        let record: KeyPackageRecord = read_json(self.key_package_record_path(label)).ok()?;
        if record.account_id_hex != account_id_hex || record.key_package_id.is_empty() {
            return None;
        }
        let bytes = hex::decode(&record.key_package_hex).ok()?;
        let metadata = key_package_metadata(&KeyPackage::new(bytes)).ok()?;
        (metadata.credential_identity_hex == account_id_hex).then_some(record.key_package_id)
    }

    async fn publish_cached_key_package(
        &self,
        label: &str,
        key_package: KeyPackage,
    ) -> Result<KeyPackage, AppError> {
        let keys = self.account_home().load_signing_keys(label)?;
        let account_id_hex = keys.public_key().to_hex();
        let relay_lists = self.account_relay_list_status_for_account_id(&account_id_hex)?;
        if relay_lists.nip65.relays.is_empty() {
            return Err(AppError::MissingRelayLists(vec!["nip65".into()]));
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
            if !entry.relay_lists.nip65.relays.is_empty() {
                let source_relays = entry
                    .relay_lists
                    .nip65
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
                upsert_newer_directory_entry(
                    &mut entries_by_id,
                    self.hydrate_directory_record(entry)?,
                );
            }
        }
        for record in self.shared_storage()?.public_directory_users()? {
            let entry = self.hydrate_public_directory_record(record)?;
            upsert_newer_directory_entry(&mut entries_by_id, entry);
        }
        Ok(entries_by_id.into_values().collect())
    }

    fn directory_sync_plan(&self) -> Result<DirectorySyncPlan, AppError> {
        let mut account_ids = self
            .directory_entries()?
            .into_iter()
            .map(|entry| entry.account_id_hex)
            .collect::<Vec<_>>();
        account_ids.extend(
            self.account_home()
                .accounts()?
                .into_iter()
                .filter(|account| account.local_signing)
                .map(|account| account.account_id_hex),
        );
        Ok(DirectorySyncPlan::from_known_users(
            self.relay_endpoints(),
            account_ids,
            None,
        ))
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

                let Some(record) = Self::directory_search_record_from_caches(&caches, &account_id)?
                else {
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

    fn directory_search_record_from_caches(
        caches: &[DirectoryCache],
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        for cache in caches {
            if let Some(entry) = cache.search_record(account_id_hex)? {
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

    fn hydrate_chat_list_rows(&self, rows: &mut [ChatListRow]) -> Result<(), AppError> {
        let mut names = HashMap::new();
        let senders = rows
            .iter()
            .filter_map(|row| {
                row.last_message
                    .as_ref()
                    .map(|message| message.sender.clone())
            })
            .collect::<HashSet<_>>();
        for sender in senders {
            if let Some(name) = self.display_name_for_account_id(&sender)? {
                names.insert(sender, name);
            }
        }
        for row in rows {
            let Some(message) = row.last_message.as_mut() else {
                continue;
            };
            if let Some(name) = names.get(&message.sender) {
                message.sender_display_name = Some(name.clone());
            }
        }
        Ok(())
    }

    fn hydrate_chat_list_row(&self, row: Option<&mut ChatListRow>) -> Result<(), AppError> {
        let Some(row) = row else {
            return Ok(());
        };
        let Some(message) = row.last_message.as_mut() else {
            return Ok(());
        };
        if let Some(name) = self.display_name_for_account_id(&message.sender)? {
            message.sender_display_name = Some(name);
        }
        Ok(())
    }

    fn load_state(&self, label: &str) -> Result<AccountState, AppError> {
        self.ensure_account_state(label)?;
        account_state_from_stored(
            self.account_storage(label)?
                .load_account_projection_state(label, MAX_SEEN_EVENT_IDS)?,
        )
    }

    fn save_state(&self, state: &AccountState) -> Result<(), AppError> {
        self.account_storage(&state.label)?
            .save_account_projection_state(
                &stored_state_from_account_state(state),
                MAX_SEEN_EVENT_IDS,
            )?;
        self.chat_list_projection_stale
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(state.label.clone());
        Ok(())
    }

    fn ensure_account_state(&self, label: &str) -> Result<(), AppError> {
        let _span = tracing::debug_span!(
            target: "marmot_app::storage",
            "ensure_account_state",
            method = "ensure_account_state"
        )
        .entered();
        self.account_home().account(label)?;
        let mut ready = self
            .account_state_ready
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if ready.contains(label) {
            return Ok(());
        }
        self.migrate_legacy_account_projection_if_needed(label)?;
        self.account_storage(label)?
            .ensure_account_projection(label)?;
        ready.insert(label.to_owned());
        Ok(())
    }

    fn ensure_chat_list_projection(&self, account: &AccountSummary) -> Result<(), AppError> {
        let stale = self
            .chat_list_projection_stale
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&account.label);
        let warmed = self
            .chat_list_projection_warmed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&account.label);
        if warmed && !stale {
            return Ok(());
        }
        let storage = self.account_storage(&account.label)?;
        if stale {
            storage.refresh_chat_list_rows(&account.account_id_hex)?;
        } else {
            storage.ensure_chat_list_rows(&account.account_id_hex)?;
        }
        self.chat_list_projection_warmed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(account.label.clone());
        self.chat_list_projection_stale
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&account.label);
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
        // KeyPackages publish to (and are fetched from) the account's NIP-65
        // (kind 10002) outbox relays; there is no dedicated KeyPackage relay
        // list. Fall back to the configured default relays when the account has
        // no NIP-65 list yet.
        if !relay_lists.nip65.relays.is_empty() {
            return relay_lists
                .nip65
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

    fn legacy_account_projection_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(LEGACY_ACCOUNT_APP_DB_FILE)
    }

    fn account_storage_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(SESSION_DB_FILE)
    }

    fn account_storage(&self, label: &str) -> Result<SqliteAccountStorage, AppError> {
        if let Some(storage) = self
            .account_storages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(label)
            .cloned()
        {
            return Ok(storage);
        }
        let _span = tracing::debug_span!(
            target: "marmot_app::storage",
            "account_storage_open",
            method = "account_storage"
        )
        .entered();
        let keys = self.account_home().load_signing_keys(label)?;
        let path = self.account_storage_path(label);
        let key = self.sqlcipher_key(label, &keys, &path, SqlcipherDatabaseKind::Session)?;
        let storage = SqliteAccountStorage::open_encrypted(&path, &key)?;
        let mut storages = self
            .account_storages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(storages
            .entry(label.to_owned())
            .or_insert_with(|| storage.clone())
            .clone())
    }

    pub(crate) fn record_account_app_event(
        &self,
        label: &str,
        message: &AppMessageProjection,
    ) -> Result<AppProjectionUpdate, AppError> {
        let now = unix_now_seconds();
        let storage_update = self
            .account_storage(label)?
            .record_app_event(&stored_app_event_from_projection(message, now))?;
        self.app_projection_update(label, storage_update)
    }

    pub(crate) fn invalidate_timeline_source_message(
        &self,
        label: &str,
        source_message_id_hex: &str,
        reason: &str,
    ) -> Result<Option<AppProjectionUpdate>, AppError> {
        let update = self
            .account_storage(label)?
            .invalidate_app_event_by_source(source_message_id_hex, reason)?;
        update
            .map(|update| self.app_projection_update(label, update))
            .transpose()
    }

    pub(crate) fn invalidate_timeline_app_event(
        &self,
        label: &str,
        message_id_hex: &str,
        reason: &str,
    ) -> Result<Option<AppProjectionUpdate>, AppError> {
        let update = self
            .account_storage(label)?
            .invalidate_app_event_by_message_id(message_id_hex, reason)?;
        update
            .map(|update| self.app_projection_update(label, update))
            .transpose()
    }

    fn app_projection_update(
        &self,
        label: &str,
        storage_update: TimelineProjectionUpdate,
    ) -> Result<AppProjectionUpdate, AppError> {
        let chat_list_row = self.refresh_chat_list_row(label, &storage_update.group_id_hex)?;
        let chat_list_trigger =
            ChatListUpdateTrigger::from_timeline_changes(&storage_update.changes);
        Ok(AppProjectionUpdate {
            group_id_hex: storage_update.group_id_hex,
            timeline_messages: storage_update.messages,
            timeline_changes: storage_update.changes,
            chat_list_row,
            chat_list_trigger,
        })
    }

    pub(crate) fn prune_account_app_events_before(
        &self,
        label: &str,
        group_id_hex: &str,
        cutoff_recorded_at: u64,
    ) -> Result<usize, AppError> {
        Ok(self
            .account_storage(label)?
            .prune_app_events_before(group_id_hex, cutoff_recorded_at)?)
    }

    fn migrate_legacy_account_projection_if_needed(&self, label: &str) -> Result<(), AppError> {
        let path = self.legacy_account_projection_path(label);
        if !path.exists() {
            return Ok(());
        }
        let storage = self.account_storage(label)?;
        if storage.account_import_marker(LEGACY_ACCOUNT_PROJECTION_IMPORT_MARKER)? {
            return Ok(());
        }

        let legacy = self.legacy_account_projection(label)?;
        let state = legacy.load_state(label)?;
        storage.save_account_projection_state(
            &stored_state_from_account_state(&state),
            MAX_SEEN_EVENT_IDS,
        )?;
        for message in legacy.messages(AppMessageQuery::default())? {
            if message.message_id_hex.is_empty() {
                continue;
            }
            storage.record_app_event(&stored_app_event_from_message_record(&message))?;
        }
        if let Some(settings) = legacy.existing_notification_settings(label)? {
            storage.notification_settings(label, &settings.account_id_hex)?;
            storage.set_local_notifications_enabled(
                label,
                &settings.account_id_hex,
                settings.local_notifications_enabled,
            )?;
            storage.set_native_push_enabled(
                label,
                &settings.account_id_hex,
                settings.native_push_enabled,
            )?;
        }
        if let Some(registration) = legacy.push_registration(label)? {
            storage.upsert_push_registration(
                account_push_registration_from_app(registration.registration),
                registration.token_bytes,
            )?;
        }
        for token in legacy.all_group_push_tokens()? {
            storage.upsert_group_push_token(&account_group_push_token_from_app(&token))?;
        }
        storage.mark_account_import_complete(LEGACY_ACCOUNT_PROJECTION_IMPORT_MARKER)?;
        Ok(())
    }

    fn legacy_account_projection(
        &self,
        label: &str,
    ) -> Result<LegacyAccountProjectionDb, AppError> {
        let keys = self.account_home().load_signing_keys(label)?;
        let path = self.legacy_account_projection_path(label);
        let key = self.sqlcipher_key(
            label,
            &keys,
            &path,
            SqlcipherDatabaseKind::AccountProjection,
        )?;
        LegacyAccountProjectionDb::open(path, &key)
    }

    fn projection_status(&self, label: &str) -> AppProjectionStatus {
        let account_path = self.account_storage_path(label);
        let shared_path = self.shared_storage_path();
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
            key_package_ref_hex: fetched.key_package_ref_hex.clone(),
            key_package_event_id: fetched.key_package_event_id.clone(),
            key_package_hex: hex::encode(fetched.key_package.bytes()),
            created_at: fetched.created_at,
            source_relays: fetched.source_relays.clone(),
        });
        self.save_directory_entry(&entry)
    }

    fn remember_directory_user(&self, account_id_hex: &str) -> Result<(), AppError> {
        self.remember_directory_user_with_reason(account_id_hex, "directory")
    }

    fn remember_directory_user_with_reason(
        &self,
        account_id_hex: &str,
        reason: &str,
    ) -> Result<(), AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        let entry = self
            .directory_entry_for_account_id(&account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(&account_id_hex));
        self.save_directory_entry_with_reason(&entry, reason)
    }

    fn remember_directory_message_sender(&self, message: &ReceivedMessage) -> Result<(), AppError> {
        self.remember_directory_user_with_reason(&message.sender, "message")
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

    fn remember_directory_profile_if_newer(
        &self,
        account_id_hex: &str,
        profile: &UserProfileMetadata,
    ) -> Result<(), AppError> {
        if let Some(entry) = self.directory_entry_for_account_id(account_id_hex)?
            && entry
                .profile
                .as_ref()
                .is_some_and(|cached| cached.created_at > profile.created_at)
        {
            return Ok(());
        }
        self.remember_directory_profile(account_id_hex, profile)
    }

    fn remember_directory_relay_list_event(
        &self,
        account_id_hex: &str,
        record: &RelayEventRecord,
    ) -> Result<(), AppError> {
        let relays = relays_from_relay_list_event(&record.event);
        if relays.is_empty() {
            return Ok(());
        }
        let mut entry = self
            .directory_entry_for_account_id(account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(account_id_hex));
        match record.event.kind {
            KIND_NIP65_RELAY_LIST => entry.relay_lists.nip65.relays = relays,
            KIND_MARMOT_INBOX_RELAY_LIST => entry.relay_lists.inbox.relays = relays,
            _ => return Ok(()),
        }
        push_unique_strings(
            &mut entry.relay_lists.bootstrap_relays,
            source_relays_from_record(record),
        );
        entry.relay_lists.refresh();
        self.save_directory_entry(&entry)
    }

    fn ingest_directory_relay_event(&self, record: RelayEventRecord) -> Result<(), AppError> {
        if !self.directory_freshness().accepts(&record) {
            return Ok(());
        }
        let account_id_hex = parse_account_id_hex(&record.event.pubkey)?;
        match record.event.kind {
            KIND_NOSTR_METADATA => {
                if let Some((profile_account_id, profile)) = profile_from_record(record) {
                    self.remember_directory_profile_if_newer(&profile_account_id, &profile)?;
                }
            }
            KIND_NOSTR_CONTACT_LIST => {
                let follow_list = follow_list_from_record(record);
                self.remember_directory_follow_list(&account_id_hex, &follow_list)?;
            }
            KIND_NIP65_RELAY_LIST | KIND_MARMOT_INBOX_RELAY_LIST => {
                self.remember_directory_relay_list_event(&account_id_hex, &record)?;
            }
            KIND_MARMOT_KEY_PACKAGE => {
                let mut fetched = key_package_from_record(record)?;
                fetched.relay_lists = self
                    .account_relay_list_status_for_account_id(&account_id_hex)
                    .unwrap_or_else(|_| AccountRelayListStatus::empty());
                self.remember_directory_key_package(&fetched)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn save_directory_entry(&self, entry: &UserDirectoryRecord) -> Result<(), AppError> {
        self.save_directory_entry_with_reason(entry, "directory")
    }

    fn save_directory_entry_with_reason(
        &self,
        entry: &UserDirectoryRecord,
        reason: &str,
    ) -> Result<(), AppError> {
        let proposed_entry = self.hydrate_directory_record(entry.clone())?;
        let shared_storage = self.shared_storage()?;
        let shared_entry = shared_storage
            .public_directory_user(&proposed_entry.account_id_hex)?
            .map(|record| self.hydrate_public_directory_record(record))
            .transpose()?;
        let entry = select_newer_directory_entry(Some(proposed_entry), shared_entry)
            .expect("proposed directory entry should be present");
        shared_storage.put_public_directory_user(&public_directory_user_record(&entry)?)?;
        for cache in self.directory_caches()? {
            cache.put_with_reason(&entry, reason)?;
        }
        self.request_directory_sync_rebuild();
        Ok(())
    }

    fn set_directory_sync_handle(&self, handle: Option<DirectorySyncHandle>) {
        *self
            .directory_sync
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = handle;
    }

    fn request_directory_sync_rebuild(&self) {
        let handle = self
            .directory_sync
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(handle) = handle {
            handle.request_rebuild();
        }
    }

    fn directory_cache_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(APP_CACHE_DB_FILE)
    }

    fn shared_storage_path(&self) -> PathBuf {
        self.root.join(SHARED_DB_FILE)
    }

    fn shared_storage(&self) -> Result<SqliteSharedStorage, AppError> {
        if let Some(storage) = self
            .shared_storage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .cloned()
        {
            return Ok(storage);
        }
        let _span = tracing::debug_span!(
            target: "marmot_app::storage",
            "shared_storage_open",
            method = "shared_storage"
        )
        .entered();
        let storage = SqliteSharedStorage::open(self.shared_storage_path())?;
        let mut shared = self
            .shared_storage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(shared.get_or_insert_with(|| storage.clone()).clone())
    }

    fn validate_audit_log_path(&self, path: &str) -> Result<PathBuf, AppError> {
        let path = path.trim();
        if path.is_empty() {
            return Err(AppError::InvalidAuditLogFile(
                "audit log path is empty".to_owned(),
            ));
        }
        let path = PathBuf::from(path);
        if audit_log_file_name(&path).is_none() {
            return Err(AppError::InvalidAuditLogFile(
                "audit log file must be named audit-*.jsonl".to_owned(),
            ));
        }
        let path = fs::canonicalize(path)?;
        let root = fs::canonicalize(&self.root)?;
        if !path.starts_with(&root) {
            return Err(AppError::InvalidAuditLogFile(
                "audit log file must be inside the app root".to_owned(),
            ));
        }
        Ok(path)
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

    fn hydrate_public_directory_record(
        &self,
        record: PublicDirectoryUserRecord,
    ) -> Result<UserDirectoryRecord, AppError> {
        self.hydrate_directory_record(user_directory_record_from_public(record)?)
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

fn public_directory_user_record(
    entry: &UserDirectoryRecord,
) -> Result<PublicDirectoryUserRecord, AppError> {
    let mut relay_lists = entry.relay_lists.clone();
    relay_lists.bootstrap_relays.clear();

    let profile_json = entry
        .profile
        .clone()
        .map(|mut profile| {
            profile.source_relays.clear();
            serde_json::to_string(&profile)
        })
        .transpose()?;
    let key_package_json = entry
        .key_package
        .clone()
        .map(|mut key_package| {
            key_package.source_relays.clear();
            serde_json::to_string(&key_package)
        })
        .transpose()?;

    Ok(PublicDirectoryUserRecord {
        account_id_hex: entry.account_id_hex.clone(),
        npub: entry.npub.clone(),
        profile_json,
        relay_lists_json: serde_json::to_string(&relay_lists)?,
        key_package_json,
        event_id_hex: entry.key_package.as_ref().and_then(|key_package| {
            (!key_package.key_package_event_id.is_empty())
                .then_some(key_package.key_package_event_id.clone())
        }),
        event_kind: None,
        event_created_at: entry
            .profile
            .as_ref()
            .map(|profile| profile.created_at)
            .or_else(|| {
                entry
                    .key_package
                    .as_ref()
                    .map(|key_package| key_package.created_at)
            }),
        follows: entry.follows.clone(),
    })
}

fn user_directory_record_from_public(
    record: PublicDirectoryUserRecord,
) -> Result<UserDirectoryRecord, AppError> {
    Ok(UserDirectoryRecord {
        account_id_hex: record.account_id_hex,
        npub: record.npub,
        local_account: None,
        profile: record
            .profile_json
            .map(|json| serde_json::from_str(&json))
            .transpose()?,
        follows: record.follows,
        follow_source_relays: Vec::new(),
        relay_lists: serde_json::from_str(&record.relay_lists_json)?,
        key_package: record
            .key_package_json
            .map(|json| serde_json::from_str(&json))
            .transpose()?,
    })
}

fn directory_record_recency(entry: &UserDirectoryRecord) -> u64 {
    entry
        .profile
        .as_ref()
        .map(|profile| profile.created_at)
        .into_iter()
        .chain(
            entry
                .key_package
                .as_ref()
                .map(|key_package| key_package.created_at),
        )
        .max()
        .unwrap_or_default()
}

fn select_newer_directory_entry(
    cached: Option<UserDirectoryRecord>,
    shared: Option<UserDirectoryRecord>,
) -> Option<UserDirectoryRecord> {
    match (cached, shared) {
        (Some(cached), Some(shared)) => {
            if directory_record_recency(&shared) > directory_record_recency(&cached) {
                Some(shared)
            } else {
                Some(cached)
            }
        }
        (Some(entry), None) | (None, Some(entry)) => Some(entry),
        (None, None) => None,
    }
}

fn upsert_newer_directory_entry(
    entries_by_id: &mut BTreeMap<String, UserDirectoryRecord>,
    entry: UserDirectoryRecord,
) {
    match entries_by_id.entry(entry.account_id_hex.clone()) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(entry);
        }
        std::collections::btree_map::Entry::Occupied(mut slot) => {
            if directory_record_recency(&entry) > directory_record_recency(slot.get()) {
                *slot.get_mut() = entry;
            }
        }
    }
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
        let account_id_hex = hex::encode(publication.account_id.as_slice());
        if metadata.credential_identity_hex != account_id_hex {
            return Err(KeyPackagePublishError(
                "KeyPackage credential identity does not match publication account".into(),
            ));
        }
        let key_package_id = self
            .app
            .reusable_key_package_slot_id(&self.account_label, &account_id_hex)
            .unwrap_or_else(|| {
                let mut slot_id = [0_u8; 32];
                OsRng.fill_bytes(&mut slot_id);
                hex::encode(slot_id)
            });
        let key_package_ref_hex = metadata.key_package_ref_hex;
        let relay_client = self
            .app
            .relay_client_for_endpoints(&self.keys, &publication.endpoints);
        let nostr_publication = NostrKeyPackagePublication {
            account_id: publication.account_id.clone(),
            key_package: publication.key_package.clone(),
            key_package_slot_id: key_package_id.clone(),
            key_package_ref: key_package_ref_hex.clone(),
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
                account_id_hex,
                key_package_id,
                key_package_ref_hex,
                key_package_event_id,
                published_at: unix_now_seconds(),
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
                KIND_NIP65_RELAY_LIST | KIND_MARMOT_INBOX_RELAY_LIST
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
    [KIND_NIP65_RELAY_LIST, KIND_MARMOT_INBOX_RELAY_LIST]
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
    let (decoded, key_package_ref_hex) =
        validated_cached_key_package_with_ref(&entry.account_id_hex, &key_package)?;
    Ok(Some(FetchedKeyPackage {
        account_id_hex: entry.account_id_hex,
        key_package: decoded,
        key_package_id: key_package.key_package_id,
        key_package_ref_hex,
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
    validated_cached_key_package_with_ref(account_id_hex, key_package)
        .map(|(key_package, _)| key_package)
}

fn validated_cached_key_package_with_ref(
    account_id_hex: &str,
    key_package: &DirectoryKeyPackage,
) -> Result<(KeyPackage, String), AppError> {
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
    if !key_package.key_package_ref_hex.is_empty()
        && key_package.key_package_ref_hex != metadata.key_package_ref_hex
    {
        return Err(AppError::InvalidKeyPackageEvent(
            "cached KeyPackage ref does not match decoded KeyPackageRef".into(),
        ));
    }
    Ok((decoded, metadata.key_package_ref_hex))
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
    !status.nip65.relays.is_empty() || !status.inbox.relays.is_empty()
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
        key_package_ref_hex: metadata.key_package_ref_hex,
        key_package_event_id: event.id,
        created_at: event.created_at,
        source_relays,
        relay_lists: AccountRelayListStatus::empty(),
    })
}

fn account_key_package_record_from_fetched(fetched: FetchedKeyPackage) -> AccountKeyPackageRecord {
    AccountKeyPackageRecord {
        account_label: None,
        account_id_hex: fetched.account_id_hex,
        key_package_id: fetched.key_package_id,
        key_package_ref_hex: fetched.key_package_ref_hex,
        key_package_event_id: fetched.key_package_event_id,
        published_at: fetched.created_at,
        key_package_bytes: fetched.key_package.bytes().len(),
        source_relays: fetched.source_relays,
        local: false,
        relay: true,
    }
}

fn merge_key_package_records(
    records: Vec<AccountKeyPackageRecord>,
) -> Vec<AccountKeyPackageRecord> {
    let mut merged: BTreeMap<String, AccountKeyPackageRecord> = BTreeMap::new();
    for record in records {
        let key = if !record.key_package_event_id.is_empty() {
            record.key_package_event_id.clone()
        } else if !record.key_package_ref_hex.is_empty() {
            record.key_package_ref_hex.clone()
        } else {
            record.key_package_id.clone()
        };
        merged
            .entry(key)
            .and_modify(|existing| {
                existing.local |= record.local;
                existing.relay |= record.relay;
                existing.published_at = existing.published_at.max(record.published_at);
                if existing.account_label.is_none() {
                    existing.account_label = record.account_label.clone();
                }
                push_unique_strings(&mut existing.source_relays, record.source_relays.clone());
            })
            .or_insert(record);
    }
    let mut records = merged.into_values().collect::<Vec<_>>();
    records.sort_by(|left, right| {
        right
            .published_at
            .cmp(&left.published_at)
            .then_with(|| left.key_package_event_id.cmp(&right.key_package_event_id))
    });
    records
}

fn parse_key_package_event_id_hex(value: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    let bytes = hex::decode(trimmed)?;
    if bytes.len() != 32 {
        return Err(AppError::InvalidKeyPackageEvent(format!(
            "KeyPackage event id must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(trimmed.to_owned())
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
        KIND_MARMOT_INBOX_RELAY_LIST => "relay",
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
    use cgka_traits::app_event::{
        EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
        MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION,
        MarmotAppEvent as MarmotInnerEvent, QUOTE_REF_TAG, STREAM_CHUNKS_TAG,
        STREAM_FINAL_KIND_TAG, STREAM_HASH_TAG, STREAM_START_TAG, STREAM_TAG, STREAM_TYPE_TAG,
    };
    use marmot_account::AccountHomeError;
    use transport_quic_broker::BrokerServerTrust;

    use crate::messages::STREAM_ROUTE_QUIC;
    use crate::messages::{AppMessageIntent, build_inner_event};

    #[test]
    fn legacy_projection_update_json_defaults_new_streaming_fields() {
        let update: AppProjectionUpdate = serde_json::from_str(
            r#"{"group_id_hex":"group","timeline_messages":[],"chat_list_row":null}"#,
        )
        .unwrap();

        assert!(update.timeline_changes.is_empty());
        assert_eq!(
            update.chat_list_trigger,
            ChatListUpdateTrigger::SnapshotRefresh
        );
    }

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

        assert_eq!(queries.len(), 2);
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
            vec![KIND_NIP65_RELAY_LIST, KIND_MARMOT_INBOX_RELAY_LIST]
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
    fn directory_search_uses_graph_cache_without_promoting_known_user() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let cache = app.directory_cache_for_account(&account).unwrap();
        let graph_user = format!("{:064x}", 42);

        cache
            .put(&UserDirectoryRecord {
                account_id_hex: account.account_id_hex.clone(),
                npub: npub_for_account_id_lossy(&account.account_id_hex),
                local_account: None,
                profile: None,
                follows: vec![graph_user.clone()],
                follow_source_relays: Vec::new(),
                relay_lists: AccountRelayListStatus::empty(),
                key_package: None,
            })
            .unwrap();
        cache
            .put_search_graph_record(
                &directory::DirectorySearchGraphRecord {
                    account_id_hex: graph_user.clone(),
                    npub: npub_for_account_id_lossy(&graph_user),
                    profile: Some(UserProfileMetadata {
                        name: Some("graph-needle".into()),
                        display_name: None,
                        about: None,
                        picture: None,
                        nip05: None,
                        lud16: None,
                        created_at: 1_700_000_001,
                        source_relays: Vec::new(),
                    }),
                    follows: Some(Vec::new()),
                    metadata_updated_at: Some(1_700_000_001),
                    metadata_expires_at: None,
                },
                1_700_000_002,
            )
            .unwrap();

        let results = app
            .search_user_directory(UserDirectorySearch {
                searcher_account_id_hex: account.account_id_hex.clone(),
                query: "graph-needle".into(),
                radius_start: 1,
                radius_end: 1,
                limit: None,
            })
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].account_id_hex, graph_user);
        assert!(
            app.directory_entry_for_account_id(&graph_user)
                .unwrap()
                .is_none()
        );
    }

    fn test_directory_record(
        account_id_hex: &str,
        name: &str,
        created_at: u64,
    ) -> UserDirectoryRecord {
        UserDirectoryRecord {
            account_id_hex: account_id_hex.to_owned(),
            npub: npub_for_account_id_lossy(account_id_hex),
            local_account: None,
            profile: Some(UserProfileMetadata {
                name: Some(name.to_owned()),
                display_name: None,
                about: None,
                picture: None,
                nip05: None,
                lud16: None,
                created_at,
                source_relays: Vec::new(),
            }),
            follows: Vec::new(),
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        }
    }

    #[test]
    fn directory_entry_prefers_newer_shared_record_over_stale_cache() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let cache = app.directory_cache_for_account(&account).unwrap();
        let contact = format!("{:064x}", 42);

        cache
            .put(&test_directory_record(&contact, "old-cache", 1))
            .unwrap();
        app.shared_storage()
            .unwrap()
            .put_public_directory_user(
                &public_directory_user_record(&test_directory_record(&contact, "new-shared", 2))
                    .unwrap(),
            )
            .unwrap();

        let entry = app
            .directory_entry_for_account_id(&contact)
            .unwrap()
            .unwrap();

        assert_eq!(
            entry.profile.and_then(|profile| profile.name),
            Some("new-shared".to_owned())
        );
    }

    #[test]
    fn directory_entries_and_save_keep_newer_shared_record() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let cache = app.directory_cache_for_account(&account).unwrap();
        let contact = format!("{:064x}", 43);
        let stale = test_directory_record(&contact, "old-cache", 1);
        let fresh = test_directory_record(&contact, "new-shared", 2);

        cache.put(&stale).unwrap();
        app.shared_storage()
            .unwrap()
            .put_public_directory_user(&public_directory_user_record(&fresh).unwrap())
            .unwrap();

        let listed = app.directory_entries().unwrap();
        let listed_entry = listed
            .iter()
            .find(|entry| entry.account_id_hex == contact)
            .unwrap();
        assert_eq!(
            listed_entry
                .profile
                .as_ref()
                .and_then(|profile| profile.name.as_deref()),
            Some("new-shared")
        );

        app.save_directory_entry_with_reason(&stale, "stale-cache")
            .unwrap();
        let entry = app
            .directory_entry_for_account_id(&contact)
            .unwrap()
            .unwrap();
        assert_eq!(
            entry.profile.and_then(|profile| profile.name),
            Some("new-shared".to_owned())
        );
    }

    #[test]
    fn received_message_sender_is_admitted_to_directory_cache() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("bob").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let sender = format!("{:064x}", 42);

        assert!(
            app.directory_entry_for_account_id(&sender)
                .unwrap()
                .is_none()
        );
        app.remember_directory_message_sender(&ReceivedMessage {
            message_id_hex: "message-id".to_owned(),
            source_message_id_hex: "source-message-id".to_owned(),
            sender: sender.clone(),
            sender_display_name: None,
            group_id: GroupId::new(vec![0x01]),
            plaintext: "hello".to_owned(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: Vec::new(),
            recorded_at: 0,
        })
        .unwrap();

        let entry = app
            .directory_entry_for_account_id(&sender)
            .unwrap()
            .unwrap();
        assert_eq!(entry.account_id_hex, sender);
        assert!(entry.profile.is_none());
        assert!(entry.follows.is_empty());
    }

    #[test]
    fn directory_sync_plan_watches_local_accounts_and_known_users() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let contact = format!("{:064x}", 42);

        app.remember_directory_user_with_reason(&contact, "message")
            .unwrap();

        let plan = app.directory_sync_plan().unwrap();
        let watched = plan
            .batches
            .iter()
            .flat_map(|batch| batch.authors.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            plan.endpoints,
            vec![TransportEndpoint("wss://relay.example".to_owned())]
        );
        assert_eq!(plan.watched_user_count, 2);
        assert!(watched.contains(&account.account_id_hex));
        assert!(watched.contains(&contact));
    }

    #[test]
    fn sqlcipher_keys_use_stable_per_database_salts() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let session_path = app.account_dir("alice").join(SESSION_DB_FILE);
        let projection_path = app.legacy_account_projection_path("alice");

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
        let projection_path = app.legacy_account_projection_path("alice");
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
    fn legacy_account_projection_imports_once_into_account_storage() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let legacy_path = app.legacy_account_projection_path("alice");
        let legacy_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &legacy_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();
        let mut legacy = LegacyAccountProjectionDb::open(legacy_path.clone(), &legacy_key).unwrap();
        let group = AppGroupRecord::new(
            "aa".to_owned(),
            AppGroupNostrRoutingComponent::new(
                NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
            )
            .unwrap(),
            "legacy".to_owned(),
            String::new(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(Vec::new()),
            AppGroupMessageRetentionComponent::disabled(),
        );
        legacy
            .save_state(&AccountState {
                label: "alice".to_owned(),
                seen_events: vec!["seen".to_owned()],
                last_transport_timestamp: Some(1_700_000_100),
                groups: vec![group],
            })
            .unwrap();
        legacy
            .record_message(&AppMessageProjection {
                message_id_hex: "legacy-message".to_owned(),
                source_message_id_hex: None,
                direction: "received".to_owned(),
                group_id_hex: "aa".to_owned(),
                sender: account.account_id_hex.clone(),
                plaintext: "from legacy".to_owned(),
                kind: 9,
                tags: Vec::new(),
                recorded_at: Some(1_700_000_101),
            })
            .unwrap();
        legacy
            .set_native_push_enabled("alice", &account.account_id_hex, true)
            .unwrap();
        legacy
            .upsert_push_registration(
                PushRegistration {
                    account_ref: "alice".to_owned(),
                    account_id_hex: account.account_id_hex.clone(),
                    platform: PushPlatform::Apns,
                    token_fingerprint: "fingerprint".to_owned(),
                    server_pubkey_hex: "bb".repeat(32),
                    relay_hint: Some("wss://relay.example".to_owned()),
                    created_at_ms: 10,
                    updated_at_ms: 11,
                    last_shared_at_ms: None,
                },
                vec![1, 2, 3],
            )
            .unwrap();
        legacy
            .upsert_group_push_token(&GroupPushTokenRecord {
                group_id_hex: "aa".to_owned(),
                member_id_hex: account.account_id_hex.clone(),
                leaf_index: 7,
                platform: PushPlatform::Apns,
                token_fingerprint: "fingerprint".to_owned(),
                server_pubkey_hex: "bb".repeat(32),
                relay_hint: None,
                encrypted_token: vec![9, 8, 7],
                updated_at_ms: 12,
            })
            .unwrap();

        let groups = app.groups("alice").unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].profile.name, "legacy");
        let messages = app.messages("alice").unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].plaintext, "from legacy");
        let settings = app.notification_settings("alice").unwrap();
        assert!(settings.native_push_enabled);
        assert!(app.push_registration("alice").unwrap().is_some());
        assert_eq!(app.group_push_tokens("alice", "aa").unwrap().len(), 1);

        legacy
            .record_message(&AppMessageProjection {
                message_id_hex: "post-marker".to_owned(),
                source_message_id_hex: None,
                direction: "received".to_owned(),
                group_id_hex: "aa".to_owned(),
                sender: account.account_id_hex,
                plaintext: "should stay legacy-only".to_owned(),
                kind: 9,
                tags: Vec::new(),
                recorded_at: Some(1_700_000_102),
            })
            .unwrap();
        assert_eq!(app.messages("alice").unwrap().len(), 1);
    }

    #[test]
    fn own_relay_echo_requires_known_event_id_not_just_pubkey() {
        let local_pubkey = "11".repeat(32);
        let known_event_id = "22".repeat(32);
        let new_cross_device_event_id = "33".repeat(32);
        let known_event_ids = HashSet::from([known_event_id.clone()]);

        let known_local_delivery = relay_delivery(known_event_id.clone(), local_pubkey.clone());
        assert!(client::is_own_relay_echo(
            &known_local_delivery,
            &local_pubkey,
            &known_event_ids
        ));

        let same_pubkey_new_event = relay_delivery(new_cross_device_event_id, local_pubkey.clone());
        assert!(!client::is_own_relay_echo(
            &same_pubkey_new_event,
            &local_pubkey,
            &known_event_ids
        ));

        let known_other_pubkey_delivery = relay_delivery(known_event_id, "44".repeat(32));
        assert!(!client::is_own_relay_echo(
            &known_other_pubkey_delivery,
            &local_pubkey,
            &known_event_ids
        ));
    }

    #[test]
    fn account_worker_is_spawned_as_abortable_async_task() {
        let source = include_str!("runtime.rs");

        assert!(source.contains("tokio::spawn(run_app_runtime_account_worker"));
        assert!(source.contains("managed account worker shutdown timed out; aborting"));
    }

    #[test]
    fn account_worker_reconnect_backoff_doubles_caps_and_resets() {
        let mut backoff = runtime::AccountWorkerReconnectBackoff::new(
            Duration::from_secs(2),
            Duration::from_secs(8),
        );

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

        let parsed = runtime::parse_quic_candidates(&candidates).expect("valid fallback candidate");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].authority, "127.0.0.1:4450");
        assert_eq!(parsed[0].server_name, "127.0.0.1");
    }

    #[test]
    fn agent_stream_insecure_local_only_applies_to_loopback_brokers() {
        let loopback = "127.0.0.1:4450".parse().unwrap();
        let remote = "203.0.113.10:4450".parse().unwrap();

        assert!(matches!(
            runtime::broker_trust_for_addr(loopback, None, true),
            BrokerServerTrust::InsecureLocal
        ));
        assert!(matches!(
            runtime::broker_trust_for_addr(remote, None, true),
            BrokerServerTrust::Platform
        ));
        assert!(matches!(
            runtime::broker_trust_for_addr(remote, Some(vec![1, 2, 3]), true),
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
        let message = groups::decode_received_event(
            &bytes,
            SENDER_HEX,
            None,
            &group_id,
            "msg1",
            1_700_000_000,
        )
        .expect("valid event is accepted");
        assert_eq!(message.plaintext, "hi");
        assert_eq!(message.kind, MARMOT_APP_EVENT_KIND_CHAT);
        assert_eq!(message.sender, SENDER_HEX);
        assert_eq!(message.recorded_at, 1_700_000_000);
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
        assert!(
            groups::decode_received_event(&bytes, SENDER_HEX, None, &group_id, "msg1", 0).is_none()
        );
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
        assert!(
            groups::decode_received_event(&bytes, other_sender, None, &group_id, "msg1", 0)
                .is_none()
        );
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

    #[test]
    fn audit_engine_id_is_stable_hash_not_raw_account_prefix() {
        let account_id = MemberId::new(vec![0xab; 32]);

        let engine_id = audit_engine_id_hex(&account_id, "01".repeat(16).as_str());

        assert_eq!(engine_id.len(), 32);
        assert_eq!(
            engine_id,
            audit_engine_id_hex(&account_id, "01".repeat(16).as_str())
        );
        assert_ne!(engine_id, hex::encode(&account_id.as_slice()[..16]));
    }

    #[test]
    fn audit_identity_hashes_separate_account_and_device_scope() {
        let account_id = MemberId::new(vec![0xab; 32]);
        let first_device = "01".repeat(16);
        let second_device = "02".repeat(16);

        let account_ref = audit_account_ref_hex(&account_id);
        let first_engine = audit_engine_id_hex(&account_id, &first_device);
        let second_engine = audit_engine_id_hex(&account_id, &second_device);

        assert_eq!(account_ref.len(), 32);
        assert_eq!(account_ref, audit_account_ref_hex(&account_id));
        assert_ne!(account_ref, hex::encode(&account_id.as_slice()[..16]));
        assert_ne!(first_engine, second_engine);
    }

    #[test]
    fn audit_device_id_is_generated_once_per_account_dir() {
        let dir = tempfile::tempdir().unwrap();

        let first = audit_device_id_hex(dir.path()).unwrap();
        let second = audit_device_id_hex(dir.path()).unwrap();

        assert_eq!(first.len(), 32);
        assert_eq!(first, second);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(AUDIT_DEVICE_ID_FILE))
                .unwrap()
                .trim(),
            first
        );
    }

    #[test]
    fn telemetry_install_id_is_stable_uuid_per_app_root() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

        let first = app.telemetry_install_id().unwrap();
        let second = app.telemetry_install_id().unwrap();
        let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .telemetry_install_id()
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(first, reopened);
        assert_eq!(first.len(), 36);
        assert_eq!(first.as_bytes()[14], b'4');
        assert_eq!(first.chars().filter(|ch| *ch == '-').count(), 4);
        assert_ne!(first.len(), AUDIT_ID_BYTES * 2);
    }

    #[test]
    fn relay_telemetry_settings_persist_in_shared_storage() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

        assert_eq!(
            app.relay_telemetry_settings().unwrap(),
            RelayTelemetrySettings::default()
        );

        let updated = RelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 30,
        };
        let stored = app.set_relay_telemetry_settings(updated).unwrap();

        assert_eq!(
            stored,
            RelayTelemetrySettings {
                export_enabled: true,
                export_interval_seconds: 30,
            }
        );
        assert_eq!(
            app.relay_telemetry_export_config().unwrap(),
            RelayTelemetryExportConfig {
                enabled: true,
                endpoint: None,
                interval: Duration::from_secs(30),
                authorization_bearer_token: None,
                resource: None,
            }
        );

        let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        assert_eq!(reopened.relay_telemetry_settings().unwrap(), stored);
    }

    #[test]
    fn relay_telemetry_settings_reject_zero_interval() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

        let err = app
            .set_relay_telemetry_settings(RelayTelemetrySettings {
                export_interval_seconds: 0,
                ..Default::default()
            })
            .expect_err("zero interval should be rejected");

        assert!(matches!(err, AppError::InvalidRelayTelemetrySettings(_)));
    }

    #[test]
    fn relay_telemetry_settings_reject_invalid_persisted_interval() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        app.shared_storage()
            .unwrap()
            .set_relay_telemetry_settings(&StoredRelayTelemetrySettings {
                export_enabled: true,
                export_interval_seconds: 0,
            })
            .unwrap();

        let err = app
            .relay_telemetry_settings()
            .expect_err("invalid persisted interval should be rejected");

        assert!(matches!(err, AppError::InvalidRelayTelemetrySettings(_)));
    }

    #[test]
    fn audit_log_settings_persist_in_shared_storage() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

        assert_eq!(
            app.audit_log_settings().unwrap(),
            AuditLogSettings::default()
        );

        let stored = app
            .set_audit_log_settings(AuditLogSettings { enabled: true })
            .unwrap();

        assert_eq!(stored, AuditLogSettings { enabled: true });

        let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        assert_eq!(reopened.audit_log_settings().unwrap(), stored);
    }
}
