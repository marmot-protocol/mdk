//! First app runtime bridge for Marmot.
//!
//! This crate wires `AccountHome` into the concrete local runtime pieces needed by
//! early app surfaces: encrypted session storage, Nostr MLS peeling, Nostr
//! transport publishing, and relay-backed app projections.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
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
    AGENT_TEXT_STREAM_QUIC_FANOUT_CAPABILITY, AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE,
    AGENT_TEXT_STREAM_QUIC_RECEIVE_CAPABILITY, AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE,
    AGENT_TEXT_STREAM_QUIC_SEND_CAPABILITY, AGENT_TEXT_STREAM_QUIC_SEND_FEATURE,
};
pub use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT as AGENT_TEXT_STREAM_COMPONENT,
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID as AGENT_TEXT_STREAM_COMPONENT_ID,
    GROUP_ADMIN_POLICY_COMPONENT, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT, GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_COMPONENT, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
    GROUP_MESSAGE_RETENTION_COMPONENT, GROUP_MESSAGE_RETENTION_COMPONENT_ID,
    GROUP_PROFILE_COMPONENT, GROUP_PROFILE_COMPONENT_ID, NOSTR_ROUTING_COMPONENT,
    NOSTR_ROUTING_COMPONENT_ID,
};
use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, NostrRoutingV1, default_group_components,
};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{GroupEvent, KeyPackage};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::{
    GroupId, MemberId, TransportEndpoint, TransportGroupSubscription, TransportPublishTarget,
};
use marmot_account::{
    AccountDeviceRuntime, AccountHome, AccountSummary, KeyPackagePublication,
    KeyPackagePublishError, KeyPackagePublisher, TransportRoutingError, TransportRoutingPolicy,
};
use nostr_sdk::prelude::{Client as NostrSdkClient, PublicKey};
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_sqlite::{
    SqliteAccountStorage, SqliteSharedStorage, StoredAppMessageQuery, TimelineProjectionUpdate,
};
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
    NostrAccountRelayListKind, NostrAccountRelayListPublication, NostrKeyPackagePublication,
    NostrKeyPackagePublisher, NostrRelayClient, NostrSdkRelayClient,
};
use transport_nostr_peeler::{NostrMlsPeeler, NostrTransportEvent};

mod agent_streams;
mod app_telemetry;
mod audit_log;
mod client;
mod config;
mod conversions;
mod directory;
mod error;
mod groups;
mod ids;
mod key_package_records;
mod media;
mod messages;
mod notifications;
mod projection;
mod relay_plane;
mod relay_telemetry_export;
mod runtime;
mod sqlcipher;

pub(crate) use groups::AppGroupImageInput;
pub(crate) use runtime::blocking_app_task;
pub use runtime::{
    AccountManager, AccountSetupRequest, AccountSetupResult, AgentStreamWatchOptions,
    AgentTextStreamCryptoContext, ChatListUpdateTrigger, GroupLeaveFailure, LocalCleanupReport,
    ManagedAccount, MarmotAppEvent, MarmotAppRuntime, RelayFailure, RuntimeAccountError,
    RuntimeAgentStreamMessage, RuntimeAgentStreamUpdate, RuntimeAgentStreamWatch,
    RuntimeChatListSubscription, RuntimeChatListUpdate, RuntimeChatsSubscription,
    RuntimeEventsSubscription, RuntimeGroupEvent, RuntimeGroupStateSubscription,
    RuntimeMessageReceived, RuntimeMessageUpdate, RuntimeMessagesSubscription,
    RuntimeNotificationsSubscription, RuntimeProjectionUpdate, RuntimeSharedServices,
    RuntimeTimelineMessageUpdate, RuntimeTimelineMessagesSubscription, StreamStartView,
    TimelineWindowHandle, WipeOutcome,
};
pub(crate) use sqlcipher::{SqlcipherDatabaseKind, remove_sqlite_file_set};
pub use storage_sqlite::{TimelineMessageChange, TimelineRemoveReason, TimelineUpdateTrigger};

pub use agent_streams::{
    AgentStreamDelta, AgentStreamUpdate, AgentStreamWatchCompletion, AgentStreamWatchManager,
    AgentStreamWatchReport, AgentStreamWatchStart,
};
pub use app_telemetry::{
    AppPerformanceOperationSnapshot, AppPerformanceSnapshot, AppPerformanceTelemetry,
};
pub use audit_log::{
    AuditLogDeleteOutcome, AuditLogFile, AuditLogSettings, AuditLogTrackerUpdateResult,
    AuditLogUploadResult,
};
pub use client::AppClient;
pub use config::{
    AuditLogTrackerConfig, AuditLogUploadSource, MarmotAppConfig, MarmotServiceEndpoints,
    RelayTelemetryExportConfig, RelayTelemetryResource, RelayTelemetryRuntimeConfig,
    RelayTelemetrySettings,
};
pub use directory::{
    DirectoryKeyPackage, UserDirectoryLocalAccount, UserDirectoryRecord, UserDirectoryRefresh,
    UserDirectorySearch, UserDirectorySearchResult, UserProfileMetadata,
};
pub use error::AppError;
pub use groups::{
    AppAgentTextStreamComponent, AppBlobEndpoint, AppGroupAdminPolicyComponent,
    AppGroupAvatarUrlComponent, AppGroupEncryptedMediaComponent, AppGroupHydrationQuarantineReason,
    AppGroupImageComponent, AppGroupMemberRecord, AppGroupMessageRetentionComponent,
    AppGroupMlsState, AppGroupNostrRoutingComponent, AppGroupProfileComponent, AppGroupRecord,
    AppGroupSystemEvent, AppQuarantinedGroup, group_system_event_from_message,
};
pub use ids::{
    account_id_hex_from_ref, nprofile_for_account_id, npub_for_account_id, validate_relay_urls,
};
pub use media::{
    DEFAULT_BLOSSOM_SERVER_URL, ENCRYPTED_MEDIA_VERSION, MediaAttachmentReference,
    MediaDownloadResult, MediaLocator, MediaUploadAttachmentRequest, MediaUploadAttachmentResult,
    MediaUploadRequest, MediaUploadResult,
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
    RelayTelemetryExportBatch, RelayTelemetryExporter, build_export_batch,
    build_export_batch_with_app_performance, metric_names,
};
pub use storage_sqlite::{
    ChatListAvatar, ChatListMessagePreview, ChatListQuery, ChatListRow, MAX_TIMELINE_LIMIT,
    TimelineMessageQuery, TimelineMessageRecord, TimelinePage, TimelinePagination,
    TimelineReactionSummary, TimelineReplyPreview, TimelineUserReaction,
};
pub use transport_nostr_adapter::{
    DurationHistogramSnapshot, HistogramBucket, NostrAdapterMetrics, RelayDeliverySpread,
    RelayDeliveryStats, RelayLabelResolution, RelayLatencyStats, RelaySyncSnapshot,
};

use conversions::{
    account_group_push_token_from_app, account_push_registration_from_app,
    account_state_from_stored, app_message_record_from_stored, group_push_token_from_account,
    normalize_relay_telemetry_settings, notification_settings_from_account,
    relay_telemetry_settings_from_storage, relay_telemetry_settings_to_storage,
    stored_app_event_from_message_record, stored_app_event_from_projection,
    stored_push_registration_from_account, stored_state_from_account_state,
};
use directory::{DirectoryCache, DirectorySyncHandle};
use ids::parse_account_id_hex;
use key_package_records::{
    account_key_package_record_from_fetched, fresh_or_cached_key_package,
    key_package_from_hex_with_optional_source, key_package_from_record,
    latest_fresh_key_package_from_records, merge_key_package_records,
    parse_key_package_event_id_hex, publish_endpoints_from_bootstrap, validated_cached_key_package,
};
use projection::LegacyAccountProjectionDb;
use relay_plane::DirectoryRelayEventRecord as RelayEventRecord;

const LEGACY_ACCOUNT_APP_DB_FILE: &str = "app.sqlite3";
const LEGACY_ACCOUNT_PROJECTION_IMPORT_MARKER: &str = "legacy-account-projection-v1";
const APP_CACHE_DB_FILE: &str = "app-cache.sqlite3";
const SHARED_DB_FILE: &str = "shared.sqlite3";
const SESSION_DB_FILE: &str = "session.sqlite";
const KEY_PACKAGE_DIR: &str = "key-packages";
const SDK_FIRST_SYNC_WAIT: Duration = Duration::from_millis(750);
const SDK_DRAIN_WAIT: Duration = Duration::from_millis(250);
const APP_RUNTIME_ACCOUNT_READY_WAIT: Duration = Duration::from_secs(45);
const APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT: Duration = Duration::from_secs(5);
const APP_RUNTIME_RELAY_REBUILD_LOOKBACK: Duration = Duration::from_secs(120);
/// Maximum amount the persisted transport cursor may run ahead of local
/// wall-clock. The cursor is advanced from the inbound message timestamp, which
/// is the sender-controlled Nostr `created_at` of the outer kind-445 event and
/// is never validated upstream. Clamping the advance to `now + skew` bounds how
/// far a malicious or buggy far-future `created_at` can move the subscription
/// `since` filter, preventing an account from silently halting message
/// reception (darkmatter#182). The margin tolerates benign sender clock skew.
const TRANSPORT_CURSOR_MAX_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);
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
    directory_caches: Arc<Mutex<HashMap<String, DirectoryCache>>>,
    legacy_directory_cache_checked: Arc<Mutex<bool>>,
    #[cfg(test)]
    directory_cache_open_count: Arc<std::sync::atomic::AtomicUsize>,
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

#[derive(Clone, Debug, PartialEq)]
pub struct AgentOperationEventRequest {
    pub event_type: String,
    pub status: String,
    pub operation_id: Option<String>,
    pub run_id: Option<String>,
    pub turn_id: Option<String>,
    pub name: Option<String>,
    pub text: String,
    pub preview: Option<String>,
    pub details: Option<serde_json::Value>,
    pub sequence: Option<u64>,
    pub ok: Option<bool>,
    pub duration_ms: Option<u64>,
    pub reply_to_message_id: Option<String>,
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

impl SyncSummary {
    /// Fold another summary's contents into this one. Used to combine the
    /// relay-delivery sync with the no-inbound engine-event drain so a single
    /// `sync()` returns all surfaced events together (darkmatter#426).
    pub fn merge(&mut self, other: SyncSummary) {
        self.joined_groups.extend(other.joined_groups);
        self.messages.extend(other.messages);
        self.events.extend(other.events);
        self.projection_updates.extend(other.projection_updates);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedMessage {
    pub message_id_hex: String,
    pub source_message_id_hex: String,
    pub sender: String,
    pub sender_display_name: Option<String>,
    pub group_id: GroupId,
    pub source_epoch: u64,
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
    #[serde(default)]
    pub source_epoch: Option<u64>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AccountState {
    pub(crate) label: String,
    #[serde(default)]
    pub(crate) seen_events: Vec<String>,
    #[serde(default)]
    pub(crate) last_transport_timestamp: Option<u64>,
    #[serde(default)]
    pub(crate) groups: Vec<AppGroupRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AppMessageProjection {
    pub(crate) message_id_hex: String,
    pub(crate) source_message_id_hex: Option<String>,
    pub(crate) direction: String,
    pub(crate) group_id_hex: String,
    pub(crate) sender: String,
    pub(crate) plaintext: String,
    pub(crate) kind: u64,
    pub(crate) tags: Vec<Vec<String>>,
    pub(crate) source_epoch: Option<u64>,
    pub(crate) recorded_at: Option<u64>,
    /// Transport id of the originating commit for a synthesized kind-1210 group
    /// system row, so the row can be invalidated by origin commit if that commit
    /// loses a fork. `None` for all other projections.
    pub(crate) origin_commit_id: Option<String>,
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

struct OpenAppAccount {
    runtime: AppRuntime,
    adapter: MarmotRelayPlaneAccountAdapter,
    routing: AppTransportRouting,
    state: AccountState,
    signing_keys: nostr::Keys,
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
        Ok(self
            .relay_telemetry_settings()?
            .export_config_with_runtime_and_endpoints(
                config::RelayTelemetryRuntimeConfig::default(),
                self.service_endpoints(),
            ))
    }

    pub(crate) fn service_endpoints(&self) -> &MarmotServiceEndpoints {
        &self.config.service_endpoints
    }

    /// Whether this build may act on loopback-HTTP blob endpoints (dev/test
    /// only). Production builds return `false` and skip such endpoints in the
    /// upload/download act paths.
    pub(crate) fn allow_loopback_blob_endpoints(&self) -> bool {
        self.config.allow_loopback_blob_endpoints
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
        mut config: MarmotAppConfig,
    ) -> Self {
        // These relay-only constructors are dev/test entry points (production
        // opens through `with_relays_and_account_home*`). Default them to instant
        // convergence settlement so multi-client tests are deterministic and do
        // not wait on the pinned 1000 ms quiescence window; a caller may still
        // set an explicit value.
        if config.dev_settlement_quiescence_ms.is_none() {
            config.dev_settlement_quiescence_ms = Some(0);
        }
        let root = root.as_ref().to_path_buf();
        Self {
            account_home: AccountHome::open(&root),
            root,
            relay_urls,
            relay_plane: MarmotRelayPlane::runtime_default(APP_RUNTIME_RELAY_REBUILD_LOOKBACK),
            config,
            directory_sync: Arc::new(RwLock::new(None)),
            account_storages: Arc::new(Mutex::new(HashMap::new())),
            directory_caches: Arc::new(Mutex::new(HashMap::new())),
            legacy_directory_cache_checked: Arc::new(Mutex::new(false)),
            #[cfg(test)]
            directory_cache_open_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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
            directory_caches: Arc::new(Mutex::new(HashMap::new())),
            legacy_directory_cache_checked: Arc::new(Mutex::new(false)),
            #[cfg(test)]
            directory_cache_open_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            shared_storage: Arc::new(Mutex::new(None)),
            account_state_ready: Arc::new(Mutex::new(HashSet::new())),
            chat_list_projection_warmed: Arc::new(Mutex::new(HashSet::new())),
            chat_list_projection_stale: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn runtime(&self) -> MarmotAppRuntime {
        MarmotAppRuntime::new(self.clone())
    }

    #[cfg(test)]
    fn account_storage_cached_for_test(&self, label: &str) -> bool {
        self.account_storages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(label)
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
        // Before any subscription goes out: auth-gated relays (NIP-42)
        // withhold gift-wrapped welcomes from unauthenticated subscribers,
        // and the catch-up REQ gets no error back — the events are simply
        // absent.
        relay_plane
            .set_transport_signer(open.signing_keys.clone())
            .await;
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
            pending_projection_updates: Vec::new(),
            pending_convergence_groups: std::collections::HashSet::new(),
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
        //
        // We then UNION in the caller's explicitly-requested publish endpoints.
        // Without this, a republish/set that *adds* a relay can never reach that
        // new relay: `outbox_endpoints` returns the existing (narrower) NIP-65
        // outbox and drops the requested set entirely, so the updated list only
        // ever lands on the relays you were already on. Unioning means an
        // explicit republish reaches both your old relays (so they update) and
        // the newly-declared ones (so they learn about you for the first time).
        let requested = publish_endpoints_from_bootstrap(&bootstrap);
        let mut endpoints = self.outbox_endpoints(&account_id_hex, requested.clone());
        for endpoint in requested {
            if !endpoints.iter().any(|existing| existing.0 == endpoint.0) {
                endpoints.push(endpoint);
            }
        }
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

    /// Resolve the reacted-to target for a reaction notification from the
    /// materialized timeline (the user-visible truth) rather than raw
    /// `app_events`. Filters by id directly, so the group's full history is not
    /// scanned. Returns the small [`storage_sqlite::TimelineMessageTarget`]
    /// view carrying sender + plaintext + kind + deleted/invalidated flags;
    /// `None` when the id is absent in that group (e.g. retention-pruned, so the
    /// reaction's author cannot be verified).
    pub fn reaction_target(
        &self,
        label: &str,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> Result<Option<storage_sqlite::TimelineMessageTarget>, AppError> {
        self.ensure_account_state(label)?;
        Ok(self
            .account_storage(label)?
            .timeline_message_target(group_id_hex, message_id_hex)?)
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
        .supported_app_components(self.supported_app_component_ids());
        // Production uses the protocol-pinned convergence policy (SessionConfig's
        // default). Only a dev/test override changes it — never shipped (see
        // spec/implementation-model.md, "Convergence Policy Overrides").
        if let Some(ms) = self.config.dev_settlement_quiescence_ms {
            session_config = session_config.convergence_policy(CanonicalizationPolicy {
                settlement_quiescence_ms: ms,
                ..CanonicalizationPolicy::default()
            });
        }
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
        if audit_log_enabled && let Some(recorder) = self.open_audit_recorder(label, &account_id) {
            session_config = session_config.recorder(recorder);
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
            signing_keys: keys,
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

    fn profiles_by_id(&self) -> Result<HashMap<String, String>, AppError> {
        Ok(self
            .profiles()?
            .into_iter()
            .map(|profile| (profile.account_id_hex, profile.label))
            .collect())
    }

    fn local_account_labels_by_id(&self) -> Result<HashMap<String, String>, AppError> {
        Ok(self
            .account_home()
            .accounts()?
            .into_iter()
            .map(|account| (account.account_id_hex, account.label))
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

    fn display_names_for_account_ids(
        &self,
        account_id_hexes: &[String],
    ) -> Result<HashMap<String, String>, AppError> {
        let mut account_ids = account_id_hexes
            .iter()
            .map(|account_id| parse_account_id_hex(account_id))
            .collect::<Result<Vec<_>, _>>()?;
        account_ids.sort();
        account_ids.dedup();
        if account_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let caches = self.directory_caches()?;
        let shared_storage = self.shared_storage()?;
        let local_names = self.local_account_labels_by_id()?;
        let mut names = HashMap::new();

        for account_id in account_ids {
            if let Some(entry) = self.directory_entry_for_account_id_with_handles(
                &account_id,
                &caches,
                &shared_storage,
            )? && let Some(name) = display_name_for_profile(entry.profile.as_ref())
            {
                names.insert(account_id, name);
                continue;
            }
            if let Some(name) = local_names.get(&account_id) {
                names.insert(account_id, name.clone());
            }
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
        let senders = rows
            .iter()
            .filter_map(|row| {
                row.last_message
                    .as_ref()
                    .map(|message| message.sender.clone())
            })
            .collect::<HashSet<_>>();
        let senders = senders.into_iter().collect::<Vec<_>>();
        let names = self.display_names_for_account_ids(&senders)?;
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
        group_id_hex: &str,
        message_id_hex: &str,
        reason: &str,
    ) -> Result<Option<AppProjectionUpdate>, AppError> {
        let update = self
            .account_storage(label)?
            .invalidate_app_event_by_message_id(group_id_hex, message_id_hex, reason)?;
        update
            .map(|update| self.app_projection_update(label, update))
            .transpose()
    }

    /// Invalidate every synthesized group system row produced by a commit that
    /// fork recovery rolled back. One commit can have synthesized several rows
    /// (1:N), so this is a multi-row invalidation keyed on `origin_commit_id`.
    pub(crate) fn invalidate_timeline_origin_commit(
        &self,
        label: &str,
        origin_commit_id_hex: &str,
        reason: &str,
    ) -> Result<Option<AppProjectionUpdate>, AppError> {
        let update = self
            .account_storage(label)?
            .invalidate_app_events_by_origin_commit(origin_commit_id_hex, reason)?;
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

    /// Evict every in-memory handle and warm flag bound to `label`.
    ///
    /// Must be called before the account directory is deleted on removal or
    /// setup-failure rollback. Without this, the cached `SqliteAccountStorage`
    /// connection in `account_storages` (and the `directory_caches` handle)
    /// keeps pointing at the now-unlinked inode: after the user re-imports the
    /// same account, the session DB is rebuilt fresh while projection paths
    /// keep writing through the stale handle, silently losing data. Clearing
    /// the warm/stale/ready flags forces the rebuilt account to re-warm its
    /// projections from the fresh database.
    fn drop_account_caches(&self, label: &str) {
        self.account_storages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(label);
        self.directory_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(label);
        self.account_state_ready
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(label);
        self.chat_list_projection_warmed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(label);
        self.chat_list_projection_stale
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(label);
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
        components.insert(GROUP_ENCRYPTED_MEDIA_COMPONENT_ID);
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
    // Each agent-text-stream-QUIC role maps to its own distinct backing
    // capability (a private-use MLS extension type), so a member advertises
    // `receive`/`send`/`fanout` independently and a group's
    // `required_member_roles` mask is enforceable per role (#177,
    // agent-text-stream-quic-v1.md). The capability/feature/bit mapping is the
    // shared `AGENT_TEXT_STREAM_QUIC_ROLES` table so the engine enforcement and
    // this registration cannot drift.
    for (feature, capability, description) in [
        (
            AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE.clone(),
            AGENT_TEXT_STREAM_QUIC_RECEIVE_CAPABILITY,
            "receive QUIC-backed agent text stream previews",
        ),
        (
            AGENT_TEXT_STREAM_QUIC_SEND_FEATURE.clone(),
            AGENT_TEXT_STREAM_QUIC_SEND_CAPABILITY,
            "send QUIC-backed agent text stream frames",
        ),
        (
            AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE.clone(),
            AGENT_TEXT_STREAM_QUIC_FANOUT_CAPABILITY,
            "fan out QUIC-backed agent text stream frames",
        ),
    ] {
        registry.register(
            feature,
            CapabilityRequirement {
                requires: capability,
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
            .map_err(|e| KeyPackagePublishError::unexposed(e.to_string()))?;
        let account_id_hex = hex::encode(publication.account_id.as_slice());
        if metadata.credential_identity_hex != account_id_hex {
            return Err(KeyPackagePublishError::unexposed(
                "KeyPackage credential identity does not match publication account",
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
        // Relay publish happens first. A failure here means no relay accepted
        // the event (`NostrKeyPackagePublisher` requires >=1 ack and returns
        // `Err` only when the accept count falls short), so the KeyPackage was
        // never externally exposed and the orphaned private bundle is safe to
        // prune (darkmatter#160).
        let outcome = NostrKeyPackagePublisher::new(relay_client)
            .publish_key_package(&nostr_publication)
            .await
            .map_err(|e| KeyPackagePublishError::unexposed(e.to_string()))?;
        let key_package_event_id = outcome
            .message_id
            .map(|message_id| hex::encode(message_id.as_slice()))
            .unwrap_or_default();

        // From here on the KeyPackage HAS been accepted by at least one relay,
        // so it is externally discoverable. Any subsequent failure must NOT
        // prune the private bundle, or an inviter could build a Welcome against
        // the published event that this account can never join. Mark these
        // errors `exposed` (darkmatter#160 adversarial review).
        let dir = self.app.key_package_cache_dir().join(KEY_PACKAGE_DIR);
        fs::create_dir_all(&dir).map_err(|e| KeyPackagePublishError::exposed(e.to_string()))?;
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
        .map_err(|e| KeyPackagePublishError::exposed(e.to_string()))
    }
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
pub(crate) struct DirectoryFreshness {
    max_created_at: u64,
}

impl DirectoryFreshness {
    fn from_now(max_future_skew: Duration) -> Self {
        Self {
            max_created_at: unix_now_seconds().saturating_add(max_future_skew.as_secs()),
        }
    }

    pub(crate) fn accepts(self, record: &RelayEventRecord) -> bool {
        record.event.created_at <= self.max_created_at
    }
}

#[derive(Debug)]
pub(crate) struct DirectorySelection<T> {
    pub(crate) value: T,
    pub(crate) rejected_future: bool,
}

fn sort_directory_records(records: &mut [RelayEventRecord]) {
    records.sort_by(|a, b| {
        a.event
            .created_at
            .cmp(&b.event.created_at)
            .then_with(|| a.event.id.cmp(&b.event.id))
    });
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
mod tests;
