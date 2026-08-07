//! First app runtime bridge for Marmot.
//!
//! This crate wires `AccountHome` into the concrete local runtime pieces needed by
//! early app surfaces: encrypted session storage, Nostr MLS peeling, Nostr
//! transport publishing, and relay-backed app projections.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cgka_engine::{
    FeatureRegistry, canonicalization::CanonicalizationPolicy, key_package::key_package_metadata,
};
use cgka_session::{AccountDeviceSession, SessionConfig};
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_QUIC_FANOUT_CAPABILITY, AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE,
    AGENT_TEXT_STREAM_QUIC_RECEIVE_CAPABILITY, AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE,
    AGENT_TEXT_STREAM_QUIC_SEND_CAPABILITY, AGENT_TEXT_STREAM_QUIC_SEND_FEATURE,
};
#[allow(deprecated)]
pub use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT as AGENT_TEXT_STREAM_COMPONENT,
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID as AGENT_TEXT_STREAM_COMPONENT_ID,
    GROUP_ADMIN_POLICY_COMPONENT, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT, GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_COMPONENT, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_V1_COMPONENT, GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_V2_COMPONENT, GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
    GROUP_MESSAGE_RETENTION_COMPONENT, GROUP_MESSAGE_RETENTION_COMPONENT_ID,
    GROUP_PROFILE_COMPONENT, GROUP_PROFILE_COMPONENT_ID, NOSTR_ROUTING_COMPONENT,
    NOSTR_ROUTING_COMPONENT_ID,
};
use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, NostrRoutingV1, default_group_components,
};
pub use cgka_traits::app_event::AppMessageRetentionDecision;
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{GroupEvent, KeyPackage};
use cgka_traits::storage::{DisbandTombstoneStorage, KeyPackageBundleStorage, MaintenanceStorage};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::{
    GroupId, MemberId, TransportEndpoint, TransportGroupSubscription, TransportPublishTarget,
};
use marmot_account::{
    AccountDeviceRuntime, AccountHome, AccountHomeError, AccountSummary, KeyPackagePublication,
    KeyPackagePublishError, KeyPackagePublishReceipt, KeyPackagePublisher, TransportRoutingError,
    TransportRoutingPolicy,
};
use nostr_sdk::prelude::{
    Client as NostrSdkClient, EventBuilder, Kind, PublicKey, Tag, Timestamp as NostrTimestamp,
};
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_sqlite::{
    SecurePruneAppEventsResult, SqliteAccountStorage, SqliteSharedStorage, StoredAppMessageQuery,
    TimelineProjectionUpdate,
};
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
    NostrAccountRelayListKind, NostrAccountRelayListPublication, NostrEventPublishRequest,
    NostrKeyPackagePublication, NostrKeyPackagePublisher, NostrNip65RelayListPublication,
    NostrNip65RelaySet, NostrRelayClient, NostrSdkRelayClient, parse_nip65_relay_set,
};
use transport_nostr_peeler::{NostrMlsPeeler, NostrTransportEvent};

mod agent_streams;
mod app_telemetry;
mod audit_log;
mod client;
mod config;
mod conversions;
mod directory;
mod drafts;
mod error;
mod external_signer;
mod groups;
mod ids;
mod key_package_records;
mod media;
mod messages;
mod nostr_secret;
mod notifications;
mod projection;
mod publisher_sequences;
mod relay_plane;
mod relay_telemetry_export;
mod root_runtime_lease;
mod runtime;
mod sqlcipher;

use external_signer::{AccountSigner, RegisteredExternalSigner};
pub use external_signer::{EXTERNAL_SIGNER_REJECTED, ExternalAccountSigner};
pub(crate) use groups::AppGroupImageInput;
pub use root_runtime_lease::{MARMOT_ROOT_RUNTIME_LOCK_FILE, MarmotRootRuntimeLease};
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
    RuntimeTimelineMessageUpdate, RuntimeTimelineMessagesSubscription, SignOutOptions,
    SignOutOutcome, StreamStartView, TimelineWindowHandle, WipeOutcome,
    default_directory_discovery_relays,
};
pub(crate) use sqlcipher::{SqlcipherDatabaseKind, remove_sqlite_file_set};
pub use storage_sqlite::{
    ChatPinState, TimelineMessageChange, TimelineRemoveReason, TimelineUpdateTrigger,
};

pub use agent_streams::{
    AgentStreamDelta, AgentStreamUpdate, AgentStreamWatchCompletion, AgentStreamWatchManager,
    AgentStreamWatchReport, AgentStreamWatchStart,
};
pub use app_telemetry::{
    AppPerformanceOperationSnapshot, AppPerformanceSnapshot, AppPerformanceTelemetry,
    HostPerformanceOperation, HostPerformanceOutcome,
};
pub use audit_log::{
    AuditLogDeleteOutcome, AuditLogFile, AuditLogSettings, AuditLogTrackerUpdateResult,
    AuditLogUploadResult,
};
pub use client::AppClient;
pub(crate) use client::ConvergenceScheduleState;
pub use config::{
    AuditLogTrackerConfig, AuditLogUploadSource, CursorPersistence, MarmotAppConfig,
    MarmotServiceEndpoints, RelayTelemetryExportConfig, RelayTelemetryResource,
    RelayTelemetryRuntimeConfig, RelayTelemetrySettings,
};
pub use directory::{
    DirectoryKeyPackage, MatchQuality, MatchedField, OFF_GRAPH_SEARCH_RADIUS, SearchUpdateTrigger,
    UserDirectoryLocalAccount, UserDirectoryRecord, UserDirectoryRefresh, UserDirectorySearch,
    UserDirectorySearchResult, UserProfileMetadata, UserSearchParams, UserSearchSubscription,
    UserSearchUpdate, sort_user_search_results,
};
pub use drafts::{
    MessageDraft, MessageDraftAttachment, MessageDraftAttachmentSummary, MessageDraftSummary,
};
pub use error::AppError;
pub use groups::{
    AppAgentTextStreamComponent, AppBlobEndpoint, AppDisbandFailureReason, AppDisbandRequest,
    AppGroupAdminPolicyComponent, AppGroupAvatarUrlComponent, AppGroupEncryptedMediaComponent,
    AppGroupHydrationQuarantineReason, AppGroupImageComponent, AppGroupLifecycleState,
    AppGroupMemberRecord, AppGroupMessageRetentionComponent, AppGroupMlsState,
    AppGroupNostrRoutingComponent, AppGroupOpaqueComponent, AppGroupProfileComponent,
    AppGroupRecord, AppGroupRoster, AppGroupRosterMember, AppGroupSystemEvent,
    AppInitialGroupImage, AppPriorNostrRoute, AppProtocolProfile, AppQuarantinedGroup,
    group_system_event_from_message,
};
pub use ids::{
    account_id_hex_from_ref, nprofile_for_account_id, npub_for_account_id, validate_relay_urls,
};
/// Re-exported so FFI/CLI consumers can name the audit data mode without
/// depending on `marmot-forensics` directly.
pub use marmot_forensics::AuditDataMode;
pub use media::{
    DEFAULT_BLOSSOM_SERVER_URL, DEFAULT_BLOSSOM_SERVER_URLS, ENCRYPTED_MEDIA_VERSION,
    EncryptedMediaVersion, MediaAttachmentReference, MediaDownloadResult, MediaLocator,
    MediaUploadAttachmentRequest, MediaUploadAttachmentResult, MediaUploadRequest,
    MediaUploadResult, download_profile_image, media_attachment_from_imeta_tag,
};
pub use messages::{is_stream_final_event, tag_value, tag_values};
pub use nostr_secret::is_nostr_secret;
pub use notifications::{
    BackgroundNotificationCollection, ChatNotificationSettings, GroupPushDebugInfo,
    GroupPushTokenDebugEntry, GroupPushTokenRecord, KIND_MARMOT_NOTIFICATION_RUMOR,
    KIND_MARMOT_NOTIFICATION_SERVER_RELAYS, LocalPushRegistrationDebug,
    MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST, MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
    MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE, NotificationCollectionStatus, NotificationSettings,
    NotificationTrafficClass, NotificationTrigger, NotificationUpdate, NotificationUser,
    NotificationWakeSource, PUSH_ENCRYPTED_TOKEN_LEN, PUSH_VERSION, PushPlatform, PushRegistration,
    PushRegistrationShareOutcome, PushRegistrationShareStatus, PushRegistrationSyncResult,
    build_notification_gift_wrap, build_notification_rumor_content, encrypted_push_token,
    parse_provider_token, push_token_fingerprint,
};
pub use relay_plane::{
    EngineReorgMetrics, MarmotRelayPlane, MarmotRelayPlaneAccountAdapter,
    RelayEndpointClassification, RelayEndpointPolicy, RelayPlaneHealth, RelayRollupEntry,
    RelayTelemetryRollup, RelayTelemetrySnapshot, retired_relay_hosts,
};
pub use relay_telemetry_export::{
    ExportHistogram, ExportMetricPoint, ExportMetricValue, RelayExportError,
    RelayTelemetryExportBatch, RelayTelemetryExporter, build_export_batch,
    build_export_batch_with_app_performance, metric_names,
};
pub use storage_sqlite::{
    ChatConversationKind, ChatListAttachmentKind, ChatListAvatar, ChatListMessageDeliveryState,
    ChatListMessagePreview, ChatListQuery, ChatListRow, MAX_TIMELINE_LIMIT, SelfMembership,
    TimelineMessageQuery, TimelineMessageRecord, TimelinePage, TimelinePagination,
    TimelineReactionSummary, TimelineReplyPreview, TimelineUserReaction,
};
pub use transport_nostr_adapter::{
    DurationHistogramSnapshot, HistogramBucket, NostrAdapterMetrics, RelayDeliverySpread,
    RelayDeliveryStats, RelayLabelResolution, RelayLatencyStats, RelaySyncSnapshot,
};

fn chat_pin_error_from_storage(error: storage_sqlite::ChatPinError) -> AppError {
    match error {
        storage_sqlite::ChatPinError::Storage(error) => AppError::Storage(error),
        storage_sqlite::ChatPinError::UnknownGroup(group_id_hex) => {
            AppError::UnknownGroup(group_id_hex)
        }
        storage_sqlite::ChatPinError::ArchivedChat => {
            AppError::InvalidChatPin("archived chats cannot be pinned".to_owned())
        }
        storage_sqlite::ChatPinError::InvalidOrder(details) => AppError::InvalidChatPin(details),
    }
}

use conversions::{
    account_group_push_token_from_app, account_push_registration_from_app,
    account_state_from_stored, app_message_record_from_stored,
    chat_notification_settings_from_account, group_push_token_from_account,
    normalize_relay_telemetry_settings, notification_settings_from_account,
    pending_push_registration_removal_from_account, relay_telemetry_settings_from_storage,
    relay_telemetry_settings_to_storage, stored_app_event_from_message_record,
    stored_app_event_from_projection, stored_push_registration_from_account,
    stored_state_from_account_state,
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
/// Once-only marker for the open/upgrade backfill that derives
/// `account_groups.self_membership` from current engine state for rows that
/// predate migration 0018 (where every row defaulted to `'member'`).
const SELF_MEMBERSHIP_BACKFILL_MARKER: &str = "self-membership-backfill-v1";
const APP_CACHE_DB_FILE: &str = "app-cache.sqlite3";
const SHARED_DB_FILE: &str = "shared.sqlite3";
const KEY_PACKAGE_CUTOVER_RELAY_SCAN_LIMIT: usize = 1_024;
const SESSION_DB_FILE: &str = "session.sqlite";
const KEY_PACKAGE_DIR: &str = "key-packages";
const SDK_FIRST_SYNC_WAIT: Duration = Duration::from_millis(750);
const SDK_DRAIN_WAIT: Duration = Duration::from_millis(250);
const APP_RUNTIME_ACCOUNT_READY_WAIT: Duration = Duration::from_secs(45);
/// Cap for advisory account-setup steps (directory discovery/refresh): their
/// results are best-effort, so a slow indexer must not stall login.
pub(crate) const ACCOUNT_SETUP_ADVISORY_WAIT: Duration = Duration::from_secs(10);
const APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT: Duration = Duration::from_secs(5);
const APP_RUNTIME_RELAY_REBUILD_LOOKBACK: Duration = Duration::from_secs(120);
/// Maximum amount the persisted transport cursor may run ahead of local
/// wall-clock. The cursor is advanced from the inbound message timestamp, which
/// is the sender-controlled Nostr `created_at` of the outer kind-445 event and
/// is never validated upstream. Clamping the advance to `now + skew` bounds how
/// far a malicious or buggy far-future `created_at` can move the subscription
/// `since` filter, preventing an account from silently halting message
/// reception (mdk#182). The margin tolerates benign sender clock skew.
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
    "Agile", "Amber", "Angry", "Balanced", "Bold", "Brave", "Breezy", "Bright", "Brisk", "Bubbly",
    "Calm", "Caring", "Cheerful", "Clear", "Clever", "Coral", "Cosmic", "Cozy", "Crimson", "Crisp",
    "Curious", "Daring", "Dawn", "Deep", "Diamond", "Dreamy", "Eager", "Earnest", "Easy",
    "Electric", "Emerald", "Festive", "Fiery", "Fleet", "Forest", "Fresh", "Frosty", "Gentle",
    "Glad", "Golden", "Graceful", "Grand", "Grateful", "Green", "Happy", "Hardy", "Hearty",
    "Hidden", "Honest", "Hopeful", "Humble", "Indigo", "Ivory", "Jade", "Jolly", "Kind", "Lively",
    "Loyal", "Lucky", "Majestic", "Maple", "Mellow", "Merry", "Mighty", "Mindful", "Misty",
    "Modest", "Mossy", "Neat", "Nifty", "Nimble", "Noble", "Olive", "Open", "Patient", "Peaceful",
    "Plum", "Polar", "Proud", "Quiet", "Radiant", "Rapid", "Ready", "Restful", "Rosy", "Ruby",
    "Rustic", "Sage", "Scarlet", "Serene", "Sharp", "Shiny", "Silver", "Sincere", "Sky", "Smooth",
    "Solar", "Solid", "Spirited", "Spry", "Steady", "Stellar", "Stormy", "Sturdy", "Sunlit",
    "Sunny", "Swift", "Tame", "Tangy", "Tender", "Tidy", "Topaz", "Tranquil", "Trusty", "Twilight",
    "Upbeat", "Valiant", "Verdant", "Vivid", "Warm", "Willing", "Winsome", "Wise", "Witty",
    "Wondrous", "Woodland", "Young", "Zesty",
];
const DEFAULT_PROFILE_NOUNS: &[&str] = &[
    "Albatross",
    "Alpaca",
    "Ant",
    "Antelope",
    "Armadillo",
    "Badger",
    "Bat",
    "Bear",
    "Beaver",
    "Bee",
    "Bison",
    "Bluebird",
    "Bobcat",
    "Bullfrog",
    "Bumblebee",
    "Butterfly",
    "Camel",
    "Caribou",
    "Cat",
    "Caterpillar",
    "Cheetah",
    "Chickadee",
    "Chinchilla",
    "Chipmunk",
    "Cobra",
    "Condor",
    "Cougar",
    "Crab",
    "Crane",
    "Cricket",
    "Crow",
    "Deer",
    "Dingo",
    "Dolphin",
    "Dove",
    "Dragonfly",
    "Duck",
    "Eagle",
    "Egret",
    "Elephant",
    "Elk",
    "Falcon",
    "Fawn",
    "Ferret",
    "Finch",
    "Firefly",
    "Flamingo",
    "Flounder",
    "Fox",
    "Gazelle",
    "Gecko",
    "Giraffe",
    "Goat",
    "Goose",
    "Gopher",
    "Grouse",
    "Hare",
    "Hawk",
    "Hedgehog",
    "Heron",
    "Hippo",
    "Hornet",
    "Horse",
    "Hummingbird",
    "Ibex",
    "Iguana",
    "Jackal",
    "Jaguar",
    "Jay",
    "Kestrel",
    "Kingfisher",
    "Kiwi",
    "Koala",
    "Ladybug",
    "Lark",
    "Leopard",
    "Lion",
    "Llama",
    "Lynx",
    "Macaw",
    "Magpie",
    "Mallard",
    "Manatee",
    "Marmot",
    "Meerkat",
    "Mink",
    "Mole",
    "Mongoose",
    "Monkey",
    "Moose",
    "Mouse",
    "Narwhal",
    "Newt",
    "Nightingale",
    "Octopus",
    "Opossum",
    "Orca",
    "Oriole",
    "Ostrich",
    "Otter",
    "Owl",
    "Panda",
    "Parrot",
    "Peacock",
    "Pelican",
    "Penguin",
    "Pheasant",
    "Pigeon",
    "Pony",
    "Porcupine",
    "Puffin",
    "Quail",
    "Rabbit",
    "Raccoon",
    "Ram",
    "Raven",
    "Reindeer",
    "Rhino",
    "Roadrunner",
    "Robin",
    "Salamander",
    "Salmon",
    "Seal",
    "Swan",
    "Tiger",
    "Turtle",
    "Wolf",
    "Yak",
];

type AppRuntime = AccountDeviceRuntime<
    MarmotRelayPlaneAccountAdapter,
    AppTransportRouting,
    AppKeyPackagePublisher,
>;

#[cfg(test)]
type LegacyProjectionOpenHook = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone)]
pub struct MarmotApp {
    root: PathBuf,
    /// Present for exclusive-root entry points. Every clone shares this cell,
    /// so the root remains exclusively owned until all database-capable app and
    /// runtime handles have been released — or until [`Self::close_storage`]
    /// takes the lease out, which is the only way to release it early. The
    /// lease is an advisory lock on a file *inside the Marmot root*, so on iOS
    /// it counts against the same App Group suspension rule as the databases
    /// (see [`Self::close_storage`]).
    root_runtime_lease: Arc<Mutex<Option<MarmotRootRuntimeLease>>>,
    /// Latched by [`Self::close_storage`]. Every database accessor checks it so
    /// a late call cannot silently reopen a database — and re-lock a container
    /// the host has just been told is lock-free.
    storage_closed: Arc<AtomicBool>,
    /// Admission control that makes the close *atomic* rather than merely
    /// latched: database opens hold the read side across create-and-publish,
    /// [`Self::close_storage`] holds the write side across its whole teardown.
    /// See [`Self::begin_storage_open`].
    storage_lifecycle: Arc<RwLock<()>>,
    relay_urls: Vec<String>,
    account_home: AccountHome,
    relay_plane: MarmotRelayPlane,
    config: MarmotAppConfig,
    directory_sync: Arc<RwLock<Option<DirectorySyncHandle>>>,
    account_storages: Arc<Mutex<HashMap<String, SqliteAccountStorage>>>,
    account_session_owners: Arc<Mutex<HashSet<String>>>,
    directory_caches: Arc<Mutex<HashMap<String, DirectoryCache>>>,
    legacy_directory_cache_checked: Arc<Mutex<bool>>,
    #[cfg(test)]
    directory_cache_open_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    legacy_projection_open_hook: Arc<Mutex<Option<LegacyProjectionOpenHook>>>,
    #[cfg(test)]
    test_relay_client: Option<Arc<dyn NostrRelayClient>>,
    shared_storage: Arc<Mutex<Option<SqliteSharedStorage>>>,
    account_state_ready: Arc<Mutex<HashSet<String>>>,
    chat_list_projection_warmed: Arc<Mutex<HashSet<String>>>,
    chat_list_projection_stale: Arc<Mutex<HashSet<String>>>,
    audit_log_tracker_config: Arc<Mutex<AuditLogTrackerConfig>>,
    external_signers: Arc<Mutex<HashMap<String, RegisteredExternalSigner>>>,
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
    pub missing: Vec<MissingRelayListKind>,
    pub default_relays: Vec<String>,
    pub bootstrap_relays: Vec<String>,
    pub nip65: AccountRelayListState,
    pub inbox: AccountRelayListState,
}

/// A relay list the account is missing. Typed so FFI clients can localize
/// each kind without parsing protocol-jargon strings (mdk#565).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MissingRelayListKind {
    /// NIP-65 relay list (kind 10002) — where this account publishes
    /// ("outbox"/write-side). Missing when the account has no NIP-65 relays.
    #[serde(rename = "nip65")]
    Nip65,
    /// Marmot inbox relay list (kind 10050) — where this account receives
    /// ("inbox"/read-side). Missing when the account has no inbox relays.
    #[serde(rename = "inbox")]
    Inbox,
}

impl MissingRelayListKind {
    /// Stable lowercase token, kept for the existing CLI `--json` / plain
    /// output contract (`"missing": ["nip65","inbox"]`). NOT a localization
    /// key — clients localize from the enum variant, not this string.
    pub fn token(self) -> &'static str {
        match self {
            Self::Nip65 => "nip65",
            Self::Inbox => "inbox",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRelayListState {
    pub kind: u64,
    /// Direction-appropriate relay targets for this list.
    ///
    /// For NIP-65 kind 10002 this is specifically the write-capable set:
    /// unmarked and `write` entries, excluding `read`-only entries. For the
    /// Marmot inbox list this is the declared inbox relay set.
    pub relays: Vec<String>,
    /// NIP-65 read-capable relays, including unmarked entries.
    ///
    /// Empty for non-NIP-65 lists and for cache records written before
    /// directional roles were persisted.
    #[serde(default)]
    pub read_relays: Vec<String>,
    /// NIP-65 write-capable relays, including unmarked entries.
    ///
    /// This is the explicit directional counterpart of the compatibility
    /// `relays` field. Empty for non-NIP-65 lists and for legacy cache records.
    #[serde(default)]
    pub write_relays: Vec<String>,
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
                read_relays: Vec::new(),
                write_relays: Vec::new(),
            },
            inbox: AccountRelayListState {
                kind: KIND_MARMOT_INBOX_RELAY_LIST,
                relays: Vec::new(),
                read_relays: Vec::new(),
                write_relays: Vec::new(),
            },
        };
        status.refresh();
        status
    }

    fn refresh(&mut self) {
        self.default_relays = self.nip65.relays.clone();
        self.missing = Vec::new();
        if self.nip65.relays.is_empty() {
            self.missing.push(MissingRelayListKind::Nip65);
        }
        if self.inbox.relays.is_empty() {
            self.missing.push(MissingRelayListKind::Inbox);
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
    /// Groups whose epoch-gap backfill has been armed repeatedly without the
    /// device catching up. Surfaced as [`MarmotAppEvent::EpochStallEscalated`].
    pub epoch_stall_escalations: Vec<EpochStallEscalation>,
}

impl SyncSummary {
    /// Fold another summary's contents into this one. Used to combine the
    /// relay-delivery sync with the no-inbound engine-event drain so a single
    /// `sync()` returns all surfaced events together (mdk#426).
    pub fn merge(&mut self, other: SyncSummary) {
        self.joined_groups.extend(other.joined_groups);
        self.messages.extend(other.messages);
        self.events.extend(other.events);
        self.projection_updates.extend(other.projection_updates);
        self.epoch_stall_escalations
            .extend(other.epoch_stall_escalations);
    }
}

/// A group that full-history replay is not repairing: it armed `arms` epoch-gap
/// backfills without once passing cleanly through an epoch, so it is still
/// stalled below the group's live epoch at `stalled_epoch`.
///
/// Reported once per unrecovered run so the application can say "this group
/// cannot catch up; re-syncing is recommended" and offer the stronger repair —
/// rotating this device's key package and re-activating transport over full
/// history. MDK deliberately does not rotate keys on its own: that publishes new
/// key material and is the app's decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochStallEscalation {
    pub group_id: GroupId,
    /// The device's group epoch when the escalating backfill was armed.
    pub stalled_epoch: u64,
    /// Backfills armed in this unrecovered run, including the escalating one.
    pub arms: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedMessage {
    pub message_id_hex: String,
    pub source_message_id_hex: String,
    pub sender: String,
    pub sender_display_name: Option<String>,
    pub group_id: GroupId,
    pub source_epoch: u64,
    /// Retention decision pinned from this message's authenticated MLS source
    /// epoch. `None` means the historical policy was not recoverable and is
    /// intentionally retained rather than evaluated against live group state.
    pub retention: Option<AppMessageRetentionDecision>,
    /// Displayed text for the inner app event (its `content`).
    pub plaintext: String,
    /// Nostr `kind` of the inner Marmot app event.
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    pub tags: Vec<Vec<String>>,
    /// Sender-authenticated inner app-event timestamp (seconds since epoch).
    /// Clients should sort the timeline by this value so chronology reflects
    /// send time, not delivery time. It is intentionally not clamped.
    pub recorded_at: u64,
    /// Local wall-clock time when this device observed the delivery.
    pub received_at: u64,
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

/// Records `event_id` as seen, using the caller-held `seen` set for O(1)
/// duplicate detection. The ordered `seen_events` Vec is kept only for pruning;
/// when pruning drops the oldest ids it removes them from `seen` incrementally
/// so the two stay in sync without rebuilding the set.
fn remember_seen_event(seen: &mut HashSet<String>, state: &mut AccountState, event_id: String) {
    if seen.insert(event_id.clone()) {
        state.seen_events.push(event_id);
        for pruned in prune_seen_events(&mut state.seen_events) {
            seen.remove(&pruned);
        }
    }
}

pub(crate) fn prune_seen_events(seen_events: &mut Vec<String>) -> std::vec::Drain<'_, String> {
    let overflow = seen_events.len().saturating_sub(MAX_SEEN_EVENT_IDS);
    seen_events.drain(0..overflow)
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
    /// Durable source-epoch retention decision. Legacy rows are `None` and are
    /// never destructively interpreted using the current group component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<AppMessageRetentionDecision>,
    /// Sender-authenticated inner app-event timestamp. Synthesized rows without
    /// an inner event use their local observation time.
    pub recorded_at: u64,
    /// Local wall-clock time when this device observed or created the row.
    pub received_at: u64,
    /// Local `app_events` insert order (rowid). The final LOCAL tiebreak of the
    /// raw-event replay cursor used by lag-recovery watermark/suppression (#630);
    /// not part of the cross-client display order. `#[serde(default)]` keeps
    /// older serialized records readable.
    #[serde(default)]
    pub insert_order: i64,
    /// True when convergence retained this raw row only as an invalidated
    /// losing-branch tombstone.
    #[serde(default)]
    pub invalidated: bool,
    /// Whether this delete carried an authenticated moderation grant when it
    /// was recorded. False for every non-delete event.
    #[serde(default)]
    pub moderation_grant: bool,
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
    pub maintenance_disposition: cgka_traits::SendMaintenanceDisposition,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MaintenanceRunSummary {
    pub published: u32,
    pub message_ids: Vec<String>,
    pub deferred: u32,
    pub ambiguous_exposure: u32,
    pub failures: u32,
}

/// A welcome that a confirmed group create/invite could not deliver to its
/// recipient (mdk#352). The commit is already durable, so the member is added
/// but unjoinable until the welcome reaches them. Persisted so the repair
/// handle survives the call return and a restart; re-deliver it with
/// [`AppClient::redeliver_welcome`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingWelcomeDelivery {
    pub group_id_hex: String,
    /// The stored welcome's MLS message id — the key for re-delivery.
    pub message_id_hex: String,
    pub recipient_hex: String,
    pub recorded_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecureDeleteExpiredResult {
    /// Number of expired raw app-event rows securely scrubbed and pruned.
    pub pruned_messages: u64,
    /// Number of encrypted-media epoch-secret rows securely scrubbed and
    /// deleted after their final retained source-message reference expired.
    pub secrets_deleted: u64,
    /// Ciphertext hashes for encrypted-media attachments referenced by the
    /// pruned rows. Host apps can use these opaque blob ids to purge their own
    /// decrypted-media disk caches alongside the engine plaintext wipe. The
    /// list is sorted for deterministic output, but callers should treat it as
    /// an unordered purge set.
    pub media_ciphertext_sha256: Vec<String>,
    /// True when logical deletion committed but secure WAL truncation remains
    /// pending. A later retention pass will retry it.
    pub erasure_pending: bool,
}

impl From<SecurePruneAppEventsResult> for SecureDeleteExpiredResult {
    fn from(value: SecurePruneAppEventsResult) -> Self {
        Self {
            pruned_messages: value.pruned_messages as u64,
            secrets_deleted: value.pruned_media_epoch_secrets as u64,
            media_ciphertext_sha256: value.media_ciphertext_sha256,
            erasure_pending: value.erasure_pending,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionSweepStatus {
    NoExpiredMessages,
    Pruned,
    DeferredClockSkew,
    DeferredUnread,
    DeferredScanExhausted,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionSweepGroupOutcome {
    pub group_id_hex: String,
    pub status: RetentionSweepStatus,
    pub pruned_messages: u64,
    pub secrets_deleted: u64,
    pub media_ciphertext_sha256: Vec<String>,
    /// Stable privacy-safe category such as `storage_busy`. Raw error text is
    /// intentionally never returned across the app boundary.
    pub failure_kind: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetentionSweepReport {
    pub groups: Vec<RetentionSweepGroupOutcome>,
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
    /// Relay `d` tag / durable lifecycle slot when known. For a local bundle
    /// with no lifecycle or legacy metadata, this falls back to the
    /// KeyPackageRef hex so it remains stable and non-secret.
    pub key_package_id: String,
    pub key_package_ref_hex: String,
    pub key_package_event_id: String,
    pub published_at: u64,
    pub key_package_bytes: usize,
    pub source_relays: Vec<String>,
    /// True only when the corresponding private OpenMLS bundle is durably
    /// stored and can be looked up for Welcome processing.
    pub local: bool,
    /// True when this exact event id was discovered from a relay.
    pub relay: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct KeyPackageDeletionTarget {
    pub event_id_hex: String,
    pub source_relays: Vec<TransportEndpoint>,
}

#[derive(Debug)]
pub(crate) struct KeyPackageDeletionResult {
    pub event_id_hex: String,
    pub result: Result<usize, AppError>,
}

/// Per-account unread aggregate, suitable for an account-switcher badge
/// (mdk#461). Computed from each account's materialized chat-list
/// projection without loading a full session/timeline, so it can be reported
/// for accounts that are not the active/running one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountUnread {
    pub account_id_hex: String,
    /// Total unread messages across all unarchived conversations.
    pub unread_count: u64,
    /// Number of unarchived conversations with at least one unread message.
    pub unread_conversations: u64,
    /// Whether the account has any unread message at all.
    pub has_unread: bool,
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
    pub(crate) retention: Option<AppMessageRetentionDecision>,
    pub(crate) recorded_at: Option<u64>,
    /// Transport id of the originating commit for a synthesized kind-1210 group
    /// system row, so the row can be invalidated by origin commit if that commit
    /// loses a fork. `None` for all other projections.
    pub(crate) origin_commit_id: Option<String>,
    /// True only for a delete whose authenticated sender may moderate other
    /// members' messages (group admin, non-direct group), evaluated against
    /// the signed MLS group state when the delete is recorded and persisted
    /// with the event. `false` for every other projection.
    pub(crate) moderation_grant: bool,
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
    session_guard: AppAccountSessionGuard,
    adapter: MarmotRelayPlaneAccountAdapter,
    routing: AppTransportRouting,
    state: AccountState,
    signer: Arc<dyn nostr::NostrSigner>,
}

struct AppAccountSessionGuard {
    label: String,
    owners: Arc<Mutex<HashSet<String>>>,
}

impl Drop for AppAccountSessionGuard {
    fn drop(&mut self) {
        self.owners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.label);
    }
}

impl MarmotApp {
    /// Dev/test convenience constructor — see [`MarmotApp::with_relays`]. Not a
    /// production entry point; hidden from the public API docs.
    #[doc(hidden)]
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
    /// Whether this runtime was explicitly configured to act on cleartext
    /// loopback blob endpoints for development or testing.
    ///
    /// Consumers that parse stored V1 media references outside the account
    /// worker must pass this same policy to the shared media parser so
    /// reference validation and the eventual fetch path cannot disagree.
    pub fn allow_loopback_blob_endpoints(&self) -> bool {
        self.config.allow_loopback_blob_endpoints
    }

    /// The construction-time durable transport-cursor policy every client
    /// opened from this app applies (see [`CursorPersistence`]).
    pub(crate) fn cursor_persistence(&self) -> CursorPersistence {
        self.config.cursor_persistence
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

    /// Dev/test-only convenience constructor. **Not a production entry point**
    /// and hidden from the public API docs: exclusive-root hosts open through
    /// [`MarmotApp::try_with_relays_and_account_home_and_config`], which owns
    /// the root exclusively and defaults the relay-safety gate to production
    /// posture (loopback rejected). This helper backs the crate's own tests,
    /// which drive in-process `MockRelay`s at loopback, so it opts the
    /// relay-safety gate into admitting loopback endpoints. It cannot be
    /// `#[cfg(test)]`-gated because the crate's integration tests
    /// (`crates/marmot-app/tests/*`) consume it through the public API. Callers
    /// that need an explicit posture pass a config through
    /// `with_relays_and_config`.
    #[doc(hidden)]
    pub fn with_relays(root: impl AsRef<Path>, relay_urls: Vec<String>) -> Self {
        Self::with_relays_and_config(
            root,
            relay_urls,
            MarmotAppConfig::default()
                .with_allow_loopback_relay_endpoints(true)
                .with_open_ranking_provider(None, Vec::new()),
        )
    }

    pub fn with_relays_and_config(
        root: impl AsRef<Path>,
        relay_urls: Vec<String>,
        mut config: MarmotAppConfig,
    ) -> Self {
        // These relay-only constructors are dev/test entry points (production
        // opens through `with_relays_and_account_home*`). Explicit test-policy
        // builds default them to instant settlement so multi-client tests are
        // deterministic. Normal debug and release builds keep the pinned window.
        if cfg!(feature = "test-policy-overrides") && config.dev_settlement_quiescence_ms.is_none()
        {
            config.dev_settlement_quiescence_ms = Some(0);
        }
        let root = root.as_ref().to_path_buf();
        let relay_plane = MarmotRelayPlane::runtime_default_with_loopback(
            APP_RUNTIME_RELAY_REBUILD_LOOKBACK,
            config.allow_loopback_relay_endpoints,
        );
        Self {
            account_home: AccountHome::open(&root),
            root,
            root_runtime_lease: Arc::new(Mutex::new(None)),
            storage_closed: Arc::new(AtomicBool::new(false)),
            storage_lifecycle: Arc::new(RwLock::new(())),
            relay_urls,
            relay_plane,
            config,
            directory_sync: Arc::new(RwLock::new(None)),
            account_storages: Arc::new(Mutex::new(HashMap::new())),
            account_session_owners: Arc::new(Mutex::new(HashSet::new())),
            directory_caches: Arc::new(Mutex::new(HashMap::new())),
            legacy_directory_cache_checked: Arc::new(Mutex::new(false)),
            #[cfg(test)]
            directory_cache_open_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            legacy_projection_open_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            test_relay_client: None,
            shared_storage: Arc::new(Mutex::new(None)),
            account_state_ready: Arc::new(Mutex::new(HashSet::new())),
            chat_list_projection_warmed: Arc::new(Mutex::new(HashSet::new())),
            chat_list_projection_stale: Arc::new(Mutex::new(HashSet::new())),
            audit_log_tracker_config: Arc::new(Mutex::new(AuditLogTrackerConfig::default())),
            external_signers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Constructor for tests and embeddings that coordinate root ownership
    /// externally.
    ///
    /// Independently scheduled processes must use
    /// [`Self::try_with_relays_and_account_home_and_config`].
    #[doc(hidden)]
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

    /// Constructor for tests and embeddings that coordinate ownership
    /// externally.
    ///
    /// Independently scheduled processes sharing a root must use
    /// [`Self::try_with_relays_and_account_home_and_config`] so independently
    /// hydrated runtimes cannot write the same root concurrently.
    #[doc(hidden)]
    pub fn with_relays_and_account_home_and_config(
        root: impl AsRef<Path>,
        relay_urls: Vec<String>,
        account_home: AccountHome,
        config: MarmotAppConfig,
    ) -> Self {
        let relay_plane = MarmotRelayPlane::runtime_default_with_loopback(
            APP_RUNTIME_RELAY_REBUILD_LOOKBACK,
            config.allow_loopback_relay_endpoints,
        );
        Self {
            root: root.as_ref().to_path_buf(),
            root_runtime_lease: Arc::new(Mutex::new(None)),
            storage_closed: Arc::new(AtomicBool::new(false)),
            storage_lifecycle: Arc::new(RwLock::new(())),
            relay_urls,
            account_home,
            relay_plane,
            config,
            directory_sync: Arc::new(RwLock::new(None)),
            account_storages: Arc::new(Mutex::new(HashMap::new())),
            account_session_owners: Arc::new(Mutex::new(HashSet::new())),
            directory_caches: Arc::new(Mutex::new(HashMap::new())),
            legacy_directory_cache_checked: Arc::new(Mutex::new(false)),
            #[cfg(test)]
            directory_cache_open_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            legacy_projection_open_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            test_relay_client: None,
            shared_storage: Arc::new(Mutex::new(None)),
            account_state_ready: Arc::new(Mutex::new(HashSet::new())),
            chat_list_projection_warmed: Arc::new(Mutex::new(HashSet::new())),
            chat_list_projection_stale: Arc::new(Mutex::new(HashSet::new())),
            audit_log_tracker_config: Arc::new(Mutex::new(AuditLogTrackerConfig::default())),
            external_signers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Constructor that exclusively owns the Marmot root across processes for
    /// the full lifetime of every resulting app/runtime clone.
    ///
    /// Acquisition is nonblocking. [`AppError::RuntimeBusy`] means a different
    /// process or independently constructed runtime currently owns the root.
    /// Hosts should retry later or take a bounded fallback path; they must not
    /// construct an unleased runtime against the same root.
    pub fn try_with_relays_and_account_home_and_config(
        root: impl AsRef<Path>,
        relay_urls: Vec<String>,
        account_home: AccountHome,
        config: MarmotAppConfig,
    ) -> Result<Self, AppError> {
        let root = root.as_ref().to_path_buf();
        let lease = MarmotRootRuntimeLease::try_acquire(&root)?;
        let app =
            Self::with_relays_and_account_home_and_config(&root, relay_urls, account_home, config);
        *app.root_runtime_lease
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(lease);
        Ok(app)
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

    /// Open the account's exclusive in-memory engine session.
    ///
    /// Only one [`AppClient`] for an account may exist within a [`MarmotApp`]
    /// (including its clones and managed runtime workers). A concurrent open
    /// returns [`AppError::AccountSessionBusy`]. Drop the owning client before
    /// retrying.
    pub async fn client(&self, label: &str) -> Result<AppClient, AppError> {
        #[cfg(test)]
        let relay_plane = self
            .test_relay_client
            .as_ref()
            .map(|client| MarmotRelayPlane::new(None, client.clone()))
            .unwrap_or_else(|| {
                MarmotRelayPlane::full_history_with_loopback(
                    self.config.allow_loopback_relay_endpoints,
                )
            });
        #[cfg(not(test))]
        let relay_plane = MarmotRelayPlane::full_history_with_loopback(
            self.config.allow_loopback_relay_endpoints,
        );
        self.client_with_relay_plane(label, &relay_plane, None)
            .await
    }

    async fn runtime_local_client(
        &self,
        label: &str,
        relay_plane: &MarmotRelayPlane,
        lifecycle: runtime::RuntimeLifecycle,
    ) -> Result<AppClient, AppError> {
        // Deferred hydration (mdk#1161): the account worker drives the
        // background per-group hydration pipeline after signalling local
        // readiness, so runtime opens stay flat in stored-group count.
        self.local_client_with_relay_plane_and_hydration(label, relay_plane, Some(lifecycle), true)
            .await
    }

    async fn client_with_relay_plane(
        &self,
        label: &str,
        relay_plane: &MarmotRelayPlane,
        lifecycle: Option<runtime::RuntimeLifecycle>,
    ) -> Result<AppClient, AppError> {
        let mut client = self
            .local_client_with_relay_plane(label, relay_plane, lifecycle.clone())
            .await?;
        client.prepare_transport().await?;
        if let Some(lifecycle) = &lifecycle {
            lifecycle.ensure_running()?;
        }
        self.finish_client_open_network_maintenance(&mut client)
            .await;
        Ok(client)
    }

    async fn local_client_with_relay_plane(
        &self,
        label: &str,
        relay_plane: &MarmotRelayPlane,
        lifecycle: Option<runtime::RuntimeLifecycle>,
    ) -> Result<AppClient, AppError> {
        self.local_client_with_relay_plane_and_hydration(label, relay_plane, lifecycle, false)
            .await
    }

    async fn local_client_with_relay_plane_and_hydration(
        &self,
        label: &str,
        relay_plane: &MarmotRelayPlane,
        lifecycle: Option<runtime::RuntimeLifecycle>,
        defer_group_hydration: bool,
    ) -> Result<AppClient, AppError> {
        let app = self.clone();
        // Resolve every supported account ref before touching label-keyed
        // caches or the session-owner registry.
        let label = self.account_home().account(label)?.label;
        let relay_plane_for_open = relay_plane.clone();
        let permit = lifecycle
            .as_ref()
            .map(runtime::RuntimeLifecycle::begin_account_open)
            .transpose()?;
        let open = blocking_app_task(move || {
            let _permit = permit;
            app.ensure_account_state(&label)?;
            app.open_account(&label, &relay_plane_for_open, defer_group_hydration)
        })
        .await?;
        if let Some(lifecycle) = &lifecycle {
            lifecycle.ensure_running()?;
        }
        let mut client = AppClient {
            app: self.clone(),
            runtime: open.runtime,
            _session_guard: open.session_guard,
            adapter: open.adapter,
            routing: open.routing,
            relay_plane: relay_plane.clone(),
            transport_signer: open.signer,
            state: open.state,
            pending_projection_updates: Vec::new(),
            pending_applied_sync_summary: SyncSummary::default(),
            pending_epoch_stall_escalations: Vec::new(),
            pending_convergence_groups: std::collections::HashSet::new(),
            pending_welcome_delivery_events: Vec::new(),
            epoch_stall: Default::default(),
            epoch_backfill_pending: false,
            post_join_maintenance_subscriptions: HashMap::new(),
        };
        if !defer_group_hydration {
            // These repairs read live group state. Deferred runtime opens run
            // them after the account worker's hydration pipeline instead.
            client.reconcile_hydrated_account_state()?;
        }
        Ok(client)
    }

    async fn finish_client_open_network_maintenance(&self, client: &mut AppClient) {
        client
            .app
            .retire_cached_non_current_key_package(&client.state.label)
            .await;
        client
            .app
            .retire_relay_non_current_key_packages(&client.state.label)
            .await;
        if client
            .app
            .key_package_cutover_replacement_pending(&client.state.label)
        {
            let lifecycle_current = client
                .runtime
                .key_package_maintenance_status()
                .ok()
                .flatten()
                .and_then(|lifecycle| lifecycle.current_key_package)
                .and_then(|key_package| key_package_metadata(&key_package).ok())
                .is_some_and(|metadata| {
                    client
                        .app
                        .key_package_metadata_matches_current_support(&metadata)
                });
            if lifecycle_current {
                client
                    .app
                    .clear_key_package_cutover_replacement_pending(&client.state.label);
            } else {
                match client.runtime.publish_fresh_key_package().await {
                    Ok(_) => tracing::info!(
                        target: "marmot_app::key_packages",
                        method = "finish_client_open_network_maintenance",
                        "published current key package replacement after strict cutover"
                    ),
                    Err(error) => tracing::warn!(
                        target: "marmot_app::key_packages",
                        method = "finish_client_open_network_maintenance",
                        error_kind = AppError::from(error).privacy_safe_kind(),
                        "deferred current key package replacement after strict cutover"
                    ),
                }
                if client
                    .runtime
                    .key_package_maintenance_status()
                    .ok()
                    .flatten()
                    .and_then(|lifecycle| lifecycle.current_key_package)
                    .and_then(|key_package| key_package_metadata(&key_package).ok())
                    .is_some_and(|metadata| {
                        client
                            .app
                            .key_package_metadata_matches_current_support(&metadata)
                    })
                {
                    client
                        .app
                        .clear_key_package_cutover_replacement_pending(&client.state.label);
                }
            }
        }
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
            projections: self.projection_status(label)?,
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
            .map(|kind| match kind {
                MissingRelayListKind::Nip65 => NostrAccountRelayListKind::Nip65,
                MissingRelayListKind::Inbox => NostrAccountRelayListKind::Inbox,
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

    /// Return every declared NIP-65 relay for backward-compatible list editing.
    ///
    /// Routing code must use `AccountRelayListStatus::nip65.relays`, which is
    /// the write-capable subset. Returning the union here keeps the established
    /// getter -> edit -> setter flow from deleting read-only entries. Because
    /// this faithfully returns published data, it can include retired or unsafe
    /// endpoints; clients must classify the result and remove every non-allowed
    /// entry before passing an edited list to a setter.
    pub fn account_nip65_relays(&self, label: &str) -> Result<Vec<String>, AppError> {
        let state = self.account_relay_list_status(label)?.nip65;
        let relay_set = nip65_relay_set_from_state(&state);
        let mut relays = relay_set
            .read_relays
            .into_iter()
            .map(|endpoint| endpoint.0)
            .collect::<Vec<_>>();
        push_unique_strings(
            &mut relays,
            relay_set
                .write_relays
                .into_iter()
                .map(|endpoint| endpoint.0),
        );
        Ok(relays)
    }

    /// Return the published inbox list without hiding retired entries.
    ///
    /// Clients must classify the result and remove every non-allowed entry
    /// before passing an edited list to [`Self::set_account_inbox_relays`].
    pub fn account_inbox_relays(&self, label: &str) -> Result<Vec<String>, AppError> {
        Ok(self.account_relay_list_status(label)?.inbox.relays)
    }

    pub async fn set_account_nip65_relays(
        &self,
        label: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let current = self.account_relay_list_status(label)?.nip65;
        let relay_set = nip65_relay_set_preserving_roles(&current, relays);
        self.publish_account_nip65_relay_set(
            label,
            relay_set.read_relays,
            relay_set.write_relays,
            bootstrap_relays,
        )
        .await
    }

    /// Replace the account's NIP-65 list while preserving explicit relay
    /// directions in the published kind-10002 event.
    pub async fn publish_account_nip65_relay_set(
        &self,
        label: &str,
        read_relays: Vec<TransportEndpoint>,
        write_relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let relay_set = NostrNip65RelaySet {
            read_relays: unique_transport_endpoints(read_relays),
            write_relays: unique_transport_endpoints(write_relays),
        };
        self.publish_selected_account_relay_lists_with_nip65(
            label,
            AccountRelayListBootstrap::new(relay_set.write_relays.clone(), bootstrap_relays),
            &[NostrAccountRelayListKind::Nip65],
            Some(&relay_set),
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
        self.publish_selected_account_relay_lists_with_nip65(label, bootstrap, list_kinds, None)
            .await
    }

    async fn publish_selected_account_relay_lists_with_nip65(
        &self,
        label: &str,
        bootstrap: AccountRelayListBootstrap,
        list_kinds: &[NostrAccountRelayListKind],
        nip65_relay_set: Option<&NostrNip65RelaySet>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let has_directional_nip65_relays = nip65_relay_set.is_some_and(|relays| {
            !relays.read_relays.is_empty() || !relays.write_relays.is_empty()
        });
        if bootstrap.default_relays.is_empty() && !has_directional_nip65_relays {
            return Err(AppError::MissingDefaultRelays);
        }
        self.validate_account_relay_list_declarations(&bootstrap, nip65_relay_set)?;
        let account = self.account_home().account(label)?;
        let signer = self.account_signer_for_summary(&account)?;
        let account_id = MemberId::new(hex::decode(&account.account_id_hex)?);
        let account_id_hex = account.account_id_hex;
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
        let relay_client = self.relay_client_for_endpoints(signer.as_nostr_signer(), &endpoints);
        for list_kind in list_kinds {
            let event = if *list_kind == NostrAccountRelayListKind::Nip65
                && let Some(relays) = nip65_relay_set
            {
                NostrNip65RelayListPublication {
                    account_id: account_id.clone(),
                    relays: relays.clone(),
                    publish_endpoints: endpoints.clone(),
                }
                .to_event()?
            } else {
                NostrAccountRelayListPublication {
                    account_id: account_id.clone(),
                    list_kind: *list_kind,
                    relays: bootstrap.default_relays.clone(),
                    publish_endpoints: endpoints.clone(),
                }
                .to_event()?
            };
            relay_client.publish_event(&endpoints, &event, 1).await?;
        }
        self.fetch_account_relay_list_status_for_account_id(&account_id_hex, endpoints)
            .await
    }

    /// Validate caller-owned relay-list declarations without applying the dial
    /// route's aggregate endpoint cap to the published list itself. Validating
    /// one entry at a time retains the exact retired/invalid/unsafe policy while
    /// the separately constructed publication route remains capped normally.
    fn validate_account_relay_list_declarations(
        &self,
        bootstrap: &AccountRelayListBootstrap,
        nip65_relay_set: Option<&NostrNip65RelaySet>,
    ) -> Result<(), AppError> {
        let mut declarations: Vec<(&[TransportEndpoint], &str)> = Vec::new();
        if let Some(relays) = nip65_relay_set {
            declarations.extend([
                (
                    relays.read_relays.as_slice(),
                    "account NIP-65 read-relay declaration",
                ),
                (
                    relays.write_relays.as_slice(),
                    "account NIP-65 write-relay declaration",
                ),
            ]);
        }
        declarations.extend([
            (
                bootstrap.default_relays.as_slice(),
                "account relay-list declaration",
            ),
            (
                bootstrap.bootstrap_relays.as_slice(),
                "account relay-list publication",
            ),
        ]);
        for (endpoints, context) in declarations {
            for endpoint in endpoints {
                self.relay_plane
                    .sanitize_relay_endpoints(vec![endpoint.clone()], context)
                    .map_err(AppError::RelayDirectory)?;
            }
        }
        Ok(())
    }

    /// Outbox routing for account-scoped events. Prefers the safe subset of the
    /// account's declared NIP-65 write relays (read from the local relay-list
    /// cache, no network), so e.g. republishing your relay lists / profile goes
    /// to *your* relays rather than whatever defaults the caller passed. Falls
    /// back to `fallback` when the account has no usable NIP-65 relay. Filtering
    /// here affects only the operation's route; it does not rewrite the cached
    /// or published relay list.
    fn outbox_endpoints(
        &self,
        account_id_hex: &str,
        fallback: Vec<TransportEndpoint>,
    ) -> Vec<TransportEndpoint> {
        let nip65 = self
            .account_relay_list_status_for_account_id(account_id_hex)
            .map(|status| status.nip65.relays)
            .unwrap_or_default();
        let safe = self.retain_safe_discovered_endpoints(
            nip65.into_iter().map(TransportEndpoint).collect(),
            "local account outbox routing",
        );
        if safe.is_empty() { fallback } else { safe }
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

    /// Resolve one durable raw app event by group/message id.
    pub fn message_by_id(
        &self,
        label: &str,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> Result<Option<AppMessageRecord>, AppError> {
        self.ensure_account_state(label)?;
        Ok(self
            .account_storage(label)?
            .app_message(group_id_hex, message_id_hex)?
            .map(app_message_record_from_stored))
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

    pub fn timeline_message(
        &self,
        label: &str,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> Result<Option<TimelineMessageRecord>, AppError> {
        self.ensure_account_state(label)?;
        Ok(self
            .account_storage(label)?
            .timeline_message(group_id_hex, message_id_hex)?)
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

    /// Pin or unpin one unarchived local chat and return the complete
    /// authoritative pin order after the transaction.
    pub fn set_chat_pinned(
        &self,
        label: &str,
        group_id_hex: &str,
        pinned: bool,
    ) -> Result<ChatPinState, AppError> {
        self.ensure_account_state(label)?;
        self.account_storage(label)?
            .set_chat_pinned(group_id_hex, pinned)
            .map_err(chat_pin_error_from_storage)
    }

    /// Atomically replace the order of the current pinned set.
    ///
    /// The input must contain every currently pinned group exactly once.
    pub fn set_pinned_chat_order(
        &self,
        label: &str,
        ordered_group_ids: &[String],
    ) -> Result<ChatPinState, AppError> {
        self.ensure_account_state(label)?;
        self.account_storage(label)?
            .set_pinned_chat_order(ordered_group_ids)
            .map_err(chat_pin_error_from_storage)
    }

    /// Per-account unread aggregate for the account-switcher badge
    /// (mdk#461). Each account's count is read from its materialized
    /// `chat_list_rows` projection (a single grouped `COUNT`/`SUM`), so this
    /// does not require switching into, or loading a full session/timeline for,
    /// any account — non-active accounts are reported too.
    ///
    /// Only local-signing accounts are reported (matching `managed_accounts`).
    /// The chat-list projection is built from the on-disk store if missing;
    /// this is a local operation and never touches the network. Intended for
    /// account-switcher scale, this does one encrypted database open per local
    /// signing account. A single account that fails to open or project is
    /// skipped with a privacy-safe warning rather than failing the whole query.
    pub fn account_unread_summary(&self) -> Result<Vec<AccountUnread>, AppError> {
        let accounts = self
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.local_signing)
            .collect::<Vec<_>>();
        let mut summaries = Vec::with_capacity(accounts.len());
        for account in accounts {
            match self.account_unread_for(&account) {
                Ok(summary) => summaries.push(summary),
                Err(error) => {
                    tracing::warn!(
                        target: "marmot_app::storage",
                        method = "account_unread_summary",
                        error_kind = error.privacy_safe_kind(),
                        "skipped an account whose unread aggregate could not be computed"
                    );
                }
            }
        }
        Ok(summaries)
    }

    fn account_unread_for(&self, account: &AccountSummary) -> Result<AccountUnread, AppError> {
        self.ensure_account_state(&account.label)?;
        self.ensure_chat_list_projection(account)?;
        let total = self
            .account_storage(&account.label)?
            .account_unread_total()?;
        Ok(AccountUnread {
            account_id_hex: account.account_id_hex.clone(),
            unread_count: total.unread_count,
            unread_conversations: total.unread_conversations,
            has_unread: total.has_unread(),
        })
    }

    fn refresh_chat_list_row(
        &self,
        label: &str,
        group_id_hex: &str,
    ) -> Result<Option<ChatListRow>, AppError> {
        let account = self.account_home().account(label)?;
        let classifier = Self::chat_list_mention_classifier(&account.account_id_hex);
        let mut row = self
            .account_storage(&account.label)?
            .refresh_chat_list_row(&account.account_id_hex, group_id_hex, &classifier)?;
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
        let classifier = Self::chat_list_mention_classifier(&account.account_id_hex);
        let mut row = self
            .account_storage(&account.label)?
            .initialize_chat_read_state(&account.account_id_hex, group_id_hex, &classifier)?;
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
        let classifier = Self::chat_list_mention_classifier(&account.account_id_hex);
        let mut row = self
            .account_storage(&account.label)?
            .mark_timeline_message_read(
                &account.account_id_hex,
                group_id_hex,
                message_id_hex,
                &classifier,
            )?;
        self.hydrate_chat_list_row(row.as_mut())?;
        Ok(row)
    }

    /// Set or clear a manual-unread reminder without rewinding the cumulative
    /// timeline read marker.
    pub fn set_chat_manually_unread(
        &self,
        label: &str,
        group_id_hex: &str,
        manually_unread: bool,
    ) -> Result<Option<ChatListRow>, AppError> {
        let account = self.account_home().account(label)?;
        self.ensure_account_state(&account.label)?;
        let classifier = Self::chat_list_mention_classifier(&account.account_id_hex);
        let mut row = self
            .account_storage(&account.label)?
            .set_chat_manually_unread(
                &account.account_id_hex,
                group_id_hex,
                manually_unread,
                &classifier,
            )?;
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

    pub fn chat_notification_settings(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<ChatNotificationSettings, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.group(&account.label, group_id_hex)?
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.to_owned()))?;
        let settings = self
            .account_storage(&account.label)?
            .chat_notification_settings(group_id_hex)?;
        Ok(chat_notification_settings_from_account(
            account.label,
            account.account_id_hex,
            settings,
        ))
    }

    pub fn set_chat_muted(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        muted_until_ms: Option<i64>,
    ) -> Result<ChatNotificationSettings, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.group(&account.label, group_id_hex)?
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.to_owned()))?;
        let settings = self
            .account_storage(&account.label)?
            .set_chat_muted(group_id_hex, muted_until_ms)?;
        Ok(chat_notification_settings_from_account(
            account.label,
            account.account_id_hex,
            settings,
        ))
    }

    pub fn clear_chat_muted(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<ChatNotificationSettings, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.group(&account.label, group_id_hex)?
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.to_owned()))?;
        let settings = self
            .account_storage(&account.label)?
            .clear_chat_muted(group_id_hex)?;
        Ok(chat_notification_settings_from_account(
            account.label,
            account.account_id_hex,
            settings,
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
        Ok(notification_settings_from_account(
            self.account_storage(&account.label)?
                .set_native_push_enabled(&account.label, &account.account_id_hex, enabled)?,
        ))
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
        token_fingerprint: &str,
        registration_updated_at_ms: i64,
        shared_at_ms: i64,
    ) -> Result<bool, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .mark_push_registration_shared(
                &account.label,
                token_fingerprint,
                registration_updated_at_ms,
                shared_at_ms,
            )?)
    }

    pub(crate) fn pending_push_registration_shares(
        &self,
        account_ref: &str,
        token_fingerprint: &str,
        registration_updated_at_ms: i64,
    ) -> Result<Vec<String>, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .pending_push_registration_shares(token_fingerprint, registration_updated_at_ms)?)
    }

    pub(crate) fn mark_push_registration_share_attempted(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        token_fingerprint: &str,
        registration_updated_at_ms: i64,
        attempted_at_ms: i64,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .mark_push_registration_share_attempted(
                group_id_hex,
                token_fingerprint,
                registration_updated_at_ms,
                attempted_at_ms,
            )?;
        Ok(())
    }

    pub(crate) fn complete_push_registration_share(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        token_fingerprint: &str,
        registration_updated_at_ms: i64,
    ) -> Result<bool, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .complete_push_registration_share(
                group_id_hex,
                token_fingerprint,
                registration_updated_at_ms,
            )?)
    }

    pub(crate) fn queue_push_registration_removals(
        &self,
        account_ref: &str,
        registration: PushRegistration,
    ) -> Result<usize, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .queue_push_registration_removals(
                &account_push_registration_from_app(registration),
                notifications::unix_now_ms(),
            )?)
    }

    pub(crate) fn queue_push_registration_removal_for_group(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        registration: &PushRegistration,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .queue_push_registration_removal_for_group(
                group_id_hex,
                &account_push_registration_from_app(registration.clone()),
                notifications::unix_now_ms(),
            )?;
        Ok(())
    }

    pub(crate) fn queue_push_registration_share_for_group(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        registration: &PushRegistration,
    ) -> Result<bool, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .queue_push_registration_share_for_group(
                group_id_hex,
                &registration.token_fingerprint,
                registration.updated_at_ms,
                notifications::unix_now_ms(),
            )?)
    }

    pub(crate) fn has_pending_push_registration_work(
        &self,
        account_ref: &str,
    ) -> Result<bool, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .has_pending_push_registration_work()?)
    }

    pub(crate) fn pending_push_registration_removals(
        &self,
        account_ref: &str,
    ) -> Result<Vec<(String, PushRegistration)>, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .pending_push_registration_removals()?
            .into_iter()
            .map(pending_push_registration_removal_from_account)
            .collect()
    }

    pub(crate) fn mark_push_registration_removal_attempted(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        registration: &PushRegistration,
        attempted_at_ms: i64,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        let pending = storage_sqlite::AccountPendingPushRegistrationRemoval {
            group_id_hex: group_id_hex.to_owned(),
            registration: account_push_registration_from_app(registration.clone()),
            last_attempted_at_ms: None,
        };
        self.account_storage(&account.label)?
            .mark_push_registration_removal_attempted(&pending, attempted_at_ms)?;
        Ok(())
    }

    pub(crate) fn complete_push_registration_removal(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        registration: &PushRegistration,
    ) -> Result<bool, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        let pending = storage_sqlite::AccountPendingPushRegistrationRemoval {
            group_id_hex: group_id_hex.to_owned(),
            registration: account_push_registration_from_app(registration.clone()),
            last_attempted_at_ms: None,
        };
        Ok(self
            .account_storage(&account.label)?
            .complete_push_registration_removal(&pending)?)
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

    /// Ingest inbound push-token gossip (kinds 447/448/449) into
    /// `group_push_tokens`. `active_member_ids` is the carrying group's current
    /// MLS member set; entries are owner-authenticated and bound to it by
    /// [`notifications::verify_push_gossip_for_profile`] before the spec's
    /// `(owner_ts, record_digest)` ordering primitive and tombstones (enforced by
    /// the storage `apply_*` calls) decide what mutates state. Because authority
    /// comes from each record's `owner_sig`, a kind 448 may carry — and apply —
    /// records owned by members other than `message.sender`.
    pub(crate) fn ingest_push_gossip_message(
        &self,
        account_ref: &str,
        message: &ReceivedMessage,
        active_member_ids: &[String],
        profile: cgka_traits::group::ProtocolProfile,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        let group_id_hex = hex::encode(message.group_id.as_slice());
        let storage = self.account_storage(&account.label)?;
        let action =
            notifications::parse_push_gossip(message.kind, &group_id_hex, &message.plaintext)?;
        let action = notifications::verify_push_gossip_for_profile(
            action,
            &group_id_hex,
            active_member_ids,
            profile,
        );
        match action {
            notifications::PushGossipAction::Upsert(records) => {
                for record in records {
                    storage.apply_group_push_token(&account_group_push_token_from_app(&record))?;
                }
            }
            notifications::PushGossipAction::Remove(removals) => {
                for removal in removals {
                    let digest = removal.record_digest(&group_id_hex)?;
                    storage.apply_group_push_token_tombstone(
                        &group_id_hex,
                        &removal.member_id_hex,
                        removal.leaf_index,
                        removal.platform.platform_byte(),
                        &removal.server_pubkey_hex,
                        removal.owner_ts,
                        &digest,
                        notifications::unix_now_ms(),
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

    /// Apply our own owner-signed removal locally: tombstone the record key with
    /// the removal's `(owner_ts, record_digest)` stamp so a later stale kind 448
    /// relaying our pre-removal record cannot resurrect it.
    pub(crate) fn apply_local_push_removal(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        removal: &notifications::PushTokenRemovalRecord,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        let digest = removal.record_digest(group_id_hex)?;
        self.account_storage(&account.label)?
            .apply_group_push_token_tombstone(
                group_id_hex,
                &removal.member_id_hex,
                removal.leaf_index,
                removal.platform.platform_byte(),
                &removal.server_pubkey_hex,
                removal.owner_ts,
                &digest,
                notifications::unix_now_ms(),
            )?;
        Ok(())
    }

    pub(crate) fn set_group_self_membership(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        membership: SelfMembership,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .set_group_self_membership(group_id_hex, membership)?;
        Ok(())
    }

    /// `group_id_hex` of every `account_groups` row still carrying the migration
    /// default `self_membership = 'member'`. The one-time open/upgrade backfill
    /// uses this to derive membership for legacy rows from current engine state.
    pub(crate) fn account_group_ids_defaulting_to_member(
        &self,
        account_ref: &str,
    ) -> Result<Vec<String>, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .account_group_ids_defaulting_to_member()?)
    }

    /// Whether the named once-only account-import marker has been recorded.
    pub(crate) fn account_import_marker(
        &self,
        account_ref: &str,
        name: &str,
    ) -> Result<bool, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .account_import_marker(name)?)
    }

    /// Record the named once-only account-import marker as complete.
    pub(crate) fn mark_account_import_complete(
        &self,
        account_ref: &str,
        name: &str,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .mark_account_import_complete(name)?;
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
        let mut groups = self.load_state(label)?.groups;
        // `leave_requested_at_ms` is not part of the stored projection, so stamp
        // it from the engine-owned leave-request table here. This is the single
        // population point for the group record: `visible_groups`, `group`, and
        // `subscribe_chats` all read through this method.
        let pending = self.pending_leave_requests(label)?;
        if !pending.is_empty() {
            for group in &mut groups {
                group.leave_requested_at_ms = pending.get(&group.group_id_hex).copied();
            }
        }
        let storage = self.account_storage(label)?;
        let disbanding = storage.disbanding_group_ids_hex()?;
        let requests = storage.disband_requests_by_group_hex()?;
        let disbanded = storage
            .list_disband_tombstones()?
            .into_iter()
            .map(|(group_id, _)| hex::encode(group_id.as_slice()))
            .collect::<HashSet<_>>();
        for group in &mut groups {
            group.disbanding = disbanding.contains(&group.group_id_hex);
            group.disband_request = requests.get(&group.group_id_hex).cloned().map(Into::into);
            group.disbanded = disbanded.contains(&group.group_id_hex);
        }
        Ok(groups)
    }

    /// Outstanding durable leave requests for this account, keyed by group id hex
    /// and mapped to when the user asked to leave.
    ///
    /// Reads the engine's own `cgka_leave_requests` rows rather than a
    /// denormalized projection column: the engine clears them from paths that
    /// never notify the app layer (an accepted commit that removed us, hydration
    /// finding the local member gone, a convergence reorg), so a cached copy
    /// would silently go stale.
    pub fn pending_leave_requests(&self, label: &str) -> Result<HashMap<String, u64>, AppError> {
        self.ensure_account_state(label)?;
        Ok(self.account_storage(label)?.pending_leave_requests()?)
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
        defer_group_hydration: bool,
    ) -> Result<OpenAppAccount, AppError> {
        let account = self.account_home().account(label)?;
        // Account refs may be labels, hex pubkeys, or npubs. Ownership is keyed
        // by the canonical stored label so aliases cannot open a second engine.
        let label = account.label.as_str();
        let session_guard = self.acquire_account_session(label)?;
        let state = self.load_state(label)?;
        let signer = self.account_signer_for_summary(&account)?;
        let account_id = MemberId::new(hex::decode(&account.account_id_hex)?);
        let nostr_signer = signer.as_nostr_signer();
        let peeler = NostrMlsPeeler::new().with_welcome_signer(nostr_signer.clone());
        let session_path = self.account_dir(label).join(SESSION_DB_FILE);
        let session_key = if let AccountSigner::Local(keys) = &signer {
            self.sqlcipher_key(label, keys, &session_path, SqlcipherDatabaseKind::Session)?
        } else {
            self.external_sqlcipher_key(
                label,
                &account.account_id_hex,
                &session_path,
                SqlcipherDatabaseKind::Session,
            )?
        };
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
        .account_identity_proof_signer(signer.as_proof_signer())
        .feature_registry(app_feature_registry())
        .supported_app_components(self.supported_app_component_ids());
        if defer_group_hydration {
            session_config = session_config.defer_group_hydration();
        }
        // Production uses the protocol-pinned convergence policy (SessionConfig's
        // default). Only an explicit test-policy build may change it; normal
        // debug and release builds ignore the knob (mdk#970).
        if let Some(ms) = self.config.dev_settlement_quiescence_ms {
            if cfg!(feature = "test-policy-overrides") {
                session_config = session_config.convergence_policy(CanonicalizationPolicy {
                    settlement_quiescence_ms: ms,
                    ..CanonicalizationPolicy::default()
                });
            } else {
                tracing::warn!(
                    target: "marmot_app",
                    method = "open_account",
                    "ignoring dev_settlement_quiescence_ms without test-policy-overrides; pinned v1 policy required"
                );
            }
        }
        let audit_log_enabled = match self.audit_log_settings() {
            Ok(settings) => settings.enabled,
            Err(e) => {
                tracing::warn!(
                    target: "marmot_app",
                    method = "open_account",
                    error_kind = e.privacy_safe_kind(),
                    "failed to read forensic audit log settings; continuing without audit logging"
                );
                false
            }
        };
        if audit_log_enabled && let Some(recorder) = self.open_audit_recorder(label, &account_id) {
            session_config = session_config.recorder(recorder);
        }
        self.ensure_strict_cutover_replacement_intent_before_session_open(label)?;
        let session =
            AccountDeviceSession::open(session_config).map_err(external_signer_session_error)?;

        let publish_client =
            self.relay_client_for_endpoints(nostr_signer.clone(), &self.relay_endpoints());
        let adapter = relay_plane.account_adapter(account_id.clone(), publish_client);

        let key_packages = AppKeyPackagePublisher {
            app: self.clone(),
            account_label: label.to_owned(),
            signer: signer.clone(),
        };
        let routing = self.routing_for(&state)?;
        let runtime =
            AccountDeviceRuntime::new(session, adapter.clone(), routing.clone(), key_packages);
        Ok(OpenAppAccount {
            runtime,
            session_guard,
            adapter,
            routing,
            state,
            signer: nostr_signer,
        })
    }

    fn acquire_account_session(&self, label: &str) -> Result<AppAccountSessionGuard, AppError> {
        let mut owners = self
            .account_session_owners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !owners.insert(label.to_owned()) {
            return Err(AppError::AccountSessionBusy);
        }
        Ok(AppAccountSessionGuard {
            label: label.to_owned(),
            owners: self.account_session_owners.clone(),
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
            let endpoints = self.retain_safe_discovered_endpoints(
                entry
                    .relay_lists
                    .inbox
                    .relays
                    .into_iter()
                    .map(TransportEndpoint)
                    .collect(),
                "directory inbox routing",
            );
            if !endpoints.is_empty() {
                inbox_routes
                    .entry(MemberId::new(hex::decode(entry.account_id_hex)?))
                    .or_insert(endpoints);
            }
        }

        let account = self.account_home().account(&state.label)?;
        let account_storage = self.account_storage(&state.label)?;
        let disbanded_group_ids = account_storage
            .list_disband_tombstones()?
            .into_iter()
            .map(|(group_id, _)| hex::encode(group_id.as_slice()))
            .collect::<HashSet<_>>();
        let relay_lists = self.account_relay_list_status_for_account_id(&account.account_id_hex)?;
        let mut group_routes = Vec::new();
        for group in &state.groups {
            let Ok(group_id_bytes) = hex::decode(&group.group_id_hex) else {
                tracing::warn!(
                    target: "marmot_app",
                    method = "routing_for",
                    error_kind = "invalid_persisted_route_identifier",
                    "skipping malformed persisted group route",
                );
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            if disbanded_group_ids.contains(&hex::encode(group_id.as_slice())) {
                continue;
            }
            match group.transport_subscriptions(&group_id) {
                Ok(subscriptions) => group_routes.extend(subscriptions),
                Err(_) => tracing::warn!(
                    target: "marmot_app",
                    method = "routing_for",
                    error_kind = "invalid_persisted_group_route",
                    "skipping malformed persisted group route",
                ),
            }
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
        let key_package = key_package_from_hex_with_optional_source(
            &record.key_package_hex,
            &record.key_package_event_id,
        )?;
        let metadata = key_package_metadata(&key_package)
            .map_err(|error| AppError::InvalidKeyPackageEvent(error.to_string()))?;
        Ok(key_package.with_protocol_profile(metadata.protocol_profile))
    }

    /// Best-effort public-event cleanup after the session has already
    /// transactionally removed the matching non-current private bundle.
    ///
    /// A failed relay deletion deliberately leaves the cache record in place:
    /// the current replacement then reuses the same replaceable-event `d`
    /// slot, superseding the legacy event wherever the deletion was missed.
    /// If replacement publication also fails, the next account open retries
    /// from the unchanged cache.
    async fn retire_cached_non_current_key_package(&self, label: &str) -> bool {
        let path = self.key_package_record_path(label);
        let record = match read_json::<KeyPackageRecord>(&path) {
            Ok(record) => record,
            Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return false;
            }
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "retire_cached_non_current_key_package",
                    error_kind = error.privacy_safe_kind(),
                    "could not classify cached key package after strict cutover"
                );
                if !self.mark_key_package_cutover_replacement_pending(label) {
                    return false;
                }
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(remove_error) if remove_error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(remove_error) => tracing::warn!(
                        target: "marmot_app::key_packages",
                        method = "retire_cached_non_current_key_package",
                        error_kind = AppError::from(remove_error).privacy_safe_kind(),
                        "could not remove invalid key package cache"
                    ),
                }
                return true;
            }
        };
        let is_current = key_package_from_hex_with_optional_source(
            &record.key_package_hex,
            &record.key_package_event_id,
        )
        .ok()
        .and_then(|key_package| key_package_metadata(&key_package).ok())
        .is_some_and(|metadata| {
            self.key_package_metadata_matches_current_support(&metadata)
                && metadata.credential_identity_hex == record.account_id_hex
        });
        if is_current {
            return false;
        }
        if !self.mark_key_package_cutover_replacement_pending(label) {
            return false;
        }

        if record.key_package_event_id.is_empty() {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "retire_cached_non_current_key_package",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not remove unpublished non-current key package cache"
                ),
            }
            return true;
        }

        match self
            .delete_key_package_event(label, &record.key_package_event_id, Vec::new())
            .await
        {
            Ok(accepted) => tracing::info!(
                target: "marmot_app::key_packages",
                method = "retire_cached_non_current_key_package",
                relay_accept_count = accepted,
                "retired cached non-current key package event"
            ),
            Err(error) => tracing::warn!(
                target: "marmot_app::key_packages",
                method = "retire_cached_non_current_key_package",
                error_kind = error.privacy_safe_kind(),
                "could not delete cached non-current key package event; current replacement will supersede its slot"
            ),
        }
        true
    }

    /// Scan the account's authoritative KeyPackage relays and best-effort
    /// delete every still-discoverable legacy event. This runs on each account
    /// open, so a crash or partial relay outage simply leaves work for the next
    /// restart. Local private bundles have already been retired synchronously.
    async fn retire_relay_non_current_key_packages(&self, label: &str) -> bool {
        if self.key_package_cutover_scan_complete(label)
            && !self.key_package_cutover_replacement_pending(label)
        {
            return false;
        }
        let account = match self.account_home().account(label) {
            Ok(account) => account,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "retire_relay_non_current_key_packages",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not resolve account for relay key package retirement"
                );
                return false;
            }
        };
        let relay_lists =
            match self.account_relay_list_status_for_account_id(&account.account_id_hex) {
                Ok(relay_lists) => relay_lists,
                Err(error) => {
                    tracing::warn!(
                        target: "marmot_app::key_packages",
                        method = "retire_relay_non_current_key_packages",
                        error_kind = error.privacy_safe_kind(),
                        "could not resolve relays for key package retirement"
                    );
                    return false;
                }
            };
        let source_relays = relay_lists
            .nip65
            .relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        if source_relays.is_empty() {
            return false;
        }
        let records = match self
            .fetch_key_package_events_for_account_id_with_limit(
                &account.account_id_hex,
                &source_relays,
                KEY_PACKAGE_CUTOVER_RELAY_SCAN_LIMIT,
            )
            .await
        {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "retire_relay_non_current_key_packages",
                    error_kind = error.privacy_safe_kind(),
                    "deferred relay key package retirement scan"
                );
                return false;
            }
        };

        let mut non_current_event_count = 0usize;
        let mut accepted_delete_count = 0usize;
        let mut delete_failure_count = 0usize;
        for record in records {
            let event_id = record.event.id.clone();
            let endpoints = record.endpoints.clone();
            let is_current = key_package_from_record(record)
                .ok()
                .and_then(|fetched| key_package_metadata(&fetched.key_package).ok())
                .is_some_and(|metadata| {
                    self.key_package_metadata_matches_current_support(&metadata)
                });
            if is_current {
                continue;
            }
            if !self.mark_key_package_cutover_replacement_pending(label) {
                delete_failure_count += 1;
                continue;
            }
            non_current_event_count += 1;
            match self
                .delete_key_package_event(label, &event_id, endpoints)
                .await
            {
                Ok(accepted) => accepted_delete_count += accepted,
                Err(_) => delete_failure_count += 1,
            }
        }
        if delete_failure_count == 0 {
            self.mark_key_package_cutover_scan_complete(label);
        }
        if non_current_event_count > 0 {
            tracing::info!(
                target: "marmot_app::key_packages",
                method = "retire_relay_non_current_key_packages",
                non_current_event_count,
                accepted_delete_count,
                delete_failure_count,
                "completed relay key package retirement scan"
            );
        }
        non_current_event_count > 0
    }

    fn key_package_cutover_replacement_pending_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.capability-refresh-v1-replacement-pending"))
    }

    fn key_package_cutover_scan_complete_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.capability-refresh-v1-relay-scan-complete"))
    }

    fn key_package_cutover_replacement_pending(&self, label: &str) -> bool {
        self.key_package_cutover_replacement_pending_path(label)
            .exists()
    }

    fn mark_key_package_cutover_replacement_pending(&self, label: &str) -> bool {
        let path = self.key_package_cutover_replacement_pending_path(label);
        let result = path
            .parent()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "cutover marker has no parent directory",
                )
            })
            .and_then(fs_private::create_dir_all_private)
            .and_then(|()| fs_private::write_private(&path, b"pending\n"));
        match result {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "mark_key_package_cutover_replacement_pending",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not persist key package cutover replacement intent"
                );
                false
            }
        }
    }

    fn clear_key_package_cutover_replacement_pending(&self, label: &str) {
        let path = self.key_package_cutover_replacement_pending_path(label);
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                target: "marmot_app::key_packages",
                method = "clear_key_package_cutover_replacement_pending",
                error_kind = AppError::from(error).privacy_safe_kind(),
                "could not clear completed key package replacement intent"
            ),
        }
    }

    /// Remove compatibility artifacts that live outside the account directory.
    /// Account-home deletion cannot otherwise make setup rollback complete.
    fn remove_account_key_package_artifacts(&self, label: &str) -> Result<(), AppError> {
        for path in [
            self.key_package_record_path(label),
            self.key_package_cutover_replacement_pending_path(label),
            self.key_package_cutover_scan_complete_path(label),
        ] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn key_package_cutover_scan_complete(&self, label: &str) -> bool {
        self.key_package_cutover_scan_complete_path(label).exists()
    }

    fn mark_key_package_cutover_scan_complete(&self, label: &str) {
        let path = self.key_package_cutover_scan_complete_path(label);
        let result = path
            .parent()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "cutover marker has no parent directory",
                )
            })
            .and_then(fs_private::create_dir_all_private)
            .and_then(|()| fs_private::write_private(&path, b"complete\n"));
        if let Err(error) = result {
            tracing::warn!(
                target: "marmot_app::key_packages",
                method = "mark_key_package_cutover_scan_complete",
                error_kind = AppError::from(error).privacy_safe_kind(),
                "could not persist completed key package relay scan"
            );
        }
    }

    pub fn local_key_package_records(
        &self,
        label: &str,
        owned_key_packages: Vec<KeyPackage>,
    ) -> Result<Vec<AccountKeyPackageRecord>, AppError> {
        let account = self.account_home().account(label)?;
        let legacy_record = read_json::<KeyPackageRecord>(self.key_package_record_path(label)).ok();
        let lifecycle = self.account_storage(label)?.key_package_lifecycle()?;
        let source_relays = self.account_nip65_relays(label).unwrap_or_default();
        let mut records = Vec::with_capacity(owned_key_packages.len());

        for key_package in owned_key_packages {
            let metadata = key_package_metadata(&key_package)
                .map_err(|error| AppError::InvalidKeyPackageEvent(error.to_string()))?;
            let key_package_ref = hex::decode(&metadata.key_package_ref_hex)?;
            let mut key_package_id = metadata.key_package_ref_hex.clone();
            let mut key_package_event_id = String::new();
            let mut published_at = 0;

            if let Some(lifecycle) = lifecycle.as_ref() {
                if lifecycle.current_key_package_ref.as_deref() == Some(&key_package_ref) {
                    key_package_id = lifecycle.stable_slot_id.clone();
                    key_package_event_id = lifecycle
                        .authored_event_id
                        .as_ref()
                        .map(|id| hex::encode(id.as_slice()))
                        .unwrap_or_default();
                    published_at = lifecycle
                        .authored_event_created_at
                        .map(|created_at| created_at.0)
                        .unwrap_or_default();
                } else if let Some(pending) = lifecycle
                    .pending_replacement
                    .as_ref()
                    .filter(|pending| pending.key_package_ref == key_package_ref)
                {
                    key_package_id = lifecycle.stable_slot_id.clone();
                    key_package_event_id = pending
                        .signed_event
                        .as_ref()
                        .map(|event| hex::encode(event.id.as_slice()))
                        .unwrap_or_default();
                    published_at = pending
                        .signed_event
                        .as_ref()
                        .map(|event| event.created_at.0)
                        .unwrap_or(pending.authored_created_at.0);
                } else if let Some(retained) = lifecycle
                    .retained_private_material
                    .iter()
                    .find(|retained| retained.key_package_ref == key_package_ref)
                {
                    key_package_id = lifecycle.stable_slot_id.clone();
                    published_at = retained.replaced_at.0;
                }
            }

            if let Some(legacy) = legacy_record
                .as_ref()
                .filter(|legacy| legacy.key_package_ref_hex == metadata.key_package_ref_hex)
            {
                if key_package_id == metadata.key_package_ref_hex {
                    key_package_id = legacy.key_package_id.clone();
                }
                if key_package_event_id.is_empty() {
                    key_package_event_id = legacy.key_package_event_id.clone();
                }
                if published_at == 0 {
                    published_at = legacy.published_at;
                }
            }

            records.push(AccountKeyPackageRecord {
                account_label: Some(account.label.clone()),
                account_id_hex: account.account_id_hex.clone(),
                key_package_id,
                key_package_ref_hex: metadata.key_package_ref_hex,
                key_package_event_id,
                published_at,
                key_package_bytes: key_package.bytes().len(),
                source_relays: source_relays.clone(),
                local: true,
                relay: false,
            });
        }
        Ok(records)
    }

    pub async fn account_key_package_records(
        &self,
        label: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
        owned_key_packages: Vec<KeyPackage>,
    ) -> Result<Vec<AccountKeyPackageRecord>, AppError> {
        let account = self.account_home().account(label)?;
        let account_id_hex = account.account_id_hex;
        let mut packages = self.local_key_package_records(label, owned_key_packages)?;

        let has_explicit_bootstrap_relays = !bootstrap_relays.is_empty();
        let mut relay_lists = if has_explicit_bootstrap_relays {
            self.fetch_account_relay_list_status_for_account_id(&account_id_hex, bootstrap_relays)
                .await?
        } else {
            self.account_relay_list_status_for_account_id(&account_id_hex)?
        };
        // Discover the account's NIP-65 list via default relays when it is not
        // cached yet, mirroring fetch_latest_key_package_for_account_id. We never
        // normally pull KeyPackage events from the account's own NIP-65 relays.
        // When that published route exists but every endpoint is unusable, use
        // the configured directory relays as the same operational fallback used
        // when local accounts publish a KeyPackage without rewriting NIP-65.
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
        let mut source_relays = self.retain_safe_discovered_endpoints(
            relay_lists
                .nip65
                .relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect(),
            "account key package listing",
        );
        if source_relays.is_empty() {
            source_relays = self.directory_source_relays(&[]);
        }
        if source_relays.is_empty() {
            return Err(AppError::MissingRelayLists(vec![
                MissingRelayListKind::Nip65,
            ]));
        }

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
                        error_kind = err.privacy_safe_kind(),
                        "skipping invalid key package event while listing account packages"
                    );
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
        let mut outcomes = self
            .delete_key_package_events(
                label,
                vec![KeyPackageDeletionTarget {
                    event_id_hex: event_id_hex.to_owned(),
                    source_relays,
                }],
            )
            .await?;
        outcomes
            .pop()
            .expect("single-event deletion batch returns one outcome")
            .result
    }

    pub(crate) async fn delete_key_package_events(
        &self,
        label: &str,
        targets: Vec<KeyPackageDeletionTarget>,
    ) -> Result<Vec<KeyPackageDeletionResult>, AppError> {
        let account = self.account_home().account(label)?;
        let signer = self.account_signer_for_summary(&account)?;
        let account_id_hex = account.account_id_hex;
        let mut results = targets
            .iter()
            .map(|target| KeyPackageDeletionResult {
                event_id_hex: target.event_id_hex.clone(),
                result: Err(AppError::Publish("deletion was not attempted".to_owned())),
            })
            .collect::<Vec<_>>();
        let mut requests = Vec::new();
        let mut request_indices = Vec::new();
        let mut all_endpoints = Vec::new();

        for (index, target) in targets.into_iter().enumerate() {
            let event_id_hex = match parse_key_package_event_id_hex(&target.event_id_hex) {
                Ok(event_id_hex) => event_id_hex,
                Err(error) => {
                    results[index].result = Err(error);
                    continue;
                }
            };
            let endpoints = if target.source_relays.is_empty() {
                match self.account_relay_list_status_for_account_id(&account_id_hex) {
                    Ok(relay_lists) => self.key_package_endpoints(&relay_lists),
                    Err(error) => {
                        results[index].result = Err(error);
                        continue;
                    }
                }
            } else {
                target.source_relays
            };
            if endpoints.is_empty() {
                results[index].result = Err(AppError::MissingRelayLists(vec![
                    MissingRelayListKind::Nip65,
                ]));
                continue;
            }
            let endpoints = match self
                .relay_plane
                .sanitize_relay_endpoints(endpoints, "key package deletion publish")
            {
                Ok(endpoints) => endpoints,
                Err(error) => {
                    results[index].result = Err(AppError::Transport(
                        cgka_traits::TransportAdapterError::Publish(error),
                    ));
                    continue;
                }
            };
            all_endpoints.extend(endpoints.iter().cloned());
            requests.push(NostrEventPublishRequest {
                endpoints,
                event: NostrTransportEvent::new_unsigned(
                    account_id_hex.clone(),
                    5,
                    vec![
                        vec!["e".into(), event_id_hex],
                        vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
                    ],
                    String::new(),
                ),
                required_acks: 1,
            });
            request_indices.push(index);
        }

        if !requests.is_empty() {
            let relay_client =
                self.relay_client_for_endpoints(signer.as_nostr_signer(), &all_endpoints);
            let outcomes = relay_client.publish_events(&requests).await;
            for (index, outcome) in request_indices.into_iter().zip(outcomes) {
                results[index].result = match outcome {
                    Ok(outcome) if !outcome.accepted.is_empty() => Ok(outcome.accepted.len()),
                    Ok(_) => Err(AppError::Publish(
                        "relay acknowledged zero key package deletions".to_owned(),
                    )),
                    Err(error) => Err(error.into()),
                };
            }
        }

        let path = self.key_package_record_path(label);
        for result in &mut results {
            if result.result.is_err() {
                continue;
            }
            if let Ok(record) = read_json::<KeyPackageRecord>(&path)
                && record.key_package_event_id == result.event_id_hex
            {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => result.result = Err(err.into()),
                }
            }
        }

        Ok(results)
    }

    fn key_package_record_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.json"))
    }

    fn reusable_key_package_slot_id(
        &self,
        label: &str,
        account_id_hex: &str,
    ) -> Result<Option<String>, AppError> {
        let path = self.key_package_record_path(label);
        let record: KeyPackageRecord = match read_json(&path) {
            Ok(record) => record,
            Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                if self.key_package_cutover_replacement_pending(label) {
                    return Err(AppError::Publish(
                        "legacy key package replacement is pending but its stable slot is unavailable"
                            .into(),
                    ));
                }
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if record.account_id_hex != account_id_hex || record.key_package_id.is_empty() {
            return Err(AppError::Publish(
                "legacy key package slot record does not match the local account".into(),
            ));
        }
        let bytes = hex::decode(&record.key_package_hex)?;
        // This helper only preserves the replaceable-event `d` slot. Classify
        // either deployed legacy bytes or current bytes so a strict-cutover
        // replacement can supersede the same slot; the publication boundary
        // below still rejects anything except a current KeyPackage.
        let key_package = KeyPackage::new(bytes);
        let metadata = [
            cgka_traits::group::ProtocolProfile::Current,
            cgka_traits::group::ProtocolProfile::Legacy,
        ]
        .into_iter()
        .find_map(|profile| {
            key_package_metadata(&key_package.clone().with_protocol_profile(profile)).ok()
        })
        .ok_or_else(|| AppError::Publish("legacy key package record is invalid".into()))?;
        if metadata.credential_identity_hex != account_id_hex {
            return Err(AppError::Publish(
                "legacy key package credential does not match the local account".into(),
            ));
        }
        Ok(Some(record.key_package_id))
    }

    fn validated_current_local_key_package(&self, label: &str) -> Option<KeyPackage> {
        let account = self.account_home().account(label).ok()?;
        let key_package = self.latest_key_package(label).ok()?;
        let metadata = key_package_metadata(&key_package).ok()?;
        (metadata.protocol_profile == cgka_traits::group::ProtocolProfile::Current
            && metadata.credential_identity_hex == account.account_id_hex)
            .then_some(key_package)
    }

    /// Persist strict-cutover replacement intent before the session layer can
    /// delete unpublished non-current private bundles during open.
    fn ensure_strict_cutover_replacement_intent_before_session_open(
        &self,
        label: &str,
    ) -> Result<(), AppError> {
        let account_storage_preexisted = self.account_storage_path(label).exists();
        let setup_in_progress = self.account_home().account_setup_state(label)?.is_some();
        let storage = self.account_storage(label)?;
        let existing_lifecycle = storage.key_package_lifecycle()?;
        if existing_lifecycle
            .as_ref()
            .is_some_and(|lifecycle| !lifecycle.stable_slot_id.is_empty())
        {
            return Ok(());
        }
        let current_cache = self.validated_current_local_key_package(label).is_some();
        match self.reusable_key_package_slot_id(
            label,
            &self.account_home().account(label)?.account_id_hex,
        ) {
            Ok(Some(stable_slot_id)) => {
                let mut lifecycle = existing_lifecycle
                    .clone()
                    .unwrap_or_else(|| empty_key_package_lifecycle(String::new()));
                lifecycle.stable_slot_id = stable_slot_id;
                storage.put_key_package_lifecycle(&lifecycle)?;
                if current_cache || self.mark_key_package_cutover_replacement_pending(label) {
                    return Ok(());
                }
            }
            Ok(None)
                if (!account_storage_preexisted || setup_in_progress)
                    && storage.stored_key_package_bundles()?.is_empty() =>
            {
                // Only a newly-created or durably journaled account setup can
                // mint the first slot without migration evidence. Other
                // existing databases fail closed even when no private bundles
                // remain: they may have published under an unrecoverable `d`.
                let mut slot = [0u8; 32];
                OsRng.fill_bytes(&mut slot);
                storage
                    .put_key_package_lifecycle(&empty_key_package_lifecycle(hex::encode(slot)))?;
                if self.mark_key_package_cutover_replacement_pending(label) {
                    return Ok(());
                }
            }
            Ok(None) | Err(_) if account_storage_preexisted && !setup_in_progress => {
                // A database created before the durable setup journal is
                // ambiguous: it may be an interrupted fresh setup, or an
                // upgraded device whose published stable slot was lost. Do not
                // mint a second slot. Keep normal account reads available; the
                // setup publication boundary surfaces the typed recovery state.
                if self.mark_key_package_cutover_replacement_pending(label) {
                    return Ok(());
                }
            }
            Ok(None) | Err(_) => {
                // Preserve an explicit fail-closed marker. The publisher will
                // refuse to mint a second slot until migration can recover the
                // original `d` value.
                if self.mark_key_package_cutover_replacement_pending(label) {
                    return Ok(());
                }
            }
        }
        if self.key_package_cutover_replacement_pending(label) {
            return Ok(());
        }
        Err(AppError::Io(std::io::Error::other(
            "could not persist strict cutover replacement intent before session open",
        )))
    }

    fn legacy_incomplete_setup_requires_recovery(&self, label: &str) -> Result<bool, AppError> {
        if !self.account_storage_path(label).exists()
            || self.account_home().account_setup_state(label)?.is_some()
            || self.key_package_record_path(label).exists()
        {
            return Ok(false);
        }
        let storage = self.account_storage(label)?;
        Ok(storage.key_package_lifecycle()?.is_none()
            && storage.stored_key_package_bundles()?.is_empty())
    }

    async fn member_key_package(&self, member_ref: &str) -> Result<KeyPackage, AppError> {
        // Local accounts: cache files are keyed by the account's canonical
        // label, so resolve the ref (which may be an npub or hex pubkey)
        // before looking up the cached key package. Using the raw ref here
        // would miss the file when inviting a local account by npub.
        let local_account = self.account_home().account(member_ref).ok();
        if let Some(account) = &local_account
            && let Some(key_package) = self.validated_current_local_key_package(&account.label)
        {
            return Ok(key_package);
        }
        let account_id = if let Some(account) = local_account {
            account.account_id_hex
        } else {
            PublicKey::parse(member_ref)
                .map_err(|_| AppError::InvalidPublicKey)?
                .to_hex()
        };
        if let Some(entry) = self.directory_entry_for_account_id(&account_id)? {
            if let Some(key_package) = entry.key_package {
                return validated_cached_key_package(&account_id, &key_package);
            }
            let source_relays = self.retain_safe_discovered_endpoints(
                entry
                    .relay_lists
                    .nip65
                    .relays
                    .iter()
                    .cloned()
                    .map(TransportEndpoint)
                    .collect(),
                "member key package fetch",
            );
            if !source_relays.is_empty() {
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
        let entry = self.directory_entry_for_account_id(account_id_hex)?;
        self.display_name_from_directory_entry(account_id_hex, entry.as_ref())
    }

    /// Resolve a display name from an ALREADY-FETCHED directory entry, falling
    /// back to a local account's label. Split out so callers that already hold
    /// the entry (e.g. notification building, #639) don't re-query
    /// `directory_entry_for_account_id`.
    pub(crate) fn display_name_from_directory_entry(
        &self,
        account_id_hex: &str,
        entry: Option<&UserDirectoryRecord>,
    ) -> Result<Option<String>, AppError> {
        if let Some(name) = display_name_for_profile(entry.and_then(|entry| entry.profile.as_ref()))
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
            (message.attachment_kind, message.attachment_count) =
                media::classify_chat_list_attachments(message.media_json.as_deref());
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
        (message.attachment_kind, message.attachment_count) =
            media::classify_chat_list_attachments(message.media_json.as_deref());
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

    /// Persist the account snapshot. Concurrent runtimes (the main app and a
    /// short-lived notification-wake process) may save over the same account
    /// database; the durable transport cursor is merged clamp-then-max inside
    /// the save transaction (see `save_account_projection_state` in
    /// storage-sqlite for the full cross-process semantics), so a stale or
    /// cursor-less save can never lower or wipe an advanced cursor, and a
    /// stored value poisoned above `now + TRANSPORT_CURSOR_MAX_FUTURE_SKEW` is
    /// healed down on the next save that learned a cursor. Known residual: a
    /// skew-inflated but within-clamp cursor persists until wall clock passes
    /// it — bounded exposure, ~180s beyond the 120s
    /// `APP_RUNTIME_RELAY_REBUILD_LOOKBACK`. A deliberate cursor reset must be
    /// a dedicated named API; a raw save cannot lower the merged value.
    fn save_state(&self, state: &AccountState) -> Result<(), AppError> {
        self.account_storage(&state.label)?
            .save_account_projection_state(
                &stored_state_from_account_state(state),
                MAX_SEEN_EVENT_IDS,
                TRANSPORT_CURSOR_MAX_FUTURE_SKEW.as_secs(),
            )?;
        self.chat_list_projection_stale
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(state.label.clone());
        Ok(())
    }

    pub(crate) fn delete_group_local_data(
        &self,
        label: &str,
        group_id_hex: &str,
    ) -> Result<bool, AppError> {
        self.ensure_account_state(label)?;
        let storage = self.account_storage(label)?;
        let group_id = GroupId::new(hex::decode(group_id_hex)?);
        let normalized_group_id_hex = hex::encode(group_id.as_slice());
        if storage
            .disbanding_group_ids_hex()?
            .contains(&normalized_group_id_hex)
        {
            return Err(AppError::GroupDisbanding(group_id_hex.to_owned()));
        }
        let deleted = storage.delete_local_group_data(group_id_hex)?.did_delete();
        self.chat_list_projection_stale
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(label.to_owned());
        self.chat_list_projection_warmed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(label);
        Ok(deleted)
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
        // Run KeyPackage cutover before any other account-storage access. The
        // cutover uses pre-existence of the encrypted account database as the
        // durable distinction between a fresh local account and an upgraded
        // device whose missing JSON slot must fail closed.
        self.ensure_strict_cutover_replacement_intent_before_session_open(label)?;
        self.migrate_legacy_account_projection_if_needed(label)?;
        self.account_storage(label)?
            .ensure_account_projection(label)?;
        ready.insert(label.to_owned());
        Ok(())
    }

    /// Build the unread-mention classifier injected into the chat-list
    /// projection. The storage layer never parses nostr/NIP-21, so it calls back
    /// into the same notification mention classification (`p`-tag + inline nostr
    /// pubkey references, i.e. bare `@npub1…` handles and explicit `nostr:`
    /// URIs) used for push notifications, scoped to the local account. The
    /// unread window is already kind-9 filtered, but the real chat kind is
    /// passed for correctness.
    fn chat_list_mention_classifier(
        account_id_hex: &str,
    ) -> impl Fn(&str, &[Vec<String>]) -> bool + use<> {
        let account_id_hex = account_id_hex.to_owned();
        move |plaintext, tags| {
            crate::notifications::message_text_mentions_account(
                MARMOT_APP_EVENT_KIND_CHAT,
                plaintext,
                tags,
                &account_id_hex,
            )
        }
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
        let classifier = Self::chat_list_mention_classifier(&account.account_id_hex);
        if stale {
            storage.refresh_chat_list_rows(&account.account_id_hex, &classifier)?;
        } else {
            storage.ensure_chat_list_rows(&account.account_id_hex, &classifier)?;
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
        _label: &str,
        relay_lists: &AccountRelayListStatus,
    ) -> Vec<TransportEndpoint> {
        let offered = relay_lists.inbox.relays.len();
        let safe = self.retain_safe_discovered_endpoints(
            relay_lists
                .inbox
                .relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect(),
            "local account inbox activation",
        );
        if !safe.is_empty() {
            return safe;
        }
        let fallback = self.relay_endpoints();
        if offered > 0 {
            tracing::warn!(
                target: "marmot_app::relay_plane",
                method = "account_inbox_endpoints",
                offered = offered,
                fallback = fallback.len(),
                "published account inbox has no usable endpoints; using configured defaults"
            );
        }
        fallback
    }

    fn key_package_endpoints(
        &self,
        relay_lists: &AccountRelayListStatus,
    ) -> Vec<TransportEndpoint> {
        // KeyPackages publish to (and are fetched from) the account's NIP-65
        // (kind 10002) outbox relays; there is no dedicated KeyPackage relay
        // list. Fall back to the configured default relays when the account has
        // no usable NIP-65 relay. This runtime fallback is not published as a
        // replacement for the account's relay list.
        let offered = relay_lists.nip65.relays.len();
        let safe = self.retain_safe_discovered_endpoints(
            relay_lists
                .nip65
                .relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect(),
            "local account key package routing",
        );
        if !safe.is_empty() {
            return safe;
        }
        let fallback = self.relay_endpoints();
        if offered > 0 {
            tracing::warn!(
                target: "marmot_app::relay_plane",
                method = "key_package_endpoints",
                offered = offered,
                fallback = fallback.len(),
                "published account outbox has no usable endpoints; using configured defaults"
            );
        }
        fallback
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

    /// Close every SQLite database this app has open and release the root
    /// runtime lease, so nothing this process owns holds a file lock inside the
    /// Marmot root.
    ///
    /// Callers must quiesce first — this closes databases out from under any
    /// work still running (see [`SqliteAccountStorage::close`] for what that
    /// does to in-flight transactions). [`MarmotAppRuntime::shutdown_and_close`]
    /// is the sequenced entry point host apps should use; it drains the account
    /// workers before calling this.
    ///
    /// **Terminal.** [`Self::storage_is_closed`] latches, and every database
    /// accessor then fails with
    /// [`StorageError::Closed`][cgka_traits::storage::StorageError::Closed]
    /// rather than reopening;
    /// otherwise a stray background read would re-lock the container a host has
    /// just been told is lock-free. Construct a new [`MarmotApp`] to use the
    /// root again. Idempotent.
    ///
    /// This exists for hosts that share the Marmot root across processes
    /// through a container the OS polices. On iOS the root lives in an App
    /// Group container shared with the Notification Service Extension, and a
    /// process suspended while holding *any* lock there is killed with
    /// `0xdead10cc` — which a WAL connection does for its whole lifetime, and
    /// the root lease does by design. Dropping handles cannot fix that: the
    /// databases sit behind `Arc`s reachable from the engine, the OpenMLS
    /// adapter, and app projections, so the host can neither observe nor await
    /// the last clone going away.
    ///
    /// Every database is attempted even if an earlier one fails; the first
    /// error is returned once all of them have been closed.
    pub fn close_storage(&self) -> Result<(), AppError> {
        let started_at = Instant::now();
        // Exclusive for the whole teardown. The `storage_closed` flag alone
        // would not make this atomic: two concurrent closes could interleave so
        // that one released the root lease and returned while the other was
        // still closing connections, and an open already in flight could finish
        // creating its connection after this method returned. Either way the
        // host would be told the container is lock-free while a lock still
        // existed. Holding the writer means every opener has either published
        // (so the drain below closes it) or has not yet checked the flag (so it
        // will refuse).
        let _lifecycle = self
            .storage_lifecycle
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.storage_closed.store(true, Ordering::Release);
        let mut first_error = None;
        let mut closed = 0usize;

        let account_storages = self
            .account_storages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain()
            .map(|(_, storage)| storage)
            .collect::<Vec<_>>();
        let directory_caches = self
            .directory_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain()
            .map(|(_, cache)| cache)
            .collect::<Vec<_>>();
        let shared_storage = self
            .shared_storage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();

        for storage in account_storages {
            closed += 1;
            if let Err(error) = storage.close() {
                first_error.get_or_insert(AppError::from(error));
            }
        }
        for cache in directory_caches {
            closed += 1;
            if let Err(error) = cache.close() {
                first_error.get_or_insert(error);
            }
        }
        if let Some(storage) = shared_storage {
            closed += 1;
            if let Err(error) = storage.close() {
                first_error.get_or_insert(AppError::from(error));
            }
        }

        // Last: the lease guards the databases, so it outlives them.
        drop(
            self.root_runtime_lease
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take(),
        );

        tracing::debug!(
            target: "marmot_app::storage",
            method = "close_storage",
            databases_closed = closed,
            elapsed_ms = started_at.elapsed().as_millis() as u64,
            failed = first_error.is_some(),
            "app storage closed",
        );
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Whether [`Self::close_storage`] has run. Databases are unreachable from
    /// this handle once it returns true.
    #[must_use]
    pub fn storage_is_closed(&self) -> bool {
        self.storage_closed.load(Ordering::Acquire)
    }

    /// Fail rather than reopen a database after [`Self::close_storage`].
    fn ensure_storage_open(&self, database: &'static str) -> Result<(), AppError> {
        if self.storage_is_closed() {
            return Err(AppError::from(cgka_traits::StorageError::Closed(format!(
                "{database} unavailable: app storage is closed"
            ))));
        }
        Ok(())
    }

    /// Admission for a database *open*, held from the closed check through
    /// publication into the handle cache.
    ///
    /// Opens are readers, so they still run concurrently with each other;
    /// [`Self::close_storage`] is the writer. That is what makes the close's
    /// promise true: an open holding this guard either publishes before the
    /// close can start draining, or has not yet checked the flag and will
    /// refuse. No connection can be created after the close returns.
    ///
    /// Cache *hits* deliberately skip this — a handle already in the cache is
    /// one the close will drain and shut, so returning a clone of it cannot
    /// leak a lock, and the hot read path stays uncontended.
    fn begin_storage_open(
        &self,
        database: &'static str,
    ) -> Result<RwLockReadGuard<'_, ()>, AppError> {
        let guard = self
            .storage_lifecycle
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_storage_open(database)?;
        Ok(guard)
    }

    fn account_storage(&self, label: &str) -> Result<SqliteAccountStorage, AppError> {
        self.ensure_storage_open("account storage")?;
        if let Some(storage) = self
            .account_storages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(label)
            .cloned()
        {
            return Ok(storage);
        }
        let _lifecycle = self.begin_storage_open("account storage")?;
        let _span = tracing::debug_span!(
            target: "marmot_app::storage",
            "account_storage_open",
            method = "account_storage"
        )
        .entered();
        let path = self.account_storage_path(label);
        let account = self.account_home().account(label)?;
        let key = if account.local_signing {
            let keys = self.account_home().load_signing_keys(label)?;
            self.sqlcipher_key(label, &keys, &path, SqlcipherDatabaseKind::Session)?
        } else {
            self.external_sqlcipher_key(
                label,
                &account.account_id_hex,
                &path,
                SqlcipherDatabaseKind::Session,
            )?
        };
        let storage = SqliteAccountStorage::open_encrypted(&path, &key)?;
        // Publishing under `_lifecycle` is what keeps this connection reachable
        // by a later `close_storage`; see `begin_storage_open`.
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
        self.record_account_app_event_at(label, message, unix_now_seconds())
    }

    pub(crate) fn record_account_app_event_at(
        &self,
        label: &str,
        message: &AppMessageProjection,
        received_at: u64,
    ) -> Result<AppProjectionUpdate, AppError> {
        let storage_update = self
            .account_storage(label)?
            .record_app_event_with_retention(
                &stored_app_event_from_projection(message, received_at),
                message.retention,
            )?;
        self.app_projection_update(label, storage_update)
    }

    /// As [`Self::record_account_app_event`], but a conflicting row's
    /// `moderation_grant` is replaced rather than frozen. Used by the local
    /// sender's post-publish reconciling projection so a moderation grant
    /// recomputed after group sync supersedes the optimistic pre-send value.
    pub(crate) fn record_account_app_event_refreshing_moderation_grant(
        &self,
        label: &str,
        message: &AppMessageProjection,
    ) -> Result<AppProjectionUpdate, AppError> {
        let now = unix_now_seconds();
        let storage_update = self
            .account_storage(label)?
            .record_app_event_refreshing_moderation_grant_with_retention(
                &stored_app_event_from_projection(message, now),
                message.retention,
            )?;
        self.app_projection_update(label, storage_update)
    }

    pub(crate) fn finalize_account_app_event_source_retention(
        &self,
        label: &str,
        group_id_hex: &str,
        message_id_hex: &str,
        source_message_id_hex: Option<&str>,
        source_epoch: u64,
        retention: AppMessageRetentionDecision,
    ) -> Result<Option<AppProjectionUpdate>, AppError> {
        self.account_storage(label)?
            .finalize_app_event_source_retention(
                group_id_hex,
                message_id_hex,
                source_message_id_hex,
                source_epoch,
                retention,
            )?
            .map(|update| self.app_projection_update(label, update))
            .transpose()
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

    /// Timeline-invalidation dispatch for one engine [`GroupEvent`], shared by
    /// the sync ingest loop and unit-testable without transport plumbing.
    ///
    /// - [`GroupEvent::AppMessageInvalidated`] withdraws the delivered app
    ///   message row addressed by its source message id.
    /// - [`GroupEvent::GroupStateInvalidated`] is the spec's explicit
    ///   state-notification withdrawal (convergence.md "Applying the selected
    ///   branch"): every kind-1210 system row stamped with the superseded
    ///   commit's `origin_commit_id` is invalidated — including rows the
    ///   account's own published-and-confirmed commit synthesized. The engine
    ///   pairs this event with both commit-rollback seams (`ForkRecovered`,
    ///   `CommitRolledBack`), so those commit-level events intentionally do
    ///   NOT dispatch here: one rollback must tombstone once, with one reason.
    ///
    /// Every other event carries no timeline invalidation and returns `None`.
    pub(crate) fn projection_update_for_invalidation_event(
        &self,
        label: &str,
        event: &cgka_traits::engine::GroupEvent,
    ) -> Result<Option<AppProjectionUpdate>, AppError> {
        match event {
            cgka_traits::engine::GroupEvent::AppMessageInvalidated {
                message_id, reason, ..
            } => self.invalidate_timeline_source_message(
                label,
                &hex::encode(message_id.as_slice()),
                &format!("{reason:?}"),
            ),
            cgka_traits::engine::GroupEvent::GroupStateInvalidated {
                invalidated_commit_id,
                reason,
                ..
            } => self.invalidate_timeline_origin_commit(
                label,
                &hex::encode(invalidated_commit_id.as_slice()),
                &format!("{reason:?}"),
            ),
            _ => Ok(None),
        }
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

    pub(crate) fn secure_prune_expired_account_app_events(
        &self,
        label: &str,
        group_id_hex: &str,
        now: u64,
    ) -> Result<SecureDeleteExpiredResult, AppError> {
        let account = self.account_home().account(label)?;
        let classifier = Self::chat_list_mention_classifier(&account.account_id_hex);
        Ok(self
            .account_storage(&account.label)?
            .secure_prune_expired_app_events(
                group_id_hex,
                now,
                &account.account_id_hex,
                &classifier,
            )?
            .into())
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

        // The cached account-storage lookup above releases its open guard before
        // returning. Take a new lifecycle admission across the raw legacy
        // connection and the complete import so `close_storage` cannot latch,
        // release the root lease, and then have this path reopen a database in
        // the supposedly lock-free root.
        let _lifecycle = self.begin_storage_open("legacy account projection")?;
        #[cfg(test)]
        self.run_legacy_projection_open_hook_for_test();
        let legacy = self.legacy_account_projection(label)?;
        let state = legacy.load_state(label)?;
        storage.save_account_projection_state(
            &stored_state_from_account_state(&state),
            MAX_SEEN_EVENT_IDS,
            TRANSPORT_CURSOR_MAX_FUTURE_SKEW.as_secs(),
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

    #[cfg(test)]
    fn set_legacy_projection_open_hook_for_test(&self, hook: LegacyProjectionOpenHook) {
        *self
            .legacy_projection_open_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    #[cfg(test)]
    fn run_legacy_projection_open_hook_for_test(&self) {
        let hook = self
            .legacy_projection_open_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn legacy_account_projection(
        &self,
        label: &str,
    ) -> Result<LegacyAccountProjectionDb, AppError> {
        let path = self.legacy_account_projection_path(label);
        let account = self.account_home().account(label)?;
        let key = if account.local_signing {
            let keys = self.account_home().load_signing_keys(label)?;
            self.sqlcipher_key(
                label,
                &keys,
                &path,
                SqlcipherDatabaseKind::AccountProjection,
            )?
        } else {
            self.external_sqlcipher_key(
                label,
                &account.account_id_hex,
                &path,
                SqlcipherDatabaseKind::AccountProjection,
            )?
        };
        LegacyAccountProjectionDb::open(path, &key)
    }

    fn projection_status(&self, label: &str) -> Result<AppProjectionStatus, AppError> {
        // These probes use short-lived raw SQLite connections rather than the
        // cached handles. Admit the complete probe through the same lifecycle
        // gate so a status call already in flight cannot reopen either database
        // after terminal close has returned.
        let _lifecycle = self.begin_storage_open("projection status")?;
        let account_path = self.account_storage_path(label);
        let shared_path = self.shared_storage_path();
        Ok(AppProjectionStatus {
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
        })
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

    pub(crate) fn shared_storage(&self) -> Result<SqliteSharedStorage, AppError> {
        self.ensure_storage_open("shared storage")?;
        if let Some(storage) = self
            .shared_storage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .cloned()
        {
            return Ok(storage);
        }
        let _lifecycle = self.begin_storage_open("shared storage")?;
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
        signer: Arc<dyn nostr::NostrSigner>,
        endpoints: &[TransportEndpoint],
    ) -> Arc<dyn NostrRelayClient> {
        #[cfg(test)]
        if let Some(client) = &self.test_relay_client {
            return client.clone();
        }
        let _ = endpoints;
        let client = NostrSdkClient::builder().signer(signer).build();
        Arc::new(NostrSdkRelayClient::new(client))
    }

    #[cfg(test)]
    fn with_test_relay_client(mut self, client: Arc<dyn NostrRelayClient>) -> Self {
        self.relay_plane = MarmotRelayPlane::new_with_loopback(
            None,
            client.clone(),
            self.config.allow_loopback_relay_endpoints,
        );
        self.test_relay_client = Some(client);
        self
    }

    pub async fn register_external_signer<S>(
        &self,
        account_ref: &str,
        signer: S,
    ) -> Result<(), AppError>
    where
        S: ExternalAccountSigner + 'static,
    {
        let account = self.account_home().account(account_ref)?;
        if !account.external_signing {
            return Err(AppError::ExternalSignerUnavailable(account.account_id_hex));
        }
        let signer = Arc::new(signer);
        let public_key = signer
            .get_public_key()
            .await
            .map_err(external_signer_public_key_error)?;
        if public_key.to_hex() != account.account_id_hex {
            return Err(AppError::ExternalSignerMismatch);
        }
        self.external_signers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                account.account_id_hex,
                RegisteredExternalSigner::new(public_key, signer),
            );
        Ok(())
    }

    fn account_signer_for_summary(
        &self,
        account: &AccountSummary,
    ) -> Result<AccountSigner, AppError> {
        if account.local_signing {
            return Ok(AccountSigner::Local(
                self.account_home().load_signing_keys(&account.label)?,
            ));
        }
        if account.external_signing {
            return self
                .external_signers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&account.account_id_hex)
                .map(RegisteredExternalSigner::account_signer)
                .ok_or_else(|| {
                    AppError::ExternalSignerUnavailable(account.account_id_hex.clone())
                });
        }
        Err(AccountHomeError::SecretNotFound(account.account_id_hex.clone()).into())
    }

    pub(crate) fn has_external_signer(&self, account_id_hex: &str) -> bool {
        self.external_signers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(account_id_hex)
    }

    fn account_home(&self) -> AccountHome {
        self.account_home.clone()
    }

    fn supported_app_component_ids(&self) -> Vec<u16> {
        let mut components = default_group_components();
        components.insert(GROUP_BLOSSOM_IMAGE_COMPONENT_ID);
        components.insert(NOSTR_ROUTING_COMPONENT_ID);
        components.insert(GROUP_MESSAGE_RETENTION_COMPONENT_ID);
        components.insert(AGENT_TEXT_STREAM_QUIC_COMPONENT_ID);
        components.insert(GROUP_AVATAR_URL_COMPONENT_ID);
        // Existing legacy groups continue to require V1, while fresh
        // current-profile groups require V2. Advertising both is support, not
        // negotiation: each group's required component id selects exactly one.
        components.insert(GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID);
        components.insert(GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID);
        components.into_iter().collect()
    }

    fn key_package_metadata_matches_current_support(
        &self,
        metadata: &cgka_engine::key_package::KeyPackageMetadata,
    ) -> bool {
        metadata.protocol_profile == cgka_traits::group::ProtocolProfile::Current
            && self
                .supported_app_component_ids()
                .iter()
                .all(|component_id| metadata.app_components.contains(component_id))
    }

    fn new_nostr_routing(&self) -> Result<NostrRoutingV1, AppError> {
        let mut nostr_group_id = [0_u8; 32];
        OsRng.fill_bytes(&mut nostr_group_id);
        let relays = self.relay_urls.clone();
        NostrRoutingV1::new(nostr_group_id, relays).map_err(AppError::InvalidNostrRouting)
    }
}

pub(crate) fn external_signer_public_key_error(error: nostr::SignerError) -> AppError {
    external_signer_error(error, "external signer public key")
}

pub(crate) fn external_signer_error(error: nostr::SignerError, context: &str) -> AppError {
    if error.to_string().contains(EXTERNAL_SIGNER_REJECTED) {
        AppError::ExternalSignerRejected
    } else {
        AppError::Publish(format!("{context}: {error}"))
    }
}

/// Recover a cancelled external-signer proof from a session-open failure.
///
/// The account-identity proof is signed synchronously through the external
/// signer while the device session is opened (the engine builds it during
/// `AccountDeviceSession::open`). That signing hook returns `String`, so a
/// user-cancelled Amber prompt travels up as an opaque engine error carrying
/// the `EXTERNAL_SIGNER_REJECTED` sentinel — recover the typed rejection here so
/// callers see `AppError::ExternalSignerRejected` instead of a generic session
/// error, matching `external_signer_error` on the other signer paths.
pub(crate) fn external_signer_session_error(error: cgka_session::SessionError) -> AppError {
    if error.to_string().contains(EXTERNAL_SIGNER_REJECTED) {
        AppError::ExternalSignerRejected
    } else {
        AppError::from(error)
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

    /// Atomically replace every current/prior subscription for one group.
    /// Returns whether the desired route set differs from the installed set.
    fn replace_group_routes(
        &self,
        group_id: &GroupId,
        mut routes: Vec<TransportGroupSubscription>,
    ) -> bool {
        let mut state = self.write();
        let mut existing = state
            .group_routes
            .iter()
            .filter(|route| route.group_id == *group_id)
            .cloned()
            .collect::<Vec<_>>();
        normalize_group_subscriptions(&mut existing);
        normalize_group_subscriptions(&mut routes);
        if existing == routes {
            return false;
        }
        state
            .group_routes
            .retain(|route| route.group_id != *group_id);
        state.group_routes.extend(routes);
        true
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

fn normalize_group_subscriptions(routes: &mut Vec<TransportGroupSubscription>) {
    for route in routes.iter_mut() {
        route.endpoints.sort();
        route.endpoints.dedup();
    }
    routes.sort_by(|left, right| {
        left.transport_group_id
            .cmp(&right.transport_group_id)
            .then_with(|| left.endpoints.cmp(&right.endpoints))
    });
    routes.dedup();
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
    signer: AccountSigner,
}

impl AppKeyPackagePublisher {
    fn nostr_publication(
        &self,
        publication: &KeyPackagePublication,
    ) -> Result<NostrKeyPackagePublication, KeyPackagePublishError> {
        let metadata = key_package_metadata(&publication.key_package)
            .map_err(|e| KeyPackagePublishError::unexposed(e.to_string()))?;
        if metadata.protocol_profile != cgka_traits::group::ProtocolProfile::Current {
            return Err(KeyPackagePublishError::unexposed(
                "strict cutover forbids publishing a legacy KeyPackage",
            ));
        }
        let account_id_hex = hex::encode(publication.account_id.as_slice());
        if metadata.credential_identity_hex != account_id_hex {
            return Err(KeyPackagePublishError::unexposed(
                "KeyPackage credential identity does not match publication account",
            ));
        }
        Ok(NostrKeyPackagePublication {
            account_id: publication.account_id.clone(),
            key_package: publication.key_package.clone(),
            key_package_slot_id: publication.slot_id.clone(),
            key_package_ref: metadata.key_package_ref_hex,
            mls_ciphersuite: format!("0x{:04x}", metadata.ciphersuite),
            mls_extensions: metadata
                .mls_extensions
                .iter()
                .map(|id| format!("0x{id:04x}"))
                .collect(),
            mls_proposals: metadata
                .mls_proposals
                .iter()
                .map(|id| format!("0x{id:04x}"))
                .collect(),
            app_components: metadata
                .app_components
                .iter()
                .filter(|id| {
                    **id >= cgka_traits::app_components::PRIVATE_USE_APP_COMPONENT_ID_START
                })
                .map(|id| format!("0x{id:04x}"))
                .collect(),
            publish_endpoints: publication.endpoints.clone(),
        })
    }
}

#[async_trait]
impl KeyPackagePublisher for AppKeyPackagePublisher {
    fn legacy_slot_id(
        &self,
        account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        self.app
            .reusable_key_package_slot_id(&self.account_label, &hex::encode(account_id.as_slice()))
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))
    }

    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<cgka_traits::SignedPublicationArtifact, KeyPackagePublishError> {
        let nostr_publication = self.nostr_publication(&publication)?;
        let unsigned_dto = nostr_publication
            .to_event_at(publication.created_at.0)
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?;
        let tags = unsigned_dto
            .tags
            .iter()
            .cloned()
            .map(Tag::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?;
        let signer = self.signer.as_nostr_signer();
        let public_key = signer
            .get_public_key()
            .await
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?;
        let unsigned = EventBuilder::new(
            Kind::Custom(KIND_MARMOT_KEY_PACKAGE as u16),
            unsigned_dto.content,
        )
        .tags(tags)
        .custom_created_at(NostrTimestamp::from_secs(publication.created_at.0))
        .build(public_key);
        let signed = signer
            .sign_event(unsigned)
            .await
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?;
        let event = NostrTransportEvent::from_nostr_event(&signed)
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?;
        Ok(cgka_traits::SignedPublicationArtifact {
            id: cgka_traits::MessageId::new(signed.id.to_bytes().to_vec()),
            created_at: publication.created_at,
            bytes: serde_json::to_vec(&event)
                .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?,
        })
    }

    async fn publish_prepared_key_package(
        &self,
        publication: &KeyPackagePublication,
        artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        let nostr_publication = self.nostr_publication(publication)?;
        let event: NostrTransportEvent = serde_json::from_slice(&artifact.bytes)
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?;
        if event.id != hex::encode(artifact.id.as_slice())
            || event.created_at != artifact.created_at.0
        {
            return Err(KeyPackagePublishError::unexposed(
                "persisted KeyPackage event identity does not match lifecycle record",
            ));
        }
        let relay_client = self
            .app
            .relay_client_for_endpoints(self.signer.as_nostr_signer(), &publication.endpoints);
        let outcome = NostrKeyPackagePublisher::new(relay_client)
            .publish_prepared_key_package(&nostr_publication, &event)
            .await
            .map_err(|e| KeyPackagePublishError::exposed(e.to_string()))?;
        let accepted = outcome
            .accepted
            .into_iter()
            .map(|receipt| receipt.endpoint)
            .collect::<Vec<_>>();
        let failed = outcome
            .failed
            .into_iter()
            .map(|failure| failure.endpoint)
            .collect::<Vec<_>>();

        // SQLCipher lifecycle state remains authoritative. This directory row
        // is only a best-effort projection for local invite lookups, which
        // otherwise could reuse a consumed package until the next relay fetch.
        if !accepted.is_empty() {
            let account_id_hex = hex::encode(publication.account_id.as_slice());
            let relay_lists = self
                .app
                .account_relay_list_status_for_account_id(&account_id_hex)
                .unwrap_or_else(|_| AccountRelayListStatus::empty());
            let fetched = FetchedKeyPackage {
                account_id_hex,
                key_package: publication.key_package.clone(),
                key_package_id: publication.slot_id.clone(),
                key_package_ref_hex: nostr_publication.key_package_ref,
                key_package_event_id: hex::encode(artifact.id.as_slice()),
                created_at: artifact.created_at.0,
                source_relays: accepted.iter().map(|endpoint| endpoint.0.clone()).collect(),
                relay_lists,
            };
            if self.app.remember_directory_key_package(&fetched).is_err() {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "publish_prepared_key_package",
                    "acknowledged key package directory projection remains stale"
                );
            }
        }

        Ok(KeyPackagePublishReceipt { accepted, failed })
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

fn empty_key_package_lifecycle(stable_slot_id: String) -> cgka_traits::KeyPackageLifecycleState {
    cgka_traits::KeyPackageLifecycleState::slot_only(stable_slot_id)
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

#[cfg(test)]
fn relays_from_relay_list_event(event: &NostrTransportEvent) -> Vec<String> {
    relay_list_state_from_event(event)
        .map(|state| state.relays)
        .unwrap_or_default()
}

fn relay_list_state_from_event(event: &NostrTransportEvent) -> Option<AccountRelayListState> {
    match event.kind {
        KIND_NIP65_RELAY_LIST => {
            let relay_set = parse_nip65_relay_set(event);
            let read_relays = relay_set
                .read_relays
                .into_iter()
                .map(|endpoint| endpoint.0)
                .collect::<Vec<_>>();
            let write_relays = relay_set
                .write_relays
                .into_iter()
                .map(|endpoint| endpoint.0)
                .collect::<Vec<_>>();
            Some(AccountRelayListState {
                kind: KIND_NIP65_RELAY_LIST,
                relays: write_relays.clone(),
                read_relays,
                write_relays,
            })
        }
        KIND_MARMOT_INBOX_RELAY_LIST => {
            let mut relays = Vec::new();
            for tag in &event.tags {
                if tag.first().is_some_and(|name| name == "relay")
                    && let Some(value) = tag.get(1).filter(|value| !value.trim().is_empty())
                {
                    push_unique_strings(&mut relays, [value.clone()]);
                }
            }
            Some(AccountRelayListState {
                kind: KIND_MARMOT_INBOX_RELAY_LIST,
                relays,
                read_relays: Vec::new(),
                write_relays: Vec::new(),
            })
        }
        _ => None,
    }
}

fn nip65_relay_set_from_state(state: &AccountRelayListState) -> NostrNip65RelaySet {
    if state.read_relays.is_empty() && state.write_relays.is_empty() {
        let legacy_relays = state
            .relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        return NostrNip65RelaySet {
            read_relays: legacy_relays.clone(),
            write_relays: legacy_relays,
        };
    }
    NostrNip65RelaySet {
        read_relays: state
            .read_relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect(),
        write_relays: state
            .write_relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect(),
    }
}

fn nip65_relay_set_preserving_roles(
    current: &AccountRelayListState,
    requested_relays: Vec<TransportEndpoint>,
) -> NostrNip65RelaySet {
    let current = nip65_relay_set_from_state(current);
    let mut next = NostrNip65RelaySet::default();
    for endpoint in unique_transport_endpoints(requested_relays) {
        let was_read = current.read_relays.contains(&endpoint);
        let was_write = current.write_relays.contains(&endpoint);
        if !was_read && !was_write {
            next.read_relays.push(endpoint.clone());
            next.write_relays.push(endpoint);
            continue;
        }
        if was_read {
            next.read_relays.push(endpoint.clone());
        }
        if was_write {
            next.write_relays.push(endpoint);
        }
    }
    next
}

fn unique_transport_endpoints(
    endpoints: impl IntoIterator<Item = TransportEndpoint>,
) -> Vec<TransportEndpoint> {
    let mut unique = Vec::new();
    for endpoint in endpoints {
        if !unique.contains(&endpoint) {
            unique.push(endpoint);
        }
    }
    unique
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

#[cfg(test)]
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
