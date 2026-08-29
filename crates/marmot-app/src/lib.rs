//! First app runtime bridge for Marmot.
//!
//! This crate wires `AccountHome` into the concrete local runtime pieces needed by
//! early app surfaces: encrypted session storage, Nostr MLS peeling, Nostr
//! transport publishing, and relay-backed app projections.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{GroupEvent, KeyPackage};
use cgka_traits::storage::{DisbandTombstoneStorage, KeyPackageBundleStorage, MaintenanceStorage};
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage};
use cgka_traits::{
    GroupId, MemberId, MessageId, TransportEndpoint, TransportGroupSubscription,
    TransportPublishTarget,
};
use marmot_account::{
    AccountDeviceRuntime, AccountHome, AccountHomeError, AccountSetupKind, AccountSetupPhase,
    AccountSummary, DetailedKeyPackagePublishReceipt, KeyPackagePublication,
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
#[cfg(test)]
mod local_open_test_gate;
mod media;
mod messages;
mod nostr_secret;
mod notifications;
mod projection;
mod publisher_sequences;
mod relay_plane;
mod relay_telemetry_export;
#[cfg(test)]
mod removed_local_key_package_tests;
mod root_runtime_lease;
mod runtime;
mod sqlcipher;

use external_signer::{AccountSigner, RegisteredExternalSigner};
pub use external_signer::{EXTERNAL_SIGNER_REJECTED, ExternalAccountSigner};
pub(crate) use groups::AppGroupImageInput;
pub use root_runtime_lease::{MARMOT_ROOT_RUNTIME_LOCK_FILE, MarmotRootRuntimeLease};
pub(crate) use runtime::blocking_app_task;
pub use runtime::{
    AccountManager, AccountSetupReadiness, AccountSetupRequest, AccountSetupResult,
    AgentStreamWatchOptions, AgentTextStreamCryptoContext, CatchUpAccountsSummary,
    ChatListUpdateTrigger, GroupLeaveFailure, LocalCleanupReport, ManagedAccount, MarmotAppEvent,
    MarmotAppRuntime, RelayFailure, RuntimeAccountError, RuntimeAgentStreamMessage,
    RuntimeAgentStreamUpdate, RuntimeAgentStreamWatch, RuntimeChatListSubscription,
    RuntimeChatListUpdate, RuntimeChatsSubscription, RuntimeEventsSubscription, RuntimeGroupEvent,
    RuntimeGroupStateSubscription, RuntimeMessageReceived, RuntimeMessageUpdate,
    RuntimeMessagesSubscription, RuntimeNotificationsSubscription, RuntimeProjectionUpdate,
    RuntimeSharedServices, RuntimeTimelineMessageUpdate, RuntimeTimelineMessagesSubscription,
    SignOutOptions, SignOutOutcome, StreamStartView, TimelineWindowHandle, WipeOutcome,
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
    HostPerformanceOperation, HostPerformanceOutcome, SyncErrorClass, SyncFailureClassification,
    SyncFailureCount, SyncFailureStage,
};
pub use audit_log::{
    AuditLogDeleteOutcome, AuditLogFile, AuditLogSettings, AuditLogTrackerUpdateResult,
    AuditLogUploadResult,
};
pub use client::AppClient;
pub(crate) use client::{
    ConvergenceScheduleState, DeliveryOverflowRecoveryOutcome, EpochBackfillRunOutcome,
};
pub use config::{
    AuditLogTrackerConfig, AuditLogUploadSource, CursorPersistence, MarmotAppConfig,
    MarmotServiceEndpoints, RelayTelemetryExportConfig, RelayTelemetryResource,
    RelayTelemetryRuntimeConfig, RelayTelemetrySettings,
};
pub use directory::{
    CachedIdentityProjection, DirectoryKeyPackage, MAX_CACHED_IDENTITY_PAGE_SIZE, MatchQuality,
    MatchedField, MemberKeyPackagePrewarmSummary, OFF_GRAPH_SEARCH_RADIUS, SearchUpdateTrigger,
    UserDirectoryLocalAccount, UserDirectoryRecord, UserDirectoryRefresh, UserDirectorySearch,
    UserDirectorySearchResult, UserProfileMetadata, UserSearchParams, UserSearchSubscription,
    UserSearchUpdate, sort_user_search_results,
};
pub use drafts::{
    MessageDraft, MessageDraftAttachment, MessageDraftAttachmentSummary, MessageDraftSummary,
};
pub use error::{AccountCatchUpFailure, AppError};
pub use groups::{
    AppAgentTextStreamComponent, AppBlobEndpoint, AppCreateGroupOptions, AppDisbandFailureReason,
    AppDisbandRequest, AppGroupAdminPolicyComponent, AppGroupAvatarUrlComponent,
    AppGroupConversationSnapshot, AppGroupEncryptedMediaComponent,
    AppGroupHydrationQuarantineReason, AppGroupImageComponent, AppGroupLifecycleState,
    AppGroupMemberIds, AppGroupMemberRecord, AppGroupMessageRetentionComponent, AppGroupMlsState,
    AppGroupNostrRoutingComponent, AppGroupOpaqueComponent, AppGroupProfileComponent,
    AppGroupRecord, AppGroupRoster, AppGroupRosterMember, AppGroupSystemEvent,
    AppInitialGroupImage, AppPreparedGroupImageUpload, AppPreparedGroupImageUploadState,
    AppPriorNostrRoute, AppProtocolProfile, AppQuarantinedGroup, MAX_GROUP_MEMBER_IDS_PAGE_SIZE,
    PendingGroupInvite, group_system_event_from_message,
};
pub use ids::{
    account_id_hex_from_ref, nprofile_for_account_id, npub_for_account_id, validate_relay_urls,
};
pub use media::{
    DEFAULT_BLOSSOM_SERVER_URL, DEFAULT_BLOSSOM_SERVER_URLS, ENCRYPTED_MEDIA_VERSION,
    EncryptedMediaVersion, MAX_ENCRYPTED_MEDIA_BLOB_BYTES, MAX_GROUP_IMAGE_BYTES,
    MAX_GROUP_IMAGE_DIMENSION, MAX_GROUP_IMAGE_PIXELS, MediaAttachmentReference,
    MediaDownloadResult, MediaLocator, MediaUploadAttachmentRequest, MediaUploadAttachmentResult,
    MediaUploadRequest, MediaUploadResult, download_profile_image, media_attachment_from_imeta_tag,
};
pub use messages::{is_reserved_app_event_kind, is_stream_final_event, tag_value, tag_values};
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
    ChatListMessagePreview, ChatListQuery, ChatListRow, ExistingDirectConversation,
    MAX_TIMELINE_LIMIT, SelfMembership, TimelineMessageQuery, TimelineMessageRecord, TimelinePage,
    TimelinePagination, TimelineReactionSummary, TimelineReplyPreview, TimelineUserReaction,
    select_reusable_direct_conversation,
};
pub use transport_nostr_adapter::{
    DurationHistogramSnapshot, HistogramBucket, NostrAdapterMetrics, RelayDeliverySpread,
    RelayDeliveryStats, RelayLabelResolution, RelayLatencyStats, RelaySyncSnapshot,
};

/// Canonical group-create result at the host response boundary.
///
/// `chat_list_row` is the exact row committed with the app projection before
/// this value is returned. Hosts can navigate immediately without issuing a
/// read-after-create query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedGroup {
    pub group_id: GroupId,
    pub chat_list_row: ChatListRow,
}

/// Internal outcome used to preserve the legacy create API's post-canonical
/// success contract while the detailed API requires its durable projection.
#[derive(Clone, Debug)]
pub(crate) struct CanonicalCreatedGroup {
    pub group_id: GroupId,
    pub chat_list_row: Option<ChatListRow>,
}

impl CanonicalCreatedGroup {
    pub(crate) fn into_detailed(self) -> Result<CreatedGroup, AppError> {
        let group_id_hex = hex::encode(self.group_id.as_slice());
        let chat_list_row = self
            .chat_list_row
            .ok_or(AppError::CreatedGroupProjectionUnavailable(group_id_hex))?;
        Ok(CreatedGroup {
            group_id: self.group_id,
            chat_list_row,
        })
    }
}

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
use directory::records::display_name_for_profile;
use directory::{DirectoryCache, DirectorySyncHandle};
use ids::parse_account_id_hex;
use key_package_records::{
    account_key_package_record_from_fetched, key_package_from_hex_with_optional_source,
    key_package_from_record, merge_key_package_records, parse_key_package_event_id_hex,
    publish_endpoints_from_bootstrap,
};
#[cfg(test)]
use key_package_records::{fresh_or_cached_key_package, validated_cached_key_package};
use projection::LegacyAccountProjectionDb;
use relay_plane::DirectoryRelayEventRecord as RelayEventRecord;

const LEGACY_ACCOUNT_APP_DB_FILE: &str = "app.sqlite3";
const LEGACY_ACCOUNT_PROJECTION_IMPORT_MARKER: &str = "legacy-account-projection-v1";
/// Once-only marker for the open/upgrade backfill that derives
/// `account_groups.self_membership` from current engine state for rows that
/// predate migration 0018 (where every row defaulted to `'member'`).
const SELF_MEMBERSHIP_BACKFILL_MARKER: &str = "self-membership-backfill-v1";
/// Once-only marker for the open/upgrade backfill that writes
/// `direct_conversation_members` from live rosters for Direct groups that
/// predate migration 0050.
const DIRECT_CONVERSATION_MEMBERS_BACKFILL_MARKER: &str = "direct-conversation-members-backfill-v1";
/// Invalidation reason for a sent app event that will never reach anyone,
/// whether it was refused at send time or its group turned terminal while the
/// engine still held it. The derived-state SQL keys the app-facing `Failed`
/// delivery state off this exact literal, so both producers must share it.
pub(crate) const LOCAL_PUBLISH_FAILED_REASON: &str = "local_publish_failed";
const APP_CACHE_DB_FILE: &str = "app-cache.sqlite3";
const SHARED_DB_FILE: &str = "shared.sqlite3";
const KEY_PACKAGE_CUTOVER_RELAY_SCAN_LIMIT: usize = 1_024;
// Each reported account-runtime pass can perform at most one relay deletion.
// Keep one app cutover invocation bounded even if a relay exposes a long
// parameterized-replaceable history one winner at a time. The durable frontier
// makes the next open/retry resume without losing the post-delete scan proof.
const KEY_PACKAGE_CUTOVER_MAX_DELETION_PASSES: usize = 16;
// A durable history endpoint is retained across route generations so a crash
// cannot forget it after SQL liability pruning. Bound that monotonic set; a
// 257th unique relay is rejected before exact deletion I/O rather than turning
// a privacy journal into unbounded state.
const KEY_PACKAGE_CUTOVER_RELAY_HISTORY_CAPACITY: usize = 256;
const KEY_PACKAGE_REAUTHOR_AT_AGE_SECS: u64 = 10 * 60;
const SESSION_DB_FILE: &str = "session.sqlite";
const KEY_PACKAGE_DIR: &str = "key-packages";
const REMOVED_LOCAL_KEY_PACKAGE_TOMBSTONE_DIR: &str = "removed-local-slots-v1";
const SDK_FIRST_SYNC_WAIT: Duration = Duration::from_millis(750);
const SDK_DRAIN_WAIT: Duration = Duration::from_millis(250);
/// Maximum wall-clock quantum one epoch-gap backfill drain owns the serial
/// account worker before it checkpoints its prefix and yields incomplete.
///
/// The bound is observed between deliveries, where no engine snapshot guard or
/// account-state transaction is live. One already-claimed delivery and the
/// final prefix checkpoint may therefore extend wall-clock time past the
/// quantum, but the relay receive loop itself cannot monopolize the worker.
/// Five seconds leaves headroom inside [`APP_RUNTIME_LOCAL_WORKER_RESPONSE_WAIT`]
/// for that boundary work while still amortizing relay subscription setup over
/// useful replay progress.
pub(crate) const EPOCH_BACKFILL_EXECUTION_QUANTUM: Duration = Duration::from_secs(5);
/// How long the epoch-gap backfill drain waits through *silence* for
/// end-of-stored-events before it gives up and reports an incomplete replay.
///
/// Ordinary sync treats a quiet relay as a finished drain, which is right for a
/// floored subscription that asks for a little and gets it. The backfill's
/// subscription is unfloored, so silence there is ambiguous: it is equally the
/// relay having nothing more to send and the relay still resolving a
/// whole-account history query. Only EOSE separates them, and this is the
/// budget for waiting on it.
///
/// This bounds consecutive silence inside one
/// [`EPOCH_BACKFILL_EXECUTION_QUANTUM`]. Every delivery resets it. Long working
/// replays therefore continue across multiple checkpointed quanta instead of
/// being discarded or holding the worker for their entire wall-clock span.
///
/// Because this budget is only consulted when the receive wait times out, a
/// relay delivering faster than [`SDK_DRAIN_WAIT`] never reaches it; skipped
/// deliveries therefore poll the end-of-stored-events gate directly. The
/// execution quantum independently ends duplicate-only traffic when that gate
/// never arrives.
///
/// 30 s remains the conservative consecutive-silence ceiling, but an open
/// production stream never spends it in one attempt: the 5 s execution quantum
/// yields first and a later seam resubscribes. Production EOSE completion
/// therefore requires the gate to report within that quantum (or before an
/// adapter-closed result). A worker-quantum yield is only a scheduling event:
/// it paces a later resubscription but does not spend the EOSE-failure ordinal.
/// An unavailable required relay leaves the durable intent pending; bounded
/// worker quanta and paced retries preserve availability without weakening the
/// proof that stored history was served.
pub(crate) const EPOCH_BACKFILL_EOSE_WAIT: Duration = Duration::from_secs(30);
/// How long an epoch-gap backfill whose replay went unconfirmed waits before
/// the automatic seams may try it again, doubling per attempt up to
/// [`EPOCH_BACKFILL_RETRY_BACKOFF_CAP`].
///
/// Without pacing, the receive seam runs a pending intent after *every* inbound
/// ingest, so a permanently unconfirmable replay would spend one
/// [`EPOCH_BACKFILL_EXECUTION_QUANTUM`] per delivery. Productive quantum yields
/// are exempt; only an unproductive account-wide replay earns this floor,
/// which matches the maintenance tick cadence.
pub(crate) const EPOCH_BACKFILL_RETRY_BACKOFF: Duration = Duration::from_secs(15);
/// Ceiling on the doubling in [`EPOCH_BACKFILL_RETRY_BACKOFF`]. A relay outage
/// that outlasts this is not going to be resolved by trying harder, and the
/// intent is durable, so a five-minute floor between attempts costs nothing but
/// leaves recovery responsive when the relay returns.
pub(crate) const EPOCH_BACKFILL_RETRY_BACKOFF_CAP: Duration = Duration::from_secs(5 * 60);
const APP_RUNTIME_ACCOUNT_READY_WAIT: Duration = Duration::from_secs(45);
/// Local worker operations include SQLite's bounded busy retry but no relay or
/// blob transfer. A missing response beyond this point indicates a wedged
/// worker, not ordinary storage contention.
const APP_RUNTIME_LOCAL_WORKER_RESPONSE_WAIT: Duration = Duration::from_secs(10);
/// Default deadline for worker commands that may sign, publish, or perform a
/// bounded relay exchange.
const APP_RUNTIME_WORKER_RESPONSE_WAIT: Duration = Duration::from_secs(2 * 60);
/// Media commands have their own 15-minute transfer cap; leave one minute for
/// queueing, projection, and response delivery around that bounded operation.
const APP_RUNTIME_LONG_WORKER_RESPONSE_WAIT: Duration = Duration::from_secs(16 * 60);
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
type CanonicalNip65RouteState = (
    Vec<TransportEndpoint>,
    Vec<TransportEndpoint>,
    Vec<TransportEndpoint>,
);
type KeyPackageDeletionEndpointAliases = (
    Vec<TransportEndpoint>,
    Vec<(TransportEndpoint, TransportEndpoint)>,
);

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
    /// Latched as soon as [`Self::close_storage`] starts. Every database
    /// accessor checks it so a late call cannot silently reopen a database
    /// while terminal close is in progress or after it completes.
    storage_closed: Arc<AtomicBool>,
    /// Published only after every database close has been attempted and the
    /// root lease has been released. This is the host-facing completion fact;
    /// `storage_closed` above is the earlier admission latch.
    storage_close_completed: Arc<AtomicBool>,
    /// Admission control that makes the close *atomic* rather than merely
    /// latched: database opens hold the read side across create-and-publish,
    /// [`Self::close_storage`] holds the write side across its whole teardown.
    /// See [`Self::begin_storage_open`].
    storage_lifecycle: Arc<RwLock<()>>,
    /// Admission for synchronous mutations of AccountHome and other files in
    /// the Marmot root. Terminal close holds the writer through root-lease
    /// release, so detached old-runtime work either commits before ownership
    /// transfers or wakes afterward and observes the closed latch.
    root_mutation_lifecycle: Arc<RwLock<()>>,
    relay_urls: Vec<String>,
    account_home: AccountHome,
    relay_plane: MarmotRelayPlane,
    config: MarmotAppConfig,
    directory_sync: Arc<RwLock<Option<DirectorySyncHandle>>>,
    account_storages: Arc<Mutex<HashMap<String, SqliteAccountStorage>>>,
    /// Session-owned connections are opened independently from
    /// `account_storages`. Retain one close handle per live account session so
    /// terminal close and per-account eviction can make every engine/OpenMLS
    /// clone inert without waiting for an unabortable blocking open to drop.
    account_session_storages: Arc<Mutex<HashMap<String, SqliteAccountStorage>>>,
    account_session_owners: Arc<Mutex<HashSet<String>>>,
    /// Process-local monotonic admission for account sessions. The durable
    /// signed-out bit says whether a new session may be opened; this
    /// generation additionally makes every capability captured before a
    /// sign-out permanently stale, even after an explicit sign-in clears that
    /// reversible bit again.
    account_session_admissions: Arc<Mutex<HashMap<String, AccountSessionAdmissionState>>>,
    next_account_session_admission_generation: Arc<AtomicU64>,
    /// Revocable transport capability for the one live session per account.
    /// Runtime teardown uses this registry to reach standalone public-client
    /// relay planes, not only the managed runtime's shared plane.
    account_session_adapters: Arc<Mutex<HashMap<String, MarmotRelayPlaneAccountAdapter>>>,
    directory_caches: Arc<Mutex<HashMap<String, DirectoryCache>>>,
    /// Bounded, process-local composition prewarm. Entries are never durable
    /// directory admission and never reserve or consume a KeyPackage.
    member_key_package_prewarm_cache: Arc<Mutex<directory::MemberKeyPackagePrewarmCache>>,
    legacy_directory_cache_checked: Arc<Mutex<bool>>,
    #[cfg(test)]
    directory_cache_open_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    directory_handle_acquire_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    local_open_gates: local_open_test_gate::LocalOpenGates,
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
    /// One signer-bound publisher per account. Setup publishes and the managed
    /// account worker share this client so the worker can reuse the same relay
    /// pool instead of constructing another TCP/TLS/WebSocket stack.
    account_publish_clients: Arc<Mutex<HashMap<String, Arc<dyn NostrRelayClient>>>>,
    /// Serialize the authoritative NIP-65 mutation boundary with the final
    /// kind-30443 check and relay send for each account. This closes the gap in
    /// which a route-list event could commit after validation but before the
    /// old-route KeyPackage attempt reached the transport.
    key_package_route_locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// Serialize an exact KeyPackage deletion, its pre-I/O relay-history
    /// frontier, and the strict replay that discharges that frontier with the
    /// final kind-30443 publication boundary. This is deliberately distinct
    /// from `key_package_route_locks`: cutover holds the route lock while it
    /// invokes deletion and would deadlock on recursive acquisition.
    key_package_history_locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// The root-mutation lifecycle is a close-admission read lock, not an
    /// exclusive file-operation lock. Serialize frontier read/modify/write
    /// sequences across app clones so a concurrent endpoint arm cannot be
    /// lost by another clone's completion update.
    key_package_frontier_mutation_lock: Arc<Mutex<()>>,
    /// Serialize immutable removed-local-slot publication with directory
    /// projection writes. A concurrent relay echo therefore either commits
    /// before the tombstone scrub or observes the tombstone and is rejected.
    removed_local_key_package_mutation_lock: Arc<Mutex<()>>,
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

pub(crate) struct GeneratedAccountBootstrapPublication {
    pub status: AccountRelayListStatus,
    pub relay_and_follow_duration: Duration,
    pub default_profile_duration: Duration,
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

/// A sync failure together with the prefix that was already durably applied.
///
/// Catch-up processes deliveries incrementally, so a later transport, engine,
/// or projection error cannot roll back earlier deliveries. Callers of
/// [`AppClient::sync_with_partial_progress`] must report or otherwise consume
/// `partial_summary`; dropping it would hide durable progress until the host
/// takes a fresh storage snapshot. The compatibility [`AppClient::sync`] entry
/// point retains its original [`AppError`] result.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct SyncFailure {
    pub partial_summary: SyncSummary,
    #[source]
    pub source: AppError,
}

impl SyncFailure {
    pub fn new(partial_summary: SyncSummary, source: AppError) -> Self {
        Self {
            partial_summary,
            source,
        }
    }
}

impl From<AppError> for SyncFailure {
    fn from(source: AppError) -> Self {
        Self::new(SyncSummary::default(), source)
    }
}

/// Internal sync failure that retains the bounded telemetry classification.
///
/// The sidecar is deliberately separate from [`SyncFailure`] so the public
/// two-field struct remains constructible by downstream callers.
#[derive(Debug)]
pub(crate) struct ClassifiedSyncFailure {
    pub(crate) partial_summary: SyncSummary,
    pub(crate) source: AppError,
    classification: app_telemetry::SyncFailureClassification,
}

impl ClassifiedSyncFailure {
    pub(crate) fn at_stage(
        partial_summary: SyncSummary,
        source: AppError,
        failure_stage: app_telemetry::SyncFailureStage,
    ) -> Self {
        let error_class = source.sync_error_class();
        Self {
            partial_summary,
            source,
            classification: app_telemetry::SyncFailureClassification::new(
                failure_stage,
                error_class,
            ),
        }
    }

    pub(crate) const fn classification(&self) -> app_telemetry::SyncFailureClassification {
        self.classification
    }
}

impl From<ClassifiedSyncFailure> for SyncFailure {
    fn from(failure: ClassifiedSyncFailure) -> Self {
        Self {
            partial_summary: failure.partial_summary,
            source: failure.source,
        }
    }
}

/// A group that full-history replay is not repairing: it armed `arms` epoch-gap
/// backfills in one run with no sign in between that the device caught up, and
/// it is still sitting at `stalled_epoch`.
///
/// "No sign it caught up" is the honest strength of the claim. The runtime never
/// decrypts the traffic that would reveal a group's live epoch, so it infers the
/// stall from what it can see, and an advance it does not observe reads the same
/// as no advance at all. Surface this as a strong hint, not a verdict.
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
fn remember_seen_event(
    seen: &mut HashSet<String>,
    state: &mut AccountState,
    event_id: String,
) -> bool {
    if seen.insert(event_id.clone()) {
        state.seen_events.push(event_id);
        for pruned in prune_seen_events(&mut state.seen_events) {
            seen.remove(&pruned);
        }
        true
    } else {
        false
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
    /// Restrict to these inner app-event kinds (e.g. an app-defined custom
    /// kind). `None` or an empty list applies no kind constraint.
    pub kinds: Option<Vec<u64>>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendSummary {
    pub published: usize,
    pub message_ids: Vec<String>,
    /// Whether the accepted send reached the transport, is retained in the
    /// group's durable queue, or has unknown transport completion while the
    /// exact event remains frozen. Callers never infer these states from an
    /// empty `message_ids` list (mdk#1177, mdk#1577).
    pub accept_disposition: cgka_traits::SendAcceptDisposition,
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
pub(crate) struct KeyPackageDeletionAdmission {
    pub admitted: Vec<KeyPackageDeletionTarget>,
    pub deferred: Vec<KeyPackageDeletionTarget>,
    /// Safety-rejected exact keys that were journaled but must not reach I/O.
    pub unsafe_targets: Vec<KeyPackageDeletionTarget>,
    /// Malformed target rows that cannot be journaled or sent. They remain
    /// isolated from valid siblings in the same teardown batch.
    pub invalid_targets: Vec<KeyPackageDeletionInvalidTarget>,
}

#[derive(Debug)]
pub(crate) struct KeyPackageDeletionInvalidTarget {
    pub target: KeyPackageDeletionTarget,
    pub reason: String,
}

#[derive(Debug)]
struct CachedKeyPackageRetirementAdmission {
    complete: bool,
    event_id: Option<MessageId>,
}

#[derive(Debug)]
pub(crate) struct KeyPackageDeletionResult {
    pub event_id_hex: String,
    pub accepted_endpoints: Vec<TransportEndpoint>,
    pub confirmed_absent_endpoints: Vec<TransportEndpoint>,
    pub failed_endpoints: Vec<TransportEndpoint>,
    pub result: Result<usize, AppError>,
}

fn canonicalize_key_package_fanout_targets<F>(
    targets: &mut Vec<cgka_traits::TransportFanoutTarget>,
    mut canonicalize: F,
) -> bool
where
    F: FnMut(&TransportEndpoint) -> Option<TransportEndpoint>,
{
    let before = targets.clone();
    for target in targets.iter_mut() {
        if let Some(canonical) = canonicalize(&target.endpoint) {
            target.endpoint = canonical;
        }
    }
    targets.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
    let mut merged = Vec::<cgka_traits::TransportFanoutTarget>::with_capacity(targets.len());
    for candidate in std::mem::take(targets) {
        if let Some(existing) = merged
            .last_mut()
            .filter(|existing| existing.endpoint == candidate.endpoint)
        {
            merge_key_package_fanout_target_evidence(existing, candidate);
        } else {
            merged.push(candidate);
        }
    }
    *targets = merged;
    *targets != before
}

fn key_package_lifecycle_endpoint_liability_count(
    lifecycle: &cgka_traits::KeyPackageLifecycleState,
) -> usize {
    let mut liabilities = HashSet::<(Vec<u8>, TransportEndpoint)>::new();
    let mut include = |event_id: &MessageId, targets: &[cgka_traits::TransportFanoutTarget]| {
        for target in targets {
            if target.failure_code.as_deref() != Some("confirmed_absent") {
                liabilities.insert((event_id.as_slice().to_vec(), target.endpoint.clone()));
            }
        }
    };
    if let Some(event_id) = lifecycle
        .authored_signed_event
        .as_ref()
        .map(|artifact| &artifact.id)
        .or(lifecycle.authored_event_id.as_ref())
    {
        include(event_id, &lifecycle.publication_targets);
    }
    if let Some(pending) = lifecycle.pending_replacement.as_ref()
        && let Some(artifact) = pending.signed_event.as_ref()
    {
        include(&artifact.id, &pending.targets);
    }
    for retired in &lifecycle.retired_publications_pending_deletion {
        include(&retired.event_id, &retired.deletion_targets);
    }
    liabilities.len()
}

fn retain_imported_legacy_key_package_publication(
    lifecycle: &mut cgka_traits::KeyPackageLifecycleState,
    imported: cgka_traits::RetiredKeyPackagePublication,
) {
    if let Some(existing) = lifecycle
        .retired_publications_pending_deletion
        .iter_mut()
        .find(|existing| existing.event_id == imported.event_id)
    {
        existing.authored_created_at = existing
            .authored_created_at
            .max(imported.authored_created_at);
        if existing.key_package_ref.is_none() {
            existing.key_package_ref = imported.key_package_ref;
        }
        if existing.package_not_after.is_none() {
            existing.package_not_after = imported.package_not_after;
        }
        existing.delete_without_successor |= imported.delete_without_successor;
        for target in imported.deletion_targets {
            if !existing
                .deletion_targets
                .iter()
                .any(|candidate| candidate.endpoint == target.endpoint)
            {
                existing.deletion_targets.push(target);
            }
        }
        existing
            .deletion_targets
            .sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
        return;
    }

    lifecycle
        .retired_publications_pending_deletion
        .push(imported);
    lifecycle
        .retired_publications_pending_deletion
        .sort_by(|left, right| {
            left.authored_created_at
                .cmp(&right.authored_created_at)
                .then_with(|| left.event_id.as_slice().cmp(right.event_id.as_slice()))
        });
}

fn merge_key_package_fanout_target_evidence(
    existing: &mut cgka_traits::TransportFanoutTarget,
    candidate: cgka_traits::TransportFanoutTarget,
) {
    use cgka_traits::TransportFanoutAttemptState;

    let confirmed_absent = existing.failure_code.as_deref() == Some("confirmed_absent")
        || candidate.failure_code.as_deref() == Some("confirmed_absent");
    let accepted = existing.state == TransportFanoutAttemptState::Accepted
        || candidate.state == TransportFanoutAttemptState::Accepted;
    let existing_policy_prohibited =
        existing.state == TransportFanoutAttemptState::PolicyProhibited;
    let candidate_policy_prohibited =
        candidate.state == TransportFanoutAttemptState::PolicyProhibited;
    let all_policy_prohibited = existing_policy_prohibited && candidate_policy_prohibited;
    let attempted = existing.attempt_count > 0
        || candidate.attempt_count > 0
        || existing.last_attempt_at.is_some()
        || candidate.last_attempt_at.is_some()
        || existing.state == TransportFanoutAttemptState::AttemptedFailed
        || candidate.state == TransportFanoutAttemptState::AttemptedFailed;
    let policy_failure = existing
        .failure_code
        .clone()
        .or(candidate.failure_code.clone());

    existing.attempt_count = existing.attempt_count.max(candidate.attempt_count);
    existing.last_attempt_at = match (existing.last_attempt_at, candidate.last_attempt_at) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (left, right) => left.or(right),
    };
    if confirmed_absent {
        existing.state = TransportFanoutAttemptState::AttemptedFailed;
        existing.failure_code = Some("confirmed_absent".into());
    } else if accepted {
        existing.state = TransportFanoutAttemptState::Accepted;
        existing.failure_code = None;
    } else if all_policy_prohibited {
        existing.state = TransportFanoutAttemptState::PolicyProhibited;
        existing.failure_code =
            policy_failure.or_else(|| Some("endpoint_removed_from_policy".into()));
    } else if attempted {
        existing.state = TransportFanoutAttemptState::AttemptedFailed;
        existing.failure_code = Some("possible_exposure".into());
    } else {
        existing.state = TransportFanoutAttemptState::Unattempted;
        existing.failure_code = None;
    }
}

/// Per-account unread aggregate, suitable for an account-switcher and
/// application badge (mdk#461, mdk#1460). Computed from each account's
/// materialized chat-list projection without loading a full session/timeline,
/// so it can be reported for accounts that are not the active/running one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountUnread {
    pub account_id_hex: String,
    /// Total unread messages across all unarchived conversations.
    pub unread_count: u64,
    /// Number of unarchived conversations that require badge attention:
    /// unread messages, a manual-unread reminder, or a pending invitation.
    pub unread_conversations: u64,
    /// Conversations that contribute badge attention solely because they are
    /// manually marked unread or pending confirmation. A row that already has
    /// unread messages is omitted so hosts can compute
    /// `unread_count + attention_only_conversations` without overlap.
    #[serde(default)]
    pub attention_only_conversations: u64,
    /// Whether the account has any badge-worthy conversation, including a
    /// manual-only reminder or pending invitation with no unread messages.
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RemovedLocalKeyPackageTombstone {
    account_id_hex: String,
    /// `None` is the explicit legacy fail-closed fallback used only when the
    /// removed account's durable NIP-33 slot can no longer be proven.
    stable_slot_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RemovedLocalKeyPackageScope {
    StableSlot(String),
    AccountWideLegacy,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct KeyPackageCutoverScanMarker {
    /// `false` for markers authored by the pre-peeling implementation. Those
    /// markers proved only one visible NIP-33 winner per relay and must never
    /// authorize publication after this upgrade.
    #[serde(default)]
    strict_history_peeling: bool,
    #[serde(default)]
    fresh_account_proof: bool,
    #[serde(default)]
    authoritative_relays: Vec<String>,
    /// Every durable current/pending/retired publication endpoint covered by
    /// the strict scan, including relays no longer present in NIP-65.
    #[serde(default)]
    history_relays: Vec<String>,
    /// NIP-33 ordering coordinate of the self-authored kind-10002 projection
    /// whose write-relay set was scanned. URL equality alone is insufficient:
    /// a B -> A -> B route cycle may expose a new same-slot KeyPackage on B.
    #[serde(default)]
    route_created_at: Option<u64>,
    #[serde(default)]
    route_event_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct KeyPackageCutoverRelayFrontier {
    #[serde(default)]
    relays: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default)]
struct KeyPackageRelayAdmissionSummary {
    non_current_event_count: usize,
    discovered_current_revision_count: usize,
    deferred_endpoint_count: usize,
    admission_failure_count: usize,
}

impl KeyPackageRelayAdmissionSummary {
    fn absorb(&mut self, other: Self) {
        self.non_current_event_count = self
            .non_current_event_count
            .saturating_add(other.non_current_event_count);
        self.discovered_current_revision_count = self
            .discovered_current_revision_count
            .saturating_add(other.discovered_current_revision_count);
        self.deferred_endpoint_count = self
            .deferred_endpoint_count
            .saturating_add(other.deferred_endpoint_count);
        self.admission_failure_count = self
            .admission_failure_count
            .saturating_add(other.admission_failure_count);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Nip65RouteGeneration {
    created_at: u64,
    event_id: String,
    /// Exact parsed write-relay authority from the same verified kind-10002
    /// event. Directory cache rows remain projections and must never select a
    /// different route merely because they carry a newer profile or
    /// KeyPackage timestamp.
    nip65: AccountRelayListState,
}

#[derive(Clone, Debug)]
pub(crate) struct GeneratedNip65RouteAuthorityProof {
    generation: Nip65RouteGeneration,
    endpoints: Vec<TransportEndpoint>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Nip65RouteMutationSource {
    /// Includes every pre-field journal and every ordinary route edit. Keeping
    /// this as the serde default makes old intents retain the strict gate.
    #[default]
    AccountMutation,
    /// The first route declaration authored by a durably journaled generated
    /// identity before any KeyPackage publication could have completed.
    GeneratedAccountBootstrap,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingNip65RouteMutation {
    account_id_hex: String,
    nip65: AccountRelayListState,
    #[serde(default)]
    bootstrap_relays: Vec<String>,
    #[serde(default)]
    publish_endpoints: Vec<String>,
    /// Exact signed local event. Relay-observed mutations are already accepted
    /// and can recover from their proposed state plus ordering coordinate.
    #[serde(default)]
    signed_event: Option<NostrTransportEvent>,
    generation: Nip65RouteGeneration,
    #[serde(default)]
    network_accepted: bool,
    #[serde(default)]
    source: Nip65RouteMutationSource,
}

struct OpenAppAccount {
    runtime: AppRuntime,
    session_guard: AppAccountSessionGuard,
    session_admission: AccountSessionAdmission,
    adapter: MarmotRelayPlaneAccountAdapter,
    routing: AppTransportRouting,
    state: AccountState,
    delivery_overflow_recovery_pending: bool,
    delivery_overflow_recovery_marker_token: Option<u64>,
    signer: Arc<dyn nostr::NostrSigner>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountSessionAdmissionToken {
    account_id_hex: String,
    generation: u64,
}

/// Exact capability required by the lowest account relay-list signing and
/// publication boundary. Ordinary edits carry the live account-session
/// generation; setup publication carries its separately revocable setup
/// generation. There is deliberately no capability-free variant.
#[derive(Clone, Copy)]
enum AccountRelayListMutationAdmission<'a> {
    Active(&'a AccountSessionAdmissionToken),
    Setup(&'a runtime::AccountSetupPublicationAdmission),
}

/// Exact, process-local capability for the cleanup phase of one account
/// teardown. It is valid only while ordinary admission remains closed at the
/// generation against which it was minted, and the teardown barrier revokes
/// it on every exit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountTeardownSessionAdmissionToken {
    account_id_hex: String,
    closed_generation: u64,
    generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AccountSessionAdmission {
    Active(AccountSessionAdmissionToken),
    Teardown(AccountTeardownSessionAdmissionToken),
}

#[derive(Clone, Debug)]
struct AccountSessionAdmissionState {
    account_id_hex: String,
    generation: u64,
    open: bool,
    teardown_generation: Option<u64>,
}

/// Keeps runtime account-open admission live while a completed blocking open
/// is waiting to be consumed by its async caller. A cancelled `spawn_blocking`
/// waiter cannot cancel the blocking work, so dropping the permit inside the
/// closure would let shutdown report the open drained while `OpenAppAccount`
/// was still retained in the task's result slot.
struct OpenAppAccountResult {
    open: OpenAppAccount,
    _permit: Option<runtime::RuntimeAccountOpenPermit>,
}

struct AppAccountSessionGuard {
    label: String,
    owners: Arc<Mutex<HashSet<String>>>,
    storages: Arc<Mutex<HashMap<String, SqliteAccountStorage>>>,
    adapters: Arc<Mutex<HashMap<String, MarmotRelayPlaneAccountAdapter>>>,
}

impl Drop for AppAccountSessionGuard {
    fn drop(&mut self) {
        // Keep ownership admission closed until this session's registered
        // connection is removed and closed. Releasing `owners` first would let
        // a replacement session register under the same label, which this
        // guard could then accidentally remove as if it were the old handle.
        let mut owners = self
            .owners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut storages = self
            .storages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(storage) = storages.remove(&self.label)
            && let Err(error) = storage.close()
        {
            tracing::warn!(
                target: "marmot_app::storage",
                method = "drop_account_session_guard",
                error_kind = AppError::from(error).privacy_safe_kind(),
                "failed to close released account session storage",
            );
        }
        drop(storages);
        self.adapters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.label);
        owners.remove(&self.label);
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
            storage_close_completed: Arc::new(AtomicBool::new(false)),
            storage_lifecycle: Arc::new(RwLock::new(())),
            root_mutation_lifecycle: Arc::new(RwLock::new(())),
            relay_urls,
            relay_plane,
            config,
            directory_sync: Arc::new(RwLock::new(None)),
            account_storages: Arc::new(Mutex::new(HashMap::new())),
            account_session_storages: Arc::new(Mutex::new(HashMap::new())),
            account_session_owners: Arc::new(Mutex::new(HashSet::new())),
            account_session_admissions: Arc::new(Mutex::new(HashMap::new())),
            next_account_session_admission_generation: Arc::new(AtomicU64::new(0)),
            account_session_adapters: Arc::new(Mutex::new(HashMap::new())),
            directory_caches: Arc::new(Mutex::new(HashMap::new())),
            member_key_package_prewarm_cache: Arc::new(Mutex::new(
                directory::MemberKeyPackagePrewarmCache::default(),
            )),
            legacy_directory_cache_checked: Arc::new(Mutex::new(false)),
            #[cfg(test)]
            directory_cache_open_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            directory_handle_acquire_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            local_open_gates: local_open_test_gate::LocalOpenGates::default(),
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
            account_publish_clients: Arc::new(Mutex::new(HashMap::new())),
            key_package_route_locks: Arc::new(Mutex::new(HashMap::new())),
            key_package_history_locks: Arc::new(Mutex::new(HashMap::new())),
            key_package_frontier_mutation_lock: Arc::new(Mutex::new(())),
            removed_local_key_package_mutation_lock: Arc::new(Mutex::new(())),
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
            storage_close_completed: Arc::new(AtomicBool::new(false)),
            storage_lifecycle: Arc::new(RwLock::new(())),
            root_mutation_lifecycle: Arc::new(RwLock::new(())),
            relay_urls,
            account_home,
            relay_plane,
            config,
            directory_sync: Arc::new(RwLock::new(None)),
            account_storages: Arc::new(Mutex::new(HashMap::new())),
            account_session_storages: Arc::new(Mutex::new(HashMap::new())),
            account_session_owners: Arc::new(Mutex::new(HashSet::new())),
            account_session_admissions: Arc::new(Mutex::new(HashMap::new())),
            next_account_session_admission_generation: Arc::new(AtomicU64::new(0)),
            account_session_adapters: Arc::new(Mutex::new(HashMap::new())),
            directory_caches: Arc::new(Mutex::new(HashMap::new())),
            member_key_package_prewarm_cache: Arc::new(Mutex::new(
                directory::MemberKeyPackagePrewarmCache::default(),
            )),
            legacy_directory_cache_checked: Arc::new(Mutex::new(false)),
            #[cfg(test)]
            directory_cache_open_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            directory_handle_acquire_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            local_open_gates: local_open_test_gate::LocalOpenGates::default(),
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
            account_publish_clients: Arc::new(Mutex::new(HashMap::new())),
            key_package_route_locks: Arc::new(Mutex::new(HashMap::new())),
            key_package_history_locks: Arc::new(Mutex::new(HashMap::new())),
            key_package_frontier_mutation_lock: Arc::new(Mutex::new(())),
            removed_local_key_package_mutation_lock: Arc::new(Mutex::new(())),
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

    #[cfg(test)]
    pub(crate) fn install_local_open_gate(
        &self,
        account_ref: &str,
        reached: std::sync::mpsc::Sender<()>,
        proceed: std::sync::mpsc::Receiver<()>,
    ) -> Result<(), AppError> {
        let label = self.account_home().account(account_ref)?.label;
        self.local_open_gates.install(label, reached, proceed);
        Ok(())
    }

    fn next_account_session_admission_generation(&self) -> Result<u64, AppError> {
        self.next_account_session_admission_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .map(|generation| generation + 1)
            .map_err(|_| {
                AppError::BlockingTask("account session admission generation exhausted".into())
            })
    }

    /// Capture the exact process-local account-session generation before any
    /// unabortable database open begins. A teardown closes and advances this
    /// state synchronously, so an open that completes late can never become
    /// valid again merely because a later sign-in clears the durable marker.
    fn capture_account_session_admission(
        &self,
        label: &str,
        account_id_hex: &str,
    ) -> Result<AccountSessionAdmissionToken, AppError> {
        let mut admissions = self
            .account_session_admissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(admission) = admissions.get(label)
            && admission.account_id_hex == account_id_hex
        {
            if !admission.open {
                return Err(AppError::AccountWorkerBusy);
            }
            return Ok(AccountSessionAdmissionToken {
                account_id_hex: account_id_hex.to_owned(),
                generation: admission.generation,
            });
        }

        // A missing entry is the first open in this process. A changed account
        // id is a same-label replacement: allocate a fresh generation so a
        // capability from the removed identity cannot follow the label.
        let generation = self.next_account_session_admission_generation()?;
        admissions.insert(
            label.to_owned(),
            AccountSessionAdmissionState {
                account_id_hex: account_id_hex.to_owned(),
                generation,
                open: true,
                teardown_generation: None,
            },
        );
        Ok(AccountSessionAdmissionToken {
            account_id_hex: account_id_hex.to_owned(),
            generation,
        })
    }

    /// Explicitly open a new generation after an authorized signed-out to
    /// active transition. This always advances, even when the previous state
    /// was already closed, so no pre-sign-out token can suffer an ABA.
    pub(crate) fn open_account_session_admission(
        &self,
        label: &str,
        account_id_hex: &str,
    ) -> Result<AccountSessionAdmissionToken, AppError> {
        let mut admissions = self
            .account_session_admissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let generation = self.next_account_session_admission_generation()?;
        admissions.insert(
            label.to_owned(),
            AccountSessionAdmissionState {
                account_id_hex: account_id_hex.to_owned(),
                generation,
                open: true,
                teardown_generation: None,
            },
        );
        Ok(AccountSessionAdmissionToken {
            account_id_hex: account_id_hex.to_owned(),
            generation,
        })
    }

    /// Revoke every capability captured for this label before returning. At
    /// generation exhaustion the gate still becomes permanently closed: the
    /// `open` bit is part of validation, while no later open can allocate a
    /// generation that aliases the revoked token.
    pub(crate) fn close_account_session_admission(&self, label: &str, account_id_hex: &str) {
        let mut admissions = self
            .account_session_admissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let generation = self
            .next_account_session_admission_generation()
            .unwrap_or(u64::MAX);
        admissions.insert(
            label.to_owned(),
            AccountSessionAdmissionState {
                account_id_hex: account_id_hex.to_owned(),
                generation,
                open: false,
                teardown_generation: None,
            },
        );
    }

    /// Mint the only session capability accepted while ordinary account
    /// admission is closed. The caller must already own the account teardown
    /// barrier; validation ties the capability to the exact closed generation
    /// so sign-in, another teardown, or same-label replacement revokes it.
    pub(crate) fn open_account_teardown_session_admission(
        &self,
        label: &str,
        account_id_hex: &str,
    ) -> Result<AccountTeardownSessionAdmissionToken, AppError> {
        let mut admissions = self
            .account_session_admissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let admission = admissions
            .get_mut(label)
            .filter(|admission| admission.account_id_hex == account_id_hex && !admission.open)
            .ok_or(AppError::AccountWorkerBusy)?;
        let generation = self.next_account_session_admission_generation()?;
        admission.teardown_generation = Some(generation);
        Ok(AccountTeardownSessionAdmissionToken {
            account_id_hex: account_id_hex.to_owned(),
            closed_generation: admission.generation,
            generation,
        })
    }

    pub(crate) fn close_account_teardown_session_admission(
        &self,
        label: &str,
        token: &AccountTeardownSessionAdmissionToken,
    ) {
        let mut admissions = self
            .account_session_admissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(admission) = admissions.get_mut(label)
            && !admission.open
            && admission.account_id_hex == token.account_id_hex
            && admission.generation == token.closed_generation
            && admission.teardown_generation == Some(token.generation)
        {
            admission.teardown_generation = None;
        }
    }

    pub(crate) fn account_teardown_session_admission_is_current(
        &self,
        label: &str,
        token: &AccountTeardownSessionAdmissionToken,
    ) -> bool {
        self.account_session_admissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(label)
            .is_some_and(|admission| {
                !admission.open
                    && admission.account_id_hex == token.account_id_hex
                    && admission.generation == token.closed_generation
                    && admission.teardown_generation == Some(token.generation)
            })
    }

    pub(crate) fn account_session_admission_is_current(
        &self,
        label: &str,
        token: &AccountSessionAdmissionToken,
    ) -> bool {
        self.account_session_admissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(label)
            .is_some_and(|admission| {
                admission.open
                    && admission.account_id_hex == token.account_id_hex
                    && admission.generation == token.generation
            })
    }

    pub(crate) fn active_account_session_admission_is_current(
        &self,
        label: &str,
        token: &AccountSessionAdmissionToken,
    ) -> bool {
        self.account_home().account(label).is_ok_and(|account| {
            account.is_active_signing() && account.account_id_hex == token.account_id_hex
        }) && self.account_session_admission_is_current(label, token)
    }

    pub(crate) fn account_session_admission_is_open(
        &self,
        label: &str,
        account_id_hex: &str,
    ) -> bool {
        self.account_session_admissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(label)
            .is_none_or(|admission| admission.account_id_hex != account_id_hex || admission.open)
    }

    fn account_open_admission_is_current(
        &self,
        label: &str,
        admission: &AccountSessionAdmission,
    ) -> bool {
        match admission {
            AccountSessionAdmission::Active(token) => {
                self.account_session_admission_is_current(label, token)
            }
            AccountSessionAdmission::Teardown(token) => {
                self.account_teardown_session_admission_is_current(label, token)
            }
        }
    }

    /// Open the account's exclusive in-memory engine session.
    ///
    /// Only one [`AppClient`] for an account may exist within a [`MarmotApp`]
    /// (including its clones and managed runtime workers). A concurrent open
    /// returns [`AppError::AccountSessionBusy`]. Drop the owning client before
    /// retrying.
    pub async fn client(&self, label: &str) -> Result<AppClient, AppError> {
        let account = self.account_home().account(label)?;
        if !account.is_active_signing() {
            return Err(AppError::Publish(
                "cannot open a direct client for a signed-out or non-signing account".into(),
            ));
        }
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
        let mut client = self
            .local_client_with_relay_plane(label, &relay_plane, None)
            .await?;
        // An unabortable blocking open may finish after concurrent sign-out.
        // Re-prove the exact record before transport activation; if teardown
        // already found this session in the registry, its revoked adapter also
        // makes activation fail closed.
        client.ensure_active_signing_account()?;
        client.prepare_transport().await?;
        client.ensure_active_signing_account()?;
        self.finish_client_open_network_maintenance(&mut client)
            .await;
        client.ensure_active_signing_account()?;
        Ok(client)
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

    #[cfg(test)]
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
        // Resolve every supported account ref before touching label-keyed
        // caches or the session-owner registry.
        let account = self.account_home().account(label)?;
        if !account.is_active_signing() {
            return Err(AppError::Publish(
                "cannot open a client for a signed-out or non-signing account".into(),
            ));
        }
        let label = account.label;
        let account_id_hex = account.account_id_hex.clone();
        let session_admission = AccountSessionAdmission::Active(
            self.capture_account_session_admission(&label, &account_id_hex)?,
        );
        self.local_client_with_admission(
            label,
            account_id_hex,
            relay_plane,
            lifecycle,
            defer_group_hydration,
            session_admission,
        )
        .await
    }

    /// Open one exact teardown-owned session without reopening ordinary
    /// account admission. This path is crate-private, consumes a capability
    /// owned by the live teardown barrier, and constructs a publisher that is
    /// categorically unable to emit a KeyPackage.
    pub(crate) async fn local_teardown_cleanup_client_with_relay_plane(
        &self,
        label: &str,
        account_id_hex: &str,
        relay_plane: &MarmotRelayPlane,
        admission: &AccountTeardownSessionAdmissionToken,
    ) -> Result<AppClient, AppError> {
        let account = self.account_home().account(label)?;
        if !account.signed_out
            || !account.can_sign()
            || account.account_id_hex != account_id_hex
            || admission.account_id_hex != account_id_hex
            || !self.account_teardown_session_admission_is_current(&account.label, admission)
        {
            return Err(AppError::AccountWorkerBusy);
        }
        self.local_client_with_admission(
            account.label,
            account.account_id_hex,
            relay_plane,
            None,
            false,
            AccountSessionAdmission::Teardown(admission.clone()),
        )
        .await
    }

    async fn local_client_with_admission(
        &self,
        label: String,
        account_id_hex: String,
        relay_plane: &MarmotRelayPlane,
        lifecycle: Option<runtime::RuntimeLifecycle>,
        defer_group_hydration: bool,
        session_admission: AccountSessionAdmission,
    ) -> Result<AppClient, AppError> {
        let app = self.clone();
        let label_for_open = label.clone();
        let relay_plane_for_open = relay_plane.clone();
        let permit = lifecycle
            .as_ref()
            .map(runtime::RuntimeLifecycle::begin_account_open)
            .transpose()?;
        let open_result = blocking_app_task(move || {
            app.ensure_account_state(&label_for_open)?;
            let open = app.open_account_with_admission(
                &label_for_open,
                &relay_plane_for_open,
                defer_group_hydration,
                session_admission,
            );
            #[cfg(test)]
            app.local_open_gates.wait(&label_for_open);
            open.map(|open| OpenAppAccountResult {
                open,
                _permit: permit,
            })
        })
        .await?;
        if let Some(lifecycle) = &lifecycle {
            lifecycle.ensure_running()?;
        }
        let OpenAppAccountResult {
            open,
            _permit: open_permit,
        } = open_result;
        if !self.account_open_admission_is_current(&label, &open.session_admission) {
            return Err(AppError::AccountWorkerBusy);
        }
        let seen_events_index = open
            .state
            .seen_events
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let checkpointed_transport_timestamp = open.state.last_transport_timestamp;
        // The wedge clock is the one detector threshold a test has to be able
        // to shorten: its production value is an hour, and reading a clock
        // inside the detector instead would cost the I/O-freedom the policy
        // module is built on.
        let wedge_rearm_interval_ms = if cfg!(feature = "test-policy-overrides")
            && let Some(ms) = self.config.dev_epoch_stall_wedge_rearm_interval_ms
        {
            ms
        } else {
            crate::client::epoch_stall::EPOCH_STALL_WEDGE_REARM_INTERVAL_MS
        };
        let mut client = AppClient {
            app: self.clone(),
            runtime: open.runtime,
            account_id_hex,
            session_admission: open.session_admission,
            _session_guard: open.session_guard,
            adapter: open.adapter,
            routing: open.routing,
            relay_plane: relay_plane.clone(),
            transport_signer: open.signer,
            state: open.state,
            seen_events_index,
            pending_seen_event_count: 0,
            pending_group_projection_updates: std::collections::HashSet::new(),
            pending_projection_updates: Vec::new(),
            pending_applied_sync_summary: SyncSummary::default(),
            pending_uncheckpointed_sync_summary: None,
            pending_checkpointed_sync_summary: None,
            pending_epoch_stall_escalations: Vec::new(),
            pending_convergence_groups: std::collections::HashSet::new(),
            pending_local_group_deletion_frontier_clears: std::collections::HashMap::new(),
            pending_application_event_acks: std::collections::HashSet::new(),
            pending_account_visibility_lease: None,
            pending_uncheckpointed_runtime_group_subscription_refresh: false,
            pending_runtime_group_subscription_refresh: false,
            checkpointed_transport_timestamp,
            delivery_overflow_recovery_pending: open.delivery_overflow_recovery_pending,
            delivery_overflow_recovery_marker_token: open.delivery_overflow_recovery_marker_token,
            pending_new_message_notification_groups: std::collections::HashSet::new(),
            #[cfg(test)]
            force_event_group_projection_unavailable: false,
            #[cfg(test)]
            block_after_sync_delivery_projection: None,
            #[cfg(test)]
            block_after_sync_prefix_checkpoint: None,
            #[cfg(test)]
            fail_after_convergence_retry_finalize: false,
            pending_welcome_delivery_events: Vec::new(),
            unpublished_welcome_delivery: None,
            epoch_stall: crate::client::epoch_stall::EpochStallDetector::default()
                .with_wedge_rearm_interval_ms(wedge_rearm_interval_ms),
            epoch_backfill_retry_not_before: None,
            pending_epoch_backfill: None,
            active_epoch_backfill: None,
            epoch_backfill_intent_journal_dirty: false,
            queued_epoch_backfills: std::collections::VecDeque::new(),
            post_join_maintenance_subscriptions: HashMap::new(),
            encrypted_media_not_required_epochs: HashMap::new(),
            checkpoint_route_refresh_recomputes: 0,
        };
        client.ensure_session_account()?;
        client.restore_epoch_backfill_intent_journal()?;
        let persisted_backfills = self.pending_epoch_backfill_intents(&client.state.label)?;
        client.restore_persisted_epoch_backfill_intents(persisted_backfills);
        let persisted_evidence = self.epoch_stall_evidence(&client.state.label)?;
        client.restore_persisted_epoch_stall_evidence(persisted_evidence);
        if !defer_group_hydration {
            // These repairs read live group state. Deferred runtime opens run
            // them after the account worker's hydration pipeline instead.
            client.reconcile_hydrated_account_state()?;
            client.replay_pending_account_visibility().await?;
        }
        // The open is now fully represented by `client`; shutdown may stop
        // counting the blocking handoff without waiting for the client's whole
        // lifetime.
        drop(open_permit);
        Ok(client)
    }

    async fn finish_client_open_network_maintenance(&self, client: &mut AppClient) {
        let cutover_app = client.app.clone();
        let cutover_label = client.state.label.clone();
        match cutover_app.generated_initial_key_package_publication_held(&cutover_label) {
            Ok(true) => {
                let _ = client
                    .runtime
                    .set_key_package_cutover_publication_blocked(true);
                return;
            }
            Err(error) => {
                let _ = client
                    .runtime
                    .set_key_package_cutover_publication_blocked(true);
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "finish_client_open_network_maintenance",
                    error_kind = error.privacy_safe_kind(),
                    "could not validate the generated initial KeyPackage publication hold"
                );
                return;
            }
            Ok(false) => {}
        }
        let cutover_route_lock = cutover_app.key_package_route_lock(&cutover_label);
        let cutover_route_guard = cutover_route_lock.lock().await;
        if let Err(error) = cutover_app
            .recover_pending_nip65_route_mutation(&cutover_label, client.transport_signer.clone())
            .await
        {
            let _ = client
                .runtime
                .set_key_package_cutover_publication_blocked(true);
            tracing::warn!(
                target: "marmot_app::key_packages",
                method = "finish_client_open_network_maintenance",
                error_kind = error.privacy_safe_kind(),
                "could not recover a pending authoritative NIP-65 route mutation"
            );
            return;
        }
        if let Err(error) = client.refresh_routing() {
            let _ = client
                .runtime
                .set_key_package_cutover_publication_blocked(true);
            tracing::warn!(
                target: "marmot_app::key_packages",
                method = "finish_client_open_network_maintenance",
                error_kind = error.privacy_safe_kind(),
                "could not refresh routing after NIP-65 cutover recovery"
            );
            return;
        }
        // A generated identity's exact first KeyPackage is prepared under a
        // durable no-predecessor proof before its initial NIP-65 route exists.
        // Once pending route recovery has completed, that narrow proof is
        // sufficient for the setup-priority publisher's final lifecycle,
        // route, and marker checks. Running the ordinary retirement path here
        // would invalidate the one-time proof merely because the replacement
        // intent is still pending, permanently wedging setup.
        if client
            .runtime
            .key_package_maintenance_status()
            .ok()
            .flatten()
            .is_some_and(|lifecycle| {
                cutover_app
                    .generated_account_fresh_replacement_can_open_cutover_gate(
                        &cutover_label,
                        &lifecycle,
                    )
                    .unwrap_or(false)
            })
        {
            return;
        }
        if (!cutover_app.key_package_cutover_publication_allowed(&cutover_label)
            || cutover_app.key_package_cutover_replacement_pending(&cutover_label))
            && let Err(error) = client
                .runtime
                .set_key_package_cutover_publication_blocked(true)
        {
            tracing::warn!(
                target: "marmot_app::key_packages",
                method = "finish_client_open_network_maintenance",
                error_kind = AppError::from(error).privacy_safe_kind(),
                "could not arm key package cutover publication interlock"
            );
            return;
        }
        let cached_admission =
            cutover_app.retire_cached_non_current_key_package(&cutover_label, &mut client.runtime);
        // Exact deletion now owns the active-session route lock at its lowest
        // signer/network boundary. Release the wider cutover guard before the
        // retirement runtime invokes that publisher, then reacquire it for the
        // marker/gate decisions below. Every such decision is re-read after the
        // unlocked scan, so a route mutation that wins here remains fail-closed.
        drop(cutover_route_guard);
        let relay_scan_complete = cutover_app
            .retire_relay_non_current_key_packages(&cutover_label, &mut client.runtime)
            .await;
        let cutover_route_guard = cutover_route_lock.lock().await;
        if cached_admission.complete
            && let Some(event_id) = cached_admission.event_id.as_ref()
            && let Ok(_root_mutation) =
                cutover_app.begin_root_mutation("remove terminal cached KeyPackage revision")
        {
            cutover_app.remove_terminal_cached_key_package_record(&cutover_label, event_id);
        }
        if !cached_admission.complete || !relay_scan_complete {
            if let Err(error) = client
                .runtime
                .set_key_package_cutover_publication_blocked(true)
            {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "finish_client_open_network_maintenance",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not retain key package cutover publication interlock"
                );
            }
            tracing::warn!(
                target: "marmot_app::key_packages",
                method = "finish_client_open_network_maintenance",
                cached_admission_complete = cached_admission.complete,
                relay_scan_complete,
                "deferred key package replacement until every discovered historical publication is durably admitted"
            );
            return;
        }
        // Re-read the endpoint-bound marker after the scan. A live NIP-65
        // mutation can complete while per-relay discovery is in flight; its
        // new route set must not inherit the proof for the old set.
        if !cutover_app.key_package_cutover_publication_allowed(&cutover_label) {
            tracing::warn!(
                target: "marmot_app::key_packages",
                method = "finish_client_open_network_maintenance",
                "authoritative key package relays changed during cutover; retaining publication interlock"
            );
            return;
        }
        let replacement_pending =
            cutover_app.key_package_cutover_replacement_pending(&cutover_label);
        let lifecycle_current = client
            .runtime
            .key_package_maintenance_status()
            .ok()
            .flatten()
            .is_some_and(|lifecycle| {
                cutover_app
                    .key_package_lifecycle_has_current_cutover_revision(&cutover_label, &lifecycle)
            });
        if replacement_pending && !lifecycle_current {
            let replacement_endpoints = match cutover_app
                .authoritative_key_package_relays(&cutover_label)
            {
                Ok(endpoints) if !endpoints.is_empty() => endpoints,
                Ok(_) | Err(_) => {
                    tracing::warn!(
                        target: "marmot_app::key_packages",
                        method = "finish_client_open_network_maintenance",
                        "could not prepare a cutover replacement without safe authoritative relays"
                    );
                    return;
                }
            };
            if let Err(error) = client
                .runtime
                .prepare_fresh_key_package(replacement_endpoints.clone())
                .await
            {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "finish_client_open_network_maintenance",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not durably prepare the strict-newer cutover replacement"
                );
                return;
            }
            let prepared = client
                .runtime
                .key_package_maintenance_status()
                .ok()
                .flatten()
                .is_some_and(|lifecycle| {
                    cutover_app.key_package_lifecycle_has_prepared_cutover_replacement(
                        &cutover_label,
                        &lifecycle,
                        &replacement_endpoints,
                    )
                });
            if !prepared {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "finish_client_open_network_maintenance",
                    "prepared cutover replacement failed durable strict-newer validation"
                );
                return;
            }
        }
        // Signing a pending replacement may await an external signer. Re-read
        // the generation-bound marker immediately before clearing the SQL
        // gate; a self NIP-65 update admitted through any route during that
        // wait must retain the interlock.
        if !cutover_app.key_package_cutover_publication_allowed(&cutover_label) {
            tracing::warn!(
                target: "marmot_app::key_packages",
                method = "finish_client_open_network_maintenance",
                "authoritative key package route changed while preparing the cutover replacement"
            );
            return;
        }
        // Preparing can run the conservative legacy private-material sweep and
        // create additional cutover-only consumption tombstones after the
        // relay scan's first finalization pass. Transfer/reclaim those refs in
        // this same serialized cutover before opening publication admission.
        if let Err(error) = client
            .runtime
            .finalize_key_package_cutover_consumption_evidence()
        {
            tracing::warn!(
                target: "marmot_app::key_packages",
                method = "finish_client_open_network_maintenance",
                error_kind = AppError::from(error).privacy_safe_kind(),
                "could not finalize key package cutover consumption evidence"
            );
            return;
        }
        if let Err(error) = client
            .runtime
            .set_key_package_cutover_publication_blocked(false)
        {
            tracing::warn!(
                target: "marmot_app::key_packages",
                method = "finish_client_open_network_maintenance",
                error_kind = AppError::from(error).privacy_safe_kind(),
                "could not clear completed key package cutover publication interlock"
            );
            return;
        }
        // The final publisher takes this same lock around its marker/gate/route
        // validation and relay I/O. Release before calling it to avoid
        // recursive acquisition; a route mutation that wins next re-arms the
        // gate and invalidates the marker, so the final check will fail closed.
        drop(cutover_route_guard);
        if replacement_pending {
            if lifecycle_current {
                if let Ok(_root_mutation) = client
                    .app
                    .begin_root_mutation("clear completed KeyPackage cutover replacement")
                    && let Err(error) = client
                        .app
                        .clear_key_package_cutover_replacement_pending(&client.state.label)
                {
                    tracing::warn!(
                        target: "marmot_app::key_packages",
                        method = "finish_client_open_network_maintenance",
                        error_kind = error.privacy_safe_kind(),
                        "could not durably clear completed KeyPackage cutover replacement"
                    );
                }
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
                    .is_some_and(|lifecycle| {
                        client
                            .app
                            .key_package_lifecycle_has_current_cutover_revision(
                                &client.state.label,
                                &lifecycle,
                            )
                    })
                    && let Ok(_root_mutation) = client
                        .app
                        .begin_root_mutation("clear published KeyPackage cutover replacement")
                    && let Err(error) = client
                        .app
                        .clear_key_package_cutover_replacement_pending(&client.state.label)
                {
                    tracing::warn!(
                        target: "marmot_app::key_packages",
                        method = "finish_client_open_network_maintenance",
                        error_kind = error.privacy_safe_kind(),
                        "could not durably clear published KeyPackage cutover replacement"
                    );
                }
            }
        }
    }

    fn key_package_lifecycle_has_current_cutover_revision(
        &self,
        label: &str,
        lifecycle: &cgka_traits::KeyPackageLifecycleState,
    ) -> bool {
        let Some(artifact) = lifecycle.authored_signed_event.as_ref() else {
            return false;
        };
        let Some(key_package_ref) = lifecycle.current_key_package_ref.as_ref() else {
            return false;
        };
        let Some(metadata) = lifecycle
            .current_key_package
            .as_ref()
            .and_then(|key_package| key_package_metadata(key_package).ok())
        else {
            return false;
        };
        let Ok(metadata_ref) = hex::decode(&metadata.key_package_ref_hex) else {
            return false;
        };
        let Ok(account) = self.account_home().account(label) else {
            return false;
        };
        self.key_package_metadata_matches_current_support(&metadata)
            && metadata.credential_identity_hex == account.account_id_hex
            && metadata_ref == *key_package_ref
            && !lifecycle.key_package_ref_is_consumed(key_package_ref)
            && lifecycle.authored_event_id.as_ref() == Some(&artifact.id)
            && lifecycle.authored_event_created_at == Some(artifact.created_at)
            && !lifecycle
                .deleted_live_revision_event_ids
                .contains(&artifact.id)
            && lifecycle
                .retired_publications_pending_deletion
                .iter()
                .all(|retired| retired.authored_created_at < artifact.created_at)
    }

    fn key_package_lifecycle_has_prepared_cutover_replacement(
        &self,
        label: &str,
        lifecycle: &cgka_traits::KeyPackageLifecycleState,
        authoritative_endpoints: &[TransportEndpoint],
    ) -> bool {
        let Some(pending) = lifecycle.pending_replacement.as_ref() else {
            return false;
        };
        let Some(artifact) = pending.signed_event.as_ref() else {
            return false;
        };
        let Some(metadata) = key_package_metadata(&pending.key_package).ok() else {
            return false;
        };
        let Ok(account) = self.account_home().account(label) else {
            return false;
        };
        let Ok(metadata_ref) = hex::decode(&metadata.key_package_ref_hex) else {
            return false;
        };
        let Ok(expected) =
            self.sanitize_key_package_deletion_endpoints(authoritative_endpoints.to_vec())
        else {
            return false;
        };
        let Ok(actual) = self.sanitize_key_package_deletion_endpoints(
            pending
                .targets
                .iter()
                .filter(|target| {
                    target.state != cgka_traits::TransportFanoutAttemptState::PolicyProhibited
                })
                .map(|target| target.endpoint.clone())
                .collect::<Vec<_>>(),
        ) else {
            return false;
        };

        !expected.is_empty()
            && actual == expected
            && self.key_package_metadata_matches_current_support(&metadata)
            && metadata.credential_identity_hex == account.account_id_hex
            && metadata_ref == pending.key_package_ref
            && !lifecycle.key_package_ref_is_consumed(&pending.key_package_ref)
            && artifact.created_at == pending.authored_created_at
            && !lifecycle
                .deleted_live_revision_event_ids
                .contains(&artifact.id)
            && lifecycle
                .authored_event_created_at
                .is_none_or(|high_water| artifact.created_at > high_water)
            && lifecycle
                .retired_publications_pending_deletion
                .iter()
                .all(|retired| retired.authored_created_at < artifact.created_at)
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

    /// Legacy direct-app seam retained for API compatibility.
    ///
    /// Relay-list mutations require account-worker or setup admission, neither
    /// of which a bare [`MarmotApp`] owns. Use the matching
    /// [`MarmotAppRuntime`] operation; this method always fails before reading
    /// account caches, signing, or relay I/O.
    pub async fn publish_account_relay_lists(
        &self,
        _label: &str,
        _bootstrap: AccountRelayListBootstrap,
    ) -> Result<AccountRelayListStatus, AppError> {
        Err(AppError::AccountWorkerBusy)
    }

    pub(crate) async fn publish_account_relay_lists_for_setup(
        &self,
        label: &str,
        bootstrap: AccountRelayListBootstrap,
        setup_admission: &runtime::AccountSetupPublicationAdmission,
    ) -> Result<AccountRelayListStatus, AppError> {
        self.publish_selected_account_relay_lists_with_nip65(
            label,
            bootstrap,
            &[
                NostrAccountRelayListKind::Nip65,
                NostrAccountRelayListKind::Inbox,
            ],
            None,
            AccountRelayListMutationAdmission::Setup(setup_admission),
        )
        .await
    }

    /// Durably stage and sign the generated identity's exact initial NIP-65
    /// authority without contacting a relay. The pending route file is both the
    /// crash-recovery source for the exact signed event and the final-boundary
    /// fence that prevents a KeyPackage from escaping before that authority is
    /// committed.
    pub(crate) async fn stage_generated_account_nip65_route_mutation(
        &self,
        label: &str,
        bootstrap: &AccountRelayListBootstrap,
    ) -> Result<(), AppError> {
        if bootstrap.default_relays.is_empty() {
            return Err(AppError::MissingDefaultRelays);
        }
        self.validate_account_relay_list_declarations(bootstrap, None)?;
        let route_lock = self.key_package_route_lock(label);
        let _route_guard = route_lock.lock().await;
        let account = self.account_home().account(label)?;
        let signer = self.account_signer_for_summary(&account)?;
        self.stage_generated_account_nip65_route_mutation_unlocked(
            label,
            bootstrap,
            signer.as_nostr_signer(),
        )
        .await?;
        Ok(())
    }

    /// Validate the generated setup's desired authority, stage it when absent,
    /// then exact-replay/commit it under the same account route lock. Callers
    /// pass the relay options recovered from the durable generated-setup
    /// context; an older pending intent for any other authority fails before
    /// network I/O instead of being reinterpreted as this setup attempt.
    pub(crate) async fn recover_generated_account_nip65_route_authority_for_session(
        &self,
        label: &str,
        bootstrap: &AccountRelayListBootstrap,
        signer: Arc<dyn nostr::NostrSigner>,
        session_admission: &AccountSessionAdmissionToken,
    ) -> Result<GeneratedNip65RouteAuthorityProof, AppError> {
        if bootstrap.default_relays.is_empty() {
            return Err(AppError::MissingDefaultRelays);
        }
        self.validate_account_relay_list_declarations(bootstrap, None)?;
        let route_lock = self.key_package_route_lock(label);
        let _route_guard = route_lock.lock().await;
        if !self.active_account_session_admission_is_current(label, session_admission) {
            return Err(AppError::AccountWorkerBusy);
        }
        let desired = self
            .stage_generated_account_nip65_route_mutation_unlocked(label, bootstrap, signer.clone())
            .await?;
        if !self.active_account_session_admission_is_current(label, session_admission) {
            return Err(AppError::AccountWorkerBusy);
        }
        self.recover_validated_generated_nip65_route_mutation(label, signer)
            .await?;
        let generation = self
            .read_nip65_route_generation_for_authoring(label)?
            .ok_or_else(|| {
                AppError::Publish(
                    "generated account NIP-65 authority was not durably committed".into(),
                )
            })?;
        if self.canonical_nip65_route_state(&generation.nip65)?
            != self.canonical_nip65_route_state(&desired)?
        {
            return Err(AppError::Publish(
                "generated account NIP-65 authority does not match its durable setup context"
                    .into(),
            ));
        }
        let endpoints = self.validate_nip65_route_generation(&generation)?;
        Ok(GeneratedNip65RouteAuthorityProof {
            generation,
            endpoints,
        })
    }

    #[cfg(test)]
    async fn recover_generated_account_nip65_route_authority(
        &self,
        label: &str,
        bootstrap: &AccountRelayListBootstrap,
        signer: Arc<dyn nostr::NostrSigner>,
    ) -> Result<GeneratedNip65RouteAuthorityProof, AppError> {
        let account = self.account_home().account(label)?;
        let admission =
            self.capture_account_session_admission(&account.label, &account.account_id_hex)?;
        self.recover_generated_account_nip65_route_authority_for_session(
            label, bootstrap, signer, &admission,
        )
        .await
    }

    /// Reopen the generated setup's SQL publication interlock only after the
    /// caller has refreshed routing from the recovered authority. This second
    /// route-locked proof prevents a refresh failure or an intervening route
    /// mutation from inheriting the recovery capability.
    pub(crate) async fn open_generated_account_key_package_publication_gate(
        &self,
        label: &str,
        bootstrap: &AccountRelayListBootstrap,
        proof: &GeneratedNip65RouteAuthorityProof,
        session_admission: &AccountSessionAdmissionToken,
    ) -> Result<(), AppError> {
        if bootstrap.default_relays.is_empty() {
            return Err(AppError::MissingDefaultRelays);
        }
        self.validate_account_relay_list_declarations(bootstrap, None)?;
        let route_lock = self.key_package_route_lock(label);
        let _route_guard = route_lock.lock().await;
        if !self.active_account_session_admission_is_current(label, session_admission) {
            return Err(AppError::AccountWorkerBusy);
        }
        let account = self.account_home().account(label)?;
        let publish_endpoints = self.publish_route_including_requested(
            &account.account_id_hex,
            publish_endpoints_from_bootstrap(bootstrap),
        );
        let (_, desired) =
            self.generated_account_nip65_event_and_state(&account, bootstrap, publish_endpoints)?;
        let desired_authority = self.canonical_nip65_route_state(&desired)?;
        let current = self
            .read_nip65_route_generation_for_authoring(label)?
            .ok_or_else(|| {
                AppError::Publish(
                    "generated account NIP-65 authority disappeared before gate admission".into(),
                )
            })?;
        let current_endpoints = self.validate_nip65_route_generation(&current)?;
        if current != proof.generation
            || self.canonical_nip65_route_state(&current.nip65)? != desired_authority
            || current_endpoints != proof.endpoints
            || desired_authority.0 != proof.endpoints
        {
            return Err(AppError::Publish(
                "generated account NIP-65 authority changed before KeyPackage gate admission"
                    .into(),
            ));
        }
        let storage = self.account_storage(label)?;
        let Some(mut lifecycle) = storage.key_package_lifecycle()? else {
            return Err(AppError::Publish(
                "generated account route recovery has no durable KeyPackage lifecycle".into(),
            ));
        };
        if !self.generated_account_fresh_replacement_can_open_cutover_gate(label, &lifecycle)? {
            return Err(AppError::Publish(
                "generated account route recovery cannot prove its exact fresh KeyPackage replacement"
                    .into(),
            ));
        }
        if !self.active_account_session_admission_is_current(label, session_admission) {
            return Err(AppError::AccountWorkerBusy);
        }
        self.clear_generated_initial_key_package_publication_hold(label)?;
        if lifecycle.cutover_publication_blocked {
            lifecycle.cutover_publication_blocked = false;
            storage.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok(())
    }

    /// The caller owns `key_package_route_lock(label)`. This method performs no
    /// relay I/O: it only validates existing durable authority or signs and
    /// persists one exact pending generated-bootstrap event.
    async fn stage_generated_account_nip65_route_mutation_unlocked(
        &self,
        label: &str,
        bootstrap: &AccountRelayListBootstrap,
        signer: Arc<dyn nostr::NostrSigner>,
    ) -> Result<AccountRelayListState, AppError> {
        let account = self.account_home().account(label)?;
        let publish_endpoints = self.publish_route_including_requested(
            &account.account_id_hex,
            publish_endpoints_from_bootstrap(bootstrap),
        );
        let (generated_event, desired) = self.generated_account_nip65_event_and_state(
            &account,
            bootstrap,
            publish_endpoints.clone(),
        )?;
        let desired_authority = self.canonical_nip65_route_state(&desired)?;
        let desired_endpoints = desired_authority.0.clone();
        let desired_publish_endpoints = self.canonical_nip65_publication_endpoints(
            publish_endpoints.clone(),
            "generated-account NIP-65 setup publication",
        )?;

        if self.pending_nip65_route_mutation(label) {
            let pending = self.read_pending_nip65_route_mutation(label)?;
            let pending_endpoints = self.validate_pending_nip65_route_mutation(label, &pending)?;
            let pending_publish_endpoints = self.canonical_nip65_publication_endpoints(
                pending
                    .publish_endpoints
                    .iter()
                    .cloned()
                    .map(TransportEndpoint)
                    .collect(),
                "pending generated-account NIP-65 publication",
            )?;
            let pending_bootstrap_endpoints = self.canonical_nip65_publication_endpoints(
                pending
                    .bootstrap_relays
                    .iter()
                    .cloned()
                    .map(TransportEndpoint)
                    .collect(),
                "pending generated-account bootstrap projection",
            )?;
            if pending.source != Nip65RouteMutationSource::GeneratedAccountBootstrap
                || pending.signed_event.is_none()
                || self.canonical_nip65_route_state(&pending.nip65)? != desired_authority
                || pending_endpoints != desired_endpoints
                || pending_publish_endpoints != desired_publish_endpoints
                || pending_bootstrap_endpoints != desired_publish_endpoints
            {
                return Err(AppError::Publish(
                    "pending generated-account NIP-65 route does not match its durable setup context"
                        .into(),
                ));
            }
            return Ok(pending.nip65);
        }

        if let Some(generation) = self.read_nip65_route_generation_for_authoring(label)? {
            let generation_endpoints = self.validate_nip65_route_generation(&generation)?;
            if self.canonical_nip65_route_state(&generation.nip65)? != desired_authority
                || generation_endpoints != desired_endpoints
            {
                return Err(AppError::Publish(
                    "generated account NIP-65 authority does not match its durable setup context"
                        .into(),
                ));
            }
            // The declared authority is unchanged, but a reconstructed setup
            // context may name a different bootstrap publication route. The
            // generation journal does not prove that route saw the event, so
            // deterministically re-sign the exact committed coordinate and
            // stage an id-equal replay to the context-authorized endpoints.
            // This never authors a newer route revision and never silently
            // reuses stale bootstrap endpoints.
            let mut signed_event = generated_event;
            signed_event.created_at = generation.created_at;
            signed_event = self
                .sign_account_transport_event(signer, signed_event)
                .await?;
            if signed_event.id != generation.event_id
                || relay_list_state_from_event(&signed_event).as_ref() != Some(&generation.nip65)
            {
                return Err(AppError::Publish(
                    "generated account NIP-65 generation cannot be exactly replayed to its durable setup route"
                        .into(),
                ));
            }
            let pending = PendingNip65RouteMutation {
                account_id_hex: account.account_id_hex,
                nip65: generation.nip65.clone(),
                bootstrap_relays: publish_endpoints
                    .iter()
                    .map(|endpoint| endpoint.0.clone())
                    .collect(),
                publish_endpoints: publish_endpoints
                    .iter()
                    .map(|endpoint| endpoint.0.clone())
                    .collect(),
                signed_event: Some(signed_event),
                generation: generation.clone(),
                network_accepted: false,
                source: Nip65RouteMutationSource::GeneratedAccountBootstrap,
            };
            let _root_mutation =
                self.begin_root_mutation("stage exact generated-account NIP-65 route replay")?;
            self.write_pending_nip65_route_mutation(label, &pending)?;
            return Ok(generation.nip65);
        }

        let mut signed_event = generated_event;
        signed_event.created_at = self.next_locally_authored_nip65_created_at(label)?;
        signed_event = self
            .sign_account_transport_event(signer, signed_event)
            .await?;
        let nip65 = relay_list_state_from_event(&signed_event).ok_or_else(|| {
            AppError::Publish("signed NIP-65 event has no relay-list state".into())
        })?;
        if nip65 != desired {
            return Err(AppError::Publish(
                "signed generated-account NIP-65 event changed its declared authority".into(),
            ));
        }
        let pending = PendingNip65RouteMutation {
            account_id_hex: account.account_id_hex,
            nip65: nip65.clone(),
            bootstrap_relays: publish_endpoints
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect(),
            publish_endpoints: publish_endpoints
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect(),
            signed_event: Some(signed_event.clone()),
            generation: Nip65RouteGeneration {
                created_at: signed_event.created_at,
                event_id: signed_event.id.clone(),
                nip65: nip65.clone(),
            },
            network_accepted: false,
            source: Nip65RouteMutationSource::GeneratedAccountBootstrap,
        };
        {
            let _root_mutation =
                self.begin_root_mutation("stage generated-account NIP-65 route mutation")?;
            self.write_pending_nip65_route_mutation(label, &pending)?;
            let fresh_account_proof_preserved =
                self.invalidate_key_package_cutover_scan_for_route_mutation(label)?;
            if !fresh_account_proof_preserved {
                self.arm_key_package_cutover_publication_gate_for_relays(
                    label,
                    &desired_endpoints,
                )?;
            }
        }
        Ok(nip65)
    }

    fn generated_account_nip65_event_and_state(
        &self,
        account: &AccountSummary,
        bootstrap: &AccountRelayListBootstrap,
        publish_endpoints: Vec<TransportEndpoint>,
    ) -> Result<(NostrTransportEvent, AccountRelayListState), AppError> {
        let generated_event = NostrAccountRelayListPublication {
            account_id: MemberId::new(hex::decode(&account.account_id_hex)?),
            list_kind: NostrAccountRelayListKind::Nip65,
            relays: bootstrap.default_relays.clone(),
            publish_endpoints,
        }
        .to_event()?;
        let desired = relay_list_state_from_event(&generated_event).ok_or_else(|| {
            AppError::Publish("generated NIP-65 event has no relay-list state".into())
        })?;
        Ok((generated_event, desired))
    }

    /// Publish every generated-identity bootstrap record through one scoped
    /// relay batch. The SDK connects the endpoint union once for the two relay
    /// lists, empty follow list, and default profile, then returns one ordered
    /// acknowledgement result per replaceable event.
    pub(crate) async fn publish_generated_account_bootstrap_admitted(
        &self,
        label: &str,
        bootstrap: AccountRelayListBootstrap,
        profile: &UserProfileMetadata,
        setup_admission: &runtime::AccountSetupPublicationAdmission,
    ) -> Result<GeneratedAccountBootstrapPublication, AppError> {
        if bootstrap.default_relays.is_empty() {
            return Err(AppError::MissingDefaultRelays);
        }
        self.validate_account_relay_list_declarations(&bootstrap, None)?;
        let key_package_route_lock = self.key_package_route_lock(label);
        let _key_package_route_guard = key_package_route_lock.lock().await;
        let account = self.account_home().account(label)?;
        let setup_is_current = || {
            self.account_home().account(label).is_ok_and(|current| {
                current.is_active_signing()
                    && current.account_id_hex == setup_admission.account_id_hex()
                    && current.signed_out == setup_admission.started_signed_out()
            }) && setup_admission.is_current()
                && self.account_session_admission_is_open(&account.label, &account.account_id_hex)
        };
        if !setup_is_current() {
            return Err(AppError::AccountWorkerBusy);
        }
        let signer = self.account_signer_for_summary(&account)?;
        // Validate an older exact intent against this durable setup request
        // before replaying it. A mismatched but otherwise valid pending route
        // must not be committed merely because it carries the generated source.
        let pending_preexisted = self.pending_nip65_route_mutation(label);
        let desired_nip65 = self
            .stage_generated_account_nip65_route_mutation_unlocked(
                label,
                &bootstrap,
                signer.as_nostr_signer(),
            )
            .await?;
        if pending_preexisted {
            if !setup_is_current() {
                return Err(AppError::AccountWorkerBusy);
            }
            self.recover_validated_generated_nip65_route_mutation(label, signer.as_nostr_signer())
                .await?;
        }
        let account_id = MemberId::new(hex::decode(&account.account_id_hex)?);
        // Relay-list records are discoverability maps and therefore go to the
        // bootstrap route. Profiles and contact lists are outbox content: keep
        // them on the declared write relays even though the mixed batch retains
        // the union of both endpoint sets once.
        let content_endpoints =
            self.outbox_endpoints(&account.account_id_hex, bootstrap.default_relays.clone());
        let endpoints = self.publish_route_including_requested(
            &account.account_id_hex,
            publish_endpoints_from_bootstrap(&bootstrap),
        );

        let relays = bootstrap
            .default_relays
            .iter()
            .map(|endpoint| endpoint.0.clone())
            .collect::<Vec<_>>();
        let mut requests = Vec::with_capacity(4);
        let mut record_kinds = Vec::with_capacity(4);
        let mut pending_nip65 = if self.pending_nip65_route_mutation(label) {
            Some(self.read_pending_nip65_route_mutation(label)?)
        } else {
            None
        };
        if let Some(pending) = pending_nip65.as_ref() {
            let event = pending.signed_event.clone().ok_or_else(|| {
                AppError::Publish(
                    "unacknowledged generated NIP-65 route intent has no exact signed event".into(),
                )
            })?;
            requests.push(NostrEventPublishRequest {
                endpoints: endpoints.clone(),
                event,
                required_acks: 1,
            });
            record_kinds.push("NIP-65 relay list");
        }
        requests.push(NostrEventPublishRequest {
            endpoints: endpoints.clone(),
            event: NostrAccountRelayListPublication {
                account_id: account_id.clone(),
                list_kind: NostrAccountRelayListKind::Inbox,
                relays: bootstrap.default_relays.clone(),
                publish_endpoints: endpoints.clone(),
            }
            .to_event()?,
            required_acks: 1,
        });
        record_kinds.push("inbox relay list");
        requests.push(NostrEventPublishRequest {
            endpoints: content_endpoints.clone(),
            event: NostrTransportEvent::new_unsigned(
                account.account_id_hex.clone(),
                KIND_NOSTR_CONTACT_LIST,
                Vec::new(),
                String::new(),
            ),
            required_acks: 1,
        });
        record_kinds.push("contact list");
        requests.push(NostrEventPublishRequest {
            endpoints: content_endpoints.clone(),
            event: NostrTransportEvent::new_unsigned(
                account.account_id_hex.clone(),
                KIND_NOSTR_METADATA,
                Vec::new(),
                serde_json::to_string(&directory::records::profile_content_json(profile))?,
            ),
            required_acks: 1,
        });
        record_kinds.push("profile metadata");

        let relay_client =
            self.relay_client_for_account_id(&account.account_id_hex, signer.as_nostr_signer());
        if !setup_is_current() {
            return Err(AppError::AccountWorkerBusy);
        }
        let batch = relay_client.publish_events_with_timings(&requests).await;
        let outcomes = batch.outcomes;
        if outcomes.len() != record_kinds.len() {
            return Err(AppError::Publish(format!(
                "account bootstrap returned {} outcomes for {} records",
                outcomes.len(),
                record_kinds.len()
            )));
        }
        if batch.request_durations.len() != record_kinds.len() {
            return Err(AppError::Publish(format!(
                "account bootstrap returned {} timings for {} records",
                batch.request_durations.len(),
                record_kinds.len()
            )));
        }
        let non_profile_request_count = batch.request_durations.len().saturating_sub(1);
        let relay_and_follow_duration = batch.request_durations[..non_profile_request_count]
            .iter()
            .copied()
            .max()
            .unwrap_or_default();
        let default_profile_duration = batch.request_durations.last().copied().unwrap_or_default();
        for (index, (record_kind, outcome)) in record_kinds.into_iter().zip(outcomes).enumerate() {
            if outcome?.accepted.is_empty() {
                return Err(AppError::Publish(format!(
                    "relay acknowledged zero events for bootstrap record {record_kind}"
                )));
            }
            if index == 0
                && let Some(pending) = pending_nip65.as_mut()
            {
                debug_assert_eq!(record_kind, "NIP-65 relay list");
                pending.network_accepted = true;
                {
                    let _root_mutation = self.begin_root_mutation(
                        "record generated-account NIP-65 route acknowledgement",
                    )?;
                    self.write_pending_nip65_route_mutation(label, pending)?;
                }
                self.commit_pending_nip65_route_mutation(label, pending)?;
            }
        }

        let mut status = AccountRelayListStatus {
            complete: false,
            missing: Vec::new(),
            default_relays: Vec::new(),
            bootstrap_relays: bootstrap
                .bootstrap_relays
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect(),
            nip65: desired_nip65,
            inbox: AccountRelayListState {
                kind: KIND_MARMOT_INBOX_RELAY_LIST,
                relays,
                read_relays: Vec::new(),
                write_relays: Vec::new(),
            },
        };
        status.refresh();
        self.remember_directory_relay_lists(&account.account_id_hex, &status)?;
        self.remember_directory_follow_edges_for_search(
            &account.account_id_hex,
            &directory::FetchedFollowList {
                follows: Vec::new(),
                source_relays: content_endpoints
                    .iter()
                    .map(|endpoint| endpoint.0.clone())
                    .collect(),
            },
        )?;
        self.remember_directory_profile(&account.account_id_hex, profile)?;
        Ok(GeneratedAccountBootstrapPublication {
            status,
            relay_and_follow_duration,
            default_profile_duration,
        })
    }

    #[cfg(test)]
    async fn publish_generated_account_bootstrap(
        &self,
        label: &str,
        bootstrap: AccountRelayListBootstrap,
        profile: &UserProfileMetadata,
    ) -> Result<GeneratedAccountBootstrapPublication, AppError> {
        let account = self.account_home().account(label)?;
        let admission =
            runtime::AccountSetupPublicationAdmission::for_test(&account.account_id_hex);
        self.publish_generated_account_bootstrap_admitted(label, bootstrap, profile, &admission)
            .await
    }

    /// Legacy direct-app seam retained for API compatibility; use
    /// [`MarmotAppRuntime`] so the active account worker supplies admission.
    /// This method always fails before reading account caches or publishing.
    pub async fn publish_missing_account_relay_lists(
        &self,
        _label: &str,
        _bootstrap: AccountRelayListBootstrap,
    ) -> Result<AccountRelayListStatus, AppError> {
        Err(AppError::AccountWorkerBusy)
    }

    /// Legacy direct-app seam retained for API compatibility; use
    /// [`MarmotAppRuntime`] so the active account worker supplies admission.
    /// This method always fails before reading account caches or publishing.
    pub async fn publish_missing_account_relay_lists_from_status(
        &self,
        _label: &str,
        _bootstrap: AccountRelayListBootstrap,
        _current: AccountRelayListStatus,
    ) -> Result<AccountRelayListStatus, AppError> {
        Err(AppError::AccountWorkerBusy)
    }

    pub(crate) async fn publish_missing_account_relay_lists_from_status_for_setup(
        &self,
        label: &str,
        bootstrap: AccountRelayListBootstrap,
        current: AccountRelayListStatus,
        setup_admission: &runtime::AccountSetupPublicationAdmission,
    ) -> Result<AccountRelayListStatus, AppError> {
        self.publish_missing_account_relay_lists_from_status_unlocked(
            label,
            bootstrap,
            current,
            AccountRelayListMutationAdmission::Setup(setup_admission),
        )
        .await
    }

    async fn publish_missing_account_relay_lists_from_status_unlocked(
        &self,
        label: &str,
        bootstrap: AccountRelayListBootstrap,
        current: AccountRelayListStatus,
        admission: AccountRelayListMutationAdmission<'_>,
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
        self.publish_selected_account_relay_lists_with_nip65(
            label, bootstrap, &missing, None, admission,
        )
        .await
    }

    pub(crate) async fn ensure_local_account_relay_lists_for_session(
        &self,
        label: &str,
        session_admission: &AccountSessionAdmissionToken,
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
        let missing = status
            .missing
            .iter()
            .map(|kind| match kind {
                MissingRelayListKind::Nip65 => NostrAccountRelayListKind::Nip65,
                MissingRelayListKind::Inbox => NostrAccountRelayListKind::Inbox,
            })
            .collect::<Vec<_>>();
        self.publish_selected_account_relay_lists_with_nip65(
            label,
            AccountRelayListBootstrap::new(default_relays.clone(), default_relays),
            &missing,
            None,
            AccountRelayListMutationAdmission::Active(session_admission),
        )
        .await
    }

    /// Legacy direct-app seam retained for API compatibility.
    ///
    /// Supported relay-list kinds fail closed without runtime admission;
    /// unknown kinds retain their input-validation error. Use
    /// [`MarmotAppRuntime::publish_account_relay_list_kind`] for mutations.
    pub async fn publish_account_relay_list_kind(
        &self,
        _label: &str,
        list_kind: &str,
        _relays: Vec<TransportEndpoint>,
        _bootstrap_relays: Vec<TransportEndpoint>,
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
        let _ = list_kind;
        Err(AppError::AccountWorkerBusy)
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

    /// Legacy direct-app seam retained for API compatibility; use
    /// [`MarmotAppRuntime::set_account_nip65_relays`]. This method always fails
    /// before reading the role-preserving relay-list cache or publishing.
    pub async fn set_account_nip65_relays(
        &self,
        _label: &str,
        _relays: Vec<TransportEndpoint>,
        _bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        Err(AppError::AccountWorkerBusy)
    }

    /// Legacy direct-app seam retained for API compatibility; use
    /// [`MarmotAppRuntime::publish_account_nip65_relay_set`]. This method
    /// always fails before signing or relay I/O.
    pub async fn publish_account_nip65_relay_set(
        &self,
        _label: &str,
        _read_relays: Vec<TransportEndpoint>,
        _write_relays: Vec<TransportEndpoint>,
        _bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        Err(AppError::AccountWorkerBusy)
    }

    pub(crate) async fn publish_account_nip65_relay_set_for_session(
        &self,
        label: &str,
        read_relays: Vec<TransportEndpoint>,
        write_relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
        session_admission: &AccountSessionAdmissionToken,
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
            AccountRelayListMutationAdmission::Active(session_admission),
        )
        .await
    }

    pub(crate) async fn publish_account_inbox_relays_for_session(
        &self,
        label: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
        session_admission: &AccountSessionAdmissionToken,
    ) -> Result<AccountRelayListStatus, AppError> {
        self.publish_selected_account_relay_lists_with_nip65(
            label,
            AccountRelayListBootstrap::new(relays, bootstrap_relays),
            &[NostrAccountRelayListKind::Inbox],
            None,
            AccountRelayListMutationAdmission::Active(session_admission),
        )
        .await
    }

    /// Legacy direct-app seam retained for API compatibility; use
    /// [`MarmotAppRuntime::set_account_inbox_relays`]. This method always fails
    /// before signing, relay I/O, or cache mutation.
    pub async fn set_account_inbox_relays(
        &self,
        _label: &str,
        _relays: Vec<TransportEndpoint>,
        _bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        Err(AppError::AccountWorkerBusy)
    }

    async fn publish_selected_account_relay_lists_with_nip65(
        &self,
        label: &str,
        bootstrap: AccountRelayListBootstrap,
        list_kinds: &[NostrAccountRelayListKind],
        nip65_relay_set: Option<&NostrNip65RelaySet>,
        admission: AccountRelayListMutationAdmission<'_>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let has_directional_nip65_relays = nip65_relay_set.is_some_and(|relays| {
            !relays.read_relays.is_empty() || !relays.write_relays.is_empty()
        });
        if bootstrap.default_relays.is_empty() && !has_directional_nip65_relays {
            return Err(AppError::MissingDefaultRelays);
        }
        self.validate_account_relay_list_declarations(&bootstrap, nip65_relay_set)?;
        let mut proposed_key_package_relays = None;
        if list_kinds.contains(&NostrAccountRelayListKind::Nip65) {
            let proposed = nip65_relay_set
                .map(|relay_set| relay_set.write_relays.clone())
                .unwrap_or_else(|| bootstrap.default_relays.clone());
            proposed_key_package_relays =
                Some(self.sanitize_key_package_deletion_endpoints(proposed)?);
        }
        // Inbox mutations use the same route lock as NIP-65. This gives
        // teardown one final boundary for every signed relay-list event and
        // prevents a retained caller from repopulating account caches after
        // sign-out has completed.
        let key_package_route_lock = self.key_package_route_lock(label);
        let _key_package_route_guard = key_package_route_lock.lock().await;
        let account = self.account_home().account(label)?;
        let admission_is_current = || match admission {
            AccountRelayListMutationAdmission::Active(token) => {
                account.is_active_signing()
                    && account.account_id_hex == token.account_id_hex
                    && self.active_account_session_admission_is_current(label, token)
            }
            AccountRelayListMutationAdmission::Setup(admission) => {
                admission.is_current()
                    && account.account_id_hex == admission.account_id_hex()
                    && account.signed_out == admission.started_signed_out()
                    && account.can_sign()
            }
        };
        if !admission_is_current() {
            return Err(AppError::AccountWorkerBusy);
        }
        let signer = self.account_signer_for_summary(&account)?;
        if proposed_key_package_relays.is_some() {
            // A prior process may have exposed the new route-list event and
            // died before committing its local projection. Replay the exact
            // signed event (when still unacknowledged) and finish that durable
            // intent before authoring another replaceable revision.
            if !admission_is_current() {
                return Err(AppError::AccountWorkerBusy);
            }
            self.recover_pending_nip65_route_mutation(label, signer.as_nostr_signer())
                .await?;
        }
        let nip65_created_at = list_kinds
            .contains(&NostrAccountRelayListKind::Nip65)
            .then(|| self.next_locally_authored_nip65_created_at(label))
            .transpose()?;
        let account_id = MemberId::new(hex::decode(&account.account_id_hex)?);
        let account_id_hex = account.account_id_hex.clone();
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
        let endpoints = self.publish_route_including_requested(
            &account_id_hex,
            publish_endpoints_from_bootstrap(&bootstrap),
        );
        let relay_client =
            self.relay_client_for_account_id(&account_id_hex, signer.as_nostr_signer());
        let mut requests = Vec::with_capacity(list_kinds.len());
        let mut pending_nip65 = None;
        for list_kind in list_kinds {
            let mut event = if *list_kind == NostrAccountRelayListKind::Nip65
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
            if *list_kind == NostrAccountRelayListKind::Nip65 {
                event.created_at =
                    nip65_created_at.expect("a NIP-65 relay-list batch has an authoring timestamp");
                event = self
                    .sign_account_transport_event(signer.as_nostr_signer(), event)
                    .await?;
                if !admission_is_current() {
                    return Err(AppError::AccountWorkerBusy);
                }
                let nip65 = relay_list_state_from_event(&event).ok_or_else(|| {
                    AppError::Publish("signed NIP-65 event has no relay-list state".into())
                })?;
                let generation = Nip65RouteGeneration {
                    created_at: event.created_at,
                    event_id: event.id.clone(),
                    nip65: nip65.clone(),
                };
                pending_nip65 = Some(PendingNip65RouteMutation {
                    account_id_hex: account_id_hex.clone(),
                    nip65,
                    bootstrap_relays: endpoints
                        .iter()
                        .map(|endpoint| endpoint.0.clone())
                        .collect(),
                    publish_endpoints: endpoints
                        .iter()
                        .map(|endpoint| endpoint.0.clone())
                        .collect(),
                    signed_event: Some(event.clone()),
                    generation,
                    network_accepted: false,
                    source: Nip65RouteMutationSource::AccountMutation,
                });
            }
            requests.push(NostrEventPublishRequest {
                endpoints: endpoints.clone(),
                event,
                required_acks: 1,
            });
        }
        if let Some(pending) = pending_nip65.as_ref() {
            if !admission_is_current() {
                return Err(AppError::AccountWorkerBusy);
            }
            // The intent precedes both the durable SQL gate and any network
            // I/O. A crash at either following boundary therefore leaves a
            // restart-readable reason to refuse kind-30443 publication.
            let _root_mutation = self.begin_root_mutation("stage pending NIP-65 route mutation")?;
            self.write_pending_nip65_route_mutation(label, pending)?;
            self.invalidate_key_package_cutover_scan_for_route_mutation(label)?;
            self.arm_key_package_cutover_publication_gate_for_relays(
                label,
                proposed_key_package_relays
                    .as_deref()
                    .expect("NIP-65 mutation has a proposed write-relay set"),
            )?;
        }
        if !admission_is_current() {
            return Err(AppError::AccountWorkerBusy);
        }
        let outcomes = relay_client.publish_events(&requests).await;
        if outcomes.len() != list_kinds.len() {
            return Err(AppError::Publish(format!(
                "account relay-list batch returned {} outcomes for {} events",
                outcomes.len(),
                list_kinds.len()
            )));
        }
        for (list_kind, outcome) in list_kinds.iter().zip(outcomes) {
            if outcome?.accepted.is_empty() {
                return Err(AppError::Publish(
                    "relay acknowledged zero account relay-list events".to_owned(),
                ));
            }
            if *list_kind == NostrAccountRelayListKind::Nip65
                && let Some(pending) = pending_nip65.as_mut()
            {
                pending.network_accepted = true;
                let _root_mutation =
                    self.begin_root_mutation("record NIP-65 route acknowledgement")?;
                self.write_pending_nip65_route_mutation(label, pending)?;
            }
        }

        // The signed replaceable events above are the authoritative effect of
        // this operation. Persist their declared state directly after every
        // event has an acknowledgement; synchronously querying the same relays
        // again adds no confirmation strength and used to turn a post-success
        // read outage into account-setup rollback (mdk#1436).
        let mut status = self.account_relay_list_status_for_account_id(&account_id_hex)?;
        for list_kind in list_kinds {
            match list_kind {
                NostrAccountRelayListKind::Nip65 => {
                    status.nip65 = pending_nip65
                        .as_ref()
                        .expect("published NIP-65 event has durable intent")
                        .nip65
                        .clone();
                }
                NostrAccountRelayListKind::Inbox => {
                    status.inbox = AccountRelayListState {
                        kind: KIND_MARMOT_INBOX_RELAY_LIST,
                        relays: bootstrap
                            .default_relays
                            .iter()
                            .map(|endpoint| endpoint.0.clone())
                            .collect(),
                        read_relays: Vec::new(),
                        write_relays: Vec::new(),
                    };
                }
            }
        }
        push_unique_strings(
            &mut status.bootstrap_relays,
            endpoints.iter().map(|endpoint| endpoint.0.clone()),
        );
        status.refresh();
        let _root_mutation = self.begin_root_mutation("commit account relay-list publication")?;
        let _frontier_mutation = self
            .key_package_frontier_mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(pending) = pending_nip65.as_ref() {
            // Route authority precedes its cache projection. The still-present
            // pending intent and SQL gate make a crash between these writes
            // restartable without exposing the previous route.
            self.write_nip65_route_generation(label, &pending.generation)?;
        }
        self.remember_directory_relay_lists(&account_id_hex, &status)?;
        if pending_nip65.is_some() {
            self.clear_pending_nip65_route_mutation(label)?;
        }
        Ok(status)
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

    /// Preserve the account's existing outbox route while ensuring every
    /// explicitly requested publication endpoint is reached at least once.
    fn publish_route_including_requested(
        &self,
        account_id_hex: &str,
        requested: Vec<TransportEndpoint>,
    ) -> Vec<TransportEndpoint> {
        let mut endpoints = self.outbox_endpoints(account_id_hex, requested.clone());
        for endpoint in requested {
            if !endpoints.iter().any(|existing| existing.0 == endpoint.0) {
                endpoints.push(endpoint);
            }
        }
        endpoints
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
                kinds: query.kinds,
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

    pub(crate) fn timeline_messages_by_wall_clock_with_query(
        &self,
        label: &str,
        query: TimelineMessageQuery,
    ) -> Result<TimelinePage, AppError> {
        self.ensure_account_state(label)?;
        Ok(self
            .account_storage(label)?
            .message_timeline_by_wall_clock(query)?)
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

    /// Direct-conversation candidates for a peer-keyed reuse lookup.
    ///
    /// This is the SQL-filtered chat-list projection only: empty group name,
    /// roster size 2, and a persisted member-index hit for `peer_account_id_hex`.
    /// It does not transfer named chats, 3+ member chats, or Direct chats with
    /// a different peer, and it does not hydrate last-message display names.
    pub fn direct_conversation_candidates(
        &self,
        label: &str,
        peer_account_id_hex: &str,
    ) -> Result<Vec<ChatListRow>, AppError> {
        let account = self.account_home().account(label)?;
        self.ensure_account_state(&account.label)?;
        self.ensure_chat_list_projection(&account)?;
        Ok(self
            .account_storage(&account.label)?
            .direct_conversation_candidate_rows(peer_account_id_hex)?)
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

    /// Per-account unread aggregate for the account-switcher and application
    /// badge (mdk#461, mdk#1460). Each account's count is read from its
    /// materialized `chat_list_rows` projection (a single grouped
    /// `COUNT`/`SUM`), so this does not require switching into, or loading a
    /// full session/timeline for, any account — non-active accounts are
    /// reported too. `attention_only_conversations` covers pending invitations
    /// and manual-only unread rows without overlapping unread-message totals.
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
            attention_only_conversations: total.attention_only_conversations,
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

    /// Storage-owned `account_groups.self_membership` for roster and chat-list
    /// reads. In-memory `AppClient.state.groups` may lag after a local leave or
    /// observed self-eviction because those paths write storage directly.
    pub(crate) fn stored_group_self_membership(
        &self,
        label: &str,
        group_id_hex: &str,
    ) -> Result<Option<SelfMembership>, AppError> {
        self.ensure_account_state(label)?;
        Ok(self
            .account_storage(label)?
            .group_self_membership(group_id_hex)?)
    }

    pub(crate) fn account_group_self_memberships(
        &self,
        label: &str,
    ) -> Result<std::collections::HashMap<String, SelfMembership>, AppError> {
        self.ensure_account_state(label)?;
        Ok(self
            .account_storage(label)?
            .account_group_self_memberships()?)
    }

    pub(crate) fn arm_epoch_backfill_intents(
        &self,
        label: &str,
        intents: &[storage_sqlite::StoredEpochBackfillIntent],
    ) -> Result<(), AppError> {
        self.ensure_account_state(label)?;
        self.account_storage(label)?
            .arm_epoch_backfill_intents(intents)?;
        Ok(())
    }

    pub(crate) fn pending_epoch_backfill_intents(
        &self,
        label: &str,
    ) -> Result<Vec<storage_sqlite::StoredEpochBackfillIntent>, AppError> {
        self.ensure_account_state(label)?;
        Ok(self
            .account_storage(label)?
            .pending_epoch_backfill_intents()?)
    }

    pub(crate) fn clear_epoch_backfill_intents(
        &self,
        label: &str,
        intents: &[storage_sqlite::StoredEpochBackfillIntent],
    ) -> Result<(), AppError> {
        self.ensure_account_state(label)?;
        self.account_storage(label)?
            .clear_epoch_backfill_intents(intents)?;
        Ok(())
    }

    pub(crate) fn record_epoch_stall_evidence(
        &self,
        label: &str,
        evidence: &[storage_sqlite::StoredEpochStallEvidence],
    ) -> Result<(), AppError> {
        self.ensure_account_state(label)?;
        self.account_storage(label)?
            .record_epoch_stall_evidence(evidence)?;
        Ok(())
    }

    pub(crate) fn epoch_stall_evidence(
        &self,
        label: &str,
    ) -> Result<Vec<storage_sqlite::StoredEpochStallEvidence>, AppError> {
        self.ensure_account_state(label)?;
        Ok(self.account_storage(label)?.epoch_stall_evidence()?)
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

    /// Test seam: empty the peer index and clear its completion marker so the
    /// next account-worker open looks like the first open after migration 50.
    #[cfg(any(test, feature = "test-policy-overrides"))]
    pub fn reset_direct_conversation_members_backfill_for_test(
        &self,
        account_ref: &str,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .reset_direct_conversation_members_backfill(
                DIRECT_CONVERSATION_MEMBERS_BACKFILL_MARKER,
            )?;
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

    /// Group invites still pending the local device's confirmation decision.
    ///
    /// This is the invite-policy reconciliation read (mdk#1380): unlike
    /// [`Self::groups`], it touches only the two projection columns the policy
    /// decision needs — never the seen-event window, component blobs, or
    /// disband tables — so a periodic enumeration over an idle session reads
    /// O(pending invites) rows instead of the full account projection.
    ///
    /// A row whose stored ids cannot be decoded is skipped with a privacy-safe
    /// warning (the same policy `routing_for` applies to malformed persisted
    /// group routes): one corrupt row must not disable policy reconciliation
    /// for every valid invite in the account.
    pub fn pending_group_invites(&self, label: &str) -> Result<Vec<PendingGroupInvite>, AppError> {
        self.ensure_account_state(label)?;
        let mut invites = Vec::new();
        for invite in self
            .account_storage(label)?
            .pending_confirmation_group_invites()?
        {
            let group_id_hex = invite.group_id_hex.trim().to_ascii_lowercase();
            let Ok(group_id_bytes) = hex::decode(&group_id_hex) else {
                tracing::warn!(
                    target: "marmot_app",
                    method = "pending_group_invites",
                    error_kind = "invalid_persisted_group_record",
                    "skipping malformed persisted pending invite",
                );
                continue;
            };
            let welcomer = match invite.welcomer_account_id_hex.as_deref() {
                Some(welcomer) => {
                    let welcomer = welcomer.trim().to_ascii_lowercase();
                    match hex::decode(&welcomer) {
                        Ok(welcomer) => Some(MemberId::new(welcomer)),
                        Err(_) => {
                            tracing::warn!(
                                target: "marmot_app",
                                method = "pending_group_invites",
                                error_kind = "invalid_persisted_welcomer_record",
                                "skipping malformed persisted pending invite",
                            );
                            continue;
                        }
                    }
                }
                None => None,
            };
            invites.push(PendingGroupInvite {
                group_id: GroupId::new(group_id_bytes),
                welcomer,
            });
        }
        Ok(invites)
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
        self.save_state_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
            &AccountState {
                label: state.label,
                seen_events: Vec::new(),
                last_transport_timestamp: state.last_transport_timestamp,
                groups: vec![group.clone()],
            },
            &[],
            &[],
        )?;
        Ok(group)
    }

    #[cfg(test)]
    fn open_account(
        &self,
        label: &str,
        relay_plane: &MarmotRelayPlane,
        defer_group_hydration: bool,
    ) -> Result<OpenAppAccount, AppError> {
        let account = self.account_home().account(label)?;
        let session_admission =
            self.capture_account_session_admission(&account.label, &account.account_id_hex)?;
        self.open_account_with_admission(
            &account.label,
            relay_plane,
            defer_group_hydration,
            AccountSessionAdmission::Active(session_admission),
        )
    }

    fn open_account_with_admission(
        &self,
        label: &str,
        relay_plane: &MarmotRelayPlane,
        defer_group_hydration: bool,
        session_admission: AccountSessionAdmission,
    ) -> Result<OpenAppAccount, AppError> {
        let account = self.account_home().account(label)?;
        let admitted_account_id_hex = match &session_admission {
            AccountSessionAdmission::Active(token) => &token.account_id_hex,
            AccountSessionAdmission::Teardown(token) => &token.account_id_hex,
        };
        if account.account_id_hex != *admitted_account_id_hex
            || !self.account_open_admission_is_current(&account.label, &session_admission)
        {
            return Err(AppError::AccountWorkerBusy);
        }
        // Account refs may be labels, hex pubkeys, or npubs. Ownership is keyed
        // by the canonical stored label so aliases cannot open a second engine.
        let label = account.label.as_str();
        let session_guard = self.acquire_account_session(label)?;
        let state = self.load_state(label)?;
        let delivery_overflow_recovery = self
            .account_storage(label)?
            .account_delivery_recovery(label)?;
        let delivery_overflow_recovery_pending = delivery_overflow_recovery.is_some();
        let delivery_overflow_recovery_marker_token =
            delivery_overflow_recovery.map(|recovery| recovery.marker_token);
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
        // `<account_dir>/audit-<engine_id>-v3.jsonl`. The v3 schema contains
        // privacy-safe derived values only: obfuscated identifiers, digests,
        // lengths, counts, reduced convergence data, and typed outcomes.
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
        self.canonicalize_key_package_lifecycle_targets_before_session_open(label)?;
        // `AccountDeviceSession` opens its own SQLCipher connection rather than
        // cloning `account_storages`. Hold storage-open admission until that
        // connection is published into the terminal-close registry: the close
        // writer must see either no connection or a closeable handle for every
        // successfully opened session.
        let storage_lifecycle = self.begin_storage_open("account session storage")?;
        let session =
            AccountDeviceSession::open(session_config).map_err(external_signer_session_error)?;
        self.account_session_storages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(label.to_owned(), session.storage_handle());
        // Do not carry the read guard into `routing_for`: its database helpers
        // take their own storage-open admission, and a pending close writer
        // could otherwise turn that nested read into a self-deadlock. The
        // session is now published, so terminal close can safely proceed.
        drop(storage_lifecycle);

        if !self.account_open_admission_is_current(label, &session_admission) {
            return Err(AppError::AccountWorkerBusy);
        }

        let publish_client =
            self.relay_client_for_account_id(&account.account_id_hex, nostr_signer.clone());
        let recovery_storage = self.account_storage(label)?;
        let recovery_label = label.to_owned();
        let recovery_marker: relay_plane::AccountDeliveryRecoveryMarker =
            Arc::new(move |marker_token, dropped| {
                recovery_storage
                    .mark_account_delivery_recovery(&recovery_label, marker_token, dropped)
                    .map_err(|error| {
                        if error.is_closed() {
                            relay_plane::AccountDeliveryRecoveryMarkerError::Closed
                        } else {
                            relay_plane::AccountDeliveryRecoveryMarkerError::Retryable
                        }
                    })
            });
        let adapter = relay_plane.account_adapter_with_recovery_marker(
            account_id.clone(),
            publish_client,
            Some(recovery_marker),
        );
        self.account_session_adapters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(label.to_owned(), adapter.clone());

        let key_packages = AppKeyPackagePublisher {
            app: self.clone(),
            account_label: label.to_owned(),
            signer: signer.clone(),
            session_admission: session_admission.clone(),
        };
        let routing = self.routing_for(&state)?;
        let mut runtime =
            AccountDeviceRuntime::new(session, adapter.clone(), routing.clone(), key_packages);
        // Schema-51 retained only one overwritten Welcome-consumption marker.
        // Resolve that one-time ambiguity synchronously under the newly opened
        // account writer before transport activation can ingest another Welcome
        // and destroy the detectable legacy shape.
        runtime.sweep_expired_key_package_private_material()?;
        Ok(OpenAppAccount {
            runtime,
            session_guard,
            session_admission,
            adapter,
            routing,
            state,
            delivery_overflow_recovery_pending,
            delivery_overflow_recovery_marker_token,
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
            storages: self.account_session_storages.clone(),
            adapters: self.account_session_adapters.clone(),
        })
    }

    fn account_session_adapter(&self, label: &str) -> Option<MarmotRelayPlaneAccountAdapter> {
        self.account_session_adapters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(label)
            .cloned()
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

    /// Durably admit an exact non-current cache revision before any deletion or
    /// replacement publication can escape. Historical endpoints come only from
    /// the account-private observation of this exact event; current routing is
    /// never substituted. Unknown provenance, malformed JSON, invalid ids, and
    /// capacity-deferred endpoints keep both the cache and cutover pending.
    fn retire_cached_non_current_key_package(
        &self,
        label: &str,
        runtime: &mut AppRuntime,
    ) -> CachedKeyPackageRetirementAdmission {
        let path = self.key_package_record_path(label);
        let record = match read_json::<KeyPackageRecord>(&path) {
            Ok(record) => record,
            Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return CachedKeyPackageRetirementAdmission {
                    complete: true,
                    event_id: None,
                };
            }
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "retire_cached_non_current_key_package",
                    error_kind = error.privacy_safe_kind(),
                    "could not classify cached key package after strict cutover"
                );
                let _ = self.mark_key_package_cutover_replacement_pending(label);
                return CachedKeyPackageRetirementAdmission {
                    complete: false,
                    event_id: None,
                };
            }
        };
        let current_metadata = key_package_from_hex_with_optional_source(
            &record.key_package_hex,
            &record.key_package_event_id,
        )
        .ok()
        .and_then(|key_package| key_package_metadata(&key_package).ok());
        let account = match self.account_home().account(label) {
            Ok(account) => account,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "retire_cached_non_current_key_package",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not resolve cached key package account"
                );
                return CachedKeyPackageRetirementAdmission {
                    complete: false,
                    event_id: None,
                };
            }
        };
        let lifecycle = runtime.key_package_maintenance_status().ok().flatten();
        let parsed_event_id = (!record.key_package_event_id.is_empty()).then(|| {
            parse_key_package_event_id_hex(&record.key_package_event_id).and_then(|event_id_hex| {
                hex::decode(event_id_hex)
                    .map(MessageId::new)
                    .map_err(AppError::from)
            })
        });
        let (exact_cached_endpoints, exact_cached_created_at) = parsed_event_id
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|_| {
                self.cached_key_package_provenance(
                    &account,
                    &record,
                    (!record.key_package_ref_hex.is_empty())
                        .then_some(record.key_package_ref_hex.as_str()),
                )
            })
            .unwrap_or_default();
        let cache_matches_local_coordinate = lifecycle.as_ref().is_some_and(|lifecycle| {
            !lifecycle.stable_slot_id.is_empty()
                && lifecycle.stable_slot_id == record.key_package_id
                && record.account_id_hex == account.account_id_hex
        });
        if current_metadata.as_ref().is_some_and(|metadata| {
            self.key_package_metadata_matches_current_support(metadata)
                && metadata.credential_identity_hex == account.account_id_hex
                && (record.key_package_ref_hex.is_empty()
                    || record
                        .key_package_ref_hex
                        .eq_ignore_ascii_case(&metadata.key_package_ref_hex))
        }) && cache_matches_local_coordinate
            && let Some(lifecycle) = lifecycle.as_ref()
        {
            if parsed_event_id.is_none() {
                let matches_current_ref = current_metadata.as_ref().is_some_and(|metadata| {
                    lifecycle
                        .current_key_package_ref
                        .as_ref()
                        .is_some_and(|current_ref| {
                            hex::encode(current_ref)
                                .eq_ignore_ascii_case(&metadata.key_package_ref_hex)
                        })
                });
                if matches_current_ref {
                    return CachedKeyPackageRetirementAdmission {
                        complete: true,
                        event_id: None,
                    };
                }
            } else if let Some(Ok(event_id)) = parsed_event_id.as_ref() {
                let cached_endpoints_are_covered =
                    |targets: &[cgka_traits::TransportFanoutTarget]| {
                        exact_cached_endpoints.iter().all(|endpoint| {
                            targets.iter().any(|target| target.endpoint == *endpoint)
                        })
                    };
                let signed_live_exact = lifecycle
                    .authored_signed_event
                    .as_ref()
                    .is_some_and(|artifact| artifact.id == *event_id)
                    && !lifecycle.publication_targets.is_empty()
                    && cached_endpoints_are_covered(&lifecycle.publication_targets);
                let imported_live_exact = lifecycle.authored_event_id.as_ref() == Some(event_id)
                    && !exact_cached_endpoints.is_empty()
                    && exact_cached_endpoints.iter().all(|endpoint| {
                        lifecycle
                            .publication_targets
                            .iter()
                            .any(|target| target.endpoint == *endpoint)
                    });
                let pending_exact = lifecycle
                    .pending_replacement
                    .as_ref()
                    .and_then(|pending| {
                        pending
                            .signed_event
                            .as_ref()
                            .map(|artifact| (pending, artifact))
                    })
                    .is_some_and(|(pending, artifact)| {
                        artifact.id == *event_id
                            && !pending.targets.is_empty()
                            && cached_endpoints_are_covered(&pending.targets)
                    });
                if signed_live_exact || imported_live_exact || pending_exact {
                    return CachedKeyPackageRetirementAdmission {
                        complete: true,
                        event_id: None,
                    };
                }
                let exact_retired = lifecycle
                    .retired_publications_pending_deletion
                    .iter()
                    .find(|retired| retired.event_id == *event_id);
                if exact_retired.is_some_and(|retired| {
                    !retired.deletion_targets.is_empty()
                        && cached_endpoints_are_covered(&retired.deletion_targets)
                }) {
                    return CachedKeyPackageRetirementAdmission {
                        complete: true,
                        event_id: Some(event_id.clone()),
                    };
                }
            }
        }
        if !self.mark_key_package_cutover_replacement_pending(label) {
            return CachedKeyPackageRetirementAdmission {
                complete: false,
                event_id: None,
            };
        }

        if record.key_package_event_id.is_empty() {
            let complete = match fs::remove_file(path) {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(error) => {
                    tracing::warn!(
                        target: "marmot_app::key_packages",
                        method = "retire_cached_non_current_key_package",
                        error_kind = AppError::from(error).privacy_safe_kind(),
                        "could not remove unpublished non-current key package cache"
                    );
                    false
                }
            };
            return CachedKeyPackageRetirementAdmission {
                complete,
                event_id: None,
            };
        }
        let event_id = match parsed_event_id.expect("non-empty cached event id was parsed") {
            Ok(event_id) => event_id,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "retire_cached_non_current_key_package",
                    error_kind = error.privacy_safe_kind(),
                    "could not durably admit cached key package event with invalid identity"
                );
                return CachedKeyPackageRetirementAdmission {
                    complete: false,
                    event_id: None,
                };
            }
        };
        if record.account_id_hex != account.account_id_hex {
            return CachedKeyPackageRetirementAdmission {
                complete: false,
                event_id: Some(event_id),
            };
        }
        let historical_endpoints = exact_cached_endpoints;
        if record.key_package_id.is_empty() || historical_endpoints.is_empty() {
            return CachedKeyPackageRetirementAdmission {
                complete: false,
                event_id: Some(event_id),
            };
        }
        let complete = match runtime.journal_discovered_unparsed_key_package_publication(
            record.key_package_id.clone(),
            event_id.clone(),
            Timestamp(
                exact_cached_created_at
                    .map(|cached| cached.max(record.published_at))
                    .unwrap_or(record.published_at),
            ),
            historical_endpoints,
        ) {
            Ok((_admitted, deferred)) => deferred.is_empty(),
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "retire_cached_non_current_key_package",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not durably admit cached key package deletion liability"
                );
                false
            }
        };
        CachedKeyPackageRetirementAdmission {
            complete,
            event_id: Some(event_id),
        }
    }

    fn remove_terminal_cached_key_package_record(&self, label: &str, event_id: &MessageId) {
        let Ok(Some(lifecycle)) = self
            .account_storage(label)
            .and_then(|storage| storage.key_package_lifecycle().map_err(AppError::from))
        else {
            // Failure to prove terminal durable state must retain the only
            // local exact-event cache rather than turn a read error into loss.
            return;
        };
        if lifecycle
            .retired_publications_pending_deletion
            .iter()
            .any(|retired| retired.event_id == *event_id)
        {
            return;
        }
        let path = self.key_package_record_path(label);
        let Ok(record) = read_json::<KeyPackageRecord>(&path) else {
            return;
        };
        let Ok(record_event_id_hex) = parse_key_package_event_id_hex(&record.key_package_event_id)
        else {
            return;
        };
        if record_event_id_hex != hex::encode(event_id.as_slice()) {
            // A concurrent cache refresh may already have installed another
            // exact revision. Never remove it while finalizing this one.
            return;
        }
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                target: "marmot_app::key_packages",
                method = "remove_terminal_cached_key_package_record",
                error_kind = AppError::from(error).privacy_safe_kind(),
                "could not remove terminal cached key package record"
            ),
        }
    }

    fn journal_unparsed_relay_key_package_revision(
        &self,
        runtime: &mut AppRuntime,
        stable_slot_id: &str,
        event_id_hex: &str,
        authored_created_at: u64,
        source_endpoints: Vec<TransportEndpoint>,
    ) -> Result<(usize, usize), AppError> {
        let event_id_hex = parse_key_package_event_id_hex(event_id_hex)?;
        let event_id = MessageId::new(hex::decode(event_id_hex)?);
        let (admitted, deferred) = runtime
            .journal_discovered_unparsed_key_package_publication(
                stable_slot_id.to_owned(),
                event_id,
                Timestamp(authored_created_at),
                source_endpoints,
            )
            .map_err(AppError::from)?;
        Ok((admitted.len(), deferred.len()))
    }

    fn admit_relay_key_package_records(
        &self,
        label: &str,
        runtime: &mut AppRuntime,
        records: Vec<RelayEventRecord>,
        delete_without_successor: bool,
    ) -> Result<KeyPackageRelayAdmissionSummary, AppError> {
        let lifecycle = runtime
            .key_package_maintenance_status()
            .map_err(AppError::from)?
            .filter(|lifecycle| !lifecycle.stable_slot_id.is_empty())
            .ok_or_else(|| {
                AppError::Publish(
                    "relay key package retirement requires lifecycle slot authority".into(),
                )
            })?;
        let stable_slot_id = lifecycle.stable_slot_id.clone();
        let mut live_event_ids = HashSet::new();
        if let Some(event_id) = lifecycle
            .authored_event_id
            .as_ref()
            .filter(|event_id| !lifecycle.deleted_live_revision_event_ids.contains(event_id))
        {
            live_event_ids.insert(hex::encode(event_id.as_slice()));
        }
        if let Some(artifact) = lifecycle.authored_signed_event.as_ref().filter(|artifact| {
            !lifecycle
                .deleted_live_revision_event_ids
                .contains(&artifact.id)
        }) {
            live_event_ids.insert(hex::encode(artifact.id.as_slice()));
        }
        if let Some(artifact) = lifecycle
            .pending_replacement
            .as_ref()
            .and_then(|pending| pending.signed_event.as_ref())
            .filter(|artifact| {
                !lifecycle
                    .deleted_live_revision_event_ids
                    .contains(&artifact.id)
            })
        {
            live_event_ids.insert(hex::encode(artifact.id.as_slice()));
        }
        let local_live_artifact_created_at = lifecycle
            .authored_signed_event
            .as_ref()
            .map(|artifact| artifact.created_at.0)
            .into_iter()
            .chain(
                lifecycle
                    .pending_replacement
                    .as_ref()
                    .and_then(|pending| pending.signed_event.as_ref())
                    .map(|artifact| artifact.created_at.0),
            )
            .max();

        let mut summary = KeyPackageRelayAdmissionSummary::default();
        for record in records {
            let event_id = record.event.id.clone();
            let authored_created_at = record.event.created_at;
            let raw_endpoints = record.endpoints.clone();
            if record.event.tag_value("d") != Some(stable_slot_id.as_str()) {
                // One Nostr account can have several device-local `d` slots.
                // An account-wide relay query must not turn a sibling device's
                // revision into deletion work for this lifecycle.
                continue;
            }
            if live_event_ids.contains(&event_id) {
                let observed = hex::decode(&event_id)
                    .map(MessageId::new)
                    .map_err(AppError::from)
                    .and_then(|event_id| {
                        runtime
                            .observe_live_key_package_publication(
                                stable_slot_id.clone(),
                                &event_id,
                                Timestamp(authored_created_at),
                                raw_endpoints.clone(),
                            )
                            .map_err(AppError::from)
                    });
                match observed {
                    Ok((_admitted, deferred)) if deferred.is_empty() => {}
                    Ok((_admitted, deferred)) => {
                        summary.deferred_endpoint_count = summary
                            .deferred_endpoint_count
                            .saturating_add(deferred.len());
                        summary.admission_failure_count += 1;
                    }
                    Err(_) => summary.admission_failure_count += 1,
                }
                continue;
            }

            match key_package_from_record(record) {
                Ok(fetched) => {
                    if fetched.key_package_id != stable_slot_id {
                        continue;
                    }
                    let metadata = match key_package_metadata(&fetched.key_package) {
                        Ok(metadata) => metadata,
                        Err(_) => {
                            if !self.mark_key_package_cutover_replacement_pending(label) {
                                summary.admission_failure_count += 1;
                            }
                            summary.non_current_event_count += 1;
                            match self.journal_unparsed_relay_key_package_revision(
                                runtime,
                                &stable_slot_id,
                                &fetched.key_package_event_id,
                                fetched.created_at,
                                fetched
                                    .source_relays
                                    .into_iter()
                                    .map(TransportEndpoint)
                                    .collect(),
                            ) {
                                Ok((_admitted, deferred)) => {
                                    summary.deferred_endpoint_count =
                                        summary.deferred_endpoint_count.saturating_add(deferred);
                                    if deferred > 0 {
                                        summary.admission_failure_count += 1;
                                    }
                                }
                                Err(_) => summary.admission_failure_count += 1,
                            }
                            continue;
                        }
                    };
                    // NIP-33 resolves equal timestamps by event-id tie-break.
                    // This is already a different exact id, so equality is not
                    // enough to prove the local artifact will supersede it.
                    let discovered_can_compete_with_local_artifact = local_live_artifact_created_at
                        .is_none_or(|created_at| fetched.created_at >= created_at);
                    if (!self.key_package_metadata_matches_current_support(&metadata)
                        || discovered_can_compete_with_local_artifact)
                        && !self.mark_key_package_cutover_replacement_pending(label)
                    {
                        summary.admission_failure_count += 1;
                    }
                    let event_id_hex =
                        match parse_key_package_event_id_hex(&fetched.key_package_event_id) {
                            Ok(event_id_hex) => event_id_hex,
                            Err(_) => {
                                summary.admission_failure_count += 1;
                                continue;
                            }
                        };
                    let key_package_ref = match hex::decode(&fetched.key_package_ref_hex) {
                        Ok(key_package_ref) => key_package_ref,
                        Err(_) => {
                            summary.admission_failure_count += 1;
                            continue;
                        }
                    };
                    let endpoints = match self.sanitize_key_package_deletion_endpoints(
                        fetched
                            .source_relays
                            .into_iter()
                            .map(TransportEndpoint)
                            .collect(),
                    ) {
                        Ok(endpoints) if !endpoints.is_empty() => endpoints,
                        Ok(_) | Err(_) => {
                            summary.admission_failure_count += 1;
                            continue;
                        }
                    };
                    let event_id = MessageId::new(
                        hex::decode(event_id_hex)
                            .expect("validated key package event id remains hex"),
                    );
                    match runtime.journal_discovered_retired_key_package_publication_with_policy(
                        stable_slot_id.clone(),
                        event_id,
                        Timestamp(fetched.created_at),
                        key_package_ref,
                        Timestamp(metadata.not_after),
                        endpoints,
                        delete_without_successor,
                    ) {
                        Ok((_admitted, deferred)) => {
                            summary.discovered_current_revision_count += 1;
                            summary.deferred_endpoint_count = summary
                                .deferred_endpoint_count
                                .saturating_add(deferred.len());
                            if !deferred.is_empty() {
                                summary.admission_failure_count += 1;
                            }
                        }
                        Err(_) => summary.admission_failure_count += 1,
                    }
                }
                Err(_) => {
                    if !self.mark_key_package_cutover_replacement_pending(label) {
                        summary.admission_failure_count += 1;
                    }
                    summary.non_current_event_count += 1;
                    match self.journal_unparsed_relay_key_package_revision(
                        runtime,
                        &stable_slot_id,
                        &event_id,
                        authored_created_at,
                        raw_endpoints,
                    ) {
                        Ok((_admitted, deferred)) => {
                            summary.deferred_endpoint_count =
                                summary.deferred_endpoint_count.saturating_add(deferred);
                            if deferred > 0 {
                                summary.admission_failure_count += 1;
                            }
                        }
                        Err(_) => summary.admission_failure_count += 1,
                    }
                }
            }
        }
        Ok(summary)
    }

    fn retired_key_package_deletion_target_endpoints(
        runtime: &AppRuntime,
    ) -> Result<Vec<TransportEndpoint>, AppError> {
        let mut endpoints = runtime
            .key_package_maintenance_status()
            .map_err(AppError::from)?
            .into_iter()
            .flat_map(|lifecycle| lifecycle.retired_publications_pending_deletion)
            .flat_map(|retired| retired.deletion_targets)
            .map(|target| target.endpoint)
            .collect::<Vec<_>>();
        endpoints.sort();
        endpoints.dedup();
        Ok(endpoints)
    }

    /// Scan the account's authoritative KeyPackage relays for revisions in this
    /// device's stable slot. Valid current-profile predecessors are durably
    /// journaled before any deletion I/O, then retried through the account
    /// runtime so successor eligibility and per-endpoint receipts remain
    /// authoritative. Sibling-device slots and the exact live current/pending
    /// ids are never classified as local retirement work.
    async fn retire_relay_non_current_key_packages(
        &self,
        label: &str,
        runtime: &mut AppRuntime,
    ) -> bool {
        self.retire_relay_non_current_key_packages_with_policy(label, runtime, false)
            .await
    }

    async fn retire_relay_non_current_key_packages_for_teardown(
        &self,
        label: &str,
        runtime: &mut AppRuntime,
    ) -> bool {
        self.retire_relay_non_current_key_packages_with_policy(label, runtime, true)
            .await
    }

    async fn retire_relay_non_current_key_packages_with_policy(
        &self,
        label: &str,
        runtime: &mut AppRuntime,
        authorize_without_successor: bool,
    ) -> bool {
        let destructive_cleanup_was_durable = match self.key_package_teardown_cleanup_pending(label)
        {
            Ok(pending) => pending,
            Err(_) => return false,
        };
        let authorize_without_successor =
            authorize_without_successor || destructive_cleanup_was_durable;
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
        let source_relays = match self.sanitize_key_package_deletion_endpoints(source_relays) {
            Ok(source_relays) if !source_relays.is_empty() => source_relays,
            Ok(_) | Err(_) => return false,
        };
        let history_lock = self.key_package_history_lock(label);
        let history_guard = history_lock.lock().await;
        let lifecycle = match runtime.key_package_maintenance_status() {
            Ok(Some(lifecycle)) if !lifecycle.stable_slot_id.is_empty() => lifecycle,
            Ok(_) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "retire_relay_non_current_key_packages",
                    error_kind = "missing_stable_slot",
                    "deferred relay key package retirement scan without lifecycle slot authority"
                );
                return false;
            }
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "retire_relay_non_current_key_packages",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not read lifecycle authority for relay key package retirement"
                );
                return false;
            }
        };
        if authorize_without_successor
            && runtime
                .authorize_teardown_key_package_deletions_without_successor()
                .is_err()
        {
            return false;
        }
        let known_history_relays = match self.key_package_lifecycle_history_endpoints(&lifecycle) {
            Ok(endpoints) => endpoints,
            Err(_) => return false,
        };
        let durable_history_relays = match self.key_package_cutover_relay_history(label) {
            Ok(endpoints) => endpoints,
            Err(_) => return false,
        };
        if self.key_package_cutover_scan_complete_for_relays(label, &source_relays) {
            // A fresh-account proof is endpoint-independent only until the
            // account's first completed open. Bind it to the then-current
            // authoritative set so later NIP-65 additions/re-additions re-arm
            // the scan instead of inheriting the one-time creation proof.
            if runtime
                .finalize_key_package_cutover_consumption_evidence()
                .is_err()
            {
                return false;
            }
            let Ok(_root_mutation) =
                self.begin_root_mutation("bind fresh KeyPackage cutover scan marker")
            else {
                return false;
            };
            let proof_relays = source_relays
                .iter()
                .cloned()
                .chain(known_history_relays.iter().cloned())
                .collect::<BTreeSet<_>>();
            return self
                .mark_key_package_cutover_scan_complete_for_relays(
                    label,
                    &source_relays,
                    &proof_relays,
                )
                .is_ok();
        }
        {
            let Ok(_root_mutation) =
                self.begin_root_mutation("invalidate incomplete KeyPackage history proof")
            else {
                return false;
            };
            let _frontier_mutation = self
                .key_package_frontier_mutation_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self
                .invalidate_key_package_cutover_scan_marker(label)
                .is_err()
            {
                return false;
            }
        }
        let mut relay_frontier = match self.key_package_cutover_relay_frontier(label) {
            Ok(frontier) => frontier,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "retire_relay_non_current_key_packages",
                    error_kind = error.privacy_safe_kind(),
                    "could not read the durable KeyPackage relay-history frontier"
                );
                return false;
            }
        };
        // An aggregate directory fetch is intentionally partial-success: if
        // one relay connects, callers can still use what it returned. That is
        // not strong enough for a durable scan-complete proof. Query each
        // authoritative relay and every crash-recovery frontier relay
        // independently and in parallel, requiring this invocation's own EOSE
        // from each endpoint. A historical frontier relay can be absent from
        // the current NIP-65 route and must not be forgotten for that reason.
        let stable_slot_id = lifecycle.stable_slot_id.clone();
        let mut live_event_ids = HashSet::new();
        if let Some(event_id) = lifecycle
            .authored_event_id
            .as_ref()
            .filter(|event_id| !lifecycle.deleted_live_revision_event_ids.contains(event_id))
        {
            live_event_ids.insert(hex::encode(event_id.as_slice()));
        }
        if let Some(artifact) = lifecycle.authored_signed_event.as_ref().filter(|artifact| {
            !lifecycle
                .deleted_live_revision_event_ids
                .contains(&artifact.id)
        }) {
            live_event_ids.insert(hex::encode(artifact.id.as_slice()));
        }
        if let Some(artifact) = lifecycle
            .pending_replacement
            .as_ref()
            .and_then(|pending| pending.signed_event.as_ref())
            .filter(|artifact| {
                !lifecycle
                    .deleted_live_revision_event_ids
                    .contains(&artifact.id)
            })
        {
            live_event_ids.insert(hex::encode(artifact.id.as_slice()));
        }
        let local_live_artifact_created_at = lifecycle
            .authored_signed_event
            .as_ref()
            .map(|artifact| artifact.created_at.0)
            .into_iter()
            .chain(
                lifecycle
                    .pending_replacement
                    .as_ref()
                    .and_then(|pending| pending.signed_event.as_ref())
                    .map(|artifact| artifact.created_at.0),
            )
            .max();
        let scan_relays = source_relays
            .iter()
            .cloned()
            .chain(relay_frontier.iter().cloned())
            // A settled historical relay carries its last strict short-page
            // proof in the monotonic ledger. Do not make every later route
            // edit depend on an offline retired relay forever. Current source
            // relays and any newly armed deletion frontier are always scanned
            // again; lifecycle-only history needs a fresh scan only until its
            // first proof is durably transferred into that ledger.
            .chain(
                known_history_relays
                    .difference(&durable_history_relays)
                    .cloned(),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let per_relay_records = futures::future::join_all(scan_relays.iter().map(|endpoint| {
            self.fetch_key_package_events_for_account_id_with_limit_strict(
                &account.account_id_hex,
                std::slice::from_ref(endpoint),
                KEY_PACKAGE_CUTOVER_RELAY_SCAN_LIMIT,
            )
        }))
        .await;
        let mut records = Vec::new();
        let mut all_required_relays_scanned = true;
        let mut scan_was_truncated = false;
        let mut frontier_clear_candidates = BTreeSet::new();
        let mut scanned_history_relays = durable_history_relays;
        for (endpoint, fetched) in scan_relays.iter().zip(per_relay_records) {
            let relay_records = match fetched {
                Ok(records) => records,
                Err(error) => {
                    all_required_relays_scanned = false;
                    tracing::warn!(
                        target: "marmot_app::key_packages",
                        method = "retire_relay_non_current_key_packages",
                        error_kind = error.privacy_safe_kind(),
                        "required relay did not complete a strict EOSE scan; processing reachable relay revisions while retaining the cutover gate"
                    );
                    continue;
                }
            };
            let page_was_truncated = relay_records.len() >= KEY_PACKAGE_CUTOVER_RELAY_SCAN_LIMIT;
            scan_was_truncated |= page_was_truncated;
            if !page_was_truncated {
                scanned_history_relays.insert(endpoint.clone());
            }
            if relay_frontier.contains(endpoint) && !page_was_truncated {
                frontier_clear_candidates.insert(endpoint.clone());
            }
            records.extend(relay_records);
        }
        let mut non_current_event_count = 0usize;
        let mut discovered_current_revision_count = 0usize;
        let mut deferred_endpoint_count = 0usize;
        let mut admission_failure_count = 0usize;
        for record in records {
            let event_id = record.event.id.clone();
            let authored_created_at = record.event.created_at;
            let raw_endpoints = record.endpoints.clone();
            if record.event.tag_value("d") != Some(stable_slot_id.as_str()) {
                // One Nostr account can have several device-local `d` slots.
                // An account-wide relay query must not turn a sibling device's
                // revision into deletion work for this lifecycle.
                continue;
            }
            if live_event_ids.contains(&event_id) {
                let observed = hex::decode(&event_id)
                    .map(MessageId::new)
                    .map_err(AppError::from)
                    .and_then(|event_id| {
                        runtime
                            .observe_live_key_package_publication(
                                stable_slot_id.clone(),
                                &event_id,
                                Timestamp(authored_created_at),
                                raw_endpoints.clone(),
                            )
                            .map_err(AppError::from)
                    });
                match observed {
                    Ok((_admitted, deferred)) if deferred.is_empty() => {}
                    Ok((_admitted, deferred)) => {
                        deferred_endpoint_count =
                            deferred_endpoint_count.saturating_add(deferred.len());
                        admission_failure_count += 1;
                    }
                    Err(_) => admission_failure_count += 1,
                }
                continue;
            }

            match key_package_from_record(record) {
                Ok(fetched) => {
                    if fetched.key_package_id != stable_slot_id {
                        continue;
                    }
                    let metadata = match key_package_metadata(&fetched.key_package) {
                        Ok(metadata) => metadata,
                        Err(_) => {
                            if !self.mark_key_package_cutover_replacement_pending(label) {
                                admission_failure_count += 1;
                            }
                            non_current_event_count += 1;
                            match self.journal_unparsed_relay_key_package_revision(
                                runtime,
                                &stable_slot_id,
                                &fetched.key_package_event_id,
                                fetched.created_at,
                                fetched
                                    .source_relays
                                    .into_iter()
                                    .map(TransportEndpoint)
                                    .collect(),
                            ) {
                                Ok((_admitted, deferred)) => {
                                    deferred_endpoint_count =
                                        deferred_endpoint_count.saturating_add(deferred);
                                    if deferred > 0 {
                                        admission_failure_count += 1;
                                    }
                                }
                                Err(_) => admission_failure_count += 1,
                            }
                            continue;
                        }
                    };
                    // NIP-33 resolves equal timestamps by event-id tie-break.
                    // This is already a different exact id, so equality is not
                    // enough to prove the local artifact will supersede it.
                    let discovered_can_compete_with_local_artifact = local_live_artifact_created_at
                        .is_none_or(|created_at| fetched.created_at >= created_at);
                    if (!self.key_package_metadata_matches_current_support(&metadata)
                        || discovered_can_compete_with_local_artifact)
                        && !self.mark_key_package_cutover_replacement_pending(label)
                    {
                        admission_failure_count += 1;
                    }
                    let event_id_hex =
                        match parse_key_package_event_id_hex(&fetched.key_package_event_id) {
                            Ok(event_id_hex) => event_id_hex,
                            Err(_) => {
                                admission_failure_count += 1;
                                continue;
                            }
                        };
                    let key_package_ref = match hex::decode(&fetched.key_package_ref_hex) {
                        Ok(key_package_ref) => key_package_ref,
                        Err(_) => {
                            admission_failure_count += 1;
                            continue;
                        }
                    };
                    let endpoints = match self.sanitize_key_package_deletion_endpoints(
                        fetched
                            .source_relays
                            .into_iter()
                            .map(TransportEndpoint)
                            .collect(),
                    ) {
                        Ok(endpoints) if !endpoints.is_empty() => endpoints,
                        Ok(_) | Err(_) => {
                            admission_failure_count += 1;
                            continue;
                        }
                    };
                    let event_id = MessageId::new(
                        hex::decode(event_id_hex)
                            .expect("validated key package event id remains hex"),
                    );
                    match runtime.journal_discovered_retired_key_package_publication_with_policy(
                        stable_slot_id.clone(),
                        event_id,
                        Timestamp(fetched.created_at),
                        key_package_ref,
                        Timestamp(metadata.not_after),
                        endpoints,
                        authorize_without_successor,
                    ) {
                        Ok((_admitted, deferred)) => {
                            discovered_current_revision_count += 1;
                            deferred_endpoint_count =
                                deferred_endpoint_count.saturating_add(deferred.len());
                            if !deferred.is_empty() {
                                admission_failure_count += 1;
                            }
                        }
                        Err(_) => admission_failure_count += 1,
                    }
                }
                Err(_) => {
                    if !self.mark_key_package_cutover_replacement_pending(label) {
                        admission_failure_count += 1;
                    }
                    non_current_event_count += 1;
                    match self.journal_unparsed_relay_key_package_revision(
                        runtime,
                        &stable_slot_id,
                        &event_id,
                        authored_created_at,
                        raw_endpoints,
                    ) {
                        Ok((_admitted, deferred)) => {
                            deferred_endpoint_count =
                                deferred_endpoint_count.saturating_add(deferred);
                            if deferred > 0 {
                                admission_failure_count += 1;
                            }
                        }
                        Err(_) => admission_failure_count += 1,
                    }
                }
            }
        }

        let mut summary = KeyPackageRelayAdmissionSummary {
            non_current_event_count,
            discovered_current_revision_count,
            deferred_endpoint_count,
            admission_failure_count,
        };
        if authorize_without_successor
            && runtime
                .authorize_teardown_key_package_deletions_without_successor()
                .is_err()
        {
            summary.admission_failure_count += 1;
        }

        // Move every successfully admitted strict short-page proof into a
        // monotonic ledger before clearing any crash frontier. If another
        // relay fails later, a restart still knows to include these historical
        // endpoints even after their terminal SQL liabilities are pruned.
        if summary.admission_failure_count == 0
            && self
                .extend_key_package_cutover_relay_history(label, &scanned_history_relays)
                .is_err()
        {
            summary.admission_failure_count += 1;
        }

        // A strict short-page replay discharges a frontier written by an
        // earlier process before exact deletion. If this write fails, retain
        // the in-memory frontier too so this invocation cannot manufacture a
        // completion proof that the durable state does not carry.
        if all_required_relays_scanned
            && summary.admission_failure_count == 0
            && !scan_was_truncated
            && !frontier_clear_candidates.is_empty()
        {
            match self.remove_key_package_cutover_relay_frontier_endpoints(
                label,
                &frontier_clear_candidates,
            ) {
                Ok(frontier) => relay_frontier = frontier,
                Err(_) => summary.admission_failure_count += 1,
            }
        }
        // Deletion takes this same lock around frontier arm and network I/O.
        // Release before the runtime invokes the publisher, then reacquire for
        // the strict post-delete replay and conditional discharge.
        drop(history_guard);

        // A relay may expose parameterized-replaceable history one winner at
        // a time. The AppKeyPackagePublisher deletion boundary durably arms
        // the exact canonical endpoint before kind-5 I/O, including for
        // ordinary maintenance outside this cutover. After every attempt,
        // strictly rescan the complete durable frontier: an error or explicit
        // failed receipt can still be ambiguous about relay-side acceptance.
        // The bounded loop keeps one open responsive; exhaustion leaves the
        // publication gate restart-readable.
        let mut retry_failure_count = 0usize;
        let mut peeling_failed = false;
        let mut peeling_exhausted = false;
        let mut uncovered_eligible_deletion = false;
        for pass_index in 0..KEY_PACKAGE_CUTOVER_MAX_DELETION_PASSES {
            let pending_endpoints =
                match Self::retired_key_package_deletion_target_endpoints(runtime) {
                    Ok(endpoints) => endpoints,
                    Err(_) => {
                        peeling_failed = true;
                        break;
                    }
                };
            if pending_endpoints.is_empty() && relay_frontier.is_empty() {
                uncovered_eligible_deletion = false;
                break;
            }

            let (report_failed, terminal_endpoints) = if pending_endpoints.is_empty() {
                (false, BTreeSet::new())
            } else {
                match runtime
                    .retry_retired_key_package_deletions_once_reported()
                    .await
                {
                    Ok(report) => {
                        uncovered_eligible_deletion = report.has_uncovered_eligible_deletion;
                        match self
                            .sanitize_key_package_deletion_endpoints(report.terminal_endpoints)
                        {
                            Ok(endpoints) => {
                                (false, endpoints.into_iter().collect::<BTreeSet<_>>())
                            }
                            Err(_) => {
                                peeling_failed = true;
                                break;
                            }
                        }
                    }
                    Err(_) => {
                        retry_failure_count += 1;
                        peeling_failed = true;
                        (true, BTreeSet::new())
                    }
                }
            };
            let history_guard = history_lock.lock().await;
            relay_frontier = match self.key_package_cutover_relay_frontier(label) {
                Ok(frontier) => frontier,
                Err(_) => {
                    peeling_failed = true;
                    drop(history_guard);
                    break;
                }
            };
            if !terminal_endpoints.is_subset(&relay_frontier) {
                // A terminal SQLite receipt without its pre-I/O relay intent
                // would reopen the exact crash window this frontier closes.
                peeling_failed = true;
                drop(history_guard);
                break;
            }
            if relay_frontier.is_empty() {
                drop(history_guard);
                break;
            }

            let frontier_endpoints = relay_frontier.iter().cloned().collect::<Vec<_>>();
            let refetched = futures::future::join_all(frontier_endpoints.iter().map(|endpoint| {
                self.fetch_key_package_events_for_account_id_with_limit_strict(
                    &account.account_id_hex,
                    std::slice::from_ref(endpoint),
                    KEY_PACKAGE_CUTOVER_RELAY_SCAN_LIMIT,
                )
            }))
            .await;
            let mut revealed_revision = false;
            let mut refetch_complete = true;
            let mut frontier_clear_candidates = BTreeSet::new();
            for (endpoint, fetched) in frontier_endpoints.iter().zip(refetched) {
                let records = match fetched {
                    Ok(records) => records,
                    Err(_) => {
                        refetch_complete = false;
                        continue;
                    }
                };
                let page_was_truncated = records.len() >= KEY_PACKAGE_CUTOVER_RELAY_SCAN_LIMIT;
                scan_was_truncated |= page_was_truncated;
                let admitted = match self.admit_relay_key_package_records(
                    label,
                    runtime,
                    records,
                    authorize_without_successor,
                ) {
                    Ok(admitted) => admitted,
                    Err(_) => {
                        refetch_complete = false;
                        continue;
                    }
                };
                if authorize_without_successor
                    && runtime
                        .authorize_teardown_key_package_deletions_without_successor()
                        .is_err()
                {
                    refetch_complete = false;
                }
                let endpoint_revealed = admitted.non_current_event_count > 0
                    || admitted.discovered_current_revision_count > 0;
                revealed_revision |= endpoint_revealed;
                let endpoint_complete =
                    !page_was_truncated && admitted.admission_failure_count == 0;
                summary.absorb(admitted);
                if endpoint_complete {
                    frontier_clear_candidates.insert(endpoint.clone());
                } else {
                    refetch_complete = false;
                }
            }
            if self
                .extend_key_package_cutover_relay_history(label, &frontier_clear_candidates)
                .is_err()
            {
                refetch_complete = false;
            }
            if refetch_complete {
                match self.remove_key_package_cutover_relay_frontier_endpoints(
                    label,
                    &frontier_clear_candidates,
                ) {
                    Ok(frontier) => relay_frontier = frontier,
                    Err(_) => refetch_complete = false,
                }
            }
            drop(history_guard);
            if !refetch_complete {
                peeling_failed = true;
                break;
            }
            if report_failed {
                // The strict replay discharged the ambiguous relay-side
                // frontier, but the deletion obligation itself remains
                // retryable and this invocation cannot claim success.
                break;
            }
            if !uncovered_eligible_deletion && !revealed_revision {
                break;
            }
            if pass_index + 1 == KEY_PACKAGE_CUTOVER_MAX_DELETION_PASSES {
                peeling_exhausted = true;
            }
        }

        let final_history_guard = history_lock.lock().await;
        let frontier_is_empty = self
            .key_package_cutover_relay_frontier(label)
            .is_ok_and(|frontier| frontier.is_empty());
        let mut scan_complete = all_required_relays_scanned
            && summary.admission_failure_count == 0
            && !scan_was_truncated
            && !peeling_failed
            && !peeling_exhausted
            && !uncovered_eligible_deletion
            && frontier_is_empty;
        if scan_complete {
            scan_complete = runtime
                .finalize_key_package_cutover_consumption_evidence()
                .is_ok();
        }
        if scan_complete {
            // Persistence is part of the proof: a failed marker write must
            // leave the runtime publication interlock armed for the next open.
            scan_complete = self
                .begin_root_mutation("persist completed KeyPackage cutover scan marker")
                .and_then(|_root_mutation| {
                    self.mark_key_package_cutover_scan_complete_for_relays(
                        label,
                        &source_relays,
                        &scanned_history_relays,
                    )
                })
                .is_ok();
        }
        drop(final_history_guard);
        if scan_complete
            && destructive_cleanup_was_durable
            && self
                .clear_key_package_teardown_cleanup_pending(label)
                .is_err()
        {
            scan_complete = false;
        }
        if summary.non_current_event_count > 0 || summary.discovered_current_revision_count > 0 {
            tracing::info!(
                target: "marmot_app::key_packages",
                method = "retire_relay_non_current_key_packages",
                non_current_event_count = summary.non_current_event_count,
                discovered_current_revision_count = summary.discovered_current_revision_count,
                deferred_endpoint_count = summary.deferred_endpoint_count,
                admission_failure_count = summary.admission_failure_count,
                retry_failure_count,
                all_required_relays_scanned,
                scan_was_truncated,
                peeling_exhausted,
                "completed relay key package retirement scan"
            );
        }
        scan_complete
    }

    fn key_package_cutover_replacement_pending_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.capability-refresh-v1-replacement-pending"))
    }

    fn generated_initial_key_package_publication_hold_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!(
                "{label}.generated-initial-key-package-publication-hold-v1"
            ))
    }

    fn generated_initial_key_package_publication_held(
        &self,
        label: &str,
    ) -> Result<bool, AppError> {
        self.generated_initial_key_package_publication_hold_path(label)
            .try_exists()
            .map_err(AppError::from)
    }

    /// Create a private child directory and durably publish its directory
    /// entry before any load-bearing file is written inside it. Syncing only
    /// the child after `mkdir` is insufficient: a power loss can otherwise
    /// discard the entire child namespace even though its files were synced.
    fn ensure_private_directory_entry_durable(&self, directory: &Path) -> Result<(), AppError> {
        fs_private::create_dir_all_private(directory)?;
        #[cfg(unix)]
        if let Some(parent) = directory.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// Persist the setup-owned publication hold before any initial KeyPackage
    /// can be prepared. This method only creates the crash-safe file; SQL
    /// mirroring is a separate route-serialized step so it can never recreate
    /// a hold that an explicit publisher already cleared.
    fn arm_generated_initial_key_package_publication_hold(
        &self,
        label: &str,
    ) -> Result<(), AppError> {
        let _root_mutation =
            self.begin_root_mutation("arm generated initial KeyPackage publication hold")?;
        let path = self.generated_initial_key_package_publication_hold_path(label);
        let parent = path.parent().ok_or_else(|| {
            AppError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "generated initial KeyPackage publication hold has no parent directory",
            ))
        })?;
        self.ensure_private_directory_entry_durable(parent)?;
        fs_private::write_private_atomic(&path, b"held\n")?;
        Ok(())
    }

    /// Arm only before the first lifecycle exists. Once an initial lifecycle
    /// is durable, an absent file is itself the durable record that an explicit
    /// publisher released setup ownership; resume must never resurrect it.
    fn ensure_generated_initial_key_package_publication_hold_before_preparation(
        &self,
        label: &str,
    ) -> Result<(), AppError> {
        let lifecycle_exists = if self.account_storage_path(label).exists() {
            self.account_storage(label)?
                .key_package_lifecycle()?
                .is_some()
        } else {
            false
        };
        if lifecycle_exists {
            return Ok(());
        }
        self.arm_generated_initial_key_package_publication_hold(label)
    }

    /// Mirror an existing file-backed hold into SQL without creating it. The
    /// route lock orders this check/write against explicit generated-route
    /// recovery, hold clearing, and the final kind-30443 boundary.
    async fn mirror_generated_initial_key_package_publication_hold_into_lifecycle(
        &self,
        label: &str,
    ) -> Result<(), AppError> {
        let route_lock = self.key_package_route_lock(label);
        let _route_guard = route_lock.lock().await;
        if !self.generated_initial_key_package_publication_held(label)? {
            return Ok(());
        }
        let storage = self.account_storage(label)?;
        let Some(mut lifecycle) = storage.key_package_lifecycle()? else {
            return Err(AppError::AccountSetupRetryRequired);
        };
        if !lifecycle.cutover_publication_blocked {
            lifecycle.cutover_publication_blocked = true;
            storage.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok(())
    }

    fn clear_generated_initial_key_package_publication_hold(
        &self,
        label: &str,
    ) -> Result<(), AppError> {
        let _root_mutation =
            self.begin_root_mutation("clear generated initial KeyPackage publication hold")?;
        let path = self.generated_initial_key_package_publication_hold_path(label);
        let parent_exists = match path.parent() {
            Some(parent) => parent.try_exists()?,
            None => false,
        };
        if !path.try_exists()? && !parent_exists {
            return Ok(());
        }
        remove_file_if_present(path)
    }

    pub(crate) async fn clear_generated_initial_key_package_publication_hold_for_session(
        &self,
        label: &str,
        session_admission: &AccountSessionAdmissionToken,
    ) -> Result<(), AppError> {
        let route_lock = self.key_package_route_lock(label);
        let _route_guard = route_lock.lock().await;
        if !self.active_account_session_admission_is_current(label, session_admission) {
            return Err(AppError::AccountWorkerBusy);
        }
        self.clear_generated_initial_key_package_publication_hold(label)
    }

    fn key_package_cutover_relay_frontier_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.capability-refresh-v2-relay-frontier.json"))
    }

    fn key_package_cutover_relay_history_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.capability-refresh-v2-relay-history.json"))
    }

    fn key_package_teardown_cleanup_pending_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!(
                "{label}.capability-refresh-v2-destructive-cleanup-pending"
            ))
    }

    fn key_package_teardown_cleanup_pending(&self, label: &str) -> Result<bool, AppError> {
        self.key_package_teardown_cleanup_pending_path(label)
            .try_exists()
            .map_err(AppError::from)
    }

    fn mark_key_package_teardown_cleanup_pending(&self, label: &str) -> Result<(), AppError> {
        let _root_mutation =
            self.begin_root_mutation("arm destructive KeyPackage teardown cleanup")?;
        let path = self.key_package_teardown_cleanup_pending_path(label);
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "destructive KeyPackage cleanup marker has no parent directory",
            )
        })?;
        self.ensure_private_directory_entry_durable(parent)?;
        // Persist the destructive mode before invalidating the ordinary proof.
        // A crash between these writes still makes marker admission reject the
        // old proof because retirement consults this mode directly.
        fs_private::write_private_atomic(&path, b"pending\n")?;
        self.invalidate_key_package_cutover_scan_marker(label)
    }

    fn clear_key_package_teardown_cleanup_pending(&self, label: &str) -> Result<(), AppError> {
        let _root_mutation =
            self.begin_root_mutation("clear destructive KeyPackage teardown cleanup")?;
        let path = self.key_package_teardown_cleanup_pending_path(label);
        match fs::remove_file(&path) {
            Ok(()) => {
                #[cfg(unix)]
                if let Some(parent) = path.parent() {
                    std::fs::File::open(parent)?.sync_all()?;
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Relays that must receive one strict stored-history scan before the
    /// upgrade cutover may complete.
    ///
    /// The frontier is written before exact deletion I/O. It therefore covers
    /// the crash window in which deleting a parameterized-replaceable winner
    /// reveals an older same-slot revision, including on a historical relay
    /// that is no longer in the account's current NIP-65 set.
    fn key_package_cutover_relay_frontier(
        &self,
        label: &str,
    ) -> Result<BTreeSet<TransportEndpoint>, AppError> {
        let path = self.key_package_cutover_relay_frontier_path(label);
        let frontier = match read_json::<KeyPackageCutoverRelayFrontier>(&path) {
            Ok(frontier) => frontier,
            Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeSet::new());
            }
            Err(error) => return Err(error),
        };
        let endpoints = frontier
            .relays
            .into_iter()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        Ok(self
            .sanitize_key_package_deletion_endpoints(endpoints)?
            .into_iter()
            .collect())
    }

    /// Monotonic set of relays whose KeyPackage history has mattered to this
    /// account. It survives route removal, terminal SQL-liability pruning, and
    /// completion-marker invalidation so a later cutover cannot silently
    /// forget a historical endpoint that only an older generation knew.
    fn key_package_cutover_relay_history(
        &self,
        label: &str,
    ) -> Result<BTreeSet<TransportEndpoint>, AppError> {
        let path = self.key_package_cutover_relay_history_path(label);
        let history = match read_json::<KeyPackageCutoverRelayFrontier>(&path) {
            Ok(history) => history,
            Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeSet::new());
            }
            Err(error) => return Err(error),
        };
        let endpoints = history
            .relays
            .into_iter()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        Ok(self
            .sanitize_key_package_deletion_endpoints(endpoints)?
            .into_iter()
            .collect())
    }

    fn extend_key_package_cutover_relay_history(
        &self,
        label: &str,
        endpoints: &BTreeSet<TransportEndpoint>,
    ) -> Result<BTreeSet<TransportEndpoint>, AppError> {
        if endpoints.is_empty() {
            return self.key_package_cutover_relay_history(label);
        }
        let _root_mutation = self.begin_root_mutation("extend KeyPackage cutover relay history")?;
        let _frontier_mutation = self
            .key_package_frontier_mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.extend_key_package_cutover_relay_history_under_root(label, endpoints)
    }

    fn extend_key_package_cutover_relay_history_under_root(
        &self,
        label: &str,
        endpoints: &BTreeSet<TransportEndpoint>,
    ) -> Result<BTreeSet<TransportEndpoint>, AppError> {
        let mut history = self.key_package_cutover_relay_history(label)?;
        history.extend(endpoints.iter().cloned());
        let frontier = self.key_package_cutover_relay_frontier(label)?;
        let mut projected_history = self.key_package_history_endpoints(label)?;
        projected_history.extend(history.iter().cloned());
        projected_history.extend(frontier);
        projected_history.extend(self.key_package_current_route_history_endpoints(label)?);
        if self.pending_nip65_route_mutation(label) {
            let pending = self.read_pending_nip65_route_mutation(label)?;
            projected_history.extend(
                self.sanitize_key_package_deletion_endpoints(
                    pending
                        .nip65
                        .relays
                        .into_iter()
                        .map(TransportEndpoint)
                        .collect(),
                )?,
            );
        }
        if projected_history.len() > KEY_PACKAGE_CUTOVER_RELAY_HISTORY_CAPACITY {
            return Err(AppError::Publish(
                "KeyPackage relay-history journal is full".into(),
            ));
        }
        let path = self.key_package_cutover_relay_history_path(label);
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cutover relay history has no parent directory",
            )
        })?;
        self.ensure_private_directory_entry_durable(parent)?;
        let marker = KeyPackageCutoverRelayFrontier {
            relays: history.iter().map(|endpoint| endpoint.0.clone()).collect(),
        };
        let bytes = serde_json::to_vec(&marker).map_err(std::io::Error::other)?;
        fs_private::write_private_atomic(&path, &bytes)?;
        Ok(history)
    }

    /// Durably union exact-deletion endpoints into the frontier while holding
    /// the root mutation lease across the read/modify/write sequence.
    fn extend_key_package_cutover_relay_frontier(
        &self,
        label: &str,
        endpoints: Vec<TransportEndpoint>,
    ) -> Result<(), AppError> {
        let endpoints = self
            .sanitize_key_package_deletion_endpoints(endpoints)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        if endpoints.is_empty() {
            return Err(AppError::Publish(
                "cannot arm KeyPackage cutover frontier without a safe relay endpoint".into(),
            ));
        }
        let _root_mutation = self.begin_root_mutation("arm KeyPackage cutover relay frontier")?;
        let _frontier_mutation = self
            .key_package_frontier_mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let history = self.key_package_history_endpoints(label)?;
        let mut frontier = self.key_package_cutover_relay_frontier(label)?;
        let mut projected_history = history;
        projected_history.extend(frontier.iter().cloned());
        projected_history.extend(endpoints.iter().cloned());
        projected_history.extend(self.key_package_current_route_history_endpoints(label)?);
        if self.pending_nip65_route_mutation(label) {
            let pending = self.read_pending_nip65_route_mutation(label)?;
            projected_history.extend(
                self.sanitize_key_package_deletion_endpoints(
                    pending
                        .nip65
                        .relays
                        .into_iter()
                        .map(TransportEndpoint)
                        .collect(),
                )?,
            );
        }
        if projected_history.len() > KEY_PACKAGE_CUTOVER_RELAY_HISTORY_CAPACITY {
            return Err(AppError::Publish(
                "KeyPackage relay-history journal is full; refusing exact deletion I/O".into(),
            ));
        }
        frontier.extend(endpoints);
        self.write_key_package_cutover_relay_frontier_under_root(label, &frontier)?;
        // Persisting the frontier first is load-bearing: a crash before this
        // invalidation still leaves the old marker unusable because marker
        // admission also requires an empty frontier. Removing the marker
        // before network I/O prevents a later strict scan from temporarily
        // emptying the frontier and reviving a pre-peeling completion proof.
        self.invalidate_key_package_cutover_scan_marker(label)?;
        Ok(())
    }

    /// Remove only endpoints covered by the caller's completed strict scan.
    /// The locked re-read preserves any distinct endpoint armed by another
    /// app clone before this mutation acquired the file lock.
    fn remove_key_package_cutover_relay_frontier_endpoints(
        &self,
        label: &str,
        endpoints: &BTreeSet<TransportEndpoint>,
    ) -> Result<BTreeSet<TransportEndpoint>, AppError> {
        if endpoints.is_empty() {
            return self.key_package_cutover_relay_frontier(label);
        }
        let _root_mutation =
            self.begin_root_mutation("discharge KeyPackage cutover relay frontier")?;
        let _frontier_mutation = self
            .key_package_frontier_mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut frontier = self.key_package_cutover_relay_frontier(label)?;
        frontier.retain(|endpoint| !endpoints.contains(endpoint));
        self.write_key_package_cutover_relay_frontier_under_root(label, &frontier)?;
        Ok(frontier)
    }

    fn write_key_package_cutover_relay_frontier_under_root(
        &self,
        label: &str,
        frontier: &BTreeSet<TransportEndpoint>,
    ) -> Result<(), AppError> {
        let path = self.key_package_cutover_relay_frontier_path(label);
        if frontier.is_empty() {
            match fs::remove_file(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    if let Some(parent) = path.parent() {
                        std::fs::File::open(parent)?.sync_all()?;
                    }
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cutover relay frontier has no parent directory",
            )
        })?;
        self.ensure_private_directory_entry_durable(parent)?;
        let marker = KeyPackageCutoverRelayFrontier {
            relays: frontier.iter().map(|endpoint| endpoint.0.clone()).collect(),
        };
        let bytes = serde_json::to_vec(&marker).map_err(std::io::Error::other)?;
        fs_private::write_private_atomic(&path, &bytes)?;
        Ok(())
    }

    fn pending_nip65_route_mutation_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.nip65-route-mutation-v1.json"))
    }

    fn nip65_route_generation_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.nip65-route-generation-v1.json"))
    }

    fn pending_nip65_route_mutation(&self, label: &str) -> bool {
        self.pending_nip65_route_mutation_path(label).exists()
    }

    fn read_pending_nip65_route_mutation(
        &self,
        label: &str,
    ) -> Result<PendingNip65RouteMutation, AppError> {
        read_json(self.pending_nip65_route_mutation_path(label))
    }

    fn write_pending_nip65_route_mutation(
        &self,
        label: &str,
        pending: &PendingNip65RouteMutation,
    ) -> Result<(), AppError> {
        self.write_private_json(
            &self.pending_nip65_route_mutation_path(label),
            pending,
            "pending NIP-65 route mutation",
        )
    }

    fn clear_pending_nip65_route_mutation(&self, label: &str) -> Result<(), AppError> {
        remove_file_if_present(self.pending_nip65_route_mutation_path(label))
    }

    /// Read and validate the durable local kind-10002 authority without
    /// treating a malformed or unreadable journal as an absent generation.
    /// The exact parsed relay state is bound to the same event coordinate, so
    /// every security-sensitive routing decision can fail closed instead of
    /// consulting a whole-record directory-cache winner.
    fn read_nip65_route_generation_for_authoring(
        &self,
        label: &str,
    ) -> Result<Option<Nip65RouteGeneration>, AppError> {
        match read_json(self.nip65_route_generation_path(label)) {
            Ok(generation) => {
                self.validate_nip65_route_generation(&generation)?;
                Ok(Some(generation))
            }
            Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Canonicalize each NIP-65 compatibility/directional endpoint vector for
    /// semantic authority comparisons. Persisted event order and URL aliases
    /// must not make the same relay declaration look different, while a
    /// malformed or unsafe alias still fails closed.
    fn canonical_nip65_route_state(
        &self,
        state: &AccountRelayListState,
    ) -> Result<CanonicalNip65RouteState, AppError> {
        if state.kind != KIND_NIP65_RELAY_LIST {
            return Err(AppError::Publish(
                "NIP-65 authority comparison received the wrong event kind".into(),
            ));
        }
        let canonicalize = |relays: &[String]| {
            self.sanitize_key_package_deletion_endpoints(
                relays
                    .iter()
                    .cloned()
                    .map(TransportEndpoint)
                    .collect::<Vec<_>>(),
            )
        };
        Ok((
            canonicalize(&state.relays)?,
            canonicalize(&state.read_relays)?,
            canonicalize(&state.write_relays)?,
        ))
    }

    fn validate_nip65_route_generation(
        &self,
        generation: &Nip65RouteGeneration,
    ) -> Result<Vec<TransportEndpoint>, AppError> {
        if generation.nip65.kind != KIND_NIP65_RELAY_LIST {
            return Err(AppError::Publish(
                "durable NIP-65 route generation has the wrong event kind".into(),
            ));
        }
        let event_id = hex::decode(&generation.event_id)?;
        if event_id.len() != 32 {
            return Err(AppError::Publish(
                "durable NIP-65 route generation has an invalid event id".into(),
            ));
        }
        let endpoints = generation
            .nip65
            .relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        let endpoints = self.sanitize_key_package_deletion_endpoints(endpoints)?;
        if endpoints.is_empty() {
            return Err(AppError::MissingRelayLists(vec![
                MissingRelayListKind::Nip65,
            ]));
        }
        Ok(endpoints)
    }

    fn next_locally_authored_nip65_created_at(&self, label: &str) -> Result<u64, AppError> {
        let now = unix_now_seconds();
        let created_at = match self.read_nip65_route_generation_for_authoring(label)? {
            Some(generation) => generation
                .created_at
                .checked_add(1)
                .ok_or_else(|| {
                    AppError::Publish("cannot advance the durable NIP-65 route generation".into())
                })?
                .max(now),
            None => now,
        };
        if !DirectoryFreshness::from_unix_time(now, self.config.directory_max_future_skew)
            .accepts_created_at(created_at)
        {
            return Err(AppError::Publish(
                "cannot author a NIP-65 route revision beyond the directory future-skew bound"
                    .into(),
            ));
        }
        Ok(created_at)
    }

    fn write_nip65_route_generation(
        &self,
        label: &str,
        generation: &Nip65RouteGeneration,
    ) -> Result<(), AppError> {
        self.write_private_json(
            &self.nip65_route_generation_path(label),
            generation,
            "NIP-65 route generation",
        )
    }

    fn write_private_json<T: Serialize>(
        &self,
        path: &Path,
        value: &T,
        context: &str,
    ) -> Result<(), AppError> {
        let parent = path.parent().ok_or_else(|| {
            AppError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{context} has no parent directory"),
            ))
        })?;
        self.ensure_private_directory_entry_durable(parent)?;
        let bytes = serde_json::to_vec(value)?;
        fs_private::write_private_atomic(path, &bytes)?;
        Ok(())
    }

    fn local_account_label_for_id(&self, account_id_hex: &str) -> Option<String> {
        self.account_home()
            .accounts()
            .ok()?
            .into_iter()
            .find(|account| account.account_id_hex == account_id_hex)
            .map(|account| account.label)
    }

    fn authoritative_key_package_relays(
        &self,
        label: &str,
    ) -> Result<Vec<TransportEndpoint>, AppError> {
        let Some(generation) = self.read_nip65_route_generation_for_authoring(label)? else {
            return Err(AppError::Publish(
                "local NIP-65 route authority is unavailable".into(),
            ));
        };
        self.validate_nip65_route_generation(&generation)
    }

    async fn sign_account_transport_event(
        &self,
        signer: Arc<dyn nostr::NostrSigner>,
        event: NostrTransportEvent,
    ) -> Result<NostrTransportEvent, AppError> {
        if event.sig.is_some() {
            event
                .to_verified_nostr_event()
                .map_err(|error| AppError::Publish(format!("invalid signed event: {error}")))?;
            return Ok(event);
        }
        let public_key = signer
            .get_public_key()
            .await
            .map_err(|error| AppError::Publish(format!("signer public key: {error}")))?;
        if event.pubkey != public_key.to_hex() {
            return Err(AppError::Publish(
                "relay-list event author does not match the selected account signer".into(),
            ));
        }
        let kind = u16::try_from(event.kind)
            .map(Kind::from)
            .map_err(|_| AppError::Publish(format!("unsupported event kind {}", event.kind)))?;
        let tags = event
            .tags
            .into_iter()
            .map(Tag::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| AppError::Publish(format!("relay-list event tags: {error}")))?;
        let unsigned = EventBuilder::new(kind, event.content)
            .tags(tags)
            .custom_created_at(NostrTimestamp::from_secs(event.created_at))
            .build(public_key);
        let signed = signer
            .sign_event(unsigned)
            .await
            .map_err(|error| AppError::Publish(format!("sign relay-list event: {error}")))?;
        NostrTransportEvent::from_nostr_event(&signed)
            .map_err(|error| AppError::Publish(format!("signed relay-list event: {error}")))
    }

    fn validate_pending_nip65_route_mutation(
        &self,
        label: &str,
        pending: &PendingNip65RouteMutation,
    ) -> Result<Vec<TransportEndpoint>, AppError> {
        let account = self.account_home().account(label)?;
        if pending.account_id_hex != account.account_id_hex
            || pending.nip65.kind != KIND_NIP65_RELAY_LIST
            || pending.generation.nip65 != pending.nip65
        {
            return Err(AppError::Publish(
                "pending NIP-65 route mutation does not match the local account".into(),
            ));
        }
        let event_id = hex::decode(&pending.generation.event_id)?;
        if event_id.len() != 32 {
            return Err(AppError::Publish(
                "pending NIP-65 route generation has an invalid event id".into(),
            ));
        }
        let proposed = pending
            .nip65
            .relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        let proposed = self.sanitize_key_package_deletion_endpoints(proposed)?;
        if proposed.is_empty() {
            return Err(AppError::MissingRelayLists(vec![
                MissingRelayListKind::Nip65,
            ]));
        }
        if let Some(event) = pending.signed_event.as_ref() {
            event
                .to_verified_nostr_event()
                .map_err(|error| AppError::Publish(format!("pending route event: {error}")))?;
            if event.id != pending.generation.event_id
                || event.created_at != pending.generation.created_at
                || event.pubkey != pending.account_id_hex
                || event.kind != KIND_NIP65_RELAY_LIST
                || relay_list_state_from_event(event).as_ref() != Some(&pending.nip65)
            {
                return Err(AppError::Publish(
                    "pending NIP-65 route event does not match its durable intent".into(),
                ));
            }
        }
        Ok(proposed)
    }

    fn canonical_nip65_publication_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Result<Vec<TransportEndpoint>, AppError> {
        let mut endpoints = self
            .relay_plane
            .sanitize_relay_endpoints(endpoints, context)
            .map_err(|error| {
                AppError::Transport(cgka_traits::TransportAdapterError::Publish(error))
            })?;
        endpoints.sort();
        endpoints.dedup();
        Ok(endpoints)
    }

    fn pending_nip65_route_mutation_preserves_generated_fresh_proof(
        &self,
        label: &str,
        pending: &PendingNip65RouteMutation,
    ) -> Result<bool, AppError> {
        if pending.source != Nip65RouteMutationSource::GeneratedAccountBootstrap
            || !self.key_package_cutover_has_fresh_account_proof(label)
        {
            return Ok(false);
        }
        let Some(setup) = self.account_home().account_setup_state(label)? else {
            return Ok(false);
        };
        if setup.kind != AccountSetupKind::GeneratedIdentity
            || setup.account_id_hex != pending.account_id_hex
            || matches!(
                setup.phase,
                AccountSetupPhase::KeyPackagePublicationConfirmed
            )
            || pending.signed_event.is_none()
        {
            return Ok(false);
        }
        let proposed_endpoints = self.validate_pending_nip65_route_mutation(label, pending)?;
        let Some(lifecycle) = self.account_storage(label)?.key_package_lifecycle()? else {
            return Ok(false);
        };
        Ok(self.key_package_lifecycle_has_prepared_cutover_replacement(
            label,
            &lifecycle,
            &proposed_endpoints,
        ))
    }

    fn generated_account_fresh_replacement_can_open_cutover_gate(
        &self,
        label: &str,
        lifecycle: &cgka_traits::KeyPackageLifecycleState,
    ) -> Result<bool, AppError> {
        if !self.key_package_cutover_replacement_pending(label)
            || !self.key_package_cutover_has_fresh_account_proof(label)
        {
            return Ok(false);
        }
        let Some(setup) = self.account_home().account_setup_state(label)? else {
            return Ok(false);
        };
        if setup.kind != AccountSetupKind::GeneratedIdentity
            || !matches!(
                setup.phase,
                AccountSetupPhase::LocalReady
                    | AccountSetupPhase::BootstrapPublicationStarted
                    | AccountSetupPhase::BootstrapPublicationConfirmed
                    | AccountSetupPhase::KeyPackagePublicationStarted
            )
        {
            return Ok(false);
        }
        let authoritative_endpoints = if self.pending_nip65_route_mutation(label) {
            let pending = self.read_pending_nip65_route_mutation(label)?;
            if !self
                .pending_nip65_route_mutation_preserves_generated_fresh_proof(label, &pending)?
            {
                return Ok(false);
            }
            self.validate_pending_nip65_route_mutation(label, &pending)?
        } else {
            let Some(generation) = self.read_nip65_route_generation_for_authoring(label)? else {
                return Ok(false);
            };
            self.validate_nip65_route_generation(&generation)?
        };
        Ok(self.key_package_lifecycle_has_prepared_cutover_replacement(
            label,
            lifecycle,
            &authoritative_endpoints,
        ))
    }

    fn commit_pending_nip65_route_mutation(
        &self,
        label: &str,
        pending: &PendingNip65RouteMutation,
    ) -> Result<AccountRelayListStatus, AppError> {
        let _root_mutation = self.begin_root_mutation("commit pending NIP-65 route mutation")?;
        let _frontier_mutation = self
            .key_package_frontier_mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The generation-bound state is the authority and the directory row is
        // only its projection. Persist authority first: a crash before the
        // cache write leaves the pending intent/gate in place, and restart can
        // safely repeat the projection without ever reading the old route.
        self.write_nip65_route_generation(label, &pending.generation)?;
        let mut status = self.account_relay_list_status(label)?;
        status.nip65 = pending.nip65.clone();
        push_unique_strings(
            &mut status.bootstrap_relays,
            pending.bootstrap_relays.iter().cloned(),
        );
        status.refresh();
        self.remember_directory_relay_lists(&pending.account_id_hex, &status)?;
        self.clear_pending_nip65_route_mutation(label)?;
        Ok(status)
    }

    async fn recover_pending_nip65_route_mutation(
        &self,
        label: &str,
        signer: Arc<dyn nostr::NostrSigner>,
    ) -> Result<Option<AccountRelayListStatus>, AppError> {
        self.recover_pending_nip65_route_mutation_inner(label, signer, false)
            .await
    }

    /// Recover a generated-bootstrap intent only after its caller validated
    /// the exact durable setup authority while holding the account route lock.
    /// Keeping this capability separate prevents generic startup maintenance
    /// from replaying a stale generated intent after context validation failed.
    async fn recover_validated_generated_nip65_route_mutation(
        &self,
        label: &str,
        signer: Arc<dyn nostr::NostrSigner>,
    ) -> Result<Option<AccountRelayListStatus>, AppError> {
        self.recover_pending_nip65_route_mutation_inner(label, signer, true)
            .await
    }

    async fn recover_pending_nip65_route_mutation_inner(
        &self,
        label: &str,
        signer: Arc<dyn nostr::NostrSigner>,
        generated_setup_authority_validated: bool,
    ) -> Result<Option<AccountRelayListStatus>, AppError> {
        if !self.pending_nip65_route_mutation(label) {
            return Ok(None);
        }
        let mut pending = self.read_pending_nip65_route_mutation(label)?;
        if pending.source == Nip65RouteMutationSource::GeneratedAccountBootstrap
            && !generated_setup_authority_validated
        {
            return Err(AppError::Publish(
                "generated-account NIP-65 recovery requires durable setup-context validation"
                    .into(),
            ));
        }
        let proposed = self.validate_pending_nip65_route_mutation(label, &pending)?;
        // Always re-evaluate the marker before recovery I/O. Only the exact
        // generated-account bootstrap intent may retain a fresh-identity
        // proof; every legacy or ordinary intent re-arms the SQL gate. This
        // also handles a crash after the intent file was synced but before the
        // original mutator reached its gate write.
        {
            let _root_mutation =
                self.begin_root_mutation("re-arm pending NIP-65 route mutation")?;
            let fresh_account_proof_preserved =
                self.invalidate_key_package_cutover_scan_for_route_mutation(label)?;
            if !fresh_account_proof_preserved {
                self.arm_key_package_cutover_publication_gate_for_relays(label, &proposed)?;
            }
        }
        if !pending.network_accepted {
            let event = pending.signed_event.clone().ok_or_else(|| {
                AppError::Publish(
                    "unacknowledged pending NIP-65 route mutation has no exact signed event".into(),
                )
            })?;
            let publish_endpoints = self
                .relay_plane
                .sanitize_relay_endpoints(
                    pending
                        .publish_endpoints
                        .iter()
                        .cloned()
                        .map(TransportEndpoint)
                        .collect(),
                    "pending NIP-65 route mutation publish",
                )
                .map_err(|error| {
                    AppError::Transport(cgka_traits::TransportAdapterError::Publish(error))
                })?;
            if publish_endpoints.is_empty() {
                return Err(AppError::MissingDefaultRelays);
            }
            let relay_client =
                self.relay_client_for_account_id(&pending.account_id_hex, signer.clone());
            let outcome = relay_client
                .publish_event(&publish_endpoints, &event, 1)
                .await
                .map_err(|error| AppError::Publish(error.to_string()))?;
            if outcome.accepted.is_empty() {
                return Err(AppError::Publish(
                    "relay acknowledged zero pending NIP-65 route events".into(),
                ));
            }
            pending.network_accepted = true;
            let _root_mutation =
                self.begin_root_mutation("record pending NIP-65 route acknowledgement")?;
            self.write_pending_nip65_route_mutation(label, &pending)?;
        }
        self.commit_pending_nip65_route_mutation(label, &pending)
            .map(Some)
    }

    pub(crate) async fn ingest_local_nip65_relay_event_serialized(
        &self,
        label: &str,
        record: RelayEventRecord,
    ) -> Result<AccountRelayListStatus, AppError> {
        let route_lock = self.key_package_route_lock(label);
        let _route_guard = route_lock.lock().await;
        self.ingest_local_nip65_relay_event_unlocked(label, record)
    }

    fn ingest_local_nip65_relay_event_unlocked(
        &self,
        label: &str,
        record: RelayEventRecord,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.account_home().account(label)?;
        if record.event.pubkey != account.account_id_hex
            || record.event.kind != KIND_NIP65_RELAY_LIST
            || !self.directory_freshness().accepts(&record)
        {
            return self.account_relay_list_status(label);
        }
        let nip65 = relay_list_state_from_event(&record.event).ok_or_else(|| {
            AppError::RelayDirectory("self NIP-65 event has no relay-list state".into())
        })?;
        let generation = Nip65RouteGeneration {
            created_at: record.event.created_at,
            event_id: record.event.id.clone(),
            nip65: nip65.clone(),
        };
        if self
            .read_nip65_route_generation_for_authoring(label)?
            .is_some_and(|current| {
                !nostr_replaceable_coordinate_is_newer(
                    generation.created_at,
                    &generation.event_id,
                    current.created_at,
                    &current.event_id,
                )
            })
        {
            return self.account_relay_list_status(label);
        }
        let proposed = self.sanitize_key_package_deletion_endpoints(
            nip65
                .relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect(),
        )?;
        if proposed.is_empty() {
            return Err(AppError::MissingRelayLists(vec![
                MissingRelayListKind::Nip65,
            ]));
        }
        let pending = PendingNip65RouteMutation {
            account_id_hex: account.account_id_hex,
            nip65,
            bootstrap_relays: record
                .endpoints
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect(),
            publish_endpoints: Vec::new(),
            signed_event: record.event.sig.is_some().then_some(record.event),
            generation,
            network_accepted: true,
            source: Nip65RouteMutationSource::AccountMutation,
        };
        {
            let _root_mutation =
                self.begin_root_mutation("stage observed self NIP-65 route mutation")?;
            self.write_pending_nip65_route_mutation(label, &pending)?;
            self.invalidate_key_package_cutover_scan_for_route_mutation(label)?;
            self.arm_key_package_cutover_publication_gate_for_relays(label, &proposed)?;
        }
        self.commit_pending_nip65_route_mutation(label, &pending)
    }

    fn key_package_route_lock(&self, label: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.key_package_route_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(label.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn key_package_history_lock(&self, label: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.key_package_history_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(label.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn key_package_lifecycle_history_endpoints(
        &self,
        lifecycle: &cgka_traits::KeyPackageLifecycleState,
    ) -> Result<BTreeSet<TransportEndpoint>, AppError> {
        let target_may_have_been_exposed = |target: &&cgka_traits::TransportFanoutTarget| {
            target.state == cgka_traits::TransportFanoutAttemptState::Accepted
                || target.attempt_count > 0
                || target.last_attempt_at.is_some()
        };
        let endpoints = lifecycle
            .publication_targets
            .iter()
            .filter(target_may_have_been_exposed)
            .map(|target| target.endpoint.clone())
            .chain(
                lifecycle
                    .pending_replacement
                    .iter()
                    .flat_map(|pending| pending.targets.iter())
                    .filter(target_may_have_been_exposed)
                    .map(|target| target.endpoint.clone()),
            )
            .chain(
                lifecycle
                    .retired_publications_pending_deletion
                    .iter()
                    .flat_map(|retired| retired.deletion_targets.iter())
                    .map(|target| target.endpoint.clone()),
            )
            .collect::<Vec<_>>();
        // An unsafe exact liability must remain byte-for-byte durable, but it
        // is not a relay we can dial or strictly scan. Canonicalize each
        // endpoint independently so one unsafe legacy sibling cannot prevent
        // a distinct safe sibling from reaching deletion I/O and having its
        // terminal ACK pruned. The unsafe target remains in the lifecycle and
        // therefore keeps cleanup incomplete and retryable.
        Ok(endpoints
            .into_iter()
            .filter_map(|endpoint| {
                self.canonicalize_key_package_endpoint(&endpoint, "key package lifecycle history")
                    .ok()
            })
            .collect())
    }

    fn key_package_history_endpoints(
        &self,
        label: &str,
    ) -> Result<BTreeSet<TransportEndpoint>, AppError> {
        let mut endpoints = self.key_package_cutover_relay_history(label)?;
        let Some(lifecycle) = self.account_storage(label)?.key_package_lifecycle()? else {
            return Ok(endpoints);
        };
        endpoints.extend(self.key_package_lifecycle_history_endpoints(&lifecycle)?);
        Ok(endpoints)
    }

    fn key_package_current_route_history_endpoints(
        &self,
        label: &str,
    ) -> Result<BTreeSet<TransportEndpoint>, AppError> {
        let Some(generation) = self.read_nip65_route_generation_for_authoring(label)? else {
            return Ok(BTreeSet::new());
        };
        Ok(self
            .validate_nip65_route_generation(&generation)?
            .into_iter()
            .collect())
    }

    fn invalidate_key_package_cutover_scan_for_route_mutation(
        &self,
        label: &str,
    ) -> Result<bool, AppError> {
        // Preserve a new identity's no-predecessor proof only for its exact,
        // locally-authored initial bootstrap intent. Pre-field journals and
        // every ordinary route mutation default to invalidating the proof.
        if self.pending_nip65_route_mutation(label) {
            let pending = self.read_pending_nip65_route_mutation(label)?;
            if self.pending_nip65_route_mutation_preserves_generated_fresh_proof(label, &pending)? {
                return Ok(true);
            }
        }
        self.invalidate_key_package_cutover_scan_marker(label)
            .map(|()| false)
    }

    fn invalidate_key_package_cutover_scan_marker(&self, label: &str) -> Result<(), AppError> {
        let path = self.key_package_cutover_scan_complete_path(label);
        match fs::remove_file(&path) {
            Ok(()) => {
                #[cfg(unix)]
                if let Some(parent) = path.parent() {
                    std::fs::File::open(parent)?.sync_all()?;
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn arm_key_package_cutover_publication_gate_for_relays(
        &self,
        label: &str,
        proposed_relays: &[TransportEndpoint],
    ) -> Result<(), AppError> {
        let _frontier_mutation = self
            .key_package_frontier_mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let history = self.key_package_history_endpoints(label)?;
        let frontier = self.key_package_cutover_relay_frontier(label)?;
        let proposed = self
            .sanitize_key_package_deletion_endpoints(proposed_relays.to_vec())?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut projected_history = history;
        projected_history.extend(frontier);
        projected_history.extend(proposed);
        projected_history.extend(self.key_package_current_route_history_endpoints(label)?);
        if projected_history.len() > KEY_PACKAGE_CUTOVER_RELAY_HISTORY_CAPACITY {
            return Err(AppError::Publish(
                "KeyPackage relay-history journal is full; refusing route mutation".into(),
            ));
        }
        if self.key_package_cutover_scan_complete_for_relays(label, proposed_relays)
            && !self.key_package_cutover_replacement_pending(label)
        {
            return Ok(());
        }
        if !self.account_storage_path(label).exists() {
            return Ok(());
        }
        let storage = self.account_storage(label)?;
        let Some(mut lifecycle) = storage.key_package_lifecycle()? else {
            return Ok(());
        };
        if lifecycle.stable_slot_id.is_empty() {
            return Err(AppError::Publish(
                "cannot arm key package cutover publication interlock without a stable slot".into(),
            ));
        }
        if !lifecycle.cutover_publication_blocked {
            lifecycle.cutover_publication_blocked = true;
            storage.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok(())
    }

    fn legacy_key_package_cutover_scan_complete_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.capability-refresh-v1-relay-scan-complete"))
    }

    fn key_package_cutover_scan_complete_path(&self, label: &str) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(format!("{label}.capability-refresh-v2-relay-scan-complete"))
    }

    #[cfg(test)]
    fn key_package_cutover_scan_complete(&self, label: &str) -> bool {
        self.key_package_cutover_scan_complete_path(label).exists()
    }

    fn key_package_cutover_replacement_pending(&self, label: &str) -> bool {
        self.key_package_cutover_replacement_pending_path(label)
            .exists()
    }

    fn mark_key_package_cutover_replacement_pending(&self, label: &str) -> bool {
        let path = self.key_package_cutover_replacement_pending_path(label);
        let result = (|| -> Result<(), AppError> {
            let parent = path.parent().ok_or_else(|| {
                AppError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "cutover marker has no parent directory",
                ))
            })?;
            self.ensure_private_directory_entry_durable(parent)?;
            fs_private::write_private_atomic(&path, b"pending\n")?;
            Ok(())
        })();
        match result {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "mark_key_package_cutover_replacement_pending",
                    error_kind = error.privacy_safe_kind(),
                    "could not persist key package cutover replacement intent"
                );
                false
            }
        }
    }

    fn clear_key_package_cutover_replacement_pending(&self, label: &str) -> Result<(), AppError> {
        let path = self.key_package_cutover_replacement_pending_path(label);
        remove_file_if_present(path)
    }

    fn removed_local_key_package_tombstone_root(&self) -> PathBuf {
        self.key_package_cache_dir()
            .join(KEY_PACKAGE_DIR)
            .join(REMOVED_LOCAL_KEY_PACKAGE_TOMBSTONE_DIR)
    }

    fn removed_local_key_package_account_tombstone_dir(
        &self,
        account_id_hex: &str,
    ) -> Result<PathBuf, AppError> {
        Ok(self
            .removed_local_key_package_tombstone_root()
            .join(parse_account_id_hex(account_id_hex)?))
    }

    fn removed_local_key_package_tombstone_path(
        &self,
        account_id_hex: &str,
        stable_slot_id: Option<&str>,
    ) -> Result<PathBuf, AppError> {
        let file_name = match stable_slot_id {
            Some(stable_slot_id) => format!(
                "slot-{}.json",
                hex::encode(Sha256::digest(stable_slot_id.as_bytes()))
            ),
            None => "all.json".to_owned(),
        };
        Ok(self
            .removed_local_key_package_account_tombstone_dir(account_id_hex)?
            .join(file_name))
    }

    fn validate_removed_local_key_package_tombstone(
        &self,
        path: &Path,
        account_id_hex: &str,
        stable_slot_id: Option<&str>,
    ) -> Result<(), AppError> {
        let marker: RemovedLocalKeyPackageTombstone = read_json(path)?;
        if marker.account_id_hex != account_id_hex
            || marker.stable_slot_id.as_deref() != stable_slot_id
        {
            return Err(AppError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "removed-local KeyPackage tombstone does not match its path",
            )));
        }
        Ok(())
    }

    fn active_local_key_package_slot_is_authorized_for_admitted_account(
        &self,
        account_id_hex: &str,
        stable_slot_id: &str,
        account: Option<&AccountSummary>,
    ) -> Result<bool, AppError> {
        let Some(account) = account else {
            return Ok(false);
        };
        if !account.is_active_signing() || account.account_id_hex != account_id_hex {
            return Ok(false);
        }
        Ok(self
            .account_storage(&account.label)?
            .key_package_lifecycle()?
            .is_some_and(|lifecycle| lifecycle.stable_slot_id == stable_slot_id))
    }

    fn active_local_key_package_slot_is_authorized(
        &self,
        account_id_hex: &str,
        stable_slot_id: &str,
    ) -> Result<bool, AppError> {
        let Some(account) = self.local_signing_account_for_id(account_id_hex)? else {
            return Ok(false);
        };
        let admission = self
            .account_session_admissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let admission_open = admission
            .get(&account.label)
            .is_none_or(|state| state.account_id_hex != account.account_id_hex || state.open);
        let active_account = (admission_open && account.is_active_signing()).then_some(&account);
        self.active_local_key_package_slot_is_authorized_for_admitted_account(
            account_id_hex,
            stable_slot_id,
            active_account,
        )
    }

    /// Admission-aware variant for callers already holding the account-session
    /// mutex. It must not try to reacquire that non-reentrant mutex while
    /// proving the active lifecycle exception to an account-wide legacy
    /// marker.
    pub(crate) fn removed_local_key_package_slot_is_retired_for_admitted_account(
        &self,
        account_id_hex: &str,
        stable_slot_id: &str,
        local_signing_account: Option<&AccountSummary>,
    ) -> Result<bool, AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        let account_tombstone_dir =
            self.removed_local_key_package_account_tombstone_dir(&account_id_hex)?;
        if !account_tombstone_dir.try_exists()? {
            return Ok(false);
        }
        let exact =
            self.removed_local_key_package_tombstone_path(&account_id_hex, Some(stable_slot_id))?;
        if exact.try_exists()? {
            self.validate_removed_local_key_package_tombstone(
                &exact,
                &account_id_hex,
                Some(stable_slot_id),
            )?;
            return Ok(true);
        }
        let account_wide = self.removed_local_key_package_tombstone_path(&account_id_hex, None)?;
        if !account_wide.try_exists()? {
            return Ok(false);
        }
        self.validate_removed_local_key_package_tombstone(&account_wide, &account_id_hex, None)?;
        Ok(
            !self.active_local_key_package_slot_is_authorized_for_admitted_account(
                &account_id_hex,
                stable_slot_id,
                local_signing_account,
            )?,
        )
    }

    /// Whether a directory/publication candidate belongs to private local MLS
    /// material that this installation has irreversibly removed.
    ///
    /// Exact stable-slot tombstones always win. The account-wide marker is a
    /// legacy fail-closed fallback; a later explicit re-import may use only a
    /// newly minted slot proven by its active local lifecycle.
    pub(crate) fn removed_local_key_package_slot_is_retired(
        &self,
        account_id_hex: &str,
        stable_slot_id: &str,
    ) -> Result<bool, AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        let account_tombstone_dir =
            self.removed_local_key_package_account_tombstone_dir(&account_id_hex)?;
        if !account_tombstone_dir.try_exists()? {
            return Ok(false);
        }
        let exact =
            self.removed_local_key_package_tombstone_path(&account_id_hex, Some(stable_slot_id))?;
        if exact.try_exists()? {
            self.validate_removed_local_key_package_tombstone(
                &exact,
                &account_id_hex,
                Some(stable_slot_id),
            )?;
            return Ok(true);
        }
        let account_wide = self.removed_local_key_package_tombstone_path(&account_id_hex, None)?;
        if !account_wide.try_exists()? {
            return Ok(false);
        }
        self.validate_removed_local_key_package_tombstone(&account_wide, &account_id_hex, None)?;
        Ok(!self.active_local_key_package_slot_is_authorized(&account_id_hex, stable_slot_id)?)
    }

    fn removed_local_key_package_scope(
        &self,
        account: &AccountSummary,
    ) -> Option<RemovedLocalKeyPackageScope> {
        if !account.can_sign() {
            return None;
        }
        if self.account_storage_path(&account.label).exists()
            && let Ok(storage) = self.account_storage(&account.label)
            && let Ok(Some(lifecycle)) = storage.key_package_lifecycle()
            && !lifecycle.stable_slot_id.is_empty()
        {
            return Some(RemovedLocalKeyPackageScope::StableSlot(
                lifecycle.stable_slot_id,
            ));
        }
        if let Ok(Some(stable_slot_id)) =
            self.reusable_key_package_slot_id(&account.label, &account.account_id_hex)
        {
            return Some(RemovedLocalKeyPackageScope::StableSlot(stable_slot_id));
        }
        Some(RemovedLocalKeyPackageScope::AccountWideLegacy)
    }

    fn purge_removed_local_key_package_projections(
        &self,
        account_id_hex: &str,
        scope: &RemovedLocalKeyPackageScope,
    ) -> Result<(), AppError> {
        self.member_key_package_prewarm_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(account_id_hex);
        let stable_slot_id = match scope {
            RemovedLocalKeyPackageScope::StableSlot(stable_slot_id) => {
                Some(stable_slot_id.as_str())
            }
            RemovedLocalKeyPackageScope::AccountWideLegacy => None,
        };
        let shared = self.shared_storage()?;
        if let Some(record) = shared.public_directory_user(account_id_hex)?
            && let Some(key_package_json) = record.key_package_json.as_deref()
        {
            let should_clear = stable_slot_id.is_none_or(|stable_slot_id| {
                serde_json::from_str::<DirectoryKeyPackage>(key_package_json)
                    .is_ok_and(|key_package| key_package.key_package_id == stable_slot_id)
            });
            if should_clear {
                let _ = shared.clear_public_directory_key_package_if_matches(
                    account_id_hex,
                    key_package_json,
                )?;
            }
        }
        for cache in self.directory_caches()? {
            let _ = cache.clear_key_package_if_slot(account_id_hex, stable_slot_id)?;
        }
        self.request_directory_sync_rebuild();
        Ok(())
    }

    /// Persist the immutable local-removal authority before any account
    /// artifact or AccountHome bytes are deleted, then scrub its cached
    /// projections. Marker persistence is the destructive commit prerequisite;
    /// projection cleanup is retryable because every read/write path consults
    /// the marker.
    pub(crate) fn persist_removed_local_key_package_tombstone(
        &self,
        account: &AccountSummary,
    ) -> Result<(), AppError> {
        let Some(scope) = self.removed_local_key_package_scope(account) else {
            return Ok(());
        };
        let stable_slot_id = match &scope {
            RemovedLocalKeyPackageScope::StableSlot(stable_slot_id) => {
                Some(stable_slot_id.as_str())
            }
            RemovedLocalKeyPackageScope::AccountWideLegacy => None,
        };
        {
            let _mutation = self
                .removed_local_key_package_mutation_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Create and sync each namespace level separately. `create_dir_all`
            // followed only by a sync of the deepest parent would not durably
            // publish a newly created top-level `key-packages` entry.
            self.ensure_private_directory_entry_durable(
                &self.key_package_cache_dir().join(KEY_PACKAGE_DIR),
            )?;
            let root = self.removed_local_key_package_tombstone_root();
            self.ensure_private_directory_entry_durable(&root)?;
            let account_dir =
                self.removed_local_key_package_account_tombstone_dir(&account.account_id_hex)?;
            self.ensure_private_directory_entry_durable(&account_dir)?;
            let tombstone_path = self.removed_local_key_package_tombstone_path(
                &account.account_id_hex,
                stable_slot_id,
            )?;
            if tombstone_path.try_exists()? {
                self.validate_removed_local_key_package_tombstone(
                    &tombstone_path,
                    &account.account_id_hex,
                    stable_slot_id,
                )?;
            } else {
                self.write_private_json(
                    &tombstone_path,
                    &RemovedLocalKeyPackageTombstone {
                        account_id_hex: account.account_id_hex.clone(),
                        stable_slot_id: stable_slot_id.map(str::to_owned),
                    },
                    "removed-local KeyPackage tombstone",
                )?;
            }
        }
        // The immutable marker now gates every writer. Release the mutation
        // mutex before opening caches: one-time legacy migration takes that
        // same mutex and will either have completed before the marker or will
        // observe it before importing any old projection.
        if let Err(error) =
            self.purge_removed_local_key_package_projections(&account.account_id_hex, &scope)
        {
            tracing::warn!(
                target: "marmot_app::key_packages",
                method = "persist_removed_local_key_package_tombstone",
                error_kind = error.privacy_safe_kind(),
                "removed-local KeyPackage tombstone committed but projection scrub is pending"
            );
        }
        Ok(())
    }

    /// Remove compatibility artifacts that live outside the account directory.
    /// Account-home deletion cannot otherwise make setup rollback complete.
    fn remove_account_key_package_artifacts(&self, label: &str) -> Result<(), AppError> {
        for path in [
            self.key_package_record_path(label),
            self.key_package_cutover_replacement_pending_path(label),
            self.generated_initial_key_package_publication_hold_path(label),
            self.key_package_cutover_relay_frontier_path(label),
            self.key_package_cutover_relay_history_path(label),
            self.key_package_teardown_cleanup_pending_path(label),
            self.pending_nip65_route_mutation_path(label),
            self.nip65_route_generation_path(label),
            self.legacy_key_package_cutover_scan_complete_path(label),
            self.key_package_cutover_scan_complete_path(label),
        ] {
            remove_file_if_present(path)?;
        }
        Ok(())
    }

    fn key_package_cutover_has_fresh_account_proof(&self, label: &str) -> bool {
        read_json::<KeyPackageCutoverScanMarker>(self.key_package_cutover_scan_complete_path(label))
            .is_ok_and(|marker| marker.strict_history_peeling && marker.fresh_account_proof)
    }

    fn mark_key_package_cutover_scan_complete(&self, label: &str) -> Result<(), AppError> {
        self.write_key_package_cutover_scan_marker(
            label,
            &KeyPackageCutoverScanMarker {
                strict_history_peeling: true,
                fresh_account_proof: true,
                authoritative_relays: Vec::new(),
                history_relays: Vec::new(),
                route_created_at: None,
                route_event_id: None,
            },
        )
    }

    fn key_package_cutover_scan_complete_for_relays(
        &self,
        label: &str,
        source_relays: &[TransportEndpoint],
    ) -> bool {
        if !self
            .key_package_teardown_cleanup_pending(label)
            .is_ok_and(|pending| !pending)
        {
            return false;
        }
        if !self
            .key_package_cutover_relay_frontier(label)
            .is_ok_and(|frontier| frontier.is_empty())
        {
            return false;
        }
        let Ok(marker) = read_json::<KeyPackageCutoverScanMarker>(
            self.key_package_cutover_scan_complete_path(label),
        ) else {
            return false;
        };
        if !marker.strict_history_peeling {
            return false;
        }
        if marker.fresh_account_proof && !self.pending_nip65_route_mutation(label) {
            return true;
        }
        let Ok(required_history) = self.key_package_history_endpoints(label) else {
            return false;
        };
        let history_was_covered = required_history
            .iter()
            .all(|endpoint| marker.history_relays.binary_search(&endpoint.0).is_ok());
        if !history_was_covered {
            return false;
        }
        let mut expected = source_relays
            .iter()
            .map(|endpoint| endpoint.0.clone())
            .collect::<Vec<_>>();
        expected.sort();
        expected.dedup();
        let Ok(Some(current_generation)) = self.read_nip65_route_generation_for_authoring(label)
        else {
            return false;
        };
        let Ok(authoritative_endpoints) = self.validate_nip65_route_generation(&current_generation)
        else {
            return false;
        };
        let mut generation_relays = authoritative_endpoints
            .into_iter()
            .map(|endpoint| endpoint.0)
            .collect::<Vec<_>>();
        generation_relays.sort();
        generation_relays.dedup();
        marker.authoritative_relays == expected
            && expected == generation_relays
            && marker.route_created_at == Some(current_generation.created_at)
            && marker.route_event_id == Some(current_generation.event_id)
    }

    fn mark_key_package_cutover_scan_complete_for_relays(
        &self,
        label: &str,
        source_relays: &[TransportEndpoint],
        scanned_history_relays: &BTreeSet<TransportEndpoint>,
    ) -> Result<(), AppError> {
        let _frontier_mutation = self
            .key_package_frontier_mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.key_package_cutover_relay_frontier(label)?.is_empty() {
            return Err(AppError::Publish(
                "cannot complete KeyPackage cutover with relay-history scans pending".into(),
            ));
        }
        let mut authoritative_relays = source_relays
            .iter()
            .map(|endpoint| endpoint.0.clone())
            .collect::<Vec<_>>();
        authoritative_relays.sort();
        authoritative_relays.dedup();
        let generation = self
            .read_nip65_route_generation_for_authoring(label)?
            .ok_or_else(|| {
                AppError::Publish(
                    "cannot complete KeyPackage cutover without local NIP-65 route authority"
                        .into(),
                )
            })?;
        let mut generation_relays = self
            .validate_nip65_route_generation(&generation)?
            .into_iter()
            .map(|endpoint| endpoint.0)
            .collect::<Vec<_>>();
        generation_relays.sort();
        generation_relays.dedup();
        if authoritative_relays != generation_relays {
            return Err(AppError::Publish(
                "cannot bind a KeyPackage cutover marker to stale NIP-65 relays".into(),
            ));
        }
        let required_history_relays = self
            .account_storage(label)?
            .key_package_lifecycle()?
            .as_ref()
            .map(|lifecycle| self.key_package_lifecycle_history_endpoints(lifecycle))
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .chain(source_relays.iter().cloned())
            .collect::<BTreeSet<_>>();
        if !required_history_relays.is_subset(scanned_history_relays) {
            return Err(AppError::Publish(
                "cannot complete KeyPackage cutover with an unscanned historical relay".into(),
            ));
        }
        let durable_history_relays = self
            .extend_key_package_cutover_relay_history_under_root(label, scanned_history_relays)?;
        let mut history_relays = durable_history_relays
            .iter()
            .map(|endpoint| endpoint.0.clone())
            .collect::<Vec<_>>();
        history_relays.sort();
        history_relays.dedup();
        self.write_key_package_cutover_scan_marker(
            label,
            &KeyPackageCutoverScanMarker {
                strict_history_peeling: true,
                fresh_account_proof: false,
                authoritative_relays,
                history_relays,
                route_created_at: Some(generation.created_at),
                route_event_id: Some(generation.event_id),
            },
        )
    }

    fn write_key_package_cutover_scan_marker(
        &self,
        label: &str,
        marker: &KeyPackageCutoverScanMarker,
    ) -> Result<(), AppError> {
        let path = self.key_package_cutover_scan_complete_path(label);
        let result = self.write_private_json(&path, marker, "completed KeyPackage relay scan");
        if let Err(error) = &result {
            tracing::warn!(
                target: "marmot_app::key_packages",
                method = "mark_key_package_cutover_scan_complete",
                error_kind = error.privacy_safe_kind(),
                "could not persist completed key package relay scan"
            );
        }
        result
    }

    fn key_package_cutover_publication_allowed(&self, label: &str) -> bool {
        // A prepared route mutation is publication-relevant even before its
        // kind-10002 has an acknowledgement. This file is written before the
        // durable lifecycle gate is armed, so it is also the crash-safe fence
        // for that narrow pre-arm window.
        if self.pending_nip65_route_mutation(label) {
            return false;
        }
        let Ok(source_relays) = self.authoritative_key_package_relays(label) else {
            return false;
        };
        self.key_package_cutover_scan_complete_for_relays(label, &source_relays)
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
            let mut record_source_relays = source_relays.clone();

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
                    push_unique_strings(
                        &mut record_source_relays,
                        lifecycle
                            .publication_targets
                            .iter()
                            .map(|target| target.endpoint.0.clone()),
                    );
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
                    push_unique_strings(
                        &mut record_source_relays,
                        pending
                            .targets
                            .iter()
                            .map(|target| target.endpoint.0.clone()),
                    );
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
                source_relays: record_source_relays,
                local: true,
                relay: false,
            });
        }
        Ok(records)
    }

    /// Exact locally-authored event ids and historical target snapshots that
    /// teardown must delete even when relay discovery is unavailable.
    ///
    /// This is deliberately a deletion-target projection, not a synthetic
    /// [`AccountKeyPackageRecord`]: retired signed revisions no longer own MLS
    /// private material and must never be reported as `local` KeyPackages.
    pub(crate) fn durable_key_package_deletion_targets(
        &self,
        label: &str,
    ) -> Result<Vec<KeyPackageDeletionTarget>, AppError> {
        let Some(lifecycle) = self.account_storage(label)?.key_package_lifecycle()? else {
            return Ok(Vec::new());
        };
        let mut targets = Vec::new();
        let mut push = |event_id: &cgka_traits::MessageId, endpoints: Vec<TransportEndpoint>| {
            if !endpoints.is_empty() {
                targets.push(KeyPackageDeletionTarget {
                    event_id_hex: hex::encode(event_id.as_slice()),
                    source_relays: endpoints,
                });
            }
        };

        if let Some(event_id) = lifecycle
            .authored_signed_event
            .as_ref()
            .map(|artifact| &artifact.id)
            .or(lifecycle.authored_event_id.as_ref())
        {
            push(
                event_id,
                lifecycle
                    .publication_targets
                    .iter()
                    .map(|target| target.endpoint.clone())
                    .collect(),
            );
        }
        if let Some(pending) = lifecycle.pending_replacement.as_ref()
            && let Some(artifact) = pending.signed_event.as_ref()
        {
            push(
                &artifact.id,
                pending
                    .targets
                    .iter()
                    .map(|target| target.endpoint.clone())
                    .collect(),
            );
        }
        for retired in &lifecycle.retired_publications_pending_deletion {
            push(
                &retired.event_id,
                retired
                    .deletion_targets
                    .iter()
                    .map(|target| target.endpoint.clone())
                    .collect(),
            );
        }
        Ok(targets)
    }

    pub async fn account_key_package_records(
        &self,
        label: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
        owned_key_packages: Vec<KeyPackage>,
    ) -> Result<Vec<AccountKeyPackageRecord>, AppError> {
        let account = self.account_home().account(label)?;
        let account_id_hex = account.account_id_hex.clone();
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

    /// Legacy direct-app seam retained for API compatibility.
    ///
    /// Every KeyPackage deletion requires a durable runtime admission and
    /// pre-I/O recovery journal, including relay-discovered unknown revisions.
    /// Use [`MarmotAppRuntime::delete_key_package`]; this method validates the
    /// event-id shape, then always fails before storage, signing, or relay I/O.
    pub async fn delete_key_package_event(
        &self,
        _label: &str,
        event_id_hex: &str,
        _source_relays: Vec<TransportEndpoint>,
    ) -> Result<usize, AppError> {
        parse_key_package_event_id_hex(event_id_hex)?;
        Err(AppError::Publish(
            "direct KeyPackage deletion requires durable runtime admission".to_owned(),
        ))
    }

    /// Canonicalize deletion endpoint keys through the relay dial policy
    /// without applying the live-route cardinality cap to a historical cleanup
    /// obligation. Each returned key has independently passed the same safety
    /// validation used at I/O, and canonical aliases collapse before durable
    /// admission or publication.
    fn sanitize_key_package_deletion_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
    ) -> Result<Vec<TransportEndpoint>, AppError> {
        self.key_package_deletion_endpoint_aliases(&endpoints)
            .map(|(canonical, _aliases)| canonical)
    }

    fn canonicalize_key_package_endpoint(
        &self,
        endpoint: &TransportEndpoint,
        context: &str,
    ) -> Result<TransportEndpoint, AppError> {
        let mut canonical = self
            .relay_plane
            .sanitize_relay_endpoints(vec![endpoint.clone()], context)
            .map_err(|error| {
                AppError::Transport(cgka_traits::TransportAdapterError::Publish(error))
            })?;
        canonical.pop().ok_or_else(|| {
            AppError::Publish(
                "key package endpoint canonicalization produced no endpoint".to_owned(),
            )
        })
    }

    /// Return both the deduplicated canonical I/O keys and the exact durable
    /// keys from which they came. The alias map lets active maintenance read a
    /// legacy noncanonical journal row, perform I/O only with a safety-approved
    /// canonical URL, and translate the receipt back to the exact key that its
    /// transport-generic lifecycle owner must prune.
    fn key_package_deletion_endpoint_aliases(
        &self,
        endpoints: &[TransportEndpoint],
    ) -> Result<KeyPackageDeletionEndpointAliases, AppError> {
        let mut sanitized = Vec::with_capacity(endpoints.len());
        let mut aliases = Vec::with_capacity(endpoints.len());
        for requested_endpoint in endpoints {
            let canonical_endpoint = self.canonicalize_key_package_endpoint(
                requested_endpoint,
                "key package deletion publish",
            )?;
            aliases.push((requested_endpoint.clone(), canonical_endpoint.clone()));
            sanitized.push(canonical_endpoint);
        }
        sanitized.sort();
        sanitized.dedup();
        Ok((sanitized, aliases))
    }

    /// Repair valid legacy endpoint aliases while the account worker is
    /// quiesced. Unsafe/invalid keys remain byte-for-byte intact and therefore
    /// fail closed when selected; they are never silently erased as part of an
    /// upgrade. Canonical collisions merge into one target while retaining the
    /// strongest absence, acceptance, or possible-exposure evidence.
    fn canonicalize_quiesced_key_package_lifecycle_targets(
        &self,
        lifecycle: &mut cgka_traits::KeyPackageLifecycleState,
    ) -> bool {
        let mut changed = canonicalize_key_package_fanout_targets(
            &mut lifecycle.publication_targets,
            |endpoint| {
                self.canonicalize_key_package_endpoint(
                    endpoint,
                    "key package lifecycle endpoint repair",
                )
                .ok()
            },
        );
        if let Some(pending) = lifecycle.pending_replacement.as_mut() {
            changed |= canonicalize_key_package_fanout_targets(&mut pending.targets, |endpoint| {
                self.canonicalize_key_package_endpoint(
                    endpoint,
                    "key package lifecycle endpoint repair",
                )
                .ok()
            });
        }
        for retired in &mut lifecycle.retired_publications_pending_deletion {
            changed |= canonicalize_key_package_fanout_targets(
                &mut retired.deletion_targets,
                |endpoint| {
                    self.canonicalize_key_package_endpoint(
                        endpoint,
                        "key package lifecycle endpoint repair",
                    )
                    .ok()
                },
            );
        }
        changed
    }

    /// Normalize valid persisted relay aliases while the account-session guard
    /// is held but before the transport-generic runtime reads the lifecycle.
    /// This gives successor eligibility and deletion pruning one durable
    /// endpoint identity across upgrades. Unsafe legacy keys remain unchanged
    /// and therefore retry fail-closed through the publisher boundary.
    fn canonicalize_key_package_lifecycle_targets_before_session_open(
        &self,
        label: &str,
    ) -> Result<(), AppError> {
        let storage = self.account_storage(label)?;
        let Some(mut lifecycle) = storage.key_package_lifecycle()? else {
            return Ok(());
        };
        if self.canonicalize_quiesced_key_package_lifecycle_targets(&mut lifecycle) {
            storage.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok(())
    }

    pub(crate) async fn delete_key_package_events(
        &self,
        label: &str,
        targets: Vec<KeyPackageDeletionTarget>,
        session_admission: AccountSessionAdmission,
    ) -> Result<Vec<KeyPackageDeletionResult>, AppError> {
        // Active deletion serializes its final capability proof with teardown.
        // Teardown cleanup already owns the route lock while peeling history,
        // so its exact cleanup capability must not recursively acquire it.
        let active_route_lock = matches!(&session_admission, AccountSessionAdmission::Active(_))
            .then(|| self.key_package_route_lock(label));
        let _active_route_guard = match active_route_lock.as_ref() {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let history_lock = self.key_package_history_lock(label);
        let _history_guard = history_lock.lock().await;
        let account = self.account_home().account(label)?;
        let admission_is_current = || match &session_admission {
            AccountSessionAdmission::Active(token) => {
                account.is_active_signing()
                    && account.account_id_hex == token.account_id_hex
                    && self.active_account_session_admission_is_current(label, token)
            }
            AccountSessionAdmission::Teardown(token) => {
                account.signed_out
                    && account.account_id_hex == token.account_id_hex
                    && self.account_teardown_session_admission_is_current(label, token)
            }
        };
        if !admission_is_current() {
            return Err(AppError::AccountWorkerBusy);
        }
        let signer = self.account_signer_for_summary(&account)?;
        let account_id_hex = account.account_id_hex.clone();
        // This is the lowest kind-5 I/O boundary. A process-local session
        // capability proves who may act, but it does not prove that the exact
        // relay side effect is crash-recoverable. Re-read the SQL lifecycle
        // journal only after the route/history admission locks are held, then
        // require every exact event/endpoint pair below to remain selected.
        // Active callers persist this row through
        // `prepare_key_package_deletion_recovery`; quiesced teardown persists
        // it through `prepare_quiesced_key_package_deletion_recovery`.
        let deletion_journal = self.account_storage(label)?.key_package_lifecycle()?;
        let mut results = targets
            .iter()
            .map(|target| KeyPackageDeletionResult {
                event_id_hex: target.event_id_hex.clone(),
                accepted_endpoints: Vec::new(),
                confirmed_absent_endpoints: Vec::new(),
                failed_endpoints: Vec::new(),
                result: Err(AppError::Publish("deletion was not attempted".to_owned())),
            })
            .collect::<Vec<_>>();
        let mut requests = Vec::new();
        let mut request_targets = Vec::new();
        let mut attempted = vec![false; results.len()];
        let mut errors = (0..results.len()).map(|_| None).collect::<Vec<_>>();

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
            let endpoints = match self.sanitize_key_package_deletion_endpoints(endpoints) {
                Ok(endpoints) => endpoints,
                Err(error) => {
                    results[index].result = Err(error);
                    continue;
                }
            };
            let event_id = MessageId::new(
                hex::decode(&event_id_hex)
                    .expect("validated KeyPackage event id remains canonical hex"),
            );
            let durably_selected = deletion_journal.as_ref().is_some_and(|lifecycle| {
                lifecycle
                    .retired_publications_pending_deletion
                    .iter()
                    .find(|retired| retired.event_id == event_id)
                    .is_some_and(|retired| {
                        endpoints.iter().all(|canonical_endpoint| {
                            retired.deletion_targets.iter().any(|durable_target| {
                                durable_target.failure_code.as_deref() != Some("confirmed_absent")
                                    && self
                                        .key_package_deletion_endpoint_aliases(
                                            std::slice::from_ref(&durable_target.endpoint),
                                        )
                                        .is_ok_and(|(_canonical, aliases)| {
                                            aliases.iter().any(|(durable_key, canonical_key)| {
                                                durable_key == &durable_target.endpoint
                                                    && canonical_key == canonical_endpoint
                                            })
                                        })
                            })
                        })
                    })
            });
            if !durably_selected {
                results[index].result = Err(AppError::Publish(
                    "key package deletion target was not durably selected by the account lifecycle journal"
                        .to_owned(),
                ));
                continue;
            }
            let event = NostrTransportEvent::new_unsigned(
                account_id_hex.clone(),
                5,
                vec![
                    vec!["e".into(), event_id_hex],
                    vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
                ],
                String::new(),
            );
            // One request per endpoint is load-bearing. The SDK completes a
            // request once its required acknowledgement count is met; a single
            // multi-endpoint request with `required_acks = 1` can therefore
            // cancel the remaining sends and falsely report whole-event
            // deletion after only one relay accepted it.
            for endpoint in endpoints {
                attempted[index] = true;
                requests.push(NostrEventPublishRequest {
                    endpoints: vec![endpoint.clone()],
                    event: event.clone(),
                    required_acks: 1,
                });
                request_targets.push((index, endpoint));
            }
        }

        if !requests.is_empty() {
            if !admission_is_current() {
                return Err(AppError::AccountWorkerBusy);
            }
            // Universal pre-I/O crash boundary for every kind-5 KeyPackage
            // deletion, including quiesced logout cleanup and low-level
            // relay-discovered retirement. A later accepted or ambiguous send
            // can reveal older parameterized-replaceable history, so future
            // publication remains blocked until these endpoints receive a
            // strict short-page replay.
            self.extend_key_package_cutover_relay_frontier(
                label,
                request_targets
                    .iter()
                    .map(|(_index, endpoint)| endpoint.clone())
                    .collect(),
            )?;
            let relay_client =
                self.relay_client_for_account_id(&account_id_hex, signer.as_nostr_signer());
            let mut outcomes = relay_client.publish_events(&requests).await.into_iter();
            for (index, endpoint) in request_targets {
                let Some(outcome) = outcomes.next() else {
                    if !results[index].failed_endpoints.contains(&endpoint) {
                        results[index].failed_endpoints.push(endpoint);
                    }
                    errors[index].get_or_insert_with(|| {
                        AppError::Publish(
                            "relay returned no result for a key package deletion".to_owned(),
                        )
                    });
                    continue;
                };
                match outcome {
                    Ok(outcome)
                        if outcome
                            .accepted
                            .iter()
                            .any(|receipt| receipt.endpoint == endpoint) =>
                    {
                        if !results[index].accepted_endpoints.contains(&endpoint) {
                            results[index].accepted_endpoints.push(endpoint);
                        }
                    }
                    Ok(_) => {
                        if !results[index].failed_endpoints.contains(&endpoint) {
                            results[index].failed_endpoints.push(endpoint);
                        }
                        errors[index].get_or_insert_with(|| {
                            AppError::Publish(
                                "relay acknowledged zero key package deletions".to_owned(),
                            )
                        });
                    }
                    Err(error) => {
                        let target_is_confirmed_absent =
                            error.publish_endpoint_failures().iter().any(|failure| {
                                failure.endpoint == endpoint && failure.confirms_target_absence()
                            });
                        if target_is_confirmed_absent {
                            if !results[index]
                                .confirmed_absent_endpoints
                                .contains(&endpoint)
                            {
                                results[index].confirmed_absent_endpoints.push(endpoint);
                            }
                        } else if !results[index].failed_endpoints.contains(&endpoint) {
                            results[index].failed_endpoints.push(endpoint);
                        }
                        if !target_is_confirmed_absent && errors[index].is_none() {
                            errors[index] = Some(error.into());
                        }
                    }
                }
            }
        }

        for (index, was_attempted) in attempted.into_iter().enumerate() {
            if !was_attempted {
                continue;
            }
            results[index].accepted_endpoints.sort();
            results[index].accepted_endpoints.dedup();
            results[index].confirmed_absent_endpoints.sort();
            results[index].confirmed_absent_endpoints.dedup();
            results[index].failed_endpoints.sort();
            results[index].failed_endpoints.dedup();
            let terminal_endpoint_count = results[index]
                .accepted_endpoints
                .len()
                .saturating_add(results[index].confirmed_absent_endpoints.len());
            results[index].result = if terminal_endpoint_count == 0 {
                Err(errors[index].take().unwrap_or_else(|| {
                    AppError::Publish("key package deletion produced no relay result".to_owned())
                }))
            } else if !results[index].failed_endpoints.is_empty() {
                Err(errors[index].take().unwrap_or_else(|| {
                    AppError::Publish(
                        "one or more relay key package deletions remain retryable".to_owned(),
                    )
                }))
            } else {
                Ok(terminal_endpoint_count)
            };
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

    /// Persist recovery intent before quiesced teardown can send a kind-5 for
    /// the current or pending revision.
    ///
    /// The caller must own the account teardown barrier: this whole-row
    /// lifecycle mutation is not safe beside the serialized account worker.
    pub(crate) fn prepare_quiesced_key_package_deletion_recovery(
        &self,
        label: &str,
        targets: &[KeyPackageDeletionTarget],
    ) -> Result<KeyPackageDeletionAdmission, AppError> {
        let _root_mutation =
            self.begin_root_mutation("prepare quiesced KeyPackage deletion recovery")?;
        if !targets.is_empty() {
            // Invalidate before changing the SQL journal. A crash after the
            // lifecycle commit but before removing an older completion marker
            // could otherwise let teardown's focused peel take the stale fast
            // path and erase the only retry evidence without another scan.
            self.invalidate_key_package_cutover_scan_marker(label)?;
        }
        let storage = self.account_storage(label)?;
        let mut lifecycle = match storage.key_package_lifecycle()? {
            Some(lifecycle) => lifecycle,
            None => {
                let account = self.account_home().account(label)?;
                let stable_slot_id = self
                    .reusable_key_package_slot_id(label, &account.account_id_hex)?
                    .ok_or_else(|| {
                        AppError::Publish(
                            "cannot durably journal KeyPackage deletion without a stable slot"
                                .to_owned(),
                        )
                    })?;
                cgka_traits::KeyPackageLifecycleState::slot_only(stable_slot_id)
            }
        };
        let mut changed = self.canonicalize_quiesced_key_package_lifecycle_targets(&mut lifecycle);

        // Resolve every target into the exact liability that can escape in the
        // following kind-5 send. Unknown relay-discovered event ids (including
        // other stable `d` slots) are not covered by a later local NIP-33
        // replacement and therefore need the same durable per-endpoint retry
        // journal as locally authored revisions.
        let mut deletion_liabilities: Vec<(
            String,
            MessageId,
            Vec<TransportEndpoint>,
            Vec<TransportEndpoint>,
        )> = Vec::new();
        let mut invalid_targets = Vec::new();
        for target in targets {
            let event_id_hex = match parse_key_package_event_id_hex(&target.event_id_hex) {
                Ok(event_id_hex) => event_id_hex,
                Err(error) => {
                    invalid_targets.push(KeyPackageDeletionInvalidTarget {
                        target: target.clone(),
                        reason: error.to_string(),
                    });
                    continue;
                }
            };
            if target.source_relays.is_empty() {
                invalid_targets.push(KeyPackageDeletionInvalidTarget {
                    target: KeyPackageDeletionTarget {
                        event_id_hex,
                        source_relays: Vec::new(),
                    },
                    reason: "key package deletion target has no relay endpoints".to_owned(),
                });
                continue;
            }
            let mut safe_endpoints = Vec::new();
            let mut unsafe_endpoints = Vec::new();
            for endpoint in &target.source_relays {
                match self
                    .canonicalize_key_package_endpoint(endpoint, "key package deletion publish")
                {
                    Ok(canonical) => safe_endpoints.push(canonical),
                    Err(_) => unsafe_endpoints.push(endpoint.clone()),
                }
            }
            safe_endpoints.sort();
            safe_endpoints.dedup();
            unsafe_endpoints.sort();
            unsafe_endpoints.dedup();
            let event_id = MessageId::new(
                hex::decode(&event_id_hex)
                    .map_err(|_| AppError::Publish("invalid key package event id".to_owned()))?,
            );
            if let Some((_, _, existing_safe, existing_unsafe)) = deletion_liabilities
                .iter_mut()
                .find(|(existing_id, _, _, _)| existing_id == &event_id_hex)
            {
                existing_safe.extend(safe_endpoints);
                existing_safe.sort();
                existing_safe.dedup();
                existing_unsafe.extend(unsafe_endpoints);
                existing_unsafe.sort();
                existing_unsafe.dedup();
            } else {
                deletion_liabilities.push((
                    event_id_hex,
                    event_id,
                    safe_endpoints,
                    unsafe_endpoints,
                ));
            }
        }

        let mut exact_liabilities = HashSet::new();
        let mut include_targets =
            |event_id: &MessageId, targets: &[cgka_traits::TransportFanoutTarget]| {
                for target in targets {
                    if target.failure_code.as_deref() != Some("confirmed_absent") {
                        exact_liabilities
                            .insert((event_id.as_slice().to_vec(), target.endpoint.clone()));
                    }
                }
            };
        if let Some(artifact) = lifecycle.authored_signed_event.as_ref() {
            include_targets(&artifact.id, &lifecycle.publication_targets);
        }
        if let Some(event_id) = lifecycle.authored_event_id.as_ref() {
            // Pre-artifact upgrade rows can retain the exact current event id
            // and endpoint exposure set without the signed bytes. Count those
            // pairs before admitting any new deletion liability. If a corrupt
            // row carries two differing identity representations, including
            // both is the conservative capacity decision.
            include_targets(event_id, &lifecycle.publication_targets);
        }
        if let Some(pending) = lifecycle.pending_replacement.as_ref()
            && let Some(artifact) = pending.signed_event.as_ref()
        {
            include_targets(&artifact.id, &pending.targets);
        }
        for retired in &lifecycle.retired_publications_pending_deletion {
            include_targets(&retired.event_id, &retired.deletion_targets);
        }
        let mut admitted_targets = Vec::new();
        let mut deferred_targets = Vec::new();
        let mut unsafe_targets = Vec::new();
        let mut journaled_liabilities = Vec::new();
        let mut live_event_ids = HashSet::new();
        if let Some(artifact) = lifecycle.authored_signed_event.as_ref() {
            live_event_ids.insert(artifact.id.as_slice().to_vec());
        }
        if let Some(event_id) = lifecycle.authored_event_id.as_ref() {
            live_event_ids.insert(event_id.as_slice().to_vec());
        }
        if let Some(artifact) = lifecycle
            .pending_replacement
            .as_ref()
            .and_then(|pending| pending.signed_event.as_ref())
        {
            live_event_ids.insert(artifact.id.as_slice().to_vec());
        }
        for (event_id_hex, event_id, safe_endpoints, unsafe_endpoints) in deletion_liabilities {
            let is_live_revision = live_event_ids.contains(event_id.as_slice());
            let mut requested_endpoints = safe_endpoints
                .iter()
                .chain(&unsafe_endpoints)
                .cloned()
                .collect::<Vec<_>>();
            requested_endpoints.sort();
            requested_endpoints.dedup();
            let required_new_liabilities = requested_endpoints
                .iter()
                .filter(|endpoint| {
                    !exact_liabilities
                        .contains(&(event_id.as_slice().to_vec(), (*endpoint).clone()))
                })
                .count();
            let liability_capacity = if is_live_revision {
                cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES_WITH_LIVE_DELETION_OVERFLOW
            } else {
                cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES
            };
            if required_new_liabilities > liability_capacity.saturating_sub(exact_liabilities.len())
            {
                // No exact event can be deleted at only a subset of its
                // requested endpoints. Unknown ids do not prove a sibling
                // slot; a later replacement could hide the old exact id while
                // an unjournaled endpoint remains. Defer the whole event: no
                // kind-5 target, unsafe admission, or live marker is produced
                // until every new pair fits in the bounded reserve.
                deferred_targets.push(KeyPackageDeletionTarget {
                    event_id_hex,
                    source_relays: requested_endpoints,
                });
                continue;
            }
            let mut admitted_endpoints = Vec::new();
            let mut journaled_unsafe_endpoints = Vec::new();
            let mut deferred_endpoints = Vec::new();
            for (endpoint, safe_for_io) in safe_endpoints
                .into_iter()
                .map(|endpoint| (endpoint, true))
                .chain(
                    unsafe_endpoints
                        .into_iter()
                        .map(|endpoint| (endpoint, false)),
                )
            {
                let liability = (event_id.as_slice().to_vec(), endpoint.clone());
                if exact_liabilities.contains(&liability)
                    || exact_liabilities.len() < liability_capacity
                {
                    exact_liabilities.insert(liability);
                    if safe_for_io {
                        admitted_endpoints.push(endpoint);
                    } else {
                        journaled_unsafe_endpoints.push(endpoint);
                    }
                } else {
                    deferred_endpoints.push(endpoint);
                }
            }
            if !admitted_endpoints.is_empty() {
                admitted_targets.push(KeyPackageDeletionTarget {
                    event_id_hex: event_id_hex.clone(),
                    source_relays: admitted_endpoints.clone(),
                });
            }
            if !journaled_unsafe_endpoints.is_empty() {
                unsafe_targets.push(KeyPackageDeletionTarget {
                    event_id_hex: event_id_hex.clone(),
                    source_relays: journaled_unsafe_endpoints.clone(),
                });
            }
            let mut journaled_endpoints = admitted_endpoints;
            journaled_endpoints.extend(journaled_unsafe_endpoints);
            if !journaled_endpoints.is_empty() {
                journaled_liabilities.push((event_id, journaled_endpoints, is_live_revision));
            }
            if !deferred_endpoints.is_empty() {
                deferred_targets.push(KeyPackageDeletionTarget {
                    event_id_hex,
                    source_relays: deferred_endpoints,
                });
            }
        }

        let pending_event_id = lifecycle
            .pending_replacement
            .as_ref()
            .and_then(|pending| pending.signed_event.as_ref())
            .map(|artifact| artifact.id.clone());
        for (event_id, endpoints, live_admission) in journaled_liabilities {
            let deletes_current = lifecycle
                .authored_signed_event
                .as_ref()
                .is_some_and(|artifact| artifact.id == event_id)
                || lifecycle.authored_event_id.as_ref() == Some(&event_id);
            if live_admission
                && (deletes_current || pending_event_id.as_ref() == Some(&event_id))
                && !lifecycle
                    .deleted_live_revision_event_ids
                    .contains(&event_id)
            {
                lifecycle
                    .deleted_live_revision_event_ids
                    .push(event_id.clone());
                changed = true;
            }
            if let Some(retired) = lifecycle
                .retired_publications_pending_deletion
                .iter_mut()
                .find(|retired| retired.event_id == event_id)
            {
                changed |= !retired.delete_without_successor;
                retired.delete_without_successor = true;
                for endpoint in endpoints {
                    if !retired
                        .deletion_targets
                        .iter()
                        .any(|target| target.endpoint == endpoint)
                    {
                        retired
                            .deletion_targets
                            .push(cgka_traits::TransportFanoutTarget {
                                endpoint,
                                state: cgka_traits::TransportFanoutAttemptState::Unattempted,
                                attempt_count: 0,
                                last_attempt_at: None,
                                failure_code: None,
                            });
                        changed = true;
                    }
                }
            } else {
                lifecycle.retired_publications_pending_deletion.push(
                    cgka_traits::RetiredKeyPackagePublication {
                        event_id,
                        authored_created_at: cgka_traits::Timestamp(0),
                        key_package_ref: None,
                        package_not_after: None,
                        delete_without_successor: true,
                        deletion_targets: endpoints
                            .into_iter()
                            .map(|endpoint| cgka_traits::TransportFanoutTarget {
                                endpoint,
                                state: cgka_traits::TransportFanoutAttemptState::Unattempted,
                                attempt_count: 0,
                                last_attempt_at: None,
                                failure_code: None,
                            })
                            .collect(),
                    },
                );
                changed = true;
            }
        }
        if changed {
            storage.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok(KeyPackageDeletionAdmission {
            admitted: admitted_targets,
            deferred: deferred_targets,
            unsafe_targets,
            invalid_targets,
        })
    }

    /// Commit endpoint-level acknowledgements for retired signed revisions.
    ///
    /// Call only while the account worker is quiesced. Active maintenance owns
    /// the same lifecycle row and performs this pruning inside the serialized
    /// account runtime instead.
    pub(crate) fn acknowledge_retired_key_package_deletions(
        &self,
        label: &str,
        results: &[KeyPackageDeletionResult],
    ) -> Result<(), AppError> {
        let storage = self.account_storage(label)?;
        let Some(mut lifecycle) = storage.key_package_lifecycle()? else {
            return Ok(());
        };
        let mut changed = false;
        let mut completed_retired_event_ids = Vec::new();
        for result in results {
            let mut terminal_endpoints = result.accepted_endpoints.clone();
            terminal_endpoints.extend(result.confirmed_absent_endpoints.clone());
            if terminal_endpoints.is_empty() {
                continue;
            }
            let deleted_current_revision = lifecycle
                .authored_signed_event
                .as_ref()
                .is_some_and(|artifact| hex::encode(artifact.id.as_slice()) == result.event_id_hex)
                || lifecycle
                    .authored_event_id
                    .as_ref()
                    .is_some_and(|event_id| {
                        hex::encode(event_id.as_slice()) == result.event_id_hex
                    });
            let deleted_pending_revision = lifecycle
                .pending_replacement
                .as_ref()
                .and_then(|pending| pending.signed_event.as_ref())
                .is_some_and(|artifact| hex::encode(artifact.id.as_slice()) == result.event_id_hex);
            if deleted_current_revision
                && let Some(event_id) = lifecycle
                    .authored_signed_event
                    .as_ref()
                    .map(|artifact| artifact.id.clone())
                && !lifecycle
                    .deleted_live_revision_event_ids
                    .contains(&event_id)
            {
                lifecycle.deleted_live_revision_event_ids.push(event_id);
                changed = true;
            }
            if deleted_pending_revision
                && let Some(event_id) = lifecycle
                    .pending_replacement
                    .as_ref()
                    .and_then(|pending| pending.signed_event.as_ref())
                    .map(|artifact| artifact.id.clone())
                && !lifecycle
                    .deleted_live_revision_event_ids
                    .contains(&event_id)
            {
                lifecycle.deleted_live_revision_event_ids.push(event_id);
                changed = true;
            }
            if deleted_current_revision {
                for target in &mut lifecycle.publication_targets {
                    if terminal_endpoints.contains(&target.endpoint) {
                        target.state = cgka_traits::TransportFanoutAttemptState::AttemptedFailed;
                        target.failure_code = Some("confirmed_absent".into());
                        changed = true;
                    }
                }
            }
            if deleted_pending_revision
                && let Some(pending) = lifecycle.pending_replacement.as_mut()
            {
                for target in &mut pending.targets {
                    if terminal_endpoints.contains(&target.endpoint) {
                        target.state = cgka_traits::TransportFanoutAttemptState::AttemptedFailed;
                        target.failure_code = Some("confirmed_absent".into());
                        changed = true;
                    }
                }
            }
            let Some(retired) = lifecycle
                .retired_publications_pending_deletion
                .iter_mut()
                .find(|retired| hex::encode(retired.event_id.as_slice()) == result.event_id_hex)
            else {
                continue;
            };
            let before = retired.deletion_targets.len();
            retired
                .deletion_targets
                .retain(|target| !terminal_endpoints.contains(&target.endpoint));
            if retired.deletion_targets.len() != before {
                changed = true;
                if retired.deletion_targets.is_empty() {
                    completed_retired_event_ids.push(retired.event_id.clone());
                }
            }
        }
        lifecycle
            .retired_publications_pending_deletion
            .retain(|retired| !completed_retired_event_ids.contains(&retired.event_id));
        if changed {
            storage.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok(())
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

    /// Historical relay provenance for a legacy cache can come only from a
    /// locally cached observation of that exact signed revision. Current
    /// NIP-65 or configured routing says where a replacement would publish
    /// today; projecting it onto an older event would invent exposure and can
    /// send deletion traffic to the wrong relay after an account route change.
    /// Read the account-private cache directly: the shared public projection
    /// intentionally strips source relays, and signed-out accounts are omitted
    /// from the aggregate active-account cache view.
    ///
    /// Directory-cache failures and mismatches deliberately degrade to
    /// unknown provenance. Account open must remain a local operation, and an
    /// unknown endpoint set must stay empty rather than falling back to live
    /// routing.
    fn cached_key_package_provenance(
        &self,
        account: &AccountSummary,
        record: &KeyPackageRecord,
        expected_key_package_ref_hex: Option<&str>,
    ) -> (Vec<TransportEndpoint>, Option<u64>) {
        let Some(cached) = self
            .directory_cache_for_account(account)
            .ok()
            .and_then(|cache| cache.entry(&account.account_id_hex).ok().flatten())
            .and_then(|entry| entry.key_package)
        else {
            return (Vec::new(), None);
        };
        if !cached
            .key_package_event_id
            .eq_ignore_ascii_case(&record.key_package_event_id)
            || cached.key_package_id != record.key_package_id
            || (!record.key_package_ref_hex.is_empty()
                && !cached
                    .key_package_ref_hex
                    .eq_ignore_ascii_case(&record.key_package_ref_hex))
            || expected_key_package_ref_hex
                .is_some_and(|expected| !cached.key_package_ref_hex.eq_ignore_ascii_case(expected))
        {
            return (Vec::new(), None);
        }

        let authored_created_at = cached.created_at;
        // Preserve the exact observed endpoint keys, including historical
        // values that today's dial policy rejects. The durable lifecycle must
        // retain possible exposure at those endpoints; the publisher boundary
        // partitions unsafe keys into failed receipts without dialing them.
        let mut endpoints = cached
            .source_relays
            .into_iter()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        endpoints.sort();
        endpoints.dedup();
        (endpoints, Some(authored_created_at))
    }

    /// Upgrade a pre-lifecycle current-profile cache into the durable account
    /// lifecycle. A matching OpenMLS bundle becomes the projected current
    /// package (even when the legacy cache has no event id). Conversely, a
    /// valid event id whose bundle is already gone becomes a retired
    /// liability. Exact cached source relays make that liability actionable;
    /// unknown provenance retains only the event identity, without inventing
    /// an endpoint. Both shapes preserve lifetime and stable-slot high-water.
    fn import_cached_current_key_package_lifecycle(&self, label: &str) -> Result<bool, AppError> {
        let storage = self.account_storage(label)?;
        let Some(mut lifecycle) = storage.key_package_lifecycle()? else {
            return Ok(false);
        };
        if lifecycle.stable_slot_id.is_empty()
            || lifecycle.current_key_package.is_some()
            || lifecycle.pending_replacement.is_some()
        {
            return Ok(false);
        }
        let record = match read_json::<KeyPackageRecord>(self.key_package_record_path(label)) {
            Ok(record) => record,
            Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(_) => return Ok(false),
        };
        let account = self.account_home().account(label)?;
        if record.account_id_hex != account.account_id_hex
            || record.key_package_id != lifecycle.stable_slot_id
        {
            return Ok(false);
        }
        let event_id = if record.key_package_event_id.is_empty() {
            None
        } else {
            let event_id_hex = match parse_key_package_event_id_hex(&record.key_package_event_id) {
                Ok(event_id_hex) => event_id_hex,
                Err(_) => return Ok(false),
            };
            Some(MessageId::new(hex::decode(event_id_hex)?))
        };
        let key_package = match self.validated_current_local_key_package(label) {
            Some(key_package) => key_package,
            None => return Ok(false),
        };
        let metadata = key_package_metadata(&key_package)
            .map_err(|error| AppError::InvalidKeyPackageEvent(error.to_string()))?;
        if !record.key_package_ref_hex.is_empty()
            && !record
                .key_package_ref_hex
                .eq_ignore_ascii_case(&metadata.key_package_ref_hex)
        {
            return Ok(false);
        }
        let key_package_ref = hex::decode(&metadata.key_package_ref_hex)?;
        let owns_private_bundle = cgka_engine::key_package::durably_owned_key_packages(
            &storage,
            cgka_traits::group::ProtocolProfile::Current,
        )
        .map_err(cgka_session::SessionError::from)?
        .iter()
        .any(|owned| {
            key_package_metadata(owned).is_ok_and(|owned_metadata| {
                owned_metadata
                    .key_package_ref_hex
                    .eq_ignore_ascii_case(&metadata.key_package_ref_hex)
            })
        });
        let (endpoints, cached_authored_created_at) = event_id
            .as_ref()
            .map(|_| {
                self.cached_key_package_provenance(
                    &account,
                    &record,
                    Some(&metadata.key_package_ref_hex),
                )
            })
            .unwrap_or_default();

        let authored_created_at = Timestamp(
            cached_authored_created_at
                .map(|cached| cached.max(record.published_at))
                .unwrap_or(record.published_at),
        );
        lifecycle.authored_event_created_at = Some(
            lifecycle
                .authored_event_created_at
                .map(|current| current.max(authored_created_at))
                .unwrap_or(authored_created_at),
        );
        if owns_private_bundle {
            lifecycle.current_key_package = Some(key_package);
            lifecycle.current_key_package_ref = Some(key_package_ref.clone());
            lifecycle.current_not_before = Some(Timestamp(metadata.not_before));
            lifecycle.current_not_after = Some(Timestamp(metadata.not_after));
            lifecycle.authored_event_id = event_id;
            lifecycle.authored_signed_event = None;
            lifecycle.publication_targets = if lifecycle.authored_event_id.is_some() {
                endpoints
                    .into_iter()
                    .map(|endpoint| cgka_traits::TransportFanoutTarget {
                        endpoint,
                        state: cgka_traits::TransportFanoutAttemptState::AttemptedFailed,
                        attempt_count: 1,
                        last_attempt_at: Some(authored_created_at),
                        failure_code: Some("possible_exposure".into()),
                    })
                    .collect()
            } else {
                Vec::new()
            };
            if lifecycle.authored_event_id.is_some() && lifecycle.publication_targets.is_empty() {
                let event_id = lifecycle
                    .authored_event_id
                    .clone()
                    .expect("cached event id remains selected during legacy import");
                retain_imported_legacy_key_package_publication(
                    &mut lifecycle,
                    cgka_traits::RetiredKeyPackagePublication {
                        event_id,
                        authored_created_at,
                        key_package_ref: Some(key_package_ref.clone()),
                        package_not_after: Some(Timestamp(metadata.not_after)),
                        delete_without_successor: false,
                        deletion_targets: Vec::new(),
                    },
                );
            }
        } else if let Some(event_id) = event_id {
            let imported_targets = endpoints
                .into_iter()
                .map(|endpoint| cgka_traits::TransportFanoutTarget {
                    endpoint,
                    state: cgka_traits::TransportFanoutAttemptState::Unattempted,
                    attempt_count: 0,
                    last_attempt_at: None,
                    failure_code: None,
                })
                .collect::<Vec<_>>();
            retain_imported_legacy_key_package_publication(
                &mut lifecycle,
                cgka_traits::RetiredKeyPackagePublication {
                    event_id,
                    authored_created_at,
                    key_package_ref: Some(key_package_ref),
                    package_not_after: Some(Timestamp(metadata.not_after)),
                    delete_without_successor: true,
                    deletion_targets: imported_targets,
                },
            );
        } else {
            return Ok(false);
        }
        lifecycle.refresh_at = Some(Timestamp(0));
        lifecycle.upgrade_rotation_recorded = false;
        lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
        self.canonicalize_quiesced_key_package_lifecycle_targets(&mut lifecycle);
        if key_package_lifecycle_endpoint_liability_count(&lifecycle)
            > cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES
        {
            return Err(AppError::Publish(
                "key package signed-publication endpoint-liability journal is full".into(),
            ));
        }
        storage.put_key_package_lifecycle(&lifecycle)?;
        Ok(true)
    }

    /// Arm the transport-generic publication interlock while account storage
    /// is still quiesced. Managed runtime startup performs fallible sync before
    /// its network-maintenance finish hook; persisting here prevents an
    /// immediate worker tick from publishing through that failure window.
    fn arm_key_package_cutover_publication_gate_before_session_open(
        &self,
        label: &str,
    ) -> Result<(), AppError> {
        if self.key_package_cutover_publication_allowed(label)
            && !self.key_package_cutover_replacement_pending(label)
        {
            return Ok(());
        }
        let storage = self.account_storage(label)?;
        let Some(mut lifecycle) = storage.key_package_lifecycle()? else {
            // An upgraded account whose database predates lifecycle state is
            // already fail-closed: the replacement-intent file keeps ordinary
            // admission blocked, and the final publisher rejects a missing
            // lifecycle row. Preserve that detectable shape so setup can
            // surface the typed consent-gated recovery state instead of
            // turning it into an unrelated publication error.
            return Ok(());
        };
        // A generated identity's first session deliberately staged and signed
        // its exact replacement while the gate was armed. Once that durable
        // replacement exists, its no-predecessor marker is sufficient to open
        // the SQL gate for setup-priority publication. A pending initial
        // NIP-65 intent remains a second, file-backed fence at the final relay
        // boundary; ordinary and legacy intents cannot enter this branch.
        if self.generated_account_fresh_replacement_can_open_cutover_gate(label, &lifecycle)? {
            if lifecycle.cutover_publication_blocked {
                lifecycle.cutover_publication_blocked = false;
                storage.put_key_package_lifecycle(&lifecycle)?;
            }
            return Ok(());
        }
        if lifecycle.stable_slot_id.is_empty() {
            return Err(AppError::Publish(
                "cannot arm key package cutover publication interlock without a stable slot".into(),
            ));
        }
        if !lifecycle.cutover_publication_blocked {
            lifecycle.cutover_publication_blocked = true;
            storage.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok(())
    }

    /// Persist strict-cutover replacement intent before the session layer can
    /// delete unpublished non-current private bundles during open.
    fn ensure_strict_cutover_replacement_intent_before_session_open(
        &self,
        label: &str,
    ) -> Result<(), AppError> {
        let account_storage_preexisted = self.account_storage_path(label).exists();
        let setup_state = self.account_home().account_setup_state(label)?;
        let setup_in_progress = setup_state.is_some();
        let storage = self.account_storage(label)?;
        let existing_lifecycle = storage.key_package_lifecycle()?;
        if let Some(lifecycle) = existing_lifecycle
            .as_ref()
            .filter(|lifecycle| !lifecycle.stable_slot_id.is_empty())
        {
            // Older builds wrote this load-bearing marker without syncing its
            // directory entry. An interrupted generated setup may therefore
            // retain the exact lifecycle but lose only the marker. Rebuild it
            // from the durable generated-setup provenance unless a current
            // acknowledged cutover revision proves the marker was cleared on
            // purpose after successful publication.
            if setup_state.as_ref().is_some_and(|state| {
                state.kind == AccountSetupKind::GeneratedIdentity
                    && state.phase != AccountSetupPhase::KeyPackagePublicationConfirmed
            }) && !self.key_package_cutover_replacement_pending(label)
                && !self.key_package_lifecycle_has_current_cutover_revision(label, lifecycle)
                && !self.mark_key_package_cutover_replacement_pending(label)
            {
                return Err(AppError::Io(std::io::Error::other(
                    "could not restore generated setup cutover replacement intent",
                )));
            }
            self.import_cached_current_key_package_lifecycle(label)?;
            if self.key_package_record_path(label).exists()
                && self.validated_current_local_key_package(label).is_none()
                && !self.mark_key_package_cutover_replacement_pending(label)
            {
                return Err(AppError::Io(std::io::Error::other(
                    "could not persist strict cutover replacement intent before session open",
                )));
            }
            return self.arm_key_package_cutover_publication_gate_before_session_open(label);
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
                self.import_cached_current_key_package_lifecycle(label)?;
                if current_cache || self.mark_key_package_cutover_replacement_pending(label) {
                    return self
                        .arm_key_package_cutover_publication_gate_before_session_open(label);
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
                    return self
                        .arm_key_package_cutover_publication_gate_before_session_open(label);
                }
            }
            Ok(None) | Err(_) if account_storage_preexisted && !setup_in_progress => {
                // A database created before the durable setup journal is
                // ambiguous: it may be an interrupted fresh setup, or an
                // upgraded device whose published stable slot was lost. Do not
                // mint a second slot. Keep normal account reads available; the
                // setup publication boundary surfaces the typed recovery state.
                if self.mark_key_package_cutover_replacement_pending(label) {
                    return self
                        .arm_key_package_cutover_publication_gate_before_session_open(label);
                }
            }
            Ok(None) | Err(_) => {
                // Preserve an explicit fail-closed marker. The publisher will
                // refuse to mint a second slot until migration can recover the
                // original `d` value.
                if self.mark_key_package_cutover_replacement_pending(label) {
                    return self
                        .arm_key_package_cutover_publication_gate_before_session_open(label);
                }
            }
        }
        if self.key_package_cutover_replacement_pending(label) {
            return self.arm_key_package_cutover_publication_gate_before_session_open(label);
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

    #[cfg(test)]
    pub(crate) async fn member_key_package(
        &self,
        member_ref: &str,
    ) -> Result<KeyPackage, AppError> {
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
                    self.latest_fresh_non_retired_key_package_from_records(&account_id, records)?,
                    Some(entry.clone()),
                )?;
                fetched.relay_lists = entry.relay_lists;
                if !self.remember_directory_key_package_if_live(&fetched)? {
                    return Err(AppError::MissingKeyPackage(account_id));
                }
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

    pub(crate) fn local_account_labels_by_id(&self) -> Result<HashMap<String, String>, AppError> {
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

    /// Kind-1210 rows are locally synthesized state projections, not authored
    /// Nostr events. Their sender is the authenticated MLS actor when one is
    /// available and is intentionally empty otherwise, so it is not a stable
    /// Nostr identity input. The chat-list preview renders the structured
    /// group-system payload and never consumes a sender display name.
    fn chat_list_sender_for_profile_hydration(message: &ChatListMessagePreview) -> Option<&str> {
        (message.kind != MARMOT_APP_EVENT_KIND_GROUP_SYSTEM).then_some(message.sender.as_str())
    }

    fn hydrate_chat_list_rows(&self, rows: &mut [ChatListRow]) -> Result<(), AppError> {
        let senders = rows
            .iter()
            .filter_map(|row| {
                row.last_message
                    .as_ref()
                    .and_then(Self::chat_list_sender_for_profile_hydration)
                    .map(ToOwned::to_owned)
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
        let Some(sender) = Self::chat_list_sender_for_profile_hydration(message) else {
            return Ok(());
        };
        if let Some(name) = self.display_name_for_account_id(sender)? {
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
    #[cfg(test)]
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

    fn save_state_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
        &self,
        delta: &AccountState,
        frontiers_to_clear: &[(String, u64)],
        application_event_ids_to_ack: &[MessageId],
    ) -> Result<(), AppError> {
        self.save_state_delta_clearing_local_group_deletion_frontiers_and_acking_application_events_and_visibility_batches(
            delta,
            frontiers_to_clear,
            application_event_ids_to_ack,
            &[],
        )
    }

    fn save_state_delta_clearing_local_group_deletion_frontiers_and_acking_application_events_and_visibility_batches(
        &self,
        delta: &AccountState,
        frontiers_to_clear: &[(String, u64)],
        application_event_ids_to_ack: &[MessageId],
        visibility_batch_ids_to_ack: &[Vec<u8>],
    ) -> Result<(), AppError> {
        self.account_storage(&delta.label)?
            .save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events_and_visibility_batches(
                &stored_state_from_account_state(delta),
                MAX_SEEN_EVENT_IDS,
                TRANSPORT_CURSOR_MAX_FUTURE_SKEW.as_secs(),
                frontiers_to_clear,
                application_event_ids_to_ack,
                visibility_batch_ids_to_ack,
            )?;
        self.chat_list_projection_stale
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(delta.label.clone());
        Ok(())
    }

    fn save_state_delta_and_refresh_created_chat_list_row(
        &self,
        delta: &AccountState,
        frontiers_to_clear: &[(String, u64)],
        application_event_ids_to_ack: &[MessageId],
        visibility_batch_ids_to_ack: &[Vec<u8>],
        group_id_hex: &str,
    ) -> Result<ChatListRow, AppError> {
        let account = self.account_home().account(&delta.label)?;
        let classifier = Self::chat_list_mention_classifier(&account.account_id_hex);
        let has_other_dirty_groups = delta
            .groups
            .iter()
            .any(|group| group.group_id_hex != group_id_hex);
        let mut row = self
            .account_storage(&delta.label)?
            .save_account_projection_delta_and_refresh_chat_list_row_acking_application_events_and_visibility_batches(
                &stored_state_from_account_state(delta),
                MAX_SEEN_EVENT_IDS,
                TRANSPORT_CURSOR_MAX_FUTURE_SKEW.as_secs(),
                frontiers_to_clear,
                application_event_ids_to_ack,
                visibility_batch_ids_to_ack,
                &account.account_id_hex,
                group_id_hex,
                &classifier,
            )?
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.to_owned()))?;
        self.hydrate_chat_list_row(Some(&mut row))?;

        // Only the created row belongs on the response tail. Preserve any
        // pre-existing stale marker, and add one if this delta also persisted
        // another dirty group; a later full-list query performs that rebuild.
        // A single-row refresh does not prove the full projection is warmed.
        if has_other_dirty_groups {
            self.chat_list_projection_stale
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(delta.label.clone());
        }
        Ok(row)
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
    /// Direct callers that need graceful completion should quiesce first — this
    /// closes databases out from under any work still running (see
    /// [`SqliteAccountStorage::close`] for what that does to in-flight
    /// transactions). [`MarmotAppRuntime::shutdown_and_close`] is the terminal
    /// entry point host apps should use: it closes runtime admission, gives
    /// admitted account teardown a bounded chance to finish, then prioritizes
    /// closing storage and releasing the root lease before graceful worker
    /// cleanup continues.
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
        // Root mutations are admitted before database opens in the few paths
        // that need both. Taking this writer first preserves that lock order
        // and keeps the lease until every already-admitted bounded file commit
        // has finished.
        let _root_mutation = self
            .root_mutation_lifecycle
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
        let account_session_storages = self
            .account_session_storages
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
        for storage in account_session_storages {
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
        self.storage_close_completed.store(true, Ordering::Release);

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

    /// Whether [`Self::close_storage`] has finished closing every database and
    /// releasing the root lease. Databases are unreachable from this handle
    /// once it returns true.
    #[must_use]
    pub fn storage_is_closed(&self) -> bool {
        self.storage_close_completed.load(Ordering::Acquire)
    }

    /// Fail rather than reopen a database after [`Self::close_storage`].
    fn ensure_storage_open(&self, database: &'static str) -> Result<(), AppError> {
        if self.storage_closed.load(Ordering::Acquire) {
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

    /// Admit one bounded synchronous mutation inside the Marmot root.
    ///
    /// Callers must drop the returned guard before any network or worker await.
    /// Terminal close takes the writer and latches `storage_closed` before it
    /// releases the cross-process root lease.
    pub(crate) fn begin_root_mutation(
        &self,
        operation: &'static str,
    ) -> Result<RwLockReadGuard<'_, ()>, AppError> {
        let guard = self
            .root_mutation_lifecycle
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_storage_open(operation)?;
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

    /// Withdraw every accepted-but-unpublished send in a group whose outbound
    /// queue the engine has permanently discarded.
    ///
    /// A retained send derives as `pending`, which stays truthful for as long as
    /// convergence can still release it — including across an `Unrecoverable`
    /// halt, which a verified repair drains. Only the terminal changes named by
    /// [`terminates_local_outbound_queue`](crate::client) break that promise,
    /// and there the row would otherwise claim `pending` forever.
    ///
    /// The reason is [`LOCAL_PUBLISH_FAILED_REASON`], shared with the send-time
    /// retraction path: both mean "this send will never reach anyone", the
    /// app-facing state is identically `Failed`, and a distinct literal would
    /// have to be added to every derived-state allow-list in SQL to render the
    /// same thing. Splitting the reasons is a diagnostic-granularity follow-up.
    pub(crate) fn invalidate_timeline_pending_sends_for_group(
        &self,
        label: &str,
        group_id_hex: &str,
    ) -> Result<Option<AppProjectionUpdate>, AppError> {
        let update = self
            .account_storage(label)?
            .invalidate_pending_sent_app_events_for_group(
                group_id_hex,
                LOCAL_PUBLISH_FAILED_REASON,
            )?;
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
    ///   pairs this event with the commit-rollback seam (`CommitRolledBack`),
    ///   so that commit-level event intentionally does NOT dispatch here: one
    ///   rollback must tombstone once, with one reason.
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
        let projects_group_system_activity = chat_list_row
            .as_ref()
            .is_some_and(|row| row.conversation_kind == ChatConversationKind::Group);
        let chat_list_trigger = ChatListUpdateTrigger::from_timeline_changes(
            &storage_update.changes,
            projects_group_system_activity,
        );
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

    /// Close and evict every in-memory handle and warm flag bound to `label`.
    ///
    /// Must be called before the account directory is deleted on removal or
    /// setup-failure rollback. Without this, the cached projection connection,
    /// the independently opened account-session connection, or the directory
    /// cache can keep pointing at the now-unlinked inode: after the user
    /// re-imports the same account, the session DB is rebuilt fresh while a
    /// stale handle silently loses writes. Clearing the warm/stale/ready flags
    /// forces the rebuilt account to re-warm its projections from the fresh
    /// database.
    fn drop_account_caches(&self, label: &str) {
        if let Ok(account) = self.account_home().account(label) {
            self.account_publish_clients
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&account.account_id_hex);
            self.member_key_package_prewarm_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&account.account_id_hex);
        }
        // Eviction alone is not enough: an unabortable `spawn_blocking`
        // account open can still own clones after its async worker was reaped.
        // Closing the shared handles makes every such clone inert before the
        // cache entry becomes unreachable to terminal `close_storage`. Each
        // close stays under its registry mutex so terminal draining cannot
        // miss a removed handle whose close is still in progress.
        {
            let mut storages = self
                .account_storages
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(storage) = storages.remove(label)
                && let Err(error) = storage.close()
            {
                tracing::warn!(
                    target: "marmot_app::storage",
                    method = "drop_account_caches",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "failed to close evicted account storage",
                );
            }
        }
        {
            let mut storages = self
                .account_session_storages
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(storage) = storages.remove(label)
                && let Err(error) = storage.close()
            {
                tracing::warn!(
                    target: "marmot_app::storage",
                    method = "drop_account_caches",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "failed to close evicted account session storage",
                );
            }
        }
        {
            let mut caches = self
                .directory_caches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cache) = caches.remove(label)
                && let Err(error) = cache.close()
            {
                tracing::warn!(
                    target: "marmot_app::storage",
                    method = "drop_account_caches",
                    error_kind = error.privacy_safe_kind(),
                    "failed to close evicted directory cache",
                );
            }
        }
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

    fn relay_client_for_account_id(
        &self,
        account_id_hex: &str,
        signer: Arc<dyn nostr::NostrSigner>,
    ) -> Arc<dyn NostrRelayClient> {
        #[cfg(test)]
        if let Some(client) = &self.test_relay_client {
            return client.clone();
        }
        let mut clients = self
            .account_publish_clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The signer is intentionally ignored on a cache hit. Callers that
        // replace an account signer must evict this entry first, as
        // register_external_signer and drop_account_caches do today.
        clients
            .entry(account_id_hex.to_owned())
            .or_insert_with(|| {
                let client = NostrSdkClient::builder().signer(signer).build();
                Arc::new(NostrSdkRelayClient::new(client))
            })
            .clone()
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
                account.account_id_hex.clone(),
                RegisteredExternalSigner::new(public_key, signer),
            );
        self.account_publish_clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&account.account_id_hex);
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

    /// Drop an account's registered external signer.
    ///
    /// Only account *removal* may call this. The registration is what makes an
    /// external-signer account reconcilable (see `has_external_signer`), so a
    /// reversible sign-out has to keep it or the account could never be signed
    /// back in without the host re-attaching its signer.
    pub(crate) fn forget_external_signer(&self, account_id_hex: &str) {
        self.external_signers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(account_id_hex);
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
    session_admission: AccountSessionAdmission,
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

    fn signed_artifact_reauthor_at_age_secs(&self) -> Option<u64> {
        // Buzz rejects timestamps differing from relay time by more than 900
        // seconds. Reauthor at signed-revision age >= 600 seconds, reserving
        // 300 seconds for combined clock skew, scheduling/signing delay, and
        // delivery across the relay set.
        Some(KEY_PACKAGE_REAUTHOR_AT_AGE_SECS)
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
        self.publish_prepared_key_package_detailed(publication, artifact)
            .await
            .map(Into::into)
    }

    async fn publish_prepared_key_package_detailed(
        &self,
        publication: &KeyPackagePublication,
        artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<DetailedKeyPackagePublishReceipt, KeyPackagePublishError> {
        let mut nostr_publication = self.nostr_publication(publication)?;
        let event: NostrTransportEvent = serde_json::from_slice(&artifact.bytes)
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?;
        if event.id != hex::encode(artifact.id.as_slice())
            || event.created_at != artifact.created_at.0
        {
            return Err(KeyPackagePublishError::unexposed(
                "persisted KeyPackage event identity does not match lifecycle record",
            ));
        }
        let mut canonical_publish_endpoints = Vec::new();
        let mut endpoint_aliases = Vec::new();
        let mut failed = Vec::new();
        for requested_endpoint in &publication.endpoints {
            match self
                .app
                .canonicalize_key_package_endpoint(requested_endpoint, "key package publish")
            {
                Ok(canonical_endpoint) => {
                    canonical_publish_endpoints.push(canonical_endpoint.clone());
                    endpoint_aliases.push((requested_endpoint.clone(), canonical_endpoint));
                }
                Err(_) => failed.push(requested_endpoint.clone()),
            }
        }
        canonical_publish_endpoints.sort();
        canonical_publish_endpoints.dedup();
        if canonical_publish_endpoints.is_empty() {
            return Err(KeyPackagePublishError::unexposed(
                "no safe KeyPackage publication endpoint remains after validation",
            ));
        }
        let key_package_route_lock = self.app.key_package_route_lock(&self.account_label);
        let _key_package_route_guard = key_package_route_lock.lock().await;
        let publication_account_id_hex = hex::encode(publication.account_id.as_slice());
        let live_account_matches = self
            .app
            .account_home()
            .account(&self.account_label)
            .is_ok_and(|account| {
                account.is_active_signing() && account.account_id_hex == publication_account_id_hex
            });
        let active_admission_is_current = match &self.session_admission {
            AccountSessionAdmission::Active(token) => self
                .app
                .account_session_admission_is_current(&self.account_label, token),
            // Teardown cleanup may delete or retire KeyPackages, but can never
            // author a replacement. This is a categorical mode check in
            // addition to the teardown runtime's durable publication block.
            AccountSessionAdmission::Teardown(_) => false,
        };
        if !live_account_matches || !active_admission_is_current {
            return Err(KeyPackagePublishError::unexposed(
                "key package publisher account is signed out, removed, or no longer matches the live account record",
            ));
        }
        if self
            .app
            .removed_local_key_package_slot_is_retired(
                &publication_account_id_hex,
                &publication.slot_id,
            )
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?
        {
            return Err(KeyPackagePublishError::unexposed(
                "prepared KeyPackage uses a stable slot retired by local account removal",
            ));
        }
        let key_package_history_lock = self.app.key_package_history_lock(&self.account_label);
        let _key_package_history_guard = key_package_history_lock.lock().await;
        let incomplete_generated_setup_has_valid_context = self
            .app
            .account_home()
            .account_setup_state(&self.account_label)
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?
            .filter(|state| state.kind == AccountSetupKind::GeneratedIdentity)
            .map(|_| {
                self.app
                    .account_home()
                    .account_setup_context(&self.account_label)
                    .ok()
                    .flatten()
                    .is_some_and(|bytes| {
                        serde_json::from_slice::<runtime::GeneratedAccountSetupContext>(&bytes)
                            .is_ok()
                    })
            })
            .unwrap_or(true);
        if !incomplete_generated_setup_has_valid_context
            || !self
                .app
                .generated_initial_key_package_publication_held(&self.account_label)
                .is_ok_and(|held| !held)
        {
            return Err(KeyPackagePublishError::unexposed(
                "generated initial KeyPackage publication remains durably held",
            ));
        }
        let lifecycle = self
            .app
            .account_storage(&self.account_label)
            .and_then(|storage| storage.key_package_lifecycle().map_err(AppError::from))
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?
            .ok_or_else(|| {
                KeyPackagePublishError::unexposed(
                    "key package lifecycle is unavailable at the final publication boundary",
                )
            })?;
        if lifecycle.cutover_publication_blocked
            || !self
                .app
                .key_package_cutover_publication_allowed(&self.account_label)
        {
            return Err(KeyPackagePublishError::unexposed(
                "key package publication is blocked until strict relay cutover completes",
            ));
        }
        let key_package_ref = hex::decode(&nostr_publication.key_package_ref)
            .map_err(|error| KeyPackagePublishError::unexposed(error.to_string()))?;
        if lifecycle.stable_slot_id != publication.slot_id
            || lifecycle.key_package_ref_is_consumed(&key_package_ref)
            || lifecycle
                .deleted_live_revision_event_ids
                .contains(&artifact.id)
        {
            return Err(KeyPackagePublishError::unexposed(
                "prepared KeyPackage revision is no longer live in the durable lifecycle",
            ));
        }
        let target_was_durably_admitted =
            |targets: &[cgka_traits::TransportFanoutTarget], endpoint: &TransportEndpoint| {
                targets.iter().any(|target| {
                    target.endpoint == *endpoint
                        && target.state
                            != cgka_traits::TransportFanoutAttemptState::PolicyProhibited
                        && (target.state == cgka_traits::TransportFanoutAttemptState::Accepted
                            || (target.attempt_count > 0 && target.last_attempt_at.is_some()))
                })
            };
        let matches_current = lifecycle.current_key_package.as_ref()
            == Some(&publication.key_package)
            && lifecycle.current_key_package_ref.as_ref() == Some(&key_package_ref)
            && lifecycle.authored_signed_event.as_ref() == Some(artifact)
            && lifecycle.authored_event_id.as_ref() == Some(&artifact.id)
            && canonical_publish_endpoints.iter().all(|endpoint| {
                target_was_durably_admitted(&lifecycle.publication_targets, endpoint)
            });
        let matches_pending = lifecycle
            .pending_replacement
            .as_ref()
            .is_some_and(|pending| {
                pending.key_package == publication.key_package
                    && pending.key_package_ref == key_package_ref
                    && pending.signed_event.as_ref() == Some(artifact)
                    && pending.authored_created_at == artifact.created_at
                    && canonical_publish_endpoints
                        .iter()
                        .all(|endpoint| target_was_durably_admitted(&pending.targets, endpoint))
            });
        if !matches_current && !matches_pending {
            return Err(KeyPackagePublishError::unexposed(
                "prepared KeyPackage artifact or endpoint attempt is not the durable live revision",
            ));
        }
        let authoritative_endpoints = self
            .app
            .authoritative_key_package_relays(&self.account_label)
            .map_err(|_| {
                KeyPackagePublishError::unexposed(
                    "could not validate authoritative KeyPackage publication endpoints",
                )
            })?;
        if authoritative_endpoints.is_empty()
            || canonical_publish_endpoints
                .iter()
                .any(|endpoint| !authoritative_endpoints.contains(endpoint))
        {
            return Err(KeyPackagePublishError::unexposed(
                "prepared KeyPackage publication targets are outside the authoritative relay set",
            ));
        }
        nostr_publication.publish_endpoints = canonical_publish_endpoints;
        let relay_client = self.app.relay_client_for_account_id(
            &hex::encode(publication.account_id.as_slice()),
            self.signer.as_nostr_signer(),
        );
        let outcome = NostrKeyPackagePublisher::new(relay_client)
            .publish_prepared_key_package(&nostr_publication, &event)
            .await
            .map_err(|e| KeyPackagePublishError::exposed(e.to_string()))?;
        let canonical_accepted = outcome
            .accepted
            .into_iter()
            .map(|receipt| receipt.endpoint)
            .collect::<Vec<_>>();
        let mut canonical_rejected = Vec::new();
        for failure in outcome.failed {
            if failure.rejection_category.is_some() {
                canonical_rejected.push(failure.endpoint);
            }
        }

        // SQLCipher lifecycle state remains authoritative. This directory row
        // is only a best-effort projection for local invite lookups, which
        // otherwise could reuse a consumed package until the next relay fetch.
        if !canonical_accepted.is_empty() {
            let account_id_hex = publication_account_id_hex;
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
                source_relays: canonical_accepted
                    .iter()
                    .map(|endpoint| endpoint.0.clone())
                    .collect(),
                relay_lists,
            };
            if self
                .app
                .begin_root_mutation("project acknowledged local KeyPackage")
                .and_then(|_root_mutation| self.app.remember_directory_key_package(&fetched))
                .is_err()
            {
                tracing::warn!(
                    target: "marmot_app::key_packages",
                    method = "publish_prepared_key_package",
                    "acknowledged key package directory projection remains stale"
                );
            }
        }

        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for (requested, canonical) in endpoint_aliases {
            if canonical_accepted.contains(&canonical) {
                accepted.push(requested);
            } else if canonical_rejected.contains(&canonical) {
                rejected.push(requested);
            } else {
                // Includes explicit transport failures and a malformed/missing
                // per-endpoint receipt. Neither may erase the durable exact
                // requested key's possible-exposure evidence.
                failed.push(requested);
            }
        }
        accepted.sort();
        accepted.dedup();
        rejected.sort();
        rejected.dedup();
        rejected.retain(|endpoint| !accepted.contains(endpoint));
        failed.sort();
        failed.dedup();
        failed.retain(|endpoint| !accepted.contains(endpoint) && !rejected.contains(endpoint));

        Ok(DetailedKeyPackagePublishReceipt {
            accepted,
            rejected,
            confirmed_absent: Vec::new(),
            failed,
        })
    }

    async fn delete_key_package_revision(
        &self,
        event_id: &cgka_traits::MessageId,
        endpoints: &[TransportEndpoint],
    ) -> Result<DetailedKeyPackagePublishReceipt, KeyPackagePublishError> {
        // Legacy lifecycle rows can contain both noncanonical valid aliases
        // and unsafe keys from before relay validation happened at durable
        // admission. Partition them per target: unsafe exact keys remain
        // retryable without reaching I/O, while safe siblings share one
        // canonical deletion whose receipt expands back to every requested
        // durable alias.
        if endpoints.is_empty() {
            return Err(KeyPackagePublishError::unexposed(
                "key package deletion requires at least one relay endpoint",
            ));
        }
        let mut canonical_endpoints = Vec::new();
        let mut endpoint_aliases = Vec::new();
        let mut failed = Vec::new();
        for requested_endpoint in endpoints {
            match self.app.canonicalize_key_package_endpoint(
                requested_endpoint,
                "key package deletion publish",
            ) {
                Ok(canonical_endpoint) => {
                    canonical_endpoints.push(canonical_endpoint.clone());
                    endpoint_aliases.push((requested_endpoint.clone(), canonical_endpoint));
                }
                Err(_) => failed.push(requested_endpoint.clone()),
            }
        }
        canonical_endpoints.sort();
        canonical_endpoints.dedup();
        if canonical_endpoints.is_empty() {
            failed.sort();
            failed.dedup();
            return Ok(DetailedKeyPackagePublishReceipt {
                accepted: Vec::new(),
                rejected: Vec::new(),
                confirmed_absent: Vec::new(),
                failed,
            });
        }
        let mut results = self
            .app
            .delete_key_package_events(
                &self.account_label,
                vec![KeyPackageDeletionTarget {
                    event_id_hex: hex::encode(event_id.as_slice()),
                    source_relays: canonical_endpoints,
                }],
                self.session_admission.clone(),
            )
            .await
            .map_err(|error| KeyPackagePublishError::exposed(error.to_string()))?;
        let result = results
            .pop()
            .expect("single retired-revision deletion returns one outcome");
        let expand_receipts = |canonical_receipts: &[TransportEndpoint]| {
            let mut requested = endpoint_aliases
                .iter()
                .filter(|(_requested, canonical)| canonical_receipts.contains(canonical))
                .map(|(requested, _canonical)| requested.clone())
                .collect::<Vec<_>>();
            requested.sort();
            requested.dedup();
            requested
        };
        let accepted = expand_receipts(&result.accepted_endpoints);
        let confirmed_absent = expand_receipts(&result.confirmed_absent_endpoints);
        for (requested, canonical) in endpoint_aliases {
            if !result.accepted_endpoints.contains(&canonical)
                && !result.confirmed_absent_endpoints.contains(&canonical)
            {
                // Includes explicit failure, a malformed/missing endpoint
                // receipt, and an aggregate deletion error. None proves the
                // exact durable alias absent.
                failed.push(requested);
            }
        }
        failed.sort();
        failed.dedup();
        failed.retain(|endpoint| {
            !accepted.contains(endpoint) && !confirmed_absent.contains(endpoint)
        });
        Ok(DetailedKeyPackagePublishReceipt {
            accepted,
            rejected: Vec::new(),
            confirmed_absent,
            failed,
        })
    }
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
        Self::from_unix_time(unix_now_seconds(), max_future_skew)
    }

    fn from_unix_time(now: u64, max_future_skew: Duration) -> Self {
        Self {
            max_created_at: now.saturating_add(max_future_skew.as_secs()),
        }
    }

    fn accepts_created_at(self, created_at: u64) -> bool {
        created_at <= self.max_created_at
    }

    pub(crate) fn accepts(self, record: &RelayEventRecord) -> bool {
        self.accepts_created_at(record.event.created_at)
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
            // Callers fold in order and retain the last replaceable event.
            // NIP-01 selects the lowest id when timestamps tie, so sort equal
            // timestamps in descending id order.
            .then_with(|| b.event.id.cmp(&a.event.id))
    });
}

/// NIP-01 replaceable-event ordering: greater `created_at` wins; at equal
/// timestamps the lexicographically lowest event id wins.
fn nostr_replaceable_coordinate_is_newer(
    candidate_created_at: u64,
    candidate_event_id: &str,
    current_created_at: u64,
    current_event_id: &str,
) -> bool {
    candidate_created_at > current_created_at
        || (candidate_created_at == current_created_at && candidate_event_id < current_event_id)
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

fn remove_file_if_present(path: impl AsRef<Path>) -> Result<(), AppError> {
    let path = path.as_ref();
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    };
    // Persist both a new unlink and a previously unsynced absence before a
    // caller reports the transition complete. This is load-bearing when an
    // atomically written successor record must survive without its
    // predecessor.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        // A missing parent already proves the child absent. This keeps
        // idempotent rollback valid when no compatibility namespace was ever
        // created, while still persisting an unlink (or an earlier unsynced
        // absence) whenever the parent directory exists.
        match std::fs::File::open(parent) {
            Ok(directory) => directory.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
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
