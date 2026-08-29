//! # storage-sqlite
//!
//! SQLCipher-backed SQLite implementation of the Marmot storage aggregate.
//! The backend stores Marmot metadata and custom OpenMLS storage rows in the
//! same database so group snapshot and rollback can be atomic across both
//! layers.

mod account_projection;
mod account_visibility_journal;
mod agent_stream_sequences;
mod chat_list;
mod codec;
mod connection;
mod encrypted_media_secrets;
mod epoch_backfill_intent_journal;
mod message_drafts;
mod migrations;
mod openmls_storage;
mod pending_welcome_delivery;
mod prepared_group_image_upload;
mod shared;
mod storage;
mod timeline;
mod transport_reconciliation;

pub use account_projection::{
    AccountChatNotificationSettings, AccountDeliveryRecovery, AccountGroupPushToken,
    AccountNotificationSettings, AccountPendingPushRegistrationRemoval, AccountPushRegistration,
    AccountStoredPushRegistration, AppEventReplayCursor, DeleteLocalGroupDataResult,
    SelfMembership, StoredAccountGroup, StoredAccountGroupComponent, StoredAccountState,
    StoredAppMessageQuery, StoredAppMessageRecord, StoredEpochBackfillIntent,
    StoredEpochStallEvidence, StoredNostrRoute, clamp_to_max_future_skew,
};
pub use account_visibility_journal::{AccountVisibilityJournalRow, AccountVisibilityJournalUpsert};
pub use chat_list::{
    AccountUnreadTotal, ChatConversationKind, ChatListAttachmentKind, ChatListAvatar,
    ChatListMessageDeliveryState, ChatListMessagePreview, ChatListQuery, ChatListRow, ChatPinError,
    ChatPinState, ExistingDirectConversation, select_reusable_direct_conversation,
};
#[allow(deprecated)]
pub use connection::SqliteStorage;
pub use connection::{
    CloseableConnection, ConnectionGuard, SqlCipherHardening, SqlCipherKey, SqliteAccountStorage,
    SqliteJournalMode, SqliteStorageOptions, SqliteSynchronous, open_hardened_sqlcipher,
};
pub use message_drafts::{
    StoredMessageDraft, StoredMessageDraftAttachment, StoredMessageDraftAttachmentSummary,
    StoredMessageDraftSummary,
};
pub use openmls_storage::SqliteOpenMlsStorageError;
pub use pending_welcome_delivery::PendingWelcomeDeliveryRecord;
pub use prepared_group_image_upload::{
    ACTIVE_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS,
    CONSUMED_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS, MAX_ACTIVE_PREPARED_GROUP_IMAGE_UPLOADS,
    MAX_CONSUMED_PREPARED_GROUP_IMAGE_UPLOADS, PreparedGroupImageUploadRecord,
    PreparedGroupImageUploadState,
};
pub use shared::{
    PublicDirectoryUserRecord, SqliteSharedStorage, StoredAuditLogSettings,
    StoredRelayTelemetrySettings,
};
pub use storage::messages::MessageFormatPromotionProgress;
#[cfg(feature = "storage-format-benchmarks")]
pub use storage::messages::StorageFormatBenchSizes;
pub use timeline::{
    BRANCH_SELECTION_WITHDRAWAL_REASON, BranchSelectionWithdrawalDivergence,
    LOCAL_PUBLISH_FAILED_REASON, MAX_TIMELINE_LIMIT, SecurePruneAppEventsResult, StoredAppEvent,
    TimelineMessageChange, TimelineMessageQuery, TimelineMessageRecord, TimelineMessageTarget,
    TimelinePage, TimelinePagination, TimelineProjectionUpdate, TimelineReactionSummary,
    TimelineRemoveReason, TimelineReplyPreview, TimelineUpdateTrigger, TimelineUserReaction,
};
pub use transport_reconciliation::{
    TRANSPORT_RECONCILIATION_MAX_ITEMS_PER_ROUTE, TRANSPORT_RECONCILIATION_RETENTION_SECS,
    TransportReconciliationInventory, TransportReconciliationItem, TransportReconciliationRoute,
};

pub use agent_stream_sequences::{
    AgentStreamPublisherReservation, AgentStreamPublisherReservationRequest,
    AgentStreamPublisherState, MAX_AGENT_STREAM_PUBLISHER_CONTEXTS,
};
pub(crate) use codec::{
    SQLITE_BIND_PARAMETER_CHUNK, SqliteResultExt, bool_i64, created_at_to_i64, deserialize,
    epoch_to_i64, i64_to_u64, i64_to_usize, message_state_from_i64, message_state_to_i64,
    optional_u64_to_i64, serialize, tags_from_json, u64_to_i64, unix_now_ms, unix_now_seconds,
    unix_now_seconds_i64, usize_to_i64,
};
