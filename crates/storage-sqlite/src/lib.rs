//! # storage-sqlite
//!
//! SQLCipher-backed SQLite implementation of the Marmot storage aggregate.
//! The backend stores Marmot metadata and custom OpenMLS storage rows in the
//! same database so group snapshot and rollback can be atomic across both
//! layers.

mod group_system;
pub use group_system::{
    GroupSystemEventProjection, GroupSystemEventProvenance, group_system_event_from_message,
};

mod account_projection;
mod account_recovery;
pub use account_recovery::{
    QualifiedRecoveryStallSample, RecoveryCause, RecoveryComparison, RecoveryComparisonOutcome,
    RecoveryComparisonPlan, RecoveryDemand, RecoveryDemandTicket, RecoveryEligibility,
    RecoveryEndpointCheckpoint, RecoveryLossCause, RecoveryLossSnapshot, RecoveryLossWatermark,
    RecoveryPredicate, RecoveryRequest, RecoveryRetryState, RecoveryRevisionFence,
    RecoveryScopeCheckpoint, RecoveryScopeOutcome, RecoveryScopePlan, RecoveryScopeToken,
    StoredRecoveryScope,
};
mod agent_stream_sequences;
mod attachment_acquisition;
mod attachment_history;
mod avatar_cache;
mod chat_list;
mod chat_presentation;
mod codec;
mod connection;
mod encrypted_media_secrets;
mod local_submissions;
mod message_drafts;
pub use local_submissions::LocalSubmission;
mod migrations;
mod openmls_storage;
mod pending_welcome_delivery;
mod prepared_group_image_upload;
#[cfg(test)]
mod query_work_test_support;
mod recovery_health;
mod shared;
mod storage;
mod timeline;
mod user_blocks;
pub use user_blocks::{BlockListSnapshot, BlockedUser, PendingBlockPublication, StoredBlockList};
mod transport_reconciliation;

pub use account_projection::{
    AccountChatNotificationSettings, AccountDeliveryRecovery, AccountGroupPushToken,
    AccountNotificationSettings, AccountPendingPushRegistrationRemoval, AccountPushRegistration,
    AccountStoredPushRegistration, AppEventReplayCursor, DeleteLocalGroupDataResult,
    SelfMembership, StoredAccountGroup, StoredAccountGroupComponent, StoredAccountState,
    StoredAppMessageQuery, StoredAppMessageRecord, StoredEpochBackfillIntent,
    StoredEpochStallEvidence, StoredNostrRoute, clamp_to_max_future_skew,
};
pub use attachment_acquisition::{
    ATTACHMENT_ACQUISITION_BATCH_LIMIT, ATTACHMENT_CHECKPOINT_BYTES, AttachmentAcquisition,
    AttachmentAcquisitionSource, AttachmentAcquisitionState, AttachmentAcquisitionStatus,
    AttachmentAssetRef, AttachmentDemand, AttachmentPartial, AttachmentPartialIdentity,
    AttachmentPermissionCategory, AttachmentPublishResult, AttachmentWorkerDemand,
    MAX_ATTACHMENT_LOCAL_READ_BYTES, MAX_RETAINED_ATTACHMENT_BYTES, RetainedAttachmentAsset,
};
pub use attachment_history::{
    AttachmentHistoryCursor, AttachmentHistoryEntry, AttachmentHistoryError, AttachmentHistoryPage,
    AttachmentHistoryVersion, MAX_ATTACHMENT_HISTORY_PAGE,
};
pub use avatar_cache::{
    AVATAR_IDENTITY_BATCH_LIMIT, AvatarAcquisition, AvatarAcquisitionState,
    AvatarAssetPresentation, AvatarAssetRead, AvatarAssetRef, AvatarAssetStatus, AvatarAssetTarget,
    AvatarAvailability, AvatarCacheUsage, AvatarIdentityDemand, AvatarImage, AvatarImageFormat,
    AvatarPublishResult, MAX_AVATAR_BYTES, MAX_AVATAR_CACHE_BYTES, MAX_AVATAR_CACHE_ENTRIES,
    MAX_AVATAR_DIMENSION,
};
pub use chat_list::{
    AccountAttentionTotal, AccountUnreadTotal, ChatConversationKind, ChatListAttachmentKind,
    ChatListAvatar, ChatListCursor, ChatListMessageDeliveryState, ChatListMessagePreview,
    ChatListPage, ChatListPageDirection, ChatListPageError, ChatListPageQuery, ChatListQuery,
    ChatListRow, ChatListView, ChatListWindowQuery, ChatListWindowRead, ChatPinError, ChatPinState,
    ExistingDirectConversation, conversation_kind, select_reusable_direct_conversation,
};
pub use chat_presentation::{
    CHAT_LIST_DRAFT_PREVIEW_CHARS, CHAT_PRESENTATION_BATCH_LIMIT, ChatListDraftPreview,
    ChatListRowActions, ChatPresentationActivePeer, ChatPresentationCatchUp,
    ChatPresentationCheckpoint, ChatPresentationInput, ChatPresentationRead,
    ChatPresentationVersion, ChatPresentationWrite, ConversationPresentation,
    PresentationResolution, PresentationSource, PresentationText, PresentedChatListSnapshot,
    PresentedChatRow, SelectedAvatar, SelectedChatPreview, StoredChatPresentation,
};
#[allow(deprecated)]
pub use connection::SqliteStorage;
pub use connection::{
    CloseableConnection, ConnectionGuard, SqlCipherHardening, SqlCipherKey, SqliteAccountStorage,
    SqliteJournalMode, SqliteStorageOptions, SqliteSynchronous, SqliteTimingObserver,
    SqliteTimingOperation, open_hardened_sqlcipher,
};
pub use message_drafts::{
    MessageDraftCommitObserver, MessageDraftRevision, MessageDraftRevisionError,
    SelectedMessageDraft, SelectedMessageDraftAttachment, SelectedMessageDraftContent,
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
    DirectoryPresentation, DirectoryPresentationChanges, PublicDirectoryProfileRecord,
    PublicDirectoryUserRecord, SqliteSharedStorage, StoredAuditLogSettings,
    StoredRelayTelemetrySettings, StoredUsageDiagnosticsSettings,
};
pub use storage::messages::MessageFormatPromotionProgress;
#[cfg(feature = "storage-format-benchmarks")]
pub use storage::messages::StorageFormatBenchSizes;
pub use timeline::{
    BRANCH_SELECTION_WITHDRAWAL_REASON, BranchSelectionWithdrawalDivergence,
    ConversationAccountSnapshot, ConversationAnchor, ConversationOpenAnchorOutcome,
    ConversationOpenError, ConversationOpenQuery, ConversationOpenReadState,
    ConversationOpenSnapshot, ConversationOpenTarget, ConversationPresentationPage,
    ConversationWindowQuery, DeletionSource, LOCAL_PUBLISH_FAILED_REASON, MAX_TIMELINE_LIMIT,
    SecurePruneAppEventsResult, StoredAppEvent, TimelineEditHistoryPage, TimelineEditSummary,
    TimelineEditVersion, TimelineMessageChange, TimelineMessageQuery, TimelineMessageRecord,
    TimelineMessageTarget, TimelinePage, TimelinePagination, TimelineProjectionUpdate,
    TimelineReactionSummary, TimelineRemoveReason, TimelineReplyPreview, TimelineUpdateTrigger,
    TimelineUserReaction,
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

pub use timeline::reports::{
    ContentReport, ContentReportPage, ReportDismissal, ReportDismissalPage,
};

pub use attachment_acquisition::{
    AttachmentDownloadPolicy, AttachmentTransferFrame, AttachmentTransferState,
    AttachmentTransferStatus,
};
