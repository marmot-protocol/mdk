//! # storage-sqlite
//!
//! SQLCipher-backed SQLite implementation of the Marmot storage aggregate.
//! The backend stores Marmot metadata and custom OpenMLS storage rows in the
//! same database so group snapshot and rollback can be atomic across both
//! layers.

mod app;
mod base;
mod cross;
mod protocol;
#[cfg(feature = "media-store-benchmarks")]
pub use app::media_store_bench;

pub use app::group_system::{
    GroupSystemEventProjection, GroupSystemEventProvenance, group_system_event_from_message,
};

pub use app::account_recovery::{
    ParkedRecoveryObligation, QualifiedRecoveryStallSample, RECOVERY_PARK_AFTER_QUIET_PASSES,
    RecoveryCause, RecoveryComparison, RecoveryComparisonOutcome, RecoveryComparisonPlan,
    RecoveryDemand, RecoveryDemandTicket, RecoveryDemandTransition, RecoveryEligibility,
    RecoveryEndpointCheckpoint, RecoveryLossCause, RecoveryLossImport, RecoveryLossSnapshot,
    RecoveryLossWatermark, RecoveryObligationState, RecoveryObligationStatus, RecoveryPassProgress,
    RecoveryPredicate, RecoveryRequest, RecoveryRetryState, RecoveryRevisionFence,
    RecoveryScopeCheckpoint, RecoveryScopeOutcome, RecoveryScopePlan, RecoveryScopeToken,
    StoredRecoveryScope,
};
pub use app::local_submissions::LocalSubmission;
pub use app::media_catalog::{SlotPublication, SqliteMediaCatalog, media_storage_error};
pub use app::transport::delivery_spill::{
    DeliverySpillDisposition, DeliverySpillLimits, SpilledDelivery, SpilledDeliveryBatch,
    SpilledDeliveryDeferral,
};
pub use app::transport::moderation_reports::{
    ModerationReportOutboxEntry, ModerationReportOutboxOutcome,
};
mod shared;
pub use app::transport::user_blocks::{
    BlockListSnapshot, BlockedUser, PendingBlockPublication, StoredBlockList,
};

pub use app::account_projection::{
    AccountChatNotificationSettings, AccountDeliveryRecovery, AccountGroupPushToken,
    AccountNotificationSettings, AccountPendingPushRegistrationRemoval, AccountPushRegistration,
    AccountStoredPushRegistration, AppEventReplayCursor, DeleteLocalGroupDataResult,
    SelfMembership, StoredAccountGroup, StoredAccountGroupComponent, StoredAccountState,
    StoredAppMessageQuery, StoredAppMessageRecord, StoredEpochBackfillIntent,
    StoredEpochStallEvidence, StoredNostrRoute, clamp_to_max_future_skew,
};
pub use app::attachment_acquisition::{
    ATTACHMENT_ACQUISITION_BATCH_LIMIT, ATTACHMENT_CHECKPOINT_BYTES,
    ATTACHMENT_STAGING_CHUNK_BYTES, AttachmentAcquisition, AttachmentAcquisitionSource,
    AttachmentAcquisitionState, AttachmentAcquisitionStatus, AttachmentAssetRef,
    AttachmentCheckpoint, AttachmentDemand, AttachmentPartial, AttachmentPartialIdentity,
    AttachmentPermissionCategory, AttachmentPublication, AttachmentPublishResult,
    AttachmentUploadOwner, AttachmentUploadPromotion, AttachmentUploadSource,
    AttachmentUploadStage, AttachmentWorkerDemand, MAX_ATTACHMENT_LOCAL_READ_BYTES,
    MAX_RETAINED_ATTACHMENT_BYTES, MAX_RETAINED_FILE_ATTACHMENT_BYTES, RetainedAttachmentAsset,
    RetainedAttachmentRead,
};
pub use app::attachment_history::{
    AccountAttachmentCursor, AccountAttachmentEntry, AccountAttachmentHistoryError,
    AccountAttachmentPage, AccountAttachmentQuery, AccountAttachmentVersion,
    AttachmentHistoryCursor, AttachmentHistoryEntry, AttachmentHistoryError, AttachmentHistoryPage,
    AttachmentHistoryVersion, MAX_ATTACHMENT_HISTORY_PAGE,
};
pub use app::avatar_cache::{
    AVATAR_IDENTITY_BATCH_LIMIT, AvatarAcquisition, AvatarAcquisitionState,
    AvatarAssetPresentation, AvatarAssetRead, AvatarAssetRef, AvatarAssetStatus, AvatarAssetTarget,
    AvatarAvailability, AvatarCacheUsage, AvatarIdentityDemand, AvatarImage, AvatarImageFormat,
    AvatarPublishResult, MAX_AVATAR_BYTES, MAX_AVATAR_CACHE_BYTES, MAX_AVATAR_CACHE_ENTRIES,
    MAX_AVATAR_DIMENSION,
};
pub use app::chat_list::{
    AccountAttentionTotal, AccountUnreadTotal, ChatConversationKind, ChatListAttachmentKind,
    ChatListAvatar, ChatListCursor, ChatListMessageDeliveryState, ChatListMessagePreview,
    ChatListPage, ChatListPageDirection, ChatListPageError, ChatListPageQuery, ChatListQuery,
    ChatListRow, ChatListSelectionError, ChatListSelectionSnapshot, ChatListView,
    ChatListWindowQuery, ChatListWindowRead, ChatPinError, ChatPinState,
    ExistingDirectConversation, conversation_kind, select_reusable_direct_conversation,
};
pub use app::chat_presentation::{
    CHAT_LIST_DRAFT_PREVIEW_CHARS, CHAT_PRESENTATION_BATCH_LIMIT, ChatListDraftPreview,
    ChatListRowActions, ChatPresentationActivePeer, ChatPresentationCatchUp,
    ChatPresentationCheckpoint, ChatPresentationInput, ChatPresentationRead,
    ChatPresentationVersion, ChatPresentationWrite, ConversationPresentation,
    PresentationResolution, PresentationSource, PresentationText, PresentedChatListSnapshot,
    PresentedChatRow, SelectedAvatar, SelectedChatPreview, StoredChatPresentation,
};
pub use app::message_drafts::{
    ChatListDraftVersion, MessageDraftCommitObserver, MessageDraftRevision,
    MessageDraftRevisionError, SelectedMessageDraft, SelectedMessageDraftAttachment,
    SelectedMessageDraftContent, StoredMessageDraft, StoredMessageDraftAttachment,
    StoredMessageDraftAttachmentSummary, StoredMessageDraftSummary,
};
pub use app::pending_welcome_delivery::PendingWelcomeDeliveryRecord;
pub use app::timeline::{
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
pub use app::transport::prepared_group_image_upload::{
    ACTIVE_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS,
    CONSUMED_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS, MAX_ACTIVE_PREPARED_GROUP_IMAGE_UPLOADS,
    MAX_CONSUMED_PREPARED_GROUP_IMAGE_UPLOADS, PreparedGroupImageUploadRecord,
    PreparedGroupImageUploadState,
};
pub use app::transport::transport_reconciliation::{
    TRANSPORT_RECONCILIATION_MAX_ITEMS_PER_ROUTE, TRANSPORT_RECONCILIATION_RETENTION_SECS,
    TransportReconciliationInventory, TransportReconciliationItem, TransportReconciliationRoute,
};
#[allow(deprecated)]
pub use base::connection::SqliteStorage;
pub use base::connection::{
    CloseableConnection, ConnectionGuard, DatabaseCloser, SqlCipherHardening, SqlCipherKey,
    SqliteAccountStorage, SqliteJournalMode, SqliteStorageOptions, SqliteSynchronous,
    SqliteTimingObserver, SqliteTimingOperation, open_hardened_sqlcipher,
};
pub use protocol::openmls_storage::SqliteOpenMlsStorageError;
pub use protocol::storage::messages::MessageFormatPromotionProgress;
#[cfg(feature = "storage-format-benchmarks")]
pub use protocol::storage::messages::StorageFormatBenchSizes;
pub use shared::{
    DirectoryPresentation, DirectoryPresentationChanges, PublicDirectoryProfileRecord,
    PublicDirectoryUserRecord, SqliteSharedStorage, StoredAuditLogSettings,
    StoredRelayTelemetrySettings, StoredUsageDiagnosticsSettings,
};

pub use app::transport::agent_stream_sequences::{
    AgentStreamPublisherReservation, AgentStreamPublisherReservationRequest,
    AgentStreamPublisherState, MAX_AGENT_STREAM_PUBLISHER_CONTEXTS,
};
pub(crate) use base::codec::{
    SQLITE_BIND_PARAMETER_CHUNK, SqliteResultExt, bool_i64, created_at_to_i64, deserialize,
    epoch_to_i64, i64_to_u64, i64_to_usize, message_state_from_i64, message_state_to_i64,
    optional_u64_to_i64, serialize, tags_from_json, u64_to_i64, unix_now_ms, unix_now_seconds,
    unix_now_seconds_i64, usize_to_i64,
};

pub use app::timeline::reports::{
    ContentReport, ContentReportPage, ReportDismissal, ReportDismissalPage,
};

pub use app::attachment_acquisition::{
    AttachmentDownloadPolicy, AttachmentTransferFrame, AttachmentTransferState,
    AttachmentTransferStatus, ReadmitAdmission, STORAGE_PARKED_PREFIX_MAX_AGE_SECONDS,
    STORAGE_READMIT_MARGIN_BYTES,
};

pub use base::open_progress::{StorageOpenPhase, StorageOpenProgress};
