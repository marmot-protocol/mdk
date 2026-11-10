//! # storage-sqlite
//!
//! SQLCipher-backed SQLite implementation of the Marmot storage aggregate.
//! The backend stores Marmot metadata and custom OpenMLS storage rows in the
//! same database so group snapshot and rollback can be atomic across both
//! layers.

mod app;
mod base;
mod cross;
#[cfg(feature = "media-store-benchmarks")]
pub mod media_store_bench;
mod protocol;

pub use app::compromise_warning::{
    COMPROMISE_WARNING_ITEM_CAP, COMPROMISE_WARNING_KEY_PACKAGE_RETENTION_SECS,
    CompromiseWarningGather, CompromiseWarningReason, CompromiseWarningRecord, FirstTrustedRoster,
    ObservedWarningItem,
};
pub use app::device_activity::{DeviceActivityRecord, DeviceHeartbeatSent, DeviceInactivityClock};
pub use app::device_renames::DeviceRenameRecord;
pub use app::group_system::{
    GroupSystemEventProjection, GroupSystemEventProvenance, group_system_event_from_message,
};
pub use app::handle::SqliteAppStorage;

pub use app::account_recovery::{
    MAX_LOSS_ROUTES, ParkedRecoveryObligation, RecoveryCause, RecoveryConversionInput,
    RecoveryConversionReport, RecoveryConversionRoute, RecoveryConvertedLoss,
    RecoveryConvertedObligations, RecoveryDemand, RecoveryDemandTicket, RecoveryEligibility,
    RecoveryLossCause, RecoveryLossReach, RecoveryLossSnapshot, RecoveryLossWatermark,
    RecoveryPredicate,
};
pub use app::local_submissions::LocalSubmission;
pub use app::media_catalog::{SlotPublication, SqliteMediaCatalog, media_storage_error};
pub use app::storage_compaction::{DatabaseSpace, PageReclaim};
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
    AccountChatNotificationSettings, AccountGroupPushGossipState, AccountGroupPushToken,
    AccountGroupPushTokenTombstone, AccountNotificationSettings,
    AccountPendingPushRegistrationRemoval, AccountPushRegistration, AccountPushTokenRemovalProof,
    AccountStoredPushRegistration, AppEventReplayCursor, DeleteLocalGroupDataResult,
    SelfMembership, StoredAccountGroup, StoredAccountGroupComponent, StoredAccountState,
    StoredAppMessageQuery, StoredAppMessageRecord, StoredEpochBackfillIntent,
    StoredEpochStallEvidence, StoredNostrRoute, clamp_to_max_future_skew,
};
pub use app::attachment_acquisition::{
    ATTACHMENT_ACQUISITION_BATCH_LIMIT, ATTACHMENT_CHECKPOINT_BYTES, ATTACHMENT_REMOVAL_BATCH,
    ATTACHMENT_STAGING_CHUNK_BYTES, AttachmentAcquisition, AttachmentAcquisitionSource,
    AttachmentAcquisitionState, AttachmentAcquisitionStatus, AttachmentAssetRef,
    AttachmentCheckpoint, AttachmentDemand, AttachmentKeepMedia, AttachmentMigrationState,
    AttachmentPartial, AttachmentPartialIdentity, AttachmentPermissionCategory,
    AttachmentPublication, AttachmentPublishResult, AttachmentRemoval, AttachmentStorageUsage,
    AttachmentUploadOwner, AttachmentUploadPromotion, AttachmentUploadSource,
    AttachmentUploadStage, AttachmentWorkerDemand, ChatAttachmentUsage, ChatUsageCursor,
    LegacyAttachmentBody, LegacyBodyPublication, LegacyBodyReader, MAX_ATTACHMENT_LOCAL_READ_BYTES,
    MAX_RETAINED_ATTACHMENT_BYTES, MAX_RETAINED_FILE_ATTACHMENT_BYTES, RetainedAttachmentAsset,
    RetainedAttachmentEntry, RetainedAttachmentRead, RetainedSizeCursor,
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
    AvatarAvailability, AvatarCacheUsage, AvatarFileImage, AvatarIdentityDemand, AvatarImage,
    AvatarImageFormat, AvatarPublication, AvatarPublishResult, AvatarStoredFile, DatabaseAvatar,
    DatabaseAvatarBody, MAX_AVATAR_BYTES, MAX_AVATAR_CACHE_BYTES, MAX_AVATAR_CACHE_ENTRIES,
    MAX_AVATAR_DIMENSION,
};
pub use app::backup_ledger::{BackupRun, BackupRunHead, BackupSchedule, CondemnedBackupBlob};
pub use app::backup_restore::BackupRestoreArchive;
pub use app::chat_list::{
    AccountAttentionTotal, AccountUnreadTotal, ChatConversationKind, ChatListAttachmentKind,
    ChatListAvatar, ChatListCondition, ChatListFilter, ChatListFilterNode,
    ChatListMessageDeliveryState, ChatListMessagePreview, ChatListPage, ChatListPageDirection,
    ChatListPageError, ChatListQuery, ChatListQueryError, ChatListRow, ChatListSelectionError,
    ChatListView, ChatListViewQuery, ChatListWindowQuery, ChatListWindowRead, ChatPinError,
    ChatPinState, ExistingDirectConversation, MAX_CHAT_LIST_FILTER_DEPTH,
    MAX_CHAT_LIST_FILTER_GROUP_IDS, MAX_CHAT_LIST_FILTER_NODES, MAX_CHAT_LIST_FILTER_TEXT_BYTES,
    MAX_SMALL_STATE_NUMBER, MuteSetting, ReadPosition, RetentionExpiryScan, SmallStateBroadcast,
    SmallStateItem, SmallStateItemName, SmallStateRule, SmallStateSchedule, SmallStateSync,
    SmallStateValue, SmallStateVersion, conversation_kind, normalize_search_text,
    select_reusable_direct_conversation,
};
pub use app::chat_presentation::{
    CHAT_LIST_DRAFT_PREVIEW_CHARS, CHAT_PRESENTATION_BATCH_LIMIT, ChatListDraftPreview,
    ChatListRowActions, ChatPresentationActivePeer, ChatPresentationCatchUp,
    ChatPresentationCheckpoint, ChatPresentationInput, ChatPresentationRead,
    ChatPresentationVersion, ChatPresentationWrite, ConversationPresentation,
    PresentationResolution, PresentationSource, PresentationText, PresentedChatListSnapshot,
    PresentedChatRow, SelectedAvatar, SelectedChatPreview, StoredChatPresentation,
};
pub use app::device_group_moves::{
    DeviceGroupMovePhase, DeviceGroupMoveRecord, MoveCarryOutcome, MoveRejectedSlot, MoveSibling,
};
pub use app::device_groups::{DeviceGroupRecord, DeviceGroupTrust};
pub use app::device_links::{DeviceLinkOutcome, DeviceLinkRecord};
pub use app::device_removals::DeviceRemovalRecord;
pub use app::emoji_sets::{
    EmojiSetInstallLimits, EmojiSetInstallOutcome, StoredEmojiSet, StoredEmojiSetEntry,
    StoredEmojiSetVersion, StoredEmojiSkip, StoredInstalledEmoji, StoredInstalledEmojiRow,
    StoredInstalledEmojiSet,
};
pub use app::history_deliveries::{
    HISTORY_DELIVERY_RETENTION_SECS, OwedHistoryDelivery, ParkedBundle, ParkedHistoryChat,
    ParkedHistoryDelivery,
};
pub use app::message_drafts::{
    ChatListDraftVersion, MessageDraftRevision, MessageDraftRevisionError, SelectedMessageDraft,
    SelectedMessageDraftAttachment, SelectedMessageDraftContent, StoredMessageDraft,
    StoredMessageDraftAttachment, StoredMessageDraftAttachmentSummary, StoredMessageDraftSummary,
};
pub use app::pending_welcome_delivery::PendingWelcomeDeliveryRecord;
pub use app::private_key_packages::{PrivateKeyPackageNeed, ReceivedPrivateKeyPackage};
pub use app::recovery_copies::{
    CopyFloorReason, RecoveryCopy, RecoveryRejoin, RecoveryRejoinNotice,
};
pub use app::recovery_coverage::{
    RecoveryCoverageMark, RecoveryCoverageProof, RecoveryCoverageProved, RecoveryCoverageRange,
    RecoveryCoverageSlice,
};
pub use app::recovery_epoch_gap::RecoveryEpochGapRetry;
pub use app::recovery_staging::{
    RecoveryStaged, RecoveryStagedSlice, RecoveryStagedUsage, StagedRecoveryEvent,
    StagedRecoveryEvents,
};
pub use app::recovery_units::{
    RecoveryAccountUsage, RecoveryParkedRoute, RecoveryRecheckPass, RecoveryRelayCaps,
    RecoveryRelayHealth, RecoveryRouteRemainder, RecoverySpanRetirement, RecoveryUnit,
    RecoveryUnitBreak, RecoveryUnitFence, RecoveryUnitOutcome, RecoveryUnitPark,
    RecoveryUnitPolicy, RecoveryUnitSpan, RecoveryUnitState,
};
pub use app::sibling_welcomes::{MAX_STASHED_SIBLING_WELCOMES, StashedSiblingWelcome};
pub use app::sign_ins::{ObservedSignIn, SignInAnswer, SignInCheck, SignInRecord};
pub use app::stickers::{
    StoredInstalledStickerState, StoredSticker, StoredStickerInstallOperation,
    StoredStickerOutboxEvent, StoredStickerPack, StoredStickerPackVersion,
};
pub use app::timeline::{
    AppEventImport, BRANCH_SELECTION_WITHDRAWAL_REASON, BackupHistorySource,
    BranchSelectionWithdrawalDivergence, ConversationAccountSnapshot, ConversationAnchor,
    ConversationOpenAnchorOutcome, ConversationOpenError, ConversationOpenQuery,
    ConversationOpenReadState, ConversationOpenSnapshot, ConversationOpenTarget,
    ConversationPresentationPage, ConversationWindowQuery, DeletionSource, HistoryExportEvent,
    HistoryExportRow, HistoryImportProvenance, HistoryImportSource, ImportedAppEvent,
    ImportedFileKey, LOCAL_PUBLISH_FAILED_REASON, LatestHistoryImport, MAX_TIMELINE_LIMIT,
    SecurePruneAppEventsResult, StoredAppEvent, TimelineAttachmentType, TimelineEditHistoryPage,
    TimelineEditSummary, TimelineEditVersion, TimelineMessageChange, TimelineMessageQuery,
    TimelineMessageRecord, TimelineMessageTarget, TimelinePage, TimelinePagination,
    TimelineProjectionUpdate, TimelineReactionSummary, TimelineRemoveReason, TimelineReplyPreview,
    TimelineUpdateTrigger, TimelineUserReaction,
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
pub use base::connection::{
    CloseableConnection, ConnectionGuard, DatabaseCloser, SqlCipherHardening, SqlCipherKey,
    SqliteJournalMode, SqliteStorageOptions, SqliteSynchronous, SqliteTimingObserver,
    SqliteTimingOperation, open_hardened_sqlcipher,
};
#[cfg(any(test, feature = "test-support"))]
pub use base::connection::{SnapshotFault, relax_storage_for_test_process};
pub use cross::outbound::MessageDraftCommitObserver;
pub use protocol::handle::SqliteAccountStorage;
#[allow(deprecated)]
pub use protocol::handle::SqliteStorage;
pub use protocol::openmls_storage::SqliteOpenMlsStorageError;
pub use protocol::storage::group_recovery::{
    GroupRecoveryPhase, GroupRecoveryRecord, GroupRecoveryRole,
    MAX_GROUP_RECOVERY_COORDINATOR_JOBS, MAX_GROUP_RECOVERY_COORDINATOR_JOBS_PER_GROUP,
};
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

pub use app::invitation_decisions::{InvitationDecision, InvitationDecisionWork};
