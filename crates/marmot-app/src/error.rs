use cgka_traits::{TransportAdapterError, storage::StorageError};
use marmot_account::AccountHomeError;
use marmot_session::AccountError;

use crate::MissingRelayListKind;
use marmot_observability::app_telemetry::{SyncErrorClass, SyncFailureClassification};
use marmot_observability::audit_upload::AuditUploadError;
pub use nostr_directory::error::MissingKeyPackageReason;
use nostr_directory::error::{
    DirectoryError, ResourceError, sqlite_error_kind, storage_error_kind,
};

/// Worker-safe account catch-up failure. The human-facing message remains for
/// compatibility, while telemetry propagation uses only the closed
/// classification value.
#[derive(Clone, Debug)]
pub struct AccountCatchUpFailure {
    message: String,
    classification: SyncFailureClassification,
    repair_incomplete: Option<(FullHistoryRepairIncompleteReason, bool)>,
}

impl AccountCatchUpFailure {
    pub fn new(message: String, classification: SyncFailureClassification) -> Self {
        Self {
            message,
            classification,
            repair_incomplete: None,
        }
    }

    pub(crate) fn from_sync_failure(
        message: String,
        failure: &crate::ClassifiedSyncFailure,
    ) -> Self {
        Self {
            message,
            classification: failure.classification(),
            repair_incomplete: failure.source.full_history_repair_incomplete(),
        }
    }

    pub(crate) const fn classification(&self) -> SyncFailureClassification {
        self.classification
    }
}

impl std::fmt::Display for AccountCatchUpFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(formatter)
    }
}

/// Why an explicit repair stopped without qualified history completion.
/// These bounded codes contain no relay, account or event identities. The
/// comparison job reports `CoverageUnproven`, `BelowRetentionWindow`,
/// `Cancelled` and `Deadline`; the drain-era codes remain so existing matches
/// keep compiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FullHistoryRepairIncompleteReason {
    #[error("full_history_coverage_unproven")]
    CoverageUnproven,
    /// Every route's retained-inventory window certified, but the repair's
    /// goal reaches below that window, which no comparison searched.
    #[error("full_history_below_retention_window")]
    BelowRetentionWindow,
    #[error("full_history_repair_cancelled")]
    Cancelled,
    #[error("full_history_repair_deadline")]
    Deadline,
    #[error("account_delivery_queue_overflow")]
    DeliveryLoss,
    #[error("backfill_drain_eose_timeout")]
    EoseTimeout,
    #[error("backfill_drain_no_relay_eose")]
    NoRelayEose,
    #[error("backfill_drain_novel_progress_quantum_yield")]
    NovelProgressYield,
    #[error("backfill_drain_no_progress_quantum_yield")]
    NoProgressYield,
    #[error("full_history_repair_unconfirmed")]
    Unconfirmed,
}

impl FullHistoryRepairIncompleteReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CoverageUnproven => "full_history_coverage_unproven",
            Self::BelowRetentionWindow => "full_history_below_retention_window",
            Self::Cancelled => "full_history_repair_cancelled",
            Self::Deadline => "full_history_repair_deadline",
            Self::DeliveryLoss => "account_delivery_queue_overflow",
            Self::EoseTimeout => "backfill_drain_eose_timeout",
            Self::NoRelayEose => "backfill_drain_no_relay_eose",
            Self::NovelProgressYield => "backfill_drain_novel_progress_quantum_yield",
            Self::NoProgressYield => "backfill_drain_no_progress_quantum_yield",
            Self::Unconfirmed => "full_history_repair_unconfirmed",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    ProductAnalytics(#[from] crate::ProductAnalyticsError),
    #[error(transparent)]
    Account(marmot_session::AccountError),
    #[error(transparent)]
    AccountHome(#[from] AccountHomeError),
    #[error(transparent)]
    Session(marmot_session::SessionError),
    #[error(transparent)]
    Storage(#[from] cgka_traits::storage::StorageError),
    #[error(transparent)]
    Transport(TransportAdapterError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error("{reason}")]
    MissingKeyPackage {
        account: String,
        reason: MissingKeyPackageReason,
    },
    /// The canonical invite target has no Marmot inbox endpoint that survives
    /// this device's relay-safety policy. Kept per-recipient for typed host
    /// presentation, while Display remains identity-free for safe diagnostics.
    #[error("member has no valid Marmot inbox relay")]
    MissingMemberInboxRoute(String),
    /// Relay-list or KeyPackage lookup for this account ran out of time or
    /// relay coverage, so neither absence nor a verdict was established.
    /// Retryable; Display remains identity-free.
    #[error("account directory lookup did not complete")]
    DirectoryLookupIncomplete(String),
    /// The creator is already an MLS member and cannot be added again.
    #[error("group members must not include the creator")]
    GroupCreateIncludesCreator,
    /// An invite named the inviter's own account. A device never adds its own
    /// account's other devices from published KeyPackages (mdk#2628 D14).
    #[error("invited members must not include the inviter")]
    GroupInviteIncludesInviter,
    /// A device-group action was refused (mdk#2628 item 3.1): this device
    /// does not advertise the roster, the confirmed KeyPackage is not this
    /// account's published one, the account already has a device group, or
    /// the trusted device group's roster cannot be read
    /// (`roster_unavailable`). The reason is a fixed, identity-free code.
    #[error("device group refused: {0}")]
    DeviceGroupRefused(&'static str),
    #[error("unknown local group")]
    UnknownGroup(String),
    /// Invite acceptance requires a current, non-terminal membership projection
    /// that is still waiting for host confirmation. This stable variant lets
    /// bindings reject stale invite actions without string parsing.
    #[error("group invite is not pending")]
    GroupInviteNotPending,
    /// Canonical MLS creation completed, but the host-facing derived row could
    /// not be committed. The group id lets detailed callers refresh instead of
    /// retrying creation and producing a duplicate group.
    #[error("group was created but its local chat projection is unavailable")]
    CreatedGroupProjectionUnavailable(String),
    #[error("invalid group membership page: {0}")]
    InvalidGroupMembershipPage(String),
    /// The once-per-open peer-index backfill has not finished. Retry after
    /// account hydration/reconciliation completes; do not treat this as a miss.
    #[error("direct conversation index is not ready; retry after account hydration")]
    DirectConversationIndexNotReady,
    #[error("chat presentation preparation is incomplete; retry after local maintenance")]
    ChatPresentationNotReady,
    #[error("invalid cached identity page: {0}")]
    InvalidCachedIdentityPage(String),
    #[error("invalid public event reference batch: {0}")]
    InvalidPublicEventReferences(String),
    #[error("invalid chat pin: {0}")]
    InvalidChatPin(String),
    #[error("group is disbanding or disbanded; outbound work is blocked")]
    GroupDisbanding(String),
    /// This device is out of a group that goes on without it: an admin's
    /// removal (or a realized self-eviction) has been adopted locally, so no
    /// further outbound work can ever be published for it.
    ///
    /// Deliberately distinct from [`AppError::GroupDisbanding`]: the group
    /// still exists for its remaining members, and a host that reports
    /// "disbanding" for it tells the user something false.
    #[error("this device was removed from the group; outbound work is blocked")]
    GroupRemoved(String),
    /// The group may have moved past this device's local epoch and recovery has
    /// not caught it up yet. A commit authored now could fork the group
    /// (mdk#2258). Retryable once recovery clears the gap or the local epoch
    /// moves past it. Or, after the user accepts that risk,
    /// `acknowledge_group_catching_up` and retry. Dismissing the group's
    /// history notice does not release it.
    #[error("group is still catching up on missed changes; try again once it has synced")]
    GroupCatchingUp(String),
    /// The group's last change has been owed to a group relay for over two
    /// minutes, so members who read only that relay cannot follow it
    /// (mdk#2255). MDK keeps retrying the owed relays. Retryable once they accept the change.
    /// Or, after the user accepts that some members may miss changes,
    /// `acknowledge_group_commit_undelivered` and retry.
    #[error("the group's last change has not reached every relay yet; try again shortly")]
    GroupCommitUndelivered(String),
    /// Host-supplied draft attachment metadata failed validation before storage.
    #[error("invalid message draft: {0}")]
    InvalidMessageDraft(String),
    /// The composer changed after the caller selected it; reload before retrying.
    #[error("message draft revision no longer matches")]
    MessageDraftRevisionConflict,
    #[error("no agent text stream start found for this group")]
    AgentStreamMissingStart,
    #[error("agent publisher: {0}")]
    AgentStreamPublisher(String),
    /// The finish expectation disagrees with the sealed transcript. Retrying
    /// with the same inputs cannot succeed.
    #[error("stream finalize does not match the sealed transcript")]
    AgentStreamFinishMismatch,
    /// The durable final send failed after sealing. The sealed transcript is
    /// retained, so the same finish request may be retried.
    #[error("agent stream durable send failed: {0}")]
    AgentStreamSendFailed(#[source] Box<AppError>),
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
    MissingRelayLists(Vec<MissingRelayListKind>),
    /// The selected relay set returned no current kind-3 contact-list event.
    ///
    /// Follow updates replace the entire list, so treating an absent event as
    /// an empty list could silently erase follows published elsewhere.
    #[error("current account follow list is unavailable")]
    FollowListUnavailable,
    /// The current kind-3 contact list has at least `MAX_FOLLOW_LIST_ENTRIES`
    /// follows, more than MDK reads from one list. Publishing an edit of the
    /// list it read could drop follows, so nothing was published.
    #[error("current account follow list is too large to update")]
    FollowListTooLarge,
    #[error("user is blocked")]
    UserBlocked,
    #[error("block list synchronization unavailable")]
    BlockListUnavailable,
    #[error("block list publication outcome is uncertain; retry to reconcile")]
    BlockPublicationUncertain,
    /// No valid moderation-report destination is installed; nothing was published.
    #[error("moderation reporting is not configured")]
    ModerationReportingNotConfigured,
    /// The host's moderation-report destination was rejected as a whole.
    #[error("invalid moderation report configuration: {0}")]
    InvalidModerationReportConfig(String),
    #[error("reported user public key is invalid")]
    InvalidReportedPublicKey,
    #[error("an account cannot report itself")]
    CannotReportSelf,
    /// The local per-account cap; it guards against runaway clients only.
    #[error("too many moderation reports; try again later")]
    ModerationReportRateLimited,
    /// An edit must target an available chat message this account sent;
    /// nothing was published.
    #[error("edit target must be an available self-authored chat message")]
    InvalidEditTarget,
    #[error("relay directory fetch failed: {0}")]
    RelayDirectory(String),
    /// An account worker's transport catch-up failed (sync error or timeout).
    /// Deliberately distinct from [`AppError::RelayDirectory`]: catch-up
    /// failures were once wrapped as relay-directory errors, which sent an
    /// earlier investigation chasing the wrong subsystem.
    #[error("account catch-up failed: {0}")]
    AccountCatchUp(AccountCatchUpFailure),
    #[error("invalid Nostr public key")]
    InvalidPublicKey,
    #[error("this operation does not accept a private key")]
    UnexpectedPrivateKey,
    #[error("public identity does not match the imported private key")]
    IdentityKeyMismatch,
    #[error("external signer unavailable for account")]
    ExternalSignerUnavailable(String),
    #[error("external signer public key does not match account")]
    ExternalSignerMismatch,
    #[error("external signer request was rejected or cancelled by the user")]
    ExternalSignerRejected,
    #[error("invalid Marmot KeyPackage event: {0}")]
    InvalidKeyPackageEvent(String),
    #[error("no directory entry for account")]
    MissingDirectoryEntry(String),
    #[error("invalid user directory search: {0}")]
    InvalidDirectorySearch(String),
    #[error("invalid group profile: {0}")]
    InvalidGroupProfile(String),
    #[error("invalid app component: {0}")]
    InvalidAppComponent(String),
    #[error("invalid Nostr routing component: {0}")]
    InvalidNostrRouting(String),
    #[error("invalid group avatar URL: {0}")]
    InvalidGroupAvatarUrl(String),
    #[error("invalid agent text stream policy: {0}")]
    InvalidAgentTextStreamPolicy(String),
    #[error("invalid encrypted media: {0}")]
    InvalidEncryptedMedia(String),
    /// A media reference was encrypted under `source_epoch`, but the message
    /// that would carry it is sent at `current_epoch`. The `imeta` tag has no
    /// epoch field, so recipients would derive the wrong media secret; the
    /// attachment has to be uploaded again.
    #[error(
        "media reference was encrypted at epoch {source_epoch} but the group is at epoch {current_epoch}; upload it again"
    )]
    MediaReferenceStaleEpoch {
        source_epoch: u64,
        current_epoch: u64,
    },
    /// The group's epoch is unsettled — a commit this device staged still
    /// awaits its publish outcome, or retained peer commits are not yet
    /// applied — so a media reference encrypted at `source_epoch` cannot be
    /// sent right now. Ordinary messages are retained and encrypted when the
    /// group settles; a media reference cannot be, because the delivering
    /// message's epoch is the recipient's media key. Nothing was published.
    /// Sync and send again, or upload again if the epoch moved.
    #[error(
        "media reference was encrypted at epoch {source_epoch} but the group epoch is unsettled; sync and retry, or upload it again if the epoch advanced"
    )]
    MediaReferenceEpochUnsettled { source_epoch: u64 },
    /// An inbound or host-supplied encrypted-media `imeta` reference failed the
    /// shared strict parser. Carries the stable rejection category plus
    /// privacy-safe presentation text so bindings can surface a typed reason
    /// instead of a Rust error string (mdk#1787). Attachment-local: the
    /// carrying message and its valid sibling attachments are unaffected.
    #[error("invalid encrypted media reference: {0}")]
    MediaAttachmentRejected(crate::MediaAttachmentRejection),
    /// A structurally valid reference has no locator this client may fetch
    /// under the group's `allowed_locator_kinds` or its own host-safety policy.
    /// Distinct from [`AppError::MediaAttachmentRejected`] (the reference is
    /// fine) and from [`AppError::MediaDownloadFailed`] (nothing was dialed).
    #[error("encrypted media is unfetchable: {0}")]
    MediaUnfetchable(String),
    /// Fetching, verifying, or decrypting an encrypted-media blob failed after
    /// the reference validated and a locator was selected: transport errors,
    /// timeouts, ciphertext/plaintext hash mismatches, and AEAD failures.
    #[error("encrypted media download failed: {0}")]
    MediaDownloadFailed(String),
    #[error("blob store request failed: {0}")]
    BlobStore(String),
    /// A Blossom upload exhausted its bounded transfer/response budget before
    /// the caller had a valid media descriptor. No message publication can
    /// begin until this operation succeeds, so connector callers may retry.
    #[error("media upload timed out")]
    MediaUploadTimedOut,
    /// Pre-dial rejection for untrusted profile/media fetch URLs (SSRF boundary).
    #[error("unsafe media fetch: {0}")]
    UnsafeMediaFetch(String),
    #[error("invalid sticker data: {0}")]
    InvalidSticker(String),
    #[error("sticker pack or asset is unavailable")]
    StickerNotFound,
    #[error("sticker relay operation failed: {0}")]
    StickerRelay(String),
    #[error("sticker import failed: {0}")]
    StickerImport(String),
    #[error("Signal sticker import is unavailable for external-signing accounts")]
    StickerExternalSignerImportUnsupported,
    #[error("invalid app message payload: {0}")]
    InvalidAppMessagePayload(String),
    #[error("invalid push token")]
    InvalidPushToken(String),
    #[error("invalid push notification server")]
    InvalidPushServer(String),
    #[error("invalid push token gossip")]
    InvalidPushGossip(String),
    #[error("invalid relay telemetry settings: {0}")]
    InvalidRelayTelemetrySettings(String),
    #[error("invalid audit log file: {0}")]
    InvalidAuditLogFile(String),
    #[error("audit log upload failed: {0}")]
    AuditLogUpload(String),
    #[error("local notifications are disabled")]
    NotificationsDisabled,
    #[error("SQLCipher key derivation failed: {0}")]
    SqlcipherKeyDerivation(String),
    #[error("blocking app task failed: {0}")]
    BlockingTask(String),
    #[error(
        "full-history repair incomplete: {reason}; pending delivery loss: {delivery_loss_pending}"
    )]
    FullHistoryRepairIncomplete {
        reason: FullHistoryRepairIncompleteReason,
        delivery_loss_pending: bool,
    },
    /// Another process or independently constructed production runtime owns
    /// the same Marmot root. Acquisition is intentionally nonblocking so an
    /// iOS notification extension can take its bounded fallback path.
    #[error("marmot runtime root is already in use")]
    RuntimeBusy,
    /// Another [`crate::AppClient`] from this [`crate::MarmotApp`] currently
    /// owns the account's in-memory engine session.
    #[error("marmot account session is already in use")]
    AccountSessionBusy,
    /// The managed account worker is in an exclusive catch-up phase and did
    /// not start this command. Retrying after the catch-up completes is safe.
    #[error("marmot account worker is busy catching up; operation was not started")]
    AccountWorkerBusy,
    /// The worker accepted the command, but its response did not arrive within
    /// the operation-class deadline. Completion is unknown; callers must
    /// refresh authoritative state before deciding whether to retry.
    #[error("marmot account worker response timed out; operation completion is unknown")]
    AccountWorkerResponseTimedOut,
    /// An account database predates the durable setup journal and has no
    /// recoverable stable KeyPackage slot. Local evidence cannot prove that a
    /// previously signed package was never exposed, so automatic rotation is
    /// forbidden. The host may offer the explicit incomplete-setup reset API.
    #[error(
        "incomplete account setup requires explicit recovery because prior KeyPackage exposure cannot be ruled out"
    )]
    AccountSetupRecoveryRequired,
    #[error("durable account setup can be resumed by retrying the original operation")]
    AccountSetupRetryRequired,
    #[error("onboarding action is unavailable or stale")]
    OnboardingActionUnavailable,
    #[error("account must complete interactive onboarding")]
    OnboardingRequired,
    #[error("account is not in the legacy incomplete-setup reset state")]
    AccountSetupResetNotApplicable,
    #[error("recoverable KeyPackage setup state exists; retry instead of resetting")]
    AccountSetupKeyPackageRecoveryAvailable,
    /// Automatic permission APIs require the opt-in host-managed configuration.
    #[error("host-managed attachment mode required")]
    AttachmentModeRequired,
    /// Signed-out accounts cannot grant automatic network permission.
    #[error("automatic attachment approval requires a signed-in account")]
    AttachmentAccountSignedOut,
    #[error("marmot runtime is shutting down")]
    RuntimeStopping,
    #[error("no matching reaction by this account to retract")]
    ReactionNotFound,
    #[error("transport event stream closed")]
    TransportClosed,
}

/// The directory's errors convert back to the `AppError` they replaced: the
/// same variant, message and `privacy_safe_kind` as before the directory had its
/// own type.
impl From<DirectoryError> for AppError {
    fn from(error: DirectoryError) -> Self {
        match error {
            DirectoryError::InvalidKeyPackageEvent(value) => Self::InvalidKeyPackageEvent(value),
            DirectoryError::RelayDirectory(value) => Self::RelayDirectory(value),
            DirectoryError::InvalidDirectorySearch(value) => Self::InvalidDirectorySearch(value),
            DirectoryError::DirectoryLookupIncomplete(value) => {
                Self::DirectoryLookupIncomplete(value)
            }
            DirectoryError::MissingRelayLists(value) => Self::MissingRelayLists(value),
            DirectoryError::MissingMemberInboxRoute(value) => Self::MissingMemberInboxRoute(value),
            DirectoryError::InvalidPublicEventReferences(value) => {
                Self::InvalidPublicEventReferences(value)
            }
            DirectoryError::MissingDirectoryEntry(value) => Self::MissingDirectoryEntry(value),
            DirectoryError::InvalidNostrRouting(value) => Self::InvalidNostrRouting(value),
            DirectoryError::InvalidCachedIdentityPage(value) => {
                Self::InvalidCachedIdentityPage(value)
            }
            DirectoryError::BlockingTask(value) => Self::BlockingTask(value),
            DirectoryError::Storage(value) => Self::Storage(value),
            DirectoryError::Io(value) => Self::Io(value),
            DirectoryError::Json(value) => Self::Json(value),
            DirectoryError::Sqlite(value) => Self::Sqlite(value),
            DirectoryError::Hex(value) => Self::Hex(value),
            DirectoryError::InvalidPublicKey => Self::InvalidPublicKey,
            DirectoryError::TransportClosed => Self::TransportClosed,
            DirectoryError::MissingKeyPackage { account, reason } => {
                Self::MissingKeyPackage { account, reason }
            }
            DirectoryError::KeyPackageRequirements(error) => {
                Self::from(marmot_session::SessionError::from(error))
            }
            DirectoryError::Resource(error) => *error
                .into_inner()
                .downcast::<AppError>()
                .expect("only marmot-app builds a ResourceError, always from an AppError"),
        }
    }
}

/// An app failure inside directory code travels as
/// [`DirectoryError::Resource`] and converts back unchanged.
impl From<AppError> for DirectoryError {
    fn from(error: AppError) -> Self {
        let kind = error.privacy_safe_kind();
        Self::Resource(ResourceError::from_app(error, kind))
    }
}

/// The audit upload's errors convert back to the `AppError` they replaced: the
/// same variant, message and `privacy_safe_kind` as before the upload had its
/// own type.
impl From<AuditUploadError> for AppError {
    fn from(error: AuditUploadError) -> Self {
        match error {
            AuditUploadError::InvalidAuditLogFile(value) => Self::InvalidAuditLogFile(value),
            AuditUploadError::AuditLogUpload(value) => Self::AuditLogUpload(value),
            AuditUploadError::Io(value) => Self::Io(value),
        }
    }
}

/// An external signer reports a rejection as text, which every layer passes
/// through unchanged. So each lower-stack conversion recognises it by that
/// text, wherever the rejection happened and however it was wrapped.
fn is_external_signer_rejection(error: &impl std::fmt::Display) -> bool {
    error.to_string().contains(crate::EXTERNAL_SIGNER_REJECTED)
}

impl From<TransportAdapterError> for AppError {
    fn from(error: TransportAdapterError) -> Self {
        if is_external_signer_rejection(&error) {
            Self::ExternalSignerRejected
        } else {
            Self::Transport(error)
        }
    }
}

impl From<AccountError> for AppError {
    fn from(error: AccountError) -> Self {
        if is_external_signer_rejection(&error) {
            Self::ExternalSignerRejected
        } else {
            Self::Account(error)
        }
    }
}

impl From<marmot_session::SessionError> for AppError {
    fn from(error: marmot_session::SessionError) -> Self {
        if is_external_signer_rejection(&error) {
            Self::ExternalSignerRejected
        } else {
            Self::Session(error)
        }
    }
}

impl AppError {
    /// Typed incomplete-repair evidence, including across the worker boundary.
    /// The boolean indicates outstanding delivery loss; neither case is success.
    pub fn full_history_repair_incomplete(
        &self,
    ) -> Option<(FullHistoryRepairIncompleteReason, bool)> {
        match self {
            Self::FullHistoryRepairIncomplete {
                reason,
                delivery_loss_pending,
            } => Some((*reason, *delivery_loss_pending)),
            Self::AccountCatchUp(failure) => failure.repair_incomplete,
            _ => None,
        }
    }

    pub(crate) fn is_account_not_active(&self) -> bool {
        matches!(
            self,
            Self::Transport(TransportAdapterError::AccountNotActive(_))
                | Self::Account(AccountError::Transport(
                    TransportAdapterError::AccountNotActive(_)
                ))
        )
    }

    pub(crate) fn privacy_safe_kind(&self) -> &'static str {
        match self {
            Self::ProductAnalytics(_) => "usage_diagnostics",
            Self::Account(error) => account_error_kind(error),
            Self::AccountHome(error) => account_home_error_kind(error),
            Self::Session(error) => engine_error_kind(error.as_engine_error()),
            Self::Storage(error) => storage_error_kind(error),
            Self::Transport(_) => "transport",
            Self::Io(_) => "io",
            Self::Json(_) => "json",
            Self::Sqlite(error) => sqlite_error_kind(error),
            Self::Hex(_) => "hex",
            Self::MissingKeyPackage { .. } => "missing_key_package",
            Self::MissingMemberInboxRoute(_) => "missing_member_inbox_route",
            Self::DirectoryLookupIncomplete(_) => "directory_lookup_incomplete",
            Self::GroupCreateIncludesCreator => "group_create_includes_creator",
            Self::GroupInviteIncludesInviter => "group_invite_includes_inviter",
            Self::DeviceGroupRefused(_) => "device_group_refused",
            Self::UnknownGroup(_) => "unknown_group",
            Self::GroupInviteNotPending => "group_invite_not_pending",
            Self::CreatedGroupProjectionUnavailable(_) => "created_group_projection_unavailable",
            Self::InvalidGroupMembershipPage(_) => "invalid_group_membership_page",
            Self::ChatPresentationNotReady => "chat_presentation_not_ready",
            Self::DirectConversationIndexNotReady => "direct_conversation_index_not_ready",
            Self::InvalidCachedIdentityPage(_) => "invalid_cached_identity_page",
            Self::InvalidPublicEventReferences(_) => "invalid_public_event_references",
            Self::InvalidChatPin(_) => "invalid_chat_pin",
            Self::GroupDisbanding(_) => "group_disbanding",
            Self::GroupRemoved(_) => "group_removed",
            Self::GroupCatchingUp(_) => "group_catching_up",
            Self::GroupCommitUndelivered(_) => "group_commit_undelivered",
            Self::InvalidMessageDraft(_) => "invalid_message_draft",
            Self::MessageDraftRevisionConflict => "message_draft_revision_conflict",
            Self::AgentStreamMissingStart => "agent_stream_missing_start",
            Self::AgentStreamPublisher(_) => "agent_stream_publisher",
            Self::AgentStreamFinishMismatch => "agent_stream_finish_mismatch",
            Self::AgentStreamSendFailed(_) => "agent_stream_send_failed",
            Self::AgentStreamStartNotConfirmed => "agent_stream_start_not_confirmed",
            Self::AgentStreamUnsupportedRoute => "agent_stream_unsupported_route",
            Self::AgentStreamMissingCandidate => "agent_stream_missing_candidate",
            Self::AgentStreamInvalidCandidate(_) => "agent_stream_invalid_candidate",
            Self::Publish(_) => "publish",
            Self::MissingDefaultRelays => "missing_default_relays",
            Self::MissingRelayLists(_) => "missing_relay_lists",
            Self::UserBlocked => "user_blocked",
            Self::BlockListUnavailable => "block_list_unavailable",
            Self::BlockPublicationUncertain => "block_publication_uncertain",
            Self::ModerationReportingNotConfigured => "moderation_reporting_not_configured",
            Self::InvalidModerationReportConfig(_) => "invalid_moderation_report_config",
            Self::InvalidReportedPublicKey => "invalid_reported_public_key",
            Self::CannotReportSelf => "cannot_report_self",
            Self::ModerationReportRateLimited => "moderation_report_rate_limited",
            Self::InvalidEditTarget => "invalid_edit_target",
            Self::FollowListUnavailable => "follow_list_unavailable",
            Self::FollowListTooLarge => "follow_list_too_large",
            Self::RelayDirectory(_) => "relay_directory",
            Self::AccountCatchUp(_) => "account_catch_up",
            Self::InvalidPublicKey => "invalid_public_key",
            Self::UnexpectedPrivateKey => "unexpected_private_key",
            Self::IdentityKeyMismatch => "identity_key_mismatch",
            Self::ExternalSignerUnavailable(_) => "external_signer_unavailable",
            Self::ExternalSignerMismatch => "external_signer_mismatch",
            Self::ExternalSignerRejected => "external_signer_rejected",
            Self::InvalidKeyPackageEvent(_) => "invalid_key_package_event",
            Self::MissingDirectoryEntry(_) => "missing_directory_entry",
            Self::InvalidDirectorySearch(_) => "invalid_directory_search",
            Self::InvalidGroupProfile(_) => "invalid_group_profile",
            Self::InvalidAppComponent(_) => "invalid_app_component",
            Self::InvalidNostrRouting(_) => "invalid_nostr_routing",
            Self::InvalidGroupAvatarUrl(_) => "invalid_group_avatar_url",
            Self::InvalidAgentTextStreamPolicy(_) => "invalid_agent_text_stream_policy",
            Self::InvalidEncryptedMedia(_) => "invalid_encrypted_media",
            Self::MediaReferenceStaleEpoch { .. } => "media_reference_stale_epoch",
            Self::MediaReferenceEpochUnsettled { .. } => "media_reference_epoch_unsettled",
            Self::MediaAttachmentRejected(_) => "media_attachment_rejected",
            Self::MediaUnfetchable(_) => "media_unfetchable",
            Self::MediaDownloadFailed(_) => "media_download_failed",
            Self::BlobStore(_) => "blob_store",
            Self::MediaUploadTimedOut => "media_upload_timed_out",
            Self::UnsafeMediaFetch(_) => "unsafe_media_fetch",
            Self::InvalidSticker(_) => "invalid_sticker",
            Self::StickerNotFound => "sticker_not_found",
            Self::StickerRelay(_) => "sticker_relay",
            Self::StickerImport(_) => "sticker_import",
            Self::StickerExternalSignerImportUnsupported => {
                "sticker_external_signer_import_unsupported"
            }
            Self::InvalidAppMessagePayload(_) => "invalid_app_message_payload",
            Self::InvalidPushToken(_) => "invalid_push_token",
            Self::InvalidPushServer(_) => "invalid_push_server",
            Self::InvalidPushGossip(_) => "invalid_push_gossip",
            Self::InvalidRelayTelemetrySettings(_) => "invalid_relay_telemetry_settings",
            Self::InvalidAuditLogFile(_) => "invalid_audit_log_file",
            Self::AuditLogUpload(_) => "audit_log_upload",
            Self::NotificationsDisabled => "notifications_disabled",
            Self::SqlcipherKeyDerivation(_) => "sqlcipher_key_derivation",
            Self::BlockingTask(_) => "blocking_task",
            Self::FullHistoryRepairIncomplete {
                reason,
                delivery_loss_pending,
            } => {
                if *delivery_loss_pending && *reason != FullHistoryRepairIncompleteReason::Cancelled
                {
                    "account_delivery_queue_overflow"
                } else {
                    reason.as_str()
                }
            }
            Self::RuntimeBusy => "runtime_busy",
            Self::AccountSessionBusy => "account_session_busy",
            Self::AccountWorkerBusy => "account_worker_busy",
            Self::AccountWorkerResponseTimedOut => "account_worker_response_timed_out",
            Self::AccountSetupRecoveryRequired => "account_setup_recovery_required",
            Self::OnboardingActionUnavailable => "onboarding_action_unavailable",
            Self::OnboardingRequired => "onboarding_required",
            Self::AccountSetupRetryRequired => "account_setup_retry_required",
            Self::AccountSetupResetNotApplicable => "account_setup_reset_not_applicable",
            Self::AccountSetupKeyPackageRecoveryAvailable => {
                "account_setup_key_package_recovery_available"
            }
            Self::AttachmentModeRequired => "attachment_mode_required",
            Self::AttachmentAccountSignedOut => "attachment_account_signed_out",
            Self::RuntimeStopping => "runtime_stopping",
            Self::ReactionNotFound => "reaction_not_found",
            Self::TransportClosed => "transport_closed",
        }
    }

    /// Broad, bounded cause derived only from typed variants.
    pub(crate) fn sync_error_class(&self) -> SyncErrorClass {
        match self {
            Self::Storage(error) => storage_error_class(error),
            Self::Sqlite(error) => match error.sqlite_error_code() {
                Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                    SyncErrorClass::StorageBusy
                }
                Some(rusqlite::ErrorCode::DatabaseCorrupt) => SyncErrorClass::StorageCorruption,
                Some(rusqlite::ErrorCode::DiskFull) => SyncErrorClass::StorageCapacity,
                _ => SyncErrorClass::Storage,
            },
            Self::Io(_) => SyncErrorClass::Storage,
            Self::Session(error) => engine_error_class(error.as_engine_error()),
            Self::Account(error) => account_sync_error_class(error),
            Self::Transport(error) => transport_error_class(error),
            Self::RelayDirectory(_) | Self::DirectoryLookupIncomplete(_) => {
                SyncErrorClass::RelayDirectory
            }
            Self::AccountCatchUp(error) => error.classification().error_class,
            Self::FullHistoryRepairIncomplete { reason, .. } => match reason {
                FullHistoryRepairIncompleteReason::Cancelled => SyncErrorClass::Cancelled,
                FullHistoryRepairIncompleteReason::Deadline
                | FullHistoryRepairIncompleteReason::EoseTimeout
                | FullHistoryRepairIncompleteReason::NoRelayEose => SyncErrorClass::Timeout,
                _ => SyncErrorClass::Unknown,
            },
            Self::AccountWorkerResponseTimedOut => SyncErrorClass::Timeout,
            Self::TransportClosed => SyncErrorClass::TransportClosed,
            Self::RuntimeStopping | Self::ExternalSignerRejected => SyncErrorClass::Cancelled,
            Self::Json(_)
            | Self::Hex(_)
            | Self::InvalidAppMessagePayload(_)
            | Self::InvalidAppComponent(_)
            | Self::InvalidNostrRouting(_)
            | Self::InvalidKeyPackageEvent(_) => SyncErrorClass::Protocol,
            _ => SyncErrorClass::Unknown,
        }
    }

    /// The engine error inside a session or account error, however the lower
    /// stack wrapped it. Code above the engine asks this rather than matching
    /// wrapper paths, so moving a call between layers cannot change the answer.
    pub fn as_engine_error(&self) -> Option<&cgka_traits::error::EngineError> {
        match self {
            Self::Account(error) => error.as_engine_error(),
            Self::Session(error) => Some(error.as_engine_error()),
            _ => None,
        }
    }
}

fn transport_error_class(error: &TransportAdapterError) -> SyncErrorClass {
    match error {
        TransportAdapterError::Closed => SyncErrorClass::TransportClosed,
        TransportAdapterError::InvalidInboundEncoding
        | TransportAdapterError::InvalidInboundSignature
        | TransportAdapterError::PublishTargetMismatch { .. } => SyncErrorClass::Protocol,
        _ => SyncErrorClass::Unknown,
    }
}

fn account_sync_error_class(error: &AccountError) -> SyncErrorClass {
    if let Some(error) = error.as_engine_error() {
        return engine_error_class(error);
    }
    match error {
        AccountError::Transport(error) => transport_error_class(error),
        AccountError::TransportRouting(_) | AccountError::WrongAccountDelivery => {
            SyncErrorClass::Protocol
        }
        _ => SyncErrorClass::Unknown,
    }
}

fn engine_error_class(error: &cgka_traits::error::EngineError) -> SyncErrorClass {
    use cgka_traits::error::{EngineError, PeelerError};

    match error {
        EngineError::Storage(error) => storage_error_class(error),
        EngineError::MissingWelcomeKeyPackage
        | EngineError::Peeler(
            PeelerError::DecryptFailed
            | PeelerError::MissingContext { .. }
            | PeelerError::InvalidSignature,
        ) => SyncErrorClass::Crypto,
        EngineError::Peeler(_)
        | EngineError::InvalidCredentialIdentity(_)
        | EngineError::InvalidAppMessagePayload(_)
        | EngineError::InvalidAccountIdentityProof(_)
        | EngineError::InvalidKeyPackageLifetime { .. }
        | EngineError::InvalidKeyPackageCapabilities { .. }
        | EngineError::InvalidWelcome
        | EngineError::Serialize(_)
        | EngineError::ForkedEpoch { .. }
        | EngineError::InvalidTransition(_) => SyncErrorClass::Protocol,
        _ => SyncErrorClass::Unknown,
    }
}

fn account_error_kind(error: &AccountError) -> &'static str {
    // The wrapping depth is not the diagnosis: an engine failure has the
    // engine's kind whichever layer carried it, so an operator greps one name.
    if let Some(error) = error.as_engine_error() {
        return engine_error_kind(error);
    }
    match error {
        AccountError::Transport(_) => "account_transport",
        AccountError::TransportRouting(_) => "account_transport_routing",
        AccountError::KeyPackage(_) => "account_key_package",
        AccountError::ClockSkewBlocked => "account_clock_skew_blocked",
        AccountError::KeyPackageRotationInProgress => "account_key_package_rotation_in_progress",
        AccountError::KeyPackageAnnouncementPending => "account_key_package_announcement_pending",
        AccountError::WrongAccountDelivery => "account_wrong_delivery",
        _ => "account_unknown",
    }
}

fn account_home_error_kind(error: &AccountHomeError) -> &'static str {
    match error {
        AccountHomeError::Io(_) => "account_home_io",
        AccountHomeError::Json(_) => "account_home_json",
        AccountHomeError::Hex(_) => "account_home_hex",
        AccountHomeError::AccountExists(_) => "account_home_account_exists",
        AccountHomeError::AccountIdInUse(_) => "account_home_account_id_in_use",
        AccountHomeError::UnknownAccount(_) => "account_home_unknown_account",
        AccountHomeError::InvalidSecretKey => "account_home_invalid_secret_key",
        AccountHomeError::InvalidPublicKey => "account_home_invalid_public_key",
        AccountHomeError::InvalidAccountLabel(_) => "account_home_invalid_account_label",
        AccountHomeError::AccountIdMismatch => "account_home_account_id_mismatch",
        AccountHomeError::AccountSetupStateMissing => "account_home_setup_state_missing",
        AccountHomeError::UnsupportedSecretBackend(_) => "account_home_unsupported_secret_backend",
        AccountHomeError::SecretStoreNotInitialized(_) => {
            "account_home_secret_store_not_initialized"
        }
        AccountHomeError::SecretStoreUnavailable(_) => "account_home_secret_store_unavailable",
        AccountHomeError::SecretStore(_) => "account_home_secret_store",
        AccountHomeError::SecretNotFound(_) => "account_home_secret_not_found",
        AccountHomeError::EmptyPassphrase => "account_home_empty_passphrase",
        AccountHomeError::EncryptedSecretExport(_) => "account_home_encrypted_secret_export",
        AccountHomeError::EmptySecretStoreService => "account_home_empty_secret_store_service",
    }
}

/// Privacy-safe kind for an engine failure, however the session and account
/// layers wrapped it.
///
/// Collapsing session failures to a single `"session"` kind is what made the
/// D5 field investigations blind, so the name always comes from the engine.
fn engine_error_kind(error: &cgka_traits::error::EngineError) -> &'static str {
    match error {
        // Reuse the nine storage kinds. That keeps the one transient kind
        // (`storage_busy`, the sole case `SessionError::is_transient` reports)
        // distinguishable from the eight durable ones without a second
        // transient/permanent axis to keep in sync.
        cgka_traits::error::EngineError::Storage(error) => storage_error_kind(error),
        // Engine names come from the engine so an app tracing field and an
        // engine forensic audit row say the same word for the same failure.
        error => error.privacy_safe_kind(),
    }
}

fn storage_error_class(error: &StorageError) -> SyncErrorClass {
    match error {
        StorageError::Busy(_) => SyncErrorClass::StorageBusy,
        StorageError::Corruption(_) => SyncErrorClass::StorageCorruption,
        StorageError::Capacity(_) => SyncErrorClass::StorageCapacity,
        _ => SyncErrorClass::Storage,
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountCatchUpFailure, AccountError, AppError, StorageError};
    use crate::SyncFailureClassification;
    use cgka_traits::error::EngineError;
    use cgka_traits::types::{EpochId, GroupId};

    #[test]
    fn missing_welcome_key_package() {
        let error = AppError::Account(AccountError::Engine(EngineError::MissingWelcomeKeyPackage));
        assert_eq!(error.privacy_safe_kind(), "missing_welcome_key_package");
        assert_eq!(error.sync_error_class(), crate::SyncErrorClass::Crypto);
        assert_eq!(
            EngineError::MissingWelcomeKeyPackage.to_string(),
            "missing local key package for invitation; publish a new key package and ask the sender to invite you again"
        );
        assert!(!EngineError::MissingWelcomeKeyPackage.is_transient());
    }

    #[test]
    fn invalid_key_package_capabilities_preserve_member_and_protocol_classification() {
        let member = cgka_traits::MemberId::new(vec![0xBB; 32]);
        let error = AppError::Session(marmot_session::SessionError::Engine(
            EngineError::InvalidKeyPackageCapabilities {
                member: member.clone(),
            },
        ));
        assert_eq!(
            error.privacy_safe_kind(),
            "invalid_key_package_capabilities"
        );
        assert_eq!(error.sync_error_class(), crate::SyncErrorClass::Protocol);
        assert!(matches!(error.as_engine_error(),
            Some(EngineError::InvalidKeyPackageCapabilities { member: rejected }) if rejected == &member));
        assert!(!error.to_string().contains(&hex::encode(member.as_slice())));
    }

    #[test]
    fn repair_stop_reason_and_loss_are_independent_bounded_classifications() {
        use super::FullHistoryRepairIncompleteReason as Reason;
        use crate::SyncErrorClass;
        for (reason, class) in [
            (Reason::Cancelled, SyncErrorClass::Cancelled),
            (Reason::Deadline, SyncErrorClass::Timeout),
            (Reason::NoRelayEose, SyncErrorClass::Timeout),
            (Reason::EoseTimeout, SyncErrorClass::Timeout),
            (Reason::CoverageUnproven, SyncErrorClass::Unknown),
            (Reason::BelowRetentionWindow, SyncErrorClass::Unknown),
        ] {
            for delivery_loss_pending in [false, true] {
                let error = AppError::FullHistoryRepairIncomplete {
                    reason,
                    delivery_loss_pending,
                };
                assert_eq!(error.sync_error_class(), class);
                assert!(error.to_string().contains(reason.as_str()));
                assert_eq!(
                    error.privacy_safe_kind(),
                    if delivery_loss_pending && reason != Reason::Cancelled {
                        "account_delivery_queue_overflow"
                    } else {
                        reason.as_str()
                    }
                );
            }
        }
    }

    #[test]
    fn worker_failure_preserves_typed_repair_outcome_without_parsing_messages() {
        use super::FullHistoryRepairIncompleteReason as Reason;
        for reason in [
            Reason::CoverageUnproven,
            Reason::BelowRetentionWindow,
            Reason::Cancelled,
            Reason::Deadline,
            Reason::DeliveryLoss,
            Reason::EoseTimeout,
            Reason::NoRelayEose,
            Reason::NovelProgressYield,
            Reason::NoProgressYield,
            Reason::Unconfirmed,
        ] {
            for loss in [false, true] {
                let failure = crate::ClassifiedSyncFailure::at_stage(
                    crate::SyncSummary::default(),
                    AppError::FullHistoryRepairIncomplete {
                        reason,
                        delivery_loss_pending: loss,
                    },
                    marmot_observability::app_telemetry::SyncFailureStage::Unknown,
                );
                let wrapped = AppError::AccountCatchUp(AccountCatchUpFailure::from_sync_failure(
                    "display only".into(),
                    &failure,
                ));
                assert_eq!(
                    wrapped.full_history_repair_incomplete(),
                    Some((reason, loss))
                );
                assert_eq!(wrapped.privacy_safe_kind(), "account_catch_up");
            }
        }
        let text_only = AppError::AccountCatchUp(AccountCatchUpFailure::new(
            "full_history_coverage_unproven".into(),
            marmot_observability::app_telemetry::SyncFailureClassification::UNKNOWN,
        ));
        assert_eq!(text_only.full_history_repair_incomplete(), None);
    }

    // Kind strings leave the runtime: `account_error_message` interpolates
    // them into messages the CLI daemon persists and host apps log. Pin the
    // catch-up kind so the wire-visible string cannot drift silently — it is
    // the label operators will grep for after the RelayDirectory mislabel.
    #[test]
    fn account_catch_up_kind_is_stable() {
        let err = AppError::AccountCatchUp(AccountCatchUpFailure::new(
            "runtime catch-up failed: account_session".into(),
            SyncFailureClassification::UNKNOWN,
        ));
        assert_eq!(err.privacy_safe_kind(), "account_catch_up");
        assert_eq!(
            err.to_string(),
            "account catch-up failed: runtime catch-up failed: account_session"
        );
    }

    // A session failure that is really a transient lock blip must not read the
    // same as a durable one. `SessionError::is_transient` is true for exactly
    // this case, so the kind has to carry the same split.
    #[test]
    fn transient_session_storage_failure_reports_the_busy_storage_kind() {
        let err = AppError::from(marmot_session::SessionError::from(StorageError::Busy(
            "locked".into(),
        )));
        assert_eq!(err.privacy_safe_kind(), "storage_busy");
    }

    // A fork is the single most consequential engine failure a session can
    // wrap, and `forked_epoch` is the name the engine's own audit rows already
    // use for it. Reusing that vocabulary is what lets an operator join an app
    // tracing field to an engine audit row.
    #[test]
    fn session_engine_failure_reports_the_engine_kind() {
        let err = AppError::Session(marmot_session::SessionError::Engine(
            EngineError::ForkedEpoch {
                group_id: GroupId::new(vec![1u8; 16]),
                last_stable: EpochId(7),
                conflicting_epoch: EpochId(8),
            },
        ));
        assert_eq!(err.privacy_safe_kind(), "forked_epoch");
    }

    // The engine wraps storage too, so a lock blip can arrive one layer deeper.
    // It is the same blip and must get the same name — otherwise the transient
    // case hides behind the engine's coarse `storage` bucket at one depth and
    // is visible at the other.
    #[test]
    fn transient_storage_failure_wrapped_by_the_engine_reports_the_same_kind() {
        let err = AppError::Session(marmot_session::SessionError::Engine(EngineError::Storage(
            StorageError::Busy("locked".into()),
        )));
        assert_eq!(err.privacy_safe_kind(), "storage_busy");
    }

    // Most session failures reach the app wrapped in `AccountError`, and
    // `as_engine_error` already treats all three wrappings as the same engine
    // failure. The kind has to agree: one engine failure must not get three
    // names depending on how deep it was wrapped.
    #[test]
    fn account_wrapped_session_failures_report_the_same_kind_as_unwrapped_ones() {
        let direct = AppError::Session(marmot_session::SessionError::Engine(
            EngineError::InvalidWelcome,
        ));
        let via_account_session = AppError::Account(AccountError::Session(
            marmot_session::SessionError::Engine(EngineError::InvalidWelcome),
        ));
        let via_account_engine =
            AppError::Account(AccountError::Engine(EngineError::InvalidWelcome));

        assert_eq!(direct.privacy_safe_kind(), "invalid_welcome");
        assert_eq!(via_account_session.privacy_safe_kind(), "invalid_welcome");
        assert_eq!(via_account_engine.privacy_safe_kind(), "invalid_welcome");
    }

    // `is_transient` and the kind are two views of one fact. Pin them together
    // so a future kind edit cannot silently make a retryable failure read as
    // durable (or the reverse).
    #[test]
    fn session_kind_agrees_with_is_transient() {
        for error in [
            marmot_session::SessionError::from(StorageError::Busy("locked".into())),
            marmot_session::SessionError::Engine(EngineError::Storage(StorageError::Busy(
                "locked".into(),
            ))),
            marmot_session::SessionError::from(StorageError::Closed("shut".into())),
            marmot_session::SessionError::Engine(EngineError::InvalidWelcome),
        ] {
            let transient = error.is_transient();
            let kind = AppError::Session(error).privacy_safe_kind();
            assert_eq!(transient, kind == "storage_busy", "kind {kind}");
        }
    }
}

#[cfg(test)]
mod directory_error_tests {
    //! `DirectoryError` converts back to the `AppError` the directory used
    //! before it had its own type.

    use cgka_traits::error::EngineError;
    use cgka_traits::storage::StorageError;
    use marmot_account::AccountHomeError;

    use super::AppError;
    use crate::MissingRelayListKind;
    use nostr_directory::error::{DirectoryError, MissingKeyPackageReason};

    /// Each case's `AppError` is built the way the directory built it before.
    fn cases() -> Vec<(DirectoryError, AppError)> {
        let sqlite_busy = || {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                None,
            )
        };
        let json = || serde_json::from_str::<u8>("x").unwrap_err();
        let hex = || hex::decode("zz").unwrap_err();
        let io = || std::io::Error::other("disk");
        vec![
            (
                DirectoryError::InvalidKeyPackageEvent("tag".into()),
                AppError::InvalidKeyPackageEvent("tag".into()),
            ),
            (DirectoryError::InvalidPublicKey, AppError::InvalidPublicKey),
            (
                DirectoryError::RelayDirectory("timeout".into()),
                AppError::RelayDirectory("timeout".into()),
            ),
            (
                DirectoryError::MissingKeyPackage {
                    account: "a".into(),
                    reason: MissingKeyPackageReason::ObsoleteOnly,
                },
                AppError::MissingKeyPackage {
                    account: "a".into(),
                    reason: MissingKeyPackageReason::ObsoleteOnly,
                },
            ),
            (
                DirectoryError::InvalidDirectorySearch("radius".into()),
                AppError::InvalidDirectorySearch("radius".into()),
            ),
            (
                DirectoryError::DirectoryLookupIncomplete("a".into()),
                AppError::DirectoryLookupIncomplete("a".into()),
            ),
            (
                DirectoryError::MissingRelayLists(vec![MissingRelayListKind::Inbox]),
                AppError::MissingRelayLists(vec![MissingRelayListKind::Inbox]),
            ),
            (DirectoryError::TransportClosed, AppError::TransportClosed),
            (
                DirectoryError::MissingMemberInboxRoute("a".into()),
                AppError::MissingMemberInboxRoute("a".into()),
            ),
            (
                DirectoryError::InvalidPublicEventReferences("17".into()),
                AppError::InvalidPublicEventReferences("17".into()),
            ),
            (
                DirectoryError::MissingDirectoryEntry("a".into()),
                AppError::MissingDirectoryEntry("a".into()),
            ),
            (
                DirectoryError::InvalidNostrRouting("relay".into()),
                AppError::InvalidNostrRouting("relay".into()),
            ),
            (
                DirectoryError::InvalidCachedIdentityPage("101".into()),
                AppError::InvalidCachedIdentityPage("101".into()),
            ),
            (
                DirectoryError::BlockingTask("panicked".into()),
                AppError::BlockingTask("panicked".into()),
            ),
            (
                DirectoryError::Storage(StorageError::Closed("cache".into())),
                AppError::Storage(StorageError::Closed("cache".into())),
            ),
            (
                DirectoryError::Storage(StorageError::Busy("cache".into())),
                AppError::Storage(StorageError::Busy("cache".into())),
            ),
            (DirectoryError::Io(io()), AppError::Io(io())),
            (DirectoryError::Json(json()), AppError::Json(json())),
            (
                DirectoryError::Sqlite(sqlite_busy()),
                AppError::Sqlite(sqlite_busy()),
            ),
            (DirectoryError::Hex(hex()), AppError::Hex(hex())),
            // A KeyPackage requirements failure: the app's session-error step.
            (
                DirectoryError::KeyPackageRequirements(EngineError::UnknownPending),
                AppError::from(marmot_session::SessionError::from(
                    EngineError::UnknownPending,
                )),
            ),
            (
                DirectoryError::KeyPackageRequirements(EngineError::Storage(StorageError::Busy(
                    "engine".into(),
                ))),
                AppError::from(marmot_session::SessionError::from(EngineError::Storage(
                    StorageError::Busy("engine".into()),
                ))),
            ),
            // App failures that reach directory code through a resource call:
            // account lookup,
            (
                AppError::from(AccountHomeError::UnknownAccount("alice".into())).into(),
                AppError::from(AccountHomeError::UnknownAccount("alice".into())),
            ),
            // the cache key's signing or external secret,
            (
                AppError::from(AccountHomeError::SecretNotFound("alice".into())).into(),
                AppError::from(AccountHomeError::SecretNotFound("alice".into())),
            ),
            (
                AppError::from(AccountHomeError::SecretStoreUnavailable("keychain".into())).into(),
                AppError::from(AccountHomeError::SecretStoreUnavailable("keychain".into())),
            ),
            // closed app storage,
            (
                AppError::Storage(StorageError::Closed("app storage".into())).into(),
                AppError::Storage(StorageError::Closed("app storage".into())),
            ),
            // a cache or shared-storage open, and its salt file,
            (
                AppError::Sqlite(sqlite_busy()).into(),
                AppError::Sqlite(sqlite_busy()),
            ),
            (AppError::Io(io()).into(), AppError::Io(io())),
            // and the block list.
            (
                AppError::BlockListUnavailable.into(),
                AppError::BlockListUnavailable,
            ),
        ]
    }

    /// Fails to compile when a variant is added without a case above.
    fn covered(error: &DirectoryError) {
        match error {
            DirectoryError::InvalidKeyPackageEvent(_)
            | DirectoryError::InvalidPublicKey
            | DirectoryError::RelayDirectory(_)
            | DirectoryError::MissingKeyPackage { .. }
            | DirectoryError::InvalidDirectorySearch(_)
            | DirectoryError::DirectoryLookupIncomplete(_)
            | DirectoryError::MissingRelayLists(_)
            | DirectoryError::TransportClosed
            | DirectoryError::MissingMemberInboxRoute(_)
            | DirectoryError::InvalidPublicEventReferences(_)
            | DirectoryError::MissingDirectoryEntry(_)
            | DirectoryError::InvalidNostrRouting(_)
            | DirectoryError::InvalidCachedIdentityPage(_)
            | DirectoryError::BlockingTask(_)
            | DirectoryError::Storage(_)
            | DirectoryError::Io(_)
            | DirectoryError::Json(_)
            | DirectoryError::Sqlite(_)
            | DirectoryError::Hex(_)
            | DirectoryError::KeyPackageRequirements(_)
            | DirectoryError::Resource(_) => {}
        }
    }

    #[test]
    fn every_directory_error_converts_to_the_app_error_it_replaced() {
        for (directory_error, expected) in cases() {
            covered(&directory_error);
            let message = directory_error.to_string();
            let kind = directory_error.privacy_safe_kind();
            let converted = AppError::from(directory_error);
            assert_eq!(
                std::mem::discriminant(&converted),
                std::mem::discriminant(&expected),
                "{converted:?} is not the variant of {expected:?}"
            );
            assert_eq!(converted.to_string(), expected.to_string());
            assert_eq!(
                message,
                expected.to_string(),
                "directory message for {expected:?}"
            );
            assert_eq!(converted.privacy_safe_kind(), expected.privacy_safe_kind());
            assert_eq!(
                kind,
                expected.privacy_safe_kind(),
                "directory kind for {expected:?}"
            );
            assert_eq!(format!("{converted:?}"), format!("{expected:?}"));
        }
    }

    #[test]
    fn app_errors_come_back_from_the_directory_unchanged() {
        let app = AppError::from(AccountHomeError::UnknownAccount("alice".into()));
        let carried = DirectoryError::from(app);
        assert!(matches!(carried, DirectoryError::Resource(_)));
        assert!(matches!(
            AppError::from(carried),
            AppError::AccountHome(AccountHomeError::UnknownAccount(label)) if label == "alice"
        ));
    }
}

#[cfg(test)]
mod audit_upload_error_tests {
    //! `AuditUploadError` converts back to the `AppError` the audit upload
    //! built before it had its own type.

    use super::AppError;
    use marmot_observability::audit_upload::{
        AUDIT_LOG_UPLOAD_MAX_BYTES, AuditUploadError, AuditUploadSnapshot, invalid_audit_upload,
        validate_audit_upload_endpoint,
    };

    /// Every failure the upload half builds, each with the `AppError` the
    /// upload built for it before. Steps a test can reach run for real; the
    /// request and response failures need a network, so they are written out.
    async fn cases() -> Vec<(AuditUploadError, AppError)> {
        let endpoint = |endpoint: &str, token: Option<&str>| {
            validate_audit_upload_endpoint(endpoint, token).unwrap_err()
        };
        let retired = transport_nostr::retired_relay_hosts()
            .into_iter()
            .next()
            .expect("centralized retired host list");
        let oversized = tempfile::tempfile().unwrap();
        oversized.set_len(AUDIT_LOG_UPLOAD_MAX_BYTES + 1).unwrap();
        let oversized = AuditUploadSnapshot::capture(tokio::fs::File::from_std(oversized))
            .await
            .err()
            .expect("over the upload ceiling");
        let io = || std::io::Error::other("disk");
        let upload = |message: &str| {
            (
                AuditUploadError::AuditLogUpload(message.to_owned()),
                AppError::AuditLogUpload(message.to_owned()),
            )
        };
        vec![
            // Endpoint validation.
            (
                endpoint("   ", Some("token")),
                AppError::AuditLogUpload("forensic upload endpoint is empty".to_owned()),
            ),
            (
                endpoint("https://collector.example:0/ingest", Some("token")),
                AppError::AuditLogUpload("forensic upload endpoint is invalid".to_owned()),
            ),
            (
                endpoint("http://collector.example/ingest", Some("token")),
                AppError::AuditLogUpload(
                    "forensic upload endpoint must be https, or loopback http for local testing"
                        .to_owned(),
                ),
            ),
            (
                endpoint(&format!("https://{retired}/ingest"), Some("token")),
                AppError::AuditLogUpload("forensic upload endpoint is not allowed".to_owned()),
            ),
            (
                endpoint("https://collector.example/ingest", None),
                AppError::AuditLogUpload(
                    "forensic upload endpoint requires an authorization bearer token unless it is loopback"
                        .to_owned(),
                ),
            ),
            // Snapshot capture and v4 eligibility.
            (
                oversized,
                AppError::AuditLogUpload(format!(
                    "audit log exceeds {} byte upload limit",
                    AUDIT_LOG_UPLOAD_MAX_BYTES
                )),
            ),
            (AuditUploadError::Io(io()), AppError::Io(io())),
            (
                invalid_audit_upload(),
                AppError::InvalidAuditLogFile(
                    "only valid v4 forensic audit records may be uploaded".into(),
                ),
            ),
            // The validation worker, the network deadline, resolution and
            // pinning, and the request.
            upload("audit validation worker failed"),
            upload("request timed out"),
            upload("request failed"),
            upload("HTTP 503"),
            upload("connection failed"),
            upload("invalid response body"),
        ]
    }

    /// Fails to compile when a variant is added without a case above.
    fn covered(error: &AuditUploadError) {
        match error {
            AuditUploadError::InvalidAuditLogFile(_)
            | AuditUploadError::AuditLogUpload(_)
            | AuditUploadError::Io(_) => {}
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_audit_upload_error_converts_to_the_app_error_it_replaced() {
        for (upload_error, expected) in cases().await {
            covered(&upload_error);
            let message = upload_error.to_string();
            let converted = AppError::from(upload_error);
            assert_eq!(
                std::mem::discriminant(&converted),
                std::mem::discriminant(&expected),
                "{converted:?} is not the variant of {expected:?}"
            );
            assert_eq!(converted.to_string(), expected.to_string());
            assert_eq!(
                message,
                expected.to_string(),
                "upload message for {expected:?}"
            );
            assert_eq!(converted.privacy_safe_kind(), expected.privacy_safe_kind());
            assert_eq!(format!("{converted:?}"), format!("{expected:?}"));
        }
    }
}
