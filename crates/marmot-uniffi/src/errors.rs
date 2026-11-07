use cgka_traits::error::EngineError;
use marmot_account::AccountHomeError;
use marmot_app::AppError;

/// Why a completed KeyPackage lookup found nothing to invite. Describes the
/// searched relays only; the set only grows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MissingKeyPackageReasonFfi {
    /// No KeyPackage publication was found.
    NotFound,
    /// Only legacy-profile KeyPackages were found: the recipient must update
    /// their app and publish a current KeyPackage.
    ObsoleteOnly,
}

impl From<marmot_app::MissingKeyPackageReason> for MissingKeyPackageReasonFfi {
    fn from(value: marmot_app::MissingKeyPackageReason) -> Self {
        match value {
            marmot_app::MissingKeyPackageReason::NotFound => Self::NotFound,
            marmot_app::MissingKeyPackageReason::ObsoleteOnly => Self::ObsoleteOnly,
        }
    }
}

impl std::fmt::Display for MissingKeyPackageReasonFfi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "not_found",
            Self::ObsoleteOnly => "obsolete_only",
        })
    }
}

/// What MDK was publishing when a relay refused the event as too large.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OversizedArtifactFfi {
    /// A group change such as an invite, a removal or an update.
    Commit,
    /// The Welcome that lets an invitee join.
    Welcome,
    /// A chat message or another application message.
    ApplicationMessage,
    /// Any other transport event.
    Other,
}

impl From<marmot_app::OversizedArtifact> for OversizedArtifactFfi {
    fn from(value: marmot_app::OversizedArtifact) -> Self {
        match value {
            marmot_app::OversizedArtifact::Commit => Self::Commit,
            marmot_app::OversizedArtifact::Welcome => Self::Welcome,
            marmot_app::OversizedArtifact::ApplicationMessage => Self::ApplicationMessage,
            marmot_app::OversizedArtifact::Other => Self::Other,
        }
    }
}

/// A coarse bucket for the size of an event a relay refused as too large.
/// These diagnostic buckets do not assert a relay's configured limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum EventSizeClassFfi {
    Under64Kib,
    From64To128Kib,
    From128To256Kib,
    From256To512Kib,
    From512KibTo1Mib,
    From1To2Mib,
    From2To4Mib,
    Over4Mib,
}

impl From<marmot_app::EventSizeClass> for EventSizeClassFfi {
    fn from(value: marmot_app::EventSizeClass) -> Self {
        use marmot_app::EventSizeClass as Class;
        match value {
            Class::Under64Kib => Self::Under64Kib,
            Class::From64To128Kib => Self::From64To128Kib,
            Class::From128To256Kib => Self::From128To256Kib,
            Class::From256To512Kib => Self::From256To512Kib,
            Class::From512KibTo1Mib => Self::From512KibTo1Mib,
            Class::From1To2Mib => Self::From1To2Mib,
            Class::From2To4Mib => Self::From2To4Mib,
            Class::Over4Mib => Self::Over4Mib,
        }
    }
}

impl std::fmt::Display for OversizedArtifactFfi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Commit => "commit",
            Self::Welcome => "welcome",
            Self::ApplicationMessage => "application_message",
            Self::Other => "other",
        })
    }
}

impl std::fmt::Display for EventSizeClassFfi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Under64Kib => "under_64_kib",
            Self::From64To128Kib => "from_64_to_128_kib",
            Self::From128To256Kib => "from_128_to_256_kib",
            Self::From256To512Kib => "from_256_to_512_kib",
            Self::From512KibTo1Mib => "from_512_kib_to_1_mib",
            Self::From1To2Mib => "from_1_to_2_mib",
            Self::From2To4Mib => "from_2_to_4_mib",
            Self::Over4Mib => "over_4_mib",
        })
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MarmotKitError {
    #[error("user is blocked")]
    UserBlocked,
    #[error("block list synchronization unavailable")]
    BlockListUnavailable,
    #[error("block list publication outcome uncertain")]
    BlockPublicationUncertain,
    /// No valid moderation-report destination is installed; nothing was published.
    #[error("moderation reporting is not configured")]
    ModerationReportingNotConfigured,
    /// The moderation-report destination was rejected as a whole.
    #[error("invalid moderation report configuration: {details}")]
    InvalidModerationReportConfig { details: String },
    #[error("reported user public key is invalid")]
    InvalidReportedPublicKey,
    #[error("an account cannot report itself")]
    CannotReportSelf,
    /// Local per-account cap against runaway clients; retry later.
    #[error("too many moderation reports; try again later")]
    ModerationReportRateLimited,
    /// The edit target is missing, not a chat message, sent by another
    /// account, deleted, or withdrawn by convergence; nothing was published.
    #[error("edit target must be an available self-authored chat message")]
    InvalidEditTarget,
    #[error("usage and diagnostics consent required")]
    ConsentRequired,
    #[error("invalid product analytics configuration")]
    InvalidProductAnalyticsConfiguration,
    #[error("unregistered or invalid product observation")]
    InvalidProductObservation,
    #[error("identity already exists: {account}")]
    DuplicateIdentity { account: String },
    #[error("unknown account: {account_ref}")]
    UnknownAccount { account_ref: String },
    #[error("unknown group: {group_id_hex}")]
    UnknownGroup { group_id_hex: String },
    /// The named group is terminal or no longer has a pending invitation.
    /// Stable host-facing rejection for stale notification actions (mdk#1606).
    #[error("group invite is not pending")]
    GroupInviteNotPending,
    /// Canonical creation succeeded, but its derived chat row was not durable.
    /// Refresh account state; retrying creation would produce a duplicate.
    #[error("group was created but its local chat projection is unavailable: {group_id_hex}")]
    CreatedGroupProjectionUnavailable { group_id_hex: String },
    #[error("group membership page exceeds the maximum of {max_groups} groups")]
    InvalidGroupMembershipPage { max_groups: u64 },
    #[error("cached identity page exceeds the maximum of {max_accounts} accounts")]
    InvalidCachedIdentityPage { max_accounts: u64 },
    #[error("public event preview batch exceeds the maximum of {max_references} references")]
    InvalidPublicEventReferences { max_references: u64 },
    /// The group exists but its full hydration has not completed yet
    /// (mdk#1161). Retryable: the runtime's background pipeline promotes the
    /// group shortly after account readiness, and worker-routed reads wait
    /// for exactly the named group. Distinct from `UnknownGroup` so hosts can
    /// render "still loading" instead of "no such group".
    #[error("group hydration pending: {group_id_hex}")]
    GroupHydrationPending { group_id_hex: String },
    /// The once-per-open peer-index backfill has not finished (mdk#1463).
    /// Retryable: the account worker completes it after startup hydration.
    /// Distinct from a successful `None` so hosts do not create a duplicate
    /// direct conversation.
    #[error("direct conversation index is not ready; retry after account hydration")]
    DirectConversationIndexNotReady,
    #[error("chat presentation preparation is incomplete; retry after local maintenance")]
    ChatPresentationNotReady,
    #[error("invalid chat pin: {details}")]
    InvalidChatPin { details: String },
    /// Host-supplied draft attachment metadata is malformed.
    #[error("invalid message draft: {details}")]
    InvalidMessageDraft { details: String },
    /// Host-supplied encrypted-media metadata does not match the target
    /// group's selected media profile or locator policy, or an upload request
    /// is unusable (empty batch, oversized, no endpoint).
    #[error("invalid media reference: {details}")]
    InvalidMediaReference { details: String },
    /// An attachment was encrypted at `source_epoch`, but the group moved to
    /// `current_epoch`, or to another branch at the same epoch, before it could
    /// be sent (mdk#2158). Its media key is bound to the epoch it was encrypted
    /// under, so it cannot be sent; upload the file again. Nothing was
    /// published.
    #[error(
        "media reference was encrypted at epoch {source_epoch} but the group has moved off it (now at epoch {current_epoch}); upload it again"
    )]
    MediaReferenceStaleEpoch {
        source_epoch: u64,
        current_epoch: u64,
    },
    /// The group's epoch is unsettled, so an attachment encrypted at
    /// `source_epoch` cannot be sent right now. Nothing was published. Sync
    /// and send again; if the epoch moved, that send fails with
    /// `MediaReferenceStaleEpoch` and the file must be uploaded again.
    #[error(
        "the group's epoch is unsettled, so media encrypted at epoch {source_epoch} cannot be sent yet; sync and send again"
    )]
    MediaReferenceEpochUnsettled { source_epoch: u64 },
    /// An encrypted-media `imeta` reference failed MDK's shared strict parser
    /// (mdk#1787): `parse_media_imeta_tag` on an inbound tag, or a host-built
    /// reference passed to build/send/upload/download whose fields are
    /// structurally invalid. `kind` is the stable category the timeline's
    /// `Rejected` outcomes also report, so explicit parsing and projection
    /// agree without string matching; `details` is privacy-safe presentation
    /// text. Attachment-local: never a reason to hide the carrying message.
    #[error("invalid media attachment [{kind}]: {details}")]
    MediaAttachmentRejected {
        kind: crate::conversions::MediaAttachmentRejectionKindFfi,
        details: String,
    },
    /// The reference is valid but has no locator this client may fetch under
    /// the group's current `allowed_locator_kinds` or its own host-safety
    /// policy; nothing was dialed. Not retryable until the policy, the client,
    /// or the sender's locators change. Distinct from
    /// [`MarmotKitError::MediaAttachmentRejected`] (the reference is fine) and
    /// [`MarmotKitError::MediaDownloadFailed`] (a fetch was attempted).
    #[error("media is unfetchable under the current locator policy: {details}")]
    MediaUnfetchable { details: String },
    /// Fetching, verifying, or decrypting the blob failed after a fetchable
    /// locator was selected: transport errors and timeouts (retryable),
    /// ciphertext/plaintext hash mismatches, and AEAD failures (the served
    /// bytes or the epoch secret do not match the reference).
    #[error("media download failed: {details}")]
    MediaDownloadFailed { details: String },
    #[error("invalid hex: {details}")]
    InvalidHex { details: String },
    #[error("invalid nostr identity: {details}")]
    InvalidIdentity { details: String },
    /// A fetched Nostr event exists for the recipient but cannot be used as a
    /// valid Marmot KeyPackage. Kept distinct from malformed recipient input so
    /// host apps can present a setup/invite state without string matching.
    #[error("invalid key package event: {details}")]
    InvalidKeyPackageEvent { details: String },
    /// A completed lookup found no KeyPackage this device may invite. Branch on
    /// `reason`: `ObsoleteOnly` means the recipient must update their app and
    /// publish a current KeyPackage; `NotFound` means none was published.
    #[error("missing key package for {account} [{reason}]")]
    MissingKeyPackage {
        account: String,
        reason: MissingKeyPackageReasonFfi,
    },
    /// The invite target has no kind-10050 inbox endpoint that this device can
    /// safely use. The account id lets hosts identify the affected selection
    /// without parsing display text.
    #[error("member {account} has no valid Marmot inbox relay")]
    MissingMemberInboxRoute { account: String },
    /// Relay-list or KeyPackage lookup for `account` ran out of time or relay
    /// coverage. Nothing is known to be missing; offer retry. Display omits
    /// the account; read it from the field.
    #[error("directory lookup did not complete")]
    DirectoryLookupIncomplete { account: String },
    #[error("publish failed: {details}")]
    Publish { details: String },
    /// All current targets refused this artifact for size on the observed attempt.
    /// A legacy Welcome can have earlier exposure hidden by a crash or expired
    /// bookkeeping; this is not proof of non-delivery or a terminal outcome.
    /// Keep native retries and confirmed state. No relay limit is inferred.
    #[error("event too large: {artifact} ({size_class})")]
    EventTooLarge {
        artifact: OversizedArtifactFfi,
        size_class: EventSizeClassFfi,
    },
    /// No current kind-3 event was found on the account's known outbox/default
    /// relays. Retrying after directory/relay recovery is safe; publishing from
    /// an assumed empty list is not.
    #[error("current account follow list is unavailable")]
    FollowListUnavailable,
    /// The current kind-3 list has at least 2,048 follows, more than MDK reads
    /// from one list, so a follow or unfollow could drop follows. Nothing was
    /// published; manage this list in a client that edits it whole.
    #[error("current account follow list is too large to update")]
    FollowListTooLarge,
    #[error("transport closed")]
    TransportClosed,
    /// Another process or runtime owns the shared Marmot root. This is a typed,
    /// retryable/fallback signal for the iOS foreground app and NSE; neither
    /// host should open an unleased runtime after receiving it.
    #[error("marmot runtime root is already in use")]
    RuntimeBusy,
    /// Another client or managed worker in this runtime currently owns the
    /// account's in-memory engine session. Retry only after that owner closes.
    #[error("marmot account session is already in use")]
    AccountSessionBusy,
    /// A pre-journal account has an encrypted database but no recoverable
    /// stable KeyPackage slot. Automatic retry cannot prove non-exposure; the
    /// host may offer `reset_incomplete_account_setup` with explicit consent.
    #[error("incomplete account setup requires explicit recovery")]
    AccountSetupRecoveryRequired,
    #[error("durable account setup can be resumed by retrying")]
    AccountSetupRetryRequired,
    #[error("onboarding action is unavailable or stale")]
    OnboardingActionUnavailable,
    #[error("account must complete interactive onboarding")]
    OnboardingRequired,
    #[error("account is not eligible for incomplete-setup reset")]
    AccountSetupResetNotApplicable,
    #[error("recoverable KeyPackage setup state exists; retry instead of resetting")]
    AccountSetupKeyPackageRecoveryAvailable,
    #[error("marmot runtime is shutting down")]
    RuntimeStopping,
    /// Automatic acquisition permission requires HostManaged configuration.
    #[error("host-managed attachment mode required")]
    AttachmentModeRequired,
    /// A signed-out account cannot approve automatic network requests.
    #[error("automatic attachment approval requires a signed-in account")]
    AttachmentAccountSignedOut,
    /// An account worker's transport catch-up failed (sync error or timeout).
    /// Distinct, typed variant — separate from [`MarmotKitError::Runtime`] —
    /// so hosts (notably the NSE wake path) can tell a catch-up failure from
    /// a generic runtime error; the untyped bucket is what sent an earlier
    /// investigation chasing the wrong subsystem.
    #[error("account catch-up failed: {details}")]
    AccountCatchUp { details: String },
    #[error("local account is not an admin of group {group_id_hex}")]
    NotGroupAdmin { group_id_hex: String },
    #[error("admin must self-demote before leaving group {group_id_hex}")]
    AdminCannotSelfRemove { group_id_hex: String },
    /// A leave is already in flight for this group. The durable request survives
    /// restarts and the engine keeps re-proposing until a commit removes us, so
    /// this is not a failure to retry — surface progress instead. Check
    /// `GroupManagementStateFfi::leave_request_pending` before offering Leave.
    #[error("a leave request is already pending for group {group_id_hex}")]
    LeaveAlreadyRequested { group_id_hex: String },
    #[error("operation would remove the last admin from group {group_id_hex}")]
    WouldRemoveLastAdmin { group_id_hex: String },
    #[error("group {group_id_hex} cannot enable disbanding until all members support it")]
    DisbandingUnsupportedMembers {
        group_id_hex: String,
        member_ids_hex: Vec<String>,
    },
    #[error("group {group_id_hex} has not enabled disbanding")]
    DisbandingNotEnabled { group_id_hex: String },
    /// The group cannot turn on account-devices now. `reason` is the same
    /// aggregate answer `Marmot::account_devices_activation` gives, never
    /// `Eligible`; it never names which members or devices hold it back.
    #[error("group {group_id_hex} cannot turn on account-devices now: {reason:?}")]
    AccountDevicesActivationRefused {
        group_id_hex: String,
        reason: crate::conversions::AccountDevicesActivationFfi,
    },
    #[error("group {group_id_hex} is disbanding or disbanded")]
    GroupDisbanding { group_id_hex: String },
    /// This device was removed from the group; it goes on without us. Kept
    /// distinct from `GroupDisbanding` so a host does not tell the user a live
    /// group was disbanded.
    #[error("this device was removed from group {group_id_hex}")]
    GroupRemoved { group_id_hex: String },
    /// The group moved past this device and recovery has not caught it up.
    /// Group changes would fork it, so they wait; retry once it has synced.
    #[error("group {group_id_hex} is still catching up on missed changes")]
    GroupCatchingUp { group_id_hex: String },
    /// The group's last change has not reached every group relay yet, so
    /// members who read only those relays cannot follow it. MDK keeps retrying
    /// them; retry once they accept, or after `acknowledge_group_commit_undelivered`.
    #[error("group {group_id_hex}'s last change has not reached every relay yet")]
    GroupCommitUndelivered { group_id_hex: String },
    #[error("member {member_id_hex} is not in group {group_id_hex}")]
    MemberNotInGroup {
        group_id_hex: String,
        member_id_hex: String,
    },
    #[error("member {member_id_hex} is already an admin of group {group_id_hex}")]
    AlreadyAdmin {
        group_id_hex: String,
        member_id_hex: String,
    },
    #[error("member {member_id_hex} is not an admin of group {group_id_hex}")]
    NotAdmin {
        group_id_hex: String,
        member_id_hex: String,
    },
    /// Transient storage lock contention (`SQLITE_BUSY` / "database is locked")
    /// that survived the storage layer's internal retry-with-backoff. It is a
    /// distinct, typed variant — separate from [`MarmotKitError::Runtime`] — so
    /// the app (#484) can recognise a *transient* condition worth a user retry
    /// or auto-retry instead of string-parsing "database is locked" and
    /// surfacing it as a fatal "Send failed".
    #[error("storage busy: {details}")]
    StorageBusy { details: String },
    /// The store has been closed by [`Marmot::shutdown_and_close`][crate::Marmot::shutdown_and_close]
    /// and this call reached a database that is no longer open.
    ///
    /// Typed, and deliberately not [`MarmotKitError::Runtime`], because it is
    /// an *expected* outcome rather than a fault: a host closing its store
    /// before suspension races whatever work was still in flight, and that work
    /// must be reportable as "we shut down" instead of as a storage failure the
    /// user gets told about. Never retryable — the handle is spent; construct a
    /// new `Marmot` when the app resumes.
    #[error("storage closed: {details}")]
    StorageClosed { details: String },
    /// The device has no room for this operation: free space would fall
    /// below the configured disk reserve, or the volume or database is full.
    /// A send refuses an attachment its disk cannot stage, before anything
    /// is uploaded or published (mdk#2314). Typed so hosts can tell the user
    /// to free space instead of reporting a generic failure; retry once
    /// space is available.
    #[error("storage full: {details}")]
    StorageFull { details: String },
    /// The account exists but its raw private key could not be located in the
    /// keystore — e.g. a public-only / watch-only account, or a secret that was
    /// never loaded. Distinct, typed variant (#543) so a key-backup surface can
    /// tell "this account has no exportable key" apart from a generic runtime
    /// failure without string-parsing.
    #[error("account secret not found: {details}")]
    SecretNotFound { details: String },
    /// The platform secret store / keychain is locked, uninitialized, or
    /// otherwise unavailable, so the raw private key could not be read. Typed
    /// variant (#543) so a key-backup surface can prompt the user to unlock the
    /// keystore rather than reporting an opaque runtime error.
    #[error("account keystore unavailable: {details}")]
    KeystoreUnavailable { details: String },
    /// The user supplied an empty passphrase for NIP-49 encrypted key export.
    /// Distinct typed variant (#544) so backup UI can keep the user in the
    /// passphrase sheet instead of showing a generic runtime failure.
    #[error("passphrase cannot be empty")]
    EmptyPassphrase,
    /// NIP-49 encryption failed after keystore access succeeded. Carries only
    /// library/error classification text, never passphrase or key material.
    #[error("encrypted secret-key export failed: {details}")]
    EncryptionFailed { details: String },
    /// A filesystem IO error while reading the key, appending the reveal audit
    /// entry, or persisting the NIP-49 key-security byte. Typed variant (#543)
    /// so a key-backup surface can distinguish disk failures from arbitrary
    /// runtime faults.
    #[error("io error: {details}")]
    Io { details: String },
    /// The account is configured for external signing, but this runtime has no
    /// registered callback for it yet. Typed so clients can prompt the user to
    /// reconnect Amber instead of surfacing a generic runtime failure.
    #[error("external signer unavailable for account {account}")]
    ExternalSignerUnavailable { account: String },
    /// The external signer returned a different public key than the account it
    /// was registered for. Typed so clients can treat this as a hard account
    /// mismatch rather than a retryable runtime error.
    #[error("external signer public key does not match account")]
    ExternalSignerMismatch,
    /// The user rejected/cancelled an external signer prompt. Typed separately
    /// from runtime failures so clients can keep the user in the flow or offer a
    /// retry without treating the account as broken.
    #[error("external signer request was rejected or cancelled")]
    ExternalSignerRejected,
    /// The group's outbound retention queue is full
    /// (`MAX_QUEUED_OUTBOUND_INTENTS_PER_GROUP`), so this message was **not**
    /// accepted and nothing was queued for it. The app layer has already
    /// retracted the optimistic local row; this variant is typed rather than
    /// the untyped [`MarmotKitError::Runtime`] bucket so the host can say the
    /// group is stuck instead of reporting an opaque failure. Unlike
    /// [`MarmotKitError::StorageBusy`] it is not worth an automatic retry:
    /// whatever the group is waiting on — a stalled publication, unsettled
    /// convergence input, or an inactive transport — clears on its own schedule,
    /// not on a timer this call could pick. Prompt the user to resend once the
    /// group is sending again.
    #[error("group {group_id_hex} has too many messages waiting to be sent")]
    GroupSendQueueFull { group_id_hex: String },
    /// The group is halted and cannot send until another member re-admits this
    /// device with a replacement Welcome. Messages accepted before the halt are
    /// still held and publish once the repair lands; only this new send was
    /// refused. Typed rather than the untyped [`MarmotKitError::Runtime`] bucket
    /// so the host can tell the user the conversation needs re-joining instead of
    /// surfacing opaque error text (mdk#1177). Not worth an automatic retry: the
    /// repair arrives on a remote member's schedule.
    #[error("group {group_id_hex} is unrecoverable and needs to be re-joined before sending")]
    GroupUnrecoverableRepairRequired { group_id_hex: String },
    #[error("invalid sticker data: {details}")]
    InvalidSticker { details: String },
    #[error("sticker pack or asset is unavailable")]
    StickerNotFound,
    #[error("sticker network operation failed: {details}")]
    StickerNetwork { details: String },
    #[error("sticker import failed: {details}")]
    StickerImport { details: String },
    #[error("Signal sticker import is unavailable for external-signing accounts")]
    StickerImportUnsupported,
    /// An emoji set, its address or an entry is malformed, or no emoji in it
    /// could be installed.
    #[error("invalid emoji set: {details}")]
    InvalidEmojiSet { details: String },
    #[error("emoji set or emoji is unavailable")]
    EmojiSetNotFound,
    /// Relays or an image host could not be reached.
    #[error("emoji set network operation failed: {details}")]
    EmojiSetNetwork { details: String },
    /// Over 4 MiB, 4096 px per side, or 200 animation frames.
    #[error("emoji image is too large: {details}")]
    EmojiImageTooLarge { details: String },
    /// Not PNG/APNG, GIF, WebP or JPEG, malformed, or its stated MIME type
    /// does not match its bytes.
    #[error("emoji image is unsupported: {details}")]
    EmojiImageUnsupported { details: String },
    /// Installed-set or stored-byte cap reached.
    #[error("emoji set limit reached: {details}")]
    EmojiSetLimit { details: String },
    // Plain comments here: this enum's UniFFI metadata, docstrings
    // included, is near the 16 KiB buffer limit. The stored set version is
    // not the one the user was shown; nothing was downloaded. Show the set
    // again (`emoji_set`) and retry with `current_event_id_hex`.
    #[error("emoji set changed; current version {current_event_id_hex}")]
    EmojiSetChanged { current_event_id_hex: String },
    // Cancelled through its control, or by runtime shutdown or close.
    // Nothing was stored.
    #[error("emoji set install was cancelled")]
    EmojiSetInstallCancelled,
    /// This device was unlinked from the account by its other devices. The
    /// account stays signed out here: wipe it, then link the device again
    /// (mdk#2628 D67).
    #[error("this device was unlinked from the account: {account_ref}")]
    AccountUnlinked { account_ref: String },
    /// Recovery waits for the coordinator's source group to settle.
    #[error("group recovery requires a settled source")]
    GroupRecoveryUnsettled { group_id_hex: String },
    /// Recovery must restart its authenticated challenge, not retry the grant.
    #[error("group recovery requires a fresh challenge")]
    GroupRecoverySourceMismatch { group_id_hex: String },
    #[error("marmot runtime error: {details}")]
    Runtime { details: String },
    /// The account worker is completing an exclusive catch-up and definitely
    /// did not start this operation. Safe to retry after the worker becomes
    /// available.
    #[error("marmot account worker is busy catching up; operation was not started")]
    AccountWorkerBusy,
    /// The worker response exceeded its operation-class deadline. The command
    /// may have completed, so refresh authoritative state before retrying.
    #[error("marmot account worker response timed out; operation completion is unknown")]
    AccountWorkerResponseTimedOut,
    #[error("chat window requests require 1 to 100 rows")]
    ChatWindowInvalidLimit,
    #[error("chat window changed; use the latest sequence")]
    ChatWindowStale,
    #[error("visible anchor must belong to the retained window")]
    ChatWindowAnchorOutside,
    #[error("chat window is closed; reopen it")]
    ChatWindowClosed,
    #[error("chat window query failed: {details}")]
    ChatWindowQuery { details: String },
    /// A chat-list query broke a size bound, its node list was not one tree,
    /// or a window was opened with a `MessageText` node. Nothing was read; fix
    /// the query rather than retrying it.
    #[error("invalid chat-list query: {reason}")]
    InvalidChatListQuery {
        reason: crate::conversions::ChatListQueryErrorFfi,
    },
    #[error("conversation window requests require 1 to 200 rows")]
    ConversationWindowInvalidLimit,
    #[error("selected draft changed; refresh before retrying")]
    MessageDraftRevisionConflict,
    #[error("conversation changed; refresh the sequence before retrying")]
    ConversationWindowStale,
    #[error("revision belongs to another conversation window generation")]
    ConversationWindowWrongGeneration,
    #[error("visible anchor must belong to the retained conversation window")]
    ConversationWindowAnchorOutside,
    #[error("conversation window closed; reopen it")]
    ConversationWindowClosed,
    #[error("conversation capture temporarily unavailable; retry pending")]
    ConversationWindowNotReady,
    #[error("conversation operation timed out; accepted commands may still complete")]
    ConversationWindowTimedOut,
    #[error("conversation opening mode and message target disagree")]
    ConversationWindowInvalidTarget,
    #[error("conversation query failed: {details}")]
    ConversationWindowQuery { details: String },
    #[error("conversation presentation failed: {details}")]
    ConversationWindowPresentation { details: String },
    /// An explicit target disappeared; an already-open window remains usable.
    #[error("conversation target message is no longer retained")]
    ConversationWindowMessageNotRetained,
    #[error("invalid app component: {details}")]
    InvalidAppComponent { details: String },
}

impl From<AppError> for MarmotKitError {
    fn from(value: AppError) -> Self {
        Self::from(&value)
    }
}

/// Directory failures map through the `AppError` they convert to, so
/// bindings see the same error cases either way.
impl From<marmot_app::DirectoryError> for MarmotKitError {
    fn from(value: marmot_app::DirectoryError) -> Self {
        Self::from(AppError::from(value))
    }
}

impl From<&AppError> for MarmotKitError {
    fn from(value: &AppError) -> Self {
        if let Some(cause) = value.as_oversized_event() {
            return Self::EventTooLarge {
                artifact: cause.artifact.into(),
                size_class: cause.size_class.into(),
            };
        }
        if let Some(err) = value.as_engine_error() {
            return Self::from_engine_error(err);
        }
        match value {
            AppError::InvalidAppComponent(details) => Self::InvalidAppComponent {
                details: details.clone(),
            },
            AppError::UserBlocked => Self::UserBlocked,
            AppError::BlockListUnavailable => Self::BlockListUnavailable,
            AppError::BlockPublicationUncertain => Self::BlockPublicationUncertain,
            AppError::ModerationReportingNotConfigured => Self::ModerationReportingNotConfigured,
            AppError::InvalidModerationReportConfig(details) => {
                Self::InvalidModerationReportConfig {
                    details: details.clone(),
                }
            }
            AppError::InvalidReportedPublicKey => Self::InvalidReportedPublicKey,
            AppError::CannotReportSelf => Self::CannotReportSelf,
            AppError::ModerationReportRateLimited => Self::ModerationReportRateLimited,
            AppError::InvalidEditTarget => Self::InvalidEditTarget,
            AppError::ProductAnalytics(marmot_app::ProductAnalyticsError::ConsentRequired) => {
                Self::ConsentRequired
            }
            AppError::ProductAnalytics(marmot_app::ProductAnalyticsError::InvalidConfiguration) => {
                Self::InvalidProductAnalyticsConfiguration
            }
            AppError::ProductAnalytics(marmot_app::ProductAnalyticsError::InvalidEvent) => {
                Self::InvalidProductObservation
            }
            AppError::AccountHome(AccountHomeError::UnknownAccount(account_ref)) => {
                Self::UnknownAccount {
                    account_ref: account_ref.clone(),
                }
            }
            AppError::AccountHome(AccountHomeError::AccountExists(account)) => {
                Self::DuplicateIdentity {
                    account: account.clone(),
                }
            }
            AppError::AccountHome(AccountHomeError::AccountUnlinked(account_ref)) => {
                Self::AccountUnlinked {
                    account_ref: account_ref.clone(),
                }
            }
            // Beside `experimental_device_groups_unavailable`: the same
            // test-build constructor contract, so the same shape.
            AppError::ExperimentalDeviceGroupsRequired => Self::Runtime {
                details: "experimental_device_groups_required".to_owned(),
            },
            // #543: reveal_nsec must surface its required failure modes as typed
            // FFI errors, not the untyped `Runtime` bucket, so a key-backup
            // surface can distinguish "no exportable key" / "keystore locked" /
            // "disk IO" without string-parsing.
            //
            // No raw key is loaded for this account (public-only / watch-only,
            // or the secret was never imported).
            AppError::AccountHome(err @ AccountHomeError::SecretNotFound(_)) => {
                Self::SecretNotFound {
                    details: err.to_string(),
                }
            }
            // The platform keystore is locked / uninitialized / unavailable.
            AppError::AccountHome(
                err @ (AccountHomeError::SecretStoreNotInitialized(_)
                | AccountHomeError::SecretStoreUnavailable(_)
                | AccountHomeError::SecretStore(_)),
            ) => Self::KeystoreUnavailable {
                details: err.to_string(),
            },
            AppError::AccountHome(AccountHomeError::EmptyPassphrase) => Self::EmptyPassphrase,
            AppError::AccountHome(AccountHomeError::EncryptedSecretExport(details)) => {
                Self::EncryptionFailed {
                    details: details.clone(),
                }
            }
            // A filesystem IO error reading the key, appending the reveal audit
            // entry, or persisting the key-security byte — surfaced either
            // directly at the app layer or wrapped in an AccountHomeError.
            AppError::Io(err) => Self::Io {
                details: err.to_string(),
            },
            AppError::AccountHome(err @ AccountHomeError::Io(_)) => Self::Io {
                details: err.to_string(),
            },
            AppError::UnknownGroup(group_id_hex) => Self::UnknownGroup {
                group_id_hex: group_id_hex.clone(),
            },
            AppError::GroupInviteNotPending => Self::GroupInviteNotPending,
            AppError::CreatedGroupProjectionUnavailable(group_id_hex) => {
                Self::CreatedGroupProjectionUnavailable {
                    group_id_hex: group_id_hex.clone(),
                }
            }
            AppError::InvalidGroupMembershipPage(_) => Self::InvalidGroupMembershipPage {
                max_groups: marmot_app::MAX_GROUP_MEMBER_IDS_PAGE_SIZE as u64,
            },
            AppError::ChatPresentationNotReady => Self::ChatPresentationNotReady,
            AppError::InvalidChatListQuery(error) => Self::InvalidChatListQuery {
                reason: (*error).into(),
            },
            AppError::DirectConversationIndexNotReady => Self::DirectConversationIndexNotReady,
            AppError::InvalidCachedIdentityPage(_) => Self::InvalidCachedIdentityPage {
                max_accounts: marmot_app::MAX_CACHED_IDENTITY_PAGE_SIZE as u64,
            },
            AppError::InvalidPublicEventReferences(_) => Self::InvalidPublicEventReferences {
                max_references: marmot_app::MAX_PUBLIC_EVENT_REFERENCES as u64,
            },
            AppError::InvalidChatPin(details) => Self::InvalidChatPin {
                details: details.clone(),
            },
            AppError::GroupDisbanding(group_id_hex) => Self::GroupDisbanding {
                group_id_hex: group_id_hex.clone(),
            },
            AppError::GroupRemoved(group_id_hex) => Self::GroupRemoved {
                group_id_hex: group_id_hex.clone(),
            },
            AppError::GroupCatchingUp(group_id_hex) => Self::GroupCatchingUp {
                group_id_hex: group_id_hex.clone(),
            },
            AppError::GroupCommitUndelivered(group_id_hex) => Self::GroupCommitUndelivered {
                group_id_hex: group_id_hex.clone(),
            },
            AppError::MessageDraftRevisionConflict => Self::MessageDraftRevisionConflict,
            AppError::InvalidMessageDraft(details) => Self::InvalidMessageDraft {
                details: details.clone(),
            },
            // Encrypted-media validation failures are always media-boundary
            // errors; map them to the typed variant so send/upload/download
            // agree with build/parse even when a call site uses `?`/`From`.
            AppError::InvalidEncryptedMedia(details) => Self::InvalidMediaReference {
                details: details.clone(),
            },
            AppError::MediaReferenceStaleEpoch {
                source_epoch,
                current_epoch,
            } => Self::MediaReferenceStaleEpoch {
                source_epoch: *source_epoch,
                current_epoch: *current_epoch,
            },
            AppError::MediaReferenceEpochUnsettled { source_epoch } => {
                Self::MediaReferenceEpochUnsettled {
                    source_epoch: *source_epoch,
                }
            }
            AppError::MediaAttachmentRejected(rejection) => Self::MediaAttachmentRejected {
                kind: rejection.kind.into(),
                details: rejection.detail.clone(),
            },
            AppError::MediaUnfetchable(details) => Self::MediaUnfetchable {
                details: details.clone(),
            },
            AppError::MediaDownloadFailed(details) => Self::MediaDownloadFailed {
                details: details.clone(),
            },
            AppError::UnsafeMediaFetch(details) => Self::InvalidMediaReference {
                details: details.clone(),
            },
            AppError::Hex(err) => Self::InvalidHex {
                details: err.to_string(),
            },
            AppError::MissingKeyPackage { account, reason } => Self::MissingKeyPackage {
                account: account.clone(),
                reason: (*reason).into(),
            },
            AppError::MissingMemberInboxRoute(account) => Self::MissingMemberInboxRoute {
                account: account.clone(),
            },
            AppError::DirectoryLookupIncomplete(account) => Self::DirectoryLookupIncomplete {
                account: account.clone(),
            },
            AppError::InvalidPublicKey => Self::InvalidIdentity {
                details: "invalid nostr public key".into(),
            },
            AppError::UnexpectedPrivateKey => Self::InvalidIdentity {
                details: "this operation does not accept a private key".into(),
            },
            AppError::IdentityKeyMismatch => Self::InvalidIdentity {
                details: "public identity does not match the imported private key".into(),
            },
            AppError::InvalidKeyPackageEvent(details) => Self::InvalidKeyPackageEvent {
                details: details.clone(),
            },
            AppError::Publish(details) => Self::Publish {
                details: details.clone(),
            },
            AppError::EventTooLarge {
                artifact,
                size_class,
            } => Self::EventTooLarge {
                artifact: (*artifact).into(),
                size_class: (*size_class).into(),
            },
            AppError::FollowListUnavailable => Self::FollowListUnavailable,
            AppError::FollowListTooLarge => Self::FollowListTooLarge,
            AppError::TransportClosed => Self::TransportClosed,
            AppError::RuntimeBusy => Self::RuntimeBusy,
            AppError::AccountSessionBusy => Self::AccountSessionBusy,
            AppError::AccountWorkerBusy => Self::AccountWorkerBusy,
            AppError::AccountWorkerResponseTimedOut => Self::AccountWorkerResponseTimedOut,
            AppError::AccountSetupRecoveryRequired => Self::AccountSetupRecoveryRequired,
            AppError::OnboardingActionUnavailable => Self::OnboardingActionUnavailable,
            AppError::OnboardingRequired => Self::OnboardingRequired,
            AppError::AccountSetupRetryRequired => Self::AccountSetupRetryRequired,
            AppError::AccountSetupResetNotApplicable => Self::AccountSetupResetNotApplicable,
            AppError::AccountSetupKeyPackageRecoveryAvailable => {
                Self::AccountSetupKeyPackageRecoveryAvailable
            }
            AppError::RuntimeStopping => Self::RuntimeStopping,
            AppError::AttachmentModeRequired => Self::AttachmentModeRequired,
            AppError::AttachmentAccountSignedOut => Self::AttachmentAccountSignedOut,
            AppError::AccountCatchUp(details) => Self::AccountCatchUp {
                details: details.to_string(),
            },
            // #484: a transient storage busy error can also surface directly at
            // the app layer (not only wrapped in an EngineError). Classify it
            // as the typed transient variant here too, so Android never sees
            // transient contention as an untyped fatal Runtime error.
            AppError::Storage(storage_err) if storage_err.is_transient() => Self::StorageBusy {
                details: storage_err.to_string(),
            },
            // A store closed for suspension is an orderly end state, not a
            // fault. Give it its own variant so hosts can drop the result
            // silently instead of surfacing an error while backgrounding.
            AppError::Storage(storage_err) if storage_err.is_closed() => Self::StorageClosed {
                details: storage_err.to_string(),
            },
            AppError::Storage(storage_err @ cgka_traits::StorageError::Capacity(_)) => {
                Self::StorageFull {
                    details: storage_err.to_string(),
                }
            }
            AppError::ExternalSignerUnavailable(account) => Self::ExternalSignerUnavailable {
                account: account.clone(),
            },
            AppError::ExternalSignerMismatch => Self::ExternalSignerMismatch,
            AppError::ExternalSignerRejected => Self::ExternalSignerRejected,
            AppError::InvalidSticker(details) => Self::InvalidSticker {
                details: details.clone(),
            },
            AppError::StickerNotFound => Self::StickerNotFound,
            AppError::StickerRelay(details) => Self::StickerNetwork {
                details: details.clone(),
            },
            AppError::StickerImport(details) => Self::StickerImport {
                details: details.clone(),
            },
            AppError::StickerExternalSignerImportUnsupported => Self::StickerImportUnsupported,
            AppError::InvalidEmojiSet(details) => Self::InvalidEmojiSet {
                details: details.clone(),
            },
            AppError::EmojiSetNotFound => Self::EmojiSetNotFound,
            AppError::EmojiSetNetwork(details) => Self::EmojiSetNetwork {
                details: details.clone(),
            },
            AppError::EmojiImageTooLarge(details) => Self::EmojiImageTooLarge {
                details: details.clone(),
            },
            AppError::EmojiImageUnsupported(details) => Self::EmojiImageUnsupported {
                details: details.clone(),
            },
            AppError::EmojiSetLimit(details) => Self::EmojiSetLimit {
                details: details.clone(),
            },
            AppError::EmojiSetChanged {
                current_event_id_hex,
            } => Self::EmojiSetChanged {
                current_event_id_hex: current_event_id_hex.clone(),
            },
            AppError::EmojiSetInstallCancelled => Self::EmojiSetInstallCancelled,
            other => Self::Runtime {
                details: other.to_string(),
            },
        }
    }
}

impl MarmotKitError {
    fn from_engine_error(value: &EngineError) -> Self {
        match value {
            EngineError::GroupRecoveryUnsettled { group_id } => Self::GroupRecoveryUnsettled {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::GroupRecoverySourceMismatch { group_id } => {
                Self::GroupRecoverySourceMismatch {
                    group_id_hex: hex::encode(group_id.as_slice()),
                }
            }
            EngineError::UnknownGroup(group_id) => Self::UnknownGroup {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::GroupNotHydrated(group_id) => Self::GroupHydrationPending {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::NotGroupAdmin { group_id } => Self::NotGroupAdmin {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::AdminCannotSelfRemove { group_id } => Self::AdminCannotSelfRemove {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            // The authoritative already-leaving signal. `Marmot::leave_group`
            // prechecks the pending flag for fast UX, but that check is a
            // check-then-act race, so the engine's verdict must map to the same
            // named error rather than falling through to `Runtime`.
            EngineError::LeaveAlreadyRequested { group_id } => Self::LeaveAlreadyRequested {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::AdminDepletion { group_id } => Self::WouldRemoveLastAdmin {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::DisbandingUnsupportedMembers { group_id, members } => {
                Self::DisbandingUnsupportedMembers {
                    group_id_hex: hex::encode(group_id.as_slice()),
                    member_ids_hex: members
                        .iter()
                        .map(|member| hex::encode(member.as_slice()))
                        .collect(),
                }
            }
            EngineError::DisbandingNotEnabled { group_id } => Self::DisbandingNotEnabled {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            EngineError::AccountDevicesActivationRefused { group_id, reason } => {
                Self::AccountDevicesActivationRefused {
                    group_id_hex: hex::encode(group_id.as_slice()),
                    reason: marmot_app::AppAccountDevicesActivation::from(Some(*reason)).into(),
                }
            }
            EngineError::UnknownMember { group_id, member } => Self::MemberNotInGroup {
                group_id_hex: hex::encode(group_id.as_slice()),
                member_id_hex: hex::encode(member.as_slice()),
            },
            // The send was refused, not deferred: the host must be able to say
            // so, and must not auto-retry a condition that cannot clear until
            // the group resolves.
            EngineError::QueuedOutboundAtCapacity { group_id } => Self::GroupSendQueueFull {
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            // mdk#1177: a halted group needs a re-join, which is something the
            // host can tell the user and act on. Keep it out of `Runtime` so it
            // does not have to be recovered by parsing the reason text.
            EngineError::GroupUnrecoverableRepairRequired { group_id } => {
                Self::GroupUnrecoverableRepairRequired {
                    group_id_hex: hex::encode(group_id.as_slice()),
                }
            }
            // #484: surface transient storage lock contention as a typed,
            // app-distinguishable variant rather than flattening it into the
            // untyped `Runtime` bucket. `StorageError::is_transient()` is the
            // single source of truth for which storage errors are transient.
            EngineError::Storage(storage_err) if storage_err.is_transient() => Self::StorageBusy {
                details: storage_err.to_string(),
            },
            // Engine work racing a close for suspension: an orderly end state,
            // reported as such rather than as a runtime fault.
            EngineError::Storage(storage_err) if storage_err.is_closed() => Self::StorageClosed {
                details: storage_err.to_string(),
            },
            EngineError::Storage(storage_err @ cgka_traits::StorageError::Capacity(_)) => {
                Self::StorageFull {
                    details: storage_err.to_string(),
                }
            }
            other => Self::Runtime {
                details: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn missing_keypackage_reason_preserves_typed_cause_and_stable_label() {
        use super::MissingKeyPackageReasonFfi;
        use marmot_app::MissingKeyPackageReason;
        for (source, expected, label) in [
            (
                MissingKeyPackageReason::NotFound,
                MissingKeyPackageReasonFfi::NotFound,
                "not_found",
            ),
            (
                MissingKeyPackageReason::ObsoleteOnly,
                MissingKeyPackageReasonFfi::ObsoleteOnly,
                "obsolete_only",
            ),
        ] {
            let converted = MarmotKitError::from(AppError::MissingKeyPackage {
                account: "recipient-account".into(),
                reason: source,
            });
            let MarmotKitError::MissingKeyPackage { account, reason } = converted else {
                panic!("missing KeyPackage lost its typed error");
            };
            assert_eq!(account, "recipient-account");
            assert_eq!(reason, expected, "typed KeyPackage reason");
            assert_eq!(reason.to_string(), label, "stable KeyPackage reason label");
        }
    }

    use super::MarmotKitError;
    use cgka_traits::error::EngineError;
    use cgka_traits::storage::StorageError;
    use marmot_account::AccountHomeError;
    use marmot_app::{AccountError, AppError};

    #[test]
    fn block_and_follow_refusals_keep_distinct_host_choices() {
        type Expected = fn(&MarmotKitError) -> bool;
        let cases: [(AppError, Expected); 4] = [
            (AppError::UserBlocked, |e| {
                matches!(e, MarmotKitError::UserBlocked)
            }),
            (AppError::BlockListUnavailable, |e| {
                matches!(e, MarmotKitError::BlockListUnavailable)
            }),
            (AppError::BlockPublicationUncertain, |e| {
                matches!(e, MarmotKitError::BlockPublicationUncertain)
            }),
            (AppError::FollowListTooLarge, |e| {
                matches!(e, MarmotKitError::FollowListTooLarge)
            }),
        ];
        for (native, expected) in cases {
            let ffi = MarmotKitError::from(native);
            assert!(
                expected(&ffi),
                "block/follow refusal lost its host choice: {ffi:?}"
            );
        }
    }

    #[test]
    fn account_and_runtime_refusals_keep_distinct_host_actions() {
        type Expected = fn(&MarmotKitError) -> bool;
        let cases: [(AppError, Expected); 8] = [
            (
                AppError::AccountHome(AccountHomeError::AccountUnlinked("alice".into())),
                |e| matches!(e, MarmotKitError::AccountUnlinked { .. }),
            ),
            (
                AppError::ExternalSignerUnavailable(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
                ),
                |e| matches!(e, MarmotKitError::ExternalSignerUnavailable { .. }),
            ),
            (AppError::ExternalSignerMismatch, |e| {
                matches!(e, MarmotKitError::ExternalSignerMismatch)
            }),
            (AppError::OnboardingActionUnavailable, |e| {
                matches!(e, MarmotKitError::OnboardingActionUnavailable)
            }),
            (AppError::OnboardingRequired, |e| {
                matches!(e, MarmotKitError::OnboardingRequired)
            }),
            (AppError::TransportClosed, |e| {
                matches!(e, MarmotKitError::TransportClosed)
            }),
            (AppError::ChatPresentationNotReady, |e| {
                matches!(e, MarmotKitError::ChatPresentationNotReady)
            }),
            (
                AppError::ProductAnalytics(marmot_app::ProductAnalyticsError::InvalidConfiguration),
                |e| matches!(e, MarmotKitError::InvalidProductAnalyticsConfiguration),
            ),
        ];
        for (native, expected) in cases {
            let ffi = MarmotKitError::from(native);
            assert!(
                expected(&ffi),
                "account/runtime refusal lost its host action: {ffi:?}"
            );
        }
    }

    #[test]
    fn native_identity_and_hex_refusals_remain_typed() {
        // These native AppError arms are distinct from the FFI reference
        // parser's direct InvalidIdentity construction. Wording remains Display.
        for native in [
            AppError::InvalidPublicKey,
            AppError::UnexpectedPrivateKey,
            AppError::IdentityKeyMismatch,
        ] {
            assert!(
                matches!(
                    MarmotKitError::from(native),
                    MarmotKitError::InvalidIdentity { .. }
                ),
                "native identity refusal lost its typed host category"
            );
        }
        // dismiss_history_notice forwards the real native notice-id parser's
        // Hex failure; this is separate from the FFI group's direct parser.
        let malformed = hex::decode("not-hex").unwrap_err();
        assert!(matches!(
            MarmotKitError::from(AppError::Hex(malformed)),
            MarmotKitError::InvalidHex { .. }
        ));
    }

    #[test]
    fn media_and_publication_refusals_keep_distinct_host_choices() {
        type Expected = fn(&MarmotKitError) -> bool;
        let cases: [(AppError, Expected); 3] = [
            (
                AppError::MediaUnfetchable("no usable file media locator".into()),
                |e| matches!(e, MarmotKitError::MediaUnfetchable { .. }),
            ),
            (
                AppError::MediaDownloadFailed("media ciphertext hash mismatch".into()),
                |e| matches!(e, MarmotKitError::MediaDownloadFailed { .. }),
            ),
            (
                AppError::Publish("primary publication failure".into()),
                |e| matches!(e, MarmotKitError::Publish { .. }),
            ),
        ];
        for (native, expected) in cases {
            let ffi = MarmotKitError::from(native);
            assert!(
                expected(&ffi),
                "media/publication refusal lost its host choice: {ffi:?}"
            );
        }
    }

    #[test]
    fn oversized_causes_preserve_the_artifact_and_coarse_size() {
        use super::{EventSizeClassFfi as Size, OversizedArtifactFfi as Artifact};
        use marmot_app::OversizedArtifact as Native;
        // The real early cause classifier is shared with wrapped transport
        // errors. No receipt, relay limit or complete publication is invented.
        for (artifact, expected) in [
            (Native::Commit, Artifact::Commit),
            (Native::Welcome, Artifact::Welcome),
            (Native::ApplicationMessage, Artifact::ApplicationMessage),
            (Native::Other, Artifact::Other),
        ] {
            let native = AppError::EventTooLarge {
                artifact,
                size_class: marmot_app::EventSizeClass::of_bytes(1024),
            };
            let MarmotKitError::EventTooLarge {
                artifact,
                size_class,
            } = MarmotKitError::from(native)
            else {
                panic!("oversized cause lost its typed host category");
            };
            assert_eq!(artifact, expected, "oversized artifact kind");
            assert_eq!(size_class, Size::Under64Kib);
        }
    }

    #[test]
    fn remaining_size_classes_preserve_their_host_bucket() {
        use super::EventSizeClassFfi as Size;
        // The supported lower Rust factory supplies valid enum inputs. This
        // does not assert every bounded App publisher emits every bucket.
        // Under64Kib is owned above; From2To4Mib by Welcome diagnosis.
        for (bytes, expected) in [
            (64 * 1024, Size::From64To128Kib),
            (128 * 1024, Size::From128To256Kib),
            (256 * 1024, Size::From256To512Kib),
            (512 * 1024, Size::From512KibTo1Mib),
            (1024 * 1024, Size::From1To2Mib),
            (4 * 1024 * 1024 + 1, Size::Over4Mib),
        ] {
            let native = marmot_app::EventSizeClass::of_bytes(bytes);
            assert_eq!(Size::from(native), expected, "coarse host size bucket");
        }
    }

    #[test]
    fn attachment_configuration_and_account_errors_stay_typed() {
        assert!(matches!(
            MarmotKitError::from(AppError::AttachmentModeRequired),
            MarmotKitError::AttachmentModeRequired
        ));
        assert!(matches!(
            MarmotKitError::from(AppError::AttachmentAccountSignedOut),
            MarmotKitError::AttachmentAccountSignedOut
        ));
    }

    #[test]
    fn moderation_report_errors_stay_typed() {
        assert!(matches!(
            MarmotKitError::from(AppError::ModerationReportingNotConfigured),
            MarmotKitError::ModerationReportingNotConfigured
        ));
        assert!(matches!(
            MarmotKitError::from(AppError::InvalidModerationReportConfig("relay 0 is unsafe".into())),
            MarmotKitError::InvalidModerationReportConfig { details } if details == "relay 0 is unsafe"
        ));
        assert!(matches!(
            MarmotKitError::from(AppError::InvalidReportedPublicKey),
            MarmotKitError::InvalidReportedPublicKey
        ));
        assert!(matches!(
            MarmotKitError::from(AppError::CannotReportSelf),
            MarmotKitError::CannotReportSelf
        ));
        assert!(matches!(
            MarmotKitError::from(AppError::ModerationReportRateLimited),
            MarmotKitError::ModerationReportRateLimited
        ));
        assert!(matches!(
            MarmotKitError::from(AppError::InvalidEditTarget),
            MarmotKitError::InvalidEditTarget
        ));
    }

    #[test]
    fn stale_group_invite_crosses_ffi_as_typed_variant() {
        let ffi: MarmotKitError = AppError::GroupInviteNotPending.into();
        assert!(matches!(ffi, MarmotKitError::GroupInviteNotPending));
        assert_eq!(ffi.to_string(), "group invite is not pending");
    }

    #[test]
    fn oversized_membership_page_crosses_ffi_as_typed_variant() {
        let ffi: MarmotKitError =
            AppError::InvalidGroupMembershipPage("too many groups".into()).into();
        assert!(matches!(
            ffi,
            MarmotKitError::InvalidGroupMembershipPage { max_groups: 100 }
        ));
    }

    #[test]
    fn oversized_public_event_batch_crosses_ffi_as_typed_variant() {
        let ffi: MarmotKitError =
            AppError::InvalidPublicEventReferences("too many references".into()).into();
        assert!(matches!(
            ffi,
            MarmotKitError::InvalidPublicEventReferences { max_references: 16 }
        ));
    }

    #[test]
    fn oversized_cached_identity_page_crosses_ffi_as_typed_variant() {
        let ffi: MarmotKitError =
            AppError::InvalidCachedIdentityPage("too many accounts".into()).into();
        assert!(matches!(
            ffi,
            MarmotKitError::InvalidCachedIdentityPage { max_accounts: 100 }
        ));
    }

    #[test]
    fn created_group_projection_failure_crosses_ffi_as_typed_variant() {
        let ffi = MarmotKitError::from(AppError::CreatedGroupProjectionUnavailable(
            "010203".to_owned(),
        ));
        assert!(matches!(
            ffi,
            MarmotKitError::CreatedGroupProjectionUnavailable { group_id_hex }
                if group_id_hex == "010203"
        ));
    }

    // #484: a transient SQLITE_BUSY surfaced from a send must cross the UniFFI
    // boundary as the typed `StorageBusy` variant — never the untyped `Runtime`
    // bucket — so Android can distinguish transient contention from a fatal
    // failure without string-parsing "database is locked".
    // An account catch-up failure must cross the UniFFI
    // boundary as the typed `AccountCatchUp` variant — never the untyped
    // `Runtime` bucket, and never `RelayDirectory` (the mislabel that sent an
    // earlier investigation chasing the wrong subsystem).
    #[test]
    fn account_catch_up_crosses_ffi_as_typed_variant() {
        let app_err = AppError::AccountCatchUp(marmot_app::AccountCatchUpFailure::new(
            "runtime catch-up failed: account_session".into(),
            marmot_app::SyncFailureClassification::UNKNOWN,
        ));
        let ffi: MarmotKitError = app_err.into();
        match ffi {
            MarmotKitError::AccountCatchUp { details } => {
                assert!(
                    details.contains("account_session"),
                    "typed AccountCatchUp should carry the worker detail, got: {details}"
                );
            }
            other => panic!("expected AccountCatchUp, got {other:?}"),
        }
    }

    #[test]
    fn runtime_busy_crosses_ffi_as_typed_variant() {
        let ffi: MarmotKitError = AppError::RuntimeBusy.into();
        assert!(
            matches!(ffi, MarmotKitError::RuntimeBusy),
            "exclusive-root contention must remain distinguishable at the host boundary"
        );
    }

    #[test]
    fn account_session_busy_crosses_ffi_as_typed_variant() {
        let ffi: MarmotKitError = AppError::AccountSessionBusy.into();
        assert!(
            matches!(ffi, MarmotKitError::AccountSessionBusy),
            "in-process account-session contention must remain distinguishable at the host boundary"
        );
    }

    #[test]
    fn direct_conversation_index_not_ready_crosses_ffi_as_typed_variant() {
        let ffi: MarmotKitError = AppError::DirectConversationIndexNotReady.into();
        assert!(
            matches!(ffi, MarmotKitError::DirectConversationIndexNotReady),
            "an unfinished peer-index backfill must stay retryable at the host boundary"
        );
    }

    // The `leave_group` precheck on `leave_request_pending` is not atomic with
    // the send it guards, so two concurrent leaves can both pass it. The engine
    // settles the race under its own lock, and the loser's verdict has to reach
    // the host as the same named error the precheck would have produced — never
    // the untyped `Runtime` bucket, which is exactly the opaque failure this
    // field was added to eliminate.
    // Asserted against `from_engine_error` directly rather than through an
    // `AppError`: a leave failure arrives wrapped as
    // `AppError::Session(SessionError::Engine(..))`, and `marmot-session` is not a
    // dependency of this crate. `From<AppError>` funnels every such error through
    // `as_engine_error()` into this same function (see above), so this covers the
    // mapping without pulling in a crate just to construct a wrapper.
    #[test]
    fn leave_already_requested_crosses_ffi_as_typed_variant() {
        let group_id = cgka_traits::GroupId::new(vec![0x11; 16]);
        let ffi = MarmotKitError::from_engine_error(&EngineError::LeaveAlreadyRequested {
            group_id: group_id.clone(),
        });
        match ffi {
            MarmotKitError::LeaveAlreadyRequested { group_id_hex } => {
                assert_eq!(group_id_hex, hex::encode(group_id.as_slice()));
            }
            other => panic!("expected LeaveAlreadyRequested, got {other:?}"),
        }
    }

    #[test]
    fn disbanding_not_enabled_crosses_ffi_as_typed_variant() {
        let group_id = cgka_traits::GroupId::new(vec![0x22; 16]);
        let ffi = MarmotKitError::from_engine_error(&EngineError::DisbandingNotEnabled {
            group_id: group_id.clone(),
        });
        match ffi {
            MarmotKitError::DisbandingNotEnabled { group_id_hex } => {
                assert_eq!(group_id_hex, hex::encode(group_id.as_slice()));
            }
            other => panic!("expected DisbandingNotEnabled, got {other:?}"),
        }
    }

    #[test]
    fn account_devices_activation_refusal_crosses_ffi_with_its_aggregate_reason() {
        use crate::conversions::AccountDevicesActivationFfi;
        use cgka_traits::error::AccountDevicesActivationRefusal as Refusal;
        let group_id = cgka_traits::GroupId::new(vec![0x22; 16]);
        for (reason, expected) in [
            (Refusal::NotAdmin, AccountDevicesActivationFfi::NotAdmin),
            (
                Refusal::AlreadyRequired,
                AccountDevicesActivationFfi::AlreadyEnabled,
            ),
            (
                Refusal::LegacyProfile,
                AccountDevicesActivationFfi::LegacyGroup,
            ),
            (
                Refusal::UnsupportedLeaves,
                AccountDevicesActivationFfi::MembersNeedUpdate,
            ),
            (
                Refusal::LeafCarriesData,
                AccountDevicesActivationFfi::DevicesNeedReplacement,
            ),
            (
                Refusal::LeafLimitExceeded,
                AccountDevicesActivationFfi::DeviceLimitExceeded,
            ),
        ] {
            let ffi =
                MarmotKitError::from_engine_error(&EngineError::AccountDevicesActivationRefused {
                    group_id: group_id.clone(),
                    reason,
                });
            match ffi {
                MarmotKitError::AccountDevicesActivationRefused {
                    group_id_hex,
                    reason,
                } => {
                    assert_eq!(group_id_hex, hex::encode(group_id.as_slice()));
                    assert_eq!(reason, expected);
                }
                other => panic!("expected AccountDevicesActivationRefused, got {other:?}"),
            }
        }
    }

    #[test]
    fn group_access_errors_keep_typed_actions_and_distinct_identity_payloads() {
        type Expected = fn(&MarmotKitError) -> bool;
        let group = cgka_traits::GroupId::new(vec![0x11; 16]);
        let member = cgka_traits::MemberId::new(vec![0x22; 32]);
        let cases: [(EngineError, Expected); 7] = [
            (
                EngineError::UnknownGroup(group.clone()),
                |e| matches!(e, MarmotKitError::UnknownGroup { group_id_hex } if group_id_hex == &"11".repeat(16)),
            ),
            (
                EngineError::GroupNotHydrated(group.clone()),
                |e| matches!(e, MarmotKitError::GroupHydrationPending { group_id_hex } if group_id_hex == &"11".repeat(16)),
            ),
            (
                EngineError::NotGroupAdmin {
                    group_id: group.clone(),
                },
                |e| matches!(e, MarmotKitError::NotGroupAdmin { group_id_hex } if group_id_hex == &"11".repeat(16)),
            ),
            (
                EngineError::AdminCannotSelfRemove {
                    group_id: group.clone(),
                },
                |e| matches!(e, MarmotKitError::AdminCannotSelfRemove { group_id_hex } if group_id_hex == &"11".repeat(16)),
            ),
            (
                EngineError::AdminDepletion {
                    group_id: group.clone(),
                },
                |e| matches!(e, MarmotKitError::WouldRemoveLastAdmin { group_id_hex } if group_id_hex == &"11".repeat(16)),
            ),
            (
                EngineError::UnknownMember {
                    group_id: group.clone(),
                    member: member.clone(),
                },
                |e| matches!(e, MarmotKitError::MemberNotInGroup { group_id_hex, member_id_hex } if group_id_hex == &"11".repeat(16) && member_id_hex == &"22".repeat(32)),
            ),
            (
                EngineError::DisbandingUnsupportedMembers {
                    group_id: group,
                    members: vec![member, cgka_traits::MemberId::new(vec![0x33; 32])],
                },
                |e| matches!(e, MarmotKitError::DisbandingUnsupportedMembers { group_id_hex, member_ids_hex } if group_id_hex == &"11".repeat(16) && member_ids_hex == &vec!["22".repeat(32), "33".repeat(32)]),
            ),
        ];
        for (source, expected) in cases {
            let ffi = MarmotKitError::from_engine_error(&source);
            assert!(expected(&ffi), "{source:?} mapped to {ffi:?}");
        }
    }

    #[test]
    fn app_group_gates_preserve_the_host_recovery_action() {
        type Expected = fn(&MarmotKitError) -> bool;
        let cases: [(AppError, Expected); 4] = [
            (
                AppError::GroupDisbanding("ab".repeat(16)),
                |e| matches!(e, MarmotKitError::GroupDisbanding { group_id_hex } if group_id_hex == &"ab".repeat(16)),
            ),
            (
                AppError::GroupRemoved("ab".repeat(16)),
                |e| matches!(e, MarmotKitError::GroupRemoved { group_id_hex } if group_id_hex == &"ab".repeat(16)),
            ),
            (
                AppError::GroupCatchingUp("ab".repeat(16)),
                |e| matches!(e, MarmotKitError::GroupCatchingUp { group_id_hex } if group_id_hex == &"ab".repeat(16)),
            ),
            (
                AppError::GroupCommitUndelivered("ab".repeat(16)),
                |e| matches!(e, MarmotKitError::GroupCommitUndelivered { group_id_hex } if group_id_hex == &"ab".repeat(16)),
            ),
        ];
        for (source, expected) in cases {
            let ffi = MarmotKitError::from(&source);
            assert!(expected(&ffi), "{source:?} mapped to {ffi:?}");
        }
    }

    #[test]
    fn recovery_error_retry_meaning() {
        let group_id = cgka_traits::GroupId::new(vec![0x33; 16]);
        let expected = hex::encode(group_id.as_slice());
        let unsettled = MarmotKitError::from_engine_error(&EngineError::GroupRecoveryUnsettled {
            group_id: group_id.clone(),
        });
        let changed =
            MarmotKitError::from_engine_error(&EngineError::GroupRecoverySourceMismatch {
                group_id,
            });
        assert!(!unsettled.to_string().contains(&expected));
        assert!(!changed.to_string().contains(&expected));
        assert!(
            matches!(unsettled, MarmotKitError::GroupRecoveryUnsettled { group_id_hex } if group_id_hex == expected)
        );
        assert!(
            matches!(changed, MarmotKitError::GroupRecoverySourceMismatch { group_id_hex } if group_id_hex == expected)
        );
    }

    // A refused send is the one signal the retention feature owes the host: the
    // message was not accepted at all. Flattened into `Runtime` the host cannot
    // tell it from any other failure without string-parsing, and cannot explain
    // to the user why the group stopped accepting messages.
    #[test]
    fn queued_outbound_at_capacity_crosses_ffi_as_typed_variant() {
        let group_id = cgka_traits::GroupId::new(vec![0x33; 16]);
        let ffi = MarmotKitError::from_engine_error(&EngineError::QueuedOutboundAtCapacity {
            group_id: group_id.clone(),
        });
        match ffi {
            MarmotKitError::GroupSendQueueFull { group_id_hex } => {
                assert_eq!(group_id_hex, hex::encode(group_id.as_slice()));
            }
            other => panic!("expected GroupSendQueueFull, got {other:?}"),
        }
    }

    // A wedged group is a durable, host-actionable condition, not an engine bug.
    // Flattened into `Runtime` the host can only string-match the reason text to
    // tell "re-join required" from any other failure (mdk#1177).
    #[test]
    fn group_unrecoverable_repair_required_crosses_ffi_as_typed_variant() {
        let group_id = cgka_traits::GroupId::new(vec![0x44; 16]);
        let ffi =
            MarmotKitError::from_engine_error(&EngineError::GroupUnrecoverableRepairRequired {
                group_id: group_id.clone(),
            });
        match ffi {
            MarmotKitError::GroupUnrecoverableRepairRequired { group_id_hex } => {
                assert_eq!(group_id_hex, hex::encode(group_id.as_slice()));
            }
            other => panic!("expected GroupUnrecoverableRepairRequired, got {other:?}"),
        }
    }

    // The variant it replaced must not regress into the opaque bucket by way of
    // some future refactor reusing `InvalidTransition` for this case.
    #[test]
    fn invalid_transition_remains_the_untyped_engine_bug_signal() {
        let ffi = MarmotKitError::from_engine_error(&EngineError::InvalidTransition(
            cgka_traits::engine_state::InvalidTransition {
                from: "Leaving",
                to: "AppMessage",
                reason: "leave request is current",
            },
        ));
        assert!(
            matches!(ffi, MarmotKitError::Runtime { .. }),
            "InvalidTransition denotes an engine bug and stays untyped; got {ffi:?}"
        );
    }

    /// mdk#3012: an ordinary constructor's refusal of a device-group root
    /// reaches hosts as the code the README documents, beside
    /// `experimental_device_groups_unavailable`.
    #[test]
    fn a_device_group_root_refusal_crosses_ffi_as_its_documented_code() {
        let ffi: MarmotKitError = (&AppError::ExperimentalDeviceGroupsRequired).into();
        assert!(matches!(ffi, MarmotKitError::Runtime { details }
            if details == "experimental_device_groups_required"));
    }

    /// mdk#2158: an attachment whose epoch the group left, or whose group is
    /// mid-epoch-change, crosses the FFI as its own typed error with both
    /// epochs, not as a generic invalid reference a host can only string-match.
    #[test]
    fn media_epoch_failures_cross_ffi_as_typed_variants() {
        let stale: MarmotKitError = AppError::MediaReferenceStaleEpoch {
            source_epoch: 2,
            current_epoch: 3,
        }
        .into();
        assert!(
            matches!(
                stale,
                MarmotKitError::MediaReferenceStaleEpoch {
                    source_epoch: 2,
                    current_epoch: 3
                }
            ),
            "{stale:?}"
        );
        let unsettled: MarmotKitError =
            AppError::MediaReferenceEpochUnsettled { source_epoch: 4 }.into();
        assert!(
            matches!(
                unsettled,
                MarmotKitError::MediaReferenceEpochUnsettled { source_epoch: 4 }
            ),
            "{unsettled:?}"
        );
    }

    #[test]
    fn unsafe_media_fetch_crosses_ffi_as_typed_media_reference() {
        let app_err = AppError::UnsafeMediaFetch("unsafe profile image URL".into());
        let ffi: MarmotKitError = app_err.into();
        assert!(matches!(ffi, MarmotKitError::InvalidMediaReference { .. }));
    }

    #[test]
    fn invalid_encrypted_media_crosses_ffi_as_typed_media_reference() {
        let app_err =
            AppError::InvalidEncryptedMedia("group requires encrypted-media-v2 references".into());
        let ffi: MarmotKitError = app_err.into();
        match ffi {
            MarmotKitError::InvalidMediaReference { details } => {
                assert!(
                    details.contains("encrypted-media-v2"),
                    "typed InvalidMediaReference should carry the media detail, got: {details}"
                );
            }
            other => panic!("expected InvalidMediaReference, got {other:?}"),
        }
    }

    #[test]
    fn storage_busy_crosses_ffi_as_typed_variant_via_engine() {
        // Send path: storage Busy wrapped in EngineError, wrapped in AppError
        // through the account/engine error chain (the real `do_send` shape).
        let app_err = AppError::Account(AccountError::Engine(EngineError::Storage(
            StorageError::Busy("database is locked".to_string()),
        )));
        let ffi: MarmotKitError = app_err.into();
        match ffi {
            MarmotKitError::StorageBusy { details } => {
                assert!(
                    details.contains("busy"),
                    "typed StorageBusy should carry the storage detail, got: {details}"
                );
            }
            other => panic!("expected StorageBusy, got {other:?}"),
        }
    }

    #[test]
    fn storage_busy_crosses_ffi_as_typed_variant_directly() {
        // A transient storage Busy can also surface directly at the app layer
        // (AppError::Storage) without an EngineError wrapper.
        let app_err = AppError::Storage(StorageError::Busy("database is locked".to_string()));
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(ffi, MarmotKitError::StorageBusy { .. }),
            "direct AppError::Storage(Busy) must map to StorageBusy, got {ffi:?}"
        );
    }

    #[test]
    fn a_full_disk_crosses_ffi_as_storage_full() {
        let app_err = AppError::Storage(StorageError::Capacity("no room".to_string()));
        assert!(matches!(
            MarmotKitError::from(app_err),
            MarmotKitError::StorageFull { .. }
        ));
        let engine_err = AppError::Account(AccountError::Engine(EngineError::Storage(
            StorageError::Capacity("no room".to_string()),
        )));
        assert!(matches!(
            MarmotKitError::from(engine_err),
            MarmotKitError::StorageFull { .. }
        ));
    }

    #[test]
    fn non_transient_storage_error_stays_runtime() {
        // A durable backend fault must NOT be misclassified as transient.
        let app_err = AppError::Storage(StorageError::Backend("disk full".to_string()));
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(ffi, MarmotKitError::Runtime { .. }),
            "non-transient storage faults must stay Runtime, got {ffi:?}"
        );

        let engine_app_err = AppError::Account(AccountError::Engine(EngineError::Storage(
            StorageError::NotFound,
        )));
        let engine_ffi: MarmotKitError = engine_app_err.into();
        assert!(
            matches!(engine_ffi, MarmotKitError::Runtime { .. }),
            "non-transient engine storage faults must stay Runtime, got {engine_ffi:?}"
        );
    }

    // #543: reveal_nsec must surface its required failure modes (no exportable
    // key / keystore locked-or-unavailable / disk IO) as typed FFI variants so
    // a key-backup surface can react without string-parsing a generic Runtime
    // error.
    #[test]
    fn reveal_secret_not_found_crosses_ffi_as_typed_variant() {
        let app_err = AppError::AccountHome(AccountHomeError::SecretNotFound(
            "no secret stored for account".to_string(),
        ));
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(ffi, MarmotKitError::SecretNotFound { .. }),
            "public-only / missing secret must map to SecretNotFound, got {ffi:?}"
        );
    }

    #[test]
    fn reveal_keystore_unavailable_crosses_ffi_as_typed_variant() {
        for app_err in [
            AppError::AccountHome(AccountHomeError::SecretStoreNotInitialized(
                "keychain not initialized".to_string(),
            )),
            AppError::AccountHome(AccountHomeError::SecretStoreUnavailable(
                "keychain locked".to_string(),
            )),
            AppError::AccountHome(AccountHomeError::SecretStore(
                "keychain query failed".to_string(),
            )),
        ] {
            let ffi: MarmotKitError = app_err.into();
            assert!(
                matches!(ffi, MarmotKitError::KeystoreUnavailable { .. }),
                "locked / unavailable keystore must map to KeystoreUnavailable, got {ffi:?}"
            );
        }
    }

    #[test]
    fn reveal_io_error_crosses_ffi_as_typed_variant() {
        // A direct app-layer IO error (e.g. appending the reveal audit line).
        let direct: MarmotKitError = AppError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "audit append failed",
        ))
        .into();
        assert!(
            matches!(direct, MarmotKitError::Io { .. }),
            "direct app-layer IO failure must map to Io, got {direct:?}"
        );

        // An IO error wrapped in AccountHomeError (e.g. persisting the
        // key-security byte or reading the keystore file).
        let wrapped: MarmotKitError = AppError::AccountHome(AccountHomeError::Io(
            std::io::Error::other("key-security write failed"),
        ))
        .into();
        assert!(
            matches!(wrapped, MarmotKitError::Io { .. }),
            "AccountHome IO failure must map to Io, got {wrapped:?}"
        );
    }

    /// Each sticker failure crosses the FFI as its own variant; none may
    /// fall through to the generic `Runtime` arm.
    #[test]
    fn sticker_errors_map_to_their_typed_variants() {
        type Expected = fn(&MarmotKitError) -> bool;
        let cases: Vec<(AppError, Expected)> = vec![
            (
                AppError::InvalidSticker("bad hash".into()),
                |e| matches!(e, MarmotKitError::InvalidSticker { details } if details == "bad hash"),
            ),
            (AppError::StickerNotFound, |e| {
                matches!(e, MarmotKitError::StickerNotFound)
            }),
            (
                AppError::StickerRelay("offline".into()),
                |e| matches!(e, MarmotKitError::StickerNetwork { details } if details == "offline"),
            ),
            (
                AppError::StickerImport("refused".into()),
                |e| matches!(e, MarmotKitError::StickerImport { details } if details == "refused"),
            ),
            (AppError::StickerExternalSignerImportUnsupported, |e| {
                matches!(e, MarmotKitError::StickerImportUnsupported)
            }),
        ];
        for (app_err, expected) in cases {
            let label = format!("{app_err:?}");
            let ffi = MarmotKitError::from(app_err);
            assert!(expected(&ffi), "{label} mapped to {ffi:?}");
        }
    }

    /// Each emoji set failure crosses the FFI as its own variant so hosts
    /// can tell bad sets, image limits, network failures and caps apart.
    #[test]
    fn emoji_set_errors_map_to_their_typed_variants() {
        type Expected = fn(&MarmotKitError) -> bool;
        let cases: Vec<(AppError, Expected)> = vec![
            (
                AppError::InvalidEmojiSet("no emoji".into()),
                |e| matches!(e, MarmotKitError::InvalidEmojiSet { details } if details == "no emoji"),
            ),
            (AppError::EmojiSetNotFound, |e| {
                matches!(e, MarmotKitError::EmojiSetNotFound)
            }),
            (
                AppError::EmojiSetNetwork("offline".into()),
                |e| matches!(e, MarmotKitError::EmojiSetNetwork { details } if details == "offline"),
            ),
            (
                AppError::EmojiImageTooLarge("4 MiB".into()),
                |e| matches!(e, MarmotKitError::EmojiImageTooLarge { details } if details == "4 MiB"),
            ),
            (
                AppError::EmojiImageUnsupported("tiff".into()),
                |e| matches!(e, MarmotKitError::EmojiImageUnsupported { details } if details == "tiff"),
            ),
            (
                AppError::EmojiSetLimit("50 sets".into()),
                |e| matches!(e, MarmotKitError::EmojiSetLimit { details } if details == "50 sets"),
            ),
            (
                AppError::EmojiSetChanged {
                    current_event_id_hex: "ab".into(),
                },
                |e| matches!(e, MarmotKitError::EmojiSetChanged { current_event_id_hex } if current_event_id_hex == "ab"),
            ),
            (AppError::EmojiSetInstallCancelled, |e| {
                matches!(e, MarmotKitError::EmojiSetInstallCancelled)
            }),
        ];
        for (app_err, expected) in cases {
            let label = format!("{app_err:?}");
            let ffi = MarmotKitError::from(app_err);
            assert!(expected(&ffi), "{label} mapped to {ffi:?}");
        }
    }

    #[test]
    fn invalid_key_package_event_maps_to_typed_variant() {
        let app_err = AppError::InvalidKeyPackageEvent("unsupported cipher suite".to_string());
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(
                ffi,
                MarmotKitError::InvalidKeyPackageEvent { ref details }
                    if details == "unsupported cipher suite"
            ),
            "invalid KeyPackage events must not be flattened into InvalidIdentity, got {ffi:?}"
        );
    }

    #[test]
    fn directory_lookup_incomplete_crosses_ffi_with_account() {
        let account = "33".repeat(32);
        let ffi: MarmotKitError = AppError::DirectoryLookupIncomplete(account.clone()).into();
        assert!(!ffi.to_string().contains(&account));
        assert!(matches!(
            ffi,
            MarmotKitError::DirectoryLookupIncomplete { account: recipient }
                if recipient == account
        ));
    }

    #[test]
    /// The typed FFI error preserves the recipient needed for client recovery UI.
    fn missing_member_inbox_route_crosses_ffi_with_recipient() {
        let account = "11".repeat(32);
        let ffi: MarmotKitError = AppError::MissingMemberInboxRoute(account.clone()).into();
        assert!(matches!(
            ffi,
            MarmotKitError::MissingMemberInboxRoute { account: recipient }
                if recipient == account
        ));
    }

    #[test]
    fn incomplete_account_setup_crosses_ffi_as_typed_recovery() {
        let ffi: MarmotKitError = AppError::AccountSetupRecoveryRequired.into();
        assert!(matches!(ffi, MarmotKitError::AccountSetupRecoveryRequired));
    }

    #[test]
    fn account_setup_reset_refusals_cross_ffi_as_typed_variants() {
        assert!(matches!(
            MarmotKitError::from(AppError::AccountSetupRetryRequired),
            MarmotKitError::AccountSetupRetryRequired
        ));
        assert!(matches!(
            MarmotKitError::from(AppError::AccountSetupResetNotApplicable),
            MarmotKitError::AccountSetupResetNotApplicable
        ));
        assert!(matches!(
            MarmotKitError::from(AppError::AccountSetupKeyPackageRecoveryAvailable),
            MarmotKitError::AccountSetupKeyPackageRecoveryAvailable
        ));
    }

    #[test]
    fn account_worker_availability_crosses_ffi_without_losing_retry_semantics() {
        assert!(matches!(
            MarmotKitError::from(AppError::AccountWorkerBusy),
            MarmotKitError::AccountWorkerBusy
        ));
        assert!(matches!(
            MarmotKitError::from(AppError::AccountWorkerResponseTimedOut),
            MarmotKitError::AccountWorkerResponseTimedOut
        ));
    }

    #[test]
    fn encrypted_export_empty_passphrase_crosses_ffi_as_typed_variant() {
        let app_err = AppError::AccountHome(AccountHomeError::EmptyPassphrase);
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(ffi, MarmotKitError::EmptyPassphrase),
            "empty passphrase must map to EmptyPassphrase, got {ffi:?}"
        );
    }

    #[test]
    fn encrypted_export_failure_crosses_ffi_as_typed_variant() {
        let app_err = AppError::AccountHome(AccountHomeError::EncryptedSecretExport(
            "scrypt params rejected".to_string(),
        ));
        let ffi: MarmotKitError = app_err.into();
        assert!(
            matches!(
                ffi,
                MarmotKitError::EncryptionFailed { ref details }
                    if details == "scrypt params rejected"
            ),
            "NIP-49 encryption failures must map to EncryptionFailed without duplicating the AccountHomeError prefix, got {ffi:?}"
        );
    }

    /// MarmotKit's column of `marmot-app`'s lower-stack error table: the
    /// variant follows what the error is, however the lower stack wrapped it.
    #[test]
    fn lower_stack_errors_cross_ffi_by_kind_not_by_wrapping() {
        let mismatches: Vec<String> = marmot_app::error_kind_table::lower_stack_rows()
            .into_iter()
            .filter_map(|row| {
                let ffi = MarmotKitError::from(&row.error);
                let variant = variant_name(&ffi);
                (variant != row.expected.marmotkit).then(|| {
                    format!(
                        "{}: {variant}, expected {}",
                        row.name, row.expected.marmotkit
                    )
                })
            })
            .collect();
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    fn variant_name(error: &MarmotKitError) -> String {
        format!("{error:?}")
            .split([' ', '{', '('])
            .next()
            .unwrap_or_default()
            .to_owned()
    }
}

impl From<marmot_app::ChatListQueryError> for MarmotKitError {
    fn from(v: marmot_app::ChatListQueryError) -> Self {
        Self::InvalidChatListQuery { reason: v.into() }
    }
}

impl From<marmot_app::ChatListWindowError> for MarmotKitError {
    fn from(v: marmot_app::ChatListWindowError) -> Self {
        use marmot_app::ChatListWindowError as E;
        match v {
            E::InvalidLimit => Self::ChatWindowInvalidLimit,
            E::StaleWindow => Self::ChatWindowStale,
            E::AnchorOutsideWindow => Self::ChatWindowAnchorOutside,
            E::Closed => Self::ChatWindowClosed,
            E::App(e) => Self::from(e.as_ref()),
            E::Query(e) => Self::ChatWindowQuery {
                details: e.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod screen_error_tests {
    use super::*;
    #[test]
    fn conversation_errors_preserve_retry_revision_and_close_classification() {
        use marmot_app::ConversationWindowError as W;
        use std::sync::Arc;
        assert!(matches!(
            MarmotKitError::from(W::Query(Arc::new(
                marmot_app::ConversationOpenError::MessageNotFound
            ))),
            MarmotKitError::ConversationWindowMessageNotRetained
        ));
        for error in [
            marmot_app::ConversationOpenError::InvalidLimit,
            marmot_app::ConversationOpenError::InvalidAnchorPosition,
            marmot_app::ConversationOpenError::AnchorScopeMismatch,
        ] {
            assert!(matches!(
                MarmotKitError::from(W::Query(Arc::new(error))),
                MarmotKitError::ConversationWindowQuery { .. }
            ));
        }
        assert!(matches!(
            MarmotKitError::from(W::InvalidLimit),
            MarmotKitError::ConversationWindowInvalidLimit
        ));
        assert!(matches!(
            MarmotKitError::from(W::StaleWindow),
            MarmotKitError::ConversationWindowStale
        ));
        assert!(matches!(
            MarmotKitError::from(W::AnchorOutsideWindow),
            MarmotKitError::ConversationWindowAnchorOutside
        ));
        assert!(matches!(
            MarmotKitError::from(W::NotReady),
            MarmotKitError::ConversationWindowNotReady
        ));
        assert!(matches!(
            MarmotKitError::from(W::Closed),
            MarmotKitError::ConversationWindowClosed
        ));
        assert!(matches!(
            MarmotKitError::from(W::App(Arc::new(AppError::Storage(
                cgka_traits::storage::StorageError::Busy("busy".into())
            )))),
            MarmotKitError::StorageBusy { .. }
        ));
        assert!(matches!(
            MarmotKitError::from(W::App(Arc::new(AppError::RuntimeStopping))),
            MarmotKitError::RuntimeStopping
        ));
        assert!(matches!(
            MarmotKitError::from(W::App(Arc::new(AppError::MessageDraftRevisionConflict))),
            MarmotKitError::MessageDraftRevisionConflict
        ));
    }
    #[test]
    fn shared_screen_errors_preserve_retry_and_close_classification() {
        use marmot_app::ChatListWindowError as W;
        use std::sync::Arc;
        assert!(matches!(
            MarmotKitError::from(W::InvalidLimit),
            MarmotKitError::ChatWindowInvalidLimit
        ));
        assert!(matches!(
            MarmotKitError::from(W::StaleWindow),
            MarmotKitError::ChatWindowStale
        ));
        assert!(matches!(
            MarmotKitError::from(W::AnchorOutsideWindow),
            MarmotKitError::ChatWindowAnchorOutside
        ));
        assert!(matches!(
            MarmotKitError::from(W::Closed),
            MarmotKitError::ChatWindowClosed
        ));
        let error = Arc::new(AppError::Storage(cgka_traits::storage::StorageError::Busy(
            "busy".into(),
        )));
        assert!(matches!(
            MarmotKitError::from(W::App(error.clone())),
            MarmotKitError::StorageBusy { .. }
        ));
        assert!(matches!(
            MarmotKitError::from(error.as_ref()),
            MarmotKitError::StorageBusy { .. }
        ));
        let error = Arc::new(AppError::RuntimeStopping);
        assert!(matches!(
            MarmotKitError::from(W::App(error.clone())),
            MarmotKitError::RuntimeStopping
        ));
        assert!(matches!(
            MarmotKitError::from(error.as_ref()),
            MarmotKitError::RuntimeStopping
        ));
    }
}

impl From<marmot_app::ConversationWindowError> for MarmotKitError {
    fn from(v: marmot_app::ConversationWindowError) -> Self {
        use marmot_app::ConversationWindowError as E;
        match v {
            E::InvalidLimit => Self::ConversationWindowInvalidLimit,
            E::StaleWindow => Self::ConversationWindowStale,
            E::AnchorOutsideWindow => Self::ConversationWindowAnchorOutside,
            E::Closed => Self::ConversationWindowClosed,
            E::NotReady => Self::ConversationWindowNotReady,
            E::App(e) => Self::from(e.as_ref()),
            E::Query(e)
                if matches!(
                    e.as_ref(),
                    marmot_app::ConversationOpenError::MessageNotFound
                ) =>
            {
                Self::ConversationWindowMessageNotRetained
            }
            E::Query(e) => Self::ConversationWindowQuery {
                details: e.to_string(),
            },
            E::Presentation(e) => Self::ConversationWindowPresentation {
                details: e.to_string(),
            },
        }
    }
}
