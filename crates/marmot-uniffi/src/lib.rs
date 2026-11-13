//! UniFFI bindings for the Marmot app runtime.
//!
//! This crate is a thin FFI adapter over [`marmot_app::MarmotApp`] and
//! [`marmot_app::MarmotAppRuntime`]. It is consumed by generated Swift and
//! Kotlin bindings, plus anything else that wants a UniFFI-shaped surface.
//!
//! Design notes:
//! - One process-wide [`Marmot`] handle owns the [`MarmotApp`] + runtime pair.
//! - Async methods run on a Tokio runtime owned by this crate, not on the host
//!   thread that polls them: [`marmot_uniffi_macros::on_tokio_runtime`] spawns
//!   each body through [`tokio_runtime`], and constructors enter the same
//!   runtime so construction-time spawns land there too.
//! - Internal Rust types that don't map cleanly across the FFI boundary are
//!   re-exposed as FFI-friendly records (e.g. byte ids → hex strings,
//!   variant-with-payload enums → flattened variants).
//! - Subscriptions are returned as long-lived `uniffi::Object` instances;
//!   host apps drive them by awaiting `next()` until it returns `None`.
//! - The [`Marmot`] command surface is large, so its inherent `impl` blocks are
//!   split by domain under [`commands`]; this module keeps construction,
//!   lifecycle, the shared free helpers, module wiring, and the re-exports.

use std::sync::Arc;

use cgka_traits::TransportEndpoint;
use marmot_app::{
    MarmotApp, MarmotAppConfig, MarmotAppRuntime, TimelineAttachmentType, TimelineMessageQuery,
    TimelinePagination,
};

/// Shared metadata lookup bound for native adapters.
pub use marmot_app::MAX_ATTACHMENT_ASSET_LOOKUPS;

mod commands;
mod deployment;
pub use commands::user_blocks::{BlockListSnapshotFfi, BlockListSubscription, BlockedUserFfi};
pub use deployment::{
    MarmotDeploymentFfi, OpenRankingProviderFfi, RelayEventLimitFfi, marmot_deployment_neutral,
    marmot_deployment_white_noise,
};
// Public: `marmot-c` builds its `#[repr(C)]` mirrors from these modules so
// the C ABI can never drift from the Swift/Kotlin surface.
pub mod conversions;
pub use conversions::AttachmentAcquisitionModeFfi;
pub use conversions::PendingWelcomeDeliveryFfi;
mod errors;
mod external_signer;
mod markdown;
mod nip46;
mod publisher;
mod secret_store;
mod tokio_runtime;
pub use publisher::{
    AgentTextPublisher, PublisherAckFfi, PublisherInfoFfi, PublisherOptionsFfi, PublisherRecordFfi,
    PublisherTrustFfi,
};
pub mod subscriptions;

pub use conversions::conversation_window::*;
use conversions::group_id_from_hex;
pub use errors::{
    EventSizeClassFfi, MarmotKitError, MissingKeyPackageReasonFfi, OversizedArtifactFfi,
};
pub use external_signer::ExternalAccountSignerFfi;
pub use markdown::{
    MarkdownAlignmentFfi, MarkdownAutolinkKindFfi, MarkdownBlockFfi, MarkdownCodeBlockKindFfi,
    MarkdownDocumentFfi, MarkdownInlineFfi, MarkdownLinkDestinationKindFfi, MarkdownListItemFfi,
    MarkdownListKindFfi, MarkdownNostrEntityFfi, MarkdownNostrHrpFfi, MarkdownTableCellFfi,
    MarkdownTimestampStyleFfi,
};
pub use nip46::{
    Nip46ErrorFfi, Nip46PermissionsFfi, Nip46SessionFfi, Nip46StateFfi, Nip46StatusFfi,
};
pub use secret_store::SecretStore;
pub use subscriptions::{ConversationWindowSubscription, RelayLivenessSubscription};

uniffi::setup_scaffolding!();

/// Relay endpoint policy. Loopback is an explicit local-test opt-in;
/// private, link-local, and public plaintext endpoints remain rejected.
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum RelayPolicyFfi {
    PublicOnly,
    AllowLoopback,
    /// Explicit development opt-in for both relay and blob loopback endpoints.
    AllowLoopbackRelaysAndBlobs,
}

pub use commands::{
    CreateGroupOptionsFfi, InitialGroupImageFfi, LocalSendAcceptanceFfi, LocalSendStatusFfi,
    MediaUploadSubmissionFfi, MemberKeyPackagePrewarmSummaryFfi, OnboardingSubscription,
    PreparedGroupImageUploadFfi, PreparedGroupImageUploadStateFfi, PublicEventPreviewFfi,
    PublicEventPreviewStateFfi, parse_media_imeta_tag, verify_public_nostr_event_json,
};
pub use conversions::{
    AccountDevicesActivationFfi, AppBlobEndpointFfi, AppGroupEncryptedMediaComponentFfi,
    AppGroupMemberIdsFfi, AppPerformanceOperationSnapshotFfi, AppPerformanceSnapshotFfi,
    AuditDeliveryBacklogV5Ffi, AuditDeliveryFailureKindV5Ffi, AuditDeliveryFailureV5Ffi,
    AuditDeliveryStatusV5Ffi, AuditLogDeleteResultFfi, AuditLogFileFfi, AuditLogRetentionFfi,
    AuditLogSettingsFfi, AuditLogSourceFfi, AuditLogTrackerUpdateResultV5Ffi, AuditOtlpConfigV5Ffi,
    AuditOtlpTrackerResultV5Ffi, BackgroundNotificationCollectionFfi, CachedIdentityProjectionFfi,
    ChatConversationKindFfi, ChatListAttachmentKindFfi, ChatListAvatarFfi,
    ChatListMessageDeliveryStateFfi, ChatListMessagePreviewFfi, ChatListRowFfi,
    ChatListSubscriptionUpdateFfi, ChatListUpdateTriggerFfi, ChatNotificationSettingsFfi,
    ChatPinStateFfi, CreatedGroupFfi, CursorPersistenceFfi, DiagnosticsExporterStatusFfi,
    DiscardFailedSendOutcomeFfi, DiscardFailedSendResultFfi, DurationHistogramBucketFfi,
    DurationHistogramSnapshotFfi, EmojiSetAssetFfi, EmojiSetCoverFfi, EmojiSetEmojiFfi,
    EmojiSetFfi, EmojiSetInstallControlFfi, EmojiSetInstallProgressFfi, EmojiSetInstallResultFfi,
    EmojiSetSyncResultFfi, EmojiSkipFfi, EmojiSkipReasonFfi, EncryptedMediaVersionFfi,
    ExistingDirectConversationFfi, GroupEvolutionStatusFfi, GroupMaintenanceStatusFfi,
    GroupPushDebugInfoFfi, GroupPushTokenDebugEntryFfi, GroupSystemEventFfi,
    GroupSystemEventProvenanceFfi, HostPerformanceOperationFfi, HostPerformanceOutcomeFfi,
    InstalledCustomEmojiAssetFfi, InstalledCustomEmojiFfi, InstalledEmojiSetStateFfi,
    KeyPackageMaintenanceStatusFfi, LocalPushRegistrationDebugFfi, MaintenanceObligationFfi,
    MaintenancePhaseFfi, MaintenanceTriggerFfi, MediaAttachmentOutcomeFfi,
    MediaAttachmentReferenceFfi, MediaAttachmentRejectionFfi, MediaAttachmentRejectionKindFfi,
    MediaDownloadResultFfi, MediaFileTransferControlFfi, MediaFileUploadAttachmentRequestFfi,
    MediaFileUploadRequestFfi, MediaLocatorFfi, MediaRecordFfi, MediaUploadAttachmentRequestFfi,
    MediaUploadAttachmentResultFfi, MediaUploadRequestFfi, MediaUploadResultFfi,
    MessageDraftAttachmentFfi, MessageDraftAttachmentSummaryFfi, MessageDraftFfi,
    MessageDraftSummaryFfi, MessageTagFfi, NotificationCollectionStatusFfi,
    NotificationSettingsFfi, NotificationTrafficClassFfi, NotificationTriggerFfi,
    NotificationUpdateFfi, NotificationUserFfi, NotificationWakeSourceFfi, OnboardingActionFfi,
    OnboardingDeviceDiscoveryFfi, OnboardingDevicePackageFfi, OnboardingFindingFfi,
    OnboardingIssueFfi, OnboardingOptionsFfi, OnboardingRelayCapabilityFfi,
    OnboardingRelayRepairFfi, OnboardingRelayRepairModeFfi, OnboardingRelayTagChangeFfi,
    OnboardingRelayTagDispositionFfi, OnboardingRelayTagFfi, OnboardingRelayTagRoleFfi,
    OnboardingRepairProposalFfi, OnboardingSingleDeviceNoticeFfi, OnboardingSnapshotFfi,
    OnboardingStatusFfi, OnboardingStepFfi, OnboardingStepStateFfi, PeriodicMaintenancePolicyFfi,
    PollOptionResultFfi, PollProjectionFfi, PollTypeFfi, PollVoteFfi, PollVotePageFfi,
    ProductAnalyticsActivityFfi, ProductAnalyticsMetadataFfi, ProductAnalyticsRuntimeConfigFfi,
    ProductEventFfi, ProductEventModeFfi, ProductEventPropertyFfi, ProductEventSchemaFfi,
    ProductPropertyKindFfi, ProductPropertySchemaFfi, ProductRecordResultFfi, PushPlatformFfi,
    PushRegistrationFfi, PushRegistrationShareOutcomeFfi, PushRegistrationShareStatusFfi,
    PushRegistrationSyncResultFfi, RelayEndpointClassificationFfi, RelayEndpointPolicyFfi,
    RelayTelemetryResourceFfi, RelayTelemetryRuntimeConfigFfi, RelayTelemetrySettingsFfi,
    RetentionSweepGroupOutcomeFfi, RetentionSweepReportFfi, RetentionSweepStatusFfi,
    RuntimeProjectionUpdateFfi, SecureDeleteExpiredResultFfi, StickerAssetFfi, StickerFfi,
    StickerImportResultFfi, StickerPackFfi, StickerRefFfi, StickerSyncResultFfi,
    TimelineMessageChangeFfi, TimelineMessageQueryFfi, TimelineMessageRecordFfi, TimelinePageFfi,
    TimelineProjectionUpdateFfi, TimelineReactionEmojiFfi, TimelineReactionSummaryFfi,
    TimelineRemoveReasonFfi, TimelineSubscriptionUpdateFfi, TimelineUpdateTriggerFfi,
    TimelineUserReactionFfi, TransportFanoutStatusFfi, UsageDiagnosticsDecisionFfi,
    UsageDiagnosticsSettingsFfi, UsageDiagnosticsStatusFfi, UserEmojiListFfi,
};

/// Convenience: turn an FFI string list of relay URLs into the engine's
/// [`TransportEndpoint`] wrapper, dedup-stripped of empties.
pub(crate) fn endpoints(urls: &[String]) -> Vec<TransportEndpoint> {
    let mut endpoints = Vec::new();
    for url in urls {
        let url = url.trim();
        if url.is_empty() {
            continue;
        }
        let endpoint = TransportEndpoint::from(url);
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
    endpoints
}

pub(crate) fn optional_group_id_hex(
    group_id_hex: Option<String>,
) -> Result<Option<String>, MarmotKitError> {
    match group_id_hex {
        Some(value) if !value.trim().is_empty() => Ok(Some(hex::encode(
            group_id_from_hex(value.trim())?.as_slice(),
        ))),
        _ => Ok(None),
    }
}

pub(crate) fn optional_message_id_hex(
    message_id_hex: Option<String>,
) -> Result<Option<String>, MarmotKitError> {
    let Some(value) = message_id_hex else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(value).map_err(|err| MarmotKitError::InvalidHex {
        details: err.to_string(),
    })?;
    if bytes.len() != 32 {
        return Err(MarmotKitError::InvalidHex {
            details: format!("expected 32-byte message id, got {} bytes", bytes.len()),
        });
    }
    Ok(Some(hex::encode(bytes)))
}

pub(crate) fn timeline_query_from_ffi(
    query: TimelineMessageQueryFfi,
) -> Result<TimelineMessageQuery, MarmotKitError> {
    Ok(TimelineMessageQuery {
        group_id_hex: optional_group_id_hex(query.group_id_hex)?,
        search: query.search.and_then(|value| {
            let value = value.trim().to_owned();
            (!value.is_empty()).then_some(value)
        }),
        sender: query
            .sender
            .map(|sender| {
                conversions::normalize_member_ref_ffi(&sender).map(|member| member.account_id_hex)
            })
            .transpose()?,
        since: query.since,
        until: query.until,
        attachment_type: match query.attachment_type {
            0 => TimelineAttachmentType::Any,
            1 => TimelineAttachmentType::Image,
            2 => TimelineAttachmentType::Video,
            3 => TimelineAttachmentType::Audio,
            4 => TimelineAttachmentType::File,
            5 => TimelineAttachmentType::Attachment,
            _ => {
                return Err(MarmotKitError::Runtime {
                    details: "timeline attachment_type must be in 0..=5".into(),
                });
            }
        },
        search_wall_clock: query.search_wall_clock,
        cursor_group_id: optional_group_id_hex(query.cursor_group_id)?,
        pagination: TimelinePagination {
            before: query.before,
            before_message_id: optional_message_id_hex(query.before_message_id)?,
            before_inclusive: false,
            after: query.after,
            after_message_id: optional_message_id_hex(query.after_message_id)?,
            limit: query.limit.map(|value| value as usize),
        },
    })
}

/// Composable runtime construction options. The deployment is required.
/// Omitted policies use public-only endpoints and an advancing cursor.
/// Omitted labels stay untagged; omitted secret storage uses the platform
/// keychain under the deployment's keychain service.
#[derive(Clone, uniffi::Record)]
pub struct MarmotOptions {
    #[uniffi(default = None)]
    pub relay_policy: Option<RelayPolicyFfi>,
    #[uniffi(default = None)]
    pub cursor_persistence: Option<CursorPersistenceFfi>,
    #[uniffi(default = None)]
    pub client_name: Option<String>,
    /// Short name of the platform this device runs on, such as `iOS`. With
    /// `client_name`, it fills this device's entry on the account's Devices
    /// screen (mdk#2628 3.6). Blank, or over 64 bytes once trimmed, is left out.
    #[uniffi(default = None)]
    pub device_platform: Option<String>,
    #[uniffi(default = None)]
    pub secret_store: Option<Arc<dyn SecretStore>>,
    #[uniffi(default = None)]
    pub attachment_acquisition_mode: Option<AttachmentAcquisitionModeFfi>,
    /// Destination for private moderation reports (`submit_moderation_report`). Set per
    /// build flavor. Invalid values leave reporting unconfigured; `configure_moderation_reporting`
    /// reports why.
    #[uniffi(default = None)]
    pub moderation_report_config: Option<ModerationReportConfigFfi>,
    /// Deployment services: recovery relays, discovery indexers, media and
    /// image servers, Open Ranking, moderation label namespace and keychain
    /// service. Required, with no default, so a
    /// host can't silently open a different keychain service: White Noise
    /// apps pass `marmot_deployment_white_noise()`.
    pub deployment: MarmotDeploymentFfi,
}

impl MarmotOptions {
    /// Options with only the deployment set; every policy at its default.
    pub fn for_deployment(deployment: MarmotDeploymentFfi) -> Self {
        Self {
            relay_policy: None,
            cursor_persistence: None,
            client_name: None,
            device_platform: None,
            secret_store: None,
            attachment_acquisition_mode: None,
            moderation_report_config: None,
            deployment,
        }
    }

    fn app_config(&self) -> MarmotAppConfig {
        let relay_policy = self.relay_policy.unwrap_or(RelayPolicyFfi::PublicOnly);
        MarmotAppConfig::default()
            .with_attachment_acquisition_mode(
                self.attachment_acquisition_mode.unwrap_or_default().into(),
            )
            .with_allow_loopback_relay_endpoints(matches!(
                relay_policy,
                RelayPolicyFfi::AllowLoopback | RelayPolicyFfi::AllowLoopbackRelaysAndBlobs
            ))
            .with_allow_loopback_blob_endpoints(matches!(
                relay_policy,
                RelayPolicyFfi::AllowLoopbackRelaysAndBlobs
            ))
            .with_cursor_persistence(
                self.cursor_persistence
                    .unwrap_or(CursorPersistenceFfi::Advance)
                    .into(),
            )
            .with_key_package_client_name(self.client_name.clone())
            .with_device_platform(self.device_platform.clone())
            .with_moderation_report_config(self.moderation_report_config.clone().map(Into::into))
            .with_deployment(self.deployment.clone().into())
    }
}

/// Check the experimental host capability before acquiring constructor resources.
/// Shared with the C boundary so unavailable builds never take callback ownership.
pub fn require_experimental_device_groups() -> Result<(), MarmotKitError> {
    if cfg!(feature = "dev-device-groups") {
        Ok(())
    } else {
        Err(MarmotKitError::Runtime {
            details: "experimental_device_groups_unavailable".to_owned(),
        })
    }
}

#[derive(uniffi::Object)]
pub struct Marmot {
    pub(crate) app: MarmotApp,
    pub(crate) runtime: MarmotAppRuntime,
}

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Open with any combination of runtime options, including the required
    /// deployment. The other constructors are wrappers around this entry
    /// point and take the deployment as their last argument.
    #[uniffi::constructor]
    pub fn new_with_configuration(
        root_path: String,
        relay_urls: Vec<String>,
        options: MarmotOptions,
    ) -> Result<Arc<Self>, MarmotKitError> {
        Self::open_with_configuration(root_path, relay_urls, options, false)
    }

    /// Open an explicitly experimental device-group test build. The native
    /// library must enable `dev-device-groups`; otherwise this fails
    /// before opening the root or taking ownership of host secret storage.
    /// Ordinary constructors remain disabled even in a capable library.
    /// Use matching native and generated bindings, and this constructor for
    /// every foreground/background opener of the same experimental root.
    #[uniffi::constructor]
    pub fn new_with_experimental_device_groups(
        root_path: String,
        relay_urls: Vec<String>,
        options: MarmotOptions,
    ) -> Result<Arc<Self>, MarmotKitError> {
        Self::open_with_configuration(root_path, relay_urls, options, true)
    }

    /// Open with an explicit relay policy and optional host-owned key storage.
    /// Existing constructors retain their public-only relay policy.
    #[uniffi::constructor]
    pub fn new_with_options(
        root_path: String,
        relay_urls: Vec<String>,
        relay_policy: RelayPolicyFfi,
        secret_store: Option<Arc<dyn SecretStore>>,
        deployment: MarmotDeploymentFfi,
    ) -> Result<Arc<Self>, MarmotKitError> {
        Self::new_with_configuration(
            root_path,
            relay_urls,
            MarmotOptions {
                relay_policy: Some(relay_policy),
                secret_store,
                ..MarmotOptions::for_deployment(deployment)
            },
        )
    }

    /// Open the Marmot app at `root_path`, configured with the given default
    /// relay URLs and `deployment`. Account secrets (Nostr private keys) are
    /// stored in the platform keyring (Keychain on Apple platforms, Android's
    /// native keyring on Android) under the deployment's keychain service —
    /// not in a plaintext file. Fallible because initializing the platform
    /// secret store can fail or another process may own the same root
    /// ([`MarmotKitError::RuntimeBusy`]). Root ownership is nonblocking and
    /// remains held until the final `Marmot`/runtime handle is dropped, even
    /// after [`Marmot::shutdown`]. Call [`Marmot::start`] before subscribing
    /// to events.
    #[uniffi::constructor]
    pub fn new(
        root_path: String,
        relay_urls: Vec<String>,
        deployment: MarmotDeploymentFfi,
    ) -> Result<Arc<Self>, MarmotKitError> {
        Self::new_with_configuration(
            root_path,
            relay_urls,
            MarmotOptions::for_deployment(deployment),
        )
    }

    /// Open the Marmot app with host-supplied account-secret storage instead
    /// of the platform keychain. Identical to [`Marmot::new`] except that
    /// every read, write, and removal of an account signing key goes through
    /// `secret_store`.
    ///
    /// For hosts that already own an encrypted store: a desktop client with a
    /// password-sealed vault, an iOS host that wants its own Keychain
    /// access-control flags, an Android host layering policy over the
    /// Keystore. The key crosses the boundary as secret-key hex, so the store
    /// is responsible for protecting it at rest.
    ///
    /// `secret_store` is called from runtime worker threads and may be called
    /// concurrently; implementations must be thread-safe.
    #[uniffi::constructor]
    pub fn new_with_secret_store(
        root_path: String,
        relay_urls: Vec<String>,
        secret_store: Arc<dyn SecretStore>,
        deployment: MarmotDeploymentFfi,
    ) -> Result<Arc<Self>, MarmotKitError> {
        Self::new_with_configuration(
            root_path,
            relay_urls,
            MarmotOptions {
                secret_store: Some(secret_store),
                ..MarmotOptions::for_deployment(deployment)
            },
        )
    }

    /// Open the Marmot app with an explicit durable transport-cursor policy.
    /// Identical to [`Marmot::new`] except for the policy; `new` itself is
    /// [`CursorPersistenceFfi::Advance`].
    ///
    /// Wake-collection processes — the iOS NSE constructing one `Marmot` per
    /// push around [`Marmot::collect_notifications_after_wake`], and the
    /// notification reply/mark-read action paths — construct with
    /// [`CursorPersistenceFfi::Frozen`]: the pass still ingests, decrypts, and
    /// projects everything, but a sub-second drain on cold sockets can never
    /// ratchet the durable `since` floor past events it did not receive (the
    /// wake-collection trigger). Foreground app processes keep [`Marmot::new`].
    // Construction-surface addition: binding regeneration and the workspace
    // version bump ride the release per this crate's lockstep invariant — do
    // not bump versions here.
    #[uniffi::constructor]
    pub fn new_with_cursor_persistence(
        root_path: String,
        relay_urls: Vec<String>,
        cursor_persistence: CursorPersistenceFfi,
        deployment: MarmotDeploymentFfi,
    ) -> Result<Arc<Self>, MarmotKitError> {
        Self::new_with_configuration(
            root_path,
            relay_urls,
            MarmotOptions {
                cursor_persistence: Some(cursor_persistence),
                ..MarmotOptions::for_deployment(deployment)
            },
        )
    }

    /// Open with an optional public client label for new KeyPackage publications.
    /// Existing constructors remain untagged. Whitespace-only labels, and labels
    /// longer than 64 bytes once trimmed, are omitted rather than truncated.
    /// Hosts must supply this on every foreground/background runtime construction.
    #[uniffi::constructor]
    pub fn new_with_client_name(
        root_path: String,
        relay_urls: Vec<String>,
        client_name: Option<String>,
        cursor_persistence: CursorPersistenceFfi,
        secret_store: Option<Arc<dyn SecretStore>>,
        deployment: MarmotDeploymentFfi,
    ) -> Result<Arc<Self>, MarmotKitError> {
        Self::new_with_configuration(
            root_path,
            relay_urls,
            MarmotOptions {
                client_name,
                cursor_persistence: Some(cursor_persistence),
                secret_store,
                ..MarmotOptions::for_deployment(deployment)
            },
        )
    }

    /// Bring the runtime to local readiness.
    ///
    /// On success, persisted account state is seeded and worker-routed local
    /// reads are available: group reads issued before a group's background
    /// hydration completes wait for exactly that group. Relay activation,
    /// group-subscription registration, shared-directory synchronization,
    /// remaining group hydration, and initial catch-up continue
    /// asynchronously. Hosts should render local projections immediately and
    /// represent network progress separately.
    ///
    /// Ready is NOT "safe to send without waiting" (mdk#1161): mutations
    /// issued before the initial catch-up completes are queued and replayed
    /// in arrival order after it, so first-send latency can still cover
    /// remaining hydration plus catch-up even when the target group is
    /// already readable.
    ///
    /// The binding signature and result type are unchanged; this local-ready
    /// completion point is the behavioral contract for this implementation.
    pub async fn start(&self) -> Result<(), MarmotKitError> {
        self.runtime.start().await?;
        Ok(())
    }

    /// Tear the runtime down. Drops all subscriptions; long-lived
    /// [`EventsSubscription`] / [`ChatsSubscription`] / etc. instances on the
    /// host side will see their `next()` return `None` shortly after.
    ///
    /// This stops work but does **not** release the store's file locks — the
    /// SQLite connections stay open. Hosts whose process can be suspended
    /// should call [`Marmot::shutdown_and_close`] instead.
    pub async fn shutdown(&self) {
        self.runtime.shutdown().await;
    }

    /// Stop admitting runtime work, close every SQLite database and release the
    /// Marmot root's runtime lease, then make a bounded attempt at graceful
    /// worker cleanup.
    ///
    /// Await this before letting the process be suspended. When it returns,
    /// nothing this process owns holds a file lock inside the Marmot root —
    /// which is the fact iOS actually checks: a process suspended while holding
    /// a lock in a shared App Group container is killed with `0xdead10cc`, and
    /// a WAL connection holds one on its `-shm` sidecar for its entire
    /// lifetime. [`Marmot::shutdown`] cannot deliver that on its own; it stops
    /// workers, but the databases are shared behind `Arc`s that no host can
    /// observe or await going away.
    ///
    /// **Terminal: this handle is finished.** Every subsequent call that
    /// touches storage fails with [`MarmotKitError::StorageClosed`] rather than
    /// reopening the databases, because reopening would re-lock the container
    /// this method just cleared. Construct a new `Marmot` on resume — which is
    /// what a foregrounding app does anyway.
    ///
    /// Storage closure runs in a runtime-owned task, so cancelling the host
    /// future cannot cancel it. Safe to call twice or concurrently, and safe to
    /// call with or without a preceding [`Marmot::shutdown`]. Graceful cleanup
    /// has a fixed budget; the close itself waits only for an already-admitted
    /// database open or SQLite statement. Begin this call early enough to cover
    /// that close before the host's suspension assertion expires.
    /// An error means at least one database reported a problem while closing;
    /// every database is still attempted and left closed, so a failure is not
    /// a reason to retry or to keep the process alive.
    // Object-method and error-variant addition: binding regeneration and the
    // workspace version bump ride the release per this crate's lockstep
    // invariant — do not bump versions here.
    #[marmot_uniffi_macros::survives_cancellation]
    pub async fn shutdown_and_close(&self) -> Result<(), MarmotKitError> {
        self.runtime.shutdown_and_close().await?;
        Ok(())
    }

    /// True once [`Marmot::shutdown_and_close`] has closed the store. A host
    /// can check this to confirm it is safe to be suspended, or to notice it is
    /// holding a spent handle and needs a fresh one.
    pub fn storage_is_closed(&self) -> bool {
        self.runtime.storage_is_closed()
    }

    /// True once shutdown has started. Host apps can use this to avoid
    /// launching more subscriptions or account work while they are moving to
    /// the background.
    pub fn is_stopping(&self) -> bool {
        self.runtime.is_stopping()
    }
}

impl Marmot {
    /// Validate intent before constructing a foreign store or opening a root.
    fn open_with_configuration(
        root_path: String,
        relay_urls: Vec<String>,
        options: MarmotOptions,
        experimental_device_groups: bool,
    ) -> Result<Arc<Self>, MarmotKitError> {
        if experimental_device_groups {
            require_experimental_device_groups()?;
        }
        let config = options
            .app_config()
            .with_dev_device_groups(experimental_device_groups);
        let store = options.secret_store.map(|store| {
            Arc::new(secret_store::ForeignSecretStore::new(store))
                as Arc<dyn marmot_account::AccountSecretStore>
        });
        Self::open(root_path, relay_urls, config, store)
    }

    /// Account home backed by the host store or deployment's platform keychain.
    fn open(
        root_path: String,
        relay_urls: Vec<String>,
        config: MarmotAppConfig,
        secret_store: Option<Arc<dyn marmot_account::AccountSecretStore>>,
    ) -> Result<Arc<Self>, MarmotKitError> {
        // Opening can spawn relay-plane tasks (`Handle::try_current` users);
        // they belong on the runtime the exports will run on.
        let tokio_handle = tokio_runtime::handle()?;
        let _entered = tokio_handle.enter();
        let account_home = match secret_store {
            Some(store) => marmot_account::AccountHome::open_with_secret_store(&root_path, store),
            None => marmot_account::AccountHome::open_with_keychain(
                &root_path,
                config.deployment.keychain_service.clone(),
            )
            .map_err(marmot_app::AppError::from)?,
        };
        let app = MarmotApp::try_with_relays_and_account_home_and_config(
            &root_path,
            relay_urls,
            account_home,
            config,
        )?;
        let runtime = app.runtime();
        Ok(Arc::new(Self { app, runtime }))
    }
}

pub use subscriptions::PresentedChatListSubscription;

pub use conversions::{
    AccountAttentionEntryFfi, AccountAttentionSnapshotFfi, AccountAttentionStateFfi,
    AccountAttentionTotalFfi, AccountAttentionUnavailableFfi, ChatListAnchorOutcomeFfi,
    ChatListPageDirectionFfi, ChatListViewFfi, ChatListWindowSnapshotFfi,
};
pub use subscriptions::{AccountAttentionSubscription, ChatListWindowSubscription};

pub use commands::moderation::*;

pub use commands::AttachmentTransferSubscription;

#[cfg(test)]
mod tests {
    use super::*;

    /// Crate-root re-exports are public API for Rust consumers. Each type
    /// named here must stay importable from the root, not only through
    /// `conversions`, so an additive export list change cannot drop one.
    #[test]
    fn crate_root_keeps_pre_existing_public_exports() {
        fn importable<T>() {}
        importable::<crate::RuntimeProjectionUpdateFfi>();
        importable::<crate::TimelineProjectionUpdateFfi>();
        importable::<crate::TimelineSubscriptionUpdateFfi>();
        importable::<crate::StickerPackFfi>();
    }

    #[cfg(not(feature = "dev-device-groups"))]
    #[test]
    fn an_unavailable_experimental_constructor_never_opens_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("unopened");
        let result = Marmot::new_with_experimental_device_groups(
            root.to_str().unwrap().to_owned(),
            Vec::new(),
            MarmotOptions::for_deployment(marmot_deployment_neutral()),
        );
        assert!(matches!(result, Err(MarmotKitError::Runtime { details })
            if details == "experimental_device_groups_unavailable"));
        assert!(!root.exists());
    }

    #[test]
    fn runtime_options_defaults_and_combined_policies() {
        let defaults = MarmotOptions::for_deployment(marmot_deployment_neutral()).app_config();
        assert!(!defaults.allow_loopback_relay_endpoints);
        assert!(!defaults.allow_loopback_blob_endpoints);
        assert_eq!(
            defaults.cursor_persistence,
            marmot_app::CursorPersistence::Advance
        );
        assert_eq!(defaults.key_package_client_name, None);
        assert_eq!(defaults.device_platform, None);
        assert_eq!(
            defaults.attachment_acquisition_mode,
            marmot_app::AttachmentAcquisitionMode::NativeAutomatic
        );
        assert_eq!(
            MarmotOptions {
                attachment_acquisition_mode: Some(AttachmentAcquisitionModeFfi::HostManaged),
                ..MarmotOptions::for_deployment(marmot_deployment_neutral())
            }
            .app_config()
            .attachment_acquisition_mode,
            marmot_app::AttachmentAcquisitionMode::HostManaged
        );
        for (policy, relay, blob) in [
            (RelayPolicyFfi::PublicOnly, false, false),
            (RelayPolicyFfi::AllowLoopback, true, false),
            (RelayPolicyFfi::AllowLoopbackRelaysAndBlobs, true, true),
        ] {
            let config = MarmotOptions {
                relay_policy: Some(policy),
                cursor_persistence: Some(CursorPersistenceFfi::Frozen),
                client_name: Some(" whitenoise ".into()),
                device_platform: Some("iOS".into()),
                ..MarmotOptions::for_deployment(marmot_deployment_neutral())
            }
            .app_config();
            assert_eq!(config.allow_loopback_relay_endpoints, relay);
            assert_eq!(config.allow_loopback_blob_endpoints, blob);
            assert_eq!(
                config.cursor_persistence,
                marmot_app::CursorPersistence::Frozen
            );
            assert_eq!(
                config.key_package_client_name.as_deref(),
                Some(" whitenoise ")
            );
            assert_eq!(config.device_platform.as_deref(), Some("iOS"));
        }
    }

    #[test]
    fn runtime_options_carry_the_deployment() {
        assert_eq!(
            MarmotOptions::for_deployment(marmot_deployment_white_noise())
                .app_config()
                .deployment,
            marmot_app::MarmotDeployment::white_noise(),
        );
        let neutral = MarmotOptions::for_deployment(MarmotDeploymentFfi {
            keychain_service: " org.example.app ".into(),
            ..marmot_deployment_neutral()
        })
        .app_config();
        assert_eq!(
            neutral.deployment,
            marmot_app::MarmotDeployment {
                keychain_service: "org.example.app".into(),
                ..marmot_app::MarmotDeployment::neutral()
            }
        );
    }

    #[test]
    fn optional_message_id_hex_trims_and_canonicalizes() {
        assert_eq!(optional_message_id_hex(None).unwrap(), None);
        assert_eq!(optional_message_id_hex(Some("  ".into())).unwrap(), None);
        assert_eq!(
            optional_message_id_hex(Some(format!(" {} ", "AB".repeat(32)))).unwrap(),
            Some("ab".repeat(32))
        );
        assert!(matches!(optional_message_id_hex(Some("abcd".into())),
            Err(MarmotKitError::InvalidHex { details }) if details == "expected 32-byte message id, got 2 bytes"));
    }

    #[test]
    fn timeline_query_preserves_search_cursor_direction_and_exclusive_before() {
        let empty = timeline_query_from_ffi(TimelineMessageQueryFfi::default()).unwrap();
        assert!(empty.group_id_hex.is_none() && empty.search.is_none());
        assert!(empty.sender.is_none() && empty.since.is_none() && empty.until.is_none());
        assert_eq!(empty.attachment_type, TimelineAttachmentType::Any);
        assert!(!empty.search_wall_clock);
        assert!(empty.cursor_group_id.is_none());
        assert!(empty.pagination.before.is_none() && empty.pagination.after.is_none());
        assert!(empty.pagination.limit.is_none());
        assert!(!empty.pagination.before_inclusive);
        let query = timeline_query_from_ffi(TimelineMessageQueryFfi {
            group_id_hex: Some(format!(" {} ", "AB".repeat(16))),
            search: Some("  needle  ".into()),
            sender: Some(format!(
                " {} ",
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            )),
            since: Some(200),
            until: Some(600),
            attachment_type: 5,
            search_wall_clock: true,
            cursor_group_id: Some(" ABCD ".into()),
            before: Some(501),
            before_message_id: Some(format!(" {} ", "CD".repeat(32))),
            after: Some(201),
            after_message_id: Some(format!(" {} ", "EF".repeat(32))),
            limit: Some(42),
        })
        .unwrap();
        assert_eq!(query.group_id_hex, Some("ab".repeat(16)));
        assert_eq!(query.search.as_deref(), Some("needle"));
        assert_eq!(
            query.sender.as_deref(),
            Some("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        );
        assert_eq!((query.since, query.until), (Some(200), Some(600)));
        assert_eq!(query.attachment_type, TimelineAttachmentType::Attachment);
        assert!(query.search_wall_clock);
        assert_eq!(query.cursor_group_id.as_deref(), Some("abcd"));
        assert_eq!(query.pagination.before, Some(501));
        assert_eq!(query.pagination.before_message_id, Some("cd".repeat(32)));
        assert_eq!(query.pagination.after, Some(201));
        assert_eq!(query.pagination.after_message_id, Some("ef".repeat(32)));
        assert_eq!(query.pagination.limit, Some(42));
        assert!(!query.pagination.before_inclusive);
        let blank = timeline_query_from_ffi(TimelineMessageQueryFfi {
            search: Some("  ".into()),
            ..Default::default()
        })
        .unwrap();
        assert!(blank.search.is_none());
    }

    #[test]
    fn timeline_query_validation() {
        for (value, expected) in [
            (0, TimelineAttachmentType::Any),
            (1, TimelineAttachmentType::Image),
            (2, TimelineAttachmentType::Video),
            (3, TimelineAttachmentType::Audio),
            (4, TimelineAttachmentType::File),
            (5, TimelineAttachmentType::Attachment),
        ] {
            let query = timeline_query_from_ffi(TimelineMessageQueryFfi {
                attachment_type: value,
                ..Default::default()
            })
            .unwrap();
            assert_eq!(query.attachment_type, expected);
        }
        for attachment_type in [6, u32::MAX] {
            assert!(matches!(timeline_query_from_ffi(TimelineMessageQueryFfi {
                attachment_type,
                ..Default::default()
            }), Err(MarmotKitError::Runtime { details }) if details == "timeline attachment_type must be in 0..=5"));
        }
        assert!(matches!(
            timeline_query_from_ffi(TimelineMessageQueryFfi {
                sender: Some("not-a-public-key".into()),
                ..Default::default()
            }),
            Err(MarmotKitError::InvalidIdentity { .. })
        ));
        assert!(matches!(
            timeline_query_from_ffi(TimelineMessageQueryFfi {
                cursor_group_id: Some("not-hex".into()),
                ..Default::default()
            }),
            Err(MarmotKitError::InvalidHex { .. })
        ));
    }

    #[test]
    fn optional_group_id_hex_trims_and_canonicalizes() {
        // None and blank input map to the account-wide tail (None), not an error.
        assert_eq!(optional_group_id_hex(None).unwrap(), None);
        assert_eq!(optional_group_id_hex(Some("   ".into())).unwrap(), None);
        // Uppercase + surrounding whitespace canonicalize to lowercase hex so the
        // case-sensitive storage match and live filter compare against the same form.
        assert_eq!(
            optional_group_id_hex(Some(format!(" {} ", "AB".repeat(16)))).unwrap(),
            Some("ab".repeat(16))
        );
        // MLS group ids are opaque variable-length bytes. MDK-created OpenMLS
        // ids are 16 bytes today, but the FFI boundary must not reject other
        // non-empty lengths before storage/runtime can resolve them.
        assert_eq!(
            optional_group_id_hex(Some("ABCD".into())).unwrap(),
            Some("abcd".into())
        );
        // Invalid hex is rejected rather than silently yielding empty history.
        assert!(matches!(optional_group_id_hex(Some("nothex".into())),
            Err(MarmotKitError::InvalidHex { details }) if details == "Invalid character 'n' at position 0"));
        // Absurdly large group ids are rejected at the FFI boundary instead of
        // allocating arbitrary host input.
        assert!(matches!(optional_group_id_hex(Some("ab".repeat(1025))),
            Err(MarmotKitError::InvalidHex { details }) if details == "group id exceeds 1024 bytes"));
    }

    #[test]
    fn endpoints_trim_drop_empties_and_deduplicate_in_order() {
        let urls = vec![
            " wss://relay.one ".to_owned(),
            "".to_owned(),
            "wss://relay.two".to_owned(),
            "wss://relay.one".to_owned(),
            "  ".to_owned(),
        ];

        assert_eq!(
            endpoints(&urls),
            vec![
                TransportEndpoint::from("wss://relay.one"),
                TransportEndpoint::from("wss://relay.two"),
            ]
        );
    }
}
