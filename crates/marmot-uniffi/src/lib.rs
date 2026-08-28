//! UniFFI bindings for the Marmot app runtime.
//!
//! This crate is a thin FFI adapter over [`marmot_app::MarmotApp`] and
//! [`marmot_app::MarmotAppRuntime`]. It is consumed by generated Swift and
//! Kotlin bindings, plus anything else that wants a UniFFI-shaped surface.
//!
//! Design notes:
//! - One process-wide [`Marmot`] handle owns the [`MarmotApp`] + runtime pair.
//! - All async methods rely on UniFFI's tokio integration (the global tokio
//!   runtime is implicit via the `async_runtime = "tokio"` attribute).
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
    MarmotApp, MarmotAppConfig, MarmotAppRuntime, TimelineMessageQuery, TimelinePagination,
};

mod commands;
// Public: `marmot-c` builds its `#[repr(C)]` mirrors from these modules so
// the C ABI can never drift from the Swift/Kotlin surface.
pub mod conversions;
mod errors;
mod external_signer;
mod markdown;
mod secret_store;
pub mod subscriptions;

use conversions::group_id_from_hex;
pub use errors::MarmotKitError;
pub use external_signer::ExternalAccountSignerFfi;
pub use markdown::{
    MarkdownAlignmentFfi, MarkdownAutolinkKindFfi, MarkdownBlockFfi, MarkdownCodeBlockKindFfi,
    MarkdownDocumentFfi, MarkdownInlineFfi, MarkdownLinkDestinationKindFfi, MarkdownListItemFfi,
    MarkdownListKindFfi, MarkdownNostrEntityFfi, MarkdownNostrHrpFfi, MarkdownTableCellFfi,
};
pub use secret_store::SecretStore;

uniffi::setup_scaffolding!();

pub use commands::{
    CreateGroupOptionsFfi, InitialGroupImageFfi, MemberKeyPackagePrewarmSummaryFfi,
    PreparedGroupImageUploadFfi, PreparedGroupImageUploadStateFfi, parse_media_imeta_tag,
};
pub use conversions::{
    AppBlobEndpointFfi, AppGroupEncryptedMediaComponentFfi, AppGroupMemberIdsFfi,
    AppPerformanceOperationSnapshotFfi, AppPerformanceSnapshotFfi, AuditLogDeleteResultFfi,
    AuditLogFileFfi, AuditLogSettingsFfi, AuditLogTrackerConfigFfi, AuditLogTrackerUpdateResultFfi,
    AuditLogUploadResultFfi, AuditLogUploadSourceFfi, BackgroundNotificationCollectionFfi,
    CachedIdentityProjectionFfi, ChatConversationKindFfi, ChatListAttachmentKindFfi,
    ChatListAvatarFfi, ChatListMessageDeliveryStateFfi, ChatListMessagePreviewFfi, ChatListRowFfi,
    ChatListSubscriptionUpdateFfi, ChatListUpdateTriggerFfi, ChatNotificationSettingsFfi,
    ChatPinStateFfi, CreatedGroupFfi, CursorPersistenceFfi, DurationHistogramBucketFfi,
    DurationHistogramSnapshotFfi, EncryptedMediaVersionFfi, ExistingDirectConversationFfi,
    GroupEvolutionStatusFfi, GroupMaintenanceStatusFfi, GroupPushDebugInfoFfi,
    GroupPushTokenDebugEntryFfi, GroupSystemEventFfi, HostPerformanceOperationFfi,
    HostPerformanceOutcomeFfi, KeyPackageMaintenanceStatusFfi, LocalPushRegistrationDebugFfi,
    MaintenanceObligationFfi, MaintenancePhaseFfi, MaintenanceTriggerFfi,
    MediaAttachmentReferenceFfi, MediaDownloadResultFfi, MediaLocatorFfi, MediaRecordFfi,
    MediaUploadAttachmentRequestFfi, MediaUploadAttachmentResultFfi, MediaUploadRequestFfi,
    MediaUploadResultFfi, MessageDraftAttachmentFfi, MessageDraftAttachmentSummaryFfi,
    MessageDraftFfi, MessageDraftSummaryFfi, MessageTagFfi, NotificationCollectionStatusFfi,
    NotificationSettingsFfi, NotificationTrafficClassFfi, NotificationTriggerFfi,
    NotificationUpdateFfi, NotificationUserFfi, NotificationWakeSourceFfi,
    PeriodicMaintenancePolicyFfi, PushPlatformFfi, PushRegistrationFfi,
    PushRegistrationShareOutcomeFfi, PushRegistrationShareStatusFfi, PushRegistrationSyncResultFfi,
    RelayEndpointClassificationFfi, RelayEndpointPolicyFfi, RelayTelemetryResourceFfi,
    RelayTelemetryRuntimeConfigFfi, RelayTelemetrySettingsFfi, RetentionSweepGroupOutcomeFfi,
    RetentionSweepReportFfi, RetentionSweepStatusFfi, RuntimeProjectionUpdateFfi,
    SecureDeleteExpiredResultFfi, TimelineMessageChangeFfi, TimelineMessageQueryFfi,
    TimelineMessageRecordFfi, TimelinePageFfi, TimelineProjectionUpdateFfi,
    TimelineReactionEmojiFfi, TimelineReactionSummaryFfi, TimelineRemoveReasonFfi,
    TimelineSubscriptionUpdateFfi, TimelineUpdateTriggerFfi, TimelineUserReactionFfi,
    TransportFanoutStatusFfi,
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

#[derive(uniffi::Object)]
pub struct Marmot {
    pub(crate) app: MarmotApp,
    pub(crate) runtime: MarmotAppRuntime,
}

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Open the Marmot app at `root_path`, configured with the given default
    /// relay URLs. Account secrets (Nostr private keys) are stored in the
    /// platform keyring (Keychain on Apple platforms, Android's native
    /// keyring on Android) via the default keychain-backed account home —
    /// not in a plaintext file. Fallible because initializing the platform
    /// secret store can fail or another process may own the same root
    /// ([`MarmotKitError::RuntimeBusy`]). Root ownership is nonblocking and
    /// remains held until the final `Marmot`/runtime handle is dropped, even
    /// after [`Marmot::shutdown`]. Call [`Marmot::start`] before subscribing
    /// to events.
    #[uniffi::constructor]
    pub fn new(root_path: String, relay_urls: Vec<String>) -> Result<Arc<Self>, MarmotKitError> {
        Self::open(root_path, relay_urls, MarmotAppConfig::default(), None)
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
    ) -> Result<Arc<Self>, MarmotKitError> {
        Self::open(
            root_path,
            relay_urls,
            MarmotAppConfig::default(),
            Some(Arc::new(secret_store::ForeignSecretStore::new(
                secret_store,
            ))),
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
    ) -> Result<Arc<Self>, MarmotKitError> {
        Self::open(
            root_path,
            relay_urls,
            MarmotAppConfig::default().with_cursor_persistence(cursor_persistence.into()),
            None,
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
    /// Shared open path behind the exported constructors: account home backed
    /// by `secret_store` (the platform keychain when `None`), app configured
    /// by `config`, runtime pair.
    fn open(
        root_path: String,
        relay_urls: Vec<String>,
        config: MarmotAppConfig,
        secret_store: Option<Arc<dyn marmot_account::AccountSecretStore>>,
    ) -> Result<Arc<Self>, MarmotKitError> {
        let account_home = match secret_store {
            Some(store) => marmot_account::AccountHome::open_with_secret_store(&root_path, store),
            None => marmot_account::AccountHome::open_with_default_keychain(&root_path)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_message_id_hex_trims_and_canonicalizes() {
        assert_eq!(optional_message_id_hex(None).unwrap(), None);
        assert_eq!(optional_message_id_hex(Some("  ".into())).unwrap(), None);
        assert_eq!(
            optional_message_id_hex(Some(format!(" {} ", "AB".repeat(32)))).unwrap(),
            Some("ab".repeat(32))
        );
        assert!(optional_message_id_hex(Some("abcd".into())).is_err());
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
        assert!(optional_group_id_hex(Some("nothex".into())).is_err());
        // Absurdly large group ids are rejected at the FFI boundary instead of
        // allocating arbitrary host input.
        assert!(optional_group_id_hex(Some("ab".repeat(1025))).is_err());
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
