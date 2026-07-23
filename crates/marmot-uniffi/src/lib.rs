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
mod conversions;
mod errors;
mod external_signer;
mod markdown;
mod subscriptions;

use conversions::group_id_from_hex;
pub use errors::MarmotKitError;
pub use external_signer::ExternalAccountSignerFfi;
pub use markdown::{
    MarkdownAlignmentFfi, MarkdownAutolinkKindFfi, MarkdownBlockFfi, MarkdownCodeBlockKindFfi,
    MarkdownDocumentFfi, MarkdownInlineFfi, MarkdownLinkDestinationKindFfi, MarkdownListItemFfi,
    MarkdownListKindFfi, MarkdownNostrEntityFfi, MarkdownNostrHrpFfi, MarkdownTableCellFfi,
};

uniffi::setup_scaffolding!();

pub use conversions::{
    AppBlobEndpointFfi, AppGroupEncryptedMediaComponentFfi, AuditDataModeFfi,
    AuditLogDeleteResultFfi, AuditLogFileFfi, AuditLogSettingsFfi, AuditLogTrackerConfigFfi,
    AuditLogTrackerUpdateResultFfi, AuditLogUploadResultFfi, AuditLogUploadSourceFfi,
    BackgroundNotificationCollectionFfi, ChatListAvatarFfi, ChatListMessagePreviewFfi,
    ChatListRowFfi, ChatListSubscriptionUpdateFfi, ChatListUpdateTriggerFfi, CursorPersistenceFfi,
    EncryptedMediaVersionFfi, GroupPushDebugInfoFfi, GroupPushTokenDebugEntryFfi,
    GroupSystemEventFfi, LocalPushRegistrationDebugFfi, MediaAttachmentReferenceFfi,
    MediaDownloadResultFfi, MediaLocatorFfi, MediaRecordFfi, MediaUploadAttachmentRequestFfi,
    MediaUploadAttachmentResultFfi, MediaUploadRequestFfi, MediaUploadResultFfi,
    MessageDraftAttachmentFfi, MessageDraftAttachmentSummaryFfi, MessageDraftFfi,
    MessageDraftSummaryFfi, NotificationCollectionStatusFfi, NotificationSettingsFfi,
    NotificationTrafficClassFfi, NotificationTriggerFfi, NotificationUpdateFfi,
    NotificationUserFfi, NotificationWakeSourceFfi, PushPlatformFfi, PushRegistrationFfi,
    RelayTelemetryResourceFfi, RelayTelemetryRuntimeConfigFfi, RelayTelemetrySettingsFfi,
    RuntimeProjectionUpdateFfi, SecureDeleteExpiredResultFfi, TimelineMessageChangeFfi,
    TimelineMessageQueryFfi, TimelineMessageRecordFfi, TimelinePageFfi,
    TimelineProjectionUpdateFfi, TimelineReactionEmojiFfi, TimelineReactionSummaryFfi,
    TimelineRemoveReasonFfi, TimelineSubscriptionUpdateFfi, TimelineUpdateTriggerFfi,
    TimelineUserReactionFfi,
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
    /// secret store can fail. Call [`Marmot::start`] before subscribing to
    /// events.
    #[uniffi::constructor]
    pub fn new(root_path: String, relay_urls: Vec<String>) -> Result<Arc<Self>, MarmotKitError> {
        Self::open(root_path, relay_urls, MarmotAppConfig::default())
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
        )
    }

    /// Bring the runtime online: reconcile known accounts, start workers,
    /// subscribe to transport events.
    pub async fn start(&self) -> Result<(), MarmotKitError> {
        self.runtime.start().await?;
        Ok(())
    }

    /// Tear the runtime down. Drops all subscriptions; long-lived
    /// [`EventsSubscription`] / [`ChatsSubscription`] / etc. instances on the
    /// host side will see their `next()` return `None` shortly after.
    pub async fn shutdown(&self) {
        self.runtime.shutdown().await;
    }

    /// True once shutdown has started. Host apps can use this to avoid
    /// launching more subscriptions or account work while they are moving to
    /// the background.
    pub fn is_stopping(&self) -> bool {
        self.runtime.is_stopping()
    }
}

impl Marmot {
    /// Shared open path behind the exported constructors: keychain-backed
    /// account home, app configured by `config`, runtime pair.
    fn open(
        root_path: String,
        relay_urls: Vec<String>,
        config: MarmotAppConfig,
    ) -> Result<Arc<Self>, MarmotKitError> {
        let account_home = marmot_account::AccountHome::open_with_default_keychain(&root_path)
            .map_err(marmot_app::AppError::from)?;
        let app = MarmotApp::with_relays_and_account_home_and_config(
            &root_path,
            relay_urls,
            account_home,
            config,
        );
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
