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
use marmot_app::{MarmotApp, MarmotAppRuntime, TimelineMessageQuery, TimelinePagination};

mod commands;
mod conversions;
mod errors;
mod markdown;
mod subscriptions;

use conversions::group_id_from_hex;
pub use errors::MarmotKitError;
pub use markdown::{
    MarkdownAlignmentFfi, MarkdownAutolinkKindFfi, MarkdownBlockFfi, MarkdownCodeBlockKindFfi,
    MarkdownDocumentFfi, MarkdownInlineFfi, MarkdownListItemFfi, MarkdownListKindFfi,
    MarkdownNostrEntityFfi, MarkdownNostrHrpFfi, MarkdownTableCellFfi,
};

uniffi::setup_scaffolding!();

pub use conversions::{
    AppBlobEndpointFfi, AppGroupEncryptedMediaComponentFfi, AuditLogDeleteResultFfi,
    AuditLogFileFfi, AuditLogSettingsFfi, AuditLogTrackerConfigFfi, AuditLogTrackerUpdateResultFfi,
    AuditLogUploadResultFfi, AuditLogUploadSourceFfi, BackgroundNotificationCollectionFfi,
    ChatListAvatarFfi, ChatListMessagePreviewFfi, ChatListRowFfi, ChatListSubscriptionUpdateFfi,
    ChatListUpdateTriggerFfi, GroupPushDebugInfoFfi, GroupPushTokenDebugEntryFfi,
    GroupSystemEventFfi, LocalPushRegistrationDebugFfi, MediaAttachmentReferenceFfi,
    MediaDownloadResultFfi, MediaLocatorFfi, MediaRecordFfi, MediaUploadAttachmentRequestFfi,
    MediaUploadAttachmentResultFfi, MediaUploadRequestFfi, MediaUploadResultFfi,
    NotificationCollectionStatusFfi, NotificationSettingsFfi, NotificationTriggerFfi,
    NotificationUpdateFfi, NotificationUserFfi, NotificationWakeSourceFfi, PushPlatformFfi,
    PushRegistrationFfi, RelayTelemetryResourceFfi, RelayTelemetryRuntimeConfigFfi,
    RelayTelemetrySettingsFfi, RuntimeProjectionUpdateFfi, TimelineMessageChangeFfi,
    TimelineMessageQueryFfi, TimelineMessageRecordFfi, TimelinePageFfi,
    TimelineProjectionUpdateFfi, TimelineReactionEmojiFfi, TimelineReactionSummaryFfi,
    TimelineRemoveReasonFfi, TimelineSubscriptionUpdateFfi, TimelineUpdateTriggerFfi,
    TimelineUserReactionFfi,
};

/// Convenience: turn an FFI string list of relay URLs into the engine's
/// [`TransportEndpoint`] wrapper, dedup-stripped of empties.
pub(crate) fn endpoints(urls: &[String]) -> Vec<TransportEndpoint> {
    urls.iter()
        .filter(|u| !u.trim().is_empty())
        .map(|u| TransportEndpoint::from(u.as_str()))
        .collect()
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
        let account_home = marmot_account::AccountHome::open_with_default_keychain(&root_path)
            .map_err(marmot_app::AppError::from)?;
        let app = MarmotApp::with_relays_and_account_home(&root_path, relay_urls, account_home);
        let runtime = app.runtime();
        Ok(Arc::new(Self { app, runtime }))
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
            optional_group_id_hex(Some(format!(" {} ", "AB".repeat(32)))).unwrap(),
            Some("ab".repeat(32))
        );
        // Invalid hex is rejected rather than silently yielding empty history.
        assert!(optional_group_id_hex(Some("nothex".into())).is_err());
    }
}
