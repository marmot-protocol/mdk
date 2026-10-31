//! A chat's history moved from one of the account's devices to another
//! (mdk#2628 4.2a).
//!
//! The sending device packs its history of one chat into bundles
//! (`history_bundle.rs`), and the receiving device imports each one. The
//! transport through the device group is not built yet, so the
//! `test-policy-overrides` hooks are the only callers. An import only adds
//! rows: storage never overwrites a held row, marks each new one with the
//! sending device's slot, and never counts it as unread.

use super::AppClient;
use crate::history_bundle::{
    BundledEvent, ChatPosition, HISTORY_BUNDLE_MAX_PLAINTEXT, HistoryBundle, HistoryBundleBuilder,
    open_history_bundle,
};
use crate::media::media_imeta_tags_preserve_message;
use crate::{AppError, AppProjectionUpdate, unix_now_seconds};
use cgka_traits::MarmotAppEvent;
use cgka_traits::app_components::DeviceSlotId;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM};
use cgka_traits::types::GroupId;
use storage_sqlite::ImportedAppEvent;

const TRACE_TARGET: &str = "marmot_app::chat_history";
/// Rows read from storage at a time while filling a bundle.
const EXPORT_PAGE_ROWS: usize = 512;

impl AppClient {
    /// The next bundle of the chat `group_id`'s history after `after`, the
    /// previous bundle's `to`, or from the start. None once nothing follows.
    #[cfg_attr(not(feature = "test-policy-overrides"), allow(dead_code))]
    pub(crate) fn export_chat_history(
        &self,
        group_id: &GroupId,
        after: Option<&ChatPosition>,
    ) -> Result<Option<HistoryBundle>, AppError> {
        let group_id_hex = self.history_chat(group_id)?;
        let storage = self.app.account_storage(&self.state.label)?;
        let now = unix_now_seconds();
        // Every page of one bundle comes from one snapshot, so a row that lands
        // inside the stretch already read is never vouched for but left out.
        cgka_traits::StorageProvider::with_read_snapshot(&storage, |storage| {
            let storage = storage.app_storage();
            let mut bundle = HistoryBundleBuilder::new(
                group_id.as_slice(),
                after.cloned(),
                HISTORY_BUNDLE_MAX_PLAINTEXT,
            );
            let mut cursor = after.cloned();
            loop {
                let page = storage.history_export_page(
                    &group_id_hex,
                    cursor
                        .as_ref()
                        .map(|position| (position.epoch, position.at, position.id.as_str())),
                    now,
                    EXPORT_PAGE_ROWS,
                )?;
                let last_page = page.len() < EXPORT_PAGE_ROWS;
                for row in page {
                    let position = ChatPosition::of_row(&row);
                    let event = row
                        .event
                        .map(|event| BundledEvent::exported(event, row.source_epoch));
                    if !bundle.take(position.clone(), event) {
                        return Ok(bundle.finish());
                    }
                    cursor = Some(position);
                }
                if last_page {
                    return Ok(bundle.finish());
                }
            }
        })
    }

    /// Import one bundle of the chat `group_id`'s history, sent by the device
    /// at `source_slot` with `key` and `ciphertext_sha256`. Returns the
    /// projection change, or none when nothing was new.
    ///
    /// Refuses the whole bundle when its hash differs, it does not decrypt, it
    /// breaks the format, or it names another chat. Drops an event outside the
    /// bundle's stretch, or one that carries an authority verdict its kind does
    /// not take.
    #[cfg_attr(not(feature = "test-policy-overrides"), allow(dead_code))]
    pub(crate) fn import_history_bundle(
        &mut self,
        group_id: &GroupId,
        source_slot: &DeviceSlotId,
        key: &[u8; 32],
        ciphertext_sha256: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<Option<AppProjectionUpdate>, AppError> {
        self.history_chat(group_id)?;
        let bundle = open_history_bundle(key, ciphertext_sha256, ciphertext)?;
        if !bundle.names_chat(group_id.as_slice()) {
            return Err(AppError::DeviceGroupRefused("history_bundle_chat"));
        }
        let count = bundle.events.len();
        let events = bundle
            .events
            .iter()
            .filter(|event| event.in_stretch(&bundle))
            .cloned()
            .map(BundledEvent::imported)
            .collect::<Vec<_>>();
        if events.len() != count {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "import_history_bundle",
                dropped = count - events.len(),
                "dropping history bundle events outside its stretch or with a misplaced verdict",
            );
        }
        self.import_chat_history(group_id, source_slot, &events)
    }

    /// Import `events` into the chat `group_id` as history the device at
    /// `source_slot` sent. Drops an event whose id does not match its content,
    /// a group-system row (those are local to each device), and a chat message
    /// whose encrypted-media reference the live path would reject.
    fn import_chat_history(
        &mut self,
        group_id: &GroupId,
        source_slot: &DeviceSlotId,
        events: &[ImportedAppEvent],
    ) -> Result<Option<AppProjectionUpdate>, AppError> {
        let group_id_hex = self.history_chat(group_id)?;
        let importable = events
            .iter()
            .filter(|event| importable(event, self.app.allow_loopback_blob_endpoints()))
            .cloned()
            .collect::<Vec<_>>();
        if importable.len() != events.len() {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "import_chat_history",
                dropped = events.len() - importable.len(),
                "dropping imported history events that fail their checks",
            );
        }
        self.app.import_account_app_events(
            &self.state.label,
            &group_id_hex,
            source_slot,
            &importable,
        )
    }

    /// The chat's group id as hex, once this device advertises the roster and
    /// holds `group_id` as one of the user's chats, never a device group.
    fn history_chat(&self, group_id: &GroupId) -> Result<String, AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        if self.is_device_group(group_id)? {
            return Err(AppError::DeviceGroupRefused("history_of_device_group"));
        }
        let group_id_hex = hex::encode(group_id.as_slice());
        if !self
            .state
            .groups
            .iter()
            .any(|group| group.group_id_hex == group_id_hex)
        {
            return Err(AppError::UnknownGroup(group_id_hex));
        }
        Ok(group_id_hex)
    }

    /// Test-policy hook: the chat's whole history as sealed bundles, as a
    /// sibling would send them.
    #[cfg(feature = "test-policy-overrides")]
    #[doc(hidden)]
    pub fn dev_export_chat_history(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<DevSealedHistoryBundle>, AppError> {
        let mut sealed = Vec::new();
        let mut after = None;
        while let Some(bundle) = self.export_chat_history(group_id, after.as_ref())? {
            let bundle_sealed = crate::history_bundle::seal_history_bundle(&bundle)?;
            sealed.push(DevSealedHistoryBundle {
                key: *bundle_sealed.key,
                ciphertext_sha256: bundle_sealed.ciphertext_sha256,
                ciphertext: bundle_sealed.ciphertext,
            });
            after = Some(bundle.to);
        }
        Ok(sealed)
    }

    /// Test-policy hook: import one sealed bundle as if a sibling had sent it.
    #[cfg(feature = "test-policy-overrides")]
    #[doc(hidden)]
    pub fn dev_import_history_bundle(
        &mut self,
        group_id: &GroupId,
        source_slot: &DeviceSlotId,
        bundle: &DevSealedHistoryBundle,
    ) -> Result<Option<AppProjectionUpdate>, AppError> {
        self.import_history_bundle(
            group_id,
            source_slot,
            &bundle.key,
            &bundle.ciphertext_sha256,
            &bundle.ciphertext,
        )
    }
}

/// Test-policy view of one sealed history bundle: what the carrying message
/// seals to the receiving device, and the ciphertext.
#[cfg(feature = "test-policy-overrides")]
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct DevSealedHistoryBundle {
    pub key: [u8; 32],
    pub ciphertext_sha256: [u8; 32],
    pub ciphertext: Vec<u8>,
}

fn importable(event: &ImportedAppEvent, allow_loopback_http: bool) -> bool {
    let id = MarmotAppEvent::new(
        &event.sender,
        event.created_at,
        event.kind,
        event.tags.clone(),
        &event.plaintext,
    )
    .id;
    id == event.message_id_hex
        && event.kind != MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
        && (event.kind != MARMOT_APP_EVENT_KIND_CHAT
            || media_imeta_tags_preserve_message(&event.tags, allow_loopback_http))
}
