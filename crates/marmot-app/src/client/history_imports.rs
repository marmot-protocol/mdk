//! What a host shows of chat history from the account's other devices
//! (mdk#2628 4.2d, D78).
//!
//! - Each timeline row imported from another device names it in
//!   `imported_from`, so a host draws "Imported from <device>" where rows
//!   change from imported to live. The name is resolved when the row is
//!   read: storage keeps the roster's names for this connection only, and
//!   this device gives it them again each time the linked devices may have
//!   changed. A name is empty for a device that has none, is no longer on
//!   the roster, or before this device first read the roster; a host then
//!   says "another device".
//! - [`AppClient::chat_history_imports`] lists each held chat whose history
//!   is arriving or has arrived, and `ChatHistoryImportsChanged` says to
//!   read it again. Only facts are shown: an empty history sends nothing, so
//!   no chat waits for one, and an expired delivery leaves nothing behind.

use super::AppClient;
use crate::AppError;
use storage_sqlite::HistoryImportSource;

const TRACE_TARGET: &str = "marmot_app::client::history_imports";

/// A held chat whose history from another of this account's devices is
/// arriving or has arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatHistoryImport {
    pub group_id_hex: String,
    pub state: ChatHistoryImportState,
}

/// Where a chat's history stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatHistoryImportState {
    /// A delivery arrived and waits for its chat or its bundle. `retrying`
    /// once fetching one of its bundles failed; it is tried again later.
    Receiving { retrying: bool },
    /// Its latest import: the device it came from, and when, in Unix
    /// seconds.
    Imported { from: HistoryImportSource, at: u64 },
}

impl AppClient {
    /// The held chats whose history is arriving or has arrived, by chat id.
    /// A chat with a delivery still waiting reads `Receiving`, even after an
    /// earlier import. Empty while device groups are off.
    pub(crate) fn chat_history_imports(&self) -> Result<Vec<ChatHistoryImport>, AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(Vec::new());
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let held = |group_id_hex: &str| {
            self.state
                .groups
                .iter()
                .any(|group| group.group_id_hex == group_id_hex)
        };
        let mut imports = std::collections::BTreeMap::new();
        for latest in storage.latest_history_imports()? {
            imports.insert(
                latest.group_id_hex,
                ChatHistoryImportState::Imported {
                    from: latest.source,
                    at: latest.imported_at,
                },
            );
        }
        for parked in storage.parked_history_chats()? {
            imports.insert(
                parked.group_id_hex,
                ChatHistoryImportState::Receiving {
                    retrying: parked.retrying,
                },
            );
        }
        Ok(imports
            .into_iter()
            .filter(|(group_id_hex, _)| held(group_id_hex))
            .map(|(group_id_hex, state)| ChatHistoryImport {
                group_id_hex,
                state,
            })
            .collect())
    }

    /// Give storage the roster's device names, so imported rows name their
    /// source. The worker calls it whenever the linked devices may have
    /// changed. None while device groups are off or no device group is
    /// trusted; a roster that can't be read keeps the names given last.
    pub(crate) fn refresh_device_labels(&mut self) {
        let labels = match self.trusted_device_roster() {
            Ok(roster) => roster
                .map(|(_, roster)| {
                    roster
                        .devices
                        .into_iter()
                        .map(|(slot, entry)| (slot, entry.label))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            Err(error) => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    method = "refresh_device_labels",
                    error_kind = error.privacy_safe_kind(),
                    "device names not refreshed; keeping the last ones"
                );
                return;
            }
        };
        let set = self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.app_storage().set_device_labels(&labels)?));
        if let Err(error) = set {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "refresh_device_labels",
                error_kind = error.privacy_safe_kind(),
                "device names not refreshed"
            );
        }
    }

    /// Whether to announce `ChatHistoryImportsChanged`, clearing the flag.
    /// Never while device groups are off.
    pub(crate) fn take_chat_history_imports_changed(&mut self) -> bool {
        std::mem::take(&mut self.chat_history_imports_changed) && self.app.device_groups_enabled()
    }
}
