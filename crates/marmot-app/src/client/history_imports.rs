//! What a host shows of chat history from the account's other devices
//! (mdk#2628 4.2d, D78).
//!
//! - Each timeline row imported from another device names it in
//!   `imported_from`, so a host draws "Imported from <device>" where rows
//!   change from imported to live. The name is resolved when the row is
//!   read: storage keeps the roster's names for this connection only, and
//!   this device gives it them whenever it reads the roster for the linked
//!   devices, each time those may have changed, and before an import while
//!   that change is not yet announced. A name is empty for a device that has
//!   none, is no longer on the roster, or before this device first read the
//!   roster; a host then says "another device".
//! - [`AppClient::chat_history_imports`] lists each held chat whose history
//!   is arriving or has arrived, and `ChatHistoryImportsChanged` fires
//!   exactly when that answer changes. Storage counts every change to what
//!   the answer reads (imported rows, parked deliveries, device names), so
//!   a seam reads the answer again only when that count or the held chats
//!   moved, and announces only if the answer differs from the one it last
//!   announced. Only facts are shown: an empty history sends nothing, so no
//!   chat waits for one, and an expired delivery leaves nothing behind.

use super::AppClient;
use crate::AppError;
use cgka_traits::app_components::{DeviceRosterV1, DeviceSlotId};
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
    /// A delivery arrived and waits to be imported, as while its bundle is
    /// fetched. `retrying` once an attempt to get one of its bundles failed;
    /// it is tried again later.
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
        // A delivery that arrived before its chat lists once the chat is
        // held; a host could not name it before.
        let held = |group_id_hex: &str| {
            self.state
                .groups
                .iter()
                .any(|group| group.group_id_hex == group_id_hex)
        };
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
    /// source. Called whenever the linked devices may have changed, and by
    /// an import before that change is announced. Nothing while device
    /// groups are off; no names while no device group is trusted; a roster
    /// that can't be read keeps the names given last.
    pub(crate) fn refresh_device_labels(&mut self) {
        if !self.app.device_groups_enabled() {
            return;
        }
        match self.trusted_device_roster() {
            Ok(roster) => self.give_device_labels(roster.as_ref().map(|(_, roster)| roster)),
            Err(error) => tracing::debug!(
                target: TRACE_TARGET,
                method = "refresh_device_labels",
                error_kind = error.privacy_safe_kind(),
                "device names not refreshed; keeping the last ones"
            ),
        }
    }

    /// Give storage the device names in `roster`, or none without one.
    pub(crate) fn give_device_labels(&self, roster: Option<&DeviceRosterV1>) {
        let labels: Vec<(DeviceSlotId, String)> = roster
            .map(|roster| {
                roster
                    .devices
                    .iter()
                    .map(|(slot, entry)| (*slot, entry.label.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let set = self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.app_storage().set_device_labels(&labels)?));
        if let Err(error) = set {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "give_device_labels",
                error_kind = error.privacy_safe_kind(),
                "device names not refreshed"
            );
        }
    }

    /// Whether to announce `ChatHistoryImportsChanged`: once as the client
    /// opens, then whenever [`Self::chat_history_imports`] answers
    /// differently from the answer last announced. It reads that answer
    /// again only when storage's change count or the held chats moved, so
    /// most calls read one counter. A failed read waits for the next call.
    /// Never while device groups are off.
    pub(crate) fn take_chat_history_imports_changed(&mut self) -> bool {
        let opened = std::mem::take(&mut self.chat_history_imports_changed);
        if !self.app.device_groups_enabled() {
            return false;
        }
        let answer = self
            .history_imports_inputs_moved()
            .and_then(|moved| moved.then(|| self.chat_history_imports()).transpose());
        match answer {
            Ok(None) => opened,
            Ok(Some(answer)) => {
                let changed = answer != self.listed_history_imports;
                self.listed_history_imports = answer;
                changed || opened
            }
            Err(error) => {
                // Read everything again next time.
                self.history_imports_inputs = None;
                tracing::debug!(
                    target: TRACE_TARGET,
                    method = "take_chat_history_imports_changed",
                    error_kind = error.privacy_safe_kind(),
                    "chat history imports not compared"
                );
                opened
            }
        }
    }

    /// Whether storage's count of changes chat history imports read, or the
    /// held chats, moved since the last call. The first call starts the
    /// count on this connection and always reads as moved.
    fn history_imports_inputs_moved(&mut self) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        if self.history_imports_inputs.is_none() {
            storage.watch_history_imports()?;
        }
        let mut held = std::collections::hash_map::DefaultHasher::new();
        for group in &self.state.groups {
            std::hash::Hash::hash(&group.group_id_hex, &mut held);
        }
        let inputs = (
            storage.history_imports_generation()?,
            std::hash::Hasher::finish(&held),
        );
        Ok(self.history_imports_inputs.replace(inputs) != Some(inputs))
    }
}
