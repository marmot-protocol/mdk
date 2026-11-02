//! Chat history from another of this account's devices (mdk#2628 4.2d): the
//! device an imported row came from, and each held chat's history state.

use marmot_app::{ChatHistoryImport, ChatHistoryImportState, HistoryImportSource};

/// The device a row or a chat's history was imported from.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct HistoryImportSourceFfi {
    /// The device's roster slot, as `linked_devices` names it.
    pub device_slot_id_hex: String,
    /// The device's name now: empty when it has none, is no longer linked,
    /// or this device has not read the roster since it started. Show
    /// "another device" then. It follows `LinkedDevicesChanged`.
    pub device_label: String,
}

impl From<HistoryImportSource> for HistoryImportSourceFfi {
    fn from(value: HistoryImportSource) -> Self {
        Self {
            device_slot_id_hex: value.device_slot_id_hex,
            device_label: value.device_label,
        }
    }
}

/// Where a chat's history from another device stands.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatHistoryImportStateFfi {
    /// A delivery arrived and waits to be imported, as while its bundle is
    /// fetched. `retrying` once an attempt to get one of its bundles failed;
    /// it is tried again later.
    Receiving { retrying: bool },
    /// Its latest import: the device it came from, and when, in Unix
    /// seconds.
    Imported {
        from: HistoryImportSourceFfi,
        at: u64,
    },
}

/// A held chat whose history from another device is arriving or has
/// arrived.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ChatHistoryImportFfi {
    pub group_id_hex: String,
    pub state: ChatHistoryImportStateFfi,
}

impl From<ChatHistoryImport> for ChatHistoryImportFfi {
    fn from(value: ChatHistoryImport) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            state: match value.state {
                ChatHistoryImportState::Receiving { retrying } => {
                    ChatHistoryImportStateFfi::Receiving { retrying }
                }
                ChatHistoryImportState::Imported { from, at } => {
                    ChatHistoryImportStateFfi::Imported {
                        from: from.into(),
                        at,
                    }
                }
            },
        }
    }
}
