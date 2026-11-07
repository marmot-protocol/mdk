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

/// Identity of an archive, not proof of original writer/authorship or past membership.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupHistorySourceFfi {
    pub recovery_public_key_hex: String,
    pub backup_id_hex: String,
    pub head_sha256_hex: String,
    pub written_at: u64,
}
impl From<marmot_app::BackupHistorySource> for BackupHistorySourceFfi {
    fn from(value: marmot_app::BackupHistorySource) -> Self {
        Self {
            recovery_public_key_hex: hex::encode(value.recovery_public_key),
            backup_id_hex: hex::encode(value.backup_id),
            head_sha256_hex: hex::encode(value.head_sha256),
            written_at: value.written_at,
        }
    }
}
/// Complete import source. Backup imports never invent a device slot/label.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum HistoryImportProvenanceFfi {
    Device { device_slot_id_hex: String },
    Backup { source: BackupHistorySourceFfi },
}
impl From<marmot_app::HistoryImportProvenance> for HistoryImportProvenanceFfi {
    fn from(value: marmot_app::HistoryImportProvenance) -> Self {
        match value {
            marmot_app::HistoryImportProvenance::Device(slot) => Self::Device {
                device_slot_id_hex: hex::encode(slot),
            },
            marmot_app::HistoryImportProvenance::Backup(source) => Self::Backup {
                source: source.into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiving_and_imported_history_preserve_their_distinct_contexts() {
        for retrying in [false, true] {
            let value = ChatHistoryImportFfi::from(ChatHistoryImport {
                group_id_hex: "ab".repeat(16),
                state: ChatHistoryImportState::Receiving { retrying },
            });
            assert_eq!(value.group_id_hex, "ab".repeat(16));
            assert_eq!(
                value.state,
                ChatHistoryImportStateFfi::Receiving { retrying }
            );
        }
        let value = ChatHistoryImportFfi::from(ChatHistoryImport {
            group_id_hex: "cd".repeat(16),
            state: ChatHistoryImportState::Imported {
                from: HistoryImportSource {
                    device_slot_id_hex: "11".repeat(32),
                    device_label: "Desk device".into(),
                },
                at: 71,
            },
        });
        assert_eq!(value.group_id_hex, "cd".repeat(16));
        assert_eq!(
            value.state,
            ChatHistoryImportStateFfi::Imported {
                from: HistoryImportSourceFfi {
                    device_slot_id_hex: "11".repeat(32),
                    device_label: "Desk device".into()
                },
                at: 71,
            }
        );
    }

    #[test]
    fn device_history_provenance_keeps_its_slot_identity() {
        let device = HistoryImportProvenanceFfi::from(marmot_app::HistoryImportProvenance::Device(
            [0x12; 32],
        ));
        assert_eq!(
            device,
            HistoryImportProvenanceFfi::Device {
                device_slot_id_hex: "12".repeat(32)
            }
        );
        // The cached-conversion keeper already owns literal Backup provenance
        // and its archive fields; this owner supplies only the Device contrast.
    }
}
