//! This account's own devices, from its device group's roster.

use marmot_app::{LinkedDevice, LinkedDeviceStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LinkedDeviceStatusFfi {
    Active,
    /// Its siblings marked it inactive.
    Inactive,
    /// It recorded that it is signing out.
    Leaving,
}

impl From<LinkedDeviceStatus> for LinkedDeviceStatusFfi {
    fn from(value: LinkedDeviceStatus) -> Self {
        match value {
            LinkedDeviceStatus::Active => Self::Active,
            LinkedDeviceStatus::Inactive => Self::Inactive,
            LinkedDeviceStatus::Leaving => Self::Leaving,
        }
    }
}

/// One of this account's own devices, as the roster of the device group this
/// device trusts lists it. Never another account's device.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct LinkedDeviceFfi {
    /// The device's KeyPackage slot, 64 lowercase hex characters. Actions on
    /// the device name it by this.
    pub slot_id_hex: String,
    /// Whether this is the calling device.
    pub is_this_device: bool,
    /// The name the user gave the device; empty until set.
    pub label: String,
    /// The device's client name; empty until set.
    pub client: String,
    /// The device's platform; empty until set.
    pub platform: String,
    /// When the device was linked, in Unix seconds, as its linker wrote it.
    pub linked_at: u64,
    /// The slot of the device that linked it; `None` for the founder.
    pub linked_by_slot_id_hex: Option<String>,
    pub status: LinkedDeviceStatusFfi,
    /// Its siblings add it to the chats the account's devices were already
    /// in when it was linked.
    pub add_to_all_chats: bool,
    /// Its siblings bring it chat history when they add it to a chat.
    pub bring_history: bool,
    /// Inactivity never removes it.
    pub keep_while_inactive: bool,
    /// The user removed it on this device, and the device group has not
    /// taken the removal yet.
    pub removal_pending: bool,
}

impl From<LinkedDevice> for LinkedDeviceFfi {
    fn from(value: LinkedDevice) -> Self {
        Self {
            slot_id_hex: value.slot_id_hex,
            is_this_device: value.is_this_device,
            label: value.label,
            client: value.client,
            platform: value.platform,
            linked_at: value.linked_at,
            linked_by_slot_id_hex: value.linked_by_slot_id_hex,
            status: value.status.into(),
            add_to_all_chats: value.add_to_all_chats,
            bring_history: value.bring_history,
            keep_while_inactive: value.keep_while_inactive,
            removal_pending: value.removal_pending,
        }
    }
}
