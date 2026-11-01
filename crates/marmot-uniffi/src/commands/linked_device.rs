//! This account's own devices, from its device group's roster, renaming
//! and removing them, and whether this device's KeyPackage refresh is held back by its
//! device group.

use crate::Marmot;
use crate::conversions::LinkedDeviceFfi;
use crate::errors::MarmotKitError;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// This account's own devices, from the roster of the device group this
    /// device trusts: this device first, then by when each was linked. Empty
    /// until this device trusts a device group, and always empty in release
    /// builds until the roster's spec lands. Refresh on `LinkedDevicesChanged`.
    pub async fn linked_devices(
        &self,
        account_ref: String,
    ) -> Result<Vec<LinkedDeviceFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .linked_devices(&account_ref)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Whether this device's KeyPackage refresh is overdue because its
    /// device group can't take the announcement that must come first. While
    /// it is, warn the user: after 30 days inviters stop treating this device
    /// as fresh. Always false until this device trusts a device group, and in
    /// release builds until the device group's spec lands. Refresh on
    /// `KeyPackageRefreshOverdueChanged`.
    pub async fn key_package_refresh_overdue(
        &self,
        account_ref: String,
    ) -> Result<bool, MarmotKitError> {
        Ok(self
            .runtime
            .key_package_refresh_overdue(&account_ref)
            .await?)
    }

    /// Rename one of this account's devices, this one included, by its
    /// `slot_id_hex` from `linked_devices`: one roster commit in the device
    /// group. Any device may rename any device. The label is at most 64
    /// bytes of UTF-8; empty clears it. Refused with `DeviceGroupRefused`:
    /// `roster_unsupported` (release builds), `label_too_long`,
    /// `no_device_group`, `unknown_device`, `roster_unavailable`, or
    /// `device_group_busy` while the device group has an earlier change in
    /// flight (retry later). A rename whose commit loses a fork is made again
    /// on a later maintenance pass, unless another rename of that device won;
    /// refresh on `LinkedDevicesChanged`.
    pub async fn rename_linked_device(
        &self,
        account_ref: String,
        slot_id_hex: String,
        label: String,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .rename_linked_device(&account_ref, slot_id_hex, label)
            .await?)
    }

    /// Remove another of this account's devices, by its `slot_id_hex` from
    /// `linked_devices`, from the device group and every chat, and delete
    /// its KeyPackage slot so inviters stop adding it. The decision is
    /// recorded at once and carried out as the device group allows;
    /// `linked_devices` shows the device with `removal_pending` until the
    /// device group takes it. Refused with `DeviceGroupRefused`:
    /// `roster_unsupported` (release builds), `no_device_group`,
    /// `unknown_device`, `this_device` (sign out instead),
    /// `device_link_pending` while the device's link may still fail, or
    /// `roster_unavailable`. Refresh on `LinkedDevicesChanged`.
    pub async fn remove_linked_device(
        &self,
        account_ref: String,
        slot_id_hex: String,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .remove_linked_device(&account_ref, slot_id_hex)
            .await?)
    }

    /// How many chats this device is in still hold a device this account
    /// removed, because the chat doesn't take a same-account removal; a chat
    /// admin can remove it. Zero until this device trusts a device group,
    /// and always zero in release builds until the device group's spec
    /// lands. Read it when showing the device list; it is not evented.
    pub async fn removed_device_leftover_chats(
        &self,
        account_ref: String,
    ) -> Result<u32, MarmotKitError> {
        Ok(self
            .runtime
            .removed_device_leftover_chats(&account_ref)
            .await?)
    }

    /// How many chats this device is in can't take any device of this
    /// account, linked or not: they don't require
    /// `marmot.group.account-devices.v1`, name no relays a sibling Welcome
    /// can carry, or already hold this account's limit of 20 leaves (mdk#2628
    /// item 3.5c). A newly linked device is added to this device's other
    /// chats. A chat admin can turn the component on; removing a device frees
    /// its leaves.
    /// Zero until this device trusts a device group, and always zero in
    /// release builds until the device group's spec lands. Read it when
    /// showing the device list; it is not evented.
    pub async fn chats_closed_to_linked_devices(
        &self,
        account_ref: String,
    ) -> Result<u32, MarmotKitError> {
        Ok(self
            .runtime
            .chats_closed_to_linked_devices(&account_ref)
            .await?)
    }
}
