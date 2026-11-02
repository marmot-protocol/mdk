//! Linking a new device of this account: the code both screens show, then
//! joining the account's device group. Every call is refused in release
//! builds until the pairing and device-group specs land.

use crate::Marmot;
use crate::conversions::DeviceLinkSnapshotFfi;
use crate::errors::MarmotKitError;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// On a new device: ask a device of this account already signed in to
    /// link this one. Show "waiting" until the snapshot's `new_device` shows
    /// the code. Refresh on `DeviceLinkChanged`.
    pub async fn start_device_link(
        &self,
        account_ref: String,
    ) -> Result<DeviceLinkSnapshotFfi, MarmotKitError> {
        Ok(self.runtime.start_device_link(&account_ref).await?.into())
    }

    /// On the new device: the user says both screens show the same emoji.
    pub async fn confirm_device_link_match(
        &self,
        account_ref: String,
    ) -> Result<DeviceLinkSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .confirm_device_link_match(&account_ref)
            .await?
            .into())
    }

    /// On the new device: cancel the link.
    pub async fn cancel_device_link(
        &self,
        account_ref: String,
    ) -> Result<DeviceLinkSnapshotFfi, MarmotKitError> {
        Ok(self.runtime.cancel_device_link(&account_ref).await?.into())
    }

    /// On a device already signed in: Link device. `label` is the name the
    /// user gave the new device, at most 64 bytes. Offer both settings on by
    /// default: `add_to_all_chats` adds it to the chats this account's
    /// devices are in, and `bring_history` brings it those chats' history.
    pub async fn link_device(
        &self,
        account_ref: String,
        prompt_id: String,
        label: String,
        add_to_all_chats: bool,
        bring_history: bool,
    ) -> Result<DeviceLinkSnapshotFfi, MarmotKitError> {
        let choices = marmot_app::DeviceLinkChoices {
            label,
            add_to_all_chats,
            bring_history,
        };
        Ok(self
            .runtime
            .link_device(&account_ref, &prompt_id, choices)
            .await?
            .into())
    }

    /// On a device already signed in: Not now.
    pub async fn decline_device_link(
        &self,
        account_ref: String,
        prompt_id: String,
    ) -> Result<DeviceLinkSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .decline_device_link(&account_ref, &prompt_id)
            .await?
            .into())
    }

    /// Linking as this device shows it now: its own new-device link, if
    /// any, and the prompts for sign-ins it can link. Re-read on
    /// `DeviceLinkChanged`.
    pub async fn device_link_snapshot(
        &self,
        account_ref: String,
    ) -> Result<DeviceLinkSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .device_link_snapshot(&account_ref)
            .await?
            .into())
    }
}
