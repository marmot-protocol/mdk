//! Renaming this account's devices (mdk#2628 item 3.6).
//!
//! Any device may rename any device, itself included: one roster commit in the
//! device group this device trusts, setting one entry's label and keeping every
//! other field as the roster holds it, through the runtime's one roster write
//! path. While that group cannot take a commit from this device, a rename is
//! refused and nothing is sent.
//!
//! A rename whose commit loses a fork to one that also changes that device's
//! entry is not made again; the Devices screen shows the winning label. The
//! engine re-issues it when the winner left that entry alone.

use cgka_traits::app_components::DEVICE_ROSTER_TEXT_MAX_LEN;
use marmot_session::{DeviceRosterEdit, DeviceRosterEditBlocked};

use super::AppClient;
use super::device_group::device_slot;
use crate::AppError;

impl AppClient {
    /// Rename one of this account's devices: set the label of `slot_id_hex`'s
    /// roster entry. The label is at most 64 bytes of UTF-8; empty clears it.
    ///
    /// Refused with nothing sent when device groups are off, with no trusted
    /// device group, for a slot the roster doesn't list (`unknown_device`),
    /// and while the device group cannot take a commit from this device now
    /// (`device_group_busy`; retry later).
    pub(crate) async fn rename_linked_device(
        &mut self,
        slot_id_hex: &str,
        label: &str,
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        if label.len() > DEVICE_ROSTER_TEXT_MAX_LEN {
            return Err(AppError::DeviceGroupRefused("label_too_long"));
        }
        let slot =
            device_slot(slot_id_hex).map_err(|_| AppError::DeviceGroupRefused("unknown_device"))?;
        self.sync_runtime_groups_for_send("rename_linked_device")
            .await?;
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Err(AppError::DeviceGroupRefused("no_device_group"));
        };
        if !roster.devices.contains_key(&slot) {
            return Err(AppError::DeviceGroupRefused("unknown_device"));
        }
        let held = self.epoch_gap_held_groups()?;
        let edit = self
            .runtime
            .edit_device_roster_entry(&group_id, &slot, &held, |entry| {
                entry.label = label.to_owned();
            })
            .await?;
        match edit {
            DeviceRosterEdit::Committed(effects) => {
                self.linked_devices_changed = true;
                self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                    .await
            }
            DeviceRosterEdit::Unchanged => Ok(()),
            DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::NoEntry) => {
                Err(AppError::DeviceGroupRefused("unknown_device"))
            }
            DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::Unreadable) => {
                Err(AppError::DeviceGroupRefused("roster_unavailable"))
            }
            DeviceRosterEdit::Blocked(blocked @ DeviceRosterEditBlocked::Busy) => {
                Err(AppError::DeviceGroupRefused(blocked.reason()))
            }
        }
    }
}
