//! The compromise warning (mdk#2628 item 3.7a, D53): someone holding the
//! account's signing key published where the account's devices did not.
//!
//! - **What it gathers.** Every `not_me` rejected slot, in the trusted device
//!   group's roster or among this device's own rejections, and every rejected
//!   KeyPackage in the roster. A `removed` slot is not a rejection in this
//!   sense. Later items join the open warning rather than raising another.
//! - **When.** At open, after every roster change, and after this device
//!   answers This wasn't me. Gathering runs at the next publication seam or
//!   host read, so a roster that changes many times in one batch is gathered
//!   once.
//! - **Seen.** Each device keeps its own seen marks. Dismiss marks
//!   everything the warning then gathers as seen, on this device only. An
//!   item stays seen when branch selection drops and restores it.
//! - **A device's first roster.** Rejections already in the first roster
//!   this device trusts from a device group count as seen (D68): the user saw
//!   them on the devices that were there. Its own rejections from before it
//!   joined still warn. The device takes that roster in the same write that
//!   trusts the group (`trust_device_group`), so a rejection committed later
//!   is never taken for one of them. Only a group trusted before migration
//!   0148 has no baseline; its first gather takes one.
//! - **Ended rejections.** A rejected sign-in the user has not seen leaves
//!   the warning once neither this device nor the roster holds it, as when
//!   the user links its slot; it warns again if it stands again.
//!
//! The wording is the host's. Everything here runs only while device groups
//! are on.

use std::collections::BTreeSet;

use cgka_traits::GroupId;
use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DeviceRosterV1, RejectedSlotReasonV1, decode_device_roster_v1,
};
use storage_sqlite::{
    CompromiseWarningGather, DeviceGroupTrust, FirstTrustedRoster, ObservedWarningItem,
    SignInAnswer,
};

use super::AppClient;
use crate::{AppError, unix_now_seconds};

/// Why something is in the compromise warning. More reasons follow: a removed
/// device trying to come back (3.6b), and leaves removed from chats, or chats
/// that could not be cleaned (3.7c). Hosts should show a reason they do not
/// know as a generic one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompromiseWarningReason {
    /// A sign-in the user answered This wasn't me, on this device or another.
    RejectedSignIn,
    /// A KeyPackage one of the account's devices found where they had not
    /// published, and rejected.
    RejectedKeyPackage,
}

/// One thing the open compromise warning gathers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompromiseWarningItem {
    pub reason: CompromiseWarningReason,
    /// The KeyPackage slot (the Nostr `d`) the rejection names: the rejected
    /// sign-in's, or the one the rejected KeyPackage appeared in.
    pub slot_id_hex: String,
    /// The rejected KeyPackage's `KeyPackageRef`, for `RejectedKeyPackage`.
    pub key_package_ref_hex: Option<String>,
    /// When the rejection was made, in Unix seconds, as the device that made
    /// it wrote it.
    pub occurred_at: u64,
}

impl AppClient {
    /// The open compromise warning: everything it gathers that the user has
    /// not seen on this device, the earliest gathered first. Empty when no
    /// warning is open, and while device groups are off.
    pub(crate) fn compromise_warning(&mut self) -> Result<Vec<CompromiseWarningItem>, AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(Vec::new());
        }
        self.gather_compromise_warning_if_due()?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        Ok(storage
            .compromise_warning()?
            .into_iter()
            .map(|record| {
                let (reason, key_package_ref_hex) = match record.reason {
                    storage_sqlite::CompromiseWarningReason::RejectedSignIn => {
                        (CompromiseWarningReason::RejectedSignIn, None)
                    }
                    storage_sqlite::CompromiseWarningReason::RejectedKeyPackage => (
                        CompromiseWarningReason::RejectedKeyPackage,
                        Some(record.subject),
                    ),
                };
                CompromiseWarningItem {
                    reason,
                    slot_id_hex: record.slot_id_hex,
                    key_package_ref_hex,
                    occurred_at: record.occurred_at,
                }
            })
            .collect())
    }

    /// Dismiss the compromise warning on this device: everything it gathers
    /// now is seen, and it stays closed until something new arrives. Other
    /// devices' warnings are unchanged.
    pub(crate) fn dismiss_compromise_warning(&mut self) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        self.gather_compromise_warning_if_due()?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        if storage.dismiss_compromise_warning(unix_now_seconds())? {
            self.compromise_warning_changed = true;
        }
        Ok(())
    }

    /// Gather again at the next seam or host read: the roster changed, or
    /// this device rejected a sign-in.
    pub(crate) fn note_compromise_warning_due(&mut self) {
        self.compromise_warning_gather_due = true;
    }

    /// Whether the open compromise warning may have changed since the last
    /// call, gathering first if a gather is due. Set at open. A gather that
    /// fails is retried at the next seam.
    pub(crate) fn take_compromise_warning_changed(&mut self) -> bool {
        if !self.app.device_groups_enabled() {
            return false;
        }
        if let Err(error) = self.gather_compromise_warning_if_due() {
            tracing::warn!(
                target: "marmot_app::client::compromise_warning",
                method = "take_compromise_warning_changed",
                error_kind = error.privacy_safe_kind(),
                "could not gather the compromise warning; retrying at the next seam"
            );
        }
        std::mem::take(&mut self.compromise_warning_changed)
    }

    fn gather_compromise_warning_if_due(&mut self) -> Result<(), AppError> {
        if !self.compromise_warning_gather_due {
            return Ok(());
        }
        self.gather_compromise_warning()?;
        self.compromise_warning_gather_due = false;
        Ok(())
    }

    /// Record every rejection this device and its trusted roster hold.
    fn gather_compromise_warning(&mut self) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let now = unix_now_seconds();
        let trusted = self.trusted_device_roster()?;
        let (own, roster) =
            self.observed_rejections(trusted.as_ref().map(|(_, roster)| roster), now)?;
        let device_group_id_hex = trusted
            .as_ref()
            .map(|(group_id, _)| hex::encode(group_id.as_slice()));
        if storage.record_compromise_warning(&CompromiseWarningGather {
            own: &own,
            roster: &roster,
            device_group_id_hex: device_group_id_hex.as_deref(),
            now,
        })? {
            self.compromise_warning_changed = true;
        }
        Ok(())
    }

    /// Move the device group's row into the trusted state `to`, and in the
    /// same write take the roster it holds now as the first this device
    /// trusts (mdk#2628 3.7a, D68): the warning counts that roster's
    /// rejections as seen and this device's own as unseen. Every move into a
    /// trusted state goes through here; storage refuses one that does not.
    ///
    /// A device that created the group takes no roster rejections, since its
    /// founding roster holds only its own (D41); so a restart that settles a
    /// creation never takes a later commit's as seen. A roster that cannot be
    /// read counts as holding none, so its rejections warn once it can.
    /// Returns whether the row moved.
    pub(crate) fn trust_device_group(
        &mut self,
        group_id: &GroupId,
        from: DeviceGroupTrust,
        to: DeviceGroupTrust,
        recorded_at: u64,
    ) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let roster = if to == DeviceGroupTrust::Linked {
            self.held_device_roster(group_id)
        } else {
            None
        };
        let now = unix_now_seconds();
        let (own, roster) = self.observed_rejections(roster.as_ref(), now)?;
        let Some(changed) = storage.trust_device_group(
            &hex::encode(group_id.as_slice()),
            from,
            to,
            None,
            recorded_at,
            &FirstTrustedRoster {
                own: &own,
                roster: &roster,
                now,
            },
        )?
        else {
            return Ok(false);
        };
        if changed && self.app.device_groups_enabled() {
            self.compromise_warning_changed = true;
        }
        Ok(true)
    }

    /// The roster `group_id` holds now, if it can be read.
    fn held_device_roster(&mut self, group_id: &GroupId) -> Option<DeviceRosterV1> {
        if !self.runtime.ensure_group_hydrated(group_id).ok()? {
            return None;
        }
        self.runtime
            .app_component(group_id, DEVICE_ROSTER_COMPONENT_ID)
            .ok()
            .flatten()
            .and_then(|bytes| decode_device_roster_v1(&bytes).ok())
    }

    /// This device's own rejections and the ones `roster` holds, as the
    /// warning gathers them.
    fn observed_rejections(
        &self,
        roster: Option<&DeviceRosterV1>,
        now: u64,
    ) -> Result<(Vec<ObservedWarningItem>, Vec<ObservedWarningItem>), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let linked_slots: BTreeSet<String> = roster
            .iter()
            .flat_map(|roster| roster.devices.keys().map(hex::encode))
            .collect();
        // A rejection of a slot the user has since linked has ended, even
        // while this device's record of it waits to be settled.
        let own = storage
            .sign_ins()?
            .into_iter()
            .filter(|record| {
                record.answer == SignInAnswer::Rejected
                    && !linked_slots.contains(&record.slot_id_hex)
            })
            .map(|record| ObservedWarningItem {
                reason: storage_sqlite::CompromiseWarningReason::RejectedSignIn,
                subject: record.slot_id_hex.clone(),
                slot_id_hex: record.slot_id_hex,
                occurred_at: record.answered_at.unwrap_or(now),
            })
            .collect();
        let mut rejected = Vec::new();
        if let Some(roster) = roster {
            for (slot, entry) in &roster.rejected_slots {
                if entry.reason == RejectedSlotReasonV1::NotMe {
                    let slot = hex::encode(slot);
                    rejected.push(ObservedWarningItem {
                        reason: storage_sqlite::CompromiseWarningReason::RejectedSignIn,
                        subject: slot.clone(),
                        slot_id_hex: slot,
                        occurred_at: entry.rejected_at,
                    });
                }
            }
            for (key_package_ref, entry) in &roster.rejected_key_packages {
                rejected.push(ObservedWarningItem {
                    reason: storage_sqlite::CompromiseWarningReason::RejectedKeyPackage,
                    subject: hex::encode(key_package_ref),
                    slot_id_hex: hex::encode(entry.slot),
                    occurred_at: entry.rejected_at,
                });
            }
        }
        Ok((own, rejected))
    }
}
