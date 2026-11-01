//! Signing out through siblings (mdk#2628 item 3.6b, D67(2)).
//!
//! `sign_out_and_wipe` asks this device's siblings to take it out of the
//! account's groups when it can: it trusts a device group, its own roster
//! entry has its tag signature key, and the roster lists another device that
//! is not `leaving`. It commits its own entry with status `leaving` and,
//! once that commit is confirmed, leaves itself every chat except the ones a
//! sibling takes it out of: chats that require
//! `marmot.group.account-devices.v1` where its own leaf's device tag reads
//! as its slot and another leaf's as a sibling that is not `leaving`. It
//! never leaves its device group, whose only admin is its account. When the
//! commit is not confirmed within about 30 seconds, it leaves every chat
//! itself.
//!
//! A sibling that finds a device `leaving` on the selected branch removes it
//! as if its user had decided to, after a random delay of up to 30 seconds,
//! so that siblings seldom commit the same removal; branch selection keeps
//! one when they do.
//!
//! While an account signs out here, its device group's removal of this
//! device does not unlink it: the sign-out only sends what it has left, its
//! SelfRemoves and its slot's deletion. No maintenance pass or pairing drive
//! runs meanwhile, so nothing else goes out.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cgka_traits::app_components::{DeviceRosterV1, DeviceSlotId, DeviceStatusV1, DeviceTagClaim};
use cgka_traits::{EpochState, GroupId};
use marmot_session::{DeviceRosterEdit, DeviceRosterEditBlocked};
use rand::Rng;

use super::AppClient;
use crate::{AppError, unix_now_seconds};

const TARGET: &str = "marmot_app::client::sign_out";

/// About how long `sign_out_and_wipe` waits for this device's `leaving`
/// commit to be confirmed before it leaves every chat itself.
const SIGN_OUT_LEAVING_WAIT: Duration = Duration::from_secs(30);

/// The longest a sibling waits, in seconds, before it decides to remove a
/// device it found `leaving`.
const LEAVING_SIBLING_JITTER_SECS: u64 = 30;

/// Where signing out through siblings stands, as one step finds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SiblingSignOut {
    /// This device signs out on its own: device groups are off, it trusts
    /// no device group, its link is not made, or no other device that is
    /// not `leaving` remains.
    OnItsOwn,
    /// The `leaving` commit is not sent, or not confirmed yet.
    Pending,
    /// The `leaving` commit is confirmed. A sibling takes this device out of
    /// these chats (hex group ids); it leaves the others itself.
    Confirmed { left_to_siblings: Vec<String> },
}

/// Marks an account as signing out on this device until dropped, so a
/// sign-out that fails or is cancelled leaves no mark behind.
#[must_use]
pub(crate) struct SigningOut {
    accounts: Arc<Mutex<HashSet<String>>>,
    account_id_hex: String,
}

impl Drop for SigningOut {
    fn drop(&mut self) {
        self.accounts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.account_id_hex);
    }
}

impl crate::MarmotApp {
    /// Note that `account_id_hex` started signing out on this device: until
    /// the returned mark drops, its device group's removal of this device
    /// does not unlink it.
    pub(crate) fn begin_signing_out(&self, account_id_hex: &str) -> SigningOut {
        self.signing_out_accounts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(account_id_hex.to_owned());
        SigningOut {
            accounts: Arc::clone(&self.signing_out_accounts),
            account_id_hex: account_id_hex.to_owned(),
        }
    }

    /// How long `sign_out_and_wipe` waits for this device's `leaving` commit
    /// to be confirmed.
    pub(crate) fn sign_out_leaving_wait(&self) -> Duration {
        #[cfg(test)]
        if let Some(wait) = *self
            .test_sign_out_leaving_wait
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            return wait;
        }
        SIGN_OUT_LEAVING_WAIT
    }

    /// Test hook: wait `wait` for the `leaving` commit instead.
    #[cfg(test)]
    pub(crate) fn set_sign_out_leaving_wait(&self, wait: Duration) {
        *self
            .test_sign_out_leaving_wait
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(wait);
    }

    /// Whether `account_id_hex` is signing out on this device.
    pub(crate) fn signing_out(&self, account_id_hex: &str) -> bool {
        self.signing_out_accounts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(account_id_hex)
    }
}

impl AppClient {
    /// Whether this account is signing out on this device.
    pub(crate) fn signing_out(&self) -> bool {
        self.app
            .signing_out(&hex::encode(self.adapter.account_id().as_slice()))
    }

    /// Whether this device's device group removed it while it signs out. It
    /// then sends only its remaining SelfRemoves and its slot's deletion
    /// (D67): no push token removal before a leave.
    pub(crate) fn removed_while_signing_out(&self) -> Result<bool, AppError> {
        Ok(self.signing_out() && self.app.removed_device_group(&self.state.label)?.is_some())
    }

    /// Move signing out through siblings one step on: commit this device's
    /// own entry as `leaving` when the device group takes a commit, then
    /// report it confirmed once the device group is quiet with the entry
    /// `leaving` on the selected branch. The caller repeats it until it is
    /// confirmed or about 30 seconds have passed. A commit that fails is
    /// logged and sent again on the next step.
    pub(crate) async fn sign_out_through_siblings_step(
        &mut self,
    ) -> Result<SiblingSignOut, AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(SiblingSignOut::OnItsOwn);
        }
        // A device group that removed this device reads as none.
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Ok(SiblingSignOut::OnItsOwn);
        };
        let own_slot = self.own_slot()?;
        // No device removes an entry without its tag signature key, so a
        // device whose link is not made yet signs out on its own.
        let Some(own) = roster
            .devices
            .get(&own_slot)
            .filter(|entry| entry.tag_signature_key.is_some())
        else {
            return Ok(SiblingSignOut::OnItsOwn);
        };
        if own.status != DeviceStatusV1::Leaving {
            if staying_siblings(&roster, &own_slot).next().is_none() {
                return Ok(SiblingSignOut::OnItsOwn);
            }
            self.commit_leaving(&group_id, &own_slot).await;
            return Ok(SiblingSignOut::Pending);
        }
        if !self.group_quiet(&group_id)? {
            return Ok(SiblingSignOut::Pending);
        }
        Ok(SiblingSignOut::Confirmed {
            left_to_siblings: self.chats_left_to_siblings(&roster, &own_slot),
        })
    }

    /// Commit this device's own entry with status `leaving`, every other
    /// field unchanged. Only while the device group takes a commit from this
    /// device; otherwise the next step tries again.
    async fn commit_leaving(&mut self, group_id: &GroupId, own_slot: &DeviceSlotId) {
        let held = match self.epoch_gap_held_groups() {
            Ok(held) => held,
            Err(error) => {
                tracing::warn!(
                    target: TARGET,
                    method = "commit_leaving",
                    error_kind = error.privacy_safe_kind(),
                    "could not read held groups; retrying"
                );
                return;
            }
        };
        let edit = self
            .runtime
            .edit_device_roster_entry(group_id, own_slot, &held, |entry| {
                entry.status = DeviceStatusV1::Leaving;
            })
            .await;
        let result = match edit {
            Ok(DeviceRosterEdit::Committed(effects)) => {
                self.linked_devices_changed = true;
                self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                    .await
            }
            Ok(
                DeviceRosterEdit::Unchanged
                | DeviceRosterEdit::Blocked(
                    DeviceRosterEditBlocked::Busy
                    | DeviceRosterEditBlocked::NoEntry
                    | DeviceRosterEditBlocked::Unreadable,
                ),
            ) => Ok(()),
            Err(error) => Err(error.into()),
        };
        if let Err(error) = result {
            tracing::warn!(
                target: TARGET,
                method = "commit_leaving",
                error_kind = error.privacy_safe_kind(),
                "could not commit this device's leaving entry; retrying"
            );
        }
    }

    /// The chats a sibling takes this device out of, as hex group ids: each
    /// requires `marmot.group.account-devices.v1`, this device's leaf there
    /// carries a device tag that reads as its slot, and another leaf carries
    /// one that reads as a device `roster` lists that is not `leaving`. A
    /// chat whose leaves cannot be read is left out, so this device leaves
    /// it itself.
    fn chats_left_to_siblings(
        &mut self,
        roster: &DeviceRosterV1,
        own_slot: &DeviceSlotId,
    ) -> Vec<String> {
        let staying = staying_siblings(roster, own_slot).collect::<HashSet<_>>();
        if staying.is_empty() {
            return Vec::new();
        }
        let groups = self
            .state
            .groups
            .iter()
            .filter_map(|group| hex::decode(&group.group_id_hex).ok().map(GroupId::new))
            .collect::<Vec<_>>();
        groups
            .into_iter()
            .filter(|group_id| {
                self.sibling_takes_this_device_out(group_id, roster, own_slot, &staying)
                    .unwrap_or(false)
            })
            .map(|group_id| hex::encode(group_id.as_slice()))
            .collect()
    }

    fn sibling_takes_this_device_out(
        &mut self,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
        own_slot: &DeviceSlotId,
        staying: &HashSet<DeviceSlotId>,
    ) -> Result<bool, AppError> {
        if self.is_device_group(group_id)?
            || !self.group_requires_account_devices(group_id)?
            || !self.runtime.ensure_group_hydrated(group_id)?
        {
            return Ok(false);
        }
        let epoch = self.runtime.group_record(group_id)?.epoch;
        let own_leaf = self.runtime.own_leaf_index(group_id)?;
        if self
            .runtime
            .member_device_tag_claim(group_id, epoch, own_leaf, roster)?
            != Some(DeviceTagClaim::Device(*own_slot))
        {
            return Ok(false);
        }
        Ok(self
            .runtime
            .own_account_leaf_claims(group_id, roster)?
            .into_iter()
            .any(|(_, claim)| matches!(claim, DeviceTagClaim::Device(slot) if staying.contains(&slot))))
    }

    /// Decide to remove each sibling the selected branch's roster lists as
    /// `leaving`, with its tag signature key, as if this device's user had
    /// decided to: the recorded removal is then carried out as any other.
    /// Each waits its own random delay of up to 30 seconds first, drawn when
    /// this client first finds it `leaving`. Never while this account is
    /// signing out here.
    pub(crate) fn decide_leaving_siblings(&mut self) -> Result<(), AppError> {
        if self.signing_out() {
            return Ok(());
        }
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            self.leaving_siblings.clear();
            return Ok(());
        };
        // A `leaving` entry on a branch that is still settling may be
        // dropped; decide once it is selected.
        if !matches!(
            self.runtime.epoch_state(&group_id),
            Some(EpochState::Stable { .. })
        ) || self.runtime.has_pending_convergence_inputs(&group_id)?
        {
            return Ok(());
        }
        let own_slot = self.own_slot()?;
        let leaving = roster
            .devices
            .iter()
            .filter(|(slot, entry)| {
                **slot != own_slot
                    && entry.status == DeviceStatusV1::Leaving
                    && entry.tag_signature_key.is_some()
            })
            .map(|(slot, _)| *slot)
            .collect::<HashSet<_>>();
        self.leaving_siblings
            .retain(|slot, _| leaving.contains(slot));
        if leaving.is_empty() {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let group_id_hex = hex::encode(group_id.as_slice());
        let decided = storage
            .device_removals()?
            .into_iter()
            .filter(|removal| removal.group_id_hex == group_id_hex)
            .map(|removal| removal.slot_hex)
            .collect::<HashSet<_>>();
        let now = unix_now_seconds();
        for slot in leaving {
            let slot_hex = hex::encode(slot);
            if decided.contains(&slot_hex) {
                self.leaving_siblings.remove(&slot);
                continue;
            }
            let decide_at = *self.leaving_siblings.entry(slot).or_insert_with(|| {
                now.saturating_add(rand::thread_rng().gen_range(0..=LEAVING_SIBLING_JITTER_SECS))
            });
            if now < decide_at {
                continue;
            }
            storage.record_device_removal(&group_id_hex, &slot_hex, now)?;
            self.leaving_siblings.remove(&slot);
            self.linked_devices_changed = true;
        }
        Ok(())
    }

    /// Test hook: date every pending decision `secs` earlier, as a wait that
    /// long would.
    #[cfg(test)]
    pub(crate) fn backdate_leaving_siblings(&mut self, secs: u64) {
        for decide_at in self.leaving_siblings.values_mut() {
            *decide_at = decide_at.saturating_sub(secs);
        }
    }
}

/// The devices `roster` lists, other than `own_slot`, that are not `leaving`.
fn staying_siblings<'a>(
    roster: &'a DeviceRosterV1,
    own_slot: &'a DeviceSlotId,
) -> impl Iterator<Item = DeviceSlotId> + 'a {
    roster
        .devices
        .iter()
        .filter(move |(slot, entry)| *slot != own_slot && entry.status != DeviceStatusV1::Leaving)
        .map(|(slot, _)| *slot)
}
