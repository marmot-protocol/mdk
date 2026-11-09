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
//! device does not unlink it, the pairing drive does not run and its push
//! token gossip stops. Once that removal lands, every publish of the
//! account is held back at the publish stop but the sign-out's own steps,
//! its SelfRemoves and its slot's deletion: each runs under a
//! [`SignOutStepPermit`], which lets only that step's own future pass the
//! stop. No maintenance pass runs, and its leaves send no push token
//! removal. The removed device-group copy stays until the wipe
//! deletes it, so a sign-out that is cancelled or fails leaves the removal
//! stored, still held back, and the next pairing drive unlinks the device.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cgka_traits::app_components::{DeviceRosterV1, DeviceSlotId, DeviceStatusV1, DeviceTagClaim};
use cgka_traits::storage::LeaveRequestStorage;
use cgka_traits::{EpochState, GroupId};
use marmot_session::{DeviceRosterEdit, DeviceRosterEditBlocked};
use rand::Rng;

use super::AppClient;
use crate::unlinked_publish_gate::publish_as_sign_out_step;
use crate::{AppError, unix_now_seconds};

const TARGET: &str = "marmot_app::client::sign_out";

/// About how long `sign_out_and_wipe` waits for this device's `leaving`
/// commit to be confirmed before it tries to leave every chat itself.
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

/// What stage 1 of `sign_out_and_wipe` did with one chat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SignOutLeave {
    /// This device's leave went through the ordinary leave path.
    Left,
    /// Its leave is recorded and the engine carries it out: this sign-out
    /// sent `StepDownAndLeave` to a chat its account administers with
    /// another account, or the device was already leaving the chat. The chat
    /// counts as left only once this device sees the commit that removes its
    /// leaf (mdk#2818).
    Recorded,
    /// This device keeps its leaf: its account is an active admin there
    /// and cannot step down from this device (mdk#2818).
    Kept(SignOutAdminKeep),
}

/// Where an admin's sign-out leave from one chat stands, as
/// `sign_out_and_wipe` polls it after stage 1 (mdk#2818).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignOutAdminLeave {
    /// This device's leaf is gone.
    Left,
    /// Its account is still on the chat's admin list: the step-down is not
    /// staged or has not merged yet, or a rival branch undid it and the
    /// engine steps down again.
    SteppingDown,
    /// Its account is off the admin list and its SelfRemove waits to be
    /// sent or committed.
    AwaitingRemoval,
    /// Branch selection left its account the chat's last admin, which
    /// blocks the leave. A blocked leave ends this chat's wait: the sign-out
    /// reports it and does not wait for a branch change that could unblock
    /// it, so the device keeps its leaf there, as a last admin's does.
    Blocked,
}

impl SignOutAdminLeave {
    /// Whether nothing more happens to this chat before the wipe.
    pub(crate) fn settled(self) -> bool {
        matches!(self, Self::Left | Self::Blocked)
    }

    /// The privacy-safe `GroupLeaveFailure::reason` that reports a chat the
    /// sign-out did not leave, or `None` once it did.
    pub(crate) fn failure_reason(self) -> Option<&'static str> {
        match self {
            Self::Left => None,
            Self::SteppingDown => Some(SIGN_OUT_STEP_DOWN_NOT_ACCEPTED),
            Self::AwaitingRemoval => Some(SIGN_OUT_REMOVAL_NOT_SEEN),
            Self::Blocked => Some(SIGN_OUT_LAST_ADMIN),
        }
    }
}

/// Why signing out keeps this device's leaf in a chat its account is an
/// active admin of. An admin's SelfRemove is refused, so leaving would
/// first take the account off the chat's admin list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignOutAdminKeep {
    /// No other account is an active admin of the chat.
    LastAdmin,
    /// Another of the account's devices has a leaf in the chat. Admin
    /// rights belong to the account, so a step-down would take them from
    /// that device too.
    AnotherDeviceStays,
    /// The account is an admin of the chat and another account is too.
    /// Signing out steps down and leaves such a chat, unless the device was
    /// removed while it signs out and so sends only its SelfRemoves.
    Admin,
}

impl SignOutAdminKeep {
    /// The privacy-safe `GroupLeaveFailure::reason` that reports the chat.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::LastAdmin => SIGN_OUT_LAST_ADMIN,
            Self::AnotherDeviceStays => SIGN_OUT_ADMIN_ON_ANOTHER_DEVICE,
            Self::Admin => SIGN_OUT_ADMIN,
        }
    }
}

/// `GroupLeaveFailure::reason` for a chat whose last active admin is this
/// account.
pub(crate) const SIGN_OUT_LAST_ADMIN: &str = "account is the chat's last admin";
/// `GroupLeaveFailure::reason` for an admin chat another of the account's
/// devices stays in.
pub(crate) const SIGN_OUT_ADMIN_ON_ANOTHER_DEVICE: &str =
    "account is an admin and another of its devices stays in the chat";
/// `GroupLeaveFailure::reason` for any other chat the account is an admin
/// of: a device removed while it signs out sends only its SelfRemoves, so
/// it cannot step down.
pub(crate) const SIGN_OUT_ADMIN: &str = "account is an admin of the chat";
/// `GroupLeaveFailure::reason` for an admin chat whose step-down had not
/// merged when the sign-out's wait ended.
pub(crate) const SIGN_OUT_STEP_DOWN_NOT_ACCEPTED: &str =
    "account's step-down as admin was not accepted in time";
/// `GroupLeaveFailure::reason` for a chat whose leave the sign-out waited
/// for, where the account is off the admin list but the removal of this
/// device was not seen when the wait ended. The account stays in the chat
/// as a member.
pub(crate) const SIGN_OUT_REMOVAL_NOT_SEEN: &str =
    "account is not an admin and its removal was not seen in time";

/// Marks an account as signing out on this device until dropped, so a
/// sign-out that fails or is cancelled leaves no mark behind. The account
/// stays marked while any of its sign-outs runs.
#[must_use]
pub(crate) struct SigningOut {
    accounts: Arc<Mutex<HashMap<String, usize>>>,
    account_id_hex: String,
}

impl Drop for SigningOut {
    fn drop(&mut self) {
        let mut accounts = self
            .accounts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(running) = accounts.get_mut(&self.account_id_hex) {
            *running -= 1;
            if *running == 0 {
                accounts.remove(&self.account_id_hex);
            }
        }
    }
}

/// Lets one step of a sign-out publish while a device its device group
/// removed during the sign-out holds every other publish back. The stop
/// stays set: only the future the step runs under the permit passes it.
pub(crate) struct SignOutStepPermit(Option<Arc<AtomicBool>>);

impl SignOutStepPermit {
    /// Whether publishing was held back: the device was removed while it
    /// signs out.
    pub(crate) fn held(&self) -> bool {
        self.0.is_some()
    }

    /// Run `step` so that its own publishes pass the stop. A task it spawns
    /// and every other publisher of the account stay held back.
    pub(crate) async fn run<F: Future>(&self, step: F) -> F::Output {
        match &self.0 {
            Some(stop) => publish_as_sign_out_step(stop.clone(), step).await,
            None => step.await,
        }
    }
}

impl crate::MarmotApp {
    /// Note that `account_id_hex` started signing out on this device: until
    /// the returned mark drops, its device group's removal of this device
    /// does not unlink it.
    pub(crate) fn begin_signing_out(&self, account_id_hex: &str) -> SigningOut {
        *self
            .signing_out_accounts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(account_id_hex.to_owned())
            .or_default() += 1;
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
    #[cfg(all(test, feature = "test-policy-overrides"))]
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
            .contains_key(account_id_hex)
    }
}

impl AppClient {
    /// Whether this account is signing out on this device.
    pub(crate) fn signing_out(&self) -> bool {
        self.app
            .signing_out(&hex::encode(self.adapter.account_id().as_slice()))
    }

    /// Whether this device's device group removed it while it signs out.
    /// It then sends only its remaining SelfRemoves and its slot's deletion
    /// (D67).
    pub(crate) fn removed_while_signing_out(&self) -> Result<bool, AppError> {
        #[cfg(feature = "unreleased-device-pairing")]
        return Ok(
            self.signing_out() && self.app.removed_device_group(&self.state.label)?.is_some()
        );
        // Without device groups no device group removes this device.
        #[cfg(not(feature = "unreleased-device-pairing"))]
        Ok(false)
    }

    /// Hold back every publish of this account once its device group
    /// removed this device while it signs out: only the sign-out's own
    /// steps, each under a [`SignOutStepPermit`], still go out (D67). The
    /// hold outlasts a sign-out that ends without a wipe, until the next
    /// pairing drive notes the removal.
    pub(crate) fn hold_removed_sign_out_publishing(&self) -> Result<bool, AppError> {
        let removed = self.removed_while_signing_out()?;
        if removed {
            self.app
                .account_publish_stop(&hex::encode(self.adapter.account_id().as_slice()))
                .store(true, Ordering::Release);
        }
        Ok(removed)
    }

    /// Let one sign-out step, a SelfRemove or the slot's deletion, publish
    /// while a removal during the sign-out holds the rest back.
    pub(crate) fn sign_out_step_permit(&self) -> Result<SignOutStepPermit, AppError> {
        if !self.hold_removed_sign_out_publishing()? {
            return Ok(SignOutStepPermit(None));
        }
        Ok(SignOutStepPermit(Some(self.app.account_publish_stop(
            &hex::encode(self.adapter.account_id().as_slice()),
        ))))
    }

    /// Why signing out keeps this device's leaf in `group_id`, read on the
    /// selected state: `None` unless its account is an active admin there
    /// and this device has an active leaf, in which case the engine would
    /// refuse its SelfRemove (mdk#2818). The send checks again.
    pub(crate) fn sign_out_admin_keep(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Option<SignOutAdminKeep>, AppError> {
        // A group that fails to hydrate is quarantined; the leave decides.
        if !self.runtime.ensure_group_hydrated(group_id)? {
            return Ok(None);
        }
        let (membership, admins) = self
            .runtime
            .group_authority_view()
            .with_group_authority_snapshot(group_id, |_, _| {
                Ok::<_, AppError>((
                    self.runtime.canonical_group_membership(group_id)?,
                    self.runtime.admin_pubkeys(group_id)?,
                ))
            })?;
        if !membership.local_leaf_active {
            return Ok(None);
        }
        let own = self.runtime.self_id();
        let has_leaf = |account: &[u8]| {
            membership
                .member_leaves
                .iter()
                .any(|leaf| leaf.member.as_slice() == account)
        };
        let active_admins = admins
            .iter()
            .filter(|admin| has_leaf(admin.as_slice()))
            .collect::<HashSet<_>>();
        if !active_admins
            .iter()
            .any(|admin| admin.as_slice() == own.as_slice())
        {
            return Ok(None);
        }
        let own_leaves = membership
            .member_leaves
            .iter()
            .filter(|leaf| leaf.member == own)
            .count();
        Ok(Some(if own_leaves > 1 {
            SignOutAdminKeep::AnotherDeviceStays
        } else if active_admins.len() == 1 {
            SignOutAdminKeep::LastAdmin
        } else {
            SignOutAdminKeep::Admin
        }))
    }

    /// Where this device's leave from `group_id`, a chat whose leave the
    /// sign-out waits for, stands (mdk#2818). The account worker keeps
    /// receiving and draining between polls, so the engine stages the
    /// step-down and then the SelfRemove from the leave request, and a
    /// member's commit of it makes the copy here terminal.
    pub(crate) fn sign_out_admin_leave(
        &mut self,
        group_id: &GroupId,
    ) -> Result<SignOutAdminLeave, AppError> {
        if self.runtime.group_record(group_id)?.is_terminal() {
            return Ok(SignOutAdminLeave::Left);
        }
        let request = self
            .app
            .account_storage(&self.state.label)?
            .leave_request(group_id)?;
        if request
            .as_ref()
            .is_some_and(|request| request.blocked.is_some())
        {
            return Ok(SignOutAdminLeave::Blocked);
        }
        Ok(if self.account_is_admin(group_id)? {
            SignOutAdminLeave::SteppingDown
        } else {
            SignOutAdminLeave::AwaitingRemoval
        })
    }

    /// Whether this account is on `group_id`'s admin list.
    pub(crate) fn account_is_admin(&self, group_id: &GroupId) -> Result<bool, AppError> {
        let own = self.runtime.self_id();
        Ok(self
            .runtime
            .admin_pubkeys(group_id)?
            .iter()
            .any(|admin| admin.as_slice() == own.as_slice()))
    }

    /// Move signing out through siblings one step on: commit this device's
    /// own entry as `leaving` when the device group takes a commit, then
    /// report it confirmed once the entry reads `leaving` on the selected
    /// branch: the device group is stable with no convergence input left,
    /// so a relay accepted the commit and no other branch is pending. The caller repeats it until it is
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
        let own_slot = match self.own_slot() {
            Ok(slot) => slot,
            // A device with no slot of its own has no entry a sibling could
            // take out.
            Err(AppError::DeviceGroupRefused("slot_unavailable")) => {
                return Ok(SiblingSignOut::OnItsOwn);
            }
            Err(error) => return Err(error),
        };
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
        if !matches!(
            self.runtime.epoch_state(&group_id),
            Some(EpochState::Stable { .. })
        ) || self.runtime.has_pending_convergence_inputs(&group_id)?
        {
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
    #[cfg(all(test, feature = "test-policy-overrides"))]
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
        .filter(move |(slot, entry)| {
            *slot != own_slot
                && matches!(
                    entry.status,
                    DeviceStatusV1::Active | DeviceStatusV1::Inactive
                )
        })
        .map(|(slot, _)| *slot)
}
