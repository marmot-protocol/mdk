//! Removing another of this account's devices (mdk#2628 item 3.6b, D22).
//!
//! The user removes a linked device from any other device. Removal is one
//! decision with three effects, each owed until it is done:
//!
//! - **The device group.** One commit removes the device's leaf (the one
//!   whose device tag reads as its slot) and its roster entry, and records
//!   the slot as `removed` with the tag signature key the entry had, so the
//!   removed device's tags still read as its slot. The decision is recorded
//!   (`device_removals`) before anything is committed, and kept for as long
//!   as this device trusts the device group: only forgetting the group
//!   deletes it. A busy device group delays the commit, a terminal or
//!   unreadable copy of it holds the removal back, and whenever the roster
//!   lists the slot again, which only a fork that drops the removal can do,
//!   the device is removed again. A removed
//!   device comes back only as a new slot. A removal made again keeps the
//!   decision's time, so once that is 30 days past its record drops at the
//!   next expiry pass.
//! - **The slot.** Once the settled roster no longer lists the slot as a
//!   device, whether it records it as `removed` or that record has expired,
//!   the device that decided the removal deletes the removed device's public
//!   KeyPackage slot, the one exception to "a device manages only its own
//!   KeyPackages" (D22). It stops once a relay accepts the deletion, and
//!   deletes the slot again if a dropped removal has to be committed again.
//! - **Chats.** Every device that trusts the device group, whichever device
//!   decided the removal, removes from each chat it is in every leaf of its
//!   account whose device tag reads as a `removed` slot, while the roster
//!   keeps that record. Only chats that require
//!   `marmot.group.account-devices.v1` can take a same-account Remove; the
//!   others are counted for the host, and a chat admin can remove the leaf.
//!   A leaf with no tag reads as unclaimed and is left alone (D55).
//! - **Private KeyPackages.** Every such device also discards the private
//!   KeyPackages it issued to a `removed` slot, keys included, and those that
//!   slot handed it, so a Welcome the removed device makes from one cannot
//!   add it back (3.4).
//!
//! The device signs out to leave; it never removes itself here.

use std::collections::HashSet;

use cgka_traits::app_components::{
    ACCOUNT_DEVICES_COMPONENT_ID, DeviceRosterOperationV1, DeviceRosterV1, DeviceSlotId,
    DeviceTagClaim, RejectedSlotReasonV1, RejectedSlotV1,
};
use cgka_traits::engine::SendIntent;
use cgka_traits::{EngineError, EpochState, FanoutMlsState, GroupId};
use storage_sqlite::{DeviceRemovalRecord, SqliteAppStorage};

use super::AppClient;
use super::device_group::device_slot;
use crate::{AppError, unix_now_seconds};

const TARGET: &str = "marmot_app::client::device_removal";

/// Leaf signature keys of this account's other devices in one group.
type LeafKeys = Vec<Vec<u8>>;

/// What [`AppClient::remove_own_account_leaves`] did in one chat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnLeafRemoval {
    /// A same-account Remove of the leaves went out.
    Sent,
    /// The chat cannot take a commit from this device now: one is in flight
    /// or settling, or this device is leaving or disbanding it. A later pass
    /// retries; a chat this device leaves is then gone.
    Busy,
    /// The chat does not require `marmot.group.account-devices.v1`, so this
    /// device cannot remove one of its account's leaves there.
    Unsupported,
}

impl AppClient {
    /// Remove the linked device in `slot_id_hex` (from `linked_devices`) from
    /// this account: from the device group and every chat, and delete its
    /// KeyPackage slot. The decision is recorded at once and carried out as
    /// the device group allows; `linked_devices` shows the device as being
    /// removed until the roster no longer lists it.
    ///
    /// Refused with nothing recorded when device groups are off
    /// (`roster_unsupported`), with no trusted device group
    /// (`no_device_group`), for a slot the roster doesn't list
    /// (`unknown_device`), for this device (`this_device`: sign out instead),
    /// and for a device whose link is not made yet (`device_link_pending`).
    pub(crate) async fn remove_linked_device(&mut self, slot_id_hex: &str) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        let slot =
            device_slot(slot_id_hex).map_err(|_| AppError::DeviceGroupRefused("unknown_device"))?;
        self.sync_runtime_groups_for_send("remove_linked_device")
            .await?;
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Err(AppError::DeviceGroupRefused("no_device_group"));
        };
        let Some(entry) = roster.devices.get(&slot) else {
            return Err(AppError::DeviceGroupRefused("unknown_device"));
        };
        if slot == self.own_slot()? {
            return Err(AppError::DeviceGroupRefused("this_device"));
        }
        // A device sets its tag signature key with its first commit in the
        // device group; until then the link may still fail and be undone.
        if entry.tag_signature_key.is_none() {
            return Err(AppError::DeviceGroupRefused("device_link_pending"));
        }
        self.app
            .account_storage(&self.state.label)?
            .app_storage()
            .record_device_removal(
                &hex::encode(group_id.as_slice()),
                &hex::encode(slot),
                unix_now_seconds(),
            )?;
        self.linked_devices_changed = true;
        self.drive_device_removals().await;
        Ok(())
    }

    /// Carry every recorded removal as far as the device group allows, then
    /// clean up after removed devices on this device: their private
    /// KeyPackages and their leaves in its chats. Runs on each maintenance
    /// pass; any failure is logged and retried on the next.
    pub(crate) async fn drive_device_removals(&mut self) {
        if !self.app.device_groups_enabled() {
            return;
        }
        if let Err(error) = self.decide_leaving_siblings() {
            tracing::warn!(
                target: TARGET,
                method = "decide_leaving_siblings",
                error_kind = error.privacy_safe_kind(),
                "could not decide a leaving device's removal; retrying"
            );
        }
        if let Err(error) = self.drive_recorded_removals().await {
            tracing::warn!(
                target: TARGET,
                method = "drive_device_removals",
                error_kind = error.privacy_safe_kind(),
                "could not carry out a device removal; retrying"
            );
        }
        if let Err(error) = self.clean_up_removed_devices().await {
            tracing::warn!(
                target: TARGET,
                method = "clean_up_removed_devices",
                error_kind = error.privacy_safe_kind(),
                "could not clean up after a removed device; retrying"
            );
        }
    }

    /// Each recorded removal is carried on its own: one that fails, such as
    /// a slot deletion no relay accepts, never holds the others back. The
    /// first failure is returned once all have run.
    async fn drive_recorded_removals(&mut self) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let removals = storage.device_removals()?;
        if removals.is_empty() {
            return Ok(());
        }
        let trusted = self.trusted_device_roster()?;
        let mut first_error = None;
        for removal in removals {
            // A removal for a group whose roster this device cannot read now
            // (its copy is terminal, or it is not the trusted group) waits.
            // Only forgetting the group deletes it, with the trust row.
            let Some((group_id, roster)) = trusted
                .as_ref()
                .filter(|(group_id, _)| hex::encode(group_id.as_slice()) == removal.group_id_hex)
            else {
                continue;
            };
            if let Err(error) = self
                .drive_recorded_removal(&storage, &removal, group_id, roster)
                .await
            {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn drive_recorded_removal(
        &mut self,
        storage: &SqliteAppStorage,
        removal: &DeviceRemovalRecord,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
    ) -> Result<(), AppError> {
        let slot = device_slot(&removal.slot_hex)?;
        if roster.devices.contains_key(&slot) {
            // Not removed yet, or listed again because branch selection
            // dropped the removal. The device may publish to its slot until
            // it is removed again, so the slot is deleted again then.
            if removal.slot_withdrawn_at.is_some() {
                storage.set_device_removal_slot_withdrawn(
                    &removal.group_id_hex,
                    &removal.slot_hex,
                    None,
                )?;
            }
            return self
                .commit_device_removal(group_id, roster, &slot, removal.requested_at)
                .await;
        }
        // Not listed: removed, its `removed` record has expired since, or a
        // failed link's undo took the entry. The slot is deleted until a
        // relay accepts it. A `not_me` record says the slot was never this
        // account's device, so it is left alone.
        let not_me = roster
            .rejected_slots
            .get(&slot)
            .is_some_and(|record| record.reason == RejectedSlotReasonV1::NotMe);
        if !not_me
            && removal.slot_withdrawn_at.is_none()
            && self
                .runtime
                .withdraw_removed_device_slot(group_id, &slot)
                .await?
                .is_some()
        {
            storage.set_device_removal_slot_withdrawn(
                &removal.group_id_hex,
                &removal.slot_hex,
                Some(unix_now_seconds()),
            )?;
        }
        Ok(())
    }

    /// One commit in the device group that removes the device in `slot`:
    /// its leaf, read from device tags, and its entry, recording the slot as
    /// `removed` at `requested_at`. Sent only while the group can take a
    /// commit from this device; otherwise a later pass retries.
    async fn commit_device_removal(
        &mut self,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
        slot: &DeviceSlotId,
        requested_at: u64,
    ) -> Result<(), AppError> {
        if !self.group_quiet(group_id)? {
            return Ok(());
        }
        let Some(entry) = roster.devices.get(slot) else {
            return Ok(());
        };
        // Branch selection can drop the commit that set the device's tag
        // signature key after the user decided. Until the key is back the
        // link may still fail, and a failed link's undo ends the decision.
        if entry.tag_signature_key.is_none() {
            return Ok(());
        }
        // The engine removes the leaf only if its tree still has it, and the
        // entry either way. A device whose leaf carries no readable tag has
        // only its entry removed.
        let leaf_signature_key = self
            .runtime
            .own_account_leaf_claims(group_id, roster)?
            .into_iter()
            .find_map(|(key, claim)| (claim == DeviceTagClaim::Device(*slot)).then_some(key))
            .unwrap_or_default();
        let operations = vec![
            DeviceRosterOperationV1::RemoveDevice(*slot),
            DeviceRosterOperationV1::SetRejectedSlot(
                *slot,
                RejectedSlotV1 {
                    reason: RejectedSlotReasonV1::Removed,
                    rejected_at: requested_at,
                    tag_signature_key: entry.tag_signature_key.clone(),
                },
            ),
        ];
        match self
            .unlink_device_from_group(group_id, leaf_signature_key, operations)
            .await
        {
            Ok(()) => {
                self.linked_devices_changed = true;
                Ok(())
            }
            Err(error)
                if matches!(
                    error.as_engine_error(),
                    Some(EngineError::LinkDeviceUnsettled { .. })
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// For each slot the trusted roster records as `removed`: discard the
    /// private KeyPackages exchanged with it, and remove from each chat this
    /// device is in every leaf of its account whose device tag reads as it.
    /// Both are idempotent, so each pass repeats them while the record lasts.
    /// Each slot and each chat is handled on its own: one that fails never
    /// holds the others back, and the first failure is returned at the end.
    async fn clean_up_removed_devices(&mut self) -> Result<(), AppError> {
        let Some((_, roster)) = self.trusted_device_roster()? else {
            return Ok(());
        };
        let removed = roster
            .rejected_slots
            .iter()
            .filter(|(_, record)| record.reason == RejectedSlotReasonV1::Removed)
            .map(|(slot, _)| *slot)
            .collect::<Vec<_>>();
        if removed.is_empty() {
            return Ok(());
        }
        let mut first_error = None;
        for slot in &removed {
            if let Err(error) = self.discard_private_key_packages_of(slot) {
                first_error.get_or_insert(error);
            }
        }
        for group_id in self.chats_to_clean_up() {
            let removal = match self.removed_device_leaves_in(&group_id, &roster) {
                Ok(keys) if keys.is_empty() => continue,
                Ok(keys) => self.remove_own_account_leaves(&group_id, keys).await,
                Err(error) => Err(error),
            };
            match removal {
                Ok(OwnLeafRemoval::Sent) => self.linked_devices_changed = true,
                Ok(OwnLeafRemoval::Busy | OwnLeafRemoval::Unsupported) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// How many chats this device is in still hold a leaf of a device this
    /// account removed that this device cannot remove, because the chat does
    /// not require `marmot.group.account-devices.v1`. A chat admin can
    /// remove it. Zero while device groups are off or no device is removed.
    pub(crate) fn removed_device_leftover_chats(&mut self) -> Result<u32, AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(0);
        }
        let Some((_, roster)) = self.trusted_device_roster()? else {
            return Ok(0);
        };
        let mut leftovers = 0u32;
        for group_id in self.chats_to_clean_up() {
            if !self
                .removed_device_leaves_in(&group_id, &roster)?
                .is_empty()
                && !self.group_requires_account_devices(&group_id)?
            {
                leftovers = leftovers.saturating_add(1);
            }
        }
        Ok(leftovers)
    }

    /// The chats this device is in that may hold a removed device's leaves:
    /// not the device group, nor a chat that has ended or is quarantined.
    /// Chats not hydrated yet are left to a later pass rather than hydrated
    /// here, ahead of the background order.
    fn chats_to_clean_up(&self) -> Vec<GroupId> {
        let unhydrated = self
            .runtime
            .unhydrated_group_ids()
            .into_iter()
            .collect::<HashSet<_>>();
        self.state
            .groups
            .iter()
            .filter_map(|group| hex::decode(&group.group_id_hex).ok().map(GroupId::new))
            .filter(|group_id| {
                !unhydrated.contains(group_id)
                    // Fails closed: a group whose kind cannot be read is
                    // left alone.
                    && self.is_device_group(group_id).ok() == Some(false)
                    && !super::group_is_terminal(&self.runtime, group_id)
                    && !super::group_is_quarantined(&self.runtime, group_id)
            })
            .collect()
    }

    /// The signature keys of this account's leaves in `group_id` whose device
    /// tag reads as a `removed` slot of `roster`.
    fn removed_device_leaves_in(
        &self,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
    ) -> Result<LeafKeys, AppError> {
        Ok(self
            .runtime
            .own_account_leaf_claims(group_id, roster)?
            .into_iter()
            .filter_map(|(key, claim)| match claim {
                DeviceTagClaim::RejectedSlot(slot)
                    if roster
                        .rejected_slots
                        .get(&slot)
                        .is_some_and(|record| record.reason == RejectedSlotReasonV1::Removed) =>
                {
                    Some(key)
                }
                _ => None,
            })
            .collect())
    }

    /// Remove other leaves of this device's account, by signature key, from
    /// the chat `group_id`, in one same-account Remove. The removal of a
    /// device and of leaves tied to a rejection (3.7c) both use it.
    ///
    /// Nothing is sent, and the result says why, when the chat does not
    /// require `marmot.group.account-devices.v1` or cannot take a commit from
    /// this device now. A chat whose commit is in flight or settling is never
    /// given a second one, so a pass that finds it busy retries later rather
    /// than queue a duplicate.
    pub(crate) async fn remove_own_account_leaves(
        &mut self,
        group_id: &GroupId,
        leaf_signature_keys: Vec<Vec<u8>>,
    ) -> Result<OwnLeafRemoval, AppError> {
        if !self.group_requires_account_devices(group_id)? {
            return Ok(OwnLeafRemoval::Unsupported);
        }
        if !self.group_quiet(group_id)? {
            return Ok(OwnLeafRemoval::Busy);
        }
        let audit_context = Self::local_human_action_context(
            "remove_own_account_devices",
            vec!["members"],
            Vec::new(),
            u64::try_from(leaf_signature_keys.len()).ok(),
        );
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::RemoveOwnAccountDevices {
                    group_id: group_id.clone(),
                    leaf_signature_keys,
                },
                audit_context,
            )
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)
            .await?;
        Ok(OwnLeafRemoval::Sent)
    }

    /// Whether this device may commit in `group_id` now, the device group or
    /// a chat: it is stable and readable, this device is not leaving or
    /// disbanding it, and nothing of this device's is queued or unconfirmed
    /// there. A later pass retries.
    pub(crate) fn group_quiet(&self, group_id: &GroupId) -> Result<bool, AppError> {
        if !matches!(
            self.runtime.epoch_state(group_id),
            Some(EpochState::Stable { .. })
        ) || self.skips_quarantined_group_reads(group_id)
            || self
                .runtime
                .leave_in_progress(group_id)
                .map_err(marmot_session::SessionError::from)?
            || self.runtime.disbanding_in_progress(group_id)?
            || self.epoch_gap_held_groups()?.contains(group_id)
            || self.runtime.has_pending_convergence_inputs(group_id)?
            || self.runtime.has_queued_outbound_intents(group_id)?
        {
            return Ok(false);
        }
        Ok(!self
            .runtime
            .outbound_fanouts_for_group(group_id)?
            .iter()
            .any(|fanout| matches!(fanout.mls_state(), FanoutMlsState::Pending(_))))
    }

    pub(crate) fn group_requires_account_devices(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        Ok(self.stored_group(group_id)?.is_some_and(|group| {
            group
                .required_capabilities
                .app_components
                .contains(ACCOUNT_DEVICES_COMPONENT_ID)
        }))
    }
}
