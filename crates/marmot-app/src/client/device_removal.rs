//! Removing another of this account's devices (mdk#2628 item 3.6b, D22).
//!
//! The user removes a linked device from any other device. Removal is one
//! decision with three effects, each owed until it is done:
//!
//! - **The device group.** One commit removes the device's leaf (the one
//!   whose device tag reads as its slot) and its roster entry, and records
//!   the slot as `removed` with the tag signature key the entry had, so the
//!   removed device's tags still read as its slot. A device that rewrote or
//!   cleared its entry's key has its leaf found by the tag it signed with
//!   that leaf's own key, which only it can make, and the record then keeps
//!   the key that leaf signs with (mdk#3679). A leaf with no such tag is
//!   never taken by a key a roster names, since any device can write one
//!   there. The decision is recorded (`device_removals`) before anything is
//!   committed, and kept for as long as this device trusts the device
//!   group: only forgetting the group deletes it. A busy device group delays
//!   the commit, a terminal or unreadable copy of it holds the removal back,
//!   and whenever the roster lists the slot again, which only a fork that
//!   drops the removal can do, the device is removed again. A removed
//!   device comes back only as a new slot. A removal made again keeps the
//!   decision's time, so once that is 30 days past its record drops at the
//!   next expiry pass. When a failed link's undo took the entry instead,
//!   which writes no record, the deciding device commits the `removed`
//!   record alone (mdk#2761), with no tag signature key: that Commit
//!   removes no leaf and the roster has no entry, so nothing in it proves
//!   one (marmot#520). Devices that applied the entry keep its key.
//! - **The slot.** Once the settled roster no longer lists the slot as a
//!   device, whether it records it as `removed` or that record has expired,
//!   the device that decided the removal deletes the removed device's public
//!   KeyPackage slot, the one exception to "a device manages only its own
//!   KeyPackages" (D22). It stops once a relay accepts the deletion, and
//!   deletes the slot again if a dropped removal has to be committed again.
//! - **Chats.** Every device that trusts the device group, whichever device
//!   decided the removal, removes from each chat it is in every leaf of its
//!   account whose device tag reads as a gone device, verified by one of its
//!   keys or by the leaf's own (mdk#3679). Only chats that require
//!   `marmot.group.account-devices.v1` can take a same-account Remove; the
//!   others are counted for the host, and a chat admin can remove the leaf.
//!   A leaf with no tag reads as unclaimed and is left alone (D55). The
//!   audit log names that Remove the user's action only on the device that
//!   keeps their decision; other devices, and every device after an
//!   automatic removal (3.6b-2), make it on their own.
//! - **Private KeyPackages.** Every such device also discards the private
//!   KeyPackages it issued to a gone device's slot, keys included, and those
//!   that slot handed it, so a Welcome the removed device makes from one
//!   cannot add it back (3.4).
//!
//! A device is gone while the roster records its slot as `removed`, keeping
//! its tag signature key, and also, once the device group is settled, while
//! the roster lists no device in a slot that a roster state this device
//! applied listed with a tag signature key (mdk#2761). The engine remembers
//! those keys for 30 days after the last state that listed them, so a
//! `removed` record dropped before this device acted on it, a link that
//! failed after its new device set its key, and a made link that a later
//! branch dropped all leave a gone device behind, not unclaimed leaves. A
//! slot a state recorded as `removed` stays removed by those keys, and each
//! cleanup pass that still finds the device's leaf in a chat keeps the keys
//! its records kept another 30 days, so a leftover outlives its record
//! (mdk#3679). This device's own slot is never gone here.
//!
//! The device signs out to leave; it never removes itself here.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use cgka_traits::app_components::{
    ACCOUNT_DEVICES_COMPONENT_ID, DEVICE_ROSTER_COMPONENT_ID, DeviceRosterOperationV1,
    DeviceRosterV1, DeviceSlotId, RejectedSlotReasonV1, RejectedSlotV1,
};
use cgka_traits::engine::SendIntent;
use cgka_traits::storage::{ROSTER_TAG_KEY_RETENTION_SECS, RosterTagKey, RosterTagKeyStorage as _};
use cgka_traits::{EngineError, EpochState, FanoutMlsState, GroupId};
use storage_sqlite::{DeviceRemovalRecord, SqliteAppStorage};

use super::AppClient;
use super::device_group::device_slot;
use crate::{AppError, unix_now_seconds};

const TARGET: &str = "marmot_app::client::device_removal";

/// How long a `removed` record lasts after its `rejected_at` before an
/// expiry pass drops it (device-roster-v1.md, "State").
const REMOVED_RECORD_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;

/// The devices this device cleans up after: their slots, and the tag
/// signature keys their leaves are read by.
#[derive(Default)]
struct GoneDevices {
    slots: BTreeSet<DeviceSlotId>,
    keys: BTreeSet<RosterTagKey>,
}

/// How [`AppClient::device_group_leaf_of`] found a device's leaf, by its
/// signature key.
enum DeviceGroupLeaf {
    /// Its device tag reads as the device's slot.
    Tagged(Vec<u8>),
    /// Its tag says it is the slot's and verifies under its own key.
    SelfSigned(Vec<u8>),
}

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
        // One that cleared the key since is removed by its committed leaf
        // whose tag it signed with that leaf's own key for the slot
        // (mdk#3679); a pending link's leaf is still its KeyPackage leaf.
        if entry.tag_signature_key.is_none()
            && self
                .device_group_leaf_of(&group_id, &roster, &slot)?
                .is_none()
        {
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
            self.device_group_work_changed = true;
            tracing::warn!(
                target: TARGET,
                method = "decide_leaving_siblings",
                error_kind = error.privacy_safe_kind(),
                "could not decide a leaving device's removal; retrying"
            );
        }
        if let Err(error) = self.drive_recorded_removals().await {
            self.device_group_work_changed = true;
            tracing::warn!(
                target: TARGET,
                method = "drive_device_removals",
                error_kind = error.privacy_safe_kind(),
                "could not carry out a device removal; retrying"
            );
        }
        if let Err(error) = self.remove_moved_siblings().await {
            self.device_group_work_changed = true;
            tracing::warn!(
                target: TARGET,
                method = "remove_moved_siblings",
                error_kind = error.privacy_safe_kind(),
                "could not clean up old moved membership; retrying"
            );
        }
        if let Err(error) = self.clean_up_removed_devices().await {
            self.device_group_work_changed = true;
            tracing::warn!(
                target: TARGET,
                method = "clean_up_removed_devices",
                error_kind = error.privacy_safe_kind(),
                "could not clean up after a removed device; retrying"
            );
        }
    }

    /// A selected Moved status ends only the old DG membership. It never
    /// creates a rejected slot, public-slot deletion or chat-removal decision.
    async fn remove_moved_siblings(&mut self) -> Result<(), AppError> {
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Ok(());
        };
        if !self.group_quiet(&group_id)? {
            return self.retry_when_quiet(&group_id);
        }
        let own = self.own_slot()?;
        let removals = self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .device_removals()?;
        let Some((slot, entry)) = roster.devices.iter().find(|(slot, entry)| {
            **slot != own
                && entry.status == cgka_traits::app_components::DeviceStatusV1::Moved
                && !removals.iter().any(|removal| {
                    removal.group_id_hex == hex::encode(group_id.as_slice())
                        && removal.slot_hex == hex::encode(slot)
                })
        }) else {
            return Ok(());
        };
        // Later ordinary Updates can retag the old leaf from its new trust.
        // The selected old entry identifies it independently of that tag.
        let Some(leaf) = entry.tag_signature_key.clone() else {
            return Ok(());
        };
        self.unlink_moved_device_from_group(&group_id, leaf, *slot)
            .await?;
        self.linked_devices_changed = true;
        Ok(())
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
                .commit_device_removal(
                    group_id,
                    roster,
                    &slot,
                    removal.requested_at,
                    Self::user_unlink_audit_context(),
                )
                .await;
        }
        // Not listed: removed, its `removed` record has expired since, or a
        // failed link's undo took the entry. The slot is deleted until a
        // relay accepts it. A `not_me` record says the slot was never this
        // account's device, so it is left alone.
        let record = roster.rejected_slots.get(&slot);
        let not_me = record.is_some_and(|record| record.reason == RejectedSlotReasonV1::NotMe);
        let withdrawn = async {
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
            Ok::<_, AppError>(())
        }
        .await;
        let recorded = if record.is_none() {
            self.record_removal_alone(group_id, &slot, removal).await
        } else {
            Ok(())
        };
        withdrawn.and(recorded)
    }

    /// A failed link's undo can take the entry of a device the user decided
    /// to remove, and it writes no `removed` record. Commit that record
    /// alone, with the decision's time, so every device that applies it
    /// cleans up after the device (mdk#2761), by the keys it remembers for
    /// the slot. The record keeps no tag signature key (marmot#520): this
    /// Commit removes no leaf and the roster has no entry, so nothing in it
    /// proves one. It is made only while this device remembers a key a
    /// roster listed for the slot.
    ///
    /// Only while the decision is under 30 days old, so a record the expiry
    /// pass drops is not made again; the undo comes about an hour after the
    /// link, which comes before the decision. Only until a roster state this
    /// device applied has held a `removed` record for the slot, as its
    /// remembered keys say (`held_as_removed`, which a record with no key
    /// sets on the keys kept for the slot): a record a sibling's expiry
    /// pass or branch selection dropped is not made again, even when one pass
    /// applied it and its drop, or after a restart, while a send that went
    /// nowhere, or whose Commit failed or was rolled back, is made again.
    /// Sent only while the device group is settled and can take a commit from
    /// this device; otherwise a later pass retries. The engine neither queues
    /// the send nor re-issues it after a lost fork, so this pass, behind
    /// these checks, is the only thing that makes the record.
    async fn record_removal_alone(
        &mut self,
        group_id: &GroupId,
        slot: &DeviceSlotId,
        removal: &DeviceRemovalRecord,
    ) -> Result<(), AppError> {
        let now = unix_now_seconds();
        if removal
            .requested_at
            .saturating_add(REMOVED_RECORD_LIFETIME_SECS)
            <= now
            || !self.device_group_settled(group_id)
        {
            return Ok(());
        }
        if !self.group_quiet(group_id)? {
            return self.retry_when_quiet(group_id);
        }
        let remembered = self.remembered_tag_keys(group_id)?;
        if remembered
            .iter()
            .any(|key| key.slot == *slot && key.held_as_removed)
            || !remembered.iter().any(|key| key.slot == *slot)
        {
            return Ok(());
        }
        let held = self.epoch_gap_held_groups()?;
        let context = Self::local_human_action_context(
            "record_removed_device",
            vec!["app_component"],
            vec![DEVICE_ROSTER_COMPONENT_ID],
            None,
        );
        let record = RejectedSlotV1 {
            reason: RejectedSlotReasonV1::Removed,
            rejected_at: removal.requested_at,
            tag_signature_key: None,
        };
        let effects = match self
            .runtime
            .record_removed_slot(group_id, &held, *slot, record, context)
            .await
        {
            Ok(effects) => effects,
            Err(error)
                if matches!(
                    error.as_engine_error(),
                    Some(EngineError::LinkDeviceUnsettled { .. })
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        self.observe_drained_session_events(&effects).await?;
        if self
            .trusted_device_roster()?
            .filter(|(trusted, _)| trusted == group_id)
            .and_then(|(_, roster)| roster.rejected_slots.get(slot).cloned())
            .is_some_and(|record| record.reason == RejectedSlotReasonV1::Removed)
        {
            self.linked_devices_changed = true;
        }
        Ok(())
    }

    /// One commit in the device group that removes the device in `slot`:
    /// its leaf ([`Self::device_group_leaf_of`]) and its entry, recording the
    /// slot as `removed` at `requested_at`. Sent only while the group can
    /// take a commit from this device; otherwise a later pass retries.
    /// `audit_context` names the user's removal as theirs; an automatic one
    /// carries none.
    pub(super) async fn commit_device_removal(
        &mut self,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
        slot: &DeviceSlotId,
        requested_at: u64,
        audit_context: marmot_forensics::AuditEventContext,
    ) -> Result<(), AppError> {
        if !self.group_quiet(group_id)? {
            return self.retry_when_quiet(group_id);
        }
        let Some(entry) = roster.devices.get(slot) else {
            return Ok(());
        };
        // The record keeps a key the device's tags read by: its entry's, or,
        // for a leaf whose tag only its own key verifies, the key that leaf
        // signs with. The engine removes the leaf only if its tree still has
        // it, and the entry either way.
        let (leaf_signature_key, tag_signature_key) =
            match self.device_group_leaf_of(group_id, roster, slot)? {
                Some(DeviceGroupLeaf::Tagged(leaf)) => (leaf, entry.tag_signature_key.clone()),
                Some(DeviceGroupLeaf::SelfSigned(leaf)) => (leaf.clone(), Some(leaf)),
                None => (Vec::new(), entry.tag_signature_key.clone()),
            };
        // Branch selection can drop the commit that set the device's tag
        // signature key after the user decided. Until the key is back, or
        // the device's leaf carries a tag it signed for the slot, the link
        // may still fail, and a failed link's undo ends the decision.
        if tag_signature_key.is_none() {
            return Ok(());
        }
        let operations = vec![
            DeviceRosterOperationV1::RemoveDevice(*slot),
            DeviceRosterOperationV1::SetRejectedSlot(
                *slot,
                RejectedSlotV1 {
                    reason: RejectedSlotReasonV1::Removed,
                    rejected_at: requested_at,
                    tag_signature_key,
                },
            ),
        ];
        match self
            .unlink_device_from_group_with_context(
                group_id,
                leaf_signature_key,
                operations,
                audit_context,
            )
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

    /// The device-group leaf of the device in `slot` (mdk#3679): the one
    /// whose device tag reads as the slot, else one whose tag names the slot
    /// and verifies under that leaf's own signature key, which only that
    /// leaf's device can sign, whatever the slot's entry now says. Either way
    /// the leaf must have committed since its Add: one still built from its
    /// Add's KeyPackage is a link not made yet, which the engine never
    /// records as `removed`. A leaf with neither tag is never taken: any
    /// device can write a key into a roster entry, so a key there proves no
    /// leaf is the slot's.
    fn device_group_leaf_of(
        &self,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
        slot: &DeviceSlotId,
    ) -> Result<Option<DeviceGroupLeaf>, AppError> {
        if let Some(leaf) = self
            .runtime
            .own_device_leaves(group_id, roster, slot, None)?
            .into_iter()
            .find(|leaf| leaf.add_not_after.is_none())
        {
            return Ok(Some(DeviceGroupLeaf::Tagged(leaf.signature_key)));
        }
        for (leaf, tagged) in self
            .runtime
            .own_account_self_signed_tags(group_id, &roster.leaf_tag_key)?
        {
            if tagged != *slot {
                continue;
            }
            let committed = self
                .runtime
                .own_device_leaves(group_id, roster, slot, Some(&leaf))?
                .iter()
                .any(|found| found.signature_key == leaf && found.add_not_after.is_none());
            if committed {
                return Ok(Some(DeviceGroupLeaf::SelfSigned(leaf)));
            }
        }
        Ok(None)
    }

    /// For each gone device (see the module docs): discard the private
    /// KeyPackages exchanged with its slot, and remove from each chat this
    /// device is in every leaf of its account that is the device's
    /// ([`Self::gone_device_leaves_in`]). Both are idempotent, so each pass
    /// repeats them while the device is gone. Each slot and each chat is
    /// handled on its own: one that fails never holds the others back, and
    /// the first failure is returned at the end. The keys of a removed device
    /// whose leaf a chat still holds are then kept another 30 days
    /// ([`Self::keep_removed_device_keys`]).
    async fn clean_up_removed_devices(&mut self) -> Result<(), AppError> {
        // One clock reading for the whole pass: the keys that found a held
        // leaf are the ones renewed, even when the removals awaited between
        // the lookup and the renewal cross the 30-day cutoff.
        let now = unix_now_seconds();
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Ok(());
        };
        let gone = self.gone_devices(&group_id, &roster, now)?;
        if gone.slots.is_empty() {
            return Ok(());
        }
        let chosen = self.chosen_removal_slots(&group_id, &gone)?;
        let mut first_error = None;
        for slot in &gone.slots {
            if let Err(error) = self.discard_private_key_packages_of(slot) {
                first_error.get_or_insert(error);
            }
        }
        let mut held = BTreeSet::new();
        for chat_id in self.sibling_commit_chats() {
            let removal = match self.gone_device_leaves_in(&chat_id, &roster, &gone) {
                Ok(leaves) if leaves.is_empty() => continue,
                Ok(leaves) => {
                    held.extend(leaves.values().copied());
                    let context = Self::gone_leaf_removal_context(
                        leaves.values().any(|slot| chosen.contains(slot)),
                        leaves.len(),
                    );
                    self.remove_own_account_leaves(&chat_id, leaves.into_keys().collect(), context)
                        .await
                }
                Err(error) => Err(error),
            };
            match removal {
                Ok(OwnLeafRemoval::Sent) => self.linked_devices_changed = true,
                Ok(OwnLeafRemoval::Busy) => {
                    if let Err(error) = self.retry_when_quiet(&chat_id) {
                        first_error.get_or_insert(error);
                    }
                }
                Ok(OwnLeafRemoval::Unsupported) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Err(error) = self.keep_removed_device_keys(&group_id, &held, now) {
            first_error.get_or_insert(error);
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Renew, as seen now, every key this device keeps for each slot in
    /// `held` that a roster state recorded as `removed`, the slots whose
    /// leaves a chat this pass scanned still holds (mdk#3679). The engine
    /// records a key only when it applies a roster state that lists it, so
    /// once the `removed` record expires a removed device's keys would be
    /// forgotten 30 days later, and with them every leaf the device left in
    /// a chat that does not require `marmot.group.account-devices.v1` or that
    /// is busy that long. Storage renews a slot's kept keys in one step and
    /// keeps the order they were seen in, so no prune drops one that still
    /// reads a leftover's tag, and they go 30 days after no chat holds the
    /// device's leaf.
    fn keep_removed_device_keys(
        &self,
        group_id: &GroupId,
        held: &BTreeSet<DeviceSlotId>,
        now: u64,
    ) -> Result<(), AppError> {
        let removed = self
            .remembered_tag_keys_at(group_id, now)?
            .into_iter()
            .filter(|key| key.held_as_removed && held.contains(&key.slot))
            .map(|key| key.slot)
            .collect::<BTreeSet<_>>();
        if removed.is_empty() {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?;
        for slot in removed {
            storage.renew_roster_tag_keys(
                group_id,
                &slot,
                now.saturating_sub(ROSTER_TAG_KEY_RETENTION_SECS),
                now,
            )?;
        }
        Ok(())
    }

    /// How many chats this device is in still hold a leaf of a gone device
    /// that this device cannot remove, because the chat does not require
    /// `marmot.group.account-devices.v1`. A chat admin can remove it. Zero
    /// while device groups are off or no device is gone.
    pub(crate) fn removed_device_leftover_chats(&mut self) -> Result<u32, AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(0);
        }
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Ok(0);
        };
        let gone = self.gone_devices(&group_id, &roster, unix_now_seconds())?;
        if gone.slots.is_empty() {
            return Ok(0);
        }
        let mut leftovers = 0u32;
        for chat_id in self.sibling_commit_chats() {
            if !self
                .gone_device_leaves_in(&chat_id, &roster, &gone)?
                .is_empty()
                && !self.group_requires_account_devices(&chat_id)?
            {
                leftovers = leftovers.saturating_add(1);
            }
        }
        Ok(leftovers)
    }

    /// The devices the trusted device group `group_id` no longer lists, by
    /// its `roster`: each slot the roster records as `removed`, read by the
    /// key its record keeps, and, while the group is settled, each slot the
    /// roster lists no device in that has a remembered tag signature key,
    /// read by every such key. This device's own slot is never one.
    fn gone_devices(
        &self,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
        now: u64,
    ) -> Result<GoneDevices, AppError> {
        let mut gone = GoneDevices::default();
        let own_slot = self.own_slot().ok();
        for (slot, record) in &roster.rejected_slots {
            if record.reason != RejectedSlotReasonV1::Removed || Some(*slot) == own_slot {
                continue;
            }
            gone.slots.insert(*slot);
            if let Some(tag_signature_key) = &record.tag_signature_key {
                gone.keys.insert(RosterTagKey {
                    slot: *slot,
                    tag_signature_key: tag_signature_key.clone(),
                    held_as_removed: true,
                });
            }
        }
        // An unsettled group may still bring a listed device back, so only
        // its settled roster says a remembered key's device is gone. A device
        // that cannot read its own slot cannot tell its own keys apart, so it
        // reads none.
        let Some(own_slot) = own_slot else {
            return Ok(gone);
        };
        if self.device_group_settled(group_id) {
            let selected = self
                .stored_group(group_id)?
                .ok_or(AppError::DeviceGroupRefused("roster_unavailable"))?;
            let removals = self
                .app
                .account_storage(&self.state.label)?
                .app_storage()
                .device_removals()?;
            for key in self.remembered_tag_keys_at(group_id, now)? {
                let explicitly_removed = removals.iter().any(|removal| {
                    removal.group_id_hex == hex::encode(group_id.as_slice())
                        && removal.slot_hex == hex::encode(key.slot)
                });
                // A device that moved to another device group is not gone,
                // whichever key a roster state listed for its slot: its
                // leaves elsewhere still carry this group's tags (mdk#3679).
                let moved = !explicitly_removed
                    && !roster.rejected_slots.contains_key(&key.slot)
                    && selected.device_roster_departures.iter().any(|departure| {
                        departure.slot == key.slot
                            && departure.cause
                                == cgka_traits::group::DeviceRosterDepartureCause::Moved
                    });
                if !roster.devices.contains_key(&key.slot) && key.slot != own_slot && !moved {
                    gone.slots.insert(key.slot);
                    gone.keys.insert(key);
                }
            }
        }
        Ok(gone)
    }

    /// The existing authoritative gone classification, shared with retained
    /// Welcome repair. Readable absence alone is not evidence of removal.
    pub(super) fn gone_device_slots(
        &self,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
    ) -> Result<BTreeSet<DeviceSlotId>, AppError> {
        Ok(self
            .gone_devices(group_id, roster, unix_now_seconds())?
            .slots)
    }

    /// The tag signature keys rosters of `group_id` this device applied
    /// listed in the last 30 days (mdk#2761): by slot, and within a slot the
    /// most recently seen first. The engine records them.
    pub(super) fn remembered_tag_keys(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<RosterTagKey>, AppError> {
        self.remembered_tag_keys_at(group_id, unix_now_seconds())
    }

    /// [`Self::remembered_tag_keys`] as of `now`, for a pass that reads them
    /// more than once.
    fn remembered_tag_keys_at(
        &self,
        group_id: &GroupId,
        now: u64,
    ) -> Result<Vec<RosterTagKey>, AppError> {
        let since = now.saturating_sub(ROSTER_TAG_KEY_RETENTION_SECS);
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .roster_tag_keys(group_id, since)?)
    }

    /// Whether `group_id` is settled: stable, with no convergence input left
    /// to process, as a link's outcome is read.
    pub(super) fn device_group_settled(&self, group_id: &GroupId) -> bool {
        matches!(
            self.runtime.epoch_state(group_id),
            Some(EpochState::Stable { .. })
        ) && matches!(
            self.runtime.has_pending_convergence_inputs(group_id),
            Ok(false)
        )
    }

    /// The chats this device is in that may take a commit about its own
    /// account's devices, removing a gone device's leaves or adding a new
    /// one: not the device group, nor a chat that has ended or is
    /// quarantined. Chats not hydrated yet are left to a later pass rather
    /// than hydrated here, ahead of the background order.
    pub(super) fn sibling_commit_chats(&self) -> Vec<GroupId> {
        self.sibling_commit_chat_scan().0
    }

    /// A partial scan can drive individual Adds, but cannot declare how many
    /// chats a newly linked device should expect.
    pub(super) fn sibling_commit_chat_scan(&self) -> (Vec<GroupId>, bool) {
        let unhydrated = self
            .runtime
            .unhydrated_group_ids()
            .into_iter()
            .collect::<HashSet<_>>();
        let mut complete = true;
        let mut chats = Vec::new();
        for record in &self.state.groups {
            let Ok(bytes) = hex::decode(&record.group_id_hex) else {
                complete = false;
                continue;
            };
            let chat = GroupId::new(bytes);
            if super::group_is_quarantined(&self.runtime, &chat) {
                continue;
            }
            if unhydrated.contains(&chat) {
                complete = false;
                continue;
            }
            match self.is_device_group(&chat) {
                Ok(true) => {}
                Ok(false) => match self.runtime.group_record(&chat) {
                    Ok(group) if !group.is_terminal() => chats.push(chat),
                    Ok(_) => {}
                    Err(_) => {
                        // Preserve the candidate for existing removal and gap-fill callers.
                        complete = false;
                        chats.push(chat);
                    }
                },
                Err(_) => complete = false,
            }
        }
        (chats, complete)
    }

    /// This account's leaves in `chat_id` that are a `gone` device's, by
    /// signature key, each with the device's slot: each leaf whose device
    /// tag names a gone slot, under `roster`'s `leaf_tag_key`, and verifies
    /// under the leaf's own key, which only that leaf's device can sign
    /// (mdk#3679), or under one of the slot's keys.
    fn gone_device_leaves_in(
        &self,
        chat_id: &GroupId,
        roster: &DeviceRosterV1,
        gone: &GoneDevices,
    ) -> Result<BTreeMap<Vec<u8>, DeviceSlotId>, AppError> {
        let mut leaves = self
            .runtime
            .own_account_self_signed_tags(chat_id, &roster.leaf_tag_key)?
            .into_iter()
            .filter(|(_, slot)| gone.slots.contains(slot))
            .collect::<BTreeMap<_, _>>();
        let keys = gone.keys.iter().cloned().collect::<Vec<_>>();
        for (leaf, slot) in
            self.runtime
                .own_account_leaves_tagged_by(chat_id, &roster.leaf_tag_key, &keys)?
        {
            leaves.entry(leaf).or_insert(slot);
        }
        Ok(leaves)
    }

    /// The `gone` devices whose removal this device's user chose, while this
    /// device keeps that decision (`device_removals`). An automatic removal
    /// records none.
    fn chosen_removal_slots(
        &self,
        group_id: &GroupId,
        gone: &GoneDevices,
    ) -> Result<BTreeSet<DeviceSlotId>, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let chosen = self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .device_removals()?
            .into_iter()
            .filter(|removal| removal.group_id_hex == group_id_hex)
            .map(|removal| removal.slot_hex)
            .collect::<HashSet<_>>();
        Ok(gone
            .slots
            .iter()
            .filter(|slot| chosen.contains(&hex::encode(slot)))
            .copied()
            .collect())
    }

    /// The audit context of removing `count` gone devices' leaves from a
    /// chat: the user's when one of them is a device whose removal they
    /// chose here (`chosen`), and none otherwise.
    fn gone_leaf_removal_context(
        chosen: bool,
        count: usize,
    ) -> marmot_forensics::AuditEventContext {
        if !chosen {
            return marmot_forensics::AuditEventContext::default();
        }
        Self::local_human_action_context(
            "remove_own_account_devices",
            vec!["members"],
            Vec::new(),
            u64::try_from(count).ok(),
        )
    }

    /// Remove other leaves of this device's account, by signature key, from
    /// the chat `group_id`, in one same-account Remove, audited with
    /// `audit_context`. The removal of a device and of leaves tied to a
    /// rejection (3.7c) both use it.
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
        audit_context: marmot_forensics::AuditEventContext,
    ) -> Result<OwnLeafRemoval, AppError> {
        if !self.group_requires_account_devices(group_id)? {
            return Ok(OwnLeafRemoval::Unsupported);
        }
        if !self.group_quiet(group_id)? {
            return Ok(OwnLeafRemoval::Busy);
        }
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
    /// When a device-group pass that found `group_id` not quiet should look
    /// again (mdk#3265): `None` while it waits for an event (quarantined, or
    /// a Leave or disband under way), the second an epoch-gap hold ends, or
    /// `Some(0)` for what passes on its own (a commit, send or convergence
    /// in flight), retried 15 s after the last maintenance run.
    pub(crate) fn quiet_retry_at(&self, group_id: &GroupId) -> Result<Option<u64>, AppError> {
        if self.skips_quarantined_group_reads(group_id)
            || self
                .runtime
                .leave_in_progress(group_id)
                .map_err(marmot_session::SessionError::from)?
            || self.runtime.disbanding_in_progress(group_id)?
        {
            return Ok(None);
        }
        let epoch = self.runtime.group_record(group_id)?.epoch;
        let now_ms = super::recovery::wall_now_ms()?;
        Ok(Some(match self.epoch_gap_open_since(group_id, epoch)? {
            Some(since) if super::self_update_waits_for_epoch_gap(since, now_ms) => since
                .saturating_add(super::EPOCH_GAP_SELF_UPDATE_HOLD_MS)
                .div_ceil(1_000),
            _ => 0,
        }))
    }

    /// Have maintenance look again at work a device-group pass left because
    /// `group_id` was not quiet, at [`Self::quiet_retry_at`].
    pub(crate) fn retry_when_quiet(&mut self, group_id: &GroupId) -> Result<(), AppError> {
        match self.quiet_retry_at(group_id)? {
            None => {}
            Some(0) => self.device_group_work_changed = true,
            Some(at) => {
                self.device_group_retry_at =
                    Some(self.device_group_retry_at.map_or(at, |next| next.min(at)));
            }
        }
        Ok(())
    }

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
            || self.epoch_gap_holds_group(group_id, super::recovery::wall_now_ms()?)?
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
