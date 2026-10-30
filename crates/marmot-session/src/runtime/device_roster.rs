//! This device's reads and writes of its device group's roster (mdk#2628):
//! its slot there, the roster as the merged group state holds it, the gate
//! its roster commits wait behind, and the sends.
//!
//! Device entries have one write path (3.4, 3.6, 3.1d):
//! [`AccountDeviceRuntime::edit_device_roster_entry`], a commit that replaces
//! one entry. Slot announcements, the tag signature key and the host's device
//! edits all use it. Rejected-slot records (3.1d's expiry and 3.2's sign-in
//! rejections) go through [`AccountDeviceRuntime::send_device_roster_update`]
//! and never touch a device entry.
//!
//! `SetDevice` replaces an entry whole, so a commit computed from an older
//! read would put back whatever a sibling or an earlier commit of this device
//! changed in that entry. The edit is sent as
//! [`SendIntent::ReplaceDeviceEntry`], which names the entry it read: the
//! engine stages it only while the slot still holds that entry, whenever it
//! prepares the commit (after the send settles convergence input, when a
//! queued copy drains, or when it re-issues the edit after a lost fork). The
//! edit is also sent only while the device group is stable and nothing else
//! of this device's is in flight there. A blocked edit sends nothing; the
//! caller retries or reports it.
//!
//! A device keeps its own entry's `client` and `platform` current itself
//! ([`DeviceSelfReport`]); each announcement of its KeyPackage writes them.

use cgka_traits::app_components::{
    AppComponentData, DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterOperationV1,
    DeviceRosterUpdateV1, DeviceRosterV1, DeviceSlotId, decode_device_roster_v1,
    encode_device_roster_update_v1,
};
use cgka_traits::engine::SendIntent;
use cgka_traits::{EngineError, EpochState, FanoutMlsState, GroupId, TransportAdapter};

use marmot_forensics::AuditEventContext;

use super::{AccountDeviceEffects, AccountDeviceRuntime};
use crate::error::{AccountError, AccountResult};
use crate::key_package::KeyPackagePublisher;
use crate::routing::TransportRoutingPolicy;
use crate::session::SessionError;

/// What [`AccountDeviceRuntime::edit_device_roster_entry`] did.
#[derive(Debug)]
pub enum DeviceRosterEdit {
    /// The roster commit was staged and sent, or queued until the device
    /// group settles.
    Committed(Box<AccountDeviceEffects>),
    /// The entry already reads as edited; nothing was sent.
    Unchanged,
    /// Nothing was sent.
    Blocked(DeviceRosterEditBlocked),
}

/// Why a roster edit sent nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceRosterEditBlocked {
    /// The device group's roster cannot be read.
    Unreadable,
    /// The roster holds no entry for the slot.
    NoEntry,
    /// The device group cannot take a commit from this device now: it is
    /// not stable, is held, quarantined or settling, an earlier change of
    /// this device's there is still queued or unconfirmed, or a commit the
    /// send settled first changed the entry this edit read.
    Busy,
}

/// What this device says about itself in its own roster entry (mdk#2628
/// 3.6): the client it runs and the platform it runs on. Empty says nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceSelfReport {
    pub client: String,
    pub platform: String,
}

impl DeviceSelfReport {
    pub(super) fn apply(&self, entry: &mut DeviceEntryV1) {
        entry.client.clone_from(&self.client);
        entry.platform.clone_from(&self.platform);
    }
}

impl DeviceRosterEditBlocked {
    /// A privacy-safe name for traces and errors.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Unreadable => "device_group_unreadable",
            Self::NoEntry => "no_roster_entry",
            Self::Busy => "device_group_busy",
        }
    }
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Set what this device says about itself in its own roster entry. The
    /// next announcement writes it when it differs; each value must fit the
    /// roster's 64-byte bound.
    pub fn set_device_self_report(&mut self, report: DeviceSelfReport) {
        self.device_self_report = report;
    }

    /// Replace the entry of `slot` in the roster of `group_id` with `edit`
    /// applied to it, in one commit. Every other field, and every other
    /// entry, stays as the roster holds it. `held` lists groups the host is
    /// holding back from commits.
    pub async fn edit_device_roster_entry(
        &mut self,
        group_id: &GroupId,
        slot: &DeviceSlotId,
        held: &[GroupId],
        edit: impl FnOnce(&mut DeviceEntryV1),
    ) -> AccountResult<DeviceRosterEdit> {
        let Some(mut roster) = self.merged_device_roster(group_id) else {
            return Ok(DeviceRosterEdit::Blocked(
                DeviceRosterEditBlocked::Unreadable,
            ));
        };
        let Some(current) = roster.devices.remove(slot) else {
            return Ok(DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::NoEntry));
        };
        let mut entry = current.clone();
        edit(&mut entry);
        if entry == current {
            return Ok(DeviceRosterEdit::Unchanged);
        }
        if !self.device_group_takes_commit(group_id, held)? {
            return Ok(DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::Busy));
        }
        let intent = SendIntent::ReplaceDeviceEntry {
            group_id: group_id.clone(),
            slot: *slot,
            expected: Box::new(current),
            entry: Box::new(entry),
        };
        let staged = match self.session.send(intent).await {
            Ok(staged) => staged,
            Err(SessionError::Engine(EngineError::DeviceEntryChanged { .. })) => {
                return Ok(DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::Busy));
            }
            Err(error) => return Err(error.into()),
        };
        Ok(DeviceRosterEdit::Committed(Box::new(
            self.publish_session_effects(staged).await?,
        )))
    }

    /// Whether this device may commit in the device group `group_id` now:
    /// it is stable and not held, quarantined or settling, and nothing of
    /// this device's is queued or unconfirmed there.
    pub(super) fn device_group_takes_commit(
        &mut self,
        group_id: &GroupId,
        held: &[GroupId],
    ) -> AccountResult<bool> {
        Ok(matches!(
            self.session.epoch_state(group_id),
            Some(EpochState::Stable { .. })
        ) && !(held.contains(group_id)
            || self
                .session
                .quarantined_groups()
                .iter()
                .any(|(quarantined, _)| quarantined == group_id)
            || self.session.has_pending_convergence_inputs(group_id)?
            || self.session.has_queued_outbound_intents(group_id)?
            || self
                .session
                .outbound_fanouts_for_group(group_id)?
                .iter()
                .any(|fanout| matches!(fanout.mls_state(), FanoutMlsState::Pending(_)))))
    }

    /// `group_id`'s roster as its merged state holds it, or `None` when it
    /// cannot be read.
    pub(super) fn merged_device_roster(&mut self, group_id: &GroupId) -> Option<DeviceRosterV1> {
        self.session
            .ensure_group_hydrated(group_id)
            .ok()
            .and_then(|_| {
                self.session
                    .app_component(group_id, DEVICE_ROSTER_COMPONENT_ID)
                    .ok()
            })
            .flatten()
            .and_then(|bytes| decode_device_roster_v1(&bytes).ok())
    }

    /// This device's KeyPackage slot as the roster keys it, if it has one
    /// that is 32 bytes.
    pub(super) fn own_device_slot(&mut self) -> AccountResult<Option<DeviceSlotId>> {
        Ok(self
            .session
            .key_package_lifecycle()?
            .and_then(|lifecycle| hex::decode(lifecycle.stable_slot_id).ok())
            .and_then(|bytes| DeviceSlotId::try_from(bytes).ok()))
    }

    /// Commit rejected-slot `operations` to `group_id`'s roster as one
    /// update, audited with `context` when the host gives one. The returned
    /// effects carry the commit. A device entry is never written here:
    /// [`Self::edit_device_roster_entry`] replaces one only while it is still
    /// the entry it read.
    pub(super) async fn send_device_roster_update(
        &mut self,
        group_id: GroupId,
        operations: Vec<DeviceRosterOperationV1>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<AccountDeviceEffects> {
        debug_assert!(operations.iter().all(|operation| matches!(
            operation,
            DeviceRosterOperationV1::SetRejectedSlot(..)
                | DeviceRosterOperationV1::RemoveRejectedSlot(_)
        )));
        let update = DeviceRosterUpdateV1::new(operations)
            .and_then(|update| encode_device_roster_update_v1(&update))
            .map_err(|error| AccountError::Engine(cgka_traits::EngineError::Serialize(error)))?;
        let intent = SendIntent::UpdateAppComponents {
            group_id,
            updates: vec![AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: update,
            }],
        };
        match context {
            Some(context) => self.send_with_audit_context(intent, context).await,
            None => self.send(intent).await,
        }
    }
}
