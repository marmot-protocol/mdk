//! Recording rejected slots on their own (mdk#2628 item 3.2, mdk#2761).
//!
//! "This wasn't me" records the sign-in's KeyPackage slot alone, as a
//! `not_me` rejected slot in the roster of this device's device group. A
//! removal that a failed link's undo outran records the removed device's
//! slot alone too, as a `removed` record keeping its tag signature key. A
//! rejection never replaces an entry: a slot the roster already holds, as a
//! device or as a rejected slot, stays as it is. Both wait behind the gate
//! the runtime's other roster updates wait behind. A `not_me` record goes
//! through the runtime's rejected-slot send. A `removed` record goes only
//! through [`AccountDeviceRuntime::record_removed_slot`], as
//! [`SendIntent::RecordRemovedSlot`], which the engine never queues and never
//! re-issues after a lost fork, so only its caller makes it again.

use cgka_traits::app_components::{
    DeviceRosterOperationV1, DeviceRosterUpdateV1, DeviceSlotId, RejectedSlotReasonV1,
    RejectedSlotV1, encode_device_roster_update_v1,
};
use cgka_traits::engine::SendIntent;
use cgka_traits::{EngineError, GroupId, TransportAdapter};
use marmot_forensics::AuditEventContext;

use super::{AccountDeviceEffects, AccountDeviceRuntime, TRACE_TARGET};
use crate::error::{AccountError, AccountResult};
use crate::key_package::KeyPackagePublisher;
use crate::routing::TransportRoutingPolicy;

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Record each of `rejections` as a rejected slot in the roster of
    /// `group_id`, in one roster update carrying `context`. The returned
    /// effects carry the commit.
    ///
    /// Leaves out every slot the merged roster already holds, as a device or
    /// a rejected slot. Sends nothing when that leaves none, the roster
    /// cannot be read, or the group cannot take a commit from this device
    /// now: it is in `held`, quarantined, or settling, or an earlier change
    /// of this device's there is still queued or unconfirmed. A later call
    /// retries. A `removed` record is refused: it goes out only through
    /// [`Self::record_removed_slot`].
    pub async fn reject_device_slots(
        &mut self,
        group_id: &GroupId,
        held: &[GroupId],
        rejections: Vec<(DeviceSlotId, RejectedSlotV1)>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        if rejections
            .iter()
            .any(|(_, rejected)| rejected.reason == RejectedSlotReasonV1::Removed)
        {
            return Err(AccountError::Engine(EngineError::Other(
                "a removed slot's record goes out only through record_removed_slot".into(),
            )));
        }
        let Some(roster) = self.merged_device_roster(group_id) else {
            return Ok(AccountDeviceEffects::default());
        };
        let operations: Vec<_> = rejections
            .into_iter()
            .filter(|(slot, _)| {
                !roster.devices.contains_key(slot) && !roster.rejected_slots.contains_key(slot)
            })
            .map(|(slot, rejected)| DeviceRosterOperationV1::SetRejectedSlot(slot, rejected))
            .collect();
        if operations.is_empty() || !self.device_group_takes_commit(group_id, held)? {
            return Ok(AccountDeviceEffects::default());
        }
        tracing::debug!(
            target: TRACE_TARGET,
            method = "reject_device_slots",
            slot_count = operations.len(),
            "recording rejected sign-ins in the device group"
        );
        self.send_device_roster_update(group_id.clone(), operations, Some(context))
            .await
    }

    /// Record `slot` in the roster of `group_id` as `removed` with `record`,
    /// alone, carrying `context` (mdk#2761): the record a removal that a
    /// failed link's undo outran leaves to make. It goes out as
    /// [`SendIntent::RecordRemovedSlot`], which the engine never queues and
    /// never re-issues after a lost fork, so only the caller makes it again.
    ///
    /// Sends nothing when the merged roster already holds the slot, as a
    /// device or a rejected slot, the roster cannot be read, or the group
    /// cannot take a commit from this device now, as
    /// [`Self::reject_device_slots`] waits. A later call retries.
    pub async fn record_removed_slot(
        &mut self,
        group_id: &GroupId,
        held: &[GroupId],
        slot: DeviceSlotId,
        record: RejectedSlotV1,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let Some(roster) = self.merged_device_roster(group_id) else {
            return Ok(AccountDeviceEffects::default());
        };
        if roster.devices.contains_key(&slot)
            || roster.rejected_slots.contains_key(&slot)
            || !self.device_group_takes_commit(group_id, held)?
        {
            return Ok(AccountDeviceEffects::default());
        }
        let roster_update =
            DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetRejectedSlot(slot, record)])
                .and_then(|update| encode_device_roster_update_v1(&update))
                .map_err(|error| AccountError::Engine(EngineError::Serialize(error)))?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "record_removed_slot",
            "recording a removed slot alone in the device group"
        );
        self.send_with_audit_context(
            SendIntent::RecordRemovedSlot {
                group_id: group_id.clone(),
                roster_update,
            },
            context,
        )
        .await
    }
}
