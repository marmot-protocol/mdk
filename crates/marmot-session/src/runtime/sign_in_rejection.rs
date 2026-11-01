//! Recording rejected slots on their own (mdk#2628 item 3.2, mdk#2761).
//!
//! "This wasn't me" records the sign-in's KeyPackage slot alone, as a
//! `not_me` rejected slot in the roster of this device's device group. A
//! removal that a failed link's undo outran records the removed device's
//! slot alone too, as a `removed` record keeping its tag signature key. A
//! rejection never replaces an entry: a slot the roster already holds, as a
//! device or as a rejected slot, stays as it is. The update goes through the
//! runtime's rejected-slot send, behind the gate its other roster updates
//! wait behind.

use cgka_traits::app_components::{DeviceRosterOperationV1, DeviceSlotId, RejectedSlotV1};
use cgka_traits::{GroupId, TransportAdapter};
use marmot_forensics::AuditEventContext;

use super::{AccountDeviceEffects, AccountDeviceRuntime, TRACE_TARGET};
use crate::error::AccountResult;
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
    /// retries.
    pub async fn reject_device_slots(
        &mut self,
        group_id: &GroupId,
        held: &[GroupId],
        rejections: Vec<(DeviceSlotId, RejectedSlotV1)>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
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
}
