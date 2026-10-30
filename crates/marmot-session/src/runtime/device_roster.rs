//! This device's reads and writes of its device group's roster (mdk#2628):
//! its slot there, the roster as the merged group state holds it, the gate
//! the runtime's roster updates wait behind, and the send. Slot
//! announcements, the tag signature key, the removed-record expiry and
//! sign-in rejections share them.

use cgka_traits::app_components::{
    AppComponentData, DEVICE_ROSTER_COMPONENT_ID, DeviceRosterOperationV1, DeviceRosterUpdateV1,
    DeviceRosterV1, DeviceSlotId, decode_device_roster_v1, encode_device_roster_update_v1,
};
use cgka_traits::engine::SendIntent;
use cgka_traits::{FanoutMlsState, GroupId, TransportAdapter};

use marmot_forensics::AuditEventContext;

use super::{AccountDeviceEffects, AccountDeviceRuntime};
use crate::error::{AccountError, AccountResult};
use crate::key_package::KeyPackagePublisher;
use crate::routing::TransportRoutingPolicy;

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// This device's roster slot, its KeyPackage publication slot, or `None`
    /// while the lifecycle has none.
    pub(super) fn own_device_slot(&mut self) -> AccountResult<Option<DeviceSlotId>> {
        Ok(self
            .session
            .key_package_lifecycle()?
            .and_then(|lifecycle| hex::decode(lifecycle.stable_slot_id).ok())
            .and_then(|bytes| DeviceSlotId::try_from(bytes).ok()))
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

    /// Whether `group_id` can take a roster commit from this device now: it
    /// is not in `held`, quarantined or settling, and no earlier change of
    /// this device's there is still queued or unconfirmed.
    pub(super) fn device_group_takes_commit(
        &mut self,
        group_id: &GroupId,
        held: &[GroupId],
    ) -> AccountResult<bool> {
        Ok(!(held.contains(group_id)
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

    /// Commit `operations` to `group_id`'s roster as one update, audited
    /// with `context` when the host gives one. The returned effects carry the
    /// commit.
    pub(super) async fn send_device_roster_update(
        &mut self,
        group_id: GroupId,
        operations: Vec<DeviceRosterOperationV1>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<AccountDeviceEffects> {
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
