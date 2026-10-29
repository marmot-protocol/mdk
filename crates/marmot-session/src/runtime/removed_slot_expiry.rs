//! Dropping old `removed` slot records (mdk#2628 item 3.1d).
//!
//! A `removed` record keeps a removed device's tag signature key, so the
//! account's devices still recognize its tags. A device drops the record once
//! 30 days have passed since its `rejected_at`, by this device's own clock
//! (device-roster-v1.md), so the roster does not keep every device the
//! account ever removed. `not_me` records stay. Maintenance makes the update
//! after its KeyPackage steps, under the same gate as the runtime's other
//! roster updates.

use cgka_traits::app_components::{DeviceRosterOperationV1, RejectedSlotReasonV1};
use cgka_traits::{GroupId, TransportAdapter};

use super::{AccountDeviceEffects, AccountDeviceRuntime, TRACE_TARGET};
use crate::error::AccountResult;
use crate::key_package::KeyPackagePublisher;
use crate::routing::TransportRoutingPolicy;

/// How long a `removed` slot record stays in the roster after its
/// `rejected_at`.
const REMOVED_SLOT_RECORD_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Maintenance's step after its KeyPackage steps: drop, in one roster
    /// update, every `removed` record in the device group this device tags
    /// from whose `rejected_at` is at least
    /// [`REMOVED_SLOT_RECORD_RETENTION_SECS`] old by this device's clock.
    ///
    /// Does nothing while maintenance is paused, the slot is withdrawn, no
    /// device group is named or its roster cannot be read, or the group
    /// cannot take a commit from this device now. A failure is logged and
    /// retried on the next pass.
    pub(super) async fn drop_expired_removed_slots_for_maintenance(
        &mut self,
        held: &[GroupId],
    ) -> AccountDeviceEffects {
        if self.maintenance_paused || self.key_package_slot_withdrawn {
            return AccountDeviceEffects::default();
        }
        self.drop_expired_removed_slots(held)
            .await
            .unwrap_or_else(|_| {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "drop_expired_removed_slots",
                    error_kind = "roster_update",
                    "could not drop expired removed-device records; maintenance retries"
                );
                AccountDeviceEffects::default()
            })
    }

    async fn drop_expired_removed_slots(
        &mut self,
        held: &[GroupId],
    ) -> AccountResult<AccountDeviceEffects> {
        let Some(group_id) = self.device_tag_group.clone() else {
            return Ok(AccountDeviceEffects::default());
        };
        let Some(roster) = self.merged_device_roster(&group_id) else {
            return Ok(AccountDeviceEffects::default());
        };
        let now = self.wall_clock.now().0;
        let expired: Vec<_> = roster
            .rejected_slots
            .iter()
            .filter(|(_, rejected)| {
                rejected.reason == RejectedSlotReasonV1::Removed
                    && rejected
                        .rejected_at
                        .checked_add(REMOVED_SLOT_RECORD_RETENTION_SECS)
                        .is_some_and(|expires_at| expires_at <= now)
            })
            .map(|(slot, _)| DeviceRosterOperationV1::RemoveRejectedSlot(*slot))
            .collect();
        if expired.is_empty() || !self.device_group_takes_commit(&group_id, held)? {
            return Ok(AccountDeviceEffects::default());
        }
        tracing::debug!(
            target: TRACE_TARGET,
            method = "drop_expired_removed_slots",
            record_count = expired.len(),
            "dropping expired removed-device records from the device group"
        );
        self.send_device_roster_update(group_id, expired).await
    }
}
