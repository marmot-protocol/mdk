//! Deleting a removed sibling's KeyPackage slot (mdk#2628 item 3.6b, D22).
//!
//! A device manages only its own KeyPackages, with one exception: a device
//! that removed a sibling from the device group deletes that sibling's
//! public slot, so inviters stop adding a removed device to new chats. It
//! names the slot by the `d` the roster recorded, as a deletion of
//! `30443:<account>:<d>`. Nothing else here deletes another device's slot.
//!
//! The deletion goes out only while the device group is settled and its
//! merged state no longer lists the slot as a device: it records the slot as
//! `removed`, or that record has expired since. Branch selection can still
//! drop the removal after that; the device that decided it then removes the
//! device again and deletes the slot again. The deletion is cleanup, not
//! revocation: a relay may keep serving the KeyPackage until it expires.

use cgka_traits::app_components::{DeviceSlotId, RejectedSlotReasonV1};
use cgka_traits::{EpochState, GroupId, Timestamp, TransportAdapter};

use super::{AccountDeviceRuntime, KEY_PACKAGE_MAX_FUTURE_SKEW_SECS, TRACE_TARGET};
use crate::error::AccountResult;
use crate::key_package::{KeyPackagePublishError, KeyPackagePublisher, KeyPackageSlotWithdrawal};
use crate::routing::TransportRoutingPolicy;

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Ask the relays to stop serving the KeyPackage slot of `slot`, a
    /// device removed from `group_id`, the device group this device tags
    /// from. The request names that slot and nothing else. It is stamped as
    /// far ahead of now as a publisher may stamp a KeyPackage, so it covers
    /// every publication in the slot an inviter would accept now, from a
    /// device whose clock runs ahead included.
    ///
    /// The caller holds the decision that removed `slot`: this checks only
    /// that the device group agrees. `None` sends nothing: `group_id` is not
    /// the device group this device tags from, its merged roster cannot be
    /// read, lists `slot` as a device or records it as `not_me`, the slot is
    /// this device's own, or the group is not settled (not stable, or with
    /// convergence input pending). Otherwise returns how many endpoints
    /// accepted it; none accepting is an error, and the caller asks again.
    pub async fn withdraw_removed_device_slot(
        &mut self,
        group_id: &GroupId,
        slot: &DeviceSlotId,
    ) -> AccountResult<Option<usize>> {
        if self.device_tag_group.as_ref() != Some(group_id)
            || self.own_device_slot()?.as_ref() == Some(slot)
            || !matches!(
                self.session.epoch_state(group_id),
                Some(EpochState::Stable { .. })
            )
            || self.session.has_pending_convergence_inputs(group_id)?
        {
            return Ok(None);
        }
        let not_listed = self.merged_device_roster(group_id).is_some_and(|roster| {
            !roster.devices.contains_key(slot)
                && roster
                    .rejected_slots
                    .get(slot)
                    .is_none_or(|record| record.reason != RejectedSlotReasonV1::NotMe)
        });
        if !not_listed {
            return Ok(None);
        }
        let endpoints = self.routing.key_package_endpoints().to_vec();
        if endpoints.is_empty() {
            return Err(KeyPackagePublishError::unexposed(
                "no KeyPackage publication endpoints are configured",
            )
            .into());
        }
        let withdrawal = KeyPackageSlotWithdrawal {
            account_id: self.session.self_id().clone(),
            slot_id: hex::encode(slot),
            created_at: Timestamp(
                self.wall_clock
                    .now()
                    .0
                    .saturating_add(KEY_PACKAGE_MAX_FUTURE_SKEW_SECS),
            ),
            endpoints,
        };
        let endpoint_count = withdrawal.endpoints.len();
        match self
            .key_packages
            .withdraw_key_package_slot(&withdrawal)
            .await
        {
            Ok(receipt) if !receipt.accepted.is_empty() => {
                tracing::info!(
                    target: TRACE_TARGET,
                    method = "withdraw_removed_device_slot",
                    endpoint_count,
                    accepted_count = receipt.accepted.len(),
                    "withdrew a removed device's key package slot"
                );
                Ok(Some(receipt.accepted.len()))
            }
            Ok(_) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "withdraw_removed_device_slot",
                    endpoint_count,
                    "no endpoint accepted a removed device's slot withdrawal"
                );
                Err(KeyPackagePublishError::unexposed(
                    "no KeyPackage relay accepted the slot withdrawal",
                )
                .into())
            }
            Err(error) => Err(error.into()),
        }
    }
}
