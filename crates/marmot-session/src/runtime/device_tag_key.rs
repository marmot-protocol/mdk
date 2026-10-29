//! This device's tag signature key (mdk#2628 item 3.1d).
//!
//! A device tags its KeyPackages and leaves once its entry in its device
//! group's roster carries its tag signature key, its MLS signature key
//! (device-tag-v1.md, "Producing tags"). The founder writes its own key into
//! the founding roster. Every other device sets its own once it has joined,
//! in a roster update whose own UpdatePath the engine already tags under that
//! key. Maintenance and every host KeyPackage publication make that update
//! first; the host names the group.
//!
//! No KeyPackage is staged while the key is due and not yet in the merged
//! roster: it would be built untagged and published after the key was set.

use cgka_traits::app_components::{
    AppComponentData, DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterOperationV1,
    DeviceRosterUpdateV1, DeviceSlotId, decode_device_roster_v1, encode_device_roster_update_v1,
};
use cgka_traits::engine::SendIntent;
use cgka_traits::{FanoutMlsState, GroupId, TransportAdapter};

use super::{AccountDeviceEffects, AccountDeviceRuntime, TRACE_TARGET};
use crate::error::{AccountError, AccountResult};
use crate::key_package::KeyPackagePublisher;
use crate::routing::TransportRoutingPolicy;

/// Where this device's roster entry stands for its tag signature key.
enum TagKey {
    /// The entry carries it, or no device group is named.
    Set,
    /// The entry lacks it.
    Due {
        slot: DeviceSlotId,
        entry: Box<DeviceEntryV1>,
    },
    /// Another device's entry carries this device's key. The engine tags from
    /// whichever entry carries it, so a KeyPackage built now would read as
    /// that device's: nothing is staged until the roster is repaired.
    HeldByAnotherDevice,
    /// It cannot be set now: the device group is unreadable, holds no entry
    /// for this device's slot, or a removed slot keeps the key.
    Blocked(&'static str),
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Tag this device's KeyPackages and leaves from `group_id`'s roster, or
    /// stop with `None`. The host names the device group it trusts and sets
    /// it again after every open. An error says the group is not live; it
    /// stays named. See [`cgka_engine::engine::Engine::set_device_tag_group`].
    pub fn set_device_tag_group(&mut self, group_id: Option<GroupId>) -> AccountResult<()> {
        self.device_tag_group = group_id.clone();
        Ok(self.session.set_device_tag_group(group_id)?)
    }

    /// The device group this device tags from, as the host last named it.
    pub fn device_tag_group(&self) -> Option<&GroupId> {
        self.device_tag_group.as_ref()
    }

    /// Whether a KeyPackage staged now is built as this device should
    /// build it: no device group is named, the slot is withdrawn, the merged
    /// roster carries this device's tag signature key in its own entry, or
    /// the device cannot tag from that roster at all. False while the key is
    /// due, whether or not an update setting it is on its way, and while
    /// another device's entry carries it.
    pub(super) fn device_tag_key_settled(&mut self) -> AccountResult<bool> {
        let Some(group_id) = self.device_tag_group.clone() else {
            return Ok(true);
        };
        if self.key_package_slot_withdrawn {
            return Ok(true);
        }
        Ok(!matches!(
            self.device_tag_key(&group_id)?,
            TagKey::Due { .. } | TagKey::HeldByAnotherDevice
        ))
    }

    /// Maintenance's step before it stages or announces a KeyPackage:
    /// [`Self::set_device_tag_key_holding`], except while maintenance is
    /// paused. A failure is logged and retried on the next pass.
    pub(super) async fn set_device_tag_key_for_maintenance(
        &mut self,
        held: &[GroupId],
    ) -> AccountDeviceEffects {
        if self.maintenance_paused {
            return AccountDeviceEffects::default();
        }
        self.set_device_tag_key_holding(held)
            .await
            .unwrap_or_else(|_| {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "set_device_tag_key",
                    error_kind = "roster_update",
                    "could not set this device's tag signature key; maintenance retries"
                );
                AccountDeviceEffects::default()
            })
    }

    /// Set this device's tag signature key in its roster entry when the
    /// entry lacks it. The returned effects carry the roster commit. The host
    /// calls this before it publishes a KeyPackage, which is refused until
    /// the merged roster carries the key.
    ///
    /// Does nothing when no device group is named, the slot is withdrawn, the
    /// entry already carries the key, or the device group cannot take a
    /// commit from this device now: it is in `held`, quarantined, or
    /// settling, or an earlier change of this device's there is still queued
    /// or unconfirmed. A later call retries.
    pub async fn set_device_tag_key_holding(
        &mut self,
        held: &[GroupId],
    ) -> AccountResult<AccountDeviceEffects> {
        let Some(group_id) = self.device_tag_group.clone() else {
            return Ok(AccountDeviceEffects::default());
        };
        if self.key_package_slot_withdrawn {
            return Ok(AccountDeviceEffects::default());
        }
        let (slot, mut entry) = match self.device_tag_key(&group_id)? {
            TagKey::Set => return Ok(AccountDeviceEffects::default()),
            TagKey::Due { slot, entry } => (slot, *entry),
            TagKey::HeldByAnotherDevice => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    method = "set_device_tag_key",
                    reason = "key_held_by_another_device",
                    "cannot set this device's tag signature key; no key package is staged"
                );
                return Ok(AccountDeviceEffects::default());
            }
            TagKey::Blocked(reason) => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    method = "set_device_tag_key",
                    reason,
                    "cannot set this device's tag signature key yet"
                );
                return Ok(AccountDeviceEffects::default());
            }
        };
        if held.contains(&group_id)
            || self
                .session
                .quarantined_groups()
                .iter()
                .any(|(quarantined, _)| quarantined == &group_id)
            || self.session.has_pending_convergence_inputs(&group_id)?
            || self.session.has_queued_outbound_intents(&group_id)?
            || self
                .session
                .outbound_fanouts_for_group(&group_id)?
                .iter()
                .any(|fanout| matches!(fanout.mls_state(), FanoutMlsState::Pending(_)))
        {
            return Ok(AccountDeviceEffects::default());
        }
        // The commit replaces the entry whole: every other field stays as
        // the roster holds it.
        entry.tag_signature_key = Some(self.session.own_signature_key());
        let update =
            DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetDevice(slot, entry)])
                .and_then(|update| encode_device_roster_update_v1(&update))
                .map_err(|error| {
                    AccountError::Engine(cgka_traits::EngineError::Serialize(error))
                })?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "set_device_tag_key",
            "setting this device's tag signature key in its device group"
        );
        self.send(SendIntent::UpdateAppComponents {
            group_id,
            updates: vec![AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: update,
            }],
        })
        .await
    }

    fn device_tag_key(&mut self, group_id: &GroupId) -> AccountResult<TagKey> {
        let Some(slot) = self
            .session
            .key_package_lifecycle()?
            .and_then(|lifecycle| hex::decode(lifecycle.stable_slot_id).ok())
            .and_then(|bytes| DeviceSlotId::try_from(bytes).ok())
        else {
            return Ok(TagKey::Blocked("slot_unavailable"));
        };
        let roster = self
            .session
            .ensure_group_hydrated(group_id)
            .ok()
            .and_then(|_| {
                self.session
                    .app_component(group_id, DEVICE_ROSTER_COMPONENT_ID)
                    .ok()
            })
            .flatten()
            .and_then(|bytes| decode_device_roster_v1(&bytes).ok());
        let Some(mut roster) = roster else {
            return Ok(TagKey::Blocked("device_group_unreadable"));
        };
        let own_key = self.session.own_signature_key();
        let Some(entry) = roster.devices.remove(&slot) else {
            return Ok(TagKey::Blocked("no_roster_entry"));
        };
        if entry.tag_signature_key.as_deref() == Some(own_key.as_slice()) {
            return Ok(TagKey::Set);
        }
        // A roster gives each key one device, and a removed slot keeps the
        // key its tags read as.
        if roster
            .devices
            .values()
            .any(|other| other.tag_signature_key.as_deref() == Some(own_key.as_slice()))
        {
            return Ok(TagKey::HeldByAnotherDevice);
        }
        if roster
            .rejected_slots
            .values()
            .any(|rejected| rejected.tag_signature_key.as_deref() == Some(own_key.as_slice()))
        {
            return Ok(TagKey::Blocked("key_held_by_removed_slot"));
        }
        Ok(TagKey::Due {
            slot,
            entry: Box::new(entry),
        })
    }
}
