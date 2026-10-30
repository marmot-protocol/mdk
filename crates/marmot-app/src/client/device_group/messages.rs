//! Messages between this account's devices inside the device group it trusts
//! (mdk#2628).
//!
//! Each is a Marmot app event sent as an MLS application message in the
//! device group, never a chat message. Every feature that talks to siblings
//! shares these pieces:
//!
//! - [`AppClient::send_device_group_message`] sends one and says whether it
//!   reached a relay.
//! - [`AppClient::observe_device_group_event`] takes each device-group event
//!   and hands a message to the feature that owns its kind. A feature adds its
//!   kinds to that one match.
//! - [`is_device_group_kind`] lists every kind sent only in a device group. A
//!   device reads one only in the device group it trusts and ignores it in any
//!   other group, so no chat projects one and no host sends one as a custom
//!   event.
//! - [`AppClient::ensure_sent_by`] reads which slot sent a message from the
//!   sending leaf's device tag (D33), through 3.1d's one tag reader. It reads
//!   only the current tree, so a message from an earlier epoch has no
//!   readable sender.
//! - [`AppClient::device_group_exchange`] names the device group, its roster,
//!   this device's slot and whether this device's own leaf is tagged, which
//!   decides whether siblings will read what it sends.

use cgka_traits::app_components::{DeviceRosterV1, DeviceSlotId, DeviceTagClaim};
use cgka_traits::app_event::MarmotAppEvent;
use cgka_traits::engine::{GroupEvent, SendIntent};
use cgka_traits::storage::MaintenanceStorage as _;
use cgka_traits::{EpochId, GroupId};
use marmot_session::{KIND_PRIVATE_KEY_PACKAGE_HAND_OFF, KIND_PRIVATE_KEY_PACKAGE_REQUEST};

use super::device_slot;
use crate::client::AppClient;
use crate::{AppError, unix_now_seconds};

const TRACE_TARGET: &str = "marmot_app::client::device_group::messages";

/// A device heartbeat (mdk#2628 3.6a, marmot#462).
pub(crate) const KIND_DEVICE_HEARTBEAT: u64 = 457;
/// An anomaly alert (mdk#2628 3.7).
pub(crate) const KIND_ANOMALY_ALERT: u64 = 462;

/// True for a kind sent only in a device group: a heartbeat, a private
/// KeyPackage request or hand-off, or an anomaly alert. A device reads these
/// only in the device group it trusts and ignores them in any other group.
/// Whatever kind a device-group feature adds goes here too.
pub(crate) fn is_device_group_kind(kind: u64) -> bool {
    matches!(
        kind,
        KIND_DEVICE_HEARTBEAT
            | KIND_PRIVATE_KEY_PACKAGE_REQUEST
            | KIND_PRIVATE_KEY_PACKAGE_HAND_OFF
            | KIND_ANOMALY_ALERT
    )
}

/// The trusted device group this device talks to its siblings in, its
/// roster, this device's slot there, and whether this device's own leaf
/// carries a device tag that reads as that slot. Siblings read nothing this
/// device sends until it does.
pub(crate) struct Exchange {
    pub(crate) group_id: GroupId,
    pub(crate) roster: DeviceRosterV1,
    pub(crate) own_slot: DeviceSlotId,
    pub(crate) tagged: bool,
}

impl Exchange {
    /// Every other device the roster lists.
    pub(crate) fn siblings(&self) -> Vec<DeviceSlotId> {
        self.roster
            .devices
            .keys()
            .filter(|slot| **slot != self.own_slot)
            .copied()
            .collect()
    }

    pub(crate) fn is_sibling(&self, slot: &DeviceSlotId) -> bool {
        *slot != self.own_slot && self.roster.devices.contains_key(slot)
    }
}

impl AppClient {
    /// The exchange this device takes part in: the trusted device group's,
    /// while the roster lists this device.
    pub(crate) fn device_group_exchange(&mut self) -> Result<Option<Exchange>, AppError> {
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Ok(None);
        };
        let Some(own_slot) = self
            .app
            .account_storage(&self.state.label)?
            .key_package_lifecycle()?
            .and_then(|lifecycle| device_slot(&lifecycle.stable_slot_id).ok())
        else {
            return Ok(None);
        };
        if !roster.devices.contains_key(&own_slot) {
            return Ok(None);
        }
        let epoch = self.runtime.group_record(&group_id)?.epoch;
        let own_leaf = self.runtime.own_leaf_index(&group_id)?;
        let tagged = self
            .runtime
            .member_device_tag_claim(&group_id, epoch, own_leaf, &roster)?
            == Some(DeviceTagClaim::Device(own_slot));
        Ok(Some(Exchange {
            group_id,
            roster,
            own_slot,
            tagged,
        }))
    }

    /// Take a message from a device-group event and hand it to the feature
    /// that owns its kind. Anything else is ignored, and so is anything that
    /// feature finds not addressed to this device.
    pub(crate) fn observe_device_group_event(&mut self, event: &GroupEvent) {
        let GroupEvent::MessageReceived {
            group_id,
            message_id,
            sender_leaf_index,
            epoch,
            payload,
            ..
        } = event
        else {
            return;
        };
        let Ok(message) = MarmotAppEvent::decode(payload) else {
            return;
        };
        let sender = (*epoch, *sender_leaf_index);
        let result = match message.kind {
            KIND_DEVICE_HEARTBEAT => {
                self.receive_device_heartbeat(group_id, sender, message.created_at)
            }
            KIND_PRIVATE_KEY_PACKAGE_REQUEST => {
                self.receive_key_package_request(group_id, message_id, sender, &message.content)
            }
            KIND_PRIVATE_KEY_PACKAGE_HAND_OFF => {
                self.receive_key_package_hand_off(group_id, sender, &message.content)
            }
            _ => return,
        };
        if let Err(error) = result {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "observe_device_group_event",
                kind = message.kind,
                error_kind = error.privacy_safe_kind(),
                "a device-group message was refused"
            );
        }
    }

    /// Refuse a message unless the leaf that sent it, at the message's epoch,
    /// carries a device tag that reads as `from`'s in `roster` (mdk#2628 D33).
    /// A sibling whose leaf is not tagged yet is refused and not counted; it
    /// sends again once it has tagged its leaf. So is a removed device, whose
    /// tag reads as its rejected slot, and a message from an epoch that is no
    /// longer current.
    pub(crate) fn ensure_sent_by(
        &mut self,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
        (epoch, sender_leaf_index): (EpochId, Option<u32>),
        from: &DeviceSlotId,
    ) -> Result<(), AppError> {
        let claim = match sender_leaf_index {
            Some(leaf) => self
                .runtime
                .member_device_tag_claim(group_id, epoch, leaf, roster)?,
            None => None,
        };
        if claim == Some(DeviceTagClaim::Device(*from)) {
            Ok(())
        } else {
            Err(AppError::DeviceGroupRefused("sender_not_tagged"))
        }
    }

    /// Send a device-group message of `kind` from this device. `false` means
    /// its publication failed terminally and reached no one. One published,
    /// unresolved or queued counts as sent: that same message still goes out.
    pub(crate) async fn send_device_group_message(
        &mut self,
        group_id: &GroupId,
        kind: u64,
        content: String,
    ) -> Result<bool, AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let event = MarmotAppEvent::new(
            account.account_id_hex,
            unix_now_seconds(),
            kind,
            Vec::new(),
            content,
        );
        let payload = event
            .encode()
            .map_err(|error| AppError::InvalidAppMessagePayload(error.to_string()))?;
        let effects = self
            .runtime
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload,
                expected_epoch: None,
            })
            .await?;
        let reached = !effects
            .failed_app_messages
            .iter()
            .any(|failed| failed.group_id == *group_id && failed.app_event_id == event.id);
        let observed = self.observe_drained_session_events(&effects).await;
        // This message's terminal failure is also the drain's publish error;
        // the caller undoes its marks instead of failing.
        if !reached {
            return Ok(false);
        }
        observed?;
        Ok(true)
    }
}
