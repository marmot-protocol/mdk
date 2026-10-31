//! Messages between this account's devices inside the device group it trusts
//! (mdk#2628).
//!
//! Each is a Marmot app event sent as an MLS application message in the
//! device group, never a chat message. Every feature that talks to siblings
//! shares these pieces:
//!
//! - [`AppClient::send_device_group_message`] sends one and says whether it
//!   reached a relay. [`AppClient::send_device_group_event`] sends one a
//!   feature built with [`AppClient::device_group_event`], for a feature that
//!   records the event's id first.
//! - [`AppClient::observe_device_group_event`] takes each device-group event
//!   and hands a message to the feature that owns its kind. A feature adds its
//!   kinds to that one match.
//! - [`is_device_group_kind`] lists every kind sent only in a device group. A
//!   device reads one only in the device group it trusts and ignores it in any
//!   other group, so no chat projects one and no host sends one as a custom
//!   event.
//! - [`AppClient::ensure_sent_by`] reads which slot sent a message from the
//!   sending leaf's device tag (D33), through 3.1d's one tag reader. A
//!   message from an earlier epoch is read from that epoch's retained anchor,
//!   so one older than the retained anchors has no readable sender.
//! - [`AppClient::device_group_exchange`] names the device group, its roster,
//!   this device's slot and whether this device's own leaf is tagged, which
//!   decides whether siblings will read what it sends.
//! - [`AppClient::device_group_message_withdrawn`] hands a withdrawn message
//!   to the feature that owns its kind. The engine names a withdrawn message
//!   only by its message id (an own send's transport id, a received
//!   message's content id), so each message of a kind in
//!   [`withdrawal_handled`] is recorded with its kind when this device sends
//!   or reads it. A feature adds its kinds to both. Records go after a week
//!   or past 4,096, so a feature also says what a withdrawn message of no
//!   recorded kind owes it.

use cgka_traits::app_components::{DeviceRosterV1, DeviceSlotId, DeviceTagClaim};
use cgka_traits::app_event::MarmotAppEvent;
use cgka_traits::engine::{GroupEvent, SendIntent};
use cgka_traits::storage::MaintenanceStorage as _;
use cgka_traits::{EpochId, GroupId, MessageId};
use marmot_session::{
    KIND_PRIVATE_KEY_PACKAGE_HAND_OFF, KIND_PRIVATE_KEY_PACKAGE_REQUEST, KIND_SIBLING_WELCOME,
};

use super::device_slot;
use crate::client::AppClient;
use crate::client::private_key_packages::SiblingWelcomeAdmission;
use crate::history_delivery::KIND_HISTORY_DELIVERY;
use crate::small_state::{KIND_SMALL_STATE_BROADCAST_REQUEST, KIND_SMALL_STATE_UPDATE};
use crate::{AppError, unix_now_seconds};

const TRACE_TARGET: &str = "marmot_app::client::device_group::messages";

/// A device heartbeat (mdk#2628 3.6a, marmot#462).
pub(crate) const KIND_DEVICE_HEARTBEAT: u64 = 457;

/// True for a kind sent only in a device group: a heartbeat, a private
/// KeyPackage request or hand-off, a sibling Welcome, a history delivery, or a
/// small-state update or broadcast request. A device reads these only in the
/// device group it trusts and ignores them in any other group. Whatever kind a
/// device-group feature adds goes here too.
pub(crate) fn is_device_group_kind(kind: u64) -> bool {
    matches!(
        kind,
        KIND_DEVICE_HEARTBEAT
            | KIND_PRIVATE_KEY_PACKAGE_REQUEST
            | KIND_PRIVATE_KEY_PACKAGE_HAND_OFF
            | KIND_SIBLING_WELCOME
            | KIND_HISTORY_DELIVERY
            | KIND_SMALL_STATE_UPDATE
            | KIND_SMALL_STATE_BROADCAST_REQUEST
    )
}

/// The trusted device group this device talks to its siblings in, its
/// roster, this device's slot there, and whether this device's own leaf
/// carries a device tag that reads as that slot at `epoch`, the group's
/// epoch when it was read. Siblings read nothing this device sends until it
/// does.
pub(crate) struct Exchange {
    pub(crate) group_id: GroupId,
    pub(crate) roster: DeviceRosterV1,
    pub(crate) own_slot: DeviceSlotId,
    pub(crate) tagged: bool,
    pub(crate) epoch: EpochId,
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
            epoch,
        }))
    }

    /// Take a message from a device-group event and hand it to the feature
    /// that owns its kind. Anything else is ignored, and so is anything that
    /// feature finds not addressed to this device. A refused message is
    /// logged and dropped. An error means a sibling Welcome could not be
    /// checked or kept: the event's projection fails and is retried, as any
    /// failed projection write is.
    pub(crate) fn observe_device_group_event(
        &mut self,
        event: &GroupEvent,
    ) -> Result<(), AppError> {
        if let GroupEvent::AppMessageInvalidated {
            group_id,
            message_id,
            ..
        } = event
        {
            self.device_group_message_withdrawn(group_id, message_id);
            return Ok(());
        }
        let GroupEvent::MessageReceived {
            group_id,
            message_id,
            sender_leaf_index,
            epoch,
            payload,
            ..
        } = event
        else {
            return Ok(());
        };
        let Ok(message) = MarmotAppEvent::decode(payload) else {
            return Ok(());
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
            KIND_SIBLING_WELCOME => match self.admit_sibling_welcome(
                group_id,
                message_id,
                sender,
                message.created_at,
                &message.content,
            )? {
                SiblingWelcomeAdmission::Admitted(admitted) => {
                    return self.stash_sibling_welcome(&admitted);
                }
                SiblingWelcomeAdmission::NotAddressed => Ok(()),
                SiblingWelcomeAdmission::Refused(refused) => Err(refused),
            },
            KIND_HISTORY_DELIVERY => {
                match self.receive_history_delivery(group_id, &message.id, sender, &message.content)
                {
                    // Only a refusal drops a delivery: with no receipts it is
                    // never sent again, so any other failure fails the
                    // projection, which reads it again, as for 461.
                    Err(error) if !matches!(error, AppError::DeviceGroupRefused(_)) => {
                        return Err(error);
                    }
                    result => result,
                }
            }
            KIND_SMALL_STATE_UPDATE => self.receive_small_state_update(group_id, &message.content),
            KIND_SMALL_STATE_BROADCAST_REQUEST => {
                self.receive_small_state_broadcast_request(group_id, &message.content)
            }
            _ => return Ok(()),
        };
        let result = result.and_then(|()| {
            if withdrawal_handled(message.kind) {
                self.record_device_group_message(
                    group_id,
                    &message.id,
                    Some(message_id),
                    message.kind,
                )
            } else {
                Ok(())
            }
        });
        if let Err(error) = result {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "observe_device_group_event",
                kind = message.kind,
                error_kind = error.privacy_safe_kind(),
                "a device-group message was refused"
            );
        }
        Ok(())
    }

    /// Refuse a message unless the leaf that sent it, at the message's epoch,
    /// carries a device tag that reads as `from`'s in `roster` (mdk#2628 D33).
    /// A sibling whose leaf is not tagged yet is refused and not counted; it
    /// sends again once it has tagged its leaf. So is a removed device, whose
    /// tag reads as its rejected slot, and a message from an epoch that is
    /// neither current nor retained.
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
                .member_device_tag_claim_at(group_id, epoch, leaf, roster)?,
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
        let event = self.device_group_event(kind, content)?;
        self.send_device_group_event(group_id, event).await
    }

    /// A device-group message of `kind` from this device, not yet sent.
    pub(crate) fn device_group_event(
        &self,
        kind: u64,
        content: String,
    ) -> Result<MarmotAppEvent, AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        Ok(MarmotAppEvent::new(
            account.account_id_hex,
            unix_now_seconds(),
            kind,
            Vec::new(),
            content,
        ))
    }

    /// Send `event`, built with [`Self::device_group_event`], as
    /// [`Self::send_device_group_message`] does.
    pub(crate) async fn send_device_group_event(
        &mut self,
        group_id: &GroupId,
        event: MarmotAppEvent,
    ) -> Result<bool, AppError> {
        self.send_device_group_event_at(group_id, event, None).await
    }

    /// [`Self::send_device_group_event`], pinned to `expected_epoch` when
    /// one is given: the engine encrypts `event` under that epoch or refuses
    /// it (`AppMessageEpochUnsettled`, `AppMessageEpochMismatch`) before
    /// writing anything, and never queues it.
    pub(crate) async fn send_device_group_event_at(
        &mut self,
        group_id: &GroupId,
        event: MarmotAppEvent,
        expected_epoch: Option<EpochId>,
    ) -> Result<bool, AppError> {
        let kind = event.kind;
        let payload = event
            .encode()
            .map_err(|error| AppError::InvalidAppMessagePayload(error.to_string()))?;
        // Recorded before the send: the message it becomes is filled in from
        // the effects of whichever drain publishes it.
        if withdrawal_handled(kind) {
            self.record_device_group_message(group_id, &event.id, None, kind)?;
        }
        let effects = self
            .runtime
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload,
                expected_epoch,
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

    /// Hand a device-group message that branch selection withdrew to the
    /// feature that owns its kind, when this device recorded sending or
    /// reading it. One with no record may be of any kind, its record gone, so
    /// small state is owed as for both of its kinds. A failure waits for that
    /// feature's own repair: small state broadcasts again at least daily.
    pub(crate) fn device_group_message_withdrawn(
        &mut self,
        group_id: &GroupId,
        message_id: &MessageId,
    ) {
        let result = self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| {
                Ok(storage.app_storage().device_group_message_kind(
                    &hex::encode(group_id.as_slice()),
                    &hex::encode(message_id.as_slice()),
                )?)
            })
            .and_then(|kind| match kind {
                Some(kind @ (KIND_SMALL_STATE_UPDATE | KIND_SMALL_STATE_BROADCAST_REQUEST)) => {
                    self.small_state_message_withdrawn(group_id, kind)
                }
                Some(KIND_HISTORY_DELIVERY) => {
                    self.history_delivery_withdrawn(group_id, message_id)
                }
                Some(_) => Ok(()),
                None => self.unrecorded_device_group_message_withdrawn(group_id),
            });
        if let Err(error) = result {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "device_group_message_withdrawn",
                error_kind = error.privacy_safe_kind(),
                "a withdrawn device-group message was not handled"
            );
        }
    }

    /// Fill in the transport ids that this device's recorded
    /// device-group sends became, from one drain's effects: published,
    /// unresolved or failed. Best effort: a send whose id is never filled in
    /// is not handed on if withdrawn.
    pub(crate) fn note_device_group_sent_ids(
        &self,
        effects: &marmot_session::AccountDeviceEffects,
    ) {
        let sent: Vec<_> = effects
            .published_app_messages
            .iter()
            .map(|message| {
                (
                    &message.group_id,
                    &message.app_event_id,
                    &message.message_id,
                )
            })
            .chain(effects.unresolved_app_messages.iter().map(|message| {
                (
                    &message.group_id,
                    &message.app_event_id,
                    &message.message_id,
                )
            }))
            // One that reached no one is never withdrawn; filling it in only
            // keeps later drains from looking for it.
            .chain(effects.failed_app_messages.iter().map(|message| {
                (
                    &message.group_id,
                    &message.app_event_id,
                    &message.message_id,
                )
            }))
            .map(|(group_id, app_event_id, message_id)| {
                (
                    hex::encode(group_id.as_slice()),
                    app_event_id.clone(),
                    hex::encode(message_id.as_slice()),
                )
            })
            .collect();
        if sent.is_empty() {
            return;
        }
        let noted = self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.app_storage().note_device_group_message_ids(&sent)?));
        if let Err(error) = noted {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "note_device_group_sent_ids",
                error_kind = error.privacy_safe_kind(),
                "device-group message ids were not recorded"
            );
        }
    }

    /// Record the kind of a device-group message this device sent or read.
    fn record_device_group_message(
        &self,
        group_id: &GroupId,
        app_event_id: &str,
        message_id: Option<&MessageId>,
        kind: u64,
    ) -> Result<(), AppError> {
        let message_id_hex = message_id.map(|message_id| hex::encode(message_id.as_slice()));
        self.app
            .account_storage(&self.state.label)?
            .app_storage()
            .record_device_group_message(
                &hex::encode(group_id.as_slice()),
                app_event_id,
                message_id_hex.as_deref(),
                kind,
                unix_now_seconds(),
            )?;
        Ok(())
    }
}

/// Whether a feature acts on a withdrawn message of `kind`: those are
/// recorded when sent or read, and [`AppClient::device_group_message_withdrawn`]
/// hands each to its feature.
fn withdrawal_handled(kind: u64) -> bool {
    matches!(
        kind,
        KIND_HISTORY_DELIVERY | KIND_SMALL_STATE_UPDATE | KIND_SMALL_STATE_BROADCAST_REQUEST
    )
}
