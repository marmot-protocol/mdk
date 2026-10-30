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
//! - [`AppClient::ensure_sent_by`] reads which slot sent a message from the
//!   sending leaf's device tag (D33), through 3.1d's one tag reader. It reads
//!   only the current tree, so a message from an earlier epoch has no
//!   readable sender.
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
use cgka_traits::{EpochId, GroupId, MessageId};
use marmot_session::{KIND_PRIVATE_KEY_PACKAGE_HAND_OFF, KIND_PRIVATE_KEY_PACKAGE_REQUEST};

use crate::client::AppClient;
use crate::small_state::{KIND_SMALL_STATE_BROADCAST_REQUEST, KIND_SMALL_STATE_UPDATE};
use crate::{AppError, unix_now_seconds};

const TRACE_TARGET: &str = "marmot_app::client::device_group::messages";

impl AppClient {
    /// Take a message from a device-group event and hand it to the feature
    /// that owns its kind. Anything else is ignored, and so is anything that
    /// feature finds not addressed to this device.
    pub(crate) fn observe_device_group_event(&mut self, event: &GroupEvent) {
        if let GroupEvent::AppMessageInvalidated {
            group_id,
            message_id,
            ..
        } = event
        {
            self.device_group_message_withdrawn(group_id, message_id);
            return;
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
            return;
        };
        let Ok(message) = MarmotAppEvent::decode(payload) else {
            return;
        };
        let result = match message.kind {
            KIND_PRIVATE_KEY_PACKAGE_REQUEST => self.receive_key_package_request(
                group_id,
                message_id,
                (*epoch, *sender_leaf_index),
                &message.content,
            ),
            KIND_PRIVATE_KEY_PACKAGE_HAND_OFF => self.receive_key_package_hand_off(
                group_id,
                (*epoch, *sender_leaf_index),
                &message.content,
            ),
            KIND_SMALL_STATE_UPDATE => self.receive_small_state_update(group_id, &message.content),
            KIND_SMALL_STATE_BROADCAST_REQUEST => {
                self.receive_small_state_broadcast_request(group_id, &message.content)
            }
            _ => return,
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
    pub(crate) fn note_device_group_message_ids(
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
                method = "note_device_group_message_ids",
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
        KIND_SMALL_STATE_UPDATE | KIND_SMALL_STATE_BROADCAST_REQUEST
    )
}
