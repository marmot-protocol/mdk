//! Sealed history deliveries to this account's other devices (mdk#2628 4.2b,
//! D60): a chat's history sent through the device group to one sibling and
//! readable only by it. `history_delivery.rs` holds the format.
//!
//! Only the adder sends (D76). When this device's own Commit that adds a
//! sibling to a chat is confirmed, the engine records the sibling's slot in
//! the same transaction (`SiblingAddStorage`). A maintenance pass turns each
//! such add into an owed history before sending anything, then exports the
//! chat's history in inline bundles, seals each bundle's key and hash to the
//! receiver's history key, and sends one delivery per bundle. Whether the
//! sibling asks for history is read then. A send that reached no relay leaves
//! the history owed; a delivery that branch selection withdraws, or whose
//! queued publish later fails for good, makes it owed again. A history longer
//! than [`MAX_INLINE_BUNDLES`] is not sent, and an event too large for one
//! delivery is left out.
//!
//! The receiver reads a delivery only from a sibling whose leaf is tagged,
//! only when it names this device, and only when it opens with this device's
//! history key. It imports the bundle through 4.2a once it holds the chat
//! and parks the delivery until then.
//!
//! Owed and parked deliveries go after a week. A history is owed from the
//! add's confirmation, so one is still sent when branch selection later
//! withdraws that Commit; the sibling imports it only if it joins the chat.

use cgka_traits::app_components::DeviceSlotId;
use cgka_traits::app_event::MarmotAppEvent;
use cgka_traits::storage::SiblingAddStorage as _;
use cgka_traits::{EpochId, GroupId, MessageId};
use storage_sqlite::{HISTORY_DELIVERY_RETENTION_SECS, OwedHistoryDelivery, ParkedHistoryDelivery};
use zeroize::Zeroizing;

use super::AppClient;
use super::device_group::Exchange;
use crate::history_bundle::seal_history_bundle;
use crate::history_delivery::{
    HistoryDelivery, INLINE_BUNDLE_MAX_PLAINTEXT, KIND_HISTORY_DELIVERY,
    MAX_HISTORY_DELIVERY_CONTENT_BYTES, MAX_INLINE_BUNDLES, delivery_context, opened_key_and_hash,
    sealed_plaintext,
};
use crate::{AppError, unix_now_seconds};

const TRACE_TARGET: &str = "marmot_app::client::history_delivery";

impl AppClient {
    /// Maintenance's history-delivery pass: expire week-old deliveries,
    /// import parked ones whose chat this device now holds, owe the history
    /// of each chat this device added a sibling to, then send what is owed. A
    /// pass that fails waits for the next.
    pub(crate) async fn drive_history_deliveries(&mut self) {
        if self.runtime.maintenance_is_paused() || !self.app.device_groups_enabled() {
            return;
        }
        let result = match self
            .import_parked_history_deliveries()
            .and_then(|()| self.owe_added_siblings_history())
        {
            Ok(()) => self.send_owed_history_deliveries().await,
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "drive_history_deliveries",
                error_kind = error.privacy_safe_kind(),
                "history deliveries were not settled; retrying at the next maintenance pass"
            );
        }
    }

    /// Owe each sibling that one of this device's own confirmed Commits added
    /// to a chat the chat's history, counted from the add, then forget the
    /// add. An add a week old is forgotten unowed, as its history would have
    /// been. Owing again what is already owed changes nothing, so a crash
    /// between the two only owes it again.
    fn owe_added_siblings_history(&self) -> Result<(), AppError> {
        let account = self.app.account_storage(&self.state.label)?;
        let storage = account.app_storage();
        let expired_before = unix_now_seconds().saturating_sub(HISTORY_DELIVERY_RETENTION_SECS);
        for add in account.sibling_adds()? {
            if add.added_at >= expired_before {
                storage.owe_history_delivery(
                    &hex::encode(add.group_id.as_slice()),
                    &hex::encode(add.slot),
                    add.added_at,
                )?;
            }
            account.forget_sibling_add(&add)?;
        }
        Ok(())
    }

    /// Send each owed history, one delivery per bundle. Each delivery's chat
    /// and receiver are recorded before it is sent, so its withdrawal can owe
    /// the history again. A delivery that reached no relay stops the pass
    /// with its history still owed; sending one twice costs the receiver only
    /// the download, since import never adds a row twice. A history that can
    /// no longer be sent is forgotten.
    async fn send_owed_history_deliveries(&mut self) -> Result<(), AppError> {
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        // Siblings read nothing this device sends until its leaf is tagged.
        if !exchange.tagged {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let mut sent = 0;
        for owed in storage.unsent_history_deliveries()? {
            let events = match self.history_deliveries(&exchange, &owed) {
                Ok(events) => events,
                Err(AppError::DeviceGroupRefused(reason)) => {
                    storage.forget_history_delivery(&owed)?;
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "send_owed_history_deliveries",
                        reason,
                        "an owed history cannot be sent and is forgotten"
                    );
                    continue;
                }
                Err(error) => return Err(error),
            };
            for event in events {
                storage.record_history_delivery_send(
                    &event.id,
                    &owed.group_id_hex,
                    &owed.receiver_slot_hex,
                    unix_now_seconds(),
                )?;
                if !self
                    .send_device_group_event(&exchange.group_id, event)
                    .await?
                {
                    return Ok(());
                }
                sent += 1;
            }
            storage.mark_history_delivery_sent(&owed, unix_now_seconds())?;
        }
        if sent > 0 {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "send_owed_history_deliveries",
                deliveries = sent,
                "history deliveries sent"
            );
        }
        Ok(())
    }

    /// The deliveries that carry `owed`: the chat's whole history in at most
    /// [`MAX_INLINE_BUNDLES`] inline bundles, each sealed to the receiver.
    /// Refused when the receiver is no longer a sibling that asks for history
    /// with a key this device can seal to, when this device no longer holds
    /// the chat, or when the history is too long to send inline.
    fn history_deliveries(
        &self,
        exchange: &Exchange,
        owed: &OwedHistoryDelivery,
    ) -> Result<Vec<MarmotAppEvent>, AppError> {
        let refused = AppError::DeviceGroupRefused;
        let receiver = hex::decode(&owed.receiver_slot_hex)
            .ok()
            .and_then(|bytes| DeviceSlotId::try_from(bytes).ok())
            .filter(|slot| exchange.is_sibling(slot))
            .ok_or(refused("history_delivery_receiver"))?;
        let entry = &exchange.roster.devices[&receiver];
        if !entry.settings.bring_history {
            return Err(refused("history_delivery_not_wanted"));
        }
        let history_key = entry
            .history_key
            .as_deref()
            .ok_or(refused("history_delivery_key"))?;
        let chat = hex::decode(&owed.group_id_hex)
            .map(GroupId::new)
            .map_err(|_| refused("history_delivery_chat"))?;
        if self.history_chat(&chat).is_err() {
            return Err(refused("history_delivery_chat"));
        }
        let mut bundles = Vec::new();
        let mut after = None;
        while let Some(bundle) =
            self.export_chat_history(&chat, after.as_ref(), INLINE_BUNDLE_MAX_PLAINTEXT)?
        {
            if bundles.len() == MAX_INLINE_BUNDLES {
                return Err(refused("history_delivery_too_long"));
            }
            after = Some(bundle.to.clone());
            bundles.push(bundle);
        }
        let context = delivery_context(&exchange.own_slot, &receiver, chat.as_slice());
        bundles
            .iter()
            .map(|bundle| {
                let sealed_bundle = seal_history_bundle(bundle)?;
                let sealed = self
                    .runtime
                    .seal_history(
                        history_key,
                        &context,
                        &sealed_plaintext(&sealed_bundle.key, &sealed_bundle.ciphertext_sha256),
                    )
                    .ok_or(refused("history_delivery_key"))?;
                let content = HistoryDelivery {
                    from: exchange.own_slot,
                    to: receiver,
                    chat: chat.as_slice().to_vec(),
                    sealed,
                    bundle: sealed_bundle.ciphertext,
                }
                .encode();
                if content.len() > MAX_HISTORY_DELIVERY_CONTENT_BYTES {
                    return Err(refused("history_delivery_too_large"));
                }
                self.device_group_event(KIND_HISTORY_DELIVERY, content)
            })
            .collect()
    }

    /// Read a delivery sent in the device group this device trusts. One for
    /// another device is ignored. One from anything but a sibling whose leaf
    /// is tagged, or that does not open with this device's history key, is
    /// refused. The bundle is imported when this device holds the chat and
    /// parked until it does.
    pub(crate) fn receive_history_delivery(
        &mut self,
        group_id: &GroupId,
        app_event_id: &str,
        sender: (EpochId, Option<u32>),
        content: &str,
    ) -> Result<(), AppError> {
        let exchange = self
            .device_group_exchange()?
            .filter(|exchange| exchange.group_id == *group_id)
            .ok_or(AppError::DeviceGroupRefused("not_trusted_device_group"))?;
        let delivery = HistoryDelivery::decode(content)?;
        if delivery.to != exchange.own_slot {
            return Ok(());
        }
        if !exchange.is_sibling(&delivery.from) {
            return Err(AppError::DeviceGroupRefused("history_delivery_sender"));
        }
        self.ensure_sent_by(group_id, &exchange.roster, sender, &delivery.from)?;
        // Opened now, so one that never opens is refused rather than parked.
        let (key, hash) = self.open_history_delivery(
            &delivery.from,
            &exchange.own_slot,
            &delivery.chat,
            &delivery.sealed,
        )?;
        let chat = GroupId::new(delivery.chat.clone());
        match self.history_chat(&chat) {
            Ok(_) => {
                self.import_delivered_bundle(&chat, &delivery.from, &key, &hash, &delivery.bundle)
            }
            Err(AppError::UnknownGroup(_)) => {
                self.app
                    .account_storage(&self.state.label)?
                    .app_storage()
                    .park_history_delivery(&ParkedHistoryDelivery {
                        app_event_id: app_event_id.to_owned(),
                        group_id_hex: hex::encode(&delivery.chat),
                        sender_slot_hex: hex::encode(delivery.from),
                        sealed: delivery.sealed,
                        bundle: delivery.bundle,
                        received_at: unix_now_seconds(),
                    })?;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Drop week-old deliveries, then import each parked one whose chat this
    /// device now holds. A parked delivery goes once imported or refused, as
    /// when its sender is no longer a sibling; any other failure stops the
    /// pass and keeps it for the next.
    fn import_parked_history_deliveries(&mut self) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        storage.expire_history_deliveries(unix_now_seconds())?;
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        for group_id_hex in storage.parked_history_delivery_chats()? {
            if !self
                .state
                .groups
                .iter()
                .any(|group| group.group_id_hex == group_id_hex)
            {
                continue;
            }
            for parked in storage.parked_history_deliveries(&group_id_hex)? {
                match self.import_parked_history_delivery(&exchange, &parked) {
                    Ok(()) => {}
                    Err(AppError::DeviceGroupRefused(reason)) => {
                        tracing::warn!(
                            target: TRACE_TARGET,
                            method = "import_parked_history_deliveries",
                            reason,
                            "a parked history delivery was refused"
                        );
                    }
                    Err(error) => return Err(error),
                }
                storage.drop_parked_history_delivery(&parked.app_event_id)?;
            }
        }
        Ok(())
    }

    fn import_parked_history_delivery(
        &mut self,
        exchange: &Exchange,
        parked: &ParkedHistoryDelivery,
    ) -> Result<(), AppError> {
        let from = hex::decode(&parked.sender_slot_hex)
            .ok()
            .and_then(|bytes| DeviceSlotId::try_from(bytes).ok())
            .filter(|slot| exchange.is_sibling(slot))
            .ok_or(AppError::DeviceGroupRefused("history_delivery_sender"))?;
        let chat = hex::decode(&parked.group_id_hex)
            .map_err(|_| AppError::DeviceGroupRefused("history_delivery_chat"))?;
        let (key, hash) =
            self.open_history_delivery(&from, &exchange.own_slot, &chat, &parked.sealed)?;
        self.import_delivered_bundle(&GroupId::new(chat), &from, &key, &hash, &parked.bundle)
    }

    /// A delivery's bundle key and ciphertext hash, opened with this device's
    /// history key.
    fn open_history_delivery(
        &self,
        from: &DeviceSlotId,
        to: &DeviceSlotId,
        chat: &[u8],
        sealed: &[u8],
    ) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), AppError> {
        let opened = self
            .runtime
            .open_history(&delivery_context(from, to, chat), sealed)?
            .map(Zeroizing::new);
        opened
            .as_deref()
            .and_then(|opened| opened_key_and_hash(opened))
            .ok_or(AppError::DeviceGroupRefused("history_delivery_seal"))
    }

    /// Import one delivered bundle and announce what changed.
    fn import_delivered_bundle(
        &mut self,
        chat: &GroupId,
        from: &DeviceSlotId,
        key: &[u8; 32],
        hash: &[u8; 32],
        bundle: &[u8],
    ) -> Result<(), AppError> {
        if let Some(update) = self.import_history_bundle(chat, from, key, hash, bundle)? {
            self.pending_projection_updates.push(update);
        }
        Ok(())
    }

    /// Branch selection withdrew the device-group message `message_id`, of
    /// the delivery kind: when this device sent it, its history is owed again.
    pub(crate) fn history_delivery_withdrawn(
        &mut self,
        group_id: &GroupId,
        message_id: &MessageId,
    ) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let Some(app_event_id) = storage.device_group_message_event_id(
            &hex::encode(group_id.as_slice()),
            &hex::encode(message_id.as_slice()),
        )?
        else {
            return Ok(());
        };
        if storage.owe_history_delivery_again(&app_event_id)? {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "history_delivery_withdrawn",
                "a withdrawn history delivery is owed again"
            );
        }
        Ok(())
    }

    /// The publish of `app_event_id` failed for good, perhaps in a drain after
    /// the send that queued it: when it was a history delivery, owe its
    /// history again.
    pub(crate) fn history_delivery_failed(&self, app_event_id: &str) -> Result<(), AppError> {
        if self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .owe_history_delivery_again(app_event_id)?
        {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "history_delivery_failed",
                "a failed history delivery is owed again"
            );
        }
        Ok(())
    }

    /// Test-policy hook: record that this device added the sibling at
    /// `receiver` to `chat`, as the engine does when its own Commit that
    /// adds it is confirmed.
    #[cfg(feature = "test-policy-overrides")]
    #[doc(hidden)]
    pub fn dev_record_sibling_add(
        &mut self,
        chat: &GroupId,
        receiver: &DeviceSlotId,
    ) -> Result<(), AppError> {
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .record_sibling_adds(chat, &[*receiver], unix_now_seconds())?)
    }
}
