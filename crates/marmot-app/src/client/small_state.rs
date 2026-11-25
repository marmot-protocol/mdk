//! Small state with this account's other devices (mdk#2628 item 4.3): each
//! chat's read position, pin, mute and archive state, kept the same on every
//! device that trusts the account's device group. Only a device that group's
//! roster lists writes it: a sibling's message counts only when its sending
//! leaf's device tag reads as a listed device, so this device sends none
//! until its own leaf is tagged (mdk#3680).
//!
//! A pass ([`AppClient::sync_small_state`]) records what this device's user
//! changed, merges items received from siblings and applies the winners.
//! Storage does all but the archive in one transaction. An archive goes
//! through the worker's in-memory account state, as every archive does
//! (mdk#178), and the next pass sees it applied. Each chat a pass changed gets
//! one chat-list update.
//!
//! Recovery is a broadcast of every item this device holds, as updates: at
//! start, at least daily, whenever the device group's tip has moved past the
//! app-payload window since the last one, at once for a device the roster
//! lists that the last one was not made for, and in answer to a sibling's
//! broadcast request. Only which devices the last broadcast was made for is
//! kept, not what each one holds.

use std::collections::{BTreeMap, BTreeSet};

use cgka_traits::{EpochId, EpochPin, GroupId};
use marmot_session::CanonicalizationPolicy;
use storage_sqlite::{SmallStateItem, SmallStateItemName};

use super::AppClient;
use crate::small_state::{
    BROADCAST_REQUEST, KIND_SMALL_STATE_BROADCAST_REQUEST, KIND_SMALL_STATE_UPDATE,
    SmallStateMergeRule, broadcast_devices, broadcast_due, decode_broadcast_request,
    decode_invitation_decisions, decode_small_state_update, encode_invitation_decision_updates,
    encode_small_state_update,
};
use crate::{AppError, AppProjectionUpdate, ChatListUpdateTrigger, MarmotApp, unix_now_seconds};

const TRACE_TARGET: &str = "marmot_app::client::small_state";

impl AppClient {
    /// Maintenance's small-state pass: record and apply, begin a broadcast
    /// when one is due, then send what is owed. A pass that fails waits for
    /// the next.
    pub(crate) async fn drive_small_state(&mut self) {
        if self.runtime.maintenance_is_paused() {
            return;
        }
        let passed = self
            .sync_small_state(&[])
            .and_then(|()| self.begin_small_state_broadcast_when_due(unix_now_seconds()));
        let result = match passed {
            Ok(()) => self.send_owed_small_state().await,
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            self.device_group_work_changed = true;
            self.answers_await_epoch(&error);
            tracing::warn!(
                target: TRACE_TARGET,
                method = "drive_small_state",
                error_kind = error.privacy_safe_kind(),
                "small state was not synced; retrying at the next maintenance pass"
            );
        }
    }

    /// Send the siblings every item this device owes them, in updates of at
    /// most [`crate::small_state::MAX_SMALL_STATE_CONTENT_BYTES`] each, then a broadcast request
    /// when one is owed. Each update's items are marked sent once it went
    /// out, and only if they still hold the value it carried; an update that
    /// reached no relay stops the pass, and its items stay owed. Sending one
    /// twice does no harm: every device merges it to the same winner.
    ///
    /// Nothing goes out until this device's own leaf is tagged: siblings
    /// refuse small state from any other leaf (mdk#3680). What is owed stays
    /// owed, and the first pass after the tag commit sends it. Each message
    /// is pinned to the branch the tag was read on, so the engine refuses one
    /// whose epoch moved or is about to, encrypting nothing, rather than send
    /// it from a leaf that lost its tag; what it carried stays owed too.
    pub(super) async fn send_owed_small_state(&mut self) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(());
        }
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        if !exchange.tagged {
            return Ok(());
        }
        let (group_id, pin) = (exchange.group_id, exchange.pin);
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let Some(schedule) = storage.small_state_schedule()? else {
            return Ok(());
        };
        let mut sent = 0;
        // Invitation decisions first: a sibling Add waits on them (mdk#3556),
        // and a page of other items no relay takes must not hold them back.
        // A page the session holds unacknowledged counts as sent, as for
        // other items: while no relay is up the Add can then go ahead
        // before the decision lands, until the session's retry delivers it.
        for (content, carried) in
            encode_invitation_decision_updates(&storage.unsent_invitation_decisions()?)
        {
            if !self
                .send_small_state_message(&group_id, pin, KIND_SMALL_STATE_UPDATE, content)
                .await?
            {
                return Ok(());
            }
            storage.mark_invitation_decisions_sent(&carried)?;
            sent += 1;
        }
        for (content, carried) in encode_small_state_update(&storage.unsent_small_state_items()?) {
            if !self
                .send_small_state_message(&group_id, pin, KIND_SMALL_STATE_UPDATE, content)
                .await?
            {
                return Ok(());
            }
            storage.mark_small_state_sent(&carried)?;
            sent += 1;
        }
        let requested = schedule.request_owed
            && self
                .send_small_state_message(
                    &group_id,
                    pin,
                    KIND_SMALL_STATE_BROADCAST_REQUEST,
                    BROADCAST_REQUEST.to_owned(),
                )
                .await?;
        if requested {
            storage.small_state_broadcast_request_sent()?;
        }
        if sent > 0 || requested {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "send_owed_small_state",
                updates = sent,
                requested,
                "small state sent"
            );
        }
        Ok(())
    }

    /// Send one small-state message pinned to `pin`, as
    /// [`Self::send_device_group_event_at`] does.
    async fn send_small_state_message(
        &mut self,
        group_id: &GroupId,
        pin: EpochPin,
        kind: u64,
        content: String,
    ) -> Result<bool, AppError> {
        let event = self.device_group_event(kind, content)?;
        self.send_device_group_event_at(group_id, event, Some(pin))
            .await
    }

    /// Begin a broadcast when [`broadcast_due`] says one is owed at `now`:
    /// every item this device holds is owed to its siblings again.
    pub(crate) fn begin_small_state_broadcast_when_due(
        &mut self,
        now: u64,
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(());
        }
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Ok(());
        };
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let Some(schedule) = storage.small_state_schedule()? else {
            return Ok(());
        };
        let Some(tip) = self.stored_group(&group_id)?.map(|group| group.epoch.0) else {
            return Ok(());
        };
        let window = CanonicalizationPolicy::default().app_message_past_epoch_limit;
        if broadcast_due(&schedule, now, tip, window, &roster) {
            storage.begin_small_state_broadcast(now, tip, &broadcast_devices(&roster))?;
            tracing::debug!(
                target: TRACE_TARGET,
                method = "begin_small_state_broadcast_when_due",
                "small-state broadcast begun"
            );
        }
        Ok(())
    }

    /// Run one small-state pass with `incoming`, items just received from
    /// siblings. Nothing happens until this device trusts its account's
    /// device group; the first pass after that starts small state.
    pub(crate) fn sync_small_state(&mut self, incoming: &[SmallStateItem]) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() || self.trusted_device_group()?.is_none() {
            return Ok(());
        }
        let account = self.app.account_home().account(&self.state.label)?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        storage.start_small_state()?;
        let classifier = MarmotApp::chat_list_mention_classifier(&account.account_id_hex);
        let outcome = storage.sync_small_state(
            &account.account_id_hex,
            incoming,
            &SmallStateMergeRule,
            &classifier,
        )?;
        let mut recorded = outcome.recorded;
        let mut changed = outcome.applied;
        let archived = self.apply_sibling_archives(outcome.archive_to_apply);
        let archives_applied = !archived.is_empty();
        for group_id_hex in archived {
            changed
                .entry(group_id_hex)
                .or_default()
                .insert(SmallStateItemName::Archive);
        }
        // At once, before this device's user can change the chats again:
        // record the archives as applied, so a later change is taken for
        // one, and apply the pins that waited for them. An archive left
        // unapplied waits for the next pass.
        if archives_applied {
            let outcome = storage.sync_small_state(
                &account.account_id_hex,
                &[],
                &SmallStateMergeRule,
                &classifier,
            )?;
            recorded += outcome.recorded;
            for (group_id_hex, names) in outcome.applied {
                changed.entry(group_id_hex).or_default().extend(names);
            }
        }
        if recorded > 0 || !changed.is_empty() {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "sync_small_state",
                recorded,
                applied_chats = changed.len(),
                "small state synced"
            );
        }
        self.announce_small_state_changes(changed)
    }

    /// Apply the archive states siblings' items won with, in the worker's
    /// in-memory account state as every archive is (mdk#178), and save them
    /// once. A sibling's archive is not this device's user archiving a chat,
    /// so it records no product outcome, as a sibling's pin or mute records
    /// none. If the save fails, every flag goes back and the next pass tries
    /// again. Returns the chats it archived or unarchived.
    fn apply_sibling_archives(&mut self, archives: Vec<(String, bool)>) -> Vec<String> {
        let mut previous = Vec::new();
        for (group_id_hex, archived) in archives {
            let Some(group) = self
                .state
                .groups
                .iter_mut()
                .find(|group| group.group_id_hex == group_id_hex)
            else {
                // The next pass tries again.
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "apply_sibling_archives",
                    "a sibling's archive names no group here"
                );
                continue;
            };
            previous.push((group_id_hex, group.archived));
            group.archived = archived;
        }
        if previous.is_empty() {
            return Vec::new();
        }
        for (group_id_hex, _) in &previous {
            self.mark_group_projection_dirty_hex(group_id_hex.clone());
        }
        if let Err(error) = self.save_state_with_pending_local_group_deletion_frontier_clears() {
            for (group_id_hex, archived) in &previous {
                if let Some(group) = self
                    .state
                    .groups
                    .iter_mut()
                    .find(|group| group.group_id_hex == *group_id_hex)
                {
                    group.archived = *archived;
                }
            }
            tracing::warn!(
                target: TRACE_TARGET,
                method = "apply_sibling_archives",
                error_kind = error.privacy_safe_kind(),
                "siblings' archives were not applied"
            );
            return Vec::new();
        }
        previous
            .into_iter()
            .map(|(group_id_hex, _)| group_id_hex)
            .collect()
    }

    /// One chat-list update for each chat a pass changed.
    fn announce_small_state_changes(
        &mut self,
        changed: BTreeMap<String, BTreeSet<SmallStateItemName>>,
    ) -> Result<(), AppError> {
        for (group_id_hex, names) in changed {
            let chat_list_trigger = if names.contains(&SmallStateItemName::Archive) {
                ChatListUpdateTrigger::ArchiveChanged
            } else if names.contains(&SmallStateItemName::Pin) {
                ChatListUpdateTrigger::PinOrderChanged
            } else if names.contains(&SmallStateItemName::Mute) {
                ChatListUpdateTrigger::MuteChanged
            } else {
                ChatListUpdateTrigger::UnreadChanged
            };
            let chat_list_row = self.app.chat_list_row(&self.state.label, &group_id_hex)?;
            self.pending_projection_updates.push(AppProjectionUpdate {
                group_id_hex,
                timeline_messages: Vec::new(),
                timeline_changes: Vec::new(),
                chat_list_row,
                chat_list_trigger,
            });
        }
        Ok(())
    }

    /// Refuse a small-state message unless a device the trusted roster lists
    /// sent it in the trusted device group: `sender`'s leaf must read, at the
    /// message's epoch, as that device's (mdk#3680). Membership is not
    /// enough: a removed device keeps its last epoch's keys for the
    /// app-message window, and its leaf reads as its removed slot. A linked
    /// sibling's message read after later commits is read from its epoch's
    /// retained anchor.
    pub(crate) fn ensure_small_state_sender(
        &mut self,
        group_id: &GroupId,
        sender: (EpochId, Option<u32>),
    ) -> Result<(), AppError> {
        match self.trusted_device_roster()? {
            Some((trusted, roster)) if trusted == *group_id => {
                self.sending_device(group_id, &roster, sender).map(drop)
            }
            _ => Err(AppError::DeviceGroupRefused("not_trusted_device_group")),
        }
    }

    /// Merge an update's items, sent at `epoch` of the device group by a
    /// sibling [`Self::ensure_small_state_sender`] admitted.
    pub(crate) fn receive_small_state_update(
        &mut self,
        group_id: &GroupId,
        epoch: u64,
        content: &str,
    ) -> Result<(), AppError> {
        self.ensure_small_state_group(group_id)?;
        let items = decode_small_state_update(content)?;
        let invitations = decode_invitation_decisions(content)?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        // An update from before this device's last broadcast began did not
        // reach a device that joined since, and that broadcast did not carry
        // what it brings: a winning decision from it is owed again, as a
        // sibling Add waits on it (mdk#3556).
        let older_than_broadcast = storage
            .small_state_schedule()?
            .and_then(|schedule| schedule.last_broadcast)
            .is_some_and(|last| epoch < last.tip);
        // A sibling's winning decision is applied on the worker's next turn,
        // not at the next maintenance pass (mdk#3566).
        self.invitation_decisions_changed |=
            storage.merge_invitation_decisions(&invitations, older_than_broadcast)?;
        self.sync_small_state(&items)
    }

    /// Take the broadcast request of a sibling
    /// [`Self::ensure_small_state_sender`] admitted: owe a broadcast, which
    /// [`broadcast_due`] spaces at least an hour after the last.
    pub(crate) fn receive_small_state_broadcast_request(
        &mut self,
        group_id: &GroupId,
        content: &str,
    ) -> Result<(), AppError> {
        self.ensure_small_state_group(group_id)?;
        decode_broadcast_request(content)?;
        self.app
            .account_storage(&self.state.label)?
            .app_storage()
            .owe_small_state_broadcast_answer()?;
        Ok(())
    }

    /// Branch selection withdrew a small-state message this device sent or
    /// read: owe every item held again for an update, whoever sent it, and a
    /// new broadcast request for a request.
    pub(crate) fn small_state_message_withdrawn(
        &mut self,
        group_id: &GroupId,
        kind: u64,
    ) -> Result<(), AppError> {
        self.ensure_small_state_group(group_id)?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        match kind {
            KIND_SMALL_STATE_UPDATE => {
                storage.owe_all_small_state_items()?;
                // An answered invitation it carried goes out again on the
                // worker's next turn, as the answer first did: a sibling
                // still waits for it (mdk#3566).
                if !storage.unsent_invitation_decisions()?.is_empty() {
                    self.send_invitation_decisions_next_turn();
                }
            }
            KIND_SMALL_STATE_BROADCAST_REQUEST => storage.owe_small_state_broadcast_request()?,
            _ => {}
        }
        Ok(())
    }

    /// A withdrawn message in the device group this device trusts that it
    /// has no record of: it may have been an update or a request whose record
    /// is gone, so every item and a request are owed again.
    pub(crate) fn unrecorded_device_group_message_withdrawn(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), AppError> {
        if self.ensure_small_state_group(group_id).is_err() {
            return Ok(());
        }
        self.small_state_message_withdrawn(group_id, KIND_SMALL_STATE_UPDATE)?;
        self.small_state_message_withdrawn(group_id, KIND_SMALL_STATE_BROADCAST_REQUEST)
    }

    /// Refuse a small-state message from anywhere but the device group this
    /// device trusts.
    fn ensure_small_state_group(&self, group_id: &GroupId) -> Result<(), AppError> {
        if self.app.device_groups_enabled()
            && self.trusted_device_group()?.as_ref() == Some(group_id)
        {
            Ok(())
        } else {
            Err(AppError::DeviceGroupRefused("not_trusted_device_group"))
        }
    }
}
