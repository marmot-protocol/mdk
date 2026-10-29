//! Small state with this account's other devices (mdk#2628 item 4.3): each
//! chat's read position, pin, mute and archive state, kept the same on every
//! device that trusts the account's device group.
//!
//! A pass ([`AppClient::sync_small_state`]) records what this device's user
//! changed, merges items received from siblings and applies the winners.
//! Storage does all but the archive in one transaction. An archive goes
//! through the worker's in-memory account state, as every archive does
//! (mdk#178), and the next pass sees it applied. Each chat a pass changed gets
//! one chat-list update.

use std::collections::{BTreeMap, BTreeSet};

use cgka_traits::GroupId;
use cgka_traits::app_components::{DeviceRosterV1, DeviceSlotId};
use cgka_traits::storage::MaintenanceStorage as _;
use storage_sqlite::{SmallStateItem, SmallStateItemName};

use super::AppClient;
use super::device_group::device_slot;
use crate::small_state::{
    KIND_SMALL_STATE_SNAPSHOT, KIND_SMALL_STATE_SNAPSHOT_REQUEST, KIND_SMALL_STATE_UPDATE,
    SmallStateMergeRule, decode_small_state_snapshot, decode_small_state_update,
    decode_snapshot_request,
};
use crate::{AppError, AppProjectionUpdate, ChatListUpdateTrigger, MarmotApp};

const TRACE_TARGET: &str = "marmot_app::client::small_state";

impl AppClient {
    /// Maintenance's small-state pass. A pass that fails waits for the next.
    pub(crate) async fn drive_small_state(&mut self) {
        if self.runtime.maintenance_is_paused() {
            return;
        }
        if let Err(error) = self.sync_small_state(&[]) {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "drive_small_state",
                error_kind = error.privacy_safe_kind(),
                "small state was not synced; retrying at the next maintenance pass"
            );
        }
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
        let mut changed = outcome.applied;
        for (group_id_hex, archived) in outcome.archive_to_apply {
            let applied = hex::decode(&group_id_hex)
                .map_err(AppError::from)
                .and_then(|group_id| {
                    self.set_group_archived_unobserved(&GroupId::new(group_id), archived)
                });
            match applied {
                Ok(_) => {
                    changed
                        .entry(group_id_hex)
                        .or_default()
                        .insert(SmallStateItemName::Archive);
                }
                // The next pass tries again.
                Err(error) => tracing::warn!(
                    target: TRACE_TARGET,
                    method = "sync_small_state",
                    error_kind = error.privacy_safe_kind(),
                    "a sibling's archive was not applied"
                ),
            }
        }
        if outcome.recorded > 0 || !changed.is_empty() {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "sync_small_state",
                recorded = outcome.recorded,
                applied_chats = changed.len(),
                "small state synced"
            );
        }
        self.announce_small_state_changes(changed)
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

    /// Merge an update's items, from any device of the trusted device group.
    pub(crate) fn receive_small_state_update(
        &mut self,
        group_id: &GroupId,
        content: &str,
    ) -> Result<(), AppError> {
        self.ensure_small_state_group(group_id)?;
        let items = decode_small_state_update(content)?;
        self.sync_small_state(&items)
    }

    /// Merge a snapshot's items, whoever asked for it, and count the part
    /// when it answers one of this device's requests.
    pub(crate) fn receive_small_state_snapshot(
        &mut self,
        group_id: &GroupId,
        content: &str,
    ) -> Result<(), AppError> {
        self.ensure_small_state_group(group_id)?;
        let snapshot = decode_small_state_snapshot(content)?;
        self.sync_small_state(&snapshot.items)?;
        self.app
            .account_storage(&self.state.label)?
            .app_storage()
            .record_small_state_snapshot_part(&snapshot.request, snapshot.part, snapshot.parts)?;
        Ok(())
    }

    /// Take a snapshot request: owe an answer when it asks this device.
    pub(crate) fn receive_small_state_snapshot_request(
        &mut self,
        group_id: &GroupId,
        content: &str,
    ) -> Result<(), AppError> {
        self.ensure_small_state_group(group_id)?;
        let (to, request) = decode_snapshot_request(content)?;
        if self.own_device_slot()? == Some(to) {
            self.small_state_snapshot_answers_owed.insert(request);
        }
        Ok(())
    }

    /// Branch selection withdrew a small-state message this device sent or
    /// merged: owe every item held again, or ask again at once for a request
    /// of this device's.
    pub(crate) fn small_state_message_withdrawn(
        &mut self,
        group_id: &GroupId,
        kind: u64,
        content: &str,
    ) -> Result<(), AppError> {
        self.ensure_small_state_group(group_id)?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        match kind {
            KIND_SMALL_STATE_UPDATE | KIND_SMALL_STATE_SNAPSHOT => {
                storage.owe_all_small_state_items()?;
            }
            KIND_SMALL_STATE_SNAPSHOT_REQUEST => {
                let (_, request) = decode_snapshot_request(content)?;
                storage.withdraw_small_state_snapshot_request(&request)?;
            }
            _ => {}
        }
        Ok(())
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

    /// This device's slot, if it has one.
    fn own_device_slot(&self) -> Result<Option<DeviceSlotId>, AppError> {
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .key_package_lifecycle()?
            .and_then(|lifecycle| device_slot(&lifecycle.stable_slot_id).ok()))
    }

    /// The siblings to ask for snapshots: every device in the roster other
    /// than this one, whatever its status, since any of them may hold a value
    /// no other device does.
    pub(crate) fn small_state_snapshot_targets(
        &self,
        roster: &DeviceRosterV1,
    ) -> Result<Vec<DeviceSlotId>, AppError> {
        let own_slot = self.own_device_slot()?;
        Ok(roster
            .devices
            .keys()
            .filter(|slot| Some(**slot) != own_slot)
            .copied()
            .collect())
    }
}
