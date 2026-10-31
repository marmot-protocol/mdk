//! Private KeyPackages in the device group (mdk#2628 item 3.4b).
//!
//! Each device issues single-use KeyPackages to every sibling in the device
//! group it trusts, and hands them over inside that group. None is ever
//! published. A sibling adds this device to a chat only with one of them
//! (3.5), never with a public KeyPackage.
//!
//! - Upkeep runs in each maintenance pass. It discards expired KeyPackages on
//!   both sides (even while maintenance is paused or cursors are frozen),
//!   stops counting issued ones that no longer advertise this
//!   client's capabilities, tops up every sibling whose stock is low, sends
//!   hand-offs that were never queued, and only then asks siblings for this
//!   device's own. A device back after a long gap therefore serves its
//!   siblings first.
//! - A device issues, hands over and asks for nothing until its own leaf in
//!   the device group carries a device tag that reads as its slot (3.1d):
//!   until then siblings would refuse what it sends, and it would issue
//!   untagged KeyPackages. A device that joins tags its leaf on its first
//!   maintenance pass; its next one serves its siblings.
//! - A request (459) or hand-off (460) is read only from the trusted device
//!   group, addressed to this device's slot, from another slot its roster
//!   lists, sent by a leaf whose device tag reads as that slot's (mdk#2628
//!   D33). Sending, dispatch by kind and that sender read are shared with
//!   every device-group message (`device_group/messages.rs`). Every KeyPackage in a hand-off must be this account's, single-use,
//!   unexpired, and tagged as that slot's too. An untagged sender is refused
//!   and not counted; it sends again once it has tagged its leaf. A request
//!   that reaches this device before it has tagged its own issues nothing;
//!   upkeep tops the sibling up afterwards.
//! - A lost hand-off is repaired by the next request: a sibling with no usable
//!   KeyPackage from a device asks again at most once an hour. There are no
//!   receipts. An issuer at its cap answers with the newest KeyPackages it
//!   already issued, handed over again, and this device never keeps one it
//!   has used (mdk#2628 D42).
//! - A sibling Welcome (461) adds this device to a chat with one of the
//!   KeyPackages it issued (3.5b). It is read like a hand-off, and also only
//!   when its relays are valid and its KeyPackage is one this device issued
//!   to its sender. The dispatch that reads it cannot wait for a join, so an
//!   admitted one is stashed (migration 0160) and each maintenance pass joins
//!   from the stash, before upkeep tops the sender's stock up again, while
//!   its carrier is still delivered. A refused one is dropped like a refused
//!   hand-off, and so is one whose carrier a branch switch withdrew. One whose
//!   checks could not be read, or admitted but not stashed, fails the event's
//!   projection, which is retried, so a failed read or write never loses it.
//! - A sibling Welcome into a chat this device still holds an active copy of,
//!   such as one ahead of the removal it follows, is held: the engine writes
//!   nothing, and the row keeps the chat's id. Each pass leaves it until that
//!   copy reads removed or unrecoverable, then joins it, with no consent
//!   asked. It goes once it can never join: its carrier withdrawn, its
//!   KeyPackage used or expired, or the chat forgotten or disbanded. A full
//!   stash makes room for a new Welcome by dropping its oldest held one.

use base64::Engine as _;
use cgka_traits::app_components::{
    DeviceRosterV1, DeviceSlotId, DeviceTagClaim, NOSTR_ROUTING_MAX_RELAYS,
    validate_nostr_relay_url,
};
use cgka_traits::storage::{IssuedPrivateKeyPackage, MaintenanceStorage as _, MessageStorage as _};
use cgka_traits::welcome::SiblingWelcomeJoin;
use cgka_traits::{
    EpochId, GroupId, IngestOutcome, KeyPackage, MemberId, MessageId, MessageState, StorageError,
    Timestamp,
};
use marmot_session::{
    KIND_PRIVATE_KEY_PACKAGE_HAND_OFF, KIND_PRIVATE_KEY_PACKAGE_REQUEST, MAX_HAND_OFF_KEY_PACKAGES,
    MAX_PRIVATE_KEY_PACKAGE_WANT, PRIVATE_KEY_PACKAGE_STOCK_LOW, PRIVATE_KEY_PACKAGE_STOCK_TARGET,
    PrivateKeyPackageHandOff, PrivateKeyPackageRequest, SiblingWelcome, private_key_package_stock,
    validate_received_private_key_package,
};
use std::collections::{BTreeMap, BTreeSet};
use storage_sqlite::{PrivateKeyPackageNeed, ReceivedPrivateKeyPackage, StashedSiblingWelcome};

use super::AppClient;
use super::device_group::device_slot;
use crate::{AppError, unix_now_seconds};

const TRACE_TARGET: &str = "marmot_app::client::private_key_packages";

/// While a need lasts, a device asks the same sibling again at most this
/// often.
const REQUEST_INTERVAL_SECS: u64 = 60 * 60;

/// The device group private KeyPackages travel in, its roster, this
/// device's slot there, and whether this device's own leaf carries a device
/// tag that reads as that slot.
struct Exchange {
    group_id: GroupId,
    roster: DeviceRosterV1,
    own_slot: DeviceSlotId,
    tagged: bool,
}

/// Where the chat a held sibling Welcome is into stands.
enum HeldChat {
    /// This device still holds an active copy of it.
    Active,
    /// Its copy reads removed or unrecoverable: the Welcome joins now.
    LetGo,
    /// Forgotten or disbanded: the Welcome never joins.
    Gone,
}

/// What admission makes of a sibling Welcome. A read admission could not
/// make is an error, never a refusal.
pub(super) enum SiblingWelcomeAdmission {
    /// Not addressed to this device.
    NotAddressed,
    /// Refused for what it says or who sent it.
    Refused(AppError),
    Admitted(StashedSiblingWelcome),
}

impl Exchange {
    /// Every other device the roster lists.
    fn siblings(&self) -> Vec<DeviceSlotId> {
        self.roster
            .devices
            .keys()
            .filter(|slot| **slot != self.own_slot)
            .copied()
            .collect()
    }

    fn is_sibling(&self, slot: &DeviceSlotId) -> bool {
        *slot != self.own_slot && self.roster.devices.contains_key(slot)
    }
}

impl AppClient {
    /// The exchange this device takes part in: the trusted device group's,
    /// while the roster lists this device.
    fn private_key_package_exchange(&mut self) -> Result<Option<Exchange>, AppError> {
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

    /// Answer a sibling's request by issuing what it wants. Upkeep sends the
    /// hand-offs. A request answered before issues nothing, and so does one
    /// that reaches this device before its own leaf is tagged.
    pub(super) fn receive_key_package_request(
        &mut self,
        group_id: &GroupId,
        message_id: &MessageId,
        sender: (EpochId, Option<u32>),
        content: &str,
    ) -> Result<(), AppError> {
        let Some(exchange) = self.private_key_package_exchange()? else {
            return Ok(());
        };
        let request = PrivateKeyPackageRequest::decode(content)
            .map_err(|_| AppError::InvalidAppMessagePayload("private KeyPackage request".into()))?;
        if &exchange.group_id != group_id || request.to != exchange.own_slot {
            return Ok(());
        }
        if !exchange.is_sibling(&request.from) {
            return Err(AppError::DeviceGroupRefused("unknown_sibling"));
        }
        self.ensure_sent_by(&exchange.group_id, &exchange.roster, sender, &request.from)?;
        if !exchange.tagged {
            return Ok(());
        }
        let issued = self.runtime.issue_private_key_packages(
            &request.from,
            request.want as usize,
            Some(message_id),
            unix_now_seconds(),
        )?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "receive_key_package_request",
            issued,
            "answered a private KeyPackage request"
        );
        Ok(())
    }

    /// Keep the KeyPackages a sibling handed over, all or none.
    pub(super) fn receive_key_package_hand_off(
        &mut self,
        group_id: &GroupId,
        sender: (EpochId, Option<u32>),
        content: &str,
    ) -> Result<(), AppError> {
        let Some(exchange) = self.private_key_package_exchange()? else {
            return Ok(());
        };
        let invalid = || AppError::InvalidAppMessagePayload("private KeyPackage hand-off".into());
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(content)
            .map_err(|_| invalid())?;
        let hand_off = PrivateKeyPackageHandOff::decode(&bytes).map_err(|_| invalid())?;
        if &exchange.group_id != group_id || hand_off.to != exchange.own_slot {
            return Ok(());
        }
        if !exchange.is_sibling(&hand_off.from) {
            return Err(AppError::DeviceGroupRefused("unknown_sibling"));
        }
        self.ensure_sent_by(&exchange.group_id, &exchange.roster, sender, &hand_off.from)?;
        let account = self.app.account_home().account(&self.state.label)?;
        let account = MemberId::new(hex::decode(&account.account_id_hex)?);
        let now = unix_now_seconds();
        let issuer_slot_hex = hex::encode(hand_off.from);
        let received = hand_off
            .key_packages
            .iter()
            .map(|key_package| {
                let metadata = validate_received_private_key_package(
                    key_package,
                    &account,
                    &exchange.roster,
                    &hand_off.from,
                    now,
                )
                .map_err(|_| AppError::DeviceGroupRefused("private_key_package_refused"))?;
                Ok(ReceivedPrivateKeyPackage {
                    key_package_ref_hex: metadata.key_package_ref_hex,
                    issuer_slot_hex: issuer_slot_hex.clone(),
                    not_before: metadata.not_before,
                    not_after: metadata.not_after,
                    key_package: key_package.bytes().to_vec(),
                    received_at: now,
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let kept = storage.insert_received_private_key_packages(&received)?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "receive_key_package_hand_off",
            kept,
            "kept handed-over private KeyPackages"
        );
        Ok(())
    }

    /// Admit a sibling Welcome that adds this device to a chat, for
    /// [`Self::stash_sibling_welcome`] to keep. Beyond a hand-off's checks,
    /// its relays must be one to [`NOSTR_ROUTING_MAX_RELAYS`] distinct relay
    /// URLs, and its KeyPackage one this device issued to the sender and
    /// still holds; the join checks that KeyPackage again. An error is a
    /// read that failed, which the caller retries rather than drop the
    /// Welcome.
    pub(super) fn admit_sibling_welcome(
        &mut self,
        group_id: &GroupId,
        message_id: &MessageId,
        sender: (EpochId, Option<u32>),
        created_at: u64,
        content: &str,
    ) -> Result<SiblingWelcomeAdmission, AppError> {
        use SiblingWelcomeAdmission::{Admitted, NotAddressed, Refused};
        let Some(exchange) = self.private_key_package_exchange()? else {
            return Ok(NotAddressed);
        };
        let invalid = || Refused(AppError::InvalidAppMessagePayload("sibling Welcome".into()));
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(content) else {
            return Ok(invalid());
        };
        let Ok(welcome) = SiblingWelcome::decode(&bytes) else {
            return Ok(invalid());
        };
        if &exchange.group_id != group_id || welcome.to != exchange.own_slot {
            return Ok(NotAddressed);
        }
        if !exchange.is_sibling(&welcome.from) {
            return Ok(Refused(AppError::DeviceGroupRefused("unknown_sibling")));
        }
        match self.ensure_sent_by(&exchange.group_id, &exchange.roster, sender, &welcome.from) {
            Ok(()) => {}
            Err(refused @ AppError::DeviceGroupRefused(_)) => return Ok(Refused(refused)),
            Err(error) => return Err(error),
        }
        if !valid_sibling_welcome_relays(&welcome.relays) {
            return Ok(invalid());
        }
        if !self
            .runtime
            .issued_private_key_packages()?
            .iter()
            .any(|record| {
                record.key_package_ref == welcome.key_package_ref
                    && record.recipient_slot == welcome.from
            })
        {
            return Ok(Refused(AppError::DeviceGroupRefused(
                "key_package_not_issued_to_sender",
            )));
        }
        Ok(Admitted(StashedSiblingWelcome {
            message_id_hex: hex::encode(message_id.as_slice()),
            content: bytes,
            created_at,
            received_at: unix_now_seconds(),
            held_group_id_hex: None,
        }))
    }

    /// Keep an admitted sibling Welcome for the next maintenance pass to
    /// join. One more than the stash holds is dropped; its sender's resend
    /// (3.5e) is the repair.
    pub(super) fn stash_sibling_welcome(
        &mut self,
        admitted: &StashedSiblingWelcome,
    ) -> Result<(), AppError> {
        let stashed = self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .stash_sibling_welcome(admitted)?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "stash_sibling_welcome",
            stashed,
            "stashed a sibling Welcome"
        );
        Ok(())
    }

    /// Join a chat from every stashed sibling Welcome, oldest first, and
    /// project the joins. A Welcome leaves the stash once its join settles,
    /// whether it joined or was refused, and unjoined once its carrier is no
    /// longer delivered. One into a chat this device still holds stays, held,
    /// until that chat lets go of it or it can never join. One whose join
    /// failed stays for the next pass.
    pub(crate) async fn join_stashed_sibling_welcomes(&mut self) {
        if !self.app.device_groups_enabled() || self.runtime.maintenance_is_paused() {
            return;
        }
        if let Err(error) = self.try_join_stashed_sibling_welcomes().await {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "join_stashed_sibling_welcomes",
                error_kind = error.privacy_safe_kind(),
                "could not join from stashed sibling Welcomes"
            );
        }
    }

    async fn try_join_stashed_sibling_welcomes(&mut self) -> Result<(), AppError> {
        let account = self.app.account_storage(&self.state.label)?;
        let storage = account.app_storage();
        let stashed = storage.stashed_sibling_welcomes()?;
        if stashed.is_empty() {
            return Ok(());
        }
        // As for any other join, keep block updates out until the joins and
        // their projection have settled.
        let policy_lock = self.app.block_update_lock(&self.state.label).await;
        let _policy_guard = policy_lock.lock().await;
        let issued = self.runtime.issued_private_key_packages()?;
        let now = unix_now_seconds();
        let (mut joined, mut held, mut refused, mut withdrawn, mut expired, mut failed) =
            (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        for record in stashed {
            let (Ok(welcome), Ok(message_id)) = (
                SiblingWelcome::decode(&record.content),
                hex::decode(&record.message_id_hex).map(MessageId::new),
            ) else {
                storage.delete_stashed_sibling_welcome(&record.message_id_hex)?;
                refused += 1;
                continue;
            };
            // Join only while the carrier is still delivered: a branch
            // switch that withdraws it (or rolls it back) withdraws the
            // Welcome too. Should the carrier be selected again, its replay
            // stashes the Welcome again.
            match account.get_message(&message_id) {
                Ok(carrier) if carrier.state == MessageState::Processed => {}
                Ok(_) | Err(StorageError::NotFound) => {
                    storage.delete_stashed_sibling_welcome(&record.message_id_hex)?;
                    withdrawn += 1;
                    continue;
                }
                Err(_) => {
                    failed += 1;
                    continue;
                }
            }
            // A held Welcome waits for its chat's copy to let go, and goes
            // once it can never join.
            if let Some(chat) = &record.held_group_id_hex {
                let key_package_held = issued.iter().any(|issued| {
                    issued.key_package_ref == welcome.key_package_ref
                        && issued.recipient_slot == welcome.from
                        && now < issued.not_after
                });
                let chat = match hex::decode(chat) {
                    Ok(chat) if key_package_held => self.held_chat(&GroupId::new(chat))?,
                    _ => HeldChat::Gone,
                };
                match chat {
                    HeldChat::Active => {
                        held += 1;
                        continue;
                    }
                    HeldChat::Gone => {
                        storage.delete_stashed_sibling_welcome(&record.message_id_hex)?;
                        expired += 1;
                        continue;
                    }
                    HeldChat::LetGo => {}
                }
            }
            match self
                .runtime
                .join_sibling_welcome(&message_id, &welcome, Some(Timestamp(record.created_at)))
                .await
            {
                Ok(SiblingWelcomeJoin::Held { group_id }) => {
                    storage.hold_stashed_sibling_welcome(
                        &record.message_id_hex,
                        &hex::encode(group_id.as_slice()),
                    )?;
                    held += 1;
                }
                Ok(SiblingWelcomeJoin::Settled(outcome)) => {
                    storage.delete_stashed_sibling_welcome(&record.message_id_hex)?;
                    if matches!(outcome, IngestOutcome::Processed) {
                        joined += 1;
                    } else {
                        refused += 1;
                    }
                }
                Err(_) => failed += 1,
            }
        }
        tracing::debug!(
            target: TRACE_TARGET,
            method = "join_stashed_sibling_welcomes",
            joined,
            held,
            refused,
            withdrawn,
            expired,
            failed,
            "joined from stashed sibling Welcomes"
        );
        if joined > 0 {
            // GroupJoined is journaled durably, so a failed projection is
            // repaired by the ordinary reopen and drain path.
            let summary = self.drain_pending_session_events().await?;
            self.pending_applied_sync_summary.merge(summary);
        }
        Ok(())
    }

    /// Where the chat a held sibling Welcome is into stands. A chat whose
    /// record cannot be read now, such as one awaiting hydration, is still
    /// active.
    fn held_chat(&self, chat: &GroupId) -> Result<HeldChat, AppError> {
        if self.is_group_forgotten(chat)? {
            return Ok(HeldChat::Gone);
        }
        Ok(match self.runtime.group_record(chat) {
            Ok(group) if group.disbanded.is_some() => HeldChat::Gone,
            Ok(group) if group.removed || group.unrecoverable => HeldChat::LetGo,
            Ok(_) | Err(_) => HeldChat::Active,
        })
    }

    /// Delete expired private KeyPackages on both sides, issued ones with
    /// their keys. Like [`marmot_session::AccountDeviceRuntime::sweep_expired_key_package_private_material`],
    /// this runs even while network maintenance is paused or cursors are
    /// frozen. A failure waits for the next pass.
    pub(crate) fn discard_expired_sibling_key_packages(&mut self) {
        let now = unix_now_seconds();
        let result = self
            .runtime
            .discard_private_key_packages(now, None)
            .map_err(AppError::from)
            .and_then(|_| {
                Ok(self
                    .app
                    .account_storage(&self.state.label)?
                    .app_storage()
                    .delete_expired_received_private_key_packages(now)?)
            });
        if let Err(error) = result {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "discard_expired_sibling_key_packages",
                error_kind = error.privacy_safe_kind(),
                "could not discard expired private KeyPackages"
            );
        }
    }

    /// One upkeep pass; a failure waits for the next one.
    pub(crate) async fn sibling_key_package_upkeep(&mut self, held: &[GroupId]) {
        self.discard_expired_sibling_key_packages();
        if !self.app.device_groups_enabled() || self.runtime.maintenance_is_paused() {
            return;
        }
        if let Err(error) = self.try_sibling_key_package_upkeep(held).await {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "sibling_key_package_upkeep",
                error_kind = error.privacy_safe_kind(),
                "private KeyPackage upkeep failed"
            );
        }
    }

    async fn try_sibling_key_package_upkeep(&mut self, held: &[GroupId]) -> Result<(), AppError> {
        let now = unix_now_seconds();
        let Some(exchange) = self.private_key_package_exchange()? else {
            return Ok(());
        };
        if held.contains(&exchange.group_id) || !exchange.tagged {
            return Ok(());
        }
        // Siblings first, replacing what no longer advertises this client's
        // capabilities.
        self.runtime.uncount_outdated_private_key_packages()?;
        let issued = self.runtime.issued_private_key_packages()?;
        for sibling in exchange.siblings() {
            let stock = private_key_package_stock(&issued, &sibling, now);
            if stock < PRIVATE_KEY_PACKAGE_STOCK_LOW {
                self.runtime.issue_private_key_packages(
                    &sibling,
                    PRIVATE_KEY_PACKAGE_STOCK_TARGET - stock,
                    None,
                    now,
                )?;
            }
        }
        self.send_private_key_package_hand_offs(&exchange).await?;
        // Then this device's own.
        for sibling in exchange.siblings() {
            self.request_private_key_packages_when_needed(&exchange, &sibling, now)
                .await?;
        }
        Ok(())
    }

    /// Send every hand-off not yet queued to a sibling the roster lists, at
    /// most [`MAX_HAND_OFF_KEY_PACKAGES`] KeyPackages each. Each batch is
    /// marked queued before it is sent, so an outcome left unknown never sends
    /// it twice (a lost one is repaired by the sibling's request), and
    /// unmarked when its publication reaches no one, so the next upkeep sends
    /// it again.
    async fn send_private_key_package_hand_offs(
        &mut self,
        exchange: &Exchange,
    ) -> Result<(), AppError> {
        let mut unqueued = BTreeMap::<DeviceSlotId, Vec<IssuedPrivateKeyPackage>>::new();
        for record in self.runtime.issued_private_key_packages()? {
            if !record.hand_off_queued && exchange.is_sibling(&record.recipient_slot) {
                unqueued
                    .entry(record.recipient_slot)
                    .or_default()
                    .push(record);
            }
        }
        for (recipient, records) in unqueued {
            for batch in records.chunks(MAX_HAND_OFF_KEY_PACKAGES) {
                let hand_off = PrivateKeyPackageHandOff {
                    from: exchange.own_slot,
                    to: recipient,
                    key_packages: batch
                        .iter()
                        .map(|record| KeyPackage::new(record.key_package.clone()))
                        .collect(),
                };
                let content = base64::engine::general_purpose::STANDARD.encode(
                    hand_off
                        .encode()
                        .map_err(|error| AppError::InvalidAppMessagePayload(error.to_string()))?,
                );
                let references: Vec<_> = batch
                    .iter()
                    .map(|record| record.key_package_ref.clone())
                    .collect();
                self.runtime
                    .set_private_key_package_hand_offs_queued(&references, true)?;
                if !self
                    .send_device_group_message(
                        &exchange.group_id,
                        KIND_PRIVATE_KEY_PACKAGE_HAND_OFF,
                        content,
                    )
                    .await?
                {
                    self.runtime
                        .set_private_key_package_hand_offs_queued(&references, false)?;
                }
            }
        }
        Ok(())
    }

    /// Ask `sibling` for KeyPackages when this device holds fewer usable ones
    /// than it needs (one, or a burst [`Self::want_private_key_packages`]
    /// set), at most once an hour while that need lasts. A met need is
    /// cleared. The request time is recorded before the request is sent, and
    /// put back only when its publication reaches no one.
    async fn request_private_key_packages_when_needed(
        &mut self,
        exchange: &Exchange,
        sibling: &DeviceSlotId,
        now: u64,
    ) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let issuer_slot_hex = hex::encode(sibling);
        let usable = storage
            .received_private_key_packages()?
            .iter()
            .filter(|record| record.issuer_slot_hex == issuer_slot_hex && record.usable_at(now))
            .count();
        let need = storage.private_key_package_need(&issuer_slot_hex)?;
        let wanted = need.as_ref().map_or(1, |need| need.need);
        if usable >= wanted as usize {
            if need.is_some() {
                storage.delete_private_key_package_need(&issuer_slot_hex)?;
            }
            return Ok(());
        }
        if need
            .as_ref()
            .and_then(|need| need.requested_at)
            .is_some_and(|requested_at| now < requested_at.saturating_add(REQUEST_INTERVAL_SECS))
        {
            return Ok(());
        }
        let want = wanted
            .max(PRIVATE_KEY_PACKAGE_STOCK_TARGET as u32)
            .min(MAX_PRIVATE_KEY_PACKAGE_WANT);
        let request = PrivateKeyPackageRequest {
            from: exchange.own_slot,
            to: *sibling,
            want,
        };
        storage.put_private_key_package_need(&PrivateKeyPackageNeed {
            issuer_slot_hex: issuer_slot_hex.clone(),
            need: wanted,
            requested_at: Some(now),
        })?;
        if !self
            .send_device_group_message(
                &exchange.group_id,
                KIND_PRIVATE_KEY_PACKAGE_REQUEST,
                request.encode(),
            )
            .await?
        {
            match need {
                Some(need) => storage.put_private_key_package_need(&need)?,
                None => storage.delete_private_key_package_need(&issuer_slot_hex)?,
            }
        }
        Ok(())
    }

    /// Take one KeyPackage `issuer` handed this device, to add that sibling
    /// to a chat (3.5): a usable one first. `None` when it holds none
    /// unexpired; never a public KeyPackage instead.
    // 3.5 and 3.6 call this; until then only tests do.
    #[cfg_attr(not(all(test, feature = "test-policy-overrides")), allow(dead_code))]
    pub(crate) fn take_private_key_package(
        &mut self,
        issuer: &DeviceSlotId,
    ) -> Result<Option<KeyPackage>, AppError> {
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .take_received_private_key_package(&hex::encode(issuer), unix_now_seconds())?
            .map(|record| {
                KeyPackage::new(record.key_package)
                    .with_protocol_profile(cgka_traits::group::ProtocolProfile::Current)
            }))
    }

    /// Need `want` usable KeyPackages from `issuer`, a burst for adding it to
    /// many chats (3.5). A larger need than before is asked for at the next
    /// upkeep, not an hour after the last request.
    // 3.5 and 3.6 call this; until then only tests do.
    #[cfg_attr(not(all(test, feature = "test-policy-overrides")), allow(dead_code))]
    pub(crate) fn want_private_key_packages(
        &mut self,
        issuer: &DeviceSlotId,
        want: u32,
    ) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let issuer_slot_hex = hex::encode(issuer);
        let want = want.clamp(1, MAX_PRIVATE_KEY_PACKAGE_WANT);
        let need = storage.private_key_package_need(&issuer_slot_hex)?;
        if need.as_ref().is_some_and(|need| need.need >= want) {
            return Ok(());
        }
        storage.put_private_key_package_need(&PrivateKeyPackageNeed {
            issuer_slot_hex,
            need: want,
            requested_at: None,
        })?;
        Ok(())
    }

    /// Discard everything exchanged with `sibling` (3.6): the KeyPackages
    /// issued to it, keys included, and those it handed over. Removing a
    /// device (`device_removal`) calls this for each `removed` slot.
    pub(crate) fn discard_private_key_packages_of(
        &mut self,
        sibling: &DeviceSlotId,
    ) -> Result<(), AppError> {
        self.runtime
            .discard_private_key_packages(unix_now_seconds(), Some(sibling))?;
        self.app
            .account_storage(&self.state.label)?
            .app_storage()
            .delete_received_private_key_packages_from(&hex::encode(sibling))?;
        Ok(())
    }
}

/// Whether `relays` is a sibling Welcome's valid relay list: one to
/// [`NOSTR_ROUTING_MAX_RELAYS`] Nostr relay URLs, none repeated once parsed.
/// Parsing folds host case, a default port and an empty path, so two
/// spellings of one relay count as a repeat.
fn valid_sibling_welcome_relays(relays: &[String]) -> bool {
    let mut parsed = BTreeSet::new();
    (1..=NOSTR_ROUTING_MAX_RELAYS).contains(&relays.len())
        && relays.iter().all(|relay| {
            validate_nostr_relay_url(relay).is_ok()
                && url::Url::parse(relay).is_ok_and(|url| parsed.insert(url))
        })
}
