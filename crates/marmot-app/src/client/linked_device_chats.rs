//! Adding linked siblings to chats (mdk#2628 3.5c/3.5d, D14/D70).
//! A new chat includes eligible siblings from private stock in its founding
//! Add; the post-link pass below handles older chats the approver already holds.
//!
//! Once a link this device approved is made, this device, and only it, adds
//! the new device to each of its chats that takes a same-account Add, when
//! the new device's "add to all my chats" setting is on (device-group.md,
//! "Approving"). Each Add uses one of the private KeyPackages the new device
//! handed this device, never a published one, and its sibling Welcome goes
//! out as a 461 (3.5b-2); the chat's history follows from the confirmed Add
//! (4.2b). Other devices add it only through gap filling (3.5e).
//!
//! - Each maintenance pass reads the chats anew: every chat this device is in
//!   and can commit in, in chat-list order, so the chats the user sees first
//!   get the device first, and a restart picks up where it stopped.
//! - A chat already holds the device when one of this account's leaves there
//!   carries the device's tag, or has the signature key the device tags with,
//!   as a leaf from an invite before the link, which carries no tag, does: an
//!   MDK device signs every KeyPackage and leaf with that one key. A client
//!   whose leaves are not signed with its tag key can hold an untagged leaf
//!   from before its link under another key. That chat gets a second
//!   leaf, whose 461 the device holds while its own copy is active (D72): a
//!   stated limit.
//! - A device this device's user decided to remove gets no Add while that
//!   removal waits to commit, or after branch selection drops it.
//! - Nor does a device in a slot a roster state this device applied held as
//!   `removed`, whichever device decided that removal, while this device
//!   keeps the key that record carried (`held_as_removed`): after branch
//!   selection drops the record, and for a later link of the slot
//!   (device-group.md, "Adding the new device to chats").
//! - A chat with this device's commit queued, in flight or settling waits for
//!   a later pass, so an Add is never doubled.
//! - Before a chat takes a KeyPackage, the engine checks the Add against the
//!   KeyPackage it would use, writing nothing. A chat that would refuse takes
//!   none: one that takes no same-account Add at all is counted by
//!   [`AppClient::chats_closed_to_linked_devices`]; one whose requirements
//!   the device's KeyPackages don't meet is passed over.
//! - It asks the new device for one KeyPackage per chat still owed (at most
//!   100 a request), beyond the usual stock of 10, and adds at most
//!   [`LINK_CHAT_ADDS_PER_PASS`] chats a pass.
//! - The work lasts [`LINK_CHAT_ADD_SECS`] after the link was made. Gap
//!   filling covers what is left after that.

use cgka_traits::GroupId;
use cgka_traits::app_components::{DeviceRosterV1, DeviceSlotId, DeviceStatusV1, DeviceTagClaim};
use cgka_traits::engine::SiblingKeyPackage;
use storage_sqlite::{ChatListQuery, DeviceLinkOutcome, ReceivedPrivateKeyPackage};

use super::AppClient;
use super::device_group::{Exchange, device_slot};
use super::private_key_packages::PrivateKeyPackageSelection;
use crate::{AppError, unix_now_seconds};

const TRACE_TARGET: &str = "marmot_app::client::linked_device_chats";

/// The most chats one maintenance pass adds a new device to. Each Add is a
/// chat Commit, a 461 and the chat's history in the device group, and the
/// pass runs on the account's worker, so a large account's link spreads over
/// several passes instead of holding the worker. Measured on a 50-chat link
/// in a debug test build, with chats of one member and no history: a pass of
/// 10 Adds took about 0.65 s against 0.1 s for a pass with none, about 55 ms
/// an Add, and one pass of all 50 took 3.3 s. The worker runs a pass every
/// 15 s, so that link took five passes, about a minute. Larger chats and
/// their history make each Add slower.
pub(crate) const LINK_CHAT_ADDS_PER_PASS: usize = 10;

/// How long after a link is made the approving device keeps adding the new
/// device to its chats: as long as it owes the device a chat's history
/// (D76), which each Add sends.
pub(crate) const LINK_CHAT_ADD_SECS: u64 = 7 * 24 * 60 * 60;

/// A new device this device adds to its chats.
struct NewDevice {
    slot: DeviceSlotId,
    /// The signature key the device tags its leaves with.
    tag_signature_key: Vec<u8>,
}

impl AppClient {
    /// One pass; a failure waits for the next one. Return how many Add
    /// attempts used the per-pass budget, so gap filling shares its remainder.
    pub(crate) async fn add_linked_devices_to_chats(
        &mut self,
        held: &[GroupId],
        selection: &mut PrivateKeyPackageSelection,
    ) -> usize {
        if !self.app.device_groups_enabled() || self.runtime.maintenance_is_paused() {
            return 0;
        }
        let mut budget = LINK_CHAT_ADDS_PER_PASS;
        if let Err(error) = self
            .try_add_linked_devices_to_chats(held, &mut budget, selection)
            .await
        {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "add_linked_devices_to_chats",
                error_kind = error.privacy_safe_kind(),
                "could not add linked devices to chats"
            );
        }
        LINK_CHAT_ADDS_PER_PASS - budget
    }

    /// Each device and each chat is handled on its own: one that fails never
    /// holds the others back, and the first failure is returned at the end.
    async fn try_add_linked_devices_to_chats(
        &mut self,
        held: &[GroupId],
        budget: &mut usize,
        selection: &mut PrivateKeyPackageSelection,
    ) -> Result<(), AppError> {
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        if held.contains(&exchange.group_id) || !exchange.tagged {
            return Ok(());
        }
        let new_devices = self.devices_to_add_to_chats(&exchange, unix_now_seconds())?;
        if new_devices.is_empty() {
            return Ok(());
        }
        let chats = self.sibling_commit_chats_in_list_order()?;
        let mut first_error: Option<AppError> = None;
        'devices: for device in new_devices {
            match self.device_setting_ready(&exchange, &device.slot, |settings| {
                settings.add_to_all_chats
            }) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            }
            let mut owed = Vec::new();
            for chat in &chats {
                match self.chat_owed_to(&exchange.roster, &device, chat) {
                    Ok(true) => owed.push(chat.clone()),
                    Ok(false) => {}
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            if owed.is_empty() {
                continue;
            }
            if let Err(error) = self.want_private_key_packages(
                &device.slot,
                u32::try_from(owed.len()).unwrap_or(u32::MAX),
            ) {
                first_error.get_or_insert(error);
            }
            for chat in owed {
                if *budget == 0 {
                    break 'devices;
                }
                match self.group_quiet(&chat) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        first_error.get_or_insert(error);
                        continue;
                    }
                }
                let candidate =
                    match self.next_private_key_package_for_chat(&chat, &device.slot, selection) {
                        Ok(Some(candidate)) => candidate,
                        Ok(None) => {
                            if !selection.has_unexpired_stock(&device.slot, unix_now_seconds()) {
                                break;
                            }
                            continue;
                        }
                        Err(error) => {
                            first_error.get_or_insert(error);
                            continue;
                        }
                    };
                *budget -= 1;
                selection.record_attempt(&device.slot, &candidate.key_package_ref_hex);
                if let Err(error) = self
                    .add_sibling_to_chat(&chat, &device.slot, candidate)
                    .await
                {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Private KeyPackages for a new chat's founding Add (3.5d). The
    /// old-chat opt-in never excludes a sibling from a newly created chat.
    /// Missing stock is requested for a later use, never looked up in
    /// public slots. Reads/admission finish before taking any KeyPackage;
    /// once taken it is never put back, including after a failed creation.
    pub(crate) fn founding_sibling_key_packages(
        &mut self,
        request: &cgka_traits::engine::CreateGroupRequest,
        optional_components: &[cgka_traits::app_components::AppComponentData],
        constructable: &cgka_traits::capabilities::GroupCapabilities,
        relays: &[String],
    ) -> Vec<SiblingKeyPackage> {
        // Finish optional reads before spending stock. Device-group hydration,
        // quarantine or stock failures must not prevent an unrelated chat.
        let selected = match self.select_founding_sibling_key_packages(
            request,
            optional_components,
            constructable,
            relays,
        ) {
            Ok(selected) => selected,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::client::linked_device_chats",
                    method = "founding_sibling_key_packages",
                    error_kind = error.privacy_safe_kind(),
                    "new chat omits siblings whose eligibility could not be read"
                );
                return Vec::new();
            }
        };
        let mut taken_siblings = Vec::with_capacity(selected.len());
        for (sibling, candidate) in selected {
            match self.take_private_key_package_exact(&sibling.slot, &candidate) {
                Ok(true) => taken_siblings.push(sibling),
                // Expiry or a failed read/write while taking one candidate
                // omits it. Never retry creation or return a possibly spent
                // package to stock; other admitted candidates remain usable.
                result => {
                    if let Err(error) = result {
                        tracing::warn!(
                            target: "marmot_app::client::linked_device_chats",
                            method = "founding_sibling_key_packages",
                            error_kind = error.privacy_safe_kind(),
                            "new chat omits a sibling whose private stock could not be taken"
                        );
                    }
                    self.want_founding_private_key_package(&sibling.slot);
                }
            }
        }
        taken_siblings
    }

    fn want_founding_private_key_package(&mut self, slot: &DeviceSlotId) {
        if let Err(error) = self.want_private_key_packages(slot, 1) {
            tracing::warn!(
                target: "marmot_app::client::linked_device_chats",
                method = "founding_sibling_key_packages",
                error_kind = error.privacy_safe_kind(),
                "could not request replacement private stock for a new chat"
            );
        }
    }

    fn select_founding_sibling_key_packages(
        &mut self,
        request: &cgka_traits::engine::CreateGroupRequest,
        optional_components: &[cgka_traits::app_components::AppComponentData],
        constructable: &cgka_traits::capabilities::GroupCapabilities,
        relays: &[String],
    ) -> Result<Vec<(SiblingKeyPackage, ReceivedPrivateKeyPackage)>, AppError> {
        use cgka_traits::app_components::{ACCOUNT_DEVICES_COMPONENT_ID, default_group_components};
        if !self.app.device_groups_enabled()
            || !cgka_traits::app_components::valid_sibling_welcome_relays(relays)
            || self.runtime.new_protocol_profile() != cgka_traits::group::ProtocolProfile::Current
            || !constructable
                .app_components
                .contains(ACCOUNT_DEVICES_COMPONENT_ID)
        {
            return Ok(Vec::new());
        }
        // A deferred open has not yet named the engine's tag source. Name it
        // before taking stock, rather than relying only on our roster read.
        self.sync_device_tag_group()?;
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(Vec::new());
        };
        if self.runtime.device_tag_group() != Some(&exchange.group_id)
            || !exchange.tagged
            || self.epoch_gap_holds_group(&exchange.group_id, super::recovery::wall_now_ms()?)?
        {
            return Ok(Vec::new());
        }
        let excluded = self.excluded_sibling_slots(&exchange)?;
        let requirements = self
            .runtime
            .create_key_package_requirements(request)
            .map_err(marmot_session::SessionError::from)?;
        // This is advisory selection only. The engine fixes its requirements
        // before adding these siblings and checks them again. Default
        // components negotiate only when all ordinary founders support them;
        // explicit requirements and the selected image must stay supported.
        let mut fixed = default_group_components()
            .into_iter()
            .filter(|id| constructable.app_components.contains(*id))
            .collect::<std::collections::BTreeSet<_>>();
        fixed.insert(ACCOUNT_DEVICES_COMPONENT_ID);
        fixed.extend(
            request
                .app_components
                .iter()
                .map(|entry| entry.component_id),
        );
        fixed.extend(optional_components.iter().map(|entry| entry.component_id));
        let mut selection = PrivateKeyPackageSelection::default();
        let mut selected = Vec::new();
        for slot in exchange.siblings() {
            let entry = &exchange.roster.devices[&slot];
            if excluded.contains(&slot)
                || !matches!(
                    entry.status,
                    DeviceStatusV1::Active | DeviceStatusV1::Inactive
                )
                || entry.tag_signature_key.is_none()
            {
                continue;
            }
            let now = unix_now_seconds();
            let stock =
                self.prepared_private_key_packages(&slot, &exchange, now, &mut selection)?;
            let mut compatible = None;
            for record in stock.compatible_records(&requirements, &fixed, now) {
                let key_package = Self::received_private_key_package(record);
                // The metadata cache rejects only stable incompatibility.
                // Lifetime and actual bytes are checked again before claim.
                if requirements.validate(&key_package).is_err() {
                    continue;
                }
                compatible = Some((SiblingKeyPackage { slot, key_package }, record.clone()));
                break;
            }
            if let Some(candidate) = compatible {
                selected.push(candidate);
            } else {
                self.want_founding_private_key_package(&slot);
            }
        }
        Ok(selected)
    }

    /// Local link outcomes govern only entries this device currently
    /// approved (the same ownership condition as failed-link undo). Another
    /// approver's later link is not blocked by this device's old outcome.
    /// Pending removals and remembered removed keys remain independent.
    pub(crate) fn excluded_sibling_slots(
        &self,
        exchange: &Exchange,
    ) -> Result<std::collections::HashSet<DeviceSlotId>, AppError> {
        let group_id_hex = hex::encode(exchange.group_id.as_slice());
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let links = storage
            .device_links()?
            .into_iter()
            .filter(|link| link.group_id_hex == group_id_hex)
            .filter_map(|link| {
                device_slot(&link.slot_hex)
                    .ok()
                    .map(|slot| (slot, link.outcome))
            })
            .collect::<std::collections::HashMap<_, _>>();
        let mut removed = storage
            .device_removals()?
            .into_iter()
            .filter(|removal| removal.group_id_hex == group_id_hex)
            .filter_map(|removal| device_slot(&removal.slot_hex).ok())
            .collect::<std::collections::HashSet<_>>();
        removed.extend(
            self.remembered_tag_keys(&exchange.group_id)?
                .into_iter()
                .filter(|key| key.held_as_removed)
                .map(|key| key.slot),
        );
        removed.extend(
            exchange
                .roster
                .devices
                .iter()
                .filter(|(slot, entry)| {
                    entry.linked_by == Some(exchange.own_slot)
                        && links.get(*slot) != Some(&DeviceLinkOutcome::Linked)
                })
                .map(|(slot, _)| *slot),
        );
        Ok(removed)
    }

    /// The devices whose links this device approved and decided made less
    /// than [`LINK_CHAT_ADD_SECS`] ago, in this device group, that the roster
    /// lists as active and linked by this device, with "add to all my chats"
    /// on and their tag signature key set. A device this device's user
    /// decided to remove is none of them, while its removal waits to commit
    /// or is made again; nor is one in a slot a roster state this device
    /// applied held as `removed`, while this device keeps that record's key.
    fn devices_to_add_to_chats(
        &self,
        exchange: &Exchange,
        now: u64,
    ) -> Result<Vec<NewDevice>, AppError> {
        let group_id_hex = hex::encode(exchange.group_id.as_slice());
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let excluded = self.excluded_sibling_slots(exchange)?;
        Ok(storage
            .device_links()?
            .into_iter()
            .filter(|link| {
                link.outcome == DeviceLinkOutcome::Linked
                    && link.group_id_hex == group_id_hex
                    && link
                        .decided_at
                        .is_some_and(|at| now < at.saturating_add(LINK_CHAT_ADD_SECS))
            })
            .filter_map(|link| {
                let slot = device_slot(&link.slot_hex).ok()?;
                if excluded.contains(&slot) {
                    return None;
                }
                let entry = exchange.roster.devices.get(&slot)?;
                (entry.linked_by == Some(exchange.own_slot)
                    && entry.status == DeviceStatusV1::Active
                    && entry.settings.add_to_all_chats)
                    .then(|| entry.tag_signature_key.clone())?
                    .map(|tag_signature_key| NewDevice {
                        slot,
                        tag_signature_key,
                    })
            })
            .collect())
    }

    /// Whether `chat` takes a same-account Add and doesn't hold `device` yet.
    fn chat_owed_to(
        &self,
        roster: &DeviceRosterV1,
        device: &NewDevice,
        chat: &GroupId,
    ) -> Result<bool, AppError> {
        if !self.invitation_allows_sibling_add(chat)? {
            return Ok(false);
        }
        if self.runtime.chat_sibling_add_refusal(chat)?.is_some() {
            return Ok(false);
        }
        Ok(!self
            .runtime
            .own_account_leaf_claims(chat, roster)?
            .into_iter()
            .any(|(key, claim)| {
                claim == DeviceTagClaim::Device(device.slot) || key == device.tag_signature_key
            }))
    }

    /// [`Self::sibling_commit_chats`], in the order the chat list shows them.
    fn sibling_commit_chats_in_list_order(&self) -> Result<Vec<GroupId>, AppError> {
        let order: std::collections::HashMap<String, usize> = self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .chat_list_rows(ChatListQuery {
                include_archived: true,
            })?
            .into_iter()
            .enumerate()
            .map(|(position, row)| (row.group_id_hex, position))
            .collect();
        let mut chats = self.sibling_commit_chats();
        chats.sort_by_key(|chat| {
            order
                .get(&hex::encode(chat.as_slice()))
                .copied()
                .unwrap_or(usize::MAX)
        });
        Ok(chats)
    }

    /// How many chats this device is in take no same-account Add, so no
    /// device of this account can be added to them: they don't require
    /// `marmot.group.account-devices.v1`, name no relays a sibling Welcome
    /// can carry, or already hold `max_leaves_per_account` leaves of this
    /// account. A chat admin can turn the first on; removing a device frees
    /// its leaves. Zero while device groups are off or this device trusts
    /// none.
    pub(crate) fn chats_closed_to_linked_devices(&mut self) -> Result<u32, AppError> {
        if !self.app.device_groups_enabled() || self.trusted_device_roster()?.is_none() {
            return Ok(0);
        }
        let mut closed = 0u32;
        for chat in self.sibling_commit_chats() {
            if self.runtime.chat_sibling_add_refusal(&chat)?.is_some() {
                closed = closed.saturating_add(1);
            }
        }
        Ok(closed)
    }
}
