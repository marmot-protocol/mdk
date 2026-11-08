//! Best-effort sibling membership repair (mdk#2628 3.5e, D82–D84).
//!
//! Claims suppress competing attempts for ten minutes; they never authorize
//! membership. They are intentionally local transient state. The selected
//! tree is checked again by the engine when an Add actually stages.
//!
//! A chat holding a sibling only by Add leaves it never used, whose
//! KeyPackages expired, holds a copy the sibling can never open (mdk#3042).
//! Once the sibling has been active for an hour after that expiry, the
//! claimant retires those leaves with a same-account Remove, and the chat is
//! then missing the sibling like any other. The wait is memory-only.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use cgka_traits::app_components::{DeviceSlotId, DeviceStatusV1, OwnDeviceLeaf};
use cgka_traits::engine::GroupEvent;
use cgka_traits::error::SiblingAddRefusal;
use cgka_traits::{EpochId, GroupId};
use serde::{Deserialize, Serialize};

use super::AppClient;
use super::device_group::Exchange;
use super::device_removal::OwnLeafRemoval;
use super::private_key_packages::PrivateKeyPackageSelection;
use crate::{AppError, unix_now_seconds};

const TARGET: &str = "marmot_app::client::sibling_chat_gaps";
pub(crate) const KIND_GAP_FILL_CLAIM: u64 = 458;
const CLAIM_LIFETIME_SECS: u64 = 600;
/// How long a sibling must be seen active after its unused Add leaf's
/// KeyPackage expired before that leaf is retired (mdk#3042): this device
/// sees one of its heartbeats dated after the expiry, then another dated at
/// least this much later. A device that opens a Welcome rotates its leaf
/// through its post-join maintenance within minutes of being active, so a
/// leaf still unused after this long is one it cannot open.
const UNUSED_ADD_ACTIVITY_SECS: u64 = 60 * 60;
const MAX_CLAIM_CONTENT_BYTES: usize = 32_768;

type Gap = (GroupId, DeviceSlotId);

/// A claim's canonical content. Decoding a struct also rejects repeated
/// fields; extra fields are refused rather than silently changing meaning.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClaimContent {
    v: u8,
    from: String,
    to: String,
    chat: String,
}

struct Claim {
    from: DeviceSlotId,
    to: DeviceSlotId,
    chat: GroupId,
    expires_at: u64,
}

impl Claim {
    fn decode(content: &str, created_at: u64, now: u64) -> Result<Option<Self>, AppError> {
        let invalid = || AppError::InvalidAppMessagePayload("gap-fill claim".into());
        if content.len() > MAX_CLAIM_CONTENT_BYTES {
            return Err(invalid());
        }
        let Some(expires_at) = created_at.checked_add(CLAIM_LIFETIME_SECS) else {
            return Ok(None);
        };
        if created_at > now || expires_at <= now {
            return Ok(None);
        }
        let wire: ClaimContent = serde_json::from_str(content).map_err(|_| invalid())?;
        if serde_json::to_string(&wire).map_err(|_| invalid())? != content {
            return Err(invalid());
        }
        let slot = |value: &str| {
            if value.len() != 64 || !lower_hex(value) {
                return Err(invalid());
            }
            hex::decode(value)
                .ok()
                .and_then(|bytes| DeviceSlotId::try_from(bytes).ok())
                .ok_or_else(invalid)
        };
        if wire.v != 1 || wire.chat.is_empty() || !lower_hex(&wire.chat) {
            return Err(invalid());
        }
        let from = slot(&wire.from)?;
        let to = slot(&wire.to)?;
        if from == to {
            return Err(invalid());
        }
        let chat = GroupId::new(hex::decode(wire.chat).map_err(|_| invalid())?);
        Ok(Some(Self {
            from,
            to,
            chat,
            expires_at,
        }))
    }

    fn content(from: DeviceSlotId, to: DeviceSlotId, chat: &GroupId) -> Option<String> {
        let content = serde_json::to_string(&ClaimContent {
            v: 1,
            from: hex::encode(from),
            to: hex::encode(to),
            chat: hex::encode(chat.as_slice()),
        })
        .ok()?;
        (content.len() <= MAX_CLAIM_CONTENT_BYTES).then_some(content)
    }
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A leaving device cannot advance gap filling; its earlier claims no
/// longer hold another worker back. Active and inactive entries remain linked.
fn claimant_is_eligible(exchange: &Exchange, slot: &DeviceSlotId) -> bool {
    exchange.roster.devices.get(slot).is_some_and(|entry| {
        matches!(
            entry.status,
            DeviceStatusV1::Active | DeviceStatusV1::Inactive
        )
    })
}

/// Effective admission inputs, independent of routine device-group commits.
/// Select targets through `gap_siblings` so local link/removal decisions and
/// pending settings intentions participate in invalidation.
#[derive(PartialEq, Eq)]
struct GapEligibility {
    group: GroupId,
    own_slot: DeviceSlotId,
    targets: BTreeMap<DeviceSlotId, Vec<u8>>,
    claimants: BTreeSet<DeviceSlotId>,
}

/// Canonical eligibility keeps advisory bookkeeping alive while a local
/// settings intention temporarily prevents a new attempt for that target.
struct GapSiblings {
    eligible: Vec<DeviceSlotId>,
    ready: Vec<DeviceSlotId>,
    first_error: Option<AppError>,
}

/// A chat holding a sibling only by leaves an Add built from its
/// KeyPackages, which it has not used (mdk#3042).
struct UnusedAdd {
    /// The latest `not_after` of those KeyPackages.
    until: u64,
    /// The first last-activity date this device read for the sibling after
    /// `until`, if any.
    active_after: Option<u64>,
}

/// What gap filling does for one sibling in one chat (mdk#3042).
#[derive(Debug, PartialEq, Eq)]
enum GapRepair {
    /// The chat holds the sibling, or takes no Add of it: nothing to do,
    /// and claims and stock waiters for it are dropped.
    Present,
    /// The chat holds the sibling only by unused Add leaves whose
    /// KeyPackages expired, and the sibling has not yet been active long
    /// enough since. Claims and stock waiters stay, so a device that
    /// finished its wait first keeps the others deferring to its claim.
    Waiting,
    /// The chat lacks the sibling: add it.
    Add,
    /// Retire these unused Add leaves, by signature key, then add it.
    Retire(Vec<Vec<u8>>),
}

/// Only changed or due chats are examined. Routine device-group commits
/// with unchanged admission inputs never reload every chat's MLS tree.
#[derive(Default)]
pub(crate) struct SiblingChatGaps {
    eligibility: Option<GapEligibility>,
    due: HashMap<GroupId, u64>,
    claims: HashMap<Gap, BTreeMap<DeviceSlotId, u64>>,
    waiting_for_stock: HashSet<Gap>,
    unused_adds: HashMap<Gap, UnusedAdd>,
}

impl SiblingChatGaps {
    /// Compare against the last inputs for which work was actually scheduled.
    /// Temporary device-group busy/hold windows do not invalidate all chats,
    /// and must not consume a genuine change before the sender is ready.
    fn schedule_eligibility(&mut self, eligibility: GapEligibility, ready: bool) -> bool {
        if !ready || self.eligibility.as_ref() == Some(&eligibility) {
            return false;
        }
        if self
            .eligibility
            .as_ref()
            .is_some_and(|prior| prior.group != eligibility.group)
        {
            self.claims.clear();
            self.waiting_for_stock.clear();
            self.unused_adds.clear();
        }
        self.eligibility = Some(eligibility);
        true
    }

    fn schedule(&mut self, chat: GroupId, at: u64) {
        self.due
            .entry(chat)
            .and_modify(|held| *held = (*held).min(at))
            .or_insert(at);
    }

    fn retain_claim(&mut self, claim: Claim) {
        self.claims
            .entry((claim.chat.clone(), claim.to))
            .or_default()
            .entry(claim.from)
            .and_modify(|at| *at = (*at).max(claim.expires_at))
            .or_insert(claim.expires_at);
        self.schedule(claim.chat, 0);
    }

    fn expire(&mut self, now: u64) {
        let mut changed = Vec::new();
        self.claims.retain(|(chat, _), claims| {
            let before = claims.len();
            claims.retain(|_, expiry| *expiry > now);
            if claims.len() != before {
                changed.push(chat.clone());
            }
            !claims.is_empty()
        });
        for chat in changed {
            self.schedule(chat, 0);
        }
    }

    /// A previous local attempt keeps its original advisory deadline even
    /// after a terminal rollback. Do not emit fresh claims or spend fresh
    /// stock every maintenance tick. Restart may forget this local hygiene.
    fn claim_wait_until(&self, gap: &Gap, own: &DeviceSlotId, now: u64) -> Option<u64> {
        self.claims
            .get(gap)
            .and_then(|claims| claims.get(own))
            .copied()
            .filter(|expiry| *expiry > now)
            .or_else(|| self.lower_claim_until(gap, own, now))
    }

    fn lower_claim_until(&self, gap: &Gap, own: &DeviceSlotId, now: u64) -> Option<u64> {
        self.claims
            .get(gap)?
            .iter()
            .find_map(|(slot, expiry)| (slot < own && *expiry > now).then_some(*expiry))
    }

    /// Decide [`GapRepair`] for `gap` from the chat's own refusal of a
    /// sibling Add, the sibling's leaves there, its last activity and the
    /// time. A chat refusing only because it holds as many of this
    /// account's leaves as it may still retires unused leaves, since that
    /// frees the place the Add after it needs; the Add runs its own check.
    fn repair(
        &mut self,
        gap: &Gap,
        refusal: Option<SiblingAddRefusal>,
        leaves: Vec<OwnDeviceLeaf>,
        last_active: Option<u64>,
        now: u64,
    ) -> GapRepair {
        let repair = self.decide_repair(gap, refusal, leaves, last_active, now);
        if repair == GapRepair::Present {
            self.claims.remove(gap);
            self.waiting_for_stock.remove(gap);
        }
        repair
    }

    /// Only a chat holding the sibling by unused Add leaves keeps its
    /// [`UnusedAdd`] entry, so the sibling's heartbeats wake that chat.
    fn decide_repair(
        &mut self,
        gap: &Gap,
        refusal: Option<SiblingAddRefusal>,
        leaves: Vec<OwnDeviceLeaf>,
        last_active: Option<u64>,
        now: u64,
    ) -> GapRepair {
        let retirable = refusal.is_none_or(|refusal| refusal == SiblingAddRefusal::AccountLeaves);
        // The latest expiry, when every leaf is still its unused Add leaf.
        let unused_until = if retirable && !leaves.is_empty() {
            leaves.iter().try_fold(0, |until, leaf| {
                leaf.add_not_after.map(|not_after| until.max(not_after))
            })
        } else {
            None
        };
        let Some(until) = unused_until else {
            self.unused_adds.remove(gap);
            return if refusal.is_none() && leaves.is_empty() {
                GapRepair::Add
            } else {
                GapRepair::Present
            };
        };
        let keys = leaves.into_iter().map(|leaf| leaf.signature_key).collect();
        if self.unused_add_expired(gap, until, last_active, now) {
            GapRepair::Retire(keys)
        } else if now > until {
            GapRepair::Waiting
        } else {
            // Kept in `unused_adds` so the sibling's first heartbeat after
            // `until` wakes the chat.
            GapRepair::Present
        }
    }

    /// Whether the unused Add leaves of `gap`, whose KeyPackages lived until
    /// `until`, are to be retired, given the sibling's last activity. Its
    /// first activity read after `until` starts the wait; activity at least
    /// [`UNUSED_ADD_ACTIVITY_SECS`] later ends it. Kept in memory: a restart,
    /// or a changed `until`, starts the wait again.
    fn unused_add_expired(
        &mut self,
        gap: &Gap,
        until: u64,
        last_active: Option<u64>,
        now: u64,
    ) -> bool {
        let entry = self.unused_adds.entry(gap.clone()).or_insert(UnusedAdd {
            until,
            active_after: None,
        });
        if entry.until != until {
            *entry = UnusedAdd {
                until,
                active_after: None,
            };
        }
        let Some(active) = last_active.filter(|active| *active > until && now > until) else {
            return false;
        };
        match entry.active_after {
            None => {
                entry.active_after = Some(active);
                false
            }
            Some(first) => active >= first.saturating_add(UNUSED_ADD_ACTIVITY_SECS),
        }
    }

    /// Forget `gap`'s own claim once the work it covered went out, so the
    /// Add that follows claims afresh.
    fn release_own_claim(&mut self, gap: &Gap, own: &DeviceSlotId) {
        if let Some(claims) = self.claims.get_mut(gap) {
            claims.remove(own);
            if claims.is_empty() {
                self.claims.remove(gap);
            }
        }
    }
}

impl AppClient {
    pub(super) fn invitation_decision_changes_sibling_gaps(&mut self, chat: &GroupId) {
        self.sibling_chat_gaps.schedule(chat.clone(), 0);
    }

    pub(crate) fn note_sibling_chat_gap_event(&mut self, event: &GroupEvent) {
        if !self.app.device_groups_enabled() {
            return;
        }
        let group = match event {
            GroupEvent::GroupCreated { group_id }
            | GroupEvent::GroupJoined { group_id, .. }
            | GroupEvent::EpochChanged { group_id, .. }
            | GroupEvent::GroupStateInvalidated { group_id, .. }
            | GroupEvent::GroupStateRevalidated { group_id, .. }
            | GroupEvent::LocalGroupCopyRestored { group_id }
            | GroupEvent::GroupHydrationRecovered { group_id, .. } => group_id,
            _ => return,
        };
        // A device-group epoch event is not chat work. Its relevant roster
        // or readiness changes are detected by the effective snapshot below.
        if self.is_device_group(group).ok() == Some(false) {
            self.sibling_chat_gaps.schedule(group.clone(), 0);
        }
    }

    /// A heartbeat from `slot` counted: recheck the chats holding it only by
    /// unused Add leaves (mdk#3042).
    pub(super) fn sibling_gap_activity(&mut self, slot: &DeviceSlotId) {
        let chats: Vec<_> = self
            .sibling_chat_gaps
            .unused_adds
            .keys()
            .filter(|(_, sibling)| sibling == slot)
            .map(|(chat, _)| chat.clone())
            .collect();
        for chat in chats {
            self.sibling_chat_gaps.schedule(chat, 0);
        }
    }

    pub(super) fn sibling_gap_stock_arrived(&mut self, slot: &DeviceSlotId) {
        let chats: Vec<_> = self
            .sibling_chat_gaps
            .waiting_for_stock
            .iter()
            .filter(|(_, sibling)| sibling == slot)
            .map(|(chat, _)| chat.clone())
            .collect();
        for chat in chats {
            self.sibling_chat_gaps.schedule(chat, 0);
        }
    }

    /// The chats this device's gap filling last found no private KeyPackage
    /// from `slot` for, in id order, while `slot` is ready for gap filling's
    /// Adds. Upkeep reads them to tell whether held stock can serve them
    /// (mdk#2883). A waiter kept through a local settings hold, or for a
    /// sibling no longer eligible, asks for nothing, like gap filling's own
    /// stock requests.
    pub(super) fn chats_waiting_for_private_stock(
        &mut self,
        exchange: &Exchange,
        slot: &DeviceSlotId,
    ) -> Result<Vec<GroupId>, AppError> {
        let mut chats: Vec<_> = self
            .sibling_chat_gaps
            .waiting_for_stock
            .iter()
            .filter(|(_, sibling)| sibling == slot)
            .map(|(chat, _)| chat.clone())
            .collect();
        if chats.is_empty() || !self.gap_siblings(exchange)?.ready.contains(slot) {
            return Ok(Vec::new());
        }
        chats.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        Ok(chats)
    }

    fn gap_siblings(&mut self, exchange: &Exchange) -> Result<GapSiblings, AppError> {
        let excluded = self.excluded_sibling_slots(exchange)?;
        let mut siblings = GapSiblings {
            eligible: Vec::new(),
            ready: Vec::new(),
            first_error: None,
        };
        for (slot, entry) in &exchange.roster.devices {
            if *slot != exchange.own_slot
                && !excluded.contains(slot)
                && matches!(
                    entry.status,
                    DeviceStatusV1::Active | DeviceStatusV1::Inactive
                )
                && entry.settings.add_to_all_chats
                && entry.tag_signature_key.is_some()
            {
                siblings.eligible.push(*slot);
                match self
                    .device_setting_ready(exchange, slot, |settings| settings.add_to_all_chats)
                {
                    Ok(true) => siblings.ready.push(*slot),
                    Ok(false) => {}
                    Err(error) => {
                        siblings.first_error.get_or_insert(error);
                    }
                }
            }
        }
        Ok(siblings)
    }

    /// What gap filling does for `slot` in `chat` ([`GapRepair`]). A chat
    /// holds the sibling when one of this account's leaves there carries its
    /// tag or has its tag signature key. A chat holding it only by unused
    /// Add leaves whose KeyPackages expired, while the sibling has been
    /// active since ([`SiblingChatGaps::unused_add_expired`]), holds a copy
    /// the sibling can never open: those leaves are retired (mdk#3042).
    fn gap_repair(&mut self, exchange: &Exchange, gap: &Gap) -> Result<GapRepair, AppError> {
        let (chat, slot) = gap;
        let refusal = self.runtime.chat_sibling_add_refusal(chat)?;
        let entry = exchange.roster.devices.get(slot);
        let leaves = if refusal.is_none_or(|refusal| refusal == SiblingAddRefusal::AccountLeaves) {
            self.runtime.own_device_leaves(
                chat,
                &exchange.roster,
                slot,
                entry.and_then(|entry| entry.tag_signature_key.as_deref()),
            )?
        } else {
            Vec::new()
        };
        let unused = !leaves.is_empty() && leaves.iter().all(|leaf| leaf.add_not_after.is_some());
        let last_active = match entry {
            Some(entry) if unused => self.sibling_last_active(slot, entry.linked_at)?,
            _ => None,
        };
        Ok(self
            .sibling_chat_gaps
            .repair(gap, refusal, leaves, last_active, unix_now_seconds()))
    }

    /// The newest date a heartbeat from the roster entry `slot` linked at
    /// `linked_at` counted for.
    fn sibling_last_active(
        &self,
        slot: &DeviceSlotId,
        linked_at: u64,
    ) -> Result<Option<u64>, AppError> {
        let slot_hex = hex::encode(slot);
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .device_activity()?
            .into_iter()
            .find(|activity| activity.slot_id_hex == slot_hex && activity.linked_at == linked_at)
            .and_then(|activity| activity.last_active_at))
    }

    pub(super) fn receive_gap_fill_claim(
        &mut self,
        group: &GroupId,
        sender: (EpochId, Option<u32>),
        created_at: u64,
        content: &str,
    ) -> Result<(), AppError> {
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        if *group != exchange.group_id {
            return Ok(());
        }
        let Some(claim) = Claim::decode(content, created_at, unix_now_seconds())? else {
            return Ok(());
        };
        if claim.from == exchange.own_slot
            || !claimant_is_eligible(&exchange, &claim.from)
            || !self.gap_siblings(&exchange)?.eligible.contains(&claim.to)
            || !self.sibling_commit_chats().contains(&claim.chat)
        {
            return Ok(());
        }
        self.ensure_sent_by(group, &exchange.roster, sender, &claim.from)?;
        self.sibling_chat_gaps.retain_claim(claim);
        Ok(())
    }

    pub(crate) async fn fill_sibling_chat_gaps(
        &mut self,
        held: &[GroupId],
        budget: usize,
        selection: &mut PrivateKeyPackageSelection,
    ) {
        if budget == 0 || !self.app.device_groups_enabled() || self.runtime.maintenance_is_paused()
        {
            return;
        }
        if let Err(error) = self
            .try_fill_sibling_chat_gaps(held, budget, selection)
            .await
        {
            tracing::warn!(target: TARGET, method = "fill_sibling_chat_gaps", error_kind = error.privacy_safe_kind(), "could not fill sibling chat gaps");
        }
    }

    async fn try_fill_sibling_chat_gaps(
        &mut self,
        held: &[GroupId],
        mut budget: usize,
        selection: &mut PrivateKeyPackageSelection,
    ) -> Result<(), AppError> {
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        let GapSiblings {
            eligible,
            ready,
            mut first_error,
        } = self.gap_siblings(&exchange)?;
        let sender_ready = !ready.is_empty()
            && !held.contains(&exchange.group_id)
            && claimant_is_eligible(&exchange, &exchange.own_slot)
            && exchange.tagged
            && self.group_quiet(&exchange.group_id)?;
        let eligibility = GapEligibility {
            group: exchange.group_id.clone(),
            own_slot: exchange.own_slot,
            targets: ready
                .iter()
                .filter_map(|slot| {
                    exchange.roster.devices[slot]
                        .tag_signature_key
                        .clone()
                        .map(|key| (*slot, key))
                })
                .collect(),
            claimants: exchange
                .roster
                .devices
                .keys()
                .filter(|slot| claimant_is_eligible(&exchange, slot))
                .copied()
                .collect(),
        };
        if eligible.is_empty() {
            self.sibling_chat_gaps.eligibility = None;
            self.sibling_chat_gaps.due.clear();
            self.sibling_chat_gaps.claims.clear();
            self.sibling_chat_gaps.waiting_for_stock.clear();
            self.sibling_chat_gaps.unused_adds.clear();
            return Ok(());
        }
        let changed = self
            .sibling_chat_gaps
            .schedule_eligibility(eligibility, sender_ready);
        if !sender_ready {
            return first_error.map_or(Ok(()), Err);
        }
        let now = unix_now_seconds();
        self.sibling_chat_gaps.expire(now);
        if changed {
            for chat in self.sibling_commit_chats() {
                self.sibling_chat_gaps.schedule(chat, 0);
            }
        }
        if self.sibling_chat_gaps.due.values().all(|at| *at > now) {
            return first_error.map_or(Ok(()), Err);
        }
        let known: HashSet<_> = self.sibling_commit_chats().into_iter().collect();
        self.sibling_chat_gaps
            .claims
            .retain(|(chat, target), claims| {
                claims.retain(|slot, _| claimant_is_eligible(&exchange, slot));
                known.contains(chat) && eligible.contains(target) && !claims.is_empty()
            });
        self.sibling_chat_gaps
            .waiting_for_stock
            .retain(|(chat, target)| known.contains(chat) && eligible.contains(target));
        self.sibling_chat_gaps
            .unused_adds
            .retain(|(chat, target), _| known.contains(chat) && eligible.contains(target));
        self.sibling_chat_gaps
            .due
            .retain(|chat, _| known.contains(chat));
        let mut due: Vec<_> = self
            .sibling_chat_gaps
            .due
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(chat, _)| chat.clone())
            .collect();
        due.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        for chat in due {
            self.sibling_chat_gaps.due.remove(&chat);
            let result = self
                .fill_one_chat_gap(&exchange, &chat, &ready, &mut budget, selection)
                .await;
            if let Err(error) = result {
                self.sibling_chat_gaps.schedule(chat, 0);
                first_error.get_or_insert(error);
            }
        }
        let mut needed = HashMap::<DeviceSlotId, u32>::new();
        for (_, slot) in &self.sibling_chat_gaps.waiting_for_stock {
            if !ready.contains(slot) {
                continue;
            }
            let count = needed.entry(*slot).or_default();
            *count = count.saturating_add(1);
        }
        for (slot, count) in needed {
            if let Err(error) = self.want_private_key_packages(&slot, count) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn fill_one_chat_gap(
        &mut self,
        exchange: &Exchange,
        chat: &GroupId,
        siblings: &[DeviceSlotId],
        budget: &mut usize,
        selection: &mut PrivateKeyPackageSelection,
    ) -> Result<(), AppError> {
        // A semantic hold does not retire advisory claims or stock waiters.
        // Their original deadlines and ordinary pruning remain independent.
        if !self.invitation_allows_sibling_add(chat)? {
            return Ok(());
        }
        if !self.group_quiet(chat)? {
            self.sibling_chat_gaps.schedule(chat.clone(), 0);
            return Ok(());
        }
        let mut first_error = None;
        for slot in siblings {
            let gap = (chat.clone(), *slot);
            let repair = self.gap_repair(exchange, &gap)?;
            let retire = match &repair {
                GapRepair::Present | GapRepair::Waiting => continue,
                GapRepair::Add => Vec::new(),
                GapRepair::Retire(keys) => keys.clone(),
            };
            if *budget == 0 {
                self.sibling_chat_gaps.schedule(chat.clone(), 0);
                break;
            }
            // An earlier target may have left a retained Commit even though
            // its send returned successfully. Do not publish another claim
            // for work this chat already cannot advance.
            if !self.group_quiet(chat)? {
                self.sibling_chat_gaps.schedule(chat.clone(), 0);
                break;
            }
            if let Some(expiry) = self.sibling_chat_gaps.claim_wait_until(
                &gap,
                &exchange.own_slot,
                unix_now_seconds(),
            ) {
                self.sibling_chat_gaps.schedule(chat.clone(), expiry);
                continue;
            }
            // Retiring unused leaves spends no KeyPackage, and the engine
            // refuses an Add while they hold the sibling's place.
            if retire.is_empty() {
                match self.next_private_key_package_for_chat(chat, slot, selection) {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        self.sibling_chat_gaps.waiting_for_stock.insert(gap);
                        continue;
                    }
                    Err(error) => {
                        first_error.get_or_insert(error);
                        continue;
                    }
                }
            }
            let Some(content) = Claim::content(exchange.own_slot, *slot, chat) else {
                continue;
            };
            let event = self.device_group_event(KIND_GAP_FILL_CLAIM, content)?;
            let Some(expiry) = event.created_at.checked_add(CLAIM_LIFETIME_SECS) else {
                continue;
            };
            if !self
                .send_device_group_event_at(&exchange.group_id, event, Some(exchange.pin))
                .await?
            {
                self.sibling_chat_gaps.schedule(chat.clone(), 0);
                continue;
            }
            self.sibling_chat_gaps.retain_claim(Claim {
                from: exchange.own_slot,
                to: *slot,
                chat: chat.clone(),
                expires_at: expiry,
            });
            if expiry <= unix_now_seconds() {
                self.sibling_chat_gaps.schedule(chat.clone(), 0);
                continue;
            }
            if let Some(until) = self.sibling_chat_gaps.lower_claim_until(
                &gap,
                &exchange.own_slot,
                unix_now_seconds(),
            ) {
                self.sibling_chat_gaps.schedule(chat.clone(), until);
                continue;
            }
            let Some(current) = self.device_group_exchange()? else {
                continue;
            };
            if current.group_id != exchange.group_id
                || !claimant_is_eligible(&current, &current.own_slot)
                || !current.tagged
                || !self.group_quiet(&current.group_id)?
                || !self.invitation_allows_sibling_add(chat)?
                || !self.group_quiet(chat)?
                || self.gap_repair(&current, &gap)? != repair
            {
                continue;
            }
            let current_siblings = self.gap_siblings(&current)?;
            if let Some(error) = current_siblings.first_error {
                first_error.get_or_insert(error);
            }
            if !current_siblings.ready.contains(slot) {
                continue;
            }
            if !retire.is_empty() {
                // The Add follows once the Remove confirms and the chat
                // finds the sibling missing, under a claim of its own.
                *budget -= 1;
                match self.remove_own_account_leaves(chat, retire).await? {
                    OwnLeafRemoval::Sent => {
                        self.sibling_chat_gaps
                            .release_own_claim(&gap, &exchange.own_slot);
                        self.sibling_chat_gaps.unused_adds.remove(&gap);
                        self.sibling_chat_gaps.schedule(chat.clone(), 0);
                    }
                    OwnLeafRemoval::Busy => self.sibling_chat_gaps.schedule(chat.clone(), 0),
                    OwnLeafRemoval::Unsupported => {}
                }
                continue;
            }
            // Sending the claim may have advanced local effects. Select
            // compatible stock again and pass that exact record to the Add;
            // a clock/preference change cannot consume another allocation.
            let candidate = match self.next_private_key_package_for_chat(chat, slot, selection) {
                Ok(Some(candidate)) => candidate,
                Ok(None) => {
                    self.sibling_chat_gaps.waiting_for_stock.insert(gap);
                    continue;
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            *budget -= 1;
            selection.record_attempt(slot, &candidate.key_package_ref_hex);
            self.add_sibling_to_chat(chat, slot, candidate).await?;
            self.sibling_chat_gaps
                .waiting_for_stock
                .remove(&(chat.clone(), *slot));
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLAIM: &str = concat!(
        "{\"v\":1,\"from\":\"",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "\",\"to\":\"",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "\",\"chat\":\"010203\"}"
    );

    /// Scheduling depends on structural inputs at the last ready pass,
    /// not on sampling a temporary busy interval. Changes during that
    /// interval must still schedule the first ready pass.
    #[test]
    fn blocked_gap_passes_preserve_the_last_scheduled_eligibility() {
        let eligibility = |key| GapEligibility {
            group: GroupId::new(vec![1, 2, 3]),
            own_slot: [1; 32],
            targets: BTreeMap::from([([2; 32], vec![key; 32])]),
            claimants: BTreeSet::from([[1; 32], [2; 32]]),
        };
        let mut state = SiblingChatGaps::default();
        assert!(!state.schedule_eligibility(eligibility(3), false));
        assert!(
            state.schedule_eligibility(eligibility(3), true),
            "first ready pass schedules"
        );
        assert!(!state.schedule_eligibility(eligibility(3), false));
        assert!(
            !state.schedule_eligibility(eligibility(3), true),
            "busy/ready alone does not rescan"
        );
        assert!(!state.schedule_eligibility(eligibility(4), false));
        assert!(
            state.schedule_eligibility(eligibility(4), true),
            "blocked key change is not consumed"
        );
        assert!(!state.schedule_eligibility(eligibility(4), true));
    }

    #[test]
    fn gap_claims_have_canonical_bytes_and_reject_ambiguous_fields() {
        assert_eq!(
            Claim::content([0x11; 32], [0x22; 32], &GroupId::new(vec![1, 2, 3])).as_deref(),
            Some(CLAIM)
        );
        let decoded = Claim::decode(CLAIM, 100, 200).unwrap().unwrap();
        assert_eq!(
            (
                decoded.from,
                decoded.to,
                decoded.chat.as_slice(),
                decoded.expires_at
            ),
            ([0x11; 32], [0x22; 32], &[1, 2, 3][..], 700)
        );
        let other_order = CLAIM
            .replace("{\"v\":1,", "{ ")
            .replace("\"chat\":\"010203\"}", "\"chat\":\"010203\", \"v\":1 }");
        for malformed in [
            other_order,
            format!(" {CLAIM}"),
            format!("{CLAIM}\n"),
            CLAIM.replace("010203", r"\u003010203"),
            CLAIM.replace("\"v\":1", "\"v\":1,\"v\":1"),
            CLAIM.replace("\"v\":1", "\"v\":1,\"extra\":false"),
            CLAIM.replace("\"v\":1", "\"v\":2"),
            CLAIM.replace("\"v\":1", "\"v\":1.0"),
            CLAIM.replace("010203", "abc"),
            CLAIM.replace("010203", "AB"),
            CLAIM.replace("010203", ""),
            CLAIM.replace(&"22".repeat(32), &"11".repeat(32)),
            format!("{}{}", " ".repeat(MAX_CLAIM_CONTENT_BYTES), CLAIM),
        ] {
            assert!(matches!(
                Claim::decode(&malformed, 100, 200),
                Err(AppError::InvalidAppMessagePayload(_))
            ));
        }
        let long_chat = GroupId::new(vec![0x45; 257]);
        let content = Claim::content([0x11; 32], [0x22; 32], &long_chat).unwrap();
        assert_eq!(
            Claim::decode(&content, 100, 200).unwrap().unwrap().chat,
            long_chat
        );
    }

    #[test]
    fn replayed_claims_keep_the_original_deadline_and_lowest_live_claimant_wins() {
        let mut state = SiblingChatGaps::default();
        let gap = (GroupId::new(vec![1, 2, 3]), [0x22; 32]);
        state.retain_claim(Claim::decode(CLAIM, 100, 200).unwrap().unwrap());
        assert_eq!(state.lower_claim_until(&gap, &[0x33; 32], 200), Some(700));
        assert_eq!(state.lower_claim_until(&gap, &[0x01; 32], 200), None);
        assert_eq!(state.claim_wait_until(&gap, &[0x11; 32], 200), Some(700));
        assert_eq!(state.claim_wait_until(&gap, &[0x01; 32], 200), None);
        state.retain_claim(Claim::decode(CLAIM, 100, 699).unwrap().unwrap());
        assert_eq!(state.lower_claim_until(&gap, &[0x33; 32], 699), Some(700));
        assert_eq!(state.lower_claim_until(&gap, &[0x33; 32], 700), None);
        state.due.clear();
        state.expire(700);
        assert_eq!(state.lower_claim_until(&gap, &[0x33; 32], 700), None);
        assert_eq!(state.claim_wait_until(&gap, &[0x11; 32], 700), None);
        assert_eq!(state.due.get(&gap.0), Some(&0));
        assert!(Claim::decode(CLAIM, 100, 700).unwrap().is_none());
        assert!(Claim::decode(CLAIM, 201, 200).unwrap().is_none());
        assert!(Claim::decode(CLAIM, u64::MAX, u64::MAX).unwrap().is_none());
    }

    /// mdk#3042: a sibling held only by unused Add leaves whose KeyPackages
    /// expired is retired after an hour of its activity since, even in a
    /// chat holding as many of this account's leaves as it may. While that
    /// wait runs, live claims stay, so a device that finished its wait
    /// first keeps the others deferring to its claim.
    #[test]
    fn expired_unused_add_leaves_are_retired_after_an_hour_of_activity() {
        let mut state = SiblingChatGaps::default();
        let gap = (GroupId::new(vec![1, 2, 3]), [0x22; 32]);
        let unused = || {
            vec![OwnDeviceLeaf {
                signature_key: vec![7; 32],
                add_not_after: Some(1_000),
            }]
        };
        let full = Some(SiblingAddRefusal::AccountLeaves);
        assert_eq!(
            state.repair(&gap, full, unused(), None, 900),
            GapRepair::Present,
            "an unexpired Add leaf holds the sibling"
        );
        state.retain_claim(Claim::decode(CLAIM, 1_100, 1_100).unwrap().unwrap());
        assert_eq!(
            state.repair(&gap, full, unused(), None, 1_100),
            GapRepair::Waiting,
            "no activity since the expiry"
        );
        assert_eq!(
            state.repair(&gap, full, unused(), Some(1_050), 1_100),
            GapRepair::Waiting,
            "the first activity since starts the hour"
        );
        assert_eq!(
            state.lower_claim_until(&gap, &[0x33; 32], 1_100),
            Some(1_700),
            "waiting keeps a lower claimant's claim"
        );
        assert_eq!(
            state.repair(&gap, full, unused(), Some(4_649), 4_700),
            GapRepair::Waiting
        );
        assert_eq!(
            state.repair(&gap, full, unused(), Some(4_650), 4_700),
            GapRepair::Retire(vec![vec![7; 32]])
        );
        assert_eq!(
            state.repair(
                &gap,
                Some(SiblingAddRefusal::ChatRelays),
                unused(),
                Some(4_650),
                4_700
            ),
            GapRepair::Present,
            "a chat taking no sibling Add retires nothing"
        );
        assert_eq!(
            state.repair(&gap, full, Vec::new(), None, 4_700),
            GapRepair::Present
        );
        assert_eq!(
            state.repair(&gap, None, Vec::new(), None, 4_700),
            GapRepair::Add
        );

        state.retain_claim(Claim::decode(CLAIM, 4_700, 4_700).unwrap().unwrap());
        let updated = vec![OwnDeviceLeaf {
            signature_key: vec![7; 32],
            add_not_after: None,
        }];
        assert_eq!(
            state.repair(&gap, None, updated, Some(4_650), 4_700),
            GapRepair::Present
        );
        assert_eq!(state.lower_claim_until(&gap, &[0x33; 32], 4_700), None);
    }
}
