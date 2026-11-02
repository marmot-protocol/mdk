//! Best-effort sibling membership repair (mdk#2628 3.5e, D82–D84).
//!
//! Claims suppress competing attempts for ten minutes; they never authorize
//! membership. They are intentionally local transient state. The selected
//! tree is checked again by the engine when an Add actually stages.

use std::collections::{BTreeMap, HashMap, HashSet};

use cgka_traits::app_components::{DeviceSlotId, DeviceStatusV1, DeviceTagClaim};
use cgka_traits::engine::{GroupEvent, SiblingKeyPackage};
use cgka_traits::{EpochId, EpochPin, GroupId};
use serde::{Deserialize, Serialize};

use super::AppClient;
use super::device_group::Exchange;
use crate::{AppError, unix_now_seconds};

const TARGET: &str = "marmot_app::client::sibling_chat_gaps";
pub(crate) const KIND_GAP_FILL_CLAIM: u64 = 458;
const CLAIM_LIFETIME_SECS: u64 = 600;
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

/// Only changed or due chats are examined. Application traffic at an
/// unchanged device-group tip never reloads every chat's MLS tree.
#[derive(Default)]
pub(crate) struct SiblingChatGaps {
    roster_tip: Option<(GroupId, EpochPin)>,
    due: HashMap<GroupId, u64>,
    claims: HashMap<Gap, BTreeMap<DeviceSlotId, u64>>,
    waiting_for_stock: HashSet<Gap>,
}

impl SiblingChatGaps {
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

    fn lower_claim_until(&self, gap: &Gap, own: &DeviceSlotId) -> Option<u64> {
        self.claims
            .get(gap)?
            .iter()
            .find_map(|(slot, expiry)| (slot < own).then_some(*expiry))
    }
}

impl AppClient {
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
            | GroupEvent::LocalGroupCopyRestored { group_id } => group_id,
            _ => return,
        };
        self.sibling_chat_gaps.schedule(group.clone(), 0);
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

    fn gap_siblings(&self, exchange: &Exchange) -> Result<Vec<DeviceSlotId>, AppError> {
        let excluded = self.excluded_sibling_slots(exchange)?;
        Ok(exchange
            .roster
            .devices
            .iter()
            .filter_map(|(slot, entry)| {
                (*slot != exchange.own_slot
                    && !excluded.contains(slot)
                    && matches!(
                        entry.status,
                        DeviceStatusV1::Active | DeviceStatusV1::Inactive
                    )
                    && entry.settings.add_to_all_chats
                    && entry.tag_signature_key.is_some())
                .then_some(*slot)
            })
            .collect())
    }

    fn gap_is_missing(
        &self,
        exchange: &Exchange,
        chat: &GroupId,
        slot: DeviceSlotId,
    ) -> Result<bool, AppError> {
        if self.runtime.chat_sibling_add_refusal(chat)?.is_some() {
            return Ok(false);
        }
        let key = exchange
            .roster
            .devices
            .get(&slot)
            .and_then(|entry| entry.tag_signature_key.as_deref());
        Ok(!self
            .runtime
            .own_account_leaf_claims(chat, &exchange.roster)?
            .into_iter()
            .any(|(held, claim)| {
                claim == DeviceTagClaim::Device(slot) || key == Some(held.as_slice())
            }))
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
            || !exchange.roster.devices.contains_key(&claim.from)
            || !self.gap_siblings(&exchange)?.contains(&claim.to)
            || !self.sibling_commit_chats().contains(&claim.chat)
        {
            return Ok(());
        }
        self.ensure_sent_by(group, &exchange.roster, sender, &claim.from)?;
        self.sibling_chat_gaps.retain_claim(claim);
        Ok(())
    }

    pub(crate) async fn fill_sibling_chat_gaps(&mut self, held: &[GroupId], budget: usize) {
        if budget == 0 || !self.app.device_groups_enabled() || self.runtime.maintenance_is_paused()
        {
            return;
        }
        if let Err(error) = self.try_fill_sibling_chat_gaps(held, budget).await {
            tracing::warn!(target: TARGET, method = "fill_sibling_chat_gaps", error_kind = error.privacy_safe_kind(), "could not fill sibling chat gaps");
        }
    }

    async fn try_fill_sibling_chat_gaps(
        &mut self,
        held: &[GroupId],
        mut budget: usize,
    ) -> Result<(), AppError> {
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        if held.contains(&exchange.group_id)
            || !exchange.tagged
            || !self.group_quiet(&exchange.group_id)?
        {
            return Ok(());
        }
        let now = unix_now_seconds();
        self.sibling_chat_gaps.expire(now);
        let tip = (exchange.group_id.clone(), exchange.pin);
        if self.sibling_chat_gaps.roster_tip.as_ref() != Some(&tip) {
            if self
                .sibling_chat_gaps
                .roster_tip
                .as_ref()
                .is_some_and(|(group, _)| *group != exchange.group_id)
            {
                self.sibling_chat_gaps.claims.clear();
                self.sibling_chat_gaps.waiting_for_stock.clear();
            }
            self.sibling_chat_gaps.roster_tip = Some(tip);
            for chat in self.sibling_commit_chats() {
                self.sibling_chat_gaps.schedule(chat, 0);
            }
        }
        let siblings = self.gap_siblings(&exchange)?;
        if self.sibling_chat_gaps.due.values().all(|at| *at > now) {
            return Ok(());
        }
        let known: HashSet<_> = self.sibling_commit_chats().into_iter().collect();
        self.sibling_chat_gaps
            .claims
            .retain(|(chat, target), claims| {
                claims.retain(|slot, _| exchange.roster.devices.contains_key(slot));
                known.contains(chat) && siblings.contains(target) && !claims.is_empty()
            });
        self.sibling_chat_gaps
            .waiting_for_stock
            .retain(|(chat, target)| known.contains(chat) && siblings.contains(target));
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
        let mut first_error = None;
        for chat in due {
            self.sibling_chat_gaps.due.remove(&chat);
            let result = self
                .fill_one_chat_gap(&exchange, &chat, &siblings, &mut budget)
                .await;
            if let Err(error) = result {
                self.sibling_chat_gaps.schedule(chat, 0);
                first_error.get_or_insert(error);
            }
        }
        let mut needed = HashMap::<DeviceSlotId, u32>::new();
        for (_, slot) in &self.sibling_chat_gaps.waiting_for_stock {
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
    ) -> Result<(), AppError> {
        if !self.group_quiet(chat)? {
            self.sibling_chat_gaps.schedule(chat.clone(), 0);
            return Ok(());
        }
        for slot in siblings {
            let gap = (chat.clone(), *slot);
            if !self.gap_is_missing(exchange, chat, *slot)? {
                self.sibling_chat_gaps.claims.remove(&gap);
                self.sibling_chat_gaps.waiting_for_stock.remove(&gap);
                continue;
            }
            if *budget == 0 {
                self.sibling_chat_gaps.schedule(chat.clone(), 0);
                break;
            }
            if let Some(expiry) = self
                .sibling_chat_gaps
                .lower_claim_until(&gap, &exchange.own_slot)
            {
                self.sibling_chat_gaps.schedule(chat.clone(), expiry);
                continue;
            }
            let Some(key_package) = self.next_private_key_package(slot)? else {
                self.sibling_chat_gaps.waiting_for_stock.insert(gap);
                continue;
            };
            if let Some(refusal) = self.runtime.sibling_add_refusal(
                chat,
                &SiblingKeyPackage {
                    slot: *slot,
                    key_package,
                },
            )? {
                if refusal == cgka_traits::error::SiblingAddRefusal::KeyPackage {
                    self.sibling_chat_gaps.waiting_for_stock.insert(gap);
                }
                continue;
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
            if let Some(until) = self
                .sibling_chat_gaps
                .lower_claim_until(&gap, &exchange.own_slot)
            {
                self.sibling_chat_gaps.schedule(chat.clone(), until);
                continue;
            }
            let Some(current) = self.device_group_exchange()? else {
                continue;
            };
            if current.group_id != exchange.group_id
                || !current.tagged
                || !self.group_quiet(&current.group_id)?
                || !self.gap_siblings(&current)?.contains(slot)
                || !self.group_quiet(chat)?
                || !self.gap_is_missing(&current, chat, *slot)?
            {
                continue;
            }
            // Sending the claim may have advanced local effects. Validate
            // the stock selected now, immediately before the existing take.
            let Some(key_package) = self.next_private_key_package(slot)? else {
                self.sibling_chat_gaps.waiting_for_stock.insert(gap);
                continue;
            };
            if self
                .runtime
                .sibling_add_refusal(
                    chat,
                    &SiblingKeyPackage {
                        slot: *slot,
                        key_package,
                    },
                )?
                .is_some()
            {
                self.sibling_chat_gaps.waiting_for_stock.insert(gap);
                continue;
            }
            *budget -= 1;
            self.add_sibling_to_chat(chat, slot).await?;
            self.sibling_chat_gaps
                .waiting_for_stock
                .remove(&(chat.clone(), *slot));
        }
        Ok(())
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
        assert!(Claim::decode(&other_order, 100, 200).unwrap().is_some());
        for malformed in [
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
        assert_eq!(state.lower_claim_until(&gap, &[0x33; 32]), Some(700));
        assert_eq!(state.lower_claim_until(&gap, &[0x01; 32]), None);
        state.retain_claim(Claim::decode(CLAIM, 100, 699).unwrap().unwrap());
        assert_eq!(state.lower_claim_until(&gap, &[0x33; 32]), Some(700));
        state.expire(700);
        assert_eq!(state.lower_claim_until(&gap, &[0x33; 32]), None);
        assert!(Claim::decode(CLAIM, 100, 700).unwrap().is_none());
        assert!(Claim::decode(CLAIM, 201, 200).unwrap().is_none());
        assert!(Claim::decode(CLAIM, u64::MAX, u64::MAX).unwrap().is_none());
    }
}
