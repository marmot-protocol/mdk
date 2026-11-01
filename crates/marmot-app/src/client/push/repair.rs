//! Repair replies to kind 447 announces and requests (mdk#2611;
//! push-notifications spec: "Repair"). A member that receives an announce
//! works out what the announcer lacks, and if its leaf ranks in the top three
//! for that announce, it sends those records and tombstones in kind 448 and
//! 449 lists after waiting its rank's slots, unless entries other members
//! carried meanwhile already cover them. A request counts as an announce
//! whose `have` is empty.
//!
//! This state lives in memory. A reply lost to a restart waits for the
//! announcer's next announce, which draws a new ranking.

use std::collections::{HashMap, HashSet};

use cgka_traits::GroupId;
use sha2::{Digest, Sha256};

use super::PushGossipGate;
use crate::AppError;
use crate::client::AppClient;
use crate::messages::AppMessageIntent;
use crate::notifications::{self, PushHave, PushPlatform};

/// How many ranked leaves reply to one announce.
const PUSH_REPAIR_RESPONDERS: usize = 3;

/// The least time between two repair replies this device sends to one
/// announcer's leaf in one group.
const PUSH_REPAIR_RATE_LIMIT_MS: i64 = 24 * 60 * 60 * 1_000;

/// A record key: member, leaf, platform and server.
type PushRecordKey = (String, u32, PushPlatform, String);

/// An ordering stamp: `owner_ts`, then the record digest as lowercase hex.
type PushStamp = (i64, String);

/// One announcer's leaf in one group.
type PushRepairPeer = (GroupId, u32);

/// The repair work this device has with each announcer's leaf, and when it
/// last replied to each.
#[derive(Debug, Default)]
pub(crate) struct PushRepairs {
    asks: HashMap<PushRepairPeer, PushRepairAsk>,
    replied_at_ms: HashMap<PushRepairPeer, i64>,
}

/// The latest announce or request one leaf sent in a group, for which this
/// device's leaf ranks in the top three, from receipt until this device
/// replies to it or finds it owes none.
#[derive(Debug)]
struct PushRepairAsk {
    /// This device's leaf's rank for the announce.
    rank: usize,
    /// The epoch of the group message that carried it.
    epoch: u64,
    have: PushHave,
    /// For each record key, the highest stamp among the kind 448 and 449
    /// entries this device processed since, carried in `epoch` or later.
    covered: HashMap<PushRecordKey, PushStamp>,
    /// Set once this device decided to reply.
    reply: Option<PushRepairReply>,
}

/// A reply waiting for its rank's slots: when it is due, and what the
/// announcer lacked when this device decided.
#[derive(Debug)]
struct PushRepairReply {
    due_at_ms: i64,
    lacking: HashMap<PushRecordKey, PushStamp>,
}

impl PushRepairAsk {
    /// Whether an entry this device processed since the announce covers the
    /// item `key` at `stamp`.
    fn covers(&self, key: &PushRecordKey, stamp: &PushStamp) -> bool {
        self.covered
            .get(key)
            .is_some_and(|covered| covered >= stamp)
    }

    fn lacks(&self, digest_hex: &str) -> bool {
        notifications::push_have_prefix(digest_hex)
            .is_some_and(|prefix| !self.have.contains(&prefix))
    }
}

impl PushRepairs {
    /// Forget the repair work and rate limits of `group_id`.
    pub(crate) fn forget_group(&mut self, group_id: &GroupId) {
        self.asks.retain(|(group, _), _| group != group_id);
        self.replied_at_ms.retain(|(group, _), _| group != group_id);
    }

    /// Forget the repair work and rate limit of each of `leaves`, which left
    /// `group_id`: a member that later takes the same leaf is another
    /// announcer.
    pub(crate) fn forget_leaves(&mut self, group_id: &GroupId, leaves: &[u32]) {
        for leaf in leaves {
            let peer = (group_id.clone(), *leaf);
            self.asks.remove(&peer);
            self.replied_at_ms.remove(&peer);
        }
    }

    fn rate_limited(&self, peer: &PushRepairPeer, now_ms: i64) -> bool {
        self.replied_at_ms
            .get(peer)
            .is_some_and(|replied| now_ms.saturating_sub(*replied) < PUSH_REPAIR_RATE_LIMIT_MS)
    }
}

#[cfg(all(test, feature = "test-policy-overrides"))]
impl PushRepairs {
    /// Every reply this device decided on is due now.
    pub(crate) fn test_make_replies_due(&mut self) {
        for reply in self.asks.values_mut().filter_map(|ask| ask.reply.as_mut()) {
            reply.due_at_ms = i64::MIN;
        }
    }

    /// Every reply this device sent was sent a rate limit earlier.
    pub(crate) fn test_age_replies_past_rate_limit(&mut self) {
        for replied_at_ms in self.replied_at_ms.values_mut() {
            *replied_at_ms = replied_at_ms.saturating_sub(PUSH_REPAIR_RATE_LIMIT_MS);
        }
    }
}

/// The relayable entries `group_id_hex` holds: each record whose stored
/// digest its fields reproduce, and each tombstone that kept its
/// owner-signed removal, by record key, with its stamp.
struct PushRelayable {
    records: Vec<(
        PushRecordKey,
        PushStamp,
        notifications::StoredGroupPushToken,
    )>,
    tombstones: Vec<(
        PushRecordKey,
        PushStamp,
        notifications::StoredPushTokenTombstone,
    )>,
}

impl PushRelayable {
    fn entries(&self) -> impl Iterator<Item = (&PushRecordKey, &PushStamp)> {
        self.records
            .iter()
            .map(|(key, stamp, _)| (key, stamp))
            .chain(self.tombstones.iter().map(|(key, stamp, _)| (key, stamp)))
    }
}

/// The rank of `own_leaf` among `leaves` for the announce `announce_id`:
/// every leaf but `announcer_leaf` sorted by
/// `SHA-256(announce_id || leaf_index as a big-endian u32)`. `None` when
/// `own_leaf` is not among them.
fn push_repair_rank(
    announce_id: &[u8; 32],
    leaves: impl IntoIterator<Item = u32>,
    announcer_leaf: u32,
    own_leaf: u32,
) -> Option<usize> {
    let mut ranked = leaves
        .into_iter()
        .filter(|leaf| *leaf != announcer_leaf)
        .collect::<HashSet<_>>()
        .into_iter()
        .map(|leaf| {
            let mut hasher = Sha256::new();
            hasher.update(announce_id);
            hasher.update(leaf.to_be_bytes());
            (<[u8; 32]>::from(hasher.finalize()), leaf)
        })
        .collect::<Vec<_>>();
    ranked.sort_unstable();
    ranked.iter().position(|(_, leaf)| *leaf == own_leaf)
}

impl AppClient {
    /// Note what `message`, if it is a kind 447 announce or request whose
    /// entries this device applied against the group's `leaves`, asks of this
    /// device. `sender_leaf` is the MLS leaf that sent it: without it this
    /// device cannot rank, so it does not reply.
    pub(crate) fn note_received_push_repair_ask(
        &mut self,
        message: &crate::ReceivedMessage,
        sender_leaf: Option<u32>,
        leaves: &[cgka_traits::engine::GroupMemberLeaf],
    ) {
        if message.kind != notifications::MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE {
            return;
        }
        let Some(have) = notifications::parse_push_repair_ask(&message.plaintext) else {
            return;
        };
        let Some(announcer_leaf) = sender_leaf else {
            tracing::debug!(
                target: "marmot_app::notifications",
                method = "note_received_push_repair_ask",
                "push repair ask has no sender leaf; no reply",
            );
            return;
        };
        self.note_push_repair_ask(
            &message.group_id,
            &message.message_id_hex,
            message.source_epoch,
            announcer_leaf,
            leaves.iter().map(|leaf| leaf.leaf_index),
            have,
        );
    }

    /// The 447 `announce_id_hex` that `announcer_leaf` sent in `group_id` at
    /// `epoch` asks for what `have` lacks. It replaces any earlier ask of that
    /// leaf there. When this device's leaf ranks in the top three among
    /// `leaves`, it decides once it has processed what it was catching up on.
    pub(crate) fn note_push_repair_ask(
        &mut self,
        group_id: &GroupId,
        announce_id_hex: &str,
        epoch: u64,
        announcer_leaf: u32,
        leaves: impl IntoIterator<Item = u32>,
        have: PushHave,
    ) {
        let peer = (group_id.clone(), announcer_leaf);
        self.push_repairs.asks.remove(&peer);
        let Some(announce_id) = hex::decode(announce_id_hex)
            .ok()
            .and_then(|id| <[u8; 32]>::try_from(id).ok())
        else {
            return;
        };
        let own_leaf = match self.runtime.own_leaf_index(group_id) {
            Ok(own_leaf) => own_leaf,
            Err(error) => {
                tracing::debug!(
                    target: "marmot_app::notifications",
                    method = "note_push_repair_ask",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "own leaf unavailable; no push repair reply",
                );
                return;
            }
        };
        let Some(rank) = push_repair_rank(&announce_id, leaves, announcer_leaf, own_leaf)
            .filter(|rank| *rank < PUSH_REPAIR_RESPONDERS)
        else {
            return;
        };
        self.push_repairs.asks.insert(
            peer,
            PushRepairAsk {
                rank,
                epoch,
                have,
                covered: HashMap::new(),
                reply: None,
            },
        );
        self.push_registration_share_queued = true;
    }

    /// Note the verified entries of a kind 448 or 449 carried in `group_id`
    /// at `epoch`: each covers, in every ask there from `epoch` or earlier,
    /// the items with its record key and a stamp no greater than its own.
    pub(crate) fn note_push_repair_cover(
        &mut self,
        group_id: &GroupId,
        epoch: u64,
        action: &notifications::PushGossipAction,
    ) {
        if !self
            .push_repairs
            .asks
            .iter()
            .any(|((group, _), ask)| group == group_id && ask.epoch <= epoch)
        {
            return;
        }
        let group_id_hex = hex::encode(group_id.as_slice());
        let entries = match action {
            notifications::PushGossipAction::Upsert(records) => records
                .iter()
                .filter_map(|record| {
                    let digest = record.record_digest().ok()?;
                    Some((
                        (
                            record.member_id_hex.clone(),
                            record.leaf_index,
                            record.platform,
                            record.server_pubkey_hex.clone(),
                        ),
                        (record.owner_ts, digest),
                    ))
                })
                .collect::<Vec<_>>(),
            notifications::PushGossipAction::Remove(removals) => removals
                .iter()
                .filter_map(|removal| {
                    let digest = removal.record_digest(&group_id_hex).ok()?;
                    Some((
                        (
                            removal.member_id_hex.clone(),
                            removal.leaf_index,
                            removal.platform,
                            removal.server_pubkey_hex.clone(),
                        ),
                        (removal.owner_ts, digest),
                    ))
                })
                .collect(),
        };
        for ((group, _), ask) in &mut self.push_repairs.asks {
            if group != group_id || ask.epoch > epoch {
                continue;
            }
            for (key, stamp) in &entries {
                let covered = ask
                    .covered
                    .entry(key.clone())
                    .or_insert_with(|| stamp.clone());
                if *covered < *stamp {
                    *covered = stamp.clone();
                }
            }
        }
    }

    /// `leaves` left `group_id`.
    pub(crate) fn forget_push_repair_leaves(&mut self, group_id: &GroupId, leaves: &[u32]) {
        self.push_repairs.forget_leaves(group_id, leaves);
    }

    /// Whether repair work is due in a group whose state does not hold it
    /// back: an ask to decide once this device has processed what it was
    /// catching up on, or a reply whose slots have passed.
    pub(crate) fn has_due_push_repair(&self) -> bool {
        let settled = self
            .push_fetch_clock
            .settled(self.push_announce_timing.catch_up_settle);
        let now_ms = notifications::unix_now_ms();
        self.push_repairs.asks.iter().any(|((group_id, _), ask)| {
            let due = match &ask.reply {
                None => settled,
                Some(reply) => reply.due_at_ms <= now_ms,
            };
            due && !matches!(
                self.push_gossip_gate(&hex::encode(group_id.as_slice()), None),
                PushGossipGate::NotYet
            )
        })
    }

    /// Decide every ask received since this device last could, then send
    /// every reply whose slots have passed. Returns whether a reply that
    /// could be sent failed and remains owed.
    ///
    /// Asks wait until this client has watched the device able to fetch for
    /// the settle time, so a device catching up decides only once it has
    /// processed the backlog, and replies others already sent can cancel its
    /// own. Its slots count from then.
    pub(crate) async fn send_due_push_repairs(&mut self) -> bool {
        if self.push_repairs.asks.is_empty() {
            return false;
        }
        if self
            .push_fetch_clock
            .settled(self.push_announce_timing.catch_up_settle)
        {
            self.decide_push_repairs();
        }
        let now_ms = notifications::unix_now_ms();
        let due = self
            .push_repairs
            .asks
            .iter()
            .filter(|(_, ask)| {
                ask.reply
                    .as_ref()
                    .is_some_and(|reply| reply.due_at_ms <= now_ms)
            })
            .map(|(peer, _)| peer.clone())
            .collect::<Vec<_>>();
        let mut pending = false;
        for peer in due {
            pending |= self.send_push_repair(&peer).await;
        }
        pending
    }

    /// Decide whether to reply to each undecided ask whose group can take
    /// gossip now; drop it when not.
    fn decide_push_repairs(&mut self) {
        let undecided = self
            .push_repairs
            .asks
            .iter()
            .filter(|(_, ask)| ask.reply.is_none())
            .map(|(peer, _)| peer.clone())
            .collect::<Vec<_>>();
        let mut replies = 0_u64;
        let mut dropped = 0_u64;
        for peer in undecided {
            let group_id_hex = hex::encode(peer.0.as_slice());
            match self.push_gossip_gate(&group_id_hex, None) {
                PushGossipGate::NotYet => continue,
                PushGossipGate::Void => {
                    self.push_repairs.asks.remove(&peer);
                    dropped += 1;
                    continue;
                }
                PushGossipGate::Due => {}
            }
            match self.push_repair_decision(&peer) {
                Ok(Some(reply)) => {
                    if let Some(ask) = self.push_repairs.asks.get_mut(&peer) {
                        ask.reply = Some(reply);
                        replies += 1;
                    }
                }
                Ok(None) => {
                    self.push_repairs.asks.remove(&peer);
                    dropped += 1;
                }
                Err(error) => {
                    // The next announce of that leaf draws a new ranking.
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "decide_push_repairs",
                        error_kind = error.privacy_safe_kind(),
                        "push repair decision failed",
                    );
                    self.push_repairs.asks.remove(&peer);
                    dropped += 1;
                }
            }
        }
        if replies + dropped > 0 {
            tracing::debug!(
                target: "marmot_app::notifications",
                method = "decide_push_repairs",
                replies,
                dropped,
                "push repair asks decided",
            );
        }
    }

    /// The reply this device owes `peer`'s ask, or `None`: the announcer's
    /// leaf has left, this device replied to it within the rate limit, or the
    /// announcer lacks nothing it can relay.
    fn push_repair_decision(
        &self,
        peer: &PushRepairPeer,
    ) -> Result<Option<PushRepairReply>, AppError> {
        let (group_id, announcer_leaf) = peer;
        let Some(ask) = self.push_repairs.asks.get(peer) else {
            return Ok(None);
        };
        let now_ms = notifications::unix_now_ms();
        if self.push_repairs.rate_limited(peer, now_ms) {
            return Ok(None);
        }
        let membership = self.runtime.canonical_group_membership(group_id)?;
        if !membership
            .member_leaves
            .iter()
            .any(|leaf| leaf.leaf_index == *announcer_leaf)
        {
            return Ok(None);
        }
        let relayable = self.relayable_push_entries(group_id)?;
        let lacking = relayable
            .entries()
            .filter(|(key, stamp)| ask.lacks(&stamp.1) && !ask.covers(key, stamp))
            .map(|(key, stamp)| (key.clone(), stamp.clone()))
            .collect::<HashMap<_, _>>();
        if lacking.is_empty() {
            return Ok(None);
        }
        let slot =
            i64::try_from(self.push_announce_timing.repair_slot.as_millis()).unwrap_or(i64::MAX);
        let rank = i64::try_from(ask.rank).unwrap_or(i64::MAX);
        Ok(Some(PushRepairReply {
            due_at_ms: now_ms.saturating_add(slot.saturating_mul(rank)),
            lacking,
        }))
    }

    /// Send `peer` the reply this device decided on, less what entries
    /// processed since cover: for each item, what this device now holds for
    /// its record key, when that is as new as the item and the announcer
    /// lacks it. Returns whether the reply failed and remains owed.
    async fn send_push_repair(&mut self, peer: &PushRepairPeer) -> bool {
        let group_id = &peer.0;
        let group_id_hex = hex::encode(group_id.as_slice());
        match self.push_gossip_gate(&group_id_hex, None) {
            PushGossipGate::NotYet => return false,
            PushGossipGate::Void => {
                self.push_repairs.asks.remove(peer);
                return false;
            }
            PushGossipGate::Due => {}
        }
        let now_ms = notifications::unix_now_ms();
        if self.push_repairs.rate_limited(peer, now_ms) {
            self.push_repairs.asks.remove(peer);
            return false;
        }
        let lists = match self.push_repair_lists(peer) {
            Ok(Some(lists)) => lists,
            Ok(None) => {
                self.push_repairs.asks.remove(peer);
                tracing::debug!(
                    target: "marmot_app::notifications",
                    method = "send_push_repair",
                    "push repair reply cancelled: entries others sent cover it",
                );
                return false;
            }
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "send_push_repair",
                    error_kind = error.privacy_safe_kind(),
                    "push repair reply preparation failed",
                );
                self.push_repairs.asks.remove(peer);
                return false;
            }
        };
        let token_lists = lists.token_lists.len();
        let removal_lists = lists.removal_lists.len();
        let intents = lists
            .token_lists
            .into_iter()
            .map(|content| AppMessageIntent::PushTokenList { content })
            .chain(
                lists
                    .removal_lists
                    .into_iter()
                    .map(|content| AppMessageIntent::PushTokenRemoval { content }),
            )
            .collect::<Vec<_>>();
        for intent in intents {
            match self.send_app_event(group_id, intent).await {
                Ok(_) => {}
                // The group's state changed since it was checked; its next
                // announce draws a new ranking.
                Err(
                    AppError::GroupRemoved(_)
                    | AppError::GroupDisbanding(_)
                    | AppError::UserBlocked,
                ) => {
                    self.push_repairs.asks.remove(peer);
                    return false;
                }
                Err(error) => {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "send_push_repair",
                        error_kind = error.privacy_safe_kind(),
                        "push repair reply remains owed",
                    );
                    return true;
                }
            }
        }
        self.push_repairs.asks.remove(peer);
        self.push_repairs
            .replied_at_ms
            .insert(peer.clone(), notifications::unix_now_ms());
        tracing::debug!(
            target: "marmot_app::notifications",
            method = "send_push_repair",
            token_lists,
            removal_lists,
            "push repair reply sent",
        );
        false
    }

    /// The lists of `peer`'s reply, or `None` when nothing is left to send.
    fn push_repair_lists(
        &self,
        peer: &PushRepairPeer,
    ) -> Result<Option<notifications::PushGossipLists>, AppError> {
        let Some(ask) = self.push_repairs.asks.get(peer) else {
            return Ok(None);
        };
        let Some(reply) = &ask.reply else {
            return Ok(None);
        };
        // Each item is sent as this device now holds it, unless entries
        // others sent since cover what it holds: a cover of the item as
        // decided does not cover a newer entry for its key.
        let wanted = |key: &PushRecordKey, stamp: &PushStamp| {
            reply
                .lacking
                .get(key)
                .is_some_and(|item| stamp >= item && !ask.covers(key, stamp) && ask.lacks(&stamp.1))
        };
        let relayable = self.relayable_push_entries(&peer.0)?;
        let tokens = relayable
            .records
            .into_iter()
            .filter(|(key, stamp, _)| wanted(key, stamp))
            .map(|(_, _, stored)| stored)
            .collect::<Vec<_>>();
        let tombstones = relayable
            .tombstones
            .into_iter()
            .filter(|(key, stamp, _)| wanted(key, stamp))
            .map(|(_, _, tombstone)| tombstone)
            .collect::<Vec<_>>();
        if tokens.is_empty() && tombstones.is_empty() {
            return Ok(None);
        }
        let sender_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let lists = notifications::push_gossip_lists(
            &tokens,
            &tombstones,
            &sender_hex,
            peer.0.as_slice().len(),
        )?;
        if lists.token_lists.is_empty() && lists.removal_lists.is_empty() {
            return Ok(None);
        }
        Ok(Some(lists))
    }

    /// Every entry this device holds in `group_id` and can relay.
    fn relayable_push_entries(&self, group_id: &GroupId) -> Result<PushRelayable, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let records = self
            .app
            .stored_group_push_tokens(&self.state.label, &group_id_hex)?
            .into_iter()
            .filter_map(|stored| {
                let digest = stored.record_digest.clone()?;
                let record = &stored.record;
                Some((
                    (
                        record.member_id_hex.clone(),
                        record.leaf_index,
                        record.platform,
                        record.server_pubkey_hex.clone(),
                    ),
                    (record.owner_ts, digest),
                    stored,
                ))
            })
            .collect();
        let tombstones = self
            .app
            .group_push_token_tombstones(&self.state.label, &group_id_hex)?
            .into_iter()
            .filter_map(|tombstone| {
                let removal = tombstone.removal.as_ref()?;
                Some((
                    (
                        removal.member_id_hex.clone(),
                        removal.leaf_index,
                        removal.platform,
                        removal.server_pubkey_hex.clone(),
                    ),
                    (removal.owner_ts, tombstone.record_digest.clone()),
                    tombstone,
                ))
            })
            .collect();
        Ok(PushRelayable {
            records,
            tombstones,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ranks follow the rank key, skip the announcer's leaf, and belong to
    /// leaves, not to their order in the roster.
    #[test]
    fn repair_ranks_follow_the_rank_key_and_skip_the_announcer() {
        let announce_id = [7_u8; 32];
        let key = |leaf: u32| {
            let mut hasher = Sha256::new();
            hasher.update(announce_id);
            hasher.update(leaf.to_be_bytes());
            <[u8; 32]>::from(hasher.finalize())
        };
        let leaves = [0_u32, 1, 2, 3, 5, 8];
        let mut expected = leaves
            .iter()
            .filter(|leaf| **leaf != 2)
            .map(|leaf| (key(*leaf), *leaf))
            .collect::<Vec<_>>();
        expected.sort();
        for (rank, (_, leaf)) in expected.iter().enumerate() {
            assert_eq!(push_repair_rank(&announce_id, leaves, 2, *leaf), Some(rank));
            let mut reversed = leaves;
            reversed.reverse();
            assert_eq!(
                push_repair_rank(&announce_id, reversed, 2, *leaf),
                Some(rank),
                "roster order does not matter"
            );
        }
        assert_eq!(push_repair_rank(&announce_id, leaves, 2, 2), None);
        assert_eq!(push_repair_rank(&announce_id, leaves, 2, 4), None);
    }
}
