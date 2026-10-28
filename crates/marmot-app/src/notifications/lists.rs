//! Kind 448 token lists and kind 449 removal lists that relay stored entries
//! unchanged, split so each carrying group message fits the size budget, and
//! the kind 447 announce whose `have` lists what this device holds
//! (push-notifications spec: "List response", "Removal", "Request, update,
//! and announce (kind 447)", "Event size").

use std::collections::HashSet;

use serde::Serialize;

use super::{
    GroupPushTokenRecord, PUSH_MAX_GOSSIP_ENTRIES, PUSH_MAX_HAVE_ENTRIES, PUSH_VERSION,
    PushPlatform, PushTokenAnnouncePayload, PushTokenGossipEntry, PushTokenGossipPayload,
    PushTokenRemovalEntry, PushTokenRemovalPayload, StoredGroupPushToken, StoredPushTokenTombstone,
    push_have_element,
};
use crate::AppError;
use crate::messages::{AppMessageIntent, build_inner_event, encode_inner_event};

/// Size limit for each carrying group message, as published, when the group's
/// delivery endpoints advertise no larger one.
pub(crate) const PUSH_GOSSIP_EVENT_MAX_BYTES: usize = 65_536;

/// The app-event contents of a push snapshot, in send order, and what it left
/// out.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PushGossipLists {
    /// Kind 448 contents.
    pub token_lists: Vec<String>,
    /// Kind 449 contents.
    pub removal_lists: Vec<String>,
    /// Records left out because their stored digest is not the one their fields
    /// produce.
    pub unverified_records: usize,
    /// Tombstones left out because they kept no owner-signed removal.
    pub unsigned_tombstones: usize,
    /// Entries left out because one alone does not fit a group message.
    pub oversized_entries: usize,
}

/// List every record and tombstone in `tokens` and `tombstones` that this
/// device can relay, as `sender_hex` sends them in a group whose MLS group id
/// is `group_id_len` bytes. Entries keep their storage order and their owner's
/// `owner_ts` and `owner_sig`.
///
/// A record whose stored digest its fields do not reproduce is left out: the
/// stamp it is ordered by does not describe it, so this device cannot vouch
/// for it, and its owner and other holders still relay it. A tombstone that
/// kept no owner-signed removal cannot be relayed at all.
pub(crate) fn push_gossip_lists(
    tokens: &[StoredGroupPushToken],
    tombstones: &[StoredPushTokenTombstone],
    sender_hex: &str,
    group_id_len: usize,
) -> Result<PushGossipLists, AppError> {
    let mut lists = PushGossipLists::default();
    let mut records = Vec::with_capacity(tokens.len());
    for stored in tokens {
        if stored.record_digest.is_some() {
            records.push(PushTokenGossipEntry::from_record(&stored.record));
        } else {
            lists.unverified_records += 1;
        }
    }
    let mut removals = Vec::with_capacity(tombstones.len());
    for tombstone in tombstones {
        match &tombstone.removal {
            Some(removal) => removals.push(PushTokenRemovalEntry::from_record(removal)),
            None => lists.unsigned_tombstones += 1,
        }
    }
    let lister = Lister {
        sender_hex,
        group_id_len,
    };
    lists.token_lists = lister.split(
        records,
        |tokens| PushTokenGossipPayload {
            v: PUSH_VERSION.to_owned(),
            tokens,
        },
        |content| AppMessageIntent::PushTokenList { content },
        &mut lists.oversized_entries,
    )?;
    lists.removal_lists = lister.split(
        removals,
        |removals| PushTokenRemovalPayload {
            v: PUSH_VERSION.to_owned(),
            removals,
        },
        |content| AppMessageIntent::PushTokenRemoval { content },
        &mut lists.oversized_entries,
    )?;
    Ok(lists)
}

/// A kind 447 announce's content, and what its `have` left out.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PushAnnounce {
    pub content: String,
    /// Records and tombstones listed in `have`.
    pub listed: usize,
    /// Records and tombstones left out of `have` because more are held than
    /// fit its element limit or the size budget.
    pub unlisted: usize,
    /// Records left out of `have` because this device cannot name them: the
    /// stored digest is not the one their fields produce, or is malformed.
    pub unknown_digests: usize,
}

/// The announce `sender_hex` sends in a group whose MLS group id is
/// `group_id_len` bytes. `tokens` carries `own`, this device's current
/// records there. `have` names `own`, then the records in `held` and the
/// tombstones in `tombstones` that `own` does not replace, each once.
///
/// A held record whose stored digest its fields do not reproduce is left out,
/// as it is from a snapshot: this device cannot vouch for it. A tombstone that
/// kept no owner-signed removal is still named, since its digest is known.
/// When more are held than fit 4,096 elements or the size budget, `have`
/// names a prefix in that order, so this device's own records come first.
pub(crate) fn push_announce(
    own: &[GroupPushTokenRecord],
    held: &[StoredGroupPushToken],
    tombstones: &[StoredPushTokenTombstone],
    sender_hex: &str,
    group_id_len: usize,
) -> Result<PushAnnounce, AppError> {
    let own = &own[..own.len().min(PUSH_MAX_GOSSIP_ENTRIES)];
    let replaced =
        |member_id_hex: &str, leaf_index: u32, platform: PushPlatform, server_pubkey_hex: &str| {
            own.iter().any(|record| {
                record.member_id_hex == member_id_hex
                    && record.leaf_index == leaf_index
                    && record.platform == platform
                    && record.server_pubkey_hex == server_pubkey_hex
            })
        };
    let mut digests = Vec::with_capacity(own.len() + held.len() + tombstones.len());
    for record in own {
        digests.push(Some(record.record_digest()?));
    }
    for stored in held {
        let record = &stored.record;
        if !replaced(
            &record.member_id_hex,
            record.leaf_index,
            record.platform,
            &record.server_pubkey_hex,
        ) {
            digests.push(stored.record_digest.clone());
        }
    }
    for tombstone in tombstones {
        if !tombstone.removal.as_ref().is_some_and(|removal| {
            replaced(
                &removal.member_id_hex,
                removal.leaf_index,
                removal.platform,
                &removal.server_pubkey_hex,
            )
        }) {
            digests.push(Some(tombstone.record_digest.clone()));
        }
    }
    let mut unknown_digests = 0;
    let mut seen = HashSet::new();
    let mut elements = Vec::with_capacity(digests.len());
    for digest in digests {
        match digest.as_deref().and_then(push_have_element) {
            Some(element) if seen.insert(element.clone()) => elements.push(element),
            Some(_) => {}
            None => unknown_digests += 1,
        }
    }

    let lister = Lister {
        sender_hex,
        group_id_len,
    };
    let intent = |content| AppMessageIntent::PushTokenUpdate { content };
    let payload = |have| PushTokenAnnouncePayload {
        v: PUSH_VERSION.to_owned(),
        tokens: own.iter().map(PushTokenGossipEntry::from_record).collect(),
        have,
    };
    let max_inner = lister.max_inner_len();
    // As in `Lister::split`, each element adds its escaped length and a
    // separating comma.
    let mut len = lister.inner_len(&intent, String::new())?
        + escaped_len(&serde_json::to_string(&payload(Vec::new()))?)?;
    let mut listed = 0;
    for element in &elements {
        let cost = usize::from(listed > 0) + escaped_len(&serde_json::to_string(element)?)?;
        if listed == PUSH_MAX_HAVE_ENTRIES || len + cost > max_inner {
            break;
        }
        len += cost;
        listed += 1;
    }
    let unlisted = elements.len() - listed;
    elements.truncate(listed);
    let content = serde_json::to_string(&payload(elements))?;
    if lister.inner_len(&intent, content.clone())? > max_inner {
        return Err(AppError::InvalidPushGossip(
            "push announce exceeds the group message size".into(),
        ));
    }
    Ok(PushAnnounce {
        content,
        listed,
        unlisted,
        unknown_digests,
    })
}

struct Lister<'a> {
    sender_hex: &'a str,
    group_id_len: usize,
}

impl Lister<'_> {
    /// Pack `entries` in order into as few payloads as fit, at most 32 entries
    /// each. An entry that does not fit even alone is counted in `oversized`.
    ///
    /// JSON escapes character by character, so the escaped length of a payload
    /// is the escaped length of its empty form plus that of each entry and of
    /// each separating comma. Every payload is measured again whole before it
    /// is returned.
    fn split<E, P>(
        &self,
        entries: Vec<E>,
        payload: impl Fn(Vec<E>) -> P,
        intent: impl Fn(String) -> AppMessageIntent,
        oversized: &mut usize,
    ) -> Result<Vec<String>, AppError>
    where
        E: Serialize,
        P: Serialize,
    {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let fixed = self.inner_len(&intent, String::new())?
            + escaped_len(&serde_json::to_string(&payload(Vec::new()))?)?;
        let max_inner = self.max_inner_len();
        let mut chunks: Vec<Vec<E>> = Vec::new();
        let mut chunk = Vec::new();
        let mut chunk_len = fixed;
        for entry in entries {
            let cost = escaped_len(&serde_json::to_string(&entry)?)?;
            if fixed + cost > max_inner {
                *oversized += 1;
                continue;
            }
            let mut comma = usize::from(!chunk.is_empty());
            if chunk.len() == PUSH_MAX_GOSSIP_ENTRIES || chunk_len + comma + cost > max_inner {
                chunks.push(std::mem::take(&mut chunk));
                chunk_len = fixed;
                comma = 0;
            }
            chunk_len += comma + cost;
            chunk.push(entry);
        }
        if !chunk.is_empty() {
            chunks.push(chunk);
        }
        chunks
            .into_iter()
            .map(|chunk| {
                let content = serde_json::to_string(&payload(chunk))?;
                if self.inner_len(&intent, content.clone())? > max_inner {
                    return Err(AppError::InvalidPushGossip(
                        "push gossip list exceeds the group message size".into(),
                    ));
                }
                Ok(content)
            })
            .collect()
    }

    /// Length of the inner app event carrying `content`, with `created_at` as
    /// wide as a `u64` allows.
    fn inner_len(
        &self,
        intent: &impl Fn(String) -> AppMessageIntent,
        content: String,
    ) -> Result<usize, AppError> {
        let event = build_inner_event(&intent(content), self.sender_hex, u64::MAX)?;
        Ok(encode_inner_event(&event)?.len())
    }

    /// Largest inner app event whose published group message fits
    /// [`PUSH_GOSSIP_EVENT_MAX_BYTES`].
    fn max_inner_len(&self) -> usize {
        let fits = |inner_len| {
            transport_nostr_peeler::group_event_json_len_bound(
                marmot_session::application_message_len(self.group_id_len, inner_len),
            ) <= PUSH_GOSSIP_EVENT_MAX_BYTES
        };
        // Both lengths grow with the inner length, and base64 makes the
        // published event longer than the inner event.
        let (mut low, mut high) = (0, PUSH_GOSSIP_EVENT_MAX_BYTES);
        while low < high {
            let mid = (low + high).div_ceil(2);
            if fits(mid) { low = mid } else { high = mid - 1 }
        }
        low
    }
}

/// Length of `text` once escaped as a JSON string, without its quotes.
fn escaped_len(text: &str) -> Result<usize, AppError> {
    Ok(serde_json::to_string(text)?.len() - 2)
}

#[cfg(test)]
pub(crate) fn published_len_bound(group_id_len: usize, inner_len: usize) -> usize {
    transport_nostr_peeler::group_event_json_len_bound(marmot_session::application_message_len(
        group_id_len,
        inner_len,
    ))
}
