//! Tag signature keys device-group rosters listed (mdk#2761).
//!
//! Every roster state this device applies records each tag signature key it
//! lists for a slot, in a device entry or in a `removed` record, in the
//! transaction that applies it: a canonical apply records each commit it
//! merges or restores, an own Commit records when it is confirmed, and a
//! founding create and a Welcome join record the roster they start from. A
//! record outlives the branch that listed it, since a device whose key a
//! dropped branch listed may have tagged leaves in chats under it.
//!
//! The engine only writes them. No convergence input, snapshot or replay
//! fingerprint reads them, so group state and branch selection are what they
//! would be without them. The app reads them to clean up after a device the
//! roster no longer lists, whether a removal's record was dropped before this
//! device acted on it, a link failed, or a branch dropped a made link.

use std::collections::BTreeSet;

use cgka_traits::Timestamp;
use cgka_traits::app_components::RejectedSlotReasonV1;
use cgka_traits::storage::{
    ROSTER_TAG_KEY_RETENTION_SECS, ROSTER_TAG_KEYS_PER_SLOT, RosterTagKey, StorageError,
    StorageProvider,
};
use cgka_traits::types::GroupId;
use openmls::group::MlsGroup;

/// Every tag signature key `group`'s roster lists now, for a device or a
/// `removed` record. Empty unless `group` requires the roster and the roster
/// reads, so recording never fails an apply that would otherwise succeed.
pub(crate) fn roster_tag_keys(group: &MlsGroup) -> BTreeSet<RosterTagKey> {
    if !crate::app_components::group_requires_device_roster(group).unwrap_or(false) {
        return BTreeSet::new();
    }
    let Some(roster) = crate::app_components::device_roster_of_group(group) else {
        return BTreeSet::new();
    };
    let devices = roster
        .devices
        .into_iter()
        .filter_map(|(slot, device)| Some((slot, device.tag_signature_key?)));
    let removed = roster
        .rejected_slots
        .into_iter()
        .filter(|(_, rejected)| rejected.reason == RejectedSlotReasonV1::Removed)
        .filter_map(|(slot, rejected)| Some((slot, rejected.tag_signature_key?)));
    devices
        .chain(removed)
        .map(|(slot, tag_signature_key)| RosterTagKey {
            slot,
            tag_signature_key,
        })
        .collect()
}

/// Record `keys`, in the order the roster states that listed them were
/// applied, as seen in `group_id` at `now`, then drop what is past its
/// bounds. A key listed again later counts from its last listing, so a
/// slot's newest key is the one a roster state listed last, even within one
/// pass. A backend without the store records none.
pub(crate) fn record_tag_keys<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    keys: &[RosterTagKey],
    now: Timestamp,
) -> Result<(), StorageError> {
    let Some(store) = storage.roster_tag_key_storage() else {
        return Ok(());
    };
    if keys.is_empty() {
        return Ok(());
    }
    let mut listed = BTreeSet::new();
    let mut keys = keys
        .iter()
        .rev()
        .filter(|key| listed.insert(*key))
        .cloned()
        .collect::<Vec<_>>();
    keys.reverse();
    store.record_roster_tag_keys(group_id, &keys, now.0)?;
    store.prune_roster_tag_keys(
        now.0.saturating_sub(ROSTER_TAG_KEY_RETENTION_SECS),
        ROSTER_TAG_KEYS_PER_SLOT,
    )
}

/// Record the tag signature keys `group`'s roster lists now.
pub(crate) fn record_roster_tag_keys<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    group: &MlsGroup,
    now: Timestamp,
) -> Result<(), StorageError> {
    let keys = roster_tag_keys(group).into_iter().collect::<Vec<_>>();
    record_tag_keys(storage, group_id, &keys, now)
}
