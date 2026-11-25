//! Tag signature keys device-group rosters listed (mdk#2761).
//!
//! Every roster state this device applies records each tag signature key it
//! lists for a slot, in a device entry or in a `removed` record, in the
//! transaction that applies it: a canonical apply records each commit it
//! merges or restores, an own Commit records when it is confirmed, and a
//! founding create and a Welcome join record the roster they start from. A
//! record outlives the branch that listed it, since a device whose key a
//! dropped branch listed may have tagged leaves in chats under it. A
//! `removed` record that keeps no key (marmot#520) holds every key this
//! device keeps for its slot as removed instead, so the slot is still known
//! to have held its record.
//!
//! The engine only writes them. No convergence input, snapshot or replay
//! fingerprint reads them, so group state and branch selection are what they
//! would be without them. The app reads them to clean up after a device the
//! roster no longer lists, whether a removal's record was dropped before this
//! device acted on it, a link failed, or a branch dropped a made link; and,
//! adding a newly linked device to its chats (mdk#2628 3.5c), to skip a slot
//! a state it applied held as removed. The app also renews a removed slot's
//! keys while a chat still holds that device's leaf (mdk#3679), which moves
//! only their sighting time and never their order.

use std::collections::BTreeSet;

use cgka_traits::Timestamp;
use cgka_traits::app_components::RejectedSlotReasonV1;
use cgka_traits::storage::{
    ROSTER_TAG_KEY_RETENTION_SECS, ROSTER_TAG_KEYS_PER_SLOT, RosterTagKey, StorageError,
    StorageProvider,
};
use cgka_traits::types::GroupId;
use openmls::group::MlsGroup;

/// What a roster state lists of one slot's tag signature keys.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RosterTagSighting {
    /// A key it lists, in a device entry or a `removed` record.
    Key(RosterTagKey),
    /// A slot it records as `removed` with no key (marmot#520).
    RemovedWithoutKey([u8; 32]),
}

/// What `group`'s roster lists now: every tag signature key, for a device or
/// a `removed` record, and every `removed` record that keeps none. Empty
/// unless `group` requires the roster and the roster reads, so recording
/// never fails an apply that would otherwise succeed.
pub(crate) fn roster_tag_keys(group: &MlsGroup) -> BTreeSet<RosterTagSighting> {
    if !crate::app_components::group_requires_device_roster(group).unwrap_or(false) {
        return BTreeSet::new();
    }
    let Some(roster) = crate::app_components::device_roster_of_group(group) else {
        return BTreeSet::new();
    };
    let devices = roster.devices.into_iter().filter_map(|(slot, device)| {
        Some(RosterTagSighting::Key(RosterTagKey {
            slot,
            tag_signature_key: device.tag_signature_key?,
            held_as_removed: false,
        }))
    });
    let removed = roster
        .rejected_slots
        .into_iter()
        .filter(|(_, rejected)| rejected.reason == RejectedSlotReasonV1::Removed)
        .map(|(slot, rejected)| match rejected.tag_signature_key {
            Some(tag_signature_key) => RosterTagSighting::Key(RosterTagKey {
                slot,
                tag_signature_key,
                held_as_removed: true,
            }),
            None => RosterTagSighting::RemovedWithoutKey(slot),
        });
    devices.chain(removed).collect()
}

/// Record `sightings`, in the order the roster states that listed them were
/// applied, as seen in `group_id` at `now`, then drop what is past its
/// bounds. A key listed again later counts from its last listing, so a
/// slot's newest key is the one a roster state listed last, even within one
/// pass. A slot recorded as `removed` with no key then has every key this
/// device keeps for it held as removed, those the same pass recorded
/// included. A backend without the store records none.
pub(crate) fn record_tag_keys<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    sightings: &[RosterTagSighting],
    now: Timestamp,
) -> Result<(), StorageError> {
    let Some(store) = storage.roster_tag_key_storage() else {
        return Ok(());
    };
    if sightings.is_empty() {
        return Ok(());
    }
    let mut listed = BTreeSet::new();
    let mut keys = sightings
        .iter()
        .rev()
        .filter_map(|sighting| match sighting {
            RosterTagSighting::Key(key) => Some(key),
            RosterTagSighting::RemovedWithoutKey(_) => None,
        })
        .filter(|key| listed.insert(*key))
        .cloned()
        .collect::<Vec<_>>();
    keys.reverse();
    store.record_roster_tag_keys(group_id, &keys, now.0)?;
    let held = sightings
        .iter()
        .filter_map(|sighting| match sighting {
            RosterTagSighting::RemovedWithoutKey(slot) => Some(slot),
            RosterTagSighting::Key(_) => None,
        })
        .collect::<BTreeSet<_>>();
    for slot in held {
        store.hold_roster_tag_keys_as_removed(group_id, slot)?;
    }
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
    let sightings = roster_tag_keys(group).into_iter().collect::<Vec<_>>();
    record_tag_keys(storage, group_id, &sightings, now)
}
