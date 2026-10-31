//! KeyPackages device-group rosters announced (mdk#2628 D31 item 7).
//!
//! Every roster state this device applies records each device's announced
//! KeyPackage, in the transaction that applies it: a canonical apply records
//! each commit it merges or restores, an own Commit records when it is
//! confirmed, and a founding create and a Welcome join record the roster they
//! start from. A record outlives the branch that announced it, since a
//! dropped announcement still names a KeyPackage its device may have
//! published.
//!
//! The engine only writes them. No convergence input, snapshot or replay
//! fingerprint reads them, so group state and branch selection are what they
//! would be without them. The app reads them to tell a slot still serving an
//! earlier announcement from one serving a KeyPackage no roster announced,
//! and never to reject a KeyPackage a roster announced.

use std::collections::BTreeSet;

use cgka_traits::Timestamp;
use cgka_traits::storage::{
    ANNOUNCED_KEY_PACKAGE_RETENTION_SECS, AnnouncedKeyPackage, StorageError, StorageProvider,
};
use cgka_traits::types::GroupId;
use openmls::group::MlsGroup;

/// Every KeyPackage `group`'s roster announces now. Empty unless `group`
/// requires the roster and the roster reads, so recording never fails an
/// apply that would otherwise succeed.
pub(crate) fn roster_announcements(group: &MlsGroup) -> BTreeSet<AnnouncedKeyPackage> {
    if !crate::app_components::group_requires_device_roster(group).unwrap_or(false) {
        return BTreeSet::new();
    }
    crate::app_components::device_roster_of_group(group)
        .map(|roster| {
            roster
                .devices
                .into_iter()
                .filter_map(|(slot, device)| {
                    Some(AnnouncedKeyPackage {
                        slot,
                        key_package_ref: device.announced_key_package?,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Record `announced` as seen in `group_id` at `now`, then drop what is past
/// its bounds. A backend without the store records none.
pub(crate) fn record_announcements<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    announced: &BTreeSet<AnnouncedKeyPackage>,
    now: Timestamp,
) -> Result<(), StorageError> {
    let Some(store) = storage.announced_key_package_storage() else {
        return Ok(());
    };
    if announced.is_empty() {
        return Ok(());
    }
    let announced = announced.iter().cloned().collect::<Vec<_>>();
    store.record_announced_key_packages(group_id, &announced, now.0)?;
    store.prune_announced_key_packages(now.0.saturating_sub(ANNOUNCED_KEY_PACKAGE_RETENTION_SECS))
}

/// Record what `group`'s roster announces now.
pub(crate) fn record_roster_announcements<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    group: &MlsGroup,
    now: Timestamp,
) -> Result<(), StorageError> {
    record_announcements(storage, group_id, &roster_announcements(group), now)
}
