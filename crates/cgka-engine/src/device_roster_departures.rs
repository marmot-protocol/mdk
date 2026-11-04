//! Selected native device-roster departures. Capture the actual source entry
//! before each merge; project the cause after it, before the resulting epoch's
//! checkpoint. Candidate probes do not create observations. Group snapshots
//! carry the projection, so branch selection restores its own causes.

use cgka_traits::app_components::{DeviceRosterV1, DeviceStatusV1};
use cgka_traits::group::{DeviceRosterDeparture, DeviceRosterDepartureCause};
use cgka_traits::storage::StorageProvider;
use cgka_traits::{EngineError, EpochId, GroupId, MessageId};
use openmls::group::MlsGroup;
use std::collections::BTreeMap;

pub(crate) struct BeforeRoster {
    epoch: EpochId,
    roster: DeviceRosterV1,
}

pub(crate) fn capture(group: &MlsGroup) -> Result<Option<BeforeRoster>, EngineError> {
    if !crate::app_components::group_requires_device_roster(group)? {
        return Ok(None);
    }
    let roster = crate::app_components::device_roster_of_group(group)
        .ok_or_else(|| EngineError::Other("authenticated device roster is unavailable".into()))?;
    Ok(Some(BeforeRoster {
        epoch: EpochId(group.epoch().as_u64()),
        roster,
    }))
}

pub(crate) fn record<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    before: Option<BeforeRoster>,
    after: &MlsGroup,
    commit_id: &MessageId,
) -> Result<(), EngineError> {
    let Some(before) = before else {
        return Ok(());
    };
    let next = crate::app_components::device_roster_of_group(after)
        .ok_or_else(|| EngineError::Other("selected device roster is unavailable".into()))?;
    let mut group = storage.get_group(group_id)?;
    let mut causes = group
        .device_roster_departures
        .into_iter()
        .map(|cause| (cause.slot, cause))
        .collect::<BTreeMap<_, _>>();
    // An actual entry is a current admission, never permanent moved immunity.
    for slot in next.devices.keys() {
        causes.remove(slot);
    }
    for (slot, entry) in before.roster.devices {
        if next.devices.contains_key(&slot) {
            continue;
        }
        let cause =
            if entry.status == DeviceStatusV1::Moved && !next.rejected_slots.contains_key(&slot) {
                DeviceRosterDepartureCause::Moved
            } else {
                DeviceRosterDepartureCause::Ordinary
            };
        causes.insert(
            slot,
            DeviceRosterDeparture {
                label: entry.label,
                slot,
                tag_signature_key: entry.tag_signature_key,
                linked_at: entry.linked_at,
                entry_rename_id: entry.rename_id,
                source_epoch: before.epoch,
                commit_id: commit_id.clone(),
                cause,
            },
        );
    }
    group.device_roster_departures = causes.into_values().collect();
    storage.put_group(&group)?;
    Ok(())
}
