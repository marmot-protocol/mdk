//! What device-group rosters announced (mdk#2628 D31 item 7).
//!
//! Every roster state a device applies records each device's announced
//! KeyPackage, in the transaction that applies it: the founding create and
//! the Welcome join, an own Commit when it is confirmed, and each commit a
//! canonical apply merges. A record outlives the branch that made it, and a
//! candidate probe records nothing.

use super::device_roster::{
    entry, found_device_group, phone_and_laptop, roster, roster_device, roster_of, roster_update,
    slot,
};
use super::*;
use cgka_traits::app_components::{DeviceEntryV1, DeviceRosterOperationV1, DeviceRosterV1};
use cgka_traits::storage::{AnnouncedKeyPackage, AnnouncedKeyPackageStorage as _};
use std::collections::BTreeSet;

fn announced(n: u8, reference: u8) -> AnnouncedKeyPackage {
    AnnouncedKeyPackage {
        slot: slot(n),
        key_package_ref: vec![reference; 32],
    }
}

/// Set the entry of slot `n`, labelled `label`, to announce `reference`.
fn announce(gid: &GroupId, n: u8, label: &str, reference: u8) -> SendIntent {
    roster_update(
        gid,
        vec![DeviceRosterOperationV1::SetDevice(
            slot(n),
            DeviceEntryV1 {
                announced_key_package: Some(vec![reference; 32]),
                ..entry(label)
            },
        )],
    )
}

/// Every announcement `roster` holds.
fn announcements(roster: &DeviceRosterV1) -> BTreeSet<AnnouncedKeyPackage> {
    roster
        .devices
        .iter()
        .filter_map(|(slot, device)| {
            Some(AnnouncedKeyPackage {
                slot: *slot,
                key_package_ref: device.announced_key_package.clone()?,
            })
        })
        .collect()
}

fn recorded(device: &Device, gid: &GroupId) -> BTreeSet<AnnouncedKeyPackage> {
    device
        .storage
        .announced_key_packages(gid, 0)
        .unwrap()
        .into_iter()
        .collect()
}

#[tokio::test]
async fn every_roster_state_a_device_applies_records_its_announcements() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let mut initial = roster(&[(1, "Phone"), (2, "Laptop")]);
    initial
        .devices
        .get_mut(&slot(1))
        .unwrap()
        .announced_key_package = Some(vec![0xa1; 32]);
    let gid = found_device_group(&mut phone, &initial, &mut [&mut laptop]).await;
    // The founding create and the Welcome join record the roster they start
    // from: the phone's entry and the KeyPackage the laptop joined with.
    let founded = announcements(&roster_of(&phone, &gid));
    assert_eq!(founded.len(), 2, "{founded:?}");
    assert!(founded.contains(&announced(1, 0xa1)));
    for device in [&phone, &laptop] {
        assert_eq!(recorded(device, &gid), founded);
    }

    // The committer records when its Commit is confirmed, a receiver when it
    // applies it.
    let commit = send_commit(&mut phone, announce(&gid, 2, "Laptop", 0xb2), &gid).await;
    assert_accepted(&mut laptop, &commit, &gid).await;
    let mut expected = founded;
    expected.insert(announced(2, 0xb2));
    for device in [&phone, &laptop] {
        assert_eq!(recorded(device, &gid), expected);
    }
}

/// One pass applies two commits, the second replacing the first's
/// announcement. The roster at the end of the pass never held the first, yet
/// it is recorded.
#[tokio::test]
async fn an_announcement_replaced_within_one_pass_is_recorded() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let mut expected = announcements(&roster_of(&laptop, &gid));
    let first = send_commit(&mut phone, announce(&gid, 2, "Laptop", 0xc1), &gid).await;
    let second = send_commit(&mut phone, announce(&gid, 2, "Laptop", 0xc2), &gid).await;
    let before = laptop.engine.epoch(&gid).unwrap().0;
    for commit in [&first, &second] {
        laptop
            .engine
            .buffer_openmls_convergence_message_at(&gid, commit.clone(), 500)
            .unwrap();
    }
    let result = laptop
        .engine
        .converge_stored_openmls_messages_at(&gid, 1_000_000)
        .unwrap();
    assert_eq!(result.accepted_commits.len(), 2, "{result:?}");
    assert_eq!(laptop.engine.epoch(&gid).unwrap().0, before + 2);
    assert_eq!(
        roster_of(&laptop, &gid).devices[&slot(2)].announced_key_package,
        Some(vec![0xc2; 32])
    );
    expected.extend([announced(2, 0xc1), announced(2, 0xc2)]);
    assert_eq!(recorded(&laptop, &gid), expected);
}

/// The phone and the laptop each announce a KeyPackage from the same epoch,
/// then adjudicate the other's commit. The device whose commit loses rewinds
/// past its own announcement, which stays recorded. The winner only probed
/// the losing commit, so it never records that announcement.
#[tokio::test]
async fn a_rewind_keeps_what_the_dropped_branch_announced() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        &mut [&mut laptop],
    )
    .await;
    let founded = announcements(&roster_of(&phone, &gid));
    let phone_commit = send_commit(&mut phone, announce(&gid, 1, "Phone", 0xe1), &gid).await;
    let laptop_commit = send_commit(&mut laptop, announce(&gid, 2, "Laptop", 0xe2), &gid).await;
    for (device, rival) in [(&mut phone, &laptop_commit), (&mut laptop, &phone_commit)] {
        device
            .engine
            .buffer_openmls_convergence_message_at(&gid, rival.clone(), 500)
            .unwrap();
        device
            .engine
            .converge_stored_openmls_messages_at(&gid, 1_000_000)
            .unwrap();
    }

    let winning = roster_of(&phone, &gid);
    assert_eq!(roster_of(&laptop, &gid), winning, "both devices converge");
    let (loser, winner, kept, dropped) = if announcements(&winning).contains(&announced(1, 0xe1)) {
        (&laptop, &phone, announced(1, 0xe1), announced(2, 0xe2))
    } else {
        (&phone, &laptop, announced(2, 0xe2), announced(1, 0xe1))
    };
    assert!(
        !announcements(&winning).contains(&dropped),
        "the losing branch's announcement is gone from the roster"
    );
    let mut won = founded;
    won.insert(kept);
    let mut lost = won.clone();
    lost.insert(dropped);
    assert_eq!(recorded(loser, &gid), lost);
    assert_eq!(recorded(winner, &gid), won);
}
