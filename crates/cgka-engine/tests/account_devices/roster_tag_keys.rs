//! Tag signature keys device-group rosters listed (mdk#2761).
//!
//! Every roster state a device applies records each tag signature key it
//! lists, in a device entry or a `removed` record, in the transaction that
//! applies it: the founding create and the Welcome join, an own Commit when
//! it is confirmed, and each commit a canonical apply merges. A record
//! outlives the branch that made it, and a candidate probe records nothing.

use super::device_roster::{
    NO_WELCOME_DEADLINE, entry, found_device_group, key_package_ref, leaf_signature_key, roster,
    roster_device, roster_of, roster_update, slot, update_bytes,
};
use super::*;
use cgka_traits::app_components::{
    DeviceEntryV1, DeviceRosterOperationV1, RejectedSlotReasonV1, RejectedSlotV1,
};
use cgka_traits::storage::{RosterTagKey, RosterTagKeyStorage as _};
use std::collections::BTreeSet;

fn tag_key(n: u8, key: u8) -> RosterTagKey {
    RosterTagKey {
        slot: slot(n),
        tag_signature_key: vec![key; 32],
        held_as_removed: false,
    }
}

/// A key a roster state listed in slot `n`'s `removed` record.
fn removed_key(n: u8, key: u8) -> RosterTagKey {
    RosterTagKey {
        held_as_removed: true,
        ..tag_key(n, key)
    }
}

/// The laptop's slot: after every planted one, so the laptop is the device
/// that joins the founding.
const LAPTOP: u8 = 9;

/// A fresh phone founds a device group at slot 1, which the laptop joins at
/// [`LAPTOP`], with an entry at each of `planted`, carrying the key given,
/// whose device never joins. The founding state's keys are taken as the
/// creating device wrote them ("Key binding"), so this is how a test lists a
/// key no leaf signs with.
async fn found_with(planted: &[(u8, &str, u8)]) -> (Device, Device, GroupId) {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let mut initial = roster(&[(1, "Phone"), (LAPTOP, "Laptop")]);
    for (n, label, key) in planted {
        initial.devices.insert(
            slot(*n),
            DeviceEntryV1 {
                tag_signature_key: Some(vec![*key; 32]),
                ..entry(label)
            },
        );
    }
    let gid = found_device_group(&mut phone, &initial, &mut [&mut laptop]).await;
    (phone, laptop, gid)
}

/// The phone's Commit linking a fresh device of the account at slot `n`,
/// whose Add binds that device's leaf key to its new entry. The device never
/// joins. Returns the Commit, unconfirmed by anyone else, and the key.
async fn link_at(phone: &mut Device, gid: &GroupId, n: u8) -> (TransportMessage, Vec<u8>) {
    let mut device = roster_device(b"alice");
    let key_package = device.engine.fresh_key_package().await.unwrap();
    let key = leaf_signature_key(&key_package);
    let roster_update = update_bytes(vec![DeviceRosterOperationV1::SetDevice(
        slot(n),
        DeviceEntryV1 {
            announced_key_package: Some(key_package_ref(&key_package)),
            tag_signature_key: Some(key.clone()),
            ..entry("Tablet")
        },
    )]);
    let commit = send_commit(
        phone,
        SendIntent::LinkDevice {
            group_id: gid.clone(),
            key_package,
            roster_update,
            deliver_until: NO_WELCOME_DEADLINE,
        },
        gid,
    )
    .await;
    (commit, key)
}

/// Remove slot `n`'s entry, whose key no leaf signs with, and record the
/// slot as `removed`, keeping `key`.
fn remove_and_record(gid: &GroupId, n: u8, key: Option<u8>) -> SendIntent {
    roster_update(
        gid,
        vec![
            DeviceRosterOperationV1::RemoveDevice(slot(n)),
            DeviceRosterOperationV1::SetRejectedSlot(
                slot(n),
                RejectedSlotV1 {
                    reason: RejectedSlotReasonV1::Removed,
                    rejected_at: 1,
                    tag_signature_key: key.map(|key| vec![key; 32]),
                },
            ),
        ],
    )
}

fn key_of(n: u8, key: &[u8]) -> RosterTagKey {
    RosterTagKey {
        slot: slot(n),
        tag_signature_key: key.to_vec(),
        held_as_removed: false,
    }
}

fn recorded(device: &Device, gid: &GroupId) -> BTreeSet<RosterTagKey> {
    device
        .storage
        .roster_tag_keys(gid, 0)
        .unwrap()
        .into_iter()
        .collect()
}

#[tokio::test]
async fn every_roster_state_a_device_applies_records_its_tag_keys() {
    let (mut phone, mut laptop, gid) = found_with(&[(4, "Watch", 0xb4)]).await;
    // The founding create and the Welcome join record the roster they start
    // from: the founder's key, the key the Add bound to the laptop's entry,
    // and the planted one.
    let founded = BTreeSet::from([
        key_of(1, &phone.engine.own_signature_key()),
        key_of(LAPTOP, &laptop.engine.own_signature_key()),
        tag_key(4, 0xb4),
    ]);
    for device in [&phone, &laptop] {
        assert_eq!(recorded(device, &gid), founded);
    }

    // The committer records when its Commit is confirmed, a receiver when it
    // applies it: a device entry's key and a `removed` record's alike.
    let (linked, tablet_key) = link_at(&mut phone, &gid, 3).await;
    assert_accepted(&mut laptop, &linked, &gid).await;
    let removed = send_commit(&mut phone, remove_and_record(&gid, 4, Some(0xb4)), &gid).await;
    assert_accepted(&mut laptop, &removed, &gid).await;
    // The record holds the key the entry listed as removed.
    let mut expected = founded;
    expected.remove(&tag_key(4, 0xb4));
    expected.extend([key_of(3, &tablet_key), removed_key(4, 0xb4)]);
    for device in [&phone, &laptop] {
        assert_eq!(recorded(device, &gid), expected);
    }
}

/// One pass applies three commits: the first records slot 3 as `removed`
/// and takes slot 4's entry, the second drops slot 3's record, as an expiry
/// pass does, and the third links a new device at slot 4. The roster at the
/// end of the pass never held the record, yet its key is recorded, held as
/// removed, and slot 4's newest key is the one the pass listed last.
#[tokio::test]
async fn a_removed_record_dropped_within_one_pass_is_recorded() {
    let (mut phone, mut laptop, gid) = found_with(&[(3, "Watch", 0xc3), (4, "Tablet", 0xd1)]).await;
    let before_pass = recorded(&laptop, &gid);
    let mut first = remove_and_record(&gid, 3, Some(0xc3));
    let SendIntent::UpdateAppComponents { updates, .. } = &mut first else {
        unreachable!()
    };
    updates[0].data = update_bytes(vec![
        DeviceRosterOperationV1::RemoveDevice(slot(3)),
        DeviceRosterOperationV1::SetRejectedSlot(
            slot(3),
            RejectedSlotV1 {
                reason: RejectedSlotReasonV1::Removed,
                rejected_at: 1,
                tag_signature_key: Some(vec![0xc3; 32]),
            },
        ),
        DeviceRosterOperationV1::RemoveDevice(slot(4)),
    ]);
    let first = send_commit(&mut phone, first, &gid).await;
    let second = send_commit(
        &mut phone,
        roster_update(
            &gid,
            vec![DeviceRosterOperationV1::RemoveRejectedSlot(slot(3))],
        ),
        &gid,
    )
    .await;
    let (third, relinked) = link_at(&mut phone, &gid, 4).await;
    let before = laptop.engine.epoch(&gid).unwrap().0;
    for commit in [&first, &second, &third] {
        laptop
            .engine
            .buffer_openmls_convergence_message_at(&gid, commit.clone(), 500)
            .unwrap();
    }
    let result = laptop
        .engine
        .converge_stored_openmls_messages_at(&gid, 1_000_000)
        .unwrap();
    assert_eq!(result.accepted_commits.len(), 3, "{result:?}");
    assert_eq!(laptop.engine.epoch(&gid).unwrap().0, before + 3);
    assert!(
        !roster_of(&laptop, &gid)
            .rejected_slots
            .contains_key(&slot(3))
    );
    let mut expected = before_pass;
    expected.remove(&tag_key(3, 0xc3));
    expected.extend([removed_key(3, 0xc3), key_of(4, &relinked)]);
    assert_eq!(recorded(&laptop, &gid), expected);
    let slot_4_newest_first = laptop
        .storage
        .roster_tag_keys(&gid, 0)
        .unwrap()
        .into_iter()
        .filter(|key| key.slot == slot(4))
        .collect::<Vec<_>>();
    assert_eq!(
        slot_4_newest_first,
        [key_of(4, &relinked), tag_key(4, 0xd1)]
    );
}

/// A `removed` record that keeps no key (marmot#520) holds the keys a
/// device keeps for its slot as removed, on the device whose own Commits
/// make the record, and on one that applies the record, its drop and a new
/// link at the slot within one pass. The key the slot is listed with after
/// the drop, and another slot's key, are not held.
#[tokio::test]
async fn a_removed_record_without_a_key_holds_the_slots_keys() {
    let (mut phone, mut laptop, gid) = found_with(&[(4, "Tablet", 0xd4), (5, "Watch", 0xd5)]).await;
    let first = send_commit(&mut phone, remove_and_record(&gid, 4, None), &gid).await;
    let second = send_commit(
        &mut phone,
        roster_update(
            &gid,
            vec![DeviceRosterOperationV1::RemoveRejectedSlot(slot(4))],
        ),
        &gid,
    )
    .await;
    let (third, relinked) = link_at(&mut phone, &gid, 4).await;
    for commit in [&first, &second, &third] {
        laptop
            .engine
            .buffer_openmls_convergence_message_at(&gid, commit.clone(), 500)
            .unwrap();
    }
    let result = laptop
        .engine
        .converge_stored_openmls_messages_at(&gid, 1_000_000)
        .unwrap();
    assert_eq!(result.accepted_commits.len(), 3, "{result:?}");
    for device in [&phone, &laptop] {
        let keys = recorded(device, &gid);
        assert!(keys.contains(&removed_key(4, 0xd4)), "{keys:?}");
        assert!(!keys.contains(&tag_key(4, 0xd4)), "{keys:?}");
        assert!(keys.contains(&key_of(4, &relinked)), "{keys:?}");
        assert!(keys.contains(&tag_key(5, 0xd5)), "{keys:?}");
    }
}

/// The phone and the laptop each link a device from the same epoch, then
/// adjudicate the other's commit. The device whose commit loses rewinds past
/// the key its Add listed, which stays recorded. The winner only probed the
/// losing commit, so it never records that key.
#[tokio::test]
async fn a_rewind_keeps_the_keys_the_dropped_branch_listed() {
    let (mut phone, mut laptop, gid) = found_with(&[]).await;
    let founded = recorded(&phone, &gid);
    let (phone_commit, phone_key) = link_at(&mut phone, &gid, 3).await;
    let (laptop_commit, laptop_key) = link_at(&mut laptop, &gid, 4).await;
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
    let phone_won = winning.devices.contains_key(&slot(3));
    let (loser, winner, kept, dropped) = if phone_won {
        (
            &laptop,
            &phone,
            key_of(3, &phone_key),
            key_of(4, &laptop_key),
        )
    } else {
        (
            &phone,
            &laptop,
            key_of(4, &laptop_key),
            key_of(3, &phone_key),
        )
    };
    assert!(
        !winning.devices.contains_key(&dropped.slot),
        "the losing branch's entry is gone from the roster"
    );
    let mut won = founded;
    won.insert(kept);
    let mut lost = won.clone();
    lost.insert(dropped);
    assert_eq!(recorded(loser, &gid), lost);
    assert_eq!(recorded(winner, &gid), won);
}

/// A selected cause belongs to its actual source branch and incarnation, not
/// the bounded observed-ever tag cache. One apply batch may contain both the
/// moved state and its RemoveDevice-only cleanup. A longer actual rival and a
/// native snapshot restore must each restore their own departure projection.
#[tokio::test]
async fn moved_departure_follows_selected_source_through_batch_rewind_and_snapshot() {
    use super::device_tag::{hold_slot, set_own_key};
    use cgka_traits::app_components::DeviceStatusV1;
    use cgka_traits::group::DeviceRosterDepartureCause;
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let mut tablet = roster_device(b"alice");
    let mut observer = roster_device(b"alice");
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop"), (3, "Tablet"), (4, "Observer")]),
        &mut [&mut laptop, &mut tablet, &mut observer],
    )
    .await;
    hold_slot(&laptop, slot(2));
    laptop
        .engine
        .set_device_tag_group(Some(gid.clone()))
        .unwrap();
    set_own_key(
        &mut laptop,
        slot(2),
        &gid,
        &mut [&mut phone, &mut tablet, &mut observer],
    )
    .await;
    let source = roster_of(&laptop, &gid).devices[&slot(2)].clone();
    let key = laptop.engine.own_signature_key();
    let branch_epoch = tablet.engine.epoch(&gid).unwrap();
    // The tablet remains on the common source and makes a longer valid rival.
    let mut rival = Vec::new();
    for _ in 0..3 {
        rival.push(
            send_commit(
                &mut tablet,
                SendIntent::SelfUpdate {
                    group_id: gid.clone(),
                },
                &gid,
            )
            .await,
        );
    }
    let mut moved = source.clone();
    moved.status = DeviceStatusV1::Moved;
    let moved = send_commit(
        &mut laptop,
        roster_update(
            &gid,
            vec![DeviceRosterOperationV1::SetDevice(slot(2), moved)],
        ),
        &gid,
    )
    .await;
    assert_accepted(&mut phone, &moved, &gid).await;
    let cleanup = send_commit(
        &mut phone,
        SendIntent::UnlinkDevice {
            group_id: gid.clone(),
            leaf_signature_key: key.clone(),
            roster_update: super::device_roster::update_bytes(vec![
                DeviceRosterOperationV1::RemoveDevice(slot(2)),
            ]),
        },
        &gid,
    )
    .await;
    for commit in [&moved, &cleanup] {
        observer
            .engine
            .buffer_openmls_convergence_message_at(&gid, commit.clone(), 500)
            .unwrap();
    }
    let applied = observer
        .engine
        .converge_stored_openmls_messages_at(&gid, 1_000_000)
        .unwrap();
    assert_eq!(applied.accepted_commits.len(), 2, "{applied:?}");
    let cause = observer
        .engine
        .group_record(&gid)
        .unwrap()
        .device_roster_departures
        .into_iter()
        .find(|d| d.slot == slot(2))
        .expect("selected Moved cleanup retains its actual source");
    assert_eq!(cause.cause, DeviceRosterDepartureCause::Moved);
    assert_eq!(cause.tag_signature_key, Some(key.clone()));
    assert_eq!(cause.linked_at, source.linked_at);
    assert_eq!(cause.entry_rename_id, source.rename_id);
    assert_eq!(cause.source_epoch.0, branch_epoch.0 + 1);
    assert!(
        !roster_of(&observer, &gid)
            .rejected_slots
            .contains_key(&slot(2))
    );
    observer
        .storage
        .create_group_snapshot(&gid, "selected-moved-departure")
        .unwrap();
    // Real branch selection restores the current entry and clears that branch's
    // moved cause. Remembered keys remain a separate, non-authoritative cache.
    for reader in [&mut phone, &mut observer] {
        for commit in &rival {
            reader
                .engine
                .buffer_openmls_convergence_message_at(&gid, commit.clone(), 500)
                .unwrap();
        }
        reader
            .engine
            .converge_stored_openmls_messages_at(&gid, 2_000_000)
            .unwrap();
        assert!(roster_of(reader, &gid).devices.contains_key(&slot(2)));
        assert!(
            reader
                .engine
                .group_record(&gid)
                .unwrap()
                .device_roster_departures
                .iter()
                .all(|d| d.slot != slot(2))
        );
    }
    assert_eq!(roster_of(&phone, &gid), roster_of(&observer, &gid));
    // An actual ordinary removal on the new selected branch supersedes the
    // earlier moved cause even for this same device key and slot.
    let removal = send_commit(
        &mut tablet,
        SendIntent::UnlinkDevice {
            group_id: gid.clone(),
            leaf_signature_key: key,
            roster_update: super::device_roster::update_bytes(vec![
                DeviceRosterOperationV1::RemoveDevice(slot(2)),
                DeviceRosterOperationV1::SetRejectedSlot(
                    slot(2),
                    RejectedSlotV1 {
                        reason: RejectedSlotReasonV1::Removed,
                        rejected_at: 1,
                        tag_signature_key: source.tag_signature_key.clone(),
                    },
                ),
            ]),
        },
        &gid,
    )
    .await;
    let before_removal = observer.engine.epoch(&gid).unwrap();
    observer.engine.ingest(removal.clone()).await.unwrap();
    let applied = observer
        .engine
        .converge_stored_openmls_messages_at(&gid, 3_000_000)
        .unwrap();
    let expected = rival
        .iter()
        .chain(std::iter::once(&removal))
        .map(|commit| hex::encode(hash_id(&commit.payload).as_slice()))
        .collect::<Vec<_>>();
    assert_eq!(
        applied.accepted_commits, expected,
        "selected rival prefix plus its removal"
    );
    assert_eq!(observer.engine.epoch(&gid).unwrap().0, before_removal.0 + 1);
    assert_eq!(
        observer
            .engine
            .group_record(&gid)
            .unwrap()
            .device_roster_departures
            .iter()
            .find(|d| d.slot == slot(2))
            .unwrap()
            .cause,
        DeviceRosterDepartureCause::Ordinary
    );
    observer
        .storage
        .rollback_group_to_snapshot(&gid, "selected-moved-departure")
        .unwrap();
    let storage = observer.storage.clone();
    drop(observer);
    let mut reopened = super::device_roster::roster_device_on(storage, b"alice");
    reopened.engine.hydrate_all_stored_groups().unwrap();
    assert_eq!(
        reopened
            .engine
            .group_record(&gid)
            .unwrap()
            .device_roster_departures,
        vec![cause]
    );
    assert!(!roster_of(&reopened, &gid).devices.contains_key(&slot(2)));
    assert!(
        !roster_of(&reopened, &gid)
            .rejected_slots
            .contains_key(&slot(2))
    );
}
