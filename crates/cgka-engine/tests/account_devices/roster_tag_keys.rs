//! Tag signature keys device-group rosters listed (mdk#2761).
//!
//! Every roster state a device applies records each tag signature key it
//! lists, in a device entry or a `removed` record, in the transaction that
//! applies it: the founding create and the Welcome join, an own Commit when
//! it is confirmed, and each commit a canonical apply merges. A record
//! outlives the branch that made it, and a candidate probe records nothing.

use super::device_roster::{
    entry, found_device_group, phone_and_laptop, roster, roster_device, roster_of, roster_update,
    slot,
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

/// Set the entry of slot `n`, labelled `label`, to carry tag signature key
/// `key`.
fn set_key_op(n: u8, label: &str, key: u8) -> DeviceRosterOperationV1 {
    DeviceRosterOperationV1::SetDevice(
        slot(n),
        DeviceEntryV1 {
            tag_signature_key: Some(vec![key; 32]),
            ..entry(label)
        },
    )
}

fn set_key(gid: &GroupId, n: u8, label: &str, key: u8) -> SendIntent {
    roster_update(gid, vec![set_key_op(n, label, key)])
}

/// Record slot `n`, which holds no device, as `removed` with key `key`.
fn record_removed_op(n: u8, key: u8) -> DeviceRosterOperationV1 {
    DeviceRosterOperationV1::SetRejectedSlot(
        slot(n),
        RejectedSlotV1 {
            reason: RejectedSlotReasonV1::Removed,
            rejected_at: 1,
            tag_signature_key: Some(vec![key; 32]),
        },
    )
}

fn record_removed(gid: &GroupId, n: u8, key: u8) -> SendIntent {
    roster_update(gid, vec![record_removed_op(n, key)])
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
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let mut initial = roster(&[(1, "Phone"), (2, "Laptop")]);
    initial.devices.get_mut(&slot(1)).unwrap().tag_signature_key = Some(vec![0xa1; 32]);
    let gid = found_device_group(&mut phone, &initial, &mut [&mut laptop]).await;
    // The founding create and the Welcome join record the roster they start
    // from. The laptop has set no key yet.
    for device in [&phone, &laptop] {
        assert_eq!(recorded(device, &gid), BTreeSet::from([tag_key(1, 0xa1)]));
    }

    // The committer records when its Commit is confirmed, a receiver when it
    // applies it: a device entry's key and a `removed` record's alike.
    for intent in [
        set_key(&gid, 2, "Laptop", 0xb2),
        record_removed(&gid, 3, 0xb3),
    ] {
        let commit = send_commit(&mut phone, intent, &gid).await;
        assert_accepted(&mut laptop, &commit, &gid).await;
    }
    let expected = BTreeSet::from([tag_key(1, 0xa1), tag_key(2, 0xb2), removed_key(3, 0xb3)]);
    for device in [&phone, &laptop] {
        assert_eq!(recorded(device, &gid), expected);
    }
}

/// One pass applies two commits: the first records slot 3 as `removed`, the
/// second drops that record, as an expiry pass does. The roster at the end
/// of the pass never held the record, yet its key is recorded, held as
/// removed. Slot 4's key changes in each, and the one the later commit
/// listed reads as its newest.
#[tokio::test]
async fn a_removed_record_dropped_within_one_pass_is_recorded() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    // Slot 4 lists key 0xd1 before the pass, then 0xd2 and 0xd1 again within
    // it. 0xd1 is the newest, though its row is the older one, the pass
    // gives both keys one time, and it sorts first.
    let commit = send_commit(&mut phone, set_key(&gid, 4, "Tablet", 0xd1), &gid).await;
    assert_accepted(&mut laptop, &commit, &gid).await;
    let before_pass = recorded(&laptop, &gid);
    let first = roster_update(
        &gid,
        vec![record_removed_op(3, 0xc3), set_key_op(4, "Tablet", 0xd2)],
    );
    let second = roster_update(
        &gid,
        vec![
            DeviceRosterOperationV1::RemoveRejectedSlot(slot(3)),
            set_key_op(4, "Tablet", 0xd1),
        ],
    );
    let first = send_commit(&mut phone, first, &gid).await;
    let second = send_commit(&mut phone, second, &gid).await;
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
    assert!(
        !roster_of(&laptop, &gid)
            .rejected_slots
            .contains_key(&slot(3))
    );
    let mut expected = before_pass;
    expected.extend([removed_key(3, 0xc3), tag_key(4, 0xd2)]);
    assert_eq!(recorded(&laptop, &gid), expected);
    let slot_4_newest_first = laptop
        .storage
        .roster_tag_keys(&gid, 0)
        .unwrap()
        .into_iter()
        .filter(|key| key.slot == slot(4))
        .collect::<Vec<_>>();
    assert_eq!(slot_4_newest_first, [tag_key(4, 0xd1), tag_key(4, 0xd2)]);
}

/// The phone and the laptop each set a key from the same epoch, then
/// adjudicate the other's commit. The device whose commit loses rewinds past
/// its own key, which stays recorded. The winner only probed the losing
/// commit, so it never records that key.
#[tokio::test]
async fn a_rewind_keeps_the_keys_the_dropped_branch_listed() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        &mut [&mut laptop],
    )
    .await;
    let founded = recorded(&phone, &gid);
    let phone_commit = send_commit(&mut phone, set_key(&gid, 1, "Phone", 0xe1), &gid).await;
    let laptop_commit = send_commit(&mut laptop, set_key(&gid, 2, "Laptop", 0xe2), &gid).await;
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
    let phone_won = winning.devices[&slot(1)].tag_signature_key == Some(vec![0xe1; 32]);
    let (loser, winner, kept, dropped) = if phone_won {
        (&laptop, &phone, tag_key(1, 0xe1), tag_key(2, 0xe2))
    } else {
        (&phone, &laptop, tag_key(2, 0xe2), tag_key(1, 0xe1))
    };
    assert_ne!(
        winning.devices[&dropped.slot].tag_signature_key,
        Some(dropped.tag_signature_key.clone()),
        "the losing branch's key is gone from the roster"
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
