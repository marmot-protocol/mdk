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
    }
}

/// Set the entry of slot `n`, labelled `label`, to carry tag signature key
/// `key`.
fn set_key(gid: &GroupId, n: u8, label: &str, key: u8) -> SendIntent {
    roster_update(
        gid,
        vec![DeviceRosterOperationV1::SetDevice(
            slot(n),
            DeviceEntryV1 {
                tag_signature_key: Some(vec![key; 32]),
                ..entry(label)
            },
        )],
    )
}

/// Record slot `n`, which holds no device, as `removed` with key `key`.
fn record_removed(gid: &GroupId, n: u8, key: u8) -> SendIntent {
    roster_update(
        gid,
        vec![DeviceRosterOperationV1::SetRejectedSlot(
            slot(n),
            RejectedSlotV1 {
                reason: RejectedSlotReasonV1::Removed,
                rejected_at: 1,
                tag_signature_key: Some(vec![key; 32]),
            },
        )],
    )
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
    for intent in [set_key(&gid, 2, "Laptop", 0xb2), record_removed(&gid, 3, 0xb3)] {
        let commit = send_commit(&mut phone, intent, &gid).await;
        assert_accepted(&mut laptop, &commit, &gid).await;
    }
    let expected = BTreeSet::from([tag_key(1, 0xa1), tag_key(2, 0xb2), tag_key(3, 0xb3)]);
    for device in [&phone, &laptop] {
        assert_eq!(recorded(device, &gid), expected);
    }
}

/// One pass applies two commits: the first records slot 3 as `removed`, the
/// second drops that record, as an expiry pass does. The roster at the end
/// of the pass never held the record, yet its key is recorded.
#[tokio::test]
async fn a_removed_record_dropped_within_one_pass_is_recorded() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let before_pass = recorded(&laptop, &gid);
    let first = send_commit(&mut phone, record_removed(&gid, 3, 0xc3), &gid).await;
    let second = send_commit(
        &mut phone,
        roster_update(
            &gid,
            vec![DeviceRosterOperationV1::RemoveRejectedSlot(slot(3))],
        ),
        &gid,
    )
    .await;
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
    assert!(!roster_of(&laptop, &gid).rejected_slots.contains_key(&slot(3)));
    let mut expected = before_pass;
    expected.insert(tag_key(3, 0xc3));
    assert_eq!(recorded(&laptop, &gid), expected);
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
