//! The link Commit, `SendIntent::LinkDevice` (mdk#2628 item 3.3b, D21): one
//! admin Commit in a device group that adds a newly linked device of the
//! account and writes its roster entry. Every member accepts it, the linked
//! device joins through its Welcome, a refused link changes nothing, and a
//! link is never queued.

use super::activation::{buffer_unsettled, queued_intents};
use super::device_roster::{
    entry, found_device_group, phone_and_laptop, roster, roster_device, roster_of, roster_update,
    slot,
};
use super::send_intents::{pending_proposals, store_pending_add};
use super::*;
use cgka_traits::app_components::{
    DeviceEntryV1, DeviceRosterOperationV1, DeviceRosterUpdateV1, MAX_LEAVES_PER_ACCOUNT,
    RejectedSlotReasonV1, RejectedSlotV1, encode_device_roster_update_v1,
};
use openmls::prelude::ProposalOrRefType;

/// The sender rule's refusal of an Add without its roster entry.
const UNANNOUNCED: &str = "a device group's Commit that adds a device sets its roster entry, for a new slot, announcing the added KeyPackage";

fn key_package_ref(key_package: &KeyPackage) -> Vec<u8> {
    hex::decode(
        cgka_engine::key_package::key_package_metadata(key_package)
            .unwrap()
            .key_package_ref_hex,
    )
    .unwrap()
}

/// The entry a link writes for the device in `key_package`.
fn linked_entry(label: &str, key_package: &KeyPackage) -> DeviceEntryV1 {
    DeviceEntryV1 {
        linked_by: Some(slot(1)),
        announced_key_package: Some(key_package_ref(key_package)),
        ..entry(label)
    }
}

fn update(operations: Vec<DeviceRosterOperationV1>) -> Vec<u8> {
    encode_device_roster_update_v1(&DeviceRosterUpdateV1::new(operations).unwrap()).unwrap()
}

fn link(
    gid: &GroupId,
    key_package: &KeyPackage,
    operations: Vec<DeviceRosterOperationV1>,
) -> SendIntent {
    SendIntent::LinkDevice {
        group_id: gid.clone(),
        key_package: key_package.clone(),
        roster_update: update(operations),
    }
}

#[tokio::test]
async fn a_link_adds_the_device_and_writes_its_entry_in_one_commit() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let mut tablet = roster_device(b"alice");
    let key_package = tablet.engine.fresh_key_package().await.unwrap();
    let tablet_entry = linked_entry("Tablet", &key_package);
    let intent = link(
        &gid,
        &key_package,
        vec![DeviceRosterOperationV1::SetDevice(
            slot(3),
            tablet_entry.clone(),
        )],
    );

    let SendResult::GroupEvolution {
        msg,
        welcomes,
        pending,
    } = phone.engine.send(intent).await.unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    assert_eq!(welcomes.len(), 1, "one Welcome, for the linked device");
    phone.engine.confirm_published(pending).await.unwrap();
    let commit = route_to_group(&msg, &gid);

    // The Commit writes the roster, so it needs an admin and is privileged.
    assert_priorities(
        &phone,
        &commit,
        &mut [&mut laptop],
        &gid,
        CommitOrderingPriority::Privileged,
    )
    .await;
    assert_joins(&mut tablet, &welcomes[0], &gid, &phone).await;

    let mut expected = roster(&[(1, "Phone"), (2, "Laptop")]);
    expected.devices.insert(slot(3), tablet_entry);
    for device in [&phone, &laptop, &tablet] {
        assert_eq!(roster_of(device, &gid), expected);
        assert_eq!(load_group(device, &gid).members().count(), 3);
    }
}

/// The link Commit carries its own Add and roster update, by value, and
/// nothing else: an Add pending in the linker's proposal store stays there,
/// while the Commit is staged and after its publish fails.
#[tokio::test]
async fn a_link_leaves_pending_proposals_alone() {
    let (mut phone, _laptop, gid) = phone_and_laptop().await;
    let pending_kp = roster_device(b"alice")
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    store_pending_add(&phone, &gid, &pending_kp);
    assert_eq!(pending_proposals(&phone, &gid), 1);

    let key_package = roster_device(b"alice")
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    let intent = link(
        &gid,
        &key_package,
        vec![DeviceRosterOperationV1::SetDevice(
            slot(3),
            linked_entry("Tablet", &key_package),
        )],
    );
    let SendResult::GroupEvolution {
        welcomes, pending, ..
    } = phone.engine.send(intent).await.unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    assert_eq!(welcomes.len(), 1);
    let group = load_group(&phone, &gid);
    let staged = group.pending_commit().expect("the Commit is staged");
    assert!(
        staged
            .queued_proposals()
            .all(|queued| queued.proposal_or_ref_type() == ProposalOrRefType::Proposal),
        "every proposal is carried by value"
    );
    assert_eq!(staged.add_proposals().count(), 1);
    assert_eq!(
        staged.queued_proposals().count(),
        2,
        "the Add and the roster update"
    );
    assert_eq!(pending_proposals(&phone, &gid), 1);

    phone.engine.publish_failed(pending).await.unwrap();
    assert!(load_group(&phone, &gid).pending_commit().is_none());
    assert_eq!(pending_proposals(&phone, &gid), 1);
}

#[tokio::test]
async fn a_refused_link_leaves_the_group_as_it_was() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let mut tablet = roster_device(b"alice");
    let key_package = tablet.engine.fresh_key_package().await.unwrap();
    let set = |n: u8, entry: DeviceEntryV1| DeviceRosterOperationV1::SetDevice(slot(n), entry);
    let epoch = phone.engine.epoch(&gid).unwrap();
    let held = roster_of(&phone, &gid);

    // The update sets exactly one device entry, and the Commit meets the
    // sender rule: the entry is for a new slot and announces the linked
    // KeyPackage.
    let cases = [
        (
            vec![
                set(3, linked_entry("Tablet", &key_package)),
                DeviceRosterOperationV1::RemoveDevice(slot(2)),
            ],
            "it must set exactly one device entry",
        ),
        (
            vec![DeviceRosterOperationV1::RemoveDevice(slot(2))],
            "it must set exactly one device entry",
        ),
        (
            vec![set(3, linked_entry("Tablet", &key_package)), reject_slot(4)],
            "it must set exactly one device entry",
        ),
        (
            vec![set(2, linked_entry("Tablet", &key_package))],
            UNANNOUNCED,
        ),
        (vec![set(3, entry("Tablet"))], UNANNOUNCED),
    ];
    for (operations, reason) in cases {
        assert_refused(
            phone
                .engine
                .send(link(&gid, &key_package, operations))
                .await,
            reason,
        );
    }

    // The KeyPackage is this account's, and not a device already here.
    let mut bob = roster_device(b"bob");
    let bobs = bob.engine.fresh_key_package().await.unwrap();
    assert_refused(
        phone
            .engine
            .send(link(&gid, &bobs, vec![set(3, linked_entry("Bob", &bobs))]))
            .await,
        "the KeyPackage to link belongs to another account",
    );
    let laptops = laptop.engine.fresh_key_package().await.unwrap();
    assert_refused(
        phone
            .engine
            .send(link(
                &gid,
                &laptops,
                vec![set(3, linked_entry("Laptop", &laptops))],
            ))
            .await,
        "the device to link is already in the device group",
    );

    // It advertises everything the device group requires.
    let mut old = device(b"alice", true);
    let olds = old.engine.fresh_key_package().await.unwrap();
    let refused = phone
        .engine
        .send(link(&gid, &olds, vec![set(3, linked_entry("Old", &olds))]))
        .await;
    assert!(
        matches!(
            refused,
            Err(EngineError::MissingRequiredCapabilities { .. })
        ),
        "{refused:?}"
    );

    // The group is where it was, and the next send works.
    assert_eq!(phone.engine.epoch(&gid).unwrap(), epoch);
    assert_eq!(roster_of(&phone, &gid), held);
    assert!(load_group(&phone, &gid).pending_commit().is_none());
    send_commit(
        &mut phone,
        link(
            &gid,
            &key_package,
            vec![set(3, linked_entry("Tablet", &key_package))],
        ),
        &gid,
    )
    .await;
}

#[tokio::test]
async fn a_link_needs_a_device_group() {
    let mut alice = roster_device(b"alice");
    let mut bob = roster_device(b"bob");
    let (gid, _) = create(
        &mut alice,
        vec![bob.engine.fresh_key_package().await.unwrap()],
        vec![],
    )
    .await
    .unwrap();
    let mut tablet = roster_device(b"alice");
    let key_package = tablet.engine.fresh_key_package().await.unwrap();
    let refused = alice
        .engine
        .send(link(
            &gid,
            &key_package,
            vec![DeviceRosterOperationV1::SetDevice(
                slot(3),
                linked_entry("Tablet", &key_package),
            )],
        ))
        .await;
    assert!(
        matches!(
            &refused,
            Err(EngineError::InvalidTransition(transition))
                if transition.from == "DeviceRosterNotRequired"
        ),
        "{refused:?}"
    );
}

/// A device joins the device group only through a link, never by an Invite
/// or a same-account Add, whose Commit would write no roster entry.
#[tokio::test]
async fn a_device_joins_the_device_group_only_through_a_link() {
    let (mut phone, _laptop, gid) = phone_and_laptop().await;
    let mut tablet = roster_device(b"alice");
    let epoch = phone.engine.epoch(&gid).unwrap();
    for intent in [
        SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![tablet.engine.fresh_key_package().await.unwrap()],
            initial_admins: vec![],
        },
        SendIntent::AddOwnAccountDevices {
            group_id: gid.clone(),
            key_packages: vec![tablet.engine.fresh_key_package().await.unwrap()],
        },
    ] {
        let refused = phone.engine.send(intent).await;
        assert!(
            matches!(
                &refused,
                Err(EngineError::InvalidTransition(transition))
                    if transition.from == "DeviceGroup"
                        && transition.reason == "a device joins the device group only through LinkDevice"
            ),
            "{refused:?}"
        );
    }
    assert_eq!(phone.engine.epoch(&gid).unwrap(), epoch);
    assert_eq!(load_group(&phone, &gid).members().count(), 2);
}

/// A link is never queued: while convergence input is unsettled it is refused
/// with `LinkDeviceUnsettled` and nothing is kept. Once the group settles the
/// same link goes out.
#[tokio::test]
async fn a_link_is_refused_not_queued_while_convergence_is_unsettled() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let mut tablet = roster_device(b"alice");
    let key_package = tablet.engine.fresh_key_package().await.unwrap();
    let intent = link(
        &gid,
        &key_package,
        vec![DeviceRosterOperationV1::SetDevice(
            slot(3),
            linked_entry("Tablet", &key_package),
        )],
    );
    let update = send_commit(
        &mut laptop,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
    buffer_unsettled(&mut phone, &update).await;

    let refused = phone.engine.send(intent.clone()).await;
    assert!(
        matches!(&refused, Err(EngineError::LinkDeviceUnsettled { group_id }) if *group_id == gid),
        "{refused:?}"
    );
    assert!(queued_intents(&phone, &gid).is_empty());

    phone
        .engine
        .converge_and_drain_queued_outbound_intents(&gid, 1_000_000)
        .await
        .unwrap();
    send_commit(&mut phone, intent, &gid).await;
    assert!(roster_of(&phone, &gid).devices.contains_key(&slot(3)));
}

/// A link while this device's own Commit awaits its publish is refused the
/// same way, and goes out once that Commit is confirmed.
#[tokio::test]
async fn a_link_while_a_commit_is_in_flight_is_refused_as_unsettled() {
    let (mut phone, _laptop, gid) = phone_and_laptop().await;
    let mut tablet = roster_device(b"alice");
    let key_package = tablet.engine.fresh_key_package().await.unwrap();
    let intent = link(
        &gid,
        &key_package,
        vec![DeviceRosterOperationV1::SetDevice(
            slot(3),
            linked_entry("Tablet", &key_package),
        )],
    );
    let SendResult::GroupEvolution { pending, .. } = phone
        .engine
        .send(SendIntent::SelfUpdate {
            group_id: gid.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected GroupEvolution")
    };

    let refused = phone.engine.send(intent.clone()).await;
    assert!(
        matches!(refused, Err(EngineError::LinkDeviceUnsettled { .. })),
        "{refused:?}"
    );
    assert!(queued_intents(&phone, &gid).is_empty());

    phone.engine.confirm_published(pending).await.unwrap();
    send_commit(&mut phone, intent, &gid).await;
}

fn reject_slot(n: u8) -> DeviceRosterOperationV1 {
    DeviceRosterOperationV1::SetRejectedSlot(
        slot(n),
        RejectedSlotV1 {
            reason: RejectedSlotReasonV1::NotMe,
            rejected_at: 1,
            tag_signature_key: None,
        },
    )
}

/// A link is checked against the roster it would leave: a slot the roster
/// rejects, or a roster already at its device cap, refuses it.
#[tokio::test]
async fn a_link_the_resulting_roster_refuses_is_refused() {
    let (mut phone, _laptop, gid) = phone_and_laptop().await;
    send_commit(&mut phone, roster_update(&gid, vec![reject_slot(3)]), &gid).await;
    let mut tablet = roster_device(b"alice");
    let key_package = tablet.engine.fresh_key_package().await.unwrap();
    assert_refused(
        phone
            .engine
            .send(link(
                &gid,
                &key_package,
                vec![DeviceRosterOperationV1::SetDevice(
                    slot(3),
                    linked_entry("Tablet", &key_package),
                )],
            ))
            .await,
        "invalid device roster update",
    );

    let mut phone = roster_device(b"alice");
    let devices: Vec<(u8, String)> = (1..=MAX_LEAVES_PER_ACCOUNT as u8)
        .map(|n| (n, format!("Device {n}")))
        .collect();
    let devices: Vec<(u8, &str)> = devices.iter().map(|(n, l)| (*n, l.as_str())).collect();
    let full = found_device_group(&mut phone, &roster(&devices), &mut []).await;
    let next = MAX_LEAVES_PER_ACCOUNT as u8 + 1;
    assert_refused(
        phone
            .engine
            .send(link(
                &full,
                &key_package,
                vec![DeviceRosterOperationV1::SetDevice(
                    slot(next),
                    linked_entry("Tablet", &key_package),
                )],
            ))
            .await,
        "invalid device roster update",
    );
}

/// No Commit this device makes in a device group takes an Add proposal from
/// the store: an intent that would is refused by the sender rule, whether it
/// would carry one such Add or two, the proposals stay pending, and a link
/// still goes out.
#[tokio::test]
async fn a_device_group_commit_takes_no_add_from_the_proposal_store() {
    let (mut phone, _laptop, gid) = phone_and_laptop().await;
    let epoch = phone.engine.epoch(&gid).unwrap();
    for (stored, reason) in [
        (1, "a device group's Commit carries its Add by value"),
        (2, "a device group's Commit adds at most one device"),
    ] {
        let pending_kp = roster_device(b"alice")
            .engine
            .fresh_key_package()
            .await
            .unwrap();
        store_pending_add(&phone, &gid, &pending_kp);
        assert_eq!(pending_proposals(&phone, &gid), stored);
        let refused = phone
            .engine
            .send(SendIntent::UpdateGroupData {
                group_id: gid.clone(),
                name: Some("Devices".into()),
                description: None,
            })
            .await;
        assert!(
            matches!(
                &refused,
                Err(EngineError::InvalidTransition(transition))
                    if transition.from == "DeviceGroup"
                        && transition.to == "Commit"
                        && transition.reason == reason
            ),
            "{refused:?}"
        );
        assert_eq!(phone.engine.epoch(&gid).unwrap(), epoch);
        assert!(load_group(&phone, &gid).pending_commit().is_none());
        assert_eq!(pending_proposals(&phone, &gid), stored);
    }

    let key_package = roster_device(b"alice")
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    send_commit(
        &mut phone,
        link(
            &gid,
            &key_package,
            vec![DeviceRosterOperationV1::SetDevice(
                slot(3),
                linked_entry("Tablet", &key_package),
            )],
        ),
        &gid,
    )
    .await;
}
