//! The link Commit, `SendIntent::LinkDevice` (mdk#2628 item 3.3b, D21): one
//! admin Commit in a device group that adds a newly linked device of the
//! account and writes its roster entry. Every member accepts it, the linked
//! device joins through its Welcome, a refused link changes nothing, and a
//! link is never queued. Its undo, `SendIntent::UnlinkDevice` (D40), removes
//! that device's leaf and entry in one Commit under the same rules.

use super::activation::{buffer_unsettled, queued_intents};
use super::device_roster::{
    NO_WELCOME_DEADLINE, create_under, entry, expect_link_welcome, found_device_group,
    key_package_ref, phone_and_laptop, roster, roster_device, roster_of, roster_update, slot,
};
use super::send_intents::{pending_proposals, store_pending_add};
use super::*;
use cgka_engine::engine::OutboundWelcomeStatus;
use cgka_traits::app_components::{
    DeviceEntryV1, DeviceRosterOperationV1, DeviceRosterUpdateV1, MAX_LEAVES_PER_ACCOUNT,
    RejectedSlotReasonV1, RejectedSlotV1, encode_device_roster_update_v1,
};
use openmls::prelude::ProposalOrRefType;

/// The sender rule's refusal of an Add without its roster entry.
const UNANNOUNCED: &str = "a device group's Commit that adds a device sets its roster entry, for a new slot, announcing the added KeyPackage";

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
        deliver_until: NO_WELCOME_DEADLINE,
    }
}

/// A link's Welcome keeps its delivery deadline, staged with the Commit and
/// once the Commit confirms, and the linker counts it as settled from then
/// on: it is never published once the new device stopped waiting (D40).
#[tokio::test]
async fn a_links_welcome_keeps_its_delivery_deadline() {
    let (mut phone, _laptop, gid) = phone_and_laptop().await;
    let key_package = roster_device(b"alice")
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    let deadline = Timestamp(1_700_000_600);
    let mut intent = link(
        &gid,
        &key_package,
        vec![DeviceRosterOperationV1::SetDevice(
            slot(3),
            linked_entry("Tablet", &key_package),
        )],
    );
    let SendIntent::LinkDevice { deliver_until, .. } = &mut intent else {
        unreachable!()
    };
    *deliver_until = deadline;

    let SendResult::GroupEvolution {
        welcomes, pending, ..
    } = phone.engine.send(intent).await.unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    let id = &welcomes[0].id;
    assert!(phone.engine.sent_welcome_awaits_commit(id).unwrap());
    assert_eq!(
        phone.engine.sent_welcome_deliver_until(id).unwrap(),
        Some(deadline)
    );

    phone.engine.confirm_published(pending).await.unwrap();
    assert!(!phone.engine.sent_welcome_awaits_commit(id).unwrap());
    assert_eq!(
        phone.engine.sent_welcome_deliver_until(id).unwrap(),
        Some(deadline),
        "promotion keeps the deadline"
    );
    assert!(matches!(
        phone
            .engine
            .outbound_welcome_status(id, Timestamp(deadline.0 - 1))
            .unwrap(),
        OutboundWelcomeStatus::Owed { .. }
    ));
    assert_eq!(
        phone.engine.outbound_welcome_status(id, deadline).unwrap(),
        OutboundWelcomeStatus::Settled
    );
}

#[tokio::test]
async fn a_link_adds_the_device_and_writes_its_entry_in_one_commit() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let mut expected = roster_of(&phone, &gid);
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
    expect_link_welcome(&mut tablet, &gid, &phone, &key_package);
    assert_joins(&mut tablet, &welcomes[0], &gid, &phone).await;

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

/// A link's Welcome keeps the `KeyPackageRef` of the KeyPackage it answers
/// while staged, once owed and once withdrawn, and so does a device group's
/// founding Welcome, so a device that lost a Welcome's id after the commit
/// still finds it by that KeyPackage (D40). A KeyPackage no relay published
/// has one too. A link retried after its commit rolled back finds both of
/// its Welcomes.
#[tokio::test]
async fn a_welcome_is_found_by_its_key_package_ref() {
    let mut first = roster_device(b"alice");
    let laptop_key_package = roster_device(b"alice")
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    assert!(laptop_key_package.source.is_none());
    let founding_ref = key_package_ref(&laptop_key_package);
    let (founded, created) = create_under(
        &mut first,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        vec![laptop_key_package],
        &GroupId::new(vec![0x42; 16]),
    )
    .await
    .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    assert_eq!(
        first
            .engine
            .sent_welcomes_for_key_package(&founded, &founding_ref)
            .unwrap(),
        vec![welcomes[0].id.clone()]
    );

    let (mut phone, _laptop, gid) = phone_and_laptop().await;
    let key_package = roster_device(b"alice")
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    let link_ref = key_package_ref(&key_package);
    let intent = link(
        &gid,
        &key_package,
        vec![DeviceRosterOperationV1::SetDevice(
            slot(3),
            linked_entry("Tablet", &key_package),
        )],
    );
    let found = |phone: &Device| {
        phone
            .engine
            .sent_welcomes_for_key_package(&gid, &link_ref)
            .unwrap()
    };
    let attempt = async |phone: &mut Device| {
        let SendResult::GroupEvolution {
            welcomes, pending, ..
        } = phone.engine.send(intent.clone()).await.unwrap()
        else {
            panic!("expected GroupEvolution")
        };
        (welcomes[0].id.clone(), pending)
    };
    let (rolled_back, pending) = attempt(&mut phone).await;
    assert_eq!(found(&phone), vec![rolled_back.clone()], "staged");
    phone.engine.publish_failed(pending).await.unwrap();
    let (welcome, pending) = attempt(&mut phone).await;
    let both = vec![rolled_back, welcome.clone()];
    assert_eq!(found(&phone), both, "retried");
    phone.engine.confirm_published(pending).await.unwrap();
    assert_eq!(found(&phone), both, "owed");
    phone.engine.withdraw_sent_welcome(&welcome).unwrap();
    assert_eq!(found(&phone), both, "withdrawn");
    assert!(
        phone
            .engine
            .sent_welcomes_for_key_package(&gid, &founding_ref)
            .unwrap()
            .is_empty()
    );
}

fn unlink(
    gid: &GroupId,
    leaf_signature_key: Vec<u8>,
    operations: Vec<DeviceRosterOperationV1>,
) -> SendIntent {
    SendIntent::UnlinkDevice {
        group_id: gid.clone(),
        leaf_signature_key,
        roster_update: update(operations),
    }
}

/// Link a tablet into the phone and laptop's device group, and let it join.
async fn link_tablet(phone: &mut Device, laptop: &mut Device, gid: &GroupId) -> Device {
    let mut tablet = roster_device(b"alice");
    let key_package = tablet.engine.fresh_key_package().await.unwrap();
    let intent = link(
        gid,
        &key_package,
        vec![DeviceRosterOperationV1::SetDevice(
            slot(3),
            linked_entry("Tablet", &key_package),
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
    phone.engine.confirm_published(pending).await.unwrap();
    assert_accepted(laptop, &route_to_group(&msg, gid), gid).await;
    expect_link_welcome(&mut tablet, gid, phone, &key_package);
    assert_joins(&mut tablet, &welcomes[0], gid, phone).await;
    tablet
}

/// The unlink removes the device's leaf and writes its roster entry away in
/// one privileged Commit, with no Welcome. Every member accepts it, and the
/// removed device sees itself removed.
#[tokio::test]
async fn an_unlink_removes_the_device_and_its_entry_in_one_commit() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let expected = roster_of(&phone, &gid);
    let mut tablet = link_tablet(&mut phone, &mut laptop, &gid).await;
    let intent = unlink(
        &gid,
        signature_key(&tablet, &gid),
        vec![DeviceRosterOperationV1::RemoveDevice(slot(3))],
    );

    let SendResult::GroupEvolution {
        msg,
        welcomes,
        pending,
    } = phone.engine.send(intent).await.unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    assert!(welcomes.is_empty());
    phone.engine.confirm_published(pending).await.unwrap();
    let commit = route_to_group(&msg, &gid);
    assert_priorities(
        &phone,
        &commit,
        &mut [&mut laptop],
        &gid,
        CommitOrderingPriority::Privileged,
    )
    .await;
    assert_accepted(&mut tablet, &commit, &gid).await;
    assert!(tablet.engine.group_record(&gid).unwrap().removed);

    for device in [&phone, &laptop] {
        assert_eq!(roster_of(device, &gid), expected);
        assert_eq!(load_group(device, &gid).members().count(), 2);
    }
}

/// The engine reads its own tree for the leaf: when the linked device's leaf
/// is already gone (here an earlier Commit removed only the leaf), the
/// unlink still removes its roster entry, in a Commit that removes no leaf.
#[tokio::test]
async fn an_unlink_whose_leaf_is_gone_removes_only_the_entry() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let expected = roster_of(&phone, &gid);
    let tablet = link_tablet(&mut phone, &mut laptop, &gid).await;
    let tablet_key = signature_key(&tablet, &gid);
    let leaf_only = send_commit(
        &mut phone,
        SendIntent::RemoveOwnAccountDevices {
            group_id: gid.clone(),
            leaf_signature_keys: vec![tablet_key.clone()],
        },
        &gid,
    )
    .await;
    assert_accepted(&mut laptop, &leaf_only, &gid).await;
    assert_eq!(load_group(&phone, &gid).members().count(), 2);
    assert!(roster_of(&phone, &gid).devices.contains_key(&slot(3)));

    let commit = send_commit(
        &mut phone,
        unlink(
            &gid,
            tablet_key,
            vec![DeviceRosterOperationV1::RemoveDevice(slot(3))],
        ),
        &gid,
    )
    .await;
    assert_accepted(&mut laptop, &commit, &gid).await;
    for device in [&phone, &laptop] {
        assert_eq!(roster_of(device, &gid), expected);
        assert_eq!(load_group(device, &gid).members().count(), 2);
    }
}

/// An unlink names one other leaf of the account and removes exactly one
/// listed device entry; anything else is refused with nothing staged.
#[tokio::test]
async fn a_refused_unlink_leaves_the_group_as_it_was() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let tablet = link_tablet(&mut phone, &mut laptop, &gid).await;
    let tablet_key = signature_key(&tablet, &gid);
    let remove = |n: u8| DeviceRosterOperationV1::RemoveDevice(slot(n));
    let epoch = phone.engine.epoch(&gid).unwrap();
    let held = roster_of(&phone, &gid);

    let cases = [
        (
            unlink(&gid, tablet_key.clone(), vec![remove(3), remove(2)]),
            "it must remove exactly one device entry",
        ),
        (
            unlink(&gid, tablet_key.clone(), vec![reject_slot(3)]),
            "it must remove exactly one device entry",
        ),
        (
            unlink(&gid, tablet_key.clone(), vec![remove(4)]),
            "the roster lists no such device",
        ),
        (
            unlink(&gid, signature_key(&phone, &gid), vec![remove(1)]),
            "use SendIntent::Leave to remove this device",
        ),
    ];
    for (intent, reason) in cases {
        assert_refused(phone.engine.send(intent).await, reason);
    }
    assert_eq!(phone.engine.epoch(&gid).unwrap(), epoch);
    assert_eq!(roster_of(&phone, &gid), held);
    assert_eq!(load_group(&phone, &gid).members().count(), 3);
    assert!(queued_intents(&phone, &gid).is_empty());
}

/// Like a link, an unlink while the device group is unsettled is refused,
/// not queued, and goes out once the group settles.
#[tokio::test]
async fn an_unlink_is_refused_not_queued_while_a_commit_is_in_flight() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let tablet = link_tablet(&mut phone, &mut laptop, &gid).await;
    let intent = unlink(
        &gid,
        signature_key(&tablet, &gid),
        vec![DeviceRosterOperationV1::RemoveDevice(slot(3))],
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
        matches!(&refused, Err(EngineError::LinkDeviceUnsettled { group_id }) if *group_id == gid),
        "{refused:?}"
    );
    assert!(queued_intents(&phone, &gid).is_empty());

    phone.engine.confirm_published(pending).await.unwrap();
    send_commit(&mut phone, intent, &gid).await;
    assert!(!roster_of(&phone, &gid).devices.contains_key(&slot(3)));
}
