//! Sending sibling Welcomes (mdk#2628 3.5b, device-group.md "Sending a
//! sibling Welcome").
//!
//! A same-account Add names, for each KeyPackage, the slot of the sibling
//! that handed it over. Its Commit stages one sibling Welcome row per
//! KeyPackage instead of a transport Welcome: the encoded `SiblingWelcome`
//! the host sends as a kind-461 message in the device group. The row is owed
//! once the Commit confirms, fails with a Commit that rolls back, and settles
//! unsent when its KeyPackage expires. The host records each 461's app event
//! id on the row before the send, marks the row delivered by that carrier,
//! and clears a failed carrier so the row is owed again. Every refusal comes
//! before anything is written.

use super::device_roster::{found_device_group, key_package_ref, roster, roster_device, slot};
use super::device_tag::{hold_slot, set_own_key};
use super::send_intents::Untouched;
use super::*;
use cgka_engine::OwedSiblingWelcome;
use cgka_engine::private_key_packages::SiblingWelcome;
use cgka_traits::app_components::{
    DeviceSlotId, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, encode_nostr_routing_v1,
};
use cgka_traits::engine::KeyPackageSource;
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::types::EpochId;
use cgka_traits::welcome::SiblingWelcomeJoin::Settled;

/// The one relay every routed chat names.
const RELAY: &str = "wss://relay.example";
const NOW: u64 = 1_000;

/// A device of `account` that joins routed chats but no device group.
pub(super) fn chat_device(account: &[u8]) -> Device {
    device_advertising(
        account,
        &[ACCOUNT_DEVICES_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID],
        Box::<MockPeeler>::default(),
    )
}

/// The first device of `account` and `new` more, in the account's device
/// group, whose id it returns: the first at slot 1 and each of the others at
/// the slot after, every one tagged.
pub(super) async fn tagged_devices(account: &[u8], new: usize) -> (Device, Vec<Device>, GroupId) {
    let mut devices: Vec<Device> = (0..=new).map(|_| roster_device(account)).collect();
    let labels = [(1, "Phone"), (2, "Laptop"), (3, "Tablet")];
    let (first, rest) = devices.split_first_mut().unwrap();
    let mut joiners: Vec<&mut Device> = rest.iter_mut().collect();
    let device_gid = found_device_group(first, &roster(&labels[..=new]), &mut joiners).await;
    for index in 0..devices.len() {
        let own = slot(u8::try_from(index + 1).unwrap());
        let (before, rest) = devices.split_at_mut(index);
        let (device, after) = rest.split_first_mut().unwrap();
        hold_slot(device, own);
        device
            .engine
            .set_device_tag_group(Some(device_gid.clone()))
            .unwrap();
        let mut others: Vec<&mut Device> = before.iter_mut().chain(after.iter_mut()).collect();
        set_own_key(device, own, &device_gid, &mut others).await;
    }
    let first = devices.remove(0);
    (first, devices, device_gid)
}

/// `founder` founds a chat routed through [`RELAY`] that each of `joiners`
/// joins from its Welcome. Every founder advertises 0x800d, so the chat
/// requires it.
pub(super) async fn found_routed_group(
    founder: &mut Device,
    joiners: &mut [&mut Device],
) -> GroupId {
    let mut key_packages = Vec::new();
    for joiner in joiners.iter_mut() {
        key_packages.push(joiner.engine.fresh_key_package().await.unwrap());
    }
    let routing = NostrRoutingV1::new([0x43; 32], vec![RELAY.into()]).unwrap();
    let (gid, created) = founder
        .engine
        .create_group(CreateGroupRequest {
            name: "routed".into(),
            description: String::new(),
            members: key_packages,
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: encode_nostr_routing_v1(&routing).unwrap(),
            }],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    for (joiner, welcome) in joiners.iter_mut().zip(welcomes) {
        joiner.engine.join_welcome(welcome).await.unwrap();
    }
    assert!(requires_account_devices(&founder.engine, &gid));
    gid
}

/// [`members`] in a chat routed through [`RELAY`], with `alice` and `bob`
/// as given.
pub(super) async fn routed_members(mut alice: Device, mut bob: Device) -> Members {
    let mut bob_sibling = chat_device(b"bob");
    let mut carol = chat_device(b"carol");
    let gid = found_routed_group(&mut alice, &mut [&mut bob, &mut bob_sibling, &mut carol]).await;
    Members {
        alice,
        bob,
        bob_sibling,
        carol,
        gid,
    }
}

/// [`routed_members`] where bob is tagged at slot 1 of his device group,
/// beside `new` more of his devices outside the chat.
pub(super) async fn siblings(new: usize) -> (Members, Vec<Device>) {
    let (bob, new, _) = tagged_devices(b"bob", new).await;
    (routed_members(chat_device(b"alice"), bob).await, new)
}

/// A private KeyPackage that `sibling`, at `slot`, issues to the device at
/// `to`, as its hand-off gives it.
pub(super) fn handed(
    sibling: &mut Device,
    slot: DeviceSlotId,
    to: DeviceSlotId,
) -> SiblingKeyPackage {
    let before = sibling.engine.issued_private_key_packages().unwrap();
    sibling
        .engine
        .issue_private_key_packages(&to, 1, None, NOW)
        .unwrap();
    let issued = sibling
        .engine
        .issued_private_key_packages()
        .unwrap()
        .into_iter()
        .find(|record| !before.contains(record))
        .unwrap();
    SiblingKeyPackage {
        slot,
        key_package: KeyPackage::new(issued.key_package)
            .with_protocol_profile(ProtocolProfile::Current),
    }
}

/// The sibling Welcomes `device` owes now.
pub(super) fn owed(device: &Device) -> Vec<OwedSiblingWelcome> {
    device.engine.owed_sibling_welcomes(Timestamp(NOW)).unwrap()
}

/// `sibling` joins `gid` through `owed` and names `adder` as its author.
pub(super) async fn assert_joins_from(
    sibling: &mut Device,
    owed: &OwedSiblingWelcome,
    gid: &GroupId,
    adder: &Device,
) {
    let welcome = SiblingWelcome::decode(&owed.content).unwrap();
    assert_eq!(
        sibling
            .engine
            .join_sibling_welcome(&hash_id(&owed.content), &welcome, None)
            .await
            .unwrap(),
        Settled(IngestOutcome::Processed)
    );
    let welcomers: Vec<_> = sibling
        .engine
        .drain_events()
        .into_iter()
        .filter_map(|event| match event {
            GroupEvent::GroupJoined {
                group_id, welcomer, ..
            } if &group_id == gid => welcomer,
            _ => None,
        })
        .collect();
    assert_eq!(welcomers, vec![adder.engine.self_id()]);
    assert_eq!(
        sibling.engine.epoch(gid).unwrap(),
        adder.engine.epoch(gid).unwrap()
    );
}

/// `device`'s sibling Welcome rows in `gid`.
fn sibling_rows(device: &Device, gid: &GroupId) -> Vec<(MessageState, StoredMessagePayload)> {
    device
        .storage
        .list_messages(gid, EpochId(0))
        .unwrap()
        .into_iter()
        .filter_map(|record| {
            let payload = StoredMessagePayload::decode(&record.payload).ok()?;
            matches!(
                payload,
                StoredMessagePayload::StagedSiblingWelcome { .. }
                    | StoredMessagePayload::OutboundSiblingWelcome { .. }
            )
            .then_some((record.state, payload))
        })
        .collect()
}

fn rows(device: &Device, gid: &GroupId) -> Vec<MessageRecord> {
    device.storage.list_messages(gid, EpochId(0)).unwrap()
}

/// bob adds his laptop to the chat. The Commit stages a sibling Welcome
/// instead of a transport Welcome, owed only once the Commit confirms: the
/// encoded `SiblingWelcome` from bob's slot to the laptop's, naming the
/// handed KeyPackage and the chat's relay. Every member accepts the Commit,
/// and the laptop joins through the sibling Welcome, consuming the private
/// KeyPackage.
#[tokio::test]
async fn a_sibling_add_owes_its_sibling_welcome_once_its_commit_confirms() {
    let (mut m, mut new) = siblings(1).await;
    let gid = m.gid.clone();
    let laptop = &mut new[0];
    let sibling = handed(laptop, slot(2), slot(1));
    let SendResult::GroupEvolution {
        msg,
        welcomes,
        pending,
    } = m
        .bob
        .engine
        .send(add_own_devices(&gid, vec![sibling.clone()]))
        .await
        .unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    assert!(welcomes.is_empty(), "{welcomes:?}");
    assert!(owed(&m.bob).is_empty());
    let [(MessageState::Sent, StoredMessagePayload::StagedSiblingWelcome { .. })] =
        &sibling_rows(&m.bob, &gid)[..]
    else {
        panic!("one staged sibling Welcome")
    };

    m.bob.engine.confirm_published(pending).await.unwrap();
    let [owed] = &owed(&m.bob)[..] else {
        panic!("one owed sibling Welcome")
    };
    assert_eq!((&owed.group_id, &owed.carrier), (&gid, &None));
    let welcome = SiblingWelcome::decode(&owed.content).unwrap();
    assert_eq!(
        (welcome.from, welcome.to, welcome.relays),
        (slot(1), slot(2), vec![RELAY.to_string()])
    );
    assert_eq!(
        welcome.key_package_ref,
        key_package_ref(&sibling.key_package)
    );

    let add = route_to_group(&msg, &gid);
    for member in [&mut m.alice, &mut m.bob_sibling, &mut m.carol] {
        assert_accepted(member, &add, &gid).await;
    }
    assert_joins_from(laptop, owed, &gid, &m.bob).await;
    assert!(
        laptop
            .engine
            .issued_private_key_packages()
            .unwrap()
            .is_empty()
    );
}

/// The host records a 461's app event id on the row before its send. A
/// second carrier is refused while one is on its way; only the carrier that
/// failed clears, and the row is owed again; only the carrier that went out
/// marks it delivered, and a delivered row is owed no more.
#[tokio::test]
async fn a_sibling_welcome_is_delivered_only_by_its_carrier() {
    let (mut m, mut new) = siblings(1).await;
    let gid = m.gid.clone();
    let sibling = handed(&mut new[0], slot(2), slot(1));
    send_commit(&mut m.bob, add_own_devices(&gid, vec![sibling]), &gid).await;
    let [owed_now] = &owed(&m.bob)[..] else {
        panic!("one owed sibling Welcome")
    };
    let id = &owed_now.id;
    let engine = &m.bob.engine;

    assert!(engine.carry_sibling_welcome(id, b"first").unwrap());
    assert!(!engine.carry_sibling_welcome(id, b"second").unwrap());
    assert_eq!(owed(&m.bob)[0].carrier.as_deref(), Some(&b"first"[..]));
    assert!(!engine.sibling_welcome_send_failed(id, b"second").unwrap());
    assert!(!engine.sibling_welcome_delivered(id, b"second").unwrap());
    assert!(engine.sibling_welcome_send_failed(id, b"first").unwrap());
    assert_eq!(owed(&m.bob)[0].carrier, None);

    assert!(engine.carry_sibling_welcome(id, b"second").unwrap());
    assert!(!engine.sibling_welcome_delivered(id, b"first").unwrap());
    assert!(engine.sibling_welcome_delivered(id, b"second").unwrap());
    assert!(owed(&m.bob).is_empty());
    assert!(!engine.carry_sibling_welcome(id, b"third").unwrap());
    assert!(!engine.sibling_welcome_send_failed(id, b"second").unwrap());
    let [(MessageState::Processed, _)] = &sibling_rows(&m.bob, &gid)[..] else {
        panic!("one delivered sibling Welcome")
    };
}

/// A sibling Welcome is owed until its KeyPackage expires, when the sibling
/// drops the key, and then settles unsent.
#[tokio::test]
async fn a_sibling_welcome_settles_unsent_when_its_key_package_expires() {
    let (mut m, mut new) = siblings(1).await;
    let gid = m.gid.clone();
    let sibling = handed(&mut new[0], slot(2), slot(1));
    let not_after = cgka_engine::key_package::key_package_metadata(&sibling.key_package)
        .unwrap()
        .not_after;
    send_commit(&mut m.bob, add_own_devices(&gid, vec![sibling]), &gid).await;
    let owed_at = |now| m.bob.engine.owed_sibling_welcomes(Timestamp(now)).unwrap();
    assert_eq!(owed_at(not_after - 1).len(), 1);
    assert!(owed_at(not_after).is_empty());
}

/// A sibling Welcome fails with its Commit: when the publish fails, and when
/// a restart rolls back the staged Commit. Neither is ever owed.
#[tokio::test]
async fn a_sibling_welcome_fails_with_its_commit() {
    let (mut m, mut new) = siblings(2).await;
    let gid = m.gid.clone();
    let laptop = handed(&mut new[0], slot(2), slot(1));
    let tablet = handed(&mut new[1], slot(3), slot(1));

    let SendResult::GroupEvolution { pending, .. } = m
        .bob
        .engine
        .send(add_own_devices(&gid, vec![laptop]))
        .await
        .unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    m.bob.engine.publish_failed(pending).await.unwrap();
    assert!(owed(&m.bob).is_empty());
    let [(MessageState::Failed, _)] = &sibling_rows(&m.bob, &gid)[..] else {
        panic!("one failed sibling Welcome")
    };

    m.bob
        .engine
        .send(add_own_devices(&gid, vec![tablet]))
        .await
        .unwrap();
    let Device { engine, storage } = m.bob;
    drop(engine);
    let mut bob = super::device_roster::roster_device_on(storage, b"bob");
    bob.engine.hydrate_all_stored_groups().unwrap();
    assert!(load_group(&bob, &gid).pending_commit().is_none());
    assert!(owed(&bob).is_empty());
    let states: Vec<_> = sibling_rows(&bob, &gid)
        .into_iter()
        .map(|(state, _)| state)
        .collect();
    assert_eq!(states, vec![MessageState::Failed; 2]);
}

/// Each sibling Add the sender cannot back with a sibling Welcome is refused
/// before anything is written: the chat's rows, record and epoch stay as they
/// were, and no Commit is left staged, so a valid Add still goes through.
#[tokio::test]
async fn a_sibling_add_refused_for_its_welcome_writes_nothing() {
    let (bob, mut new, device_gid) = tagged_devices(b"bob", 2).await;
    let mut m = routed_members(chat_device(b"alice"), bob).await;
    let gid = m.gid.clone();
    let laptop = handed(&mut new[0], slot(2), slot(1));
    let tablet = handed(&mut new[1], slot(3), slot(1));
    let named = |sibling: &SiblingKeyPackage, n: u8| SiblingKeyPackage {
        slot: slot(n),
        ..sibling.clone()
    };
    let published = SiblingKeyPackage {
        key_package: KeyPackage {
            source: Some(KeyPackageSource {
                event_id: hash_id(b"published"),
            }),
            ..laptop.key_package.clone()
        },
        ..laptop.clone()
    };
    let untagged = SiblingKeyPackage {
        slot: slot(2),
        key_package: new_sibling_key_package(&mut m.bob, b"bob").await,
    };
    let before = (Untouched::of(&m.bob, &gid), rows(&m.bob, &gid));
    let assert_untouched = |bob: &Device| {
        assert_eq!((Untouched::of(bob, &gid), rows(bob, &gid)), before);
    };
    for (siblings, reason) in [
        (
            vec![published],
            "a published KeyPackage never adds a sibling",
        ),
        (vec![named(&laptop, 1)], "the named slot is this device's"),
        (
            vec![laptop.clone(), named(&tablet, 2)],
            "two KeyPackages name the same sibling",
        ),
        (
            vec![named(&tablet, 2)],
            "the KeyPackage's device tag does not read as the named sibling",
        ),
        (
            vec![named(&laptop, 9)],
            "the KeyPackage's device tag does not read as the named sibling",
        ),
        (
            vec![untagged],
            "the KeyPackage's device tag does not read as the named sibling",
        ),
    ] {
        assert_refused(
            m.bob.engine.send(add_own_devices(&gid, siblings)).await,
            reason,
        );
        assert_untouched(&m.bob);
    }

    // bob is not tagged: his slot is not in the roster, or he names no
    // device group.
    hold_slot(&m.bob, slot(9));
    assert_refused(
        m.bob
            .engine
            .send(add_own_devices(&gid, vec![laptop.clone()]))
            .await,
        "this device is not tagged in a trusted device group",
    );
    assert_untouched(&m.bob);
    hold_slot(&m.bob, slot(1));
    m.bob.engine.set_device_tag_group(None).unwrap();
    assert_refused(
        m.bob
            .engine
            .send(add_own_devices(&gid, vec![laptop.clone()]))
            .await,
        "this device is not tagged in a trusted device group",
    );
    assert_untouched(&m.bob);
    m.bob.engine.set_device_tag_group(Some(device_gid)).unwrap();

    // A chat that names no relay.
    let mut alice = chat_device(b"alice");
    let bob_kp = m.bob.engine.fresh_key_package().await.unwrap();
    let unrouted = found_group(&mut alice, vec![bob_kp], true, &mut [&mut m.bob]).await;
    let unrouted_before = (Untouched::of(&m.bob, &unrouted), rows(&m.bob, &unrouted));
    assert_refused(
        m.bob
            .engine
            .send(add_own_devices(&unrouted, vec![laptop.clone()]))
            .await,
        "the chat must name one to 16 relays",
    );
    assert_eq!(
        (Untouched::of(&m.bob, &unrouted), rows(&m.bob, &unrouted)),
        unrouted_before
    );

    send_commit(
        &mut m.bob,
        add_own_devices(&gid, vec![laptop, tablet]),
        &gid,
    )
    .await;
    assert_eq!(owed(&m.bob).len(), 2);
}
