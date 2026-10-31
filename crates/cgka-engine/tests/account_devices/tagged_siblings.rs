//! Tagged siblings: the setup a test needs to add a sibling device to a chat
//! (mdk#2628 3.5b-2). A same-account Add goes through only when the adder is
//! tagged in its account's device group, each KeyPackage is a private one
//! its sibling handed over, and the chat names its relays. These build each
//! piece, so a test that adds a sibling reads as one line of setup.

use super::device_roster::{found_device_group, roster, roster_device, slot};
use super::device_tag::{hold_slot, set_own_key};
use super::*;
use cgka_engine::OwedSiblingWelcome;
use cgka_engine::private_key_packages::SiblingWelcome;
use cgka_traits::app_components::{
    DeviceSlotId, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, encode_nostr_routing_v1,
};
use cgka_traits::welcome::SiblingWelcomeJoin::Settled;

/// The one relay every routed chat names.
pub(super) const RELAY: &str = "wss://relay.example";
pub(super) const NOW: u64 = 1_000;

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
