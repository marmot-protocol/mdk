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

use super::device_roster::{key_package_ref, slot};
use super::device_tag::hold_slot;
use super::send_intents::Untouched;
use super::tagged_siblings::*;
use super::*;
use cgka_engine::private_key_packages::SiblingWelcome;
use cgka_traits::engine::KeyPackageSource;
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::types::EpochId;

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
/// drops the key. From then on nothing sends it; its row stays as it is, as
/// an invite Welcome's does past its deadline.
#[tokio::test]
async fn a_sibling_welcome_is_owed_until_its_key_package_expires() {
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
    // The laptop's own last-resort KeyPackage carries its tag and names no
    // publication, but no sibling hands one over.
    let last_resort = SiblingKeyPackage {
        slot: slot(2),
        key_package: new[0]
            .engine
            .fresh_key_package()
            .await
            .unwrap()
            .with_protocol_profile(ProtocolProfile::Current),
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
        (vec![named(&tablet, 2)], "not tagged as the sender's"),
        (vec![named(&laptop, 9)], "not tagged as the sender's"),
        (vec![untagged], "not tagged as the sender's"),
        (vec![last_resort], "last resort"),
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
