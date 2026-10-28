//! Creating a group (mdk#2628 item 2.3, protocol-core/group-setup.md).
//!
//! From the creator's side, a creator that supports account-devices requires
//! it in a new group when its own leaf and every founding KeyPackage
//! advertise it, without the host asking, and otherwise creates the group as
//! before. A founding Add that would break the component's rules, the leaf
//! limit included, is refused before any Welcome exists. From the joiners'
//! side, invitees join the requiring group, a member's device then adds and
//! removes its own account's devices without being an admin, and nobody can
//! add a device that does not advertise the component.

use super::*;
use cgka_traits::GroupStorage as _;

/// A KeyPackage of a new device of `account` that advertises account-devices
/// when `advertises` is set.
async fn key_package(account: &[u8], advertises: bool) -> KeyPackage {
    device(account, advertises)
        .engine
        .fresh_key_package()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_group_requires_account_devices_when_every_founder_advertises_it() {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", true);
    let mut carol = device(b"carol", true);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let carol_kp = carol.engine.fresh_key_package().await.unwrap();
    let (gid, welcomes) = create(&mut alice, vec![bob_kp.clone(), carol_kp], vec![])
        .await
        .unwrap();
    assert!(requires_account_devices(&alice.engine, &gid));
    for (joiner, welcome) in [&mut bob, &mut carol].into_iter().zip(&welcomes) {
        assert_joins(joiner, welcome, &gid, &alice).await;
        assert!(requires_account_devices(&joiner.engine, &gid));
        assert_eq!(
            joiner.engine.epoch(&gid).unwrap(),
            alice.engine.epoch(&gid).unwrap()
        );
    }

    // One founder that does not advertise it leaves the group without it,
    // created as before: the requirements differ by 0x800d alone. KeyPackages
    // are last-resort, so bob's founds this group too.
    let dave_kp = key_package(b"dave", false).await;
    let (without, _) = create(&mut alice, vec![bob_kp, dave_kp], vec![])
        .await
        .unwrap();
    assert!(!requires_account_devices(&alice.engine, &without));
    let mut expected = alice
        .engine
        .group_record(&without)
        .unwrap()
        .required_capabilities;
    expected.app_components.insert(ACCOUNT_DEVICES_COMPONENT_ID);
    assert_eq!(
        alice.engine.group_record(&gid).unwrap().required_capabilities,
        expected
    );
}

#[tokio::test]
async fn a_creator_alone_requires_it_when_its_own_leaf_advertises_it() {
    let mut alice = device(b"alice", true);
    let (gid, welcomes) = create(&mut alice, vec![], vec![]).await.unwrap();
    assert!(welcomes.is_empty());
    assert!(requires_account_devices(&alice.engine, &gid));

    // A creator whose leaf does not advertise it never requires it, whatever
    // the founding KeyPackages advertise.
    let mut dave = device(b"dave", false);
    let (alone, _) = create(&mut dave, vec![], vec![]).await.unwrap();
    assert!(!requires_account_devices(&dave.engine, &alone));
    let bob_kp = key_package(b"bob", true).await;
    let (with_bob, _) = create(&mut dave, vec![bob_kp], vec![]).await.unwrap();
    assert!(!requires_account_devices(&dave.engine, &with_bob));
}

#[tokio::test]
async fn a_founding_add_over_the_leaf_limit_is_refused_before_any_welcome() {
    let mut alice = device(b"alice", true);
    let bob_kp = key_package(b"bob", true).await;
    let at_limit: Vec<_> = std::iter::once(bob_kp.clone())
        .chain((1..MAX_LEAVES_PER_ACCOUNT).map(|_| sibling_key_package(&bob_kp, b"bob")))
        .collect();
    let mut over_limit = at_limit.clone();
    over_limit.push(sibling_key_package(&bob_kp, b"bob"));

    let refused = create(&mut alice, over_limit, vec![]).await;
    assert!(refused.unwrap_err().to_string().contains(&limit_error()));
    // Nothing is left to deliver or show: no group, so no Welcome stored
    // under one, and no event.
    assert!(alice.storage.list_groups().unwrap().is_empty());
    assert!(alice.engine.live_group_ids().unwrap().is_empty());
    assert!(
        !alice
            .engine
            .drain_events()
            .iter()
            .any(|event| matches!(event, GroupEvent::GroupCreated { .. }))
    );

    // At the limit the group is founded, and requires it.
    let (gid, welcomes) = create(&mut alice, at_limit, vec![]).await.unwrap();
    assert_eq!(welcomes.len(), MAX_LEAVES_PER_ACCOUNT);
    assert!(requires_account_devices(&alice.engine, &gid));
}

/// bob, who is not an admin, adds a device of his account to the group alice
/// founded, and that device then removes bob's first one. alice accepts both
/// Commits and the new device joins through bob's Welcome.
#[tokio::test]
async fn a_member_adds_and_removes_its_own_devices_from_the_start() {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", true);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], true, &mut [&mut bob]).await;
    assert!(!is_admin(&bob, &gid));

    let mut laptop = device(b"bob", true);
    let laptop_kp = laptop.engine.fresh_key_package().await.unwrap();
    let SendResult::GroupEvolution {
        msg,
        welcomes,
        pending,
    } = bob
        .engine
        .send(add_own_devices(&gid, vec![laptop_kp]))
        .await
        .unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    bob.engine.confirm_published(pending).await.unwrap();
    assert_accepted(&mut alice, &route_to_group(&msg, &gid), &gid).await;
    let [welcome] = &welcomes[..] else {
        panic!("one Welcome per added KeyPackage, got {}", welcomes.len())
    };
    assert_joins(&mut laptop, welcome, &gid, &bob).await;

    let phone = signature_key(&bob, &gid);
    let remove = send_commit(&mut laptop, remove_own_devices(&gid, vec![phone]), &gid).await;
    assert_accepted(&mut alice, &remove, &gid).await;
    assert_accepted(&mut bob, &remove, &gid).await;
    assert!(bob.engine.group_record(&gid).unwrap().removed);
    let bob_id = bob.engine.self_id();
    for member in [&alice, &laptop] {
        let bob_leaves = member
            .engine
            .members(&gid)
            .unwrap()
            .iter()
            .filter(|leaf| leaf.id == bob_id)
            .count();
        assert_eq!(bob_leaves, 1);
    }
}

#[tokio::test]
async fn a_device_without_account_devices_cannot_be_added_later() {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", true);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], true, &mut [&mut bob]).await;
    let epoch = alice.engine.epoch(&gid).unwrap();

    // Committers: an admin's invite and a member's own-device add.
    let dave_kp = key_package(b"dave", false).await;
    let invite = alice
        .engine
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![dave_kp.clone()],
            initial_admins: vec![],
        })
        .await;
    assert!(
        matches!(invite, Err(EngineError::MissingRequiredCapabilities { .. })),
        "{invite:?}"
    );
    let bob_laptop_kp = key_package(b"bob", false).await;
    assert!(
        bob.engine
            .send(add_own_devices(&gid, vec![bob_laptop_kp]))
            .await
            .is_err()
    );
    assert_eq!(alice.engine.epoch(&gid).unwrap(), epoch);
    assert_eq!(bob.engine.epoch(&gid).unwrap(), epoch);

    // Receivers: the same Add, crafted, is dropped.
    let crafted = crafted_commit(&alice, &gid, vec![dave_kp], vec![], None);
    assert_rejected_on_replay(&mut bob, &crafted, &gid).await;
}
