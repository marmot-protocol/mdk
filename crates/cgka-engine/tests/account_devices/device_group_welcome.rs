//! Which Welcome a new device joins its device group through (mdk#2628 D28,
//! D30). A confirmed device link records what it expects: the group, the
//! signature key of the existing device's leaf, and when the wait ends. The
//! engine joins a device group only through that Welcome, consumes the
//! expectation with the join, and refuses every other Welcome into the group
//! id the link reserved. Anyone holding the account key can read the group
//! id and found a group under it, but cannot sign as the existing device's
//! leaf.

use super::device_roster::{
    NO_WELCOME_DEADLINE, create_under, device_group_request, expect_link_welcome, roster,
    roster_device,
};
use super::*;
use cgka_engine::engine::OutboundWelcomeStatus;
use cgka_traits::storage::{DeviceGroupWelcomeExpectation, DeviceGroupWelcomeStorage as _};

/// The id the existing device's confirmation named.
fn chosen() -> GroupId {
    GroupId::new(vec![0x42; 16])
}

/// `creator` founds the device group under [`chosen`], adding `key_package`,
/// and returns its Welcome.
async fn found_under_chosen(creator: &mut Device, key_package: KeyPackage) -> TransportMessage {
    let initial = roster(&[(1, "Phone"), (2, "Laptop")]);
    let (_, created) = create_under(creator, &initial, vec![key_package], &chosen())
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    welcomes.into_iter().next().expect("one Welcome")
}

fn expectation_of(device: &Device) -> Option<DeviceGroupWelcomeExpectation> {
    device
        .storage
        .device_group_welcome_expectation(&chosen())
        .unwrap()
}

fn holds(device: &Device, gid: &GroupId) -> bool {
    device.engine.epoch(gid).is_ok()
}

#[tokio::test]
async fn the_link_welcome_joins_and_consumes_its_expectation() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let key_package = laptop.engine.fresh_key_package().await.unwrap();
    expect_link_welcome(&mut laptop, &chosen(), &phone);
    let welcome = found_under_chosen(&mut phone, key_package).await;

    assert_joins(&mut laptop, &welcome, &chosen(), &phone).await;
    assert_eq!(expectation_of(&laptop), None, "the join consumed it");
}

#[tokio::test]
async fn a_device_group_welcome_no_link_expects_is_refused() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let key_package = laptop.engine.fresh_key_package().await.unwrap();
    let welcome = found_under_chosen(&mut phone, key_package).await;

    assert_eq!(
        join_outcome(&mut laptop, &welcome).await,
        refused(InputRejectionCategory::AuthorizationFailed)
    );
    assert!(!holds(&laptop, &chosen()));
}

/// Someone holding the account key reads the confirmed group id, founds
/// their own device group under it with the new device's KeyPackage, and
/// gets their Welcome there first. It is refused, and the real Welcome still
/// joins.
#[tokio::test]
async fn a_welcome_from_another_leaf_is_refused_and_the_real_one_still_joins() {
    let mut phone = roster_device(b"alice");
    let mut key_holder = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let key_package = laptop.engine.fresh_key_package().await.unwrap();
    expect_link_welcome(&mut laptop, &chosen(), &phone);

    let forged = found_under_chosen(&mut key_holder, key_package.clone()).await;
    assert_eq!(
        join_outcome(&mut laptop, &forged).await,
        refused(InputRejectionCategory::AuthorizationFailed)
    );
    assert!(!holds(&laptop, &chosen()));
    assert!(expectation_of(&laptop).is_some(), "the expectation stays");

    let real = found_under_chosen(&mut phone, key_package).await;
    assert_joins(&mut laptop, &real, &chosen(), &phone).await;
}

/// A chat Welcome under the reserved id would take it from the device group.
/// It is refused while the link waits, and the device group still joins.
#[tokio::test]
async fn a_chat_welcome_under_the_reserved_id_is_refused() {
    let mut phone = roster_device(b"alice");
    let mut key_holder = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let key_package = laptop.engine.fresh_key_package().await.unwrap();
    expect_link_welcome(&mut laptop, &chosen(), &phone);

    let (_, created) = key_holder
        .engine
        .create_group_with_chosen_id_and_audit_context(
            CreateGroupRequest {
                name: String::new(),
                description: String::new(),
                members: vec![key_package.clone()],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            },
            chosen(),
            NO_WELCOME_DEADLINE,
            None,
        )
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    assert_eq!(
        join_outcome(&mut laptop, &welcomes[0]).await,
        refused(InputRejectionCategory::AuthorizationFailed)
    );
    assert!(!holds(&laptop, &chosen()));

    let real = found_under_chosen(&mut phone, key_package).await;
    assert_joins(&mut laptop, &real, &chosen(), &phone).await;
}

/// The founding Welcome of a device group created for a link keeps the
/// link's delivery deadline, and the creator counts it as settled from then
/// on: it is never published once the new device stopped waiting (D40).
#[tokio::test]
async fn a_founding_welcome_keeps_its_delivery_deadline() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let key_package = laptop.engine.fresh_key_package().await.unwrap();
    let deadline = Timestamp(1_700_000_600);

    let (_, created) = phone
        .engine
        .create_group_with_chosen_id_and_audit_context(
            device_group_request(&roster(&[(1, "Phone"), (2, "Laptop")]), vec![key_package]),
            chosen(),
            deadline,
            None,
        )
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    let id = &welcomes[0].id;
    assert_eq!(
        phone.engine.sent_welcome_deliver_until(id).unwrap(),
        Some(deadline)
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
async fn a_welcome_after_the_wait_or_a_withdrawal_is_refused() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let mut tablet = roster_device(b"alice");
    let laptop_key_package = laptop.engine.fresh_key_package().await.unwrap();
    let tablet_key_package = tablet.engine.fresh_key_package().await.unwrap();

    // The laptop's wait already ended.
    laptop
        .engine
        .expect_device_group_welcome(&DeviceGroupWelcomeExpectation {
            group_id: chosen(),
            sender_signature_key: phone.engine.own_signature_key(),
            expires_at: 0,
        })
        .unwrap();
    // The tablet's link was withdrawn.
    expect_link_welcome(&mut tablet, &chosen(), &phone);
    assert!(
        tablet
            .engine
            .withdraw_device_group_welcome(&chosen())
            .unwrap()
    );
    assert!(
        !tablet
            .engine
            .withdraw_device_group_welcome(&chosen())
            .unwrap()
    );

    let initial = roster(&[(1, "Phone"), (2, "Laptop"), (3, "Tablet")]);
    let (_, created) = create_under(
        &mut phone,
        &initial,
        vec![laptop_key_package, tablet_key_package],
        &chosen(),
    )
    .await
    .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    for (device, welcome) in [(&mut laptop, &welcomes[0]), (&mut tablet, &welcomes[1])] {
        assert_eq!(
            join_outcome(device, welcome).await,
            refused(InputRejectionCategory::AuthorizationFailed)
        );
        assert!(!holds(device, &chosen()));
    }
}

#[tokio::test]
async fn a_device_signs_every_leaf_with_its_one_signature_key() {
    let (phone, laptop, gid) = super::device_roster::phone_and_laptop().await;
    let phone_leaf = phone.engine.own_leaf_index(&gid).unwrap();
    let laptop_leaf = laptop.engine.own_leaf_index(&gid).unwrap();
    let group = load_group(&phone, &gid);
    for (device, leaf) in [(&phone, phone_leaf), (&laptop, laptop_leaf)] {
        let node = group
            .members()
            .find(|member| member.index.u32() == leaf)
            .expect("own leaf");
        assert_eq!(node.signature_key, device.engine.own_signature_key());
    }
}
