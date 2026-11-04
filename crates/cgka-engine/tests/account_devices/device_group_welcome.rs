//! Which Welcome a new device joins its device group through (mdk#2628 D28,
//! D30). A confirmed device link records what it expects: the group, the
//! signature key of the existing device's leaf, and when the wait ends. The
//! engine joins a device group only through that Welcome, consumes the
//! expectation with the join, and refuses every other Welcome into the group
//! id the link reserved. Anyone holding the account key can read the group
//! id and found a group under it, but cannot sign as the existing device's
//! leaf.

use super::device_roster::{
    NO_WELCOME_DEADLINE, announced_entry, create_under, device_group_request, expect_link_welcome,
    key_package_ref, roster, roster_device, slot, update_bytes,
};
use super::*;
use cgka_engine::engine::OutboundWelcomeStatus;
use cgka_traits::app_components::DeviceRosterOperationV1;
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
    expect_link_welcome(&mut laptop, &chosen(), &phone, &key_package);
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
    expect_link_welcome(&mut laptop, &chosen(), &phone, &key_package);

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

/// The new device joins only by the KeyPackage it confirmed (D41): a Welcome
/// from the confirmed leaf into the confirmed group that adds it by another
/// of its KeyPackages is refused, and the expectation stays.
#[tokio::test]
async fn a_welcome_by_another_key_package_of_the_device_is_refused() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let confirmed = laptop.engine.fresh_key_package().await.unwrap();
    let other = laptop.engine.fresh_key_package().await.unwrap();
    expect_link_welcome(&mut laptop, &chosen(), &phone, &confirmed);

    let welcome = found_under_chosen(&mut phone, other).await;
    assert_eq!(
        join_outcome(&mut laptop, &welcome).await,
        refused(InputRejectionCategory::AuthorizationFailed)
    );
    assert!(!holds(&laptop, &chosen()));
    assert!(expectation_of(&laptop).is_some(), "the expectation stays");
}

/// While a link waits, the KeyPackage it confirmed joins no other group
/// (D41), so a chat Welcome that adds the new device by it is refused and
/// cannot take what the device-group Welcome needs. A link whose wait ended
/// reserves nothing.
#[tokio::test]
async fn a_waiting_links_key_package_joins_no_other_group() {
    let mut phone = roster_device(b"alice");
    let mut bob = roster_device(b"bob");
    let mut laptop = roster_device(b"alice");
    let key_package = laptop.engine.fresh_key_package().await.unwrap();
    expect_link_welcome(&mut laptop, &chosen(), &phone, &key_package);
    let chat = |key_package: KeyPackage| CreateGroupRequest {
        name: String::new(),
        description: String::new(),
        members: vec![key_package],
        required_features: vec![],
        app_components: vec![],
        initial_admins: vec![],
    };

    let (chat_id, created) = bob
        .engine
        .create_group(chat(key_package.clone()))
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    assert_eq!(
        join_outcome(&mut laptop, &welcomes[0]).await,
        refused(InputRejectionCategory::AuthorizationFailed)
    );
    assert!(!holds(&laptop, &chat_id));
    let real = found_under_chosen(&mut phone, key_package).await;
    assert_joins(&mut laptop, &real, &chosen(), &phone).await;

    // The tablet's wait already ended: its KeyPackage joins a chat.
    let mut tablet = roster_device(b"alice");
    let key_package = tablet.engine.fresh_key_package().await.unwrap();
    tablet
        .engine
        .expect_device_group_welcome(&DeviceGroupWelcomeExpectation {
            group_id: GroupId::new(vec![0x43; 16]),
            sender_signature_key: phone.engine.own_signature_key(),
            key_package_ref: key_package_ref(&key_package),
            expires_at: 0,
        })
        .unwrap();
    let (chat_id, created) = bob.engine.create_group(chat(key_package)).await.unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    assert_joins(&mut tablet, &welcomes[0], &chat_id, &bob).await;
}

/// A chat Welcome under the reserved id would take it from the device group.
/// It is refused while the link waits, and the device group still joins.
#[tokio::test]
async fn a_chat_welcome_under_the_reserved_id_is_refused() {
    let mut phone = roster_device(b"alice");
    let mut key_holder = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let key_package = laptop.engine.fresh_key_package().await.unwrap();
    expect_link_welcome(&mut laptop, &chosen(), &phone, &key_package);

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
            None,
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
            device_group_request(&roster(&[(1, "Phone")]), vec![key_package.clone()]),
            chosen(),
            Some(update_bytes(vec![DeviceRosterOperationV1::SetDevice(
                slot(2),
                announced_entry(&roster(&[(2, "Laptop")]), &slot(2), &key_package),
            )])),
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
            key_package_ref: key_package_ref(&laptop_key_package),
            expires_at: 0,
        })
        .unwrap();
    // The tablet's link was withdrawn.
    expect_link_welcome(&mut tablet, &chosen(), &phone, &tablet_key_package);
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

    let founding = found_under_chosen(&mut phone, laptop_key_package).await;
    let (_, linked) = link_under_chosen(&mut phone, tablet_key_package, 3, "Tablet").await;
    for (device, welcome) in [(&mut laptop, &founding), (&mut tablet, &linked)] {
        assert_eq!(
            join_outcome(device, welcome).await,
            refused(InputRejectionCategory::AuthorizationFailed)
        );
        assert!(!holds(device, &chosen()));
    }
}

/// `linker` links the device in `key_package` into the device group under
/// [`chosen`], at slot `n`, and returns the link's Commit and Welcome.
async fn link_under_chosen(
    linker: &mut Device,
    key_package: KeyPackage,
    n: u8,
    label: &str,
) -> (TransportMessage, TransportMessage) {
    let roster_update = update_bytes(vec![DeviceRosterOperationV1::SetDevice(
        slot(n),
        announced_entry(&roster(&[(n, label)]), &slot(n), &key_package),
    )]);
    let SendResult::GroupEvolution {
        msg,
        welcomes,
        pending,
    } = linker
        .engine
        .send(SendIntent::LinkDevice {
            group_id: chosen(),
            key_package,
            roster_update,
            deliver_until: NO_WELCOME_DEADLINE,
        })
        .await
        .unwrap()
    else {
        panic!("a link is a group evolution")
    };
    linker.engine.confirm_published(pending).await.unwrap();
    let welcome = welcomes.into_iter().next().expect("one Welcome");
    (route_to_group(&msg, &chosen()), welcome)
}

/// The approving device's leaf keeps the signature key a new device recorded
/// at Confirm through the Commit that adds that device: the founding Add,
/// and a later link's Commit, with or without an UpdatePath (D41). Each new
/// device joins through the key it confirmed.
#[tokio::test]
async fn the_key_a_new_device_confirmed_signs_the_commit_that_adds_it() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let mut tablet = roster_device(b"alice");
    let confirmed = phone.engine.own_signature_key();
    let laptop_key_package = laptop.engine.fresh_key_package().await.unwrap();
    let tablet_key_package = tablet.engine.fresh_key_package().await.unwrap();
    for (device, key_package) in [
        (&mut laptop, &laptop_key_package),
        (&mut tablet, &tablet_key_package),
    ] {
        device
            .engine
            .expect_device_group_welcome(&DeviceGroupWelcomeExpectation {
                group_id: chosen(),
                sender_signature_key: confirmed.clone(),
                key_package_ref: key_package_ref(key_package),
                expires_at: u64::MAX,
            })
            .unwrap();
    }
    let founding = found_under_chosen(&mut phone, laptop_key_package).await;
    assert_joins(&mut laptop, &founding, &chosen(), &phone).await;
    let leaf = phone.engine.own_leaf_index(&chosen()).unwrap();
    let phone_leaf = |device: &Device| {
        load_group(device, &chosen())
            .members()
            .find(|member| member.index.u32() == leaf)
            .expect("the phone's leaf")
    };
    assert_eq!(phone_leaf(&phone).signature_key, confirmed);

    let (commit, linked) = link_under_chosen(&mut phone, tablet_key_package, 3, "Tablet").await;
    assert_accepted(&mut laptop, &commit, &chosen()).await;
    assert_joins(&mut tablet, &linked, &chosen(), &phone).await;
    for device in [&phone, &laptop, &tablet] {
        assert_eq!(phone_leaf(device).signature_key, confirmed);
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

/// The actual authenticated encrypted join and expectation/Joined write are
/// one native transaction. Join alone never changes the trusted namespace.
#[tokio::test]
async fn a_move_welcome_joins_without_cutting_original_trust() {
    use cgka_traits::storage::OutboundIntentStorage as _;
    use storage_sqlite::{
        DeviceGroupMovePhase, DeviceGroupRecord, DeviceGroupTrust, FirstTrustedRoster, SqlCipherKey,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("move.db");
    let key = SqlCipherKey::raw([0x76; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut moving = super::device_roster::roster_device_on(storage, b"alice");
    let mut original_creator = roster_device(b"alice");
    let mut destination_creator = roster_device(b"alice");
    let original = GroupId::new(vec![0x41; 17]);
    super::device_tag::hold_slot(&moving, slot(2));
    let original_package = moving.engine.fresh_key_package().await.unwrap();
    let original_ref = hex::encode(key_package_ref(&original_package));
    expect_link_welcome(&mut moving, &original, &original_creator, &original_package);
    let mut original_roster = roster(&[(1, "Original"), (2, "Moving")]);
    original_roster.leaf_tag_key = [0x31; 32];
    original_roster.devices.get_mut(&slot(2)).unwrap().rename_id = Some([0x72; 16]);
    let (_, created) = create_under(
        &mut original_creator,
        &original_roster,
        vec![original_package],
        &original,
    )
    .await
    .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("founding Welcome")
    };
    assert_joins(&mut moving, &welcomes[0], &original, &original_creator).await;
    moving
        .engine
        .set_device_tag_group(Some(original.clone()))
        .unwrap();
    super::device_tag::set_own_key(
        &mut moving,
        slot(2),
        &original,
        &mut [&mut original_creator],
    )
    .await;
    let original_roster = super::device_roster::roster_of(&moving, &original);
    let app = moving.storage.app_storage();
    let original_hex = hex::encode(original.as_slice());
    app.insert_device_group(&DeviceGroupRecord {
        group_id_hex: original_hex.clone(),
        trust: DeviceGroupTrust::AwaitingWelcome,
        key_package_ref_hex: Some(original_ref.clone()),
        recorded_at: 10,
    })
    .unwrap();
    app.trust_device_group(
        &original_hex,
        DeviceGroupTrust::AwaitingWelcome,
        DeviceGroupTrust::Linked,
        None,
        11,
        &FirstTrustedRoster {
            own: &[],
            roster: &[],
            now: 11,
        },
    )
    .unwrap()
    .unwrap();
    let destination_package = moving.engine.fresh_key_package().await.unwrap();
    expect_link_welcome(
        &mut moving,
        &chosen(),
        &destination_creator,
        &destination_package,
    );
    let mut expected = expectation_of(&moving).unwrap();
    expected.expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    moving
        .engine
        .expect_device_group_welcome(&expected)
        .unwrap();
    assert!(
        app.prepare_device_group_move(&expected, &slot(2), 12)
            .unwrap()
    );
    let welcome = found_under_chosen(&mut destination_creator, destination_package).await;
    let fault = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &fault,
        &key,
        storage_sqlite::SqlCipherHardening::live_cache(),
    )
    .unwrap();
    fault.execute_batch("CREATE TRIGGER fail_move_join BEFORE UPDATE OF phase ON device_group_moves WHEN NEW.phase = 1 BEGIN SELECT RAISE(ABORT, 'native move joined checkpoint failed'); END;").unwrap();
    let failed = moving.engine.ingest(welcome.clone()).await;
    assert!(
        matches!(failed, Err(EngineError::Storage(cgka_traits::storage::StorageError::Backend(ref message))) if message.contains("native move joined checkpoint failed")),
        "{failed:?}"
    );
    assert!(!holds(&moving, &chosen()));
    assert!(holds(&moving, &original));
    assert_eq!(expectation_of(&moving), Some(expected));
    assert_eq!(
        app.device_group_move(&chosen()).unwrap().unwrap().phase,
        DeviceGroupMovePhase::Waiting
    );
    assert_eq!(
        app.device_group(&original_hex).unwrap().unwrap().trust,
        DeviceGroupTrust::Linked
    );
    fault.execute_batch("DROP TRIGGER fail_move_join").unwrap();
    assert_joins(&mut moving, &welcome, &chosen(), &destination_creator).await;
    let movement = app.device_group_move(&chosen()).unwrap().unwrap();
    assert_eq!(movement.phase, DeviceGroupMovePhase::Joined);
    assert_eq!(movement.original_key_package_ref_hex, original_ref);
    assert!(expectation_of(&moving).is_none());
    assert_eq!(
        app.device_group(&hex::encode(chosen().as_slice()))
            .unwrap()
            .unwrap()
            .trust,
        DeviceGroupTrust::AwaitingWelcome
    );
    assert_eq!(
        app.device_groups()
            .unwrap()
            .into_iter()
            .filter(|row| row.trust.is_trusted())
            .map(|row| row.group_id_hex)
            .collect::<Vec<_>>(),
        vec![original_hex.clone()]
    );
    // The destination's first own key Commit uses that roster for its own
    // UpdatePath, while ordinary fresh KeyPackages still use the old trust.
    let before_first = super::device_roster::roster_of(&moving, &chosen());
    assert!(
        !moving
            .engine
            .own_device_tag_commit_landed(&chosen(), &before_first, &slot(2))
            .unwrap()
    );
    let expected_entry = before_first.devices[&slot(2)].clone();
    let mut own_entry = expected_entry.clone();
    own_entry.tag_signature_key = Some(moving.engine.own_signature_key());
    let commit = send_commit(
        &mut moving,
        SendIntent::ReplaceDeviceEntry {
            group_id: chosen(),
            slot: slot(2),
            expected: Box::new(expected_entry),
            entry: Box::new(own_entry),
        },
        &chosen(),
    )
    .await;
    assert_accepted(&mut destination_creator, &commit, &chosen()).await;
    let destination_roster = super::device_roster::roster_of(&moving, &chosen());
    assert!(
        moving
            .engine
            .own_device_tag_commit_landed(&chosen(), &destination_roster, &slot(2))
            .unwrap()
    );
    assert_eq!(
        cgka_engine::device_tag::device_tag_claim(
            load_group(&moving, &chosen()).own_leaf_node().unwrap(),
            &destination_roster
        ),
        cgka_traits::app_components::DeviceTagClaim::Device(slot(2)),
        "first own destination Commit must tag from its own post-roster"
    );
    assert_eq!(
        cgka_engine::device_tag::device_tag_claim(
            load_group(&moving, &original).own_leaf_node().unwrap(),
            &original_roster
        ),
        cgka_traits::app_components::DeviceTagClaim::Device(slot(2))
    );
    let still_original = moving.engine.fresh_key_package().await.unwrap();
    let key_package = parse_key_package(&still_original);
    assert_eq!(
        cgka_engine::device_tag::device_tag_claim(key_package.leaf_node(), &original_roster),
        cgka_traits::app_components::DeviceTagClaim::Device(slot(2))
    );
    assert_eq!(
        cgka_engine::device_tag::device_tag_claim(key_package.leaf_node(), &destination_roster),
        cgka_traits::app_components::DeviceTagClaim::Unclaimed
    );
    assert_eq!(
        app.device_group(&original_hex).unwrap().unwrap().trust,
        DeviceGroupTrust::Linked
    );
    // The Made cut is local storage bookkeeping here; the Session/App owner
    // separately owns authorizing this call from its selected-state proof.
    assert!(
        moving
            .storage
            .commit_device_group_move_made(&movement, &original_roster, &destination_roster, 13)
            .unwrap()
    );
    let movement = app.device_group_move(&chosen()).unwrap().unwrap();
    moving.engine.set_device_tag_group(Some(chosen())).unwrap();
    let expected_old =
        super::device_roster::roster_of(&moving, &original).devices[&slot(2)].clone();
    assert_eq!(expected_old.rename_id, Some([0x72; 16]));
    let pending_package = destination_creator
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    super::send_intents::store_pending_add(&moving, &original, &pending_package);
    assert_eq!(
        super::send_intents::pending_proposals(&moving, &original),
        1
    );
    let intent = SendIntent::MarkDeviceGroupMoved {
        group_id: original.clone(),
        slot: slot(2),
        expected: Box::new(expected_old.clone()),
    };
    let SendResult::GroupEvolution { pending, .. } =
        moving.engine.send(intent.clone()).await.unwrap()
    else {
        panic!("old status Commit");
    };
    let tag_bytes = |leaf: &LeafNode| {
        leaf.extensions()
            .app_data_dictionary()
            .unwrap()
            .dictionary()
            .get(&cgka_traits::app_components::DEVICE_TAG_COMPONENT_ID)
            .unwrap()
            .to_vec()
    };
    let valid_old_tag = tag_bytes(load_group(&moving, &original).own_leaf_node().unwrap());
    let staged_group = load_group(&moving, &original);
    let staged = staged_group.pending_commit().unwrap();
    assert_eq!(
        tag_bytes(
            staged
                .update_path_leaf_node()
                .unwrap_or_else(|| staged_group.own_leaf_node().unwrap())
        ),
        valid_old_tag,
        "an already-valid original tag is preserved byte-for-byte"
    );
    assert_eq!(
        staged.add_proposals().count(),
        0,
        "unrelated Add was not admitted"
    );
    assert_eq!(
        staged.queued_proposals().count(),
        1,
        "only the inline status update"
    );
    assert_eq!(
        super::send_intents::pending_proposals(&moving, &original),
        1
    );
    moving.engine.publish_failed(pending).await.unwrap();
    assert_eq!(
        super::send_intents::pending_proposals(&moving, &original),
        1,
        "failed old status leaves pending work intact"
    );
    // Real native work prepared after the trust cut can still use this held
    // old MLS copy. Queue it through the ordinary public outbox and drain,
    // not fabricated rows or a pre-cut-queue claim. The first failed status
    // above separately owns valid-tag byte preservation/proposal isolation.
    let heartbeat = cgka_traits::app_event::MarmotAppEvent::new(
        hex::encode(moving.engine.self_id().as_slice()),
        13,
        457,
        vec![],
        String::new(),
    )
    .encode()
    .unwrap();
    let SendResult::Queued {
        intent_id: heartbeat_id,
        ..
    } = moving
        .engine
        .queue_app_message(original.clone(), heartbeat)
        .await
        .unwrap()
    else {
        panic!("the public outbox owns the old application");
    };
    let SendResult::Queued {
        intent_id: update_id,
        ..
    } = moving
        .engine
        .send(SendIntent::SelfUpdate {
            group_id: original.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("the self-update queues behind the actual old outbox");
    };
    assert_ne!(heartbeat_id, update_id);
    assert_eq!(
        moving
            .storage
            .list_queued_outbound_intents(&original)
            .unwrap()
            .len(),
        2
    );
    for _ in 0..4 {
        if !moving
            .engine
            .has_queued_outbound_intents(&original)
            .unwrap()
        {
            break;
        }
        for result in moving
            .engine
            .converge_and_drain_queued_outbound_intents(&original, 1_000_000)
            .await
            .unwrap()
        {
            match result {
                SendResult::ApplicationMessage { msg, .. } => {
                    assert_eq!(
                        original_creator
                            .engine
                            .ingest(route_to_group(&msg, &original))
                            .await
                            .unwrap(),
                        IngestOutcome::Processed
                    );
                    let (_, queued) = moving
                        .engine
                        .regenerated_queued_intent_for_message(&msg.id)
                        .unwrap();
                    assert_eq!(queued, heartbeat_id);
                    moving
                        .engine
                        .confirm_queued_outbound_intent(&queued)
                        .unwrap();
                }
                SendResult::GroupEvolution { msg, pending, .. } => {
                    moving.engine.confirm_published(pending).await.unwrap();
                    assert_accepted(
                        &mut original_creator,
                        &route_to_group(&msg, &original),
                        &original,
                    )
                    .await;
                }
                other => panic!("unexpected old queued output: {other:?}"),
            }
        }
    }
    assert!(
        !moving
            .engine
            .has_queued_outbound_intents(&original)
            .unwrap()
    );
    assert_eq!(
        super::device_roster::roster_of(&moving, &original).devices[&slot(2)],
        expected_old
    );
    assert_eq!(
        cgka_engine::device_tag::device_tag_claim(
            load_group(&moving, &original).own_leaf_node().unwrap(),
            &original_roster
        ),
        cgka_traits::app_components::DeviceTagClaim::Unclaimed,
        "ordinary queued preparation follows the now-named destination"
    );
    assert_eq!(
        cgka_engine::device_tag::device_tag_claim(
            load_group(&moving, &original).own_leaf_node().unwrap(),
            &destination_roster
        ),
        cgka_traits::app_components::DeviceTagClaim::Device(slot(2))
    );
    assert_eq!(
        load_group(&moving, &original)
            .own_leaf_node()
            .unwrap()
            .signature_key()
            .as_slice(),
        moving.engine.own_signature_key(),
        "the original own signer is unchanged"
    );
    let marked = send_commit(&mut moving, intent, &original).await;
    assert_accepted(&mut original_creator, &marked, &original).await;
    let mut expected_moved = expected_old;
    expected_moved.status = cgka_traits::app_components::DeviceStatusV1::Moved;
    let old_after = super::device_roster::roster_of(&moving, &original);
    assert_eq!(
        old_after.devices[&slot(2)],
        expected_moved,
        "old status changes nothing else, including user marker/settings"
    );
    assert_eq!(load_group(&moving, &original).members().count(), 2);
    assert_eq!(
        cgka_engine::device_tag::device_tag_claim(
            load_group(&moving, &original).own_leaf_node().unwrap(),
            &old_after
        ),
        cgka_traits::app_components::DeviceTagClaim::Device(slot(2)),
        "old status retains its old tag despite new global trust"
    );
    assert_eq!(
        cgka_engine::device_tag::device_tag_claim(
            load_group(&moving, &original).own_leaf_node().unwrap(),
            &destination_roster
        ),
        cgka_traits::app_components::DeviceTagClaim::Unclaimed
    );
    drop(app);
    drop(moving);
    drop(fault);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut reopened = super::device_roster::roster_device_on(storage, b"alice");
    reopened.engine.hydrate_all_stored_groups().unwrap();
    assert!(holds(&reopened, &original));
    assert!(holds(&reopened, &chosen()));
    let app = reopened.storage.app_storage();
    assert_eq!(app.device_group_move(&chosen()).unwrap().unwrap(), movement);
    assert_eq!(
        app.device_group(&original_hex).unwrap().unwrap().trust,
        DeviceGroupTrust::Untrusted
    );
    assert_eq!(
        app.device_group(&hex::encode(chosen().as_slice()))
            .unwrap()
            .unwrap()
            .trust,
        DeviceGroupTrust::Linked
    );
}
