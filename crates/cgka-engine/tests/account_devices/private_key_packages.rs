//! Private KeyPackages (mdk#2628 item 3.4b): single-use KeyPackages a device
//! issues to one sibling and hands over inside the device group.
//!
//! The issuer keeps each record with its private key and never shows either
//! in its inventory. A request stops earlier records counting, keeps their
//! keys, and is answered once. An ordinary Welcome never consumes one. A hand-off round-trips, and
//! the receiver accepts only this account's single-use KeyPackages whose
//! device tag reads as the sender's slot. A sibling Welcome (mdk#2628 3.5)
//! consumes only the private KeyPackage it names, issued to its sender, and
//! one back into a chat still held active is a rejoin offer that keeps its
//! route.

use super::*;
use cgka_engine::key_package::{durably_owned_key_packages, key_package_metadata};
use cgka_engine::private_key_packages::{
    PrivateKeyPackageHandOff, PrivateKeyPackageRequest, SiblingWelcome, private_key_package_stock,
    validate_received_private_key_package,
};
use cgka_traits::app_components::{DeviceEntryV1, DeviceRosterV1};
use cgka_traits::ingest::LocalIngestState;
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::KeyPackageBundleStorage as _;
use cgka_traits::welcome::SiblingWelcomeRoute;

const NOW: u64 = 1_000;
const SLOT: [u8; 32] = [7; 32];
const OTHER_SLOT: [u8; 32] = [8; 32];

fn private_key_packages(device: &Device) -> Vec<KeyPackage> {
    device
        .engine
        .issued_private_key_packages()
        .unwrap()
        .into_iter()
        .map(|record| current(record.key_package))
        .collect()
}

fn current(bytes: Vec<u8>) -> KeyPackage {
    KeyPackage::new(bytes).with_protocol_profile(ProtocolProfile::Current)
}

#[tokio::test]
async fn private_key_packages_keep_their_keys_and_stay_out_of_the_inventory() {
    let mut phone = device(b"alice", true);
    let public = phone.engine.fresh_key_package().await.unwrap();
    assert_eq!(
        phone
            .engine
            .issue_private_key_packages(&SLOT, 3, None, NOW)
            .unwrap(),
        3
    );

    let issued = phone.engine.issued_private_key_packages().unwrap();
    assert_eq!(issued.len(), 3);
    for record in &issued {
        let metadata = key_package_metadata(&current(record.key_package.clone())).unwrap();
        assert_eq!(
            metadata.key_package_ref_hex,
            hex::encode(&record.key_package_ref)
        );
        assert!(!metadata.last_resort);
        assert_eq!(
            metadata.leaf_signature_key,
            key_package_metadata(&public).unwrap().leaf_signature_key
        );
        assert_eq!(
            (record.not_before, record.not_after),
            (metadata.not_before, metadata.not_after)
        );
        assert_eq!(record.recipient_slot, SLOT);
        assert!(record.counted && !record.hand_off_queued);
        assert_eq!(record.issued_at, NOW);
    }
    assert_eq!(phone.storage.stored_key_package_bundles().unwrap().len(), 4);
    let owned = durably_owned_key_packages(&phone.storage, ProtocolProfile::Current).unwrap();
    assert_eq!(owned, vec![public]);

    phone
        .engine
        .set_private_key_package_hand_offs_queued(&[issued[0].key_package_ref.clone()], true)
        .unwrap();
    let queued: Vec<_> = phone
        .engine
        .issued_private_key_packages()
        .unwrap()
        .into_iter()
        .map(|record| record.hand_off_queued)
        .collect();
    assert_eq!(queued.iter().filter(|queued| **queued).count(), 1);

    // Nothing has expired a second before `not_after`; everything has at it.
    let not_after = issued[0].not_after;
    assert_eq!(
        phone
            .engine
            .discard_private_key_packages(not_after - 1, None)
            .unwrap(),
        0
    );
    assert_eq!(
        phone
            .engine
            .discard_private_key_packages(not_after, None)
            .unwrap(),
        3
    );
    assert!(
        phone
            .engine
            .issued_private_key_packages()
            .unwrap()
            .is_empty()
    );
    assert_eq!(phone.storage.stored_key_package_bundles().unwrap().len(), 1);
}

#[tokio::test]
async fn a_request_stops_earlier_records_counting_and_is_answered_once() {
    let mut phone = device(b"alice", true);
    phone
        .engine
        .issue_private_key_packages(&SLOT, 4, None, NOW)
        .unwrap();
    phone
        .engine
        .issue_private_key_packages(&OTHER_SLOT, 1, None, NOW)
        .unwrap();
    let stock = |phone: &Device, slot| {
        private_key_package_stock(
            &phone.engine.issued_private_key_packages().unwrap(),
            slot,
            NOW,
        )
    };
    assert_eq!(stock(&phone, &SLOT), 4);

    let request = MessageId::new(vec![1; 32]);
    for answered in [2, 0] {
        assert_eq!(
            phone
                .engine
                .issue_private_key_packages(&SLOT, 2, Some(&request), NOW)
                .unwrap(),
            answered
        );
        assert_eq!(stock(&phone, &SLOT), 2);
        assert_eq!(private_key_packages(&phone).len(), 7);
    }
    assert_eq!(stock(&phone, &OTHER_SLOT), 1);

    // Past halfway, a counted record no longer counts. Lifetimes come from
    // the wall clock, so take the latest halfway.
    let issued = phone.engine.issued_private_key_packages().unwrap();
    let halfway = issued
        .iter()
        .map(|record| {
            cgka_traits::storage::private_key_package_halfway(record.not_before, record.not_after)
        })
        .max()
        .unwrap();
    assert_eq!(private_key_package_stock(&issued, &SLOT, halfway), 0);

    // Removing a sibling discards what was issued to it, keys included.
    assert_eq!(
        phone
            .engine
            .discard_private_key_packages(NOW, Some(&SLOT))
            .unwrap(),
        6
    );
    assert_eq!(stock(&phone, &OTHER_SLOT), 1);
    assert_eq!(phone.storage.stored_key_package_bundles().unwrap().len(), 1);
}

/// Repeated requests never delete a key the sibling may still hold. Issuing
/// stops once the sibling holds the cap's worth of unexpired records; a
/// request after that is answered with the newest ones it was given, handed
/// over again (mdk#2628 D42), and only once.
#[tokio::test]
async fn repeated_requests_keep_earlier_keys_up_to_the_cap() {
    let mut phone = device(b"alice", true);
    let want = cgka_engine::private_key_packages::MAX_PRIVATE_KEY_PACKAGE_WANT as usize;
    let cap = cgka_engine::private_key_packages::MAX_RETAINED_PRIVATE_KEY_PACKAGES;
    let mut first = None;
    for request in 0..cap / want {
        let issued = phone
            .engine
            .issue_private_key_packages(
                &SLOT,
                want,
                Some(&MessageId::new(vec![u8::try_from(request).unwrap(); 32])),
                NOW + request as u64,
            )
            .unwrap();
        assert_eq!(issued, want);
        first.get_or_insert_with(|| phone.engine.issued_private_key_packages().unwrap());
    }
    let newest: Vec<_> = phone
        .engine
        .issued_private_key_packages()
        .unwrap()
        .into_iter()
        .filter(|record| record.issued_at == NOW + (cap / want - 1) as u64)
        .map(|record| record.key_package_ref)
        .collect();
    assert_eq!(newest.len(), want);
    let every: Vec<_> = phone
        .engine
        .issued_private_key_packages()
        .unwrap()
        .into_iter()
        .map(|record| record.key_package_ref)
        .collect();
    phone
        .engine
        .set_private_key_package_hand_offs_queued(&every, true)
        .unwrap();

    let at_cap = MessageId::new(vec![0xee; 32]);
    let answered = phone
        .engine
        .issue_private_key_packages(&SLOT, want, Some(&at_cap), NOW + 10)
        .unwrap();
    assert_eq!(answered, want);
    assert_eq!(
        phone
            .engine
            .issue_private_key_packages(&SLOT, want, Some(&at_cap), NOW + 11)
            .unwrap(),
        0
    );

    let issued = phone.engine.issued_private_key_packages().unwrap();
    assert_eq!(issued.len(), cap);
    for record in &issued {
        let again = newest.contains(&record.key_package_ref);
        assert_eq!(record.request_id.as_ref() == Some(&at_cap), again);
        assert_eq!(record.counted, again);
        assert_eq!(record.hand_off_queued, !again);
    }
    for record in first.unwrap() {
        assert!(
            issued
                .iter()
                .any(|kept| kept.key_package_ref == record.key_package_ref && !kept.counted)
        );
    }
    assert_eq!(
        phone.storage.stored_key_package_bundles().unwrap().len(),
        cap
    );
}

/// When this client's capabilities change, what it issued before stops
/// counting, so upkeep replaces it; the keys stay until used or expired.
#[tokio::test]
async fn outdated_private_key_packages_stop_counting() {
    let mut phone = device(b"alice", false);
    phone
        .engine
        .issue_private_key_packages(&SLOT, 3, None, NOW)
        .unwrap();
    assert_eq!(
        phone
            .engine
            .uncount_outdated_private_key_packages()
            .unwrap(),
        0
    );

    // The same device, now advertising account-devices too.
    let mut supported: Vec<_> = default_group_components().into_iter().collect();
    supported.push(ACCOUNT_DEVICES_COMPONENT_ID);
    let mut engine = EngineBuilder::new(phone.storage.clone())
        .identity(pad32(b"alice"))
        .account_identity_proof_signer(proof_signer(b"alice"))
        .protocol_profile(ProtocolProfile::Current)
        .feature_registry(registry())
        .supported_app_components(supported)
        .peeler(Box::<MockPeeler>::default())
        .build()
        .unwrap();
    assert_eq!(engine.uncount_outdated_private_key_packages().unwrap(), 3);
    assert_eq!(
        private_key_package_stock(&engine.issued_private_key_packages().unwrap(), &SLOT, NOW),
        0
    );
    assert_eq!(phone.storage.stored_key_package_bundles().unwrap().len(), 3);
    engine
        .issue_private_key_packages(&SLOT, 2, None, NOW)
        .unwrap();
    assert_eq!(engine.uncount_outdated_private_key_packages().unwrap(), 0);
}

/// A private KeyPackage joins only through a sibling Welcome from the device
/// group. Whoever adds it with an ordinary Welcome, the device refuses it as
/// not addressed to it and keeps its key.
#[tokio::test]
async fn an_ordinary_welcome_never_consumes_a_private_key_package() {
    let mut phone = device(b"alice", true);
    let mut bob = device(b"bob", true);
    phone
        .engine
        .issue_private_key_packages(&SLOT, 1, None, NOW)
        .unwrap();
    let private = private_key_packages(&phone).remove(0);
    let (_, welcomes) = create(&mut bob, vec![private], vec![]).await.unwrap();

    assert_eq!(
        join_outcome(&mut phone, &welcomes[0]).await,
        refused(InputRejectionCategory::NotAddressedToThisDevice)
    );
    assert_eq!(phone.engine.issued_private_key_packages().unwrap().len(), 1);
    assert_eq!(phone.storage.stored_key_package_bundles().unwrap().len(), 1);
}

fn sibling_welcome(
    welcome: &TransportMessage,
    from: [u8; 32],
    key_package_ref: &[u8],
) -> SiblingWelcome {
    SiblingWelcome {
        from,
        to: OTHER_SLOT,
        key_package_ref: key_package_ref.to_vec(),
        welcome: welcome.payload.clone(),
        relays: vec![],
    }
}

async fn join_sibling(
    device: &mut Device,
    carrier: &[u8],
    welcome: &SiblingWelcome,
) -> IngestOutcome {
    device
        .engine
        .join_sibling_welcome(&hash_id(carrier), welcome, None)
        .await
        .unwrap()
}

/// The laptop issued private KeyPackages to the phone's slot, and the phone
/// added the laptop to a chat with one. The laptop joins from the phone's
/// sibling Welcome only when it names that KeyPackage and the phone's slot,
/// and the join deletes its record. A sibling Welcome consumes no other
/// KeyPackage, and a used one never joins again.
#[tokio::test]
async fn a_sibling_welcome_joins_with_the_private_key_package_issued_to_its_sender() {
    let mut phone = device(b"alice", true);
    let mut laptop = device(b"alice", true);
    laptop
        .engine
        .issue_private_key_packages(&SLOT, 2, None, NOW)
        .unwrap();
    let issued = laptop.engine.issued_private_key_packages().unwrap();
    let private = current(issued[0].key_package.clone());
    let reference = issued[0].key_package_ref.clone();
    let (gid, welcomes) = create(&mut phone, vec![private.clone()], vec![])
        .await
        .unwrap();
    let welcome = &welcomes[0];

    // A delivery, a sender the KeyPackage was not issued to and another ref
    // all leave it held, and the Welcome open.
    assert_eq!(
        join_outcome(&mut laptop, welcome).await,
        refused(InputRejectionCategory::NotAddressedToThisDevice)
    );
    for (carrier, refusal) in [
        (
            &b"another sender"[..],
            sibling_welcome(welcome, [9; 32], &reference),
        ),
        (
            b"another ref",
            sibling_welcome(welcome, SLOT, &issued[1].key_package_ref),
        ),
    ] {
        assert_eq!(
            join_sibling(&mut laptop, carrier, &refusal).await,
            refused(InputRejectionCategory::NotAddressedToThisDevice)
        );
    }
    assert_eq!(
        laptop.engine.issued_private_key_packages().unwrap().len(),
        2
    );
    assert_eq!(
        laptop.storage.stored_key_package_bundles().unwrap().len(),
        2
    );

    let sibling = sibling_welcome(welcome, SLOT, &reference);
    let sibling = SiblingWelcome::decode(&sibling.encode().unwrap()).unwrap();
    assert_eq!(
        join_sibling(&mut laptop, b"461", &sibling).await,
        IngestOutcome::Processed
    );
    assert!(laptop.engine.epoch(&gid).is_ok());
    let joined: Vec<_> = laptop
        .engine
        .drain_events()
        .into_iter()
        .filter_map(|event| match event {
            GroupEvent::GroupJoined {
                group_id, welcomer, ..
            } => Some((group_id, welcomer)),
            _ => None,
        })
        .collect();
    assert_eq!(joined, vec![(gid.clone(), Some(phone.engine.self_id()))]);
    let left = laptop.engine.issued_private_key_packages().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].key_package_ref, issued[1].key_package_ref);
    assert_eq!(
        laptop.storage.stored_key_package_bundles().unwrap().len(),
        1
    );

    // The same Welcome in another message is a duplicate, and another chat's
    // Welcome for the used KeyPackage finds no key.
    assert_eq!(
        join_sibling(&mut laptop, b"461 again", &sibling).await,
        refused(InputRejectionCategory::Duplicate)
    );
    let (_, again) = create(&mut phone, vec![private], vec![]).await.unwrap();
    assert_eq!(
        join_sibling(
            &mut laptop,
            b"used",
            &sibling_welcome(&again[0], SLOT, &reference)
        )
        .await,
        refused(InputRejectionCategory::MissingWelcomeKeyPackage)
    );

    // A sibling Welcome for a published KeyPackage consumes nothing; its
    // delivery still joins.
    let public = laptop.engine.fresh_key_package().await.unwrap();
    let public_ref =
        hex::decode(key_package_metadata(&public).unwrap().key_package_ref_hex).unwrap();
    let (other, welcomes) = create(&mut phone, vec![public], vec![]).await.unwrap();
    assert_eq!(
        join_sibling(
            &mut laptop,
            b"public",
            &sibling_welcome(&welcomes[0], SLOT, &public_ref)
        )
        .await,
        refused(InputRejectionCategory::NotAddressedToThisDevice)
    );
    assert_eq!(
        join_outcome(&mut laptop, &welcomes[0]).await,
        IngestOutcome::Processed
    );
    assert!(laptop.engine.epoch(&other).is_ok());
}

/// The phone removes the laptop from `gid` and adds it back with
/// `key_package`: the removal commit and the laptop's new Welcome.
async fn remove_and_add_back(
    phone: &mut Device,
    laptop: &Device,
    gid: &GroupId,
    key_package: KeyPackage,
) -> (TransportMessage, TransportMessage) {
    let remove = send_commit(
        phone,
        SendIntent::RemoveOwnAccountDevices {
            group_id: gid.clone(),
            leaf_signature_keys: vec![signature_key(laptop, gid)],
        },
        gid,
    )
    .await;
    let SendResult::GroupEvolution {
        welcomes, pending, ..
    } = phone
        .engine
        .send(SendIntent::AddOwnAccountDevices {
            group_id: gid.clone(),
            key_packages: vec![key_package],
        })
        .await
        .unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    phone.engine.confirm_published(pending).await.unwrap();
    (remove, welcomes.into_iter().next().unwrap())
}

/// Store the message that carried a sibling Welcome as delivered in
/// `device_group`. Only an offer's join reads it; the app checks it before
/// the first.
fn deliver_carrier(device: &Device, device_group: &GroupId, carrier: &[u8]) {
    device
        .storage
        .put_message(&MessageRecord {
            id: hash_id(carrier),
            group_id: device_group.clone(),
            epoch: cgka_traits::EpochId(0),
            state: MessageState::Processed,
            payload: Vec::new(),
            deferred_peel: None,
        })
        .unwrap();
}

/// A sibling Welcome back into a chat whose copy the laptop still holds
/// active, such as one that reaches it before the removal it follows, leaves
/// a rejoin offer that keeps its route and the KeyPackage issued. The removal
/// landing joins it, and so does consent. Each carrier of the Welcome keeps
/// its own offer, so a withdrawn one is retired and joins nothing while
/// another still joins, and a retired one leaves the Welcome free to join
/// when it arrives again.
#[tokio::test]
async fn a_sibling_welcome_before_its_removal_is_an_offer_that_keeps_its_route() {
    let mut phone = device(b"alice", true);
    let mut laptop = device(b"alice", true);
    laptop
        .engine
        .issue_private_key_packages(&SLOT, 5, None, NOW)
        .unwrap();
    let issued = laptop.engine.issued_private_key_packages().unwrap();
    let private = |index: usize| current(issued[index].key_package.clone());
    let reference = |index: usize| issued[index].key_package_ref.as_slice();
    let held = |laptop: &Device| laptop.engine.issued_private_key_packages().unwrap().len();
    let (gid, welcomes) = create(&mut phone, vec![private(0)], vec![]).await.unwrap();
    // Stands in for the device group the carriers arrive in.
    let (device_group, _) = create(&mut laptop, vec![], vec![]).await.unwrap();
    assert_eq!(
        join_sibling(
            &mut laptop,
            b"first",
            &sibling_welcome(&welcomes[0], SLOT, reference(0))
        )
        .await,
        IngestOutcome::Processed
    );
    let offered = IngestOutcome::LocalState {
        state: LocalIngestState::RejoinConfirmationRequired,
    };

    // Before its removal lands, the Welcome is an offer; the removal joins it.
    let (remove, welcome) = remove_and_add_back(&mut phone, &laptop, &gid, private(1)).await;
    deliver_carrier(&laptop, &device_group, b"before removal");
    assert_eq!(
        join_sibling(
            &mut laptop,
            b"before removal",
            &sibling_welcome(&welcome, SLOT, reference(1))
        )
        .await,
        offered
    );
    assert_eq!(held(&laptop), 4);
    let offers = laptop.engine.pending_group_rejoins_for(Some(&gid)).unwrap();
    assert_eq!(offers.len(), 1);
    assert_eq!(
        offers[0].rejoin.as_ref().unwrap().sibling,
        Some(SiblingWelcomeRoute {
            carrier: hash_id(b"before removal"),
            from: SLOT,
            key_package_ref: reference(1).to_vec(),
        })
    );
    remove_laptop(&mut laptop, &gid, remove).await;
    assert!(
        laptop
            .engine
            .retry_rejoins_after_trusted_removal()
            .await
            .unwrap()
    );
    assert!(!laptop.engine.group_record(&gid).unwrap().removed);
    assert_eq!(
        laptop.engine.epoch(&gid).unwrap(),
        phone.engine.epoch(&gid).unwrap()
    );
    assert_eq!(held(&laptop), 3);
    assert!(
        laptop
            .engine
            .pending_group_rejoins_for(None)
            .unwrap()
            .is_empty()
    );

    // Consent joins an offer while the copy is still active.
    let (_, welcome) = remove_and_add_back(&mut phone, &laptop, &gid, private(2)).await;
    deliver_carrier(&laptop, &device_group, b"consented");
    assert_eq!(
        join_sibling(
            &mut laptop,
            b"consented",
            &sibling_welcome(&welcome, SLOT, reference(2))
        )
        .await,
        offered
    );
    let [offer] =
        <[_; 1]>::try_from(laptop.engine.pending_group_rejoins_for(Some(&gid)).unwrap()).unwrap();
    let token = offer.rejoin.unwrap().local_state_token;
    assert_eq!(
        laptop
            .engine
            .confirm_group_rejoin(&offer.message_id, &token)
            .await
            .unwrap(),
        gid
    );
    assert_eq!(
        laptop.engine.epoch(&gid).unwrap(),
        phone.engine.epoch(&gid).unwrap()
    );
    assert_eq!(held(&laptop), 2);

    // Another carrier of the Welcome keeps its own offer, and retires the one
    // whose carrier was withdrawn; the delivered one joins.
    let (remove, welcome) = remove_and_add_back(&mut phone, &laptop, &gid, private(3)).await;
    let sibling = sibling_welcome(&welcome, SLOT, reference(3));
    deliver_carrier(&laptop, &device_group, b"withdrawn");
    assert_eq!(
        join_sibling(&mut laptop, b"withdrawn", &sibling).await,
        offered
    );
    withdraw_carrier(&laptop, b"withdrawn");
    deliver_carrier(&laptop, &device_group, b"redelivered");
    assert_eq!(
        join_sibling(&mut laptop, b"redelivered", &sibling).await,
        offered
    );
    let carriers: Vec<_> = laptop
        .engine
        .pending_group_rejoins_for(Some(&gid))
        .unwrap()
        .into_iter()
        .map(|offer| offer.rejoin.unwrap().sibling.unwrap().carrier)
        .collect();
    assert_eq!(carriers, vec![hash_id(b"redelivered")]);
    remove_laptop(&mut laptop, &gid, remove).await;
    assert!(
        laptop
            .engine
            .retry_rejoins_after_trusted_removal()
            .await
            .unwrap()
    );
    assert!(!laptop.engine.group_record(&gid).unwrap().removed);
    assert_eq!(
        laptop.engine.epoch(&gid).unwrap(),
        phone.engine.epoch(&gid).unwrap()
    );
    assert_eq!(held(&laptop), 1);
    assert!(
        laptop
            .engine
            .pending_group_rejoins_for(None)
            .unwrap()
            .is_empty()
    );

    // A withdrawn carrier retires its offer, on confirmation and on the retry,
    // leaving the KeyPackage issued and the Welcome free to arrive again.
    let (remove, welcome) = remove_and_add_back(&mut phone, &laptop, &gid, private(4)).await;
    let sibling = sibling_welcome(&welcome, SLOT, reference(4));
    deliver_carrier(&laptop, &device_group, b"withdrawn before consent");
    assert_eq!(
        join_sibling(&mut laptop, b"withdrawn before consent", &sibling).await,
        offered
    );
    withdraw_carrier(&laptop, b"withdrawn before consent");
    let [offer] =
        <[_; 1]>::try_from(laptop.engine.pending_group_rejoins_for(Some(&gid)).unwrap()).unwrap();
    let token = offer.rejoin.unwrap().local_state_token;
    assert!(matches!(
        laptop
            .engine
            .confirm_group_rejoin(&offer.message_id, &token)
            .await,
        Err(EngineError::InvalidWelcome)
    ));
    assert!(
        laptop
            .engine
            .pending_group_rejoins_for(None)
            .unwrap()
            .is_empty()
    );
    deliver_carrier(&laptop, &device_group, b"withdrawn before removal");
    assert_eq!(
        join_sibling(&mut laptop, b"withdrawn before removal", &sibling).await,
        offered
    );
    withdraw_carrier(&laptop, b"withdrawn before removal");
    remove_laptop(&mut laptop, &gid, remove).await;
    assert!(
        !laptop
            .engine
            .retry_rejoins_after_trusted_removal()
            .await
            .unwrap()
    );
    assert!(laptop.engine.group_record(&gid).unwrap().removed);
    assert!(
        laptop
            .engine
            .pending_group_rejoins_for(None)
            .unwrap()
            .is_empty()
    );
    assert_eq!(held(&laptop), 1);
    assert_eq!(
        join_sibling(&mut laptop, b"after removal", &sibling).await,
        IngestOutcome::Processed
    );
    assert!(!laptop.engine.group_record(&gid).unwrap().removed);
    assert_eq!(held(&laptop), 0);
}

/// Withdraw the message that carried a sibling Welcome, as a branch switch
/// does.
fn withdraw_carrier(device: &Device, carrier: &[u8]) {
    device
        .storage
        .update_message_state(&hash_id(carrier), MessageState::EpochInvalidated)
        .unwrap();
}

/// The laptop takes in the commit removing it from `gid`.
async fn remove_laptop(laptop: &mut Device, gid: &GroupId, remove: TransportMessage) {
    laptop.engine.ingest(remove).await.unwrap();
    laptop
        .engine
        .converge_stored_openmls_messages_at(gid, 1_000_000)
        .unwrap();
    assert!(laptop.engine.group_record(gid).unwrap().removed);
}

/// A sibling Welcome decodes only from its exact encoding.
#[tokio::test]
async fn a_sibling_welcome_decodes_only_its_exact_encoding() {
    let mut phone = device(b"alice", true);
    let mut laptop = device(b"alice", true);
    let public = laptop.engine.fresh_key_package().await.unwrap();
    let (_, welcomes) = create(&mut phone, vec![public], vec![]).await.unwrap();
    let sibling = SiblingWelcome {
        relays: vec!["wss://one".into(), "wss://two".into()],
        ..sibling_welcome(&welcomes[0], SLOT, &[1; 32])
    };
    let bytes = sibling.encode().unwrap();
    assert_eq!(SiblingWelcome::decode(&bytes).unwrap(), sibling);

    let mut trailing = bytes.clone();
    trailing.push(0);
    let mut version = bytes.clone();
    version[0] = 2;
    for refused in [&bytes[..bytes.len() - 1], &trailing, &version, &bytes[..65]] {
        assert!(SiblingWelcome::decode(refused).is_err());
    }
    for refused in [
        SiblingWelcome {
            key_package_ref: vec![],
            ..sibling.clone()
        },
        SiblingWelcome {
            key_package_ref: vec![1; 65],
            ..sibling.clone()
        },
        SiblingWelcome {
            welcome: [sibling.welcome.as_slice(), &[0]].concat(),
            ..sibling.clone()
        },
        SiblingWelcome {
            welcome: not_a_welcome(&mut laptop).await,
            ..sibling.clone()
        },
        SiblingWelcome {
            relays: vec![String::new()],
            ..sibling.clone()
        },
        SiblingWelcome {
            relays: vec!["w".repeat(513)],
            ..sibling.clone()
        },
    ] {
        assert!(refused.encode().is_err());
    }
}

/// A KeyPackage's bytes, which are no Welcome.
async fn not_a_welcome(device: &mut Device) -> Vec<u8> {
    device
        .engine
        .fresh_key_package()
        .await
        .unwrap()
        .bytes()
        .to_vec()
}

#[tokio::test]
async fn a_hand_off_round_trips_and_takes_no_untagged_key_package() {
    let mut phone = device(b"alice", true);
    let bob = device(b"bob", true);
    let phone_public = phone.engine.fresh_key_package().await.unwrap();
    phone
        .engine
        .issue_private_key_packages(&SLOT, 2, None, NOW)
        .unwrap();
    let key_packages = private_key_packages(&phone);
    let hand_off = PrivateKeyPackageHandOff {
        from: OTHER_SLOT,
        to: SLOT,
        key_packages: key_packages.clone(),
    };
    let decoded = PrivateKeyPackageHandOff::decode(&hand_off.encode().unwrap()).unwrap();
    assert_eq!(decoded, hand_off);
    let too_many = PrivateKeyPackageHandOff {
        key_packages: vec![key_packages[0].clone(); 21],
        ..hand_off.clone()
    };
    assert!(too_many.encode().is_err());

    // A device with no device group to tag in builds untagged KeyPackages,
    // so none reads as the sender's.
    let alice = phone.engine.self_id();
    let roster = DeviceRosterV1 {
        leaf_tag_key: [0x33; 32],
        devices: [(OTHER_SLOT, DeviceEntryV1::default())].into(),
        ..DeviceRosterV1::default()
    };
    for key_package in decoded.key_packages.iter().chain([&phone_public]) {
        for account in [&alice, &bob.engine.self_id()] {
            assert!(
                validate_received_private_key_package(
                    key_package,
                    account,
                    &roster,
                    &OTHER_SLOT,
                    NOW
                )
                .is_err()
            );
        }
    }

    let request = PrivateKeyPackageRequest {
        from: SLOT,
        to: OTHER_SLOT,
        want: 10,
    };
    assert_eq!(
        PrivateKeyPackageRequest::decode(&request.encode()).unwrap(),
        request
    );
}

/// Once its issuer can tag, every private KeyPackage carries a tag that reads
/// as the issuer's slot, so a hand-off from that slot takes it and one in
/// another slot's name does not. Another account, expiry and a last-resort
/// KeyPackage are still refused.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn a_hand_off_takes_key_packages_tagged_as_its_sender() {
    use super::device_roster::{phone_and_laptop, roster_of, slot};
    use super::device_tag::{hold_slot, set_own_key};

    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    hold_slot(&laptop, slot(2));
    laptop
        .engine
        .set_device_tag_group(Some(gid.clone()))
        .unwrap();
    set_own_key(&mut laptop, slot(2), &gid, &mut [&mut phone]).await;
    laptop
        .engine
        .issue_private_key_packages(&slot(1), 2, None, NOW)
        .unwrap();
    let laptop_public = laptop.engine.fresh_key_package().await.unwrap();
    let roster = roster_of(&phone, &gid);
    let alice = phone.engine.self_id();
    let bob = device(b"bob", true).engine.self_id();
    for key_package in private_key_packages(&laptop) {
        let metadata =
            validate_received_private_key_package(&key_package, &alice, &roster, &slot(2), NOW)
                .unwrap();
        for (account, from, now) in [
            (&alice, slot(1), NOW),
            (&bob, slot(2), NOW),
            (&alice, slot(2), metadata.not_after),
        ] {
            assert!(
                validate_received_private_key_package(&key_package, account, &roster, &from, now)
                    .is_err()
            );
        }
    }
    assert!(
        validate_received_private_key_package(&laptop_public, &alice, &roster, &slot(2), NOW)
            .is_err()
    );
}
