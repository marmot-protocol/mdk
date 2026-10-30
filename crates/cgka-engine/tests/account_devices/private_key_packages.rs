//! Private KeyPackages (mdk#2628 item 3.4b): single-use KeyPackages a device
//! issues to one sibling and hands over inside the device group.
//!
//! The issuer keeps each record with its private key and never shows either
//! in its inventory. A request stops earlier records counting, keeps their
//! keys, and is answered once. An ordinary Welcome never consumes one. A hand-off round-trips, and
//! the receiver accepts only this account's single-use KeyPackages whose
//! device tag reads as the sender's slot.

use super::*;
use cgka_engine::key_package::{durably_owned_key_packages, key_package_metadata};
use cgka_engine::private_key_packages::{
    PrivateKeyPackageHandOff, PrivateKeyPackageRequest, private_key_package_stock,
    validate_received_private_key_package,
};
use cgka_traits::app_components::{DeviceEntryV1, DeviceRosterV1};
use cgka_traits::storage::KeyPackageBundleStorage as _;

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

    // Past halfway, a counted record no longer counts.
    let record = &phone.engine.issued_private_key_packages().unwrap()[0];
    let halfway =
        cgka_traits::storage::private_key_package_halfway(record.not_before, record.not_after);
    assert_eq!(
        private_key_package_stock(
            &phone.engine.issued_private_key_packages().unwrap(),
            &SLOT,
            halfway
        ),
        0
    );

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
    use super::device_tag::set_own_key;

    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
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
