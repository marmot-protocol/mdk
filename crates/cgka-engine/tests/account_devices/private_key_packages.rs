//! Private KeyPackages (mdk#2628 item 3.4b): single-use KeyPackages a device
//! issues to one sibling and hands over inside the device group.
//!
//! The issuer keeps each record with its private key and never shows either
//! in its inventory. A request stops earlier records counting, keeps their
//! keys, and is answered once. An ordinary Welcome never consumes one. A hand-off round-trips, and
//! the receiver accepts only this account's single-use KeyPackages whose
//! device tag reads as the sender's slot. A sibling Welcome (mdk#2628 3.5)
//! consumes only the private KeyPackage it names, issued to its sender, and
//! one back into a chat still held active is held, writing nothing, until
//! that copy reads removed or unrecoverable. One carried before a forget is
//! refused for that carrier alone.

use super::*;
use cgka_engine::key_package::{durably_owned_key_packages, key_package_metadata};
use cgka_engine::private_key_packages::{
    PrivateKeyPackageHandOff, PrivateKeyPackageRequest, SiblingWelcome, private_key_package_stock,
    validate_received_private_key_package,
};
use cgka_traits::app_components::{DeviceEntryV1, DeviceRosterV1};
use cgka_traits::storage::{GroupStorage as _, KeyPackageBundleStorage as _};
use cgka_traits::welcome::SiblingWelcomeJoin::{self, Settled};
use tls_codec::VLBytes;

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

fn private_durable_rows(
    connection: &rusqlite::Connection,
) -> (
    Vec<Vec<rusqlite::types::Value>>,
    Vec<Vec<rusqlite::types::Value>>,
) {
    let query = |sql: &str, columns: usize| {
        let mut statement = connection.prepare(sql).unwrap();
        statement
            .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
            .unwrap()
            .collect::<rusqlite::Result<Vec<Vec<rusqlite::types::Value>>>>()
            .unwrap()
    };
    (
        query(
            "SELECT provider_version, label, storage_key, group_key, value FROM openmls_values ORDER BY provider_version, label, storage_key, group_key",
            5,
        ),
        query(
            "SELECT key_package_ref, issued_at, record FROM cgka_private_key_packages ORDER BY key_package_ref",
            3,
        ),
    )
}

/// A real failed second insertion must undo earlier stock changes, the first
/// new record and both new private bundles, through encrypted file reopens.
#[tokio::test]
async fn failed_private_issuance_preserves_keys_and_stock_through_reopen_and_retry() {
    use cgka_traits::storage::StorageError;
    use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private-packages.sqlite");
    let key = SqlCipherKey::raw([0x73; 32]);
    let open_observer = || {
        let connection = rusqlite::Connection::open(&path).unwrap();
        open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
        connection
    };
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut phone = build_device(
        storage,
        b"alice",
        &[ACCOUNT_DEVICES_COMPONENT_ID],
        Box::<MockPeeler>::default(),
        None,
    );
    let public = phone.engine.fresh_key_package().await.unwrap();
    assert_eq!(
        phone
            .engine
            .issue_private_key_packages(&SLOT, 2, None, NOW)
            .unwrap(),
        2
    );
    let before_issued = phone.engine.issued_private_key_packages().unwrap();
    assert_eq!(before_issued.len(), 2);
    let references = before_issued
        .iter()
        .map(|record| record.key_package_ref.clone())
        .collect::<Vec<_>>();
    phone
        .engine
        .set_private_key_package_hand_offs_queued(&references, true)
        .unwrap();
    let before_issued = phone.engine.issued_private_key_packages().unwrap();
    assert!(
        before_issued
            .iter()
            .all(|record| record.counted && record.hand_off_queued)
    );
    assert_eq!(private_key_package_stock(&before_issued, &SLOT, NOW), 2);
    assert_eq!(
        durably_owned_key_packages(&phone.storage, ProtocolProfile::Current).unwrap(),
        vec![public.clone()]
    );
    let observer = open_observer();
    let before = private_durable_rows(&observer);
    assert_eq!(before.1.len(), 2);
    assert_eq!(phone.storage.stored_key_package_bundles().unwrap().len(), 3);
    // These predicates establish the actual failure position inside the
    // transaction: two old records uncounted, one new row, and two new bundles.
    observer.execute_batch(
        "CREATE TRIGGER fail_second_private_issue BEFORE INSERT ON cgka_private_key_packages
         WHEN (SELECT COUNT(*) FROM cgka_private_key_packages) = 3
          AND (SELECT COUNT(*) FROM cgka_private_key_packages WHERE json_extract(record, '$.counted') = 0) = 2
          AND (SELECT COUNT(*) FROM openmls_values WHERE label = X'4b65795061636b616765') = 5
         BEGIN SELECT RAISE(ABORT, 'second-private-issue-fault'); END;"
    ).unwrap();
    let request = MessageId::new(vec![0x71; 32]);
    let error = phone
        .engine
        .issue_private_key_packages(&SLOT, 2, Some(&request), NOW + 1)
        .unwrap_err();
    assert!(
        matches!(&error, EngineError::Storage(StorageError::Backend(message)) if message.contains("second-private-issue-fault")),
        "{error:?}"
    );
    assert!(
        private_durable_rows(&observer) == before,
        "failed issuance must restore every issued and OpenMLS row"
    );
    assert_eq!(
        phone.engine.issued_private_key_packages().unwrap(),
        before_issued
    );
    assert_eq!(
        private_key_package_stock(
            &phone.engine.issued_private_key_packages().unwrap(),
            &SLOT,
            NOW + 1
        ),
        2
    );
    assert_eq!(
        durably_owned_key_packages(&phone.storage, ProtocolProfile::Current).unwrap(),
        vec![public.clone()]
    );

    let Device { engine, storage } = phone;
    drop(engine);
    drop(observer);
    storage.close().unwrap();
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let observer = open_observer();
    assert!(
        private_durable_rows(&observer) == before,
        "failed issuance must remain rolled back after a physical reopen"
    );
    let mut phone = build_device(
        storage,
        b"alice",
        &[ACCOUNT_DEVICES_COMPONENT_ID],
        Box::<MockPeeler>::default(),
        None,
    );
    assert_eq!(
        phone.engine.issued_private_key_packages().unwrap(),
        before_issued
    );
    assert_eq!(
        durably_owned_key_packages(&phone.storage, ProtocolProfile::Current).unwrap(),
        vec![public.clone()]
    );
    observer
        .execute_batch("DROP TRIGGER fail_second_private_issue")
        .unwrap();
    assert_eq!(
        phone
            .engine
            .issue_private_key_packages(&SLOT, 2, Some(&request), NOW + 1)
            .unwrap(),
        2
    );
    let answered = phone.engine.issued_private_key_packages().unwrap();
    assert_eq!(answered.len(), 4);
    for record in &before_issued {
        let mut expected = record.clone();
        expected.counted = false;
        assert!(
            answered.contains(&expected),
            "retry retains every earlier key and its other metadata"
        );
    }
    let new = answered
        .iter()
        .filter(|record| record.request_id.as_ref() == Some(&request))
        .collect::<Vec<_>>();
    assert_eq!(new.len(), 2);
    assert!(
        new.iter().all(|record| record.recipient_slot == SLOT
            && record.counted
            && !record.hand_off_queued)
    );
    assert_eq!(private_key_package_stock(&answered, &SLOT, NOW + 1), 2);
    assert_eq!(phone.storage.stored_key_package_bundles().unwrap().len(), 5);
    assert_eq!(
        durably_owned_key_packages(&phone.storage, ProtocolProfile::Current).unwrap(),
        vec![public.clone()]
    );
    let after = private_durable_rows(&observer);

    let Device { engine, storage } = phone;
    drop(engine);
    drop(observer);
    storage.close().unwrap();
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let observer = open_observer();
    assert!(
        private_durable_rows(&observer) == after,
        "the healed retry persists every key and record together"
    );
    let mut phone = build_device(
        storage,
        b"alice",
        &[ACCOUNT_DEVICES_COMPONENT_ID],
        Box::<MockPeeler>::default(),
        None,
    );
    assert_eq!(
        phone.engine.issued_private_key_packages().unwrap(),
        answered
    );
    assert_eq!(
        phone
            .engine
            .issue_private_key_packages(&SLOT, 2, Some(&request), NOW + 1)
            .unwrap(),
        0
    );
    assert!(
        private_durable_rows(&observer) == after,
        "the completed request stays single-use after reopen"
    );
    assert_eq!(
        durably_owned_key_packages(&phone.storage, ProtocolProfile::Current).unwrap(),
        vec![public]
    );
    let Device { engine, storage } = phone;
    drop(engine);
    drop(observer);
    storage.close().unwrap();
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

/// A Welcome that cannot be staged refuses its Add before anything is
/// written. Bob invites the laptop with a private KeyPackage, which names no
/// publication, so a peeler that wraps a Welcome only for a published
/// KeyPackage, as the Nostr binding does, cannot wrap it. Bob's chat keeps
/// every row and its record as they were, and no commit is left pending: his
/// next send goes through.
#[tokio::test]
async fn an_invite_whose_welcome_cannot_be_wrapped_writes_nothing() {
    let mut bob = device_with_peeler(b"bob", true, Box::<PublishedWelcomesOnly>::default());
    let mut laptop = device(b"alice", true);
    laptop
        .engine
        .issue_private_key_packages(&SLOT, 1, None, NOW)
        .unwrap();
    let private = private_key_packages(&laptop).remove(0);
    let (gid, _) = create(&mut bob, vec![], vec![]).await.unwrap();
    let rows = bob
        .storage
        .list_messages(&gid, cgka_traits::types::EpochId(0))
        .unwrap();
    let record = bob.engine.group_record(&gid).unwrap();

    let refused = bob
        .engine
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![private],
            initial_admins: vec![],
        })
        .await;
    assert!(
        matches!(refused, Err(EngineError::Peeler(_))),
        "{refused:?}"
    );
    assert_eq!(
        bob.storage
            .list_messages(&gid, cgka_traits::types::EpochId(0))
            .unwrap(),
        rows
    );
    assert_eq!(bob.engine.group_record(&gid).unwrap(), record);
    send_commit(
        &mut bob,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
}

fn sibling_welcome(
    welcome: &TransportMessage,
    from: [u8; 32],
    key_package_ref: &[u8],
) -> SiblingWelcome {
    SiblingWelcome {
        from,
        to: OTHER_SLOT,
        invitation_generation: None,
        key_package_ref: key_package_ref.to_vec(),
        welcome: welcome.payload.clone(),
        relays: vec![],
    }
}

async fn join_sibling(
    device: &mut Device,
    carrier: &[u8],
    welcome: &SiblingWelcome,
) -> SiblingWelcomeJoin {
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
            Settled(refused(InputRejectionCategory::NotAddressedToThisDevice))
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
        Settled(IngestOutcome::Processed)
    );
    assert!(laptop.engine.epoch(&gid).is_ok());
    assert!(
        laptop.storage.invitation_admission(&gid).unwrap().is_none(),
        "V1 does not invent an inherited generation"
    );
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
        Settled(refused(InputRejectionCategory::Duplicate))
    );
    let (_, again) = create(&mut phone, vec![private], vec![]).await.unwrap();
    assert_eq!(
        join_sibling(
            &mut laptop,
            b"used",
            &sibling_welcome(&again[0], SLOT, &reference)
        )
        .await,
        Settled(refused(InputRejectionCategory::MissingWelcomeKeyPackage))
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
        Settled(refused(InputRejectionCategory::NotAddressedToThisDevice))
    );
    assert_eq!(
        join_outcome(&mut laptop, &welcomes[0]).await,
        IngestOutcome::Processed
    );
    assert!(laptop.engine.epoch(&other).is_ok());
}

/// The phone removes the laptop from `gid` and invites it back with
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
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![key_package],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    phone.engine.confirm_published(pending).await.unwrap();
    (remove, welcomes.into_iter().next().unwrap())
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

/// What a held sibling Welcome must leave as it was: no rejoin offer, its
/// KeyPackage still issued and its key kept, and the chat's copy untouched.
/// Being held again, and joining later, shows it marked nothing either.
fn assert_held_wrote_nothing(
    laptop: &Device,
    gid: &GroupId,
    welcome: &SiblingWelcome,
    before: &cgka_traits::group::Group,
    keys: usize,
) {
    assert!(
        laptop
            .engine
            .pending_group_rejoins_for(None)
            .unwrap()
            .is_empty()
    );
    assert!(
        laptop
            .engine
            .issued_private_key_packages()
            .unwrap()
            .iter()
            .any(|issued| issued.key_package_ref == welcome.key_package_ref)
    );
    assert_eq!(
        laptop.storage.stored_key_package_bundles().unwrap().len(),
        keys
    );
    assert_eq!(&laptop.engine.group_record(gid).unwrap(), before);
}

/// A sibling Welcome back into a chat whose copy the laptop still holds
/// active, such as one that reaches it before the removal it follows, is
/// held: it names the chat and writes nothing, however often it is tried.
/// Once the copy reads removed, the same Welcome joins and consumes its
/// KeyPackage, and another carrier of it is a duplicate.
#[tokio::test]
async fn a_sibling_welcome_into_a_chat_still_held_waits_for_its_removal() {
    let mut phone = device(b"alice", true);
    let mut laptop = device(b"alice", true);
    laptop
        .engine
        .issue_private_key_packages(&SLOT, 2, None, NOW)
        .unwrap();
    let issued = laptop.engine.issued_private_key_packages().unwrap();
    let private = |index: usize| current(issued[index].key_package.clone());
    let (gid, welcomes) = create(&mut phone, vec![private(0)], vec![]).await.unwrap();
    assert_eq!(
        join_sibling(
            &mut laptop,
            b"first",
            &sibling_welcome(&welcomes[0], SLOT, &issued[0].key_package_ref)
        )
        .await,
        Settled(IngestOutcome::Processed)
    );

    let (remove, welcome) = remove_and_add_back(&mut phone, &laptop, &gid, private(1)).await;
    let original = phone.storage.invitation_admission(&gid).unwrap().unwrap();
    let sibling = SiblingWelcome {
        invitation_generation: Some(original.generation),
        ..sibling_welcome(&welcome, SLOT, &issued[1].key_package_ref)
    };
    let before = laptop.engine.group_record(&gid).unwrap();
    let keys = laptop.storage.stored_key_package_bundles().unwrap().len();
    for _ in 0..2 {
        assert_eq!(
            join_sibling(&mut laptop, b"held", &sibling).await,
            SiblingWelcomeJoin::Held {
                group_id: gid.clone()
            }
        );
        assert_held_wrote_nothing(&laptop, &gid, &sibling, &before, keys);
        assert!(laptop.storage.invitation_admission(&gid).unwrap().is_none());
    }

    remove_laptop(&mut laptop, &gid, remove).await;
    assert_eq!(
        join_sibling(&mut laptop, b"held", &sibling).await,
        Settled(IngestOutcome::Processed)
    );
    assert!(!laptop.engine.group_record(&gid).unwrap().removed);
    assert_eq!(
        laptop.storage.invitation_admission(&gid).unwrap(),
        laptop
            .engine
            .drain_events()
            .iter()
            .rev()
            .find_map(|event| match event {
                GroupEvent::GroupJoined { via_welcome, .. } =>
                    Some(cgka_traits::group::InvitationAdmission {
                        generation: original.generation,
                        created_locally: false,
                        via_welcome: Some(via_welcome.clone()),
                    }),
                _ => None,
            }),
        "later native context inherits the original admission instead of reseeding"
    );
    assert_eq!(
        laptop.engine.epoch(&gid).unwrap(),
        phone.engine.epoch(&gid).unwrap()
    );
    assert!(
        laptop
            .engine
            .issued_private_key_packages()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        join_sibling(&mut laptop, b"another carrier", &sibling).await,
        Settled(refused(InputRejectionCategory::Duplicate))
    );
}

/// A copy branch selection found unrecoverable lets go of a held sibling
/// Welcome too: it joins as the repair, as any valid Welcome does.
#[tokio::test]
async fn a_held_sibling_welcome_joins_a_chat_whose_copy_is_unrecoverable() {
    let mut phone = device(b"alice", true);
    let mut laptop = device(b"alice", true);
    laptop
        .engine
        .issue_private_key_packages(&SLOT, 2, None, NOW)
        .unwrap();
    let issued = laptop.engine.issued_private_key_packages().unwrap();
    let private = |index: usize| current(issued[index].key_package.clone());
    let (gid, welcomes) = create(&mut phone, vec![private(0)], vec![]).await.unwrap();
    join_sibling(
        &mut laptop,
        b"first",
        &sibling_welcome(&welcomes[0], SLOT, &issued[0].key_package_ref),
    )
    .await;
    let (_, welcome) = remove_and_add_back(&mut phone, &laptop, &gid, private(1)).await;
    let sibling = sibling_welcome(&welcome, SLOT, &issued[1].key_package_ref);
    assert_eq!(
        join_sibling(&mut laptop, b"held", &sibling).await,
        SiblingWelcomeJoin::Held {
            group_id: gid.clone()
        }
    );

    let mut record = laptop.storage.get_group(&gid).unwrap();
    record.unrecoverable = true;
    laptop.storage.put_group(&record).unwrap();
    assert_eq!(
        join_sibling(&mut laptop, b"held", &sibling).await,
        Settled(IngestOutcome::Processed)
    );
    let record = laptop.engine.group_record(&gid).unwrap();
    assert!(!record.unrecoverable && !record.removed);
    assert_eq!(
        laptop.engine.epoch(&gid).unwrap(),
        phone.engine.epoch(&gid).unwrap()
    );
}

/// A sibling Welcome is dated by the message that carried it. One carried
/// no later than the laptop forgot the chat is refused for that carrier
/// alone, its KeyPackage still issued, so the same Welcome sent again in a
/// carrier dated after the forget joins.
#[tokio::test]
async fn a_sibling_welcome_carried_before_a_forget_joins_from_a_later_carrier() {
    let mut phone = device(b"alice", true);
    let mut laptop = device(b"alice", true);
    laptop
        .engine
        .issue_private_key_packages(&SLOT, 2, None, NOW)
        .unwrap();
    let issued = laptop.engine.issued_private_key_packages().unwrap();
    let private = |index: usize| current(issued[index].key_package.clone());
    let (gid, welcomes) = create(&mut phone, vec![private(0)], vec![]).await.unwrap();
    join_sibling(
        &mut laptop,
        b"first",
        &sibling_welcome(&welcomes[0], SLOT, &issued[0].key_package_ref),
    )
    .await;
    let (_, welcome) = remove_and_add_back(&mut phone, &laptop, &gid, private(1)).await;
    let sibling = sibling_welcome(&welcome, SLOT, &issued[1].key_package_ref);
    assert!(laptop.engine.forget_group_local(&gid).unwrap());
    let cutoff = laptop
        .storage
        .group_local_reset_cutoff(&gid)
        .unwrap()
        .unwrap();

    assert_eq!(
        laptop
            .engine
            .join_sibling_welcome(&hash_id(b"before"), &sibling, Some(cutoff))
            .await
            .unwrap(),
        Settled(refused(InputRejectionCategory::InvalidEncoding))
    );
    assert!(
        laptop
            .engine
            .issued_private_key_packages()
            .unwrap()
            .iter()
            .any(|issued| issued.key_package_ref == sibling.key_package_ref)
    );
    assert_eq!(
        laptop
            .engine
            .join_sibling_welcome(&hash_id(b"after"), &sibling, Some(Timestamp(cutoff.0 + 1)))
            .await
            .unwrap(),
        Settled(IngestOutcome::Processed)
    );
    assert_eq!(
        laptop.engine.epoch(&gid).unwrap(),
        phone.engine.epoch(&gid).unwrap()
    );
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
    assert_eq!(bytes[0], 1);
    assert_eq!(SiblingWelcome::decode(&bytes).unwrap(), sibling);
    let inherited = SiblingWelcome {
        invitation_generation: Some([0xa5; 32]),
        ..sibling.clone()
    };
    let inherited_bytes = inherited.encode().unwrap();
    assert_eq!(inherited_bytes[0], 2);
    assert_eq!(&inherited_bytes[1..33], &SLOT);
    assert_eq!(&inherited_bytes[33..65], &OTHER_SLOT);
    assert_eq!(&inherited_bytes[65..97], &[0xa5; 32]);
    assert_eq!(&inherited_bytes[97..], &bytes[65..]);
    assert_eq!(SiblingWelcome::decode(&inherited_bytes).unwrap(), inherited);
    let mut inherited_trailing = inherited_bytes.clone();
    inherited_trailing.push(0);
    assert!(
        matches!(SiblingWelcome::decode(&inherited_trailing), Err(EngineError::Serialize(reason)) if reason == "invalid sibling Welcome")
    );
    assert!(
        matches!(SiblingWelcome::decode(&inherited_bytes[..96]), Err(EngineError::Serialize(reason)) if reason == "invalid sibling Welcome")
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    let mut version = bytes.clone();
    version[0] = 3;
    for refused in [&bytes[..bytes.len() - 1], &trailing, &version, &bytes[..65]] {
        assert_serialize_error(SiblingWelcome::decode(refused), "invalid sibling Welcome");
    }
    let not_welcome = not_a_welcome(&mut laptop).await;
    for (refused, reason) in [
        (
            SiblingWelcome {
                key_package_ref: vec![],
                ..sibling.clone()
            },
            "sibling Welcome: a KeyPackageRef is 1 to 64 bytes",
        ),
        (
            SiblingWelcome {
                key_package_ref: vec![1; 65],
                ..sibling.clone()
            },
            "sibling Welcome: a KeyPackageRef is 1 to 64 bytes",
        ),
        (
            SiblingWelcome {
                welcome: [sibling.welcome.as_slice(), &[0]].concat(),
                ..sibling.clone()
            },
            "sibling Welcome: not one mls_welcome MLSMessage",
        ),
        (
            SiblingWelcome {
                welcome: not_welcome.clone(),
                ..sibling.clone()
            },
            "sibling Welcome: not one mls_welcome MLSMessage",
        ),
        (
            SiblingWelcome {
                relays: vec![String::new()],
                ..sibling.clone()
            },
            "sibling Welcome: a relay URL is 1 to 512 bytes",
        ),
        (
            SiblingWelcome {
                relays: vec!["w".repeat(513)],
                ..sibling.clone()
            },
            "sibling Welcome: a relay URL is 1 to 512 bytes",
        ),
    ] {
        assert_serialize_error(refused.encode(), reason);
    }

    // Build framing independently of the bounded encoder, using actual MLS
    // messages. An encoder refusal cannot stand in for an untrusted decoder.
    let wire = |reference: &[u8], message: &[u8], relays: &[Vec<u8>]| {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&sibling.from);
        bytes.extend_from_slice(&sibling.to);
        VLBytes::new(reference.to_vec())
            .tls_serialize(&mut bytes)
            .unwrap();
        bytes.extend_from_slice(message);
        let mut list = Vec::new();
        for relay in relays {
            VLBytes::new(relay.clone())
                .tls_serialize(&mut list)
                .unwrap();
        }
        VLBytes::new(list).tls_serialize(&mut bytes).unwrap();
        bytes
    };
    let relays: Vec<_> = sibling
        .relays
        .iter()
        .map(|r| r.as_bytes().to_vec())
        .collect();
    assert_eq!(
        bytes,
        wire(&sibling.key_package_ref, &sibling.welcome, &relays)
    );
    for (reference_len, relay_len) in [(1, 1), (64, 512)] {
        let boundary = SiblingWelcome {
            key_package_ref: vec![1; reference_len],
            relays: vec!["w".repeat(relay_len)],
            ..sibling.clone()
        };
        assert_eq!(
            SiblingWelcome::decode(&wire(
                &boundary.key_package_ref,
                &boundary.welcome,
                &[boundary.relays[0].as_bytes().to_vec()],
            ))
            .unwrap(),
            boundary
        );
    }
    for refused in [
        wire(&[], &sibling.welcome, &relays),
        wire(&[1; 65], &sibling.welcome, &relays),
        wire(&sibling.key_package_ref, &not_welcome, &relays),
        wire(&sibling.key_package_ref, &sibling.welcome, &[vec![]]),
        wire(
            &sibling.key_package_ref,
            &sibling.welcome,
            &[vec![b'w'; 513]],
        ),
        wire(&sibling.key_package_ref, &sibling.welcome, &[vec![0xff]]),
    ] {
        assert_serialize_error(SiblingWelcome::decode(&refused), "invalid sibling Welcome");
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
    let mut bob = device(b"bob", true);
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
    assert_serialize_error(too_many.encode(), "a hand-off carries 1 to 20 KeyPackages");

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
            assert_other_error(
                validate_received_private_key_package(
                    key_package,
                    account,
                    &roster,
                    &OTHER_SLOT,
                    NOW,
                ),
                if account == &alice {
                    "private KeyPackage refused: not tagged as the sender's"
                } else {
                    "private KeyPackage refused: another account"
                },
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
    let wire = |messages: &[u8]| {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&OTHER_SLOT);
        bytes.extend_from_slice(&SLOT);
        VLBytes::new(messages.to_vec())
            .tls_serialize(&mut bytes)
            .unwrap();
        bytes
    };
    let twenty = vec![key_packages[0].clone(); 20];
    let twenty_bytes = twenty
        .iter()
        .flat_map(|k| k.bytes().iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(
        PrivateKeyPackageHandOff::decode(&wire(&twenty_bytes)).unwrap(),
        PrivateKeyPackageHandOff {
            from: OTHER_SLOT,
            to: SLOT,
            key_packages: twenty
        }
    );
    let twenty_one = vec![key_packages[0].bytes(); 21].concat();
    assert_serialize_error(
        PrivateKeyPackageHandOff::decode(&wire(&twenty_one)),
        "invalid private KeyPackage hand-off",
    );
    let bob_key_package = bob.engine.fresh_key_package().await.unwrap();
    let (_, welcomes) = create(&mut phone, vec![bob_key_package], vec![])
        .await
        .unwrap();
    assert_serialize_error(
        PrivateKeyPackageHandOff::decode(&wire(&welcomes[0].payload)),
        "invalid private KeyPackage hand-off",
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
        for (account, from, now, reason) in [
            (
                &alice,
                slot(1),
                NOW,
                "private KeyPackage refused: not tagged as the sender's",
            ),
            (
                &bob,
                slot(2),
                NOW,
                "private KeyPackage refused: another account",
            ),
            (
                &alice,
                slot(2),
                metadata.not_after,
                "private KeyPackage refused: expired",
            ),
        ] {
            assert_other_error(
                validate_received_private_key_package(&key_package, account, &roster, &from, now),
                reason,
            );
        }
    }
    assert_other_error(
        validate_received_private_key_package(&laptop_public, &alice, &roster, &slot(2), NOW),
        "private KeyPackage refused: last resort",
    );
}

/// A device asks a sibling for private KeyPackages on behalf of a chat its
/// held ones cannot serve only while the sibling's leaf in the device group
/// advertises what that chat requires (mdk#2883). A sibling whose client
/// lacks a required component would only issue more that lack it.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn a_siblings_device_group_leaf_tells_whether_its_key_packages_could_serve_a_chat() {
    use super::device_roster::{roster_device, roster_of, slot};
    use super::tagged_siblings::tag_devices;
    use cgka_traits::app_components::{
        DEVICE_ROSTER_COMPONENT_ID, GROUP_MESSAGE_RETENTION_COMPONENT_ID,
        NOSTR_ROUTING_COMPONENT_ID,
    };
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut supported: Vec<_> = default_group_components().into_iter().collect();
    supported.extend([
        ACCOUNT_DEVICES_COMPONENT_ID,
        DEVICE_ROSTER_COMPONENT_ID,
        NOSTR_ROUTING_COMPONENT_ID,
        GROUP_MESSAGE_RETENTION_COMPONENT_ID,
    ]);
    let phone = Device {
        engine: EngineBuilder::new(storage.clone())
            .identity(pad32(b"alice"))
            .account_identity_proof_signer(proof_signer(b"alice"))
            .protocol_profile(ProtocolProfile::Current)
            .feature_registry(registry())
            .supported_app_components(supported)
            .peeler(Box::<MockPeeler>::default())
            .build()
            .unwrap(),
        storage,
    };
    // The laptop's client does not support message retention.
    let (phone, others, device_group) = tag_devices(vec![phone, roster_device(b"alice")]).await;
    let laptop = &others[0];
    let requirements = |components: Vec<AppComponentData>| {
        phone
            .engine
            .create_key_package_requirements(&CreateGroupRequest {
                name: "chat".into(),
                description: String::new(),
                members: Vec::new(),
                required_features: Vec::new(),
                app_components: components,
                initial_admins: Vec::new(),
            })
            .unwrap()
    };
    let plain = requirements(Vec::new());
    let retention = requirements(vec![AppComponentData {
        component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
        data: 300u64.to_be_bytes().to_vec(),
    }]);
    let roster = roster_of(&phone, &device_group);
    let supports = |device: &Device, sibling: u8, requirements| {
        device
            .engine
            .sibling_leaf_supports(&device_group, &roster, &slot(sibling), requirements)
            .unwrap()
    };
    assert!(supports(&phone, 2, &plain));
    assert!(
        !supports(&phone, 2, &retention),
        "the laptop's leaf lacks a component the chat requires"
    );
    assert!(
        supports(laptop, 1, &retention),
        "the phone's leaf advertises it"
    );
    assert!(
        !supports(&phone, 3, &plain),
        "a slot with no leaf in the device group serves nothing"
    );
}
