//! Private KeyPackages (mdk#2628 item 3.4b): once their leaves are tagged
//! (3.1d), siblings hand each other single-use KeyPackages inside the device
//! group, never publish them, take only a sibling's own, repair a lost
//! hand-off by asking again, and send again what reached no relay.

use super::*;
use base64::Engine as _;
use cgka_traits::app_components::DeviceSlotId;
use cgka_traits::storage::IssuedPrivateKeyPackage;
use marmot_session::{
    KIND_PRIVATE_KEY_PACKAGE_HAND_OFF, KIND_PRIVATE_KEY_PACKAGE_REQUEST, MAX_HAND_OFF_KEY_PACKAGES,
    PrivateKeyPackageHandOff, PrivateKeyPackageRequest,
};
use storage_sqlite::ReceivedPrivateKeyPackage;

fn slot(client: &AppClient) -> DeviceSlotId {
    hex::decode(own_slot(client)).unwrap().try_into().unwrap()
}

fn issued(client: &AppClient) -> Vec<IssuedPrivateKeyPackage> {
    client.runtime.issued_private_key_packages().unwrap()
}

/// What `client` holds from the sibling in `issuer`.
fn received_from(client: &AppClient, issuer: &DeviceSlotId) -> Vec<ReceivedPrivateKeyPackage> {
    client
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .received_private_key_packages()
        .unwrap()
        .into_iter()
        .filter(|record| record.issuer_slot_hex == hex::encode(issuer))
        .collect()
}

fn group_messages_since(relay: &ScriptedPushRelayClient, since: usize) -> usize {
    published_kinds(relay, since)
        .into_iter()
        .filter(|kind| *kind == transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
        .count()
}

/// Until its leaf is tagged, the joining laptop issues and asks for nothing,
/// and the phone refuses a request it sends anyway (D33). Then the phone
/// serves the laptop and asks for its own; the laptop keeps them and
/// answers. Neither publishes one or lists one in its inventory, and both
/// sides survive a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn siblings_hand_each_other_private_key_packages() {
    let (mut devices, group) = linked_devices().await;
    let (phone_slot, laptop_slot) = (slot(&devices.phone), slot(&devices.laptop));
    let before = devices.relay.published_events.lock().unwrap().len();

    let untagged = PrivateKeyPackageRequest {
        from: laptop_slot,
        to: phone_slot,
        want: 5,
    };
    devices
        .laptop
        .send_device_group_message(&group, KIND_PRIVATE_KEY_PACKAGE_REQUEST, untagged.encode())
        .await
        .unwrap();
    // This pass tags the laptop's leaf, after upkeep has passed it by.
    devices.laptop.run_due_maintenance().await.unwrap();
    assert!(issued(&devices.laptop).is_empty());
    assert_eq!(
        devices_storage(&devices.laptop)
            .private_key_package_need(&hex::encode(phone_slot))
            .unwrap(),
        None
    );
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert!(issued(&devices.phone).is_empty());

    devices.phone.run_due_maintenance().await.unwrap();
    let phone_issued = issued(&devices.phone);
    assert_eq!(phone_issued.len(), 10);
    assert!(phone_issued.iter().all(|record| {
        record.recipient_slot == laptop_slot && record.hand_off_queued && record.counted
    }));

    deliver_all(&mut devices.laptop, &devices.relay).await;
    let kept = received_from(&devices.laptop, &phone_slot);
    let mut kept_refs: Vec<_> = kept
        .iter()
        .map(|record| record.key_package_ref_hex.clone())
        .collect();
    let mut issued_refs: Vec<_> = phone_issued
        .iter()
        .map(|record| hex::encode(&record.key_package_ref))
        .collect();
    kept_refs.sort();
    issued_refs.sort();
    assert_eq!(kept_refs, issued_refs);
    // It answered the phone's request; maintenance hands those over.
    assert_eq!(issued(&devices.laptop).len(), 10);
    devices.laptop.run_due_maintenance().await.unwrap();
    assert!(
        issued(&devices.laptop)
            .iter()
            .all(|record| record.recipient_slot == phone_slot && record.hand_off_queued)
    );
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(received_from(&devices.phone, &laptop_slot).len(), 10);

    // Maintenance may publish a public KeyPackage, never a private one, and
    // no inventory lists one.
    let private: Vec<_> = issued(&devices.phone)
        .into_iter()
        .chain(issued(&devices.laptop))
        .map(|record| record.key_package)
        .collect();
    for event in &devices.relay.published_events.lock().unwrap()[before..] {
        if event.kind == 30443 {
            let content = base64::engine::general_purpose::STANDARD
                .decode(&event.content)
                .unwrap();
            assert!(!private.contains(&content));
        }
    }
    for client in [&devices.phone, &devices.laptop] {
        let inventory = client.durably_owned_key_packages().unwrap();
        assert!(!inventory.is_empty());
        assert!(inventory.iter().all(|key_package| {
            !private
                .iter()
                .any(|bytes| bytes.as_slice() == key_package.bytes())
        }));
    }

    drop(devices.laptop);
    let laptop = devices.laptop_app.client("alice").await.unwrap();
    assert_eq!(received_from(&laptop, &phone_slot).len(), 10);
    assert_eq!(issued(&laptop).len(), 10);
}

/// A device keeps only KeyPackages tagged as the slot that hands them over,
/// and answers only requests from a slot the roster lists (D33).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_takes_only_its_siblings_own_key_packages() {
    let (mut devices, group) = tagging_devices().await;
    let (phone_slot, laptop_slot) = (slot(&devices.phone), slot(&devices.laptop));

    // The laptop hands the phone's own KeyPackages back as its own.
    let forwarded = PrivateKeyPackageHandOff {
        from: laptop_slot,
        to: phone_slot,
        key_packages: received_from(&devices.laptop, &phone_slot)
            .into_iter()
            .take(3)
            .map(|record| KeyPackage::new(record.key_package))
            .collect(),
    };
    devices
        .laptop
        .send_device_group_message(
            &group,
            KIND_PRIVATE_KEY_PACKAGE_HAND_OFF,
            base64::engine::general_purpose::STANDARD.encode(forwarded.encode().unwrap()),
        )
        .await
        .unwrap();
    // And asks in the name of a slot the roster does not list.
    let stranger = PrivateKeyPackageRequest {
        from: [0x77; 32],
        to: phone_slot,
        want: 5,
    };
    devices
        .laptop
        .send_device_group_message(&group, KIND_PRIVATE_KEY_PACKAGE_REQUEST, stranger.encode())
        .await
        .unwrap();

    let phone_issued = issued(&devices.phone).len();
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert!(received_from(&devices.phone, &laptop_slot).is_empty());
    assert!(received_from(&devices.phone, &phone_slot).is_empty());
    assert_eq!(issued(&devices.phone).len(), phone_issued);

    // The same leaf's hand-off of its own KeyPackages is kept.
    devices.laptop.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(received_from(&devices.phone, &laptop_slot).len(), 10);
}

/// A sibling takes one KeyPackage to add the issuer to a chat, asks for a
/// burst, and discards everything exchanged with a removed sibling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_takes_asks_for_more_and_discards_private_key_packages() {
    let (mut devices, _) = tagging_devices().await;
    let (phone_slot, laptop_slot) = (slot(&devices.phone), slot(&devices.laptop));

    let taken = devices
        .laptop
        .take_private_key_package(&phone_slot)
        .unwrap()
        .unwrap();
    let metadata = marmot_session::key_package_metadata(&taken).unwrap();
    assert!(!metadata.last_resort);
    assert!(
        issued(&devices.phone)
            .iter()
            .any(|record| hex::encode(&record.key_package_ref) == metadata.key_package_ref_hex)
    );
    assert_eq!(received_from(&devices.laptop, &phone_slot).len(), 9);

    // A burst of 30: the phone answers with 30, in two hand-offs.
    devices
        .laptop
        .want_private_key_packages(&phone_slot, 30)
        .unwrap();
    devices.laptop.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    let counted = issued(&devices.phone)
        .iter()
        .filter(|record| record.recipient_slot == laptop_slot && record.counted)
        .count();
    assert_eq!(counted, 30);
    devices.phone.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.laptop, &devices.relay).await;
    assert_eq!(received_from(&devices.laptop, &phone_slot).len(), 39);
    devices.laptop.run_due_maintenance().await.unwrap();
    let storage = devices_storage(&devices.laptop);
    assert_eq!(
        storage
            .private_key_package_need(&hex::encode(phone_slot))
            .unwrap(),
        None
    );

    // Removing the phone discards both directions, keys included.
    assert!(
        issued(&devices.laptop)
            .iter()
            .any(|record| record.recipient_slot == phone_slot)
    );
    devices
        .laptop
        .discard_private_key_packages_of(&phone_slot)
        .unwrap();
    assert!(received_from(&devices.laptop, &phone_slot).is_empty());
    assert!(
        !issued(&devices.laptop)
            .iter()
            .any(|record| record.recipient_slot == phone_slot)
    );
}

fn devices_storage(client: &AppClient) -> storage_sqlite::SqliteAppStorage {
    client.app.account_storage("alice").unwrap().app_storage()
}

/// With its hand-off lost, a sibling asks again, and only once an hour; the
/// answer replaces what was lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_hand_off_is_repaired_by_the_next_request() {
    let (mut devices, _) = tagging_devices().await;
    let phone_slot = slot(&devices.phone);
    devices_storage(&devices.laptop)
        .delete_received_private_key_packages_from(&hex::encode(phone_slot))
        .unwrap();

    devices.laptop.run_due_maintenance().await.unwrap();
    let need = devices_storage(&devices.laptop)
        .private_key_package_need(&hex::encode(phone_slot))
        .unwrap()
        .unwrap();
    assert!(need.requested_at.is_some());
    let after_request = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.run_due_maintenance().await.unwrap();
    assert_eq!(group_messages_since(&devices.relay, after_request), 0);

    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.phone.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.laptop, &devices.relay).await;
    assert_eq!(received_from(&devices.laptop, &phone_slot).len(), 10);
    devices.laptop.run_due_maintenance().await.unwrap();
    assert_eq!(
        devices_storage(&devices.laptop)
            .private_key_package_need(&hex::encode(phone_slot))
            .unwrap(),
        None
    );
}

/// A request or hand-off that every relay refused is sent again at the next
/// upkeep, and a refused request does not start the hour. One that went out
/// is never sent twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_or_hand_off_that_reached_no_one_is_sent_again() {
    let (mut devices, _) = settled_linked_devices().await;
    let phone_slot = slot(&devices.phone);
    let requested_at = |client: &AppClient| {
        devices_storage(client)
            .private_key_package_need(&hex::encode(phone_slot))
            .unwrap()
            .and_then(|need| need.requested_at)
    };
    devices
        .laptop
        .want_private_key_packages(&phone_slot, 30)
        .unwrap();

    devices.relay.reject_next_publish();
    let before = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.run_due_maintenance().await.unwrap();
    assert_eq!(group_messages_since(&devices.relay, before), 0);
    assert_eq!(requested_at(&devices.laptop), None);
    devices.laptop.run_due_maintenance().await.unwrap();
    assert_eq!(group_messages_since(&devices.relay, before), 1);
    assert!(requested_at(&devices.laptop).is_some());

    // The phone answers in two hand-offs; every relay refuses the first.
    deliver_all(&mut devices.phone, &devices.relay).await;
    let unqueued = |phone: &AppClient| {
        issued(phone)
            .iter()
            .filter(|record| !record.hand_off_queued)
            .count()
    };
    assert_eq!(unqueued(&devices.phone), 30);
    devices.relay.reject_next_publish();
    let before = devices.relay.published_events.lock().unwrap().len();
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(unqueued(&devices.phone), MAX_HAND_OFF_KEY_PACKAGES);
    assert_eq!(group_messages_since(&devices.relay, before), 1);
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(unqueued(&devices.phone), 0);
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(group_messages_since(&devices.relay, before), 2);

    deliver_all(&mut devices.laptop, &devices.relay).await;
    assert_eq!(received_from(&devices.laptop, &phone_slot).len(), 40);
}

/// Expire every private KeyPackage `app` issued or holds.
fn expire_private_key_packages(app: &MarmotApp, issuer: &DeviceSlotId) {
    use cgka_traits::storage::PrivateKeyPackageStorage as _;
    let storage = app.account_storage("alice").unwrap();
    for record in storage.list_issued_private_key_packages().unwrap() {
        storage
            .put_issued_private_key_package(&IssuedPrivateKeyPackage {
                not_before: 0,
                not_after: 1,
                ..record
            })
            .unwrap();
    }
    let app_storage = storage.app_storage();
    let issuer_hex = hex::encode(issuer);
    let received: Vec<_> = app_storage
        .received_private_key_packages()
        .unwrap()
        .into_iter()
        .filter(|record| record.issuer_slot_hex == issuer_hex)
        .map(|record| ReceivedPrivateKeyPackage {
            not_before: 0,
            not_after: 1,
            ..record
        })
        .collect();
    assert!(!received.is_empty());
    app_storage
        .delete_received_private_key_packages_from(&issuer_hex)
        .unwrap();
    app_storage
        .insert_received_private_key_packages(&received)
        .unwrap();
}

/// Expired private KeyPackages go on both sides, issued ones with their
/// keys, even while maintenance is paused or cursors are frozen, like
/// expired public KeyPackage keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_private_key_packages_go_while_maintenance_is_paused_or_frozen() {
    let (
        Devices {
            _dirs,
            relay,
            phone_app,
            laptop_app,
            phone,
            mut laptop,
            ..
        },
        _,
    ) = settled_linked_devices().await;
    let (phone_slot, laptop_slot) = (slot(&phone), slot(&laptop));
    assert!(!issued(&laptop).is_empty());

    expire_private_key_packages(&laptop_app, &phone_slot);
    laptop.pause_maintenance();
    laptop.run_due_maintenance().await.unwrap();
    assert!(issued(&laptop).is_empty());
    assert!(received_from(&laptop, &phone_slot).is_empty());

    expire_private_key_packages(&phone_app, &laptop_slot);
    drop(phone);
    drop(phone_app);
    let frozen = MarmotApp::with_relay_and_config(
        _dirs[0].path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_device_groups(true)
            .with_cursor_persistence(crate::CursorPersistence::Frozen),
    )
    .with_test_relay_client(relay);
    let mut phone = frozen.client("alice").await.unwrap();
    phone.run_due_maintenance().await.unwrap();
    assert!(issued(&phone).is_empty());
    assert!(received_from(&phone, &laptop_slot).is_empty());
}
