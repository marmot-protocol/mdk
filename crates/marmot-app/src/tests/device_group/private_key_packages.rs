//! Private KeyPackages (mdk#2628 item 3.4b): once their leaves are tagged
//! (3.1d), siblings hand each other single-use KeyPackages inside the device
//! group, never publish them, take only a sibling's own, repair a lost
//! hand-off by asking again, and send again what reached no relay. A sibling
//! Welcome (3.5b) adds a device to a chat with one of them.

use super::*;
use crate::tests::canonical_membership::deliver_events;
use base64::Engine as _;
use cgka_traits::app_components::DeviceSlotId;
use cgka_traits::app_components::NOSTR_ROUTING_MAX_RELAYS;
use cgka_traits::engine::{SendIntent, SiblingKeyPackage};
use cgka_traits::storage::IssuedPrivateKeyPackage;
use marmot_session::CanonicalizationPolicy;
use marmot_session::{
    KIND_PRIVATE_KEY_PACKAGE_HAND_OFF, KIND_PRIVATE_KEY_PACKAGE_REQUEST, KIND_SIBLING_WELCOME,
    MAX_HAND_OFF_KEY_PACKAGES, PrivateKeyPackageHandOff, PrivateKeyPackageRequest, PublishWork,
    SiblingWelcome,
};
use storage_sqlite::{ReceivedPrivateKeyPackage, StashedSiblingWelcome};

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

/// Direct Add tests deliberately skip preflight to exercise engine refusal
/// after an allocation is spent. Normal app callers select compatible stock.
fn private_candidate(client: &AppClient, issuer: &DeviceSlotId) -> ReceivedPrivateKeyPackage {
    devices_storage(client)
        .received_private_key_packages_from(&hex::encode(issuer), crate::unix_now_seconds())
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
}

fn take_private_key_package(client: &AppClient, issuer: &DeviceSlotId) -> KeyPackage {
    let record = devices_storage(client)
        .take_received_private_key_package(&hex::encode(issuer), crate::unix_now_seconds())
        .unwrap()
        .unwrap();
    AppClient::received_private_key_package(&record)
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

    // The insertion can fail after its first write too. Such a hand-off
    // certifies no new stock; the issuer can hand the same unspent keys over
    // again once the write works, without changing the allocation protocol.
    let chat = devices
        .phone
        .create_group("receive stock", &[])
        .await
        .unwrap();
    let mut selection = Default::default();
    assert!(
        devices
            .phone
            .next_private_key_package_for_chat(&chat, &laptop_slot, &mut selection)
            .unwrap()
            .is_none()
    );
    let database = phone_database(&devices);
    database
        .execute_batch(
            "CREATE TRIGGER refuse_private_stock AFTER INSERT ON private_key_packages_received
         BEGIN SELECT RAISE(ABORT, 'private hand-off write refused'); END;",
        )
        .unwrap();
    devices.laptop.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert!(received_from(&devices.phone, &laptop_slot).is_empty());
    assert!(
        devices
            .phone
            .next_private_key_package_for_chat(&chat, &laptop_slot, &mut selection)
            .unwrap()
            .is_none(),
        "a failed insert supplies no candidate to the retained context"
    );
    database
        .execute_batch("DROP TRIGGER refuse_private_stock")
        .unwrap();
    let retry = PrivateKeyPackageHandOff {
        from: laptop_slot,
        to: phone_slot,
        key_packages: issued(&devices.laptop)
            .into_iter()
            .filter(|record| record.recipient_slot == phone_slot)
            .map(|record| KeyPackage::new(record.key_package))
            .collect(),
    };
    assert_eq!(retry.key_packages.len(), 10);
    devices
        .laptop
        .send_device_group_message(
            &group,
            KIND_PRIVATE_KEY_PACKAGE_HAND_OFF,
            base64::engine::general_purpose::STANDARD.encode(retry.encode().unwrap()),
        )
        .await
        .unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(received_from(&devices.phone, &laptop_slot).len(), 10);
    let selected = devices
        .phone
        .next_private_key_package_for_chat(&chat, &laptop_slot, &mut selection)
        .unwrap()
        .expect("the same retained context sees an authentic resend once insertion commits");
    assert!(
        issued(&devices.laptop)
            .iter()
            .any(|record| hex::encode(&record.key_package_ref) == selected.key_package_ref_hex)
    );
}

/// A sibling takes one KeyPackage to add the issuer to a chat, asks for a
/// burst, and discards everything exchanged with a removed sibling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_takes_asks_for_more_and_discards_private_key_packages() {
    let (mut devices, _) = tagging_devices().await;
    let (phone_slot, laptop_slot) = (slot(&devices.phone), slot(&devices.laptop));

    let taken = take_private_key_package(&devices.laptop, &phone_slot);
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

/// Lost hand-offs can fill the phone's cap for the laptop, after which it
/// issues no more. Once delivery is back, the laptop's next request is
/// answered with the newest KeyPackages the phone already issued, handed
/// over again, long before any expires (mdk#2628 D42).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_at_the_cap_hands_over_again_what_was_lost() {
    let (mut devices, _) = settled_linked_devices().await;
    let (phone_slot, laptop_slot) = (slot(&devices.phone), slot(&devices.laptop));
    let cap = cgka_engine::private_key_packages::MAX_RETAINED_PRIVATE_KEY_PACKAGES;
    let to_laptop = |phone: &AppClient| {
        issued(phone)
            .into_iter()
            .filter(|record| record.recipient_slot == laptop_slot)
            .count()
    };
    let ask_for_a_burst = |devices: &mut Devices| {
        devices
            .laptop
            .want_private_key_packages(&phone_slot, 100)
            .unwrap();
    };

    // Each burst is issued and handed over, and the laptop loses it.
    for _ in 0..3 {
        ask_for_a_burst(&mut devices);
        devices.laptop.run_due_maintenance().await.unwrap();
        deliver_all(&mut devices.phone, &devices.relay).await;
        devices.phone.run_due_maintenance().await.unwrap();
        deliver_all(&mut devices.laptop, &devices.relay).await;
        devices_storage(&devices.laptop)
            .delete_received_private_key_packages_from(&hex::encode(phone_slot))
            .unwrap();
    }
    assert_eq!(to_laptop(&devices.phone), cap);

    ask_for_a_burst(&mut devices);
    devices.laptop.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(to_laptop(&devices.phone), cap, "nothing new is issued");
    devices.phone.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.laptop, &devices.relay).await;
    assert_eq!(received_from(&devices.laptop, &phone_slot).len(), 100);
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

/// The laptop adds the phone to `chat` with one of the phone's private
/// KeyPackages, and the test takes the sibling Welcome that leaves owed off
/// the laptop's list, so only the test sends it.
async fn adding_the_phone(devices: &mut Devices, chat: &GroupId) -> SiblingWelcome {
    add_the_phone_unpublished(devices, chat).await;
    take_owed_sibling_welcome(&devices.laptop)
}

/// The laptop adds the phone to `chat` with one of the phone's private
/// KeyPackages, confirming a Commit it never publishes, which leaves the
/// sibling Welcome owed.
async fn add_the_phone_unpublished(devices: &mut Devices, chat: &GroupId) {
    let phone_slot = slot(&devices.phone);
    let key_package = take_private_key_package(&devices.laptop, &phone_slot);
    confirm_unpublished(
        &mut devices.laptop,
        SendIntent::AddOwnAccountDevices {
            group_id: chat.clone(),
            siblings: vec![SiblingKeyPackage {
                slot: phone_slot,
                key_package,
            }],
        },
    )
    .await;
}

fn owed(client: &AppClient) -> Vec<marmot_session::OwedSiblingWelcome> {
    client.runtime.owed_sibling_welcomes(Timestamp(0)).unwrap()
}

/// Send `intent` through `client`'s session and confirm the Commit it
/// makes without publishing it: that Commit.
async fn confirm_unpublished(client: &mut AppClient, intent: SendIntent) -> TransportMessage {
    let session = client.runtime.session_mut();
    let effects = session.send(intent).await.unwrap();
    let Some(PublishWork::GroupEvolution { msg, pending, .. }) = effects.publish.into_iter().next()
    else {
        panic!("expected a group evolution")
    };
    session.confirm_published(pending).await.unwrap();
    msg
}

/// The one sibling Welcome `client` owes, settled as though a 461 had
/// delivered it.
fn take_owed_sibling_welcome(client: &AppClient) -> SiblingWelcome {
    let [owed] = <[_; 1]>::try_from(owed(client)).unwrap();
    let carrier = [0xfe; 32];
    assert!(
        client
            .runtime
            .carry_sibling_welcome(&owed.id, &carrier)
            .unwrap()
    );
    assert!(
        client
            .runtime
            .sibling_welcome_delivered(&owed.id, &carrier)
            .unwrap()
    );
    SiblingWelcome::decode(&owed.content).unwrap()
}

/// The laptop removes the phone from `chat` and adds it back with another
/// private KeyPackage, publishing neither commit, so the phone still holds
/// its copy active: the sibling Welcome that adds it back, and the removal.
async fn re_adding_the_phone(
    devices: &mut Devices,
    chat: &GroupId,
) -> (SiblingWelcome, NostrTransportEvent) {
    let phone_key = devices.phone.runtime.own_signature_key();
    let removal = confirm_unpublished(
        &mut devices.laptop,
        SendIntent::RemoveOwnAccountDevices {
            group_id: chat.clone(),
            leaf_signature_keys: vec![phone_key],
        },
    )
    .await;
    (
        adding_the_phone(devices, chat).await,
        NostrTransportEvent::from_transport_message(&removal).unwrap(),
    )
}

/// A chat the phone joins from a sibling Welcome, with the sibling Welcome
/// that adds it back after a removal it has not seen, and that removal.
async fn chat_re_adding_the_phone(
    devices: &mut Devices,
    group: &GroupId,
    chat: GroupId,
) -> (GroupId, SiblingWelcome, NostrTransportEvent) {
    let welcome = adding_the_phone(devices, &chat).await;
    send_sibling_welcome(&mut devices.laptop, group, &welcome).await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(devices.phone.state_group_record(&chat).is_some());
    let (again, removal) = re_adding_the_phone(devices, &chat).await;
    (chat, again, removal)
}

/// The chat each stashed sibling Welcome is held for, in stash order.
fn held_for(client: &AppClient) -> Vec<Option<GroupId>> {
    devices_storage(client)
        .stashed_sibling_welcomes()
        .unwrap()
        .into_iter()
        .map(|record| {
            record
                .held_group_id_hex
                .map(|chat| GroupId::new(hex::decode(chat).unwrap()))
        })
        .collect()
}

fn key_package_issued(client: &AppClient, welcome: &SiblingWelcome) -> bool {
    issued(client)
        .iter()
        .any(|record| record.key_package_ref == welcome.key_package_ref)
}

/// What a held sibling Welcome must leave alone: the chat's copy at its
/// epoch, no rejoin offer, and its private KeyPackage still issued.
fn assert_held_wrote_nothing(
    client: &AppClient,
    chat: &GroupId,
    welcome: &SiblingWelcome,
    epoch: cgka_traits::EpochId,
) {
    let record = client.runtime.group_record(chat).unwrap();
    assert!(!record.removed);
    assert_eq!(record.epoch, epoch);
    assert!(
        client
            .group_recovery_status(chat)
            .unwrap()
            .rejoin_invitations
            .is_empty()
    );
    assert!(key_package_issued(client, welcome));
}

fn group_storage(client: &AppClient) -> storage_sqlite::SqliteAccountStorage {
    client.app.account_storage("alice").unwrap()
}

async fn send_sibling_welcome(client: &mut AppClient, group: &GroupId, welcome: &SiblingWelcome) {
    let content = base64::engine::general_purpose::STANDARD.encode(welcome.encode().unwrap());
    assert!(
        client
            .send_device_group_message(group, KIND_SIBLING_WELCOME, content)
            .await
            .unwrap()
    );
}

fn stashed(client: &AppClient) -> usize {
    devices_storage(client)
        .stashed_sibling_welcomes()
        .unwrap()
        .len()
}

/// The phone stashes a sibling Welcome from the laptop and joins the chat
/// from the stash in its next maintenance pass, after a restart too. The
/// join consumes the private KeyPackage, so the same Welcome sent again is
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_adds_this_device_to_a_chat() {
    let (mut devices, group, [chat]) = tagging_devices_with_chats::<1>().await;
    let welcome = adding_the_phone(&mut devices, &chat).await;
    let original = group_storage(&devices.laptop)
        .invitation_admission(&chat)
        .unwrap()
        .unwrap();
    assert_eq!(welcome.invitation_generation, Some(original.generation));
    devices.laptop.drive_small_state().await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert!(devices.phone.state_group_record(&chat).is_none());
    let decision = devices_storage(&devices.phone)
        .invitation_decision(&hex::encode(chat.as_slice()), &original.generation)
        .unwrap()
        .unwrap();
    assert!(!decision.declined);
    assert_eq!(decision.version, 1);

    send_sibling_welcome(&mut devices.laptop, &group, &welcome).await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 1);
    assert!(devices.phone.state_group_record(&chat).is_none());

    drop(devices.phone);
    let mut phone = devices.phone_app.client("alice").await.unwrap();
    assert_eq!(stashed(&phone), 1);
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&phone), 0);
    let joined = phone.state_group_record(&chat).unwrap();
    assert!(
        !joined.pending_confirmation,
        "the retained pre-Welcome decision applies to the inherited admission after restart"
    );
    assert_eq!(
        group_storage(&phone)
            .invitation_admission(&chat)
            .unwrap()
            .unwrap()
            .generation,
        original.generation
    );
    assert!(
        issued(&phone)
            .iter()
            .all(|record| record.key_package_ref != welcome.key_package_ref)
    );

    send_sibling_welcome(&mut devices.laptop, &group, &welcome).await;
    deliver_all(&mut phone, &devices.relay).await;
    assert_eq!(stashed(&phone), 0);
}

/// A sibling Welcome sent in the device group before the phone's own commit
/// there, and read after it, is read in the epoch it was sent in: its
/// sender's leaf comes from that epoch's retained anchor, so it is stashed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_from_an_earlier_device_group_epoch_is_stashed() {
    let (mut devices, group, [chat]) = tagging_devices_with_chats::<1>().await;
    let welcome = adding_the_phone(&mut devices, &chat).await;
    let mut cursor = devices.relay.published_events.lock().unwrap().len();
    send_sibling_welcome(&mut devices.laptop, &group, &welcome).await;
    let epoch = devices.laptop.runtime.group_record(&group).unwrap().epoch;
    let phone_slot = own_slot(&devices.phone);
    devices
        .phone
        .rename_linked_device(&phone_slot, "Phone")
        .await
        .unwrap();
    assert!(devices.phone.runtime.group_record(&group).unwrap().epoch > epoch);
    deliver_new(&mut devices.phone, &devices.relay, &mut cursor).await;
    assert_eq!(stashed(&devices.phone), 1);
}

/// A sibling Welcome that reaches the phone before the removal it follows is
/// held, never offered (D72): the stash keeps each carrier under the chat's
/// id, and passes leave them, after a restart too, writing nothing while the
/// phone's copy is active. Once the removal lands, the next pass joins the
/// chat once with no consent asked, and the pass after it drops the other
/// carrier, whose KeyPackage that join used.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_into_a_chat_still_held_waits_for_its_removal() {
    let (mut devices, group, [chat_0]) = tagging_devices_with_chats::<1>().await;
    let (chat, again, removal) = chat_re_adding_the_phone(&mut devices, &group, chat_0).await;
    let epoch = devices.phone.runtime.group_record(&chat).unwrap().epoch;
    send_sibling_welcome(&mut devices.laptop, &group, &again).await;
    send_sibling_welcome(&mut devices.laptop, &group, &again).await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(held_for(&devices.phone), vec![None, None]);
    for _ in 0..2 {
        devices.phone.run_due_maintenance().await.unwrap();
        assert_eq!(
            held_for(&devices.phone),
            vec![Some(chat.clone()), Some(chat.clone())]
        );
        assert_held_wrote_nothing(&devices.phone, &chat, &again, epoch);
    }

    drop(devices.phone);
    let mut phone = devices.phone_app.client("alice").await.unwrap();
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(held_for(&phone).len(), 2);
    assert_held_wrote_nothing(&phone, &chat, &again, epoch);

    deliver_events(&mut phone, &[removal]).await;
    assert!(phone.runtime.group_record(&chat).unwrap().removed);
    phone.run_due_maintenance().await.unwrap();
    let record = phone.runtime.group_record(&chat).unwrap();
    assert!(!record.removed);
    assert_eq!(
        record.epoch,
        devices.laptop.runtime.group_record(&chat).unwrap().epoch
    );
    assert!(!key_package_issued(&phone, &again));
    assert!(
        phone
            .group_recovery_status(&chat)
            .unwrap()
            .rejoin_invitations
            .is_empty()
    );
    assert_eq!(held_for(&phone), vec![Some(chat.clone())]);
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&phone), 0);
    assert_eq!(phone.runtime.group_record(&chat).unwrap(), record);
}

/// A held sibling Welcome joins without consent once its chat's copy is
/// unrecoverable, as once it reads removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_sibling_welcome_joins_a_chat_whose_copy_is_unrecoverable() {
    use cgka_traits::storage::GroupStorage as _;
    let (mut devices, group, [chat_0]) = tagging_devices_with_chats::<1>().await;
    let (chat, again, _) = chat_re_adding_the_phone(&mut devices, &group, chat_0).await;
    send_sibling_welcome(&mut devices.laptop, &group, &again).await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(held_for(&devices.phone), vec![Some(chat.clone())]);

    let storage = group_storage(&devices.phone);
    let mut record = storage.get_group(&chat).unwrap();
    record.unrecoverable = true;
    storage.put_group(&record).unwrap();
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&devices.phone), 0);
    assert!(
        !devices
            .phone
            .runtime
            .group_record(&chat)
            .unwrap()
            .unrecoverable
    );
    assert!(!key_package_issued(&devices.phone, &again));
}

/// A join from the stash retires the chat's rejoin offers, as any join
/// does, and tells the host that chat's offers changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_from_the_stash_tells_the_host_of_the_offers_it_retires() {
    use cgka_traits::storage::{GroupStorage as _, WelcomeStorage as _};
    use cgka_traits::welcome::{PendingWelcome, RejoinWelcome};
    let (mut devices, group, [chat_0]) = tagging_devices_with_chats::<1>().await;
    let (chat, again, _) = chat_re_adding_the_phone(&mut devices, &group, chat_0).await;
    send_sibling_welcome(&mut devices.laptop, &group, &again).await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(held_for(&devices.phone), vec![Some(chat.clone())]);

    // A gift-wrapped Welcome back into the chat, stored as an offer while
    // the copy was active.
    let storage = group_storage(&devices.phone);
    storage
        .put_welcome(&PendingWelcome {
            message_id: MessageId::new(vec![0xe1; 32]),
            group_id: chat.clone(),
            welcome_bytes: vec![],
            rejoin: Some(RejoinWelcome {
                epoch: cgka_traits::EpochId(0),
                content_id: MessageId::new(vec![0xe2; 32]),
                welcomer: devices.phone.runtime.session().self_id(),
                local_state_token: vec![],
            }),
        })
        .unwrap();
    assert_eq!(
        devices
            .phone
            .group_recovery_status(&chat)
            .unwrap()
            .rejoin_invitations
            .len(),
        1
    );
    let mut record = storage.get_group(&chat).unwrap();
    record.unrecoverable = true;
    storage.put_group(&record).unwrap();
    devices.phone.pending_recovery_status_updates.clear();
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&devices.phone), 0);
    assert!(!key_package_issued(&devices.phone, &again));
    assert!(
        devices
            .phone
            .group_recovery_status(&chat)
            .unwrap()
            .rejoin_invitations
            .is_empty()
    );
    assert!(
        devices
            .phone
            .pending_recovery_status_updates
            .contains(&chat)
    );
}

/// A held sibling Welcome goes, joining nothing, once it never can: its
/// carrier is withdrawn, its private KeyPackage expires, or its chat is
/// disbanded or forgotten. Each exit takes only its own row; a pass with
/// none of them leaves every held row as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_sibling_welcome_goes_only_once_it_can_never_join() {
    use cgka_traits::storage::{
        GroupStorage as _, MessageStorage as _, PrivateKeyPackageStorage as _,
    };
    let (mut devices, group, [chat_0, chat_1, chat_2, chat_3]) =
        tagging_devices_with_chats::<4>().await;
    let (withdrawn, withdrawn_welcome, _) =
        chat_re_adding_the_phone(&mut devices, &group, chat_0).await;
    let (expired, expired_welcome, _) =
        chat_re_adding_the_phone(&mut devices, &group, chat_1).await;
    let (disbanded, disbanded_welcome, _) =
        chat_re_adding_the_phone(&mut devices, &group, chat_2).await;
    let (forgotten, forgotten_welcome, _) =
        chat_re_adding_the_phone(&mut devices, &group, chat_3).await;
    for welcome in [
        &withdrawn_welcome,
        &expired_welcome,
        &disbanded_welcome,
        &forgotten_welcome,
    ] {
        send_sibling_welcome(&mut devices.laptop, &group, welcome).await;
    }
    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.phone.run_due_maintenance().await.unwrap();
    // Rows stashed in the same second keep their carriers' order.
    let by_id = |chats: &mut Vec<GroupId>| chats.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    let held_chats = |client: &AppClient| {
        let mut chats: Vec<GroupId> = held_for(client).into_iter().map(Option::unwrap).collect();
        by_id(&mut chats);
        chats
    };
    let mut held = vec![
        withdrawn.clone(),
        expired.clone(),
        disbanded.clone(),
        forgotten.clone(),
    ];
    by_id(&mut held);
    assert_eq!(held_chats(&devices.phone), held);
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(held_chats(&devices.phone), held);

    let storage = group_storage(&devices.phone);
    let carrier = devices_storage(&devices.phone)
        .stashed_sibling_welcomes()
        .unwrap()
        .into_iter()
        .find(|record| {
            record.held_group_id_hex.as_deref() == Some(&hex::encode(withdrawn.as_slice()))
        })
        .unwrap()
        .message_id_hex;
    storage
        .update_message_state(
            &MessageId::new(hex::decode(carrier).unwrap()),
            cgka_traits::MessageState::EpochInvalidated,
        )
        .unwrap();
    devices.phone.run_due_maintenance().await.unwrap();
    held.retain(|chat| chat != &withdrawn);
    assert_eq!(held_chats(&devices.phone), held);
    assert!(key_package_issued(&devices.phone, &withdrawn_welcome));

    let mut key_package = storage
        .list_issued_private_key_packages()
        .unwrap()
        .into_iter()
        .find(|record| record.key_package_ref == expired_welcome.key_package_ref)
        .unwrap();
    key_package.not_after = unix_now_seconds();
    storage
        .put_issued_private_key_package(&key_package)
        .unwrap();
    devices.phone.run_due_maintenance().await.unwrap();
    held.retain(|chat| chat != &expired);
    assert_eq!(held_chats(&devices.phone), held);

    let mut record = storage.get_group(&disbanded).unwrap();
    record.disbanded = Some(cgka_traits::DisbandTombstone {
        epoch: record.epoch,
        actor: record.members[0].id.clone(),
        origin_commit_id: None,
        commit_digest: [0; 32],
        local_was_committer_leaf: false,
        former_members: record.members.clone(),
        announced: true,
    });
    storage.put_group(&record).unwrap();
    devices.phone.run_due_maintenance().await.unwrap();
    held.retain(|chat| chat != &disbanded);
    assert_eq!(held_chats(&devices.phone), held);
    assert!(key_package_issued(&devices.phone, &disbanded_welcome));

    assert!(devices.phone.forget_group_local(&forgotten).await.unwrap());
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&devices.phone), 0);
    assert!(key_package_issued(&devices.phone, &forgotten_welcome));
}

/// A chat this device forgot while it still held it active joins from the
/// same sibling Welcome sent again after the forget: the forget drops the
/// held row, and the new carrier dates the Welcome past the forget's cutoff.
/// This is the user's way out of a chat whose removal never arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forgotten_chat_joins_from_a_sibling_welcome_sent_again() {
    forget_then_send_again(true).await;
}

/// The same way out when the forget comes before any pass tried the
/// Welcome: the pass refuses that carrier, dated before the forget, and
/// keeps its KeyPackage, so the same Welcome in a later carrier joins.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chat_forgotten_before_any_pass_joins_from_a_sibling_welcome_sent_again() {
    forget_then_send_again(false).await;
}

/// The phone stashes a sibling Welcome back into a chat it still holds
/// active, holding it first if `held_first`, forgets the chat, and joins
/// from the same Welcome sent again after the forget.
async fn forget_then_send_again(held_first: bool) {
    use cgka_traits::storage::GroupStorage as _;
    let (mut devices, group, [chat_0]) = tagging_devices_with_chats::<1>().await;
    let (chat, again, _) = chat_re_adding_the_phone(&mut devices, &group, chat_0).await;
    send_sibling_welcome(&mut devices.laptop, &group, &again).await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    if held_first {
        devices.phone.run_due_maintenance().await.unwrap();
        assert_eq!(held_for(&devices.phone), vec![Some(chat.clone())]);
    } else {
        assert_eq!(held_for(&devices.phone), vec![None]);
    }

    assert!(devices.phone.forget_group_local(&chat).await.unwrap());
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&devices.phone), 0);
    assert!(devices.phone.state_group_record(&chat).is_none());
    assert!(key_package_issued(&devices.phone, &again));
    let cutoff = group_storage(&devices.phone)
        .group_local_reset_cutoff(&chat)
        .unwrap()
        .unwrap();
    while unix_now_seconds() <= cutoff.0 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    send_sibling_welcome(&mut devices.laptop, &group, &again).await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(held_for(&devices.phone), vec![None]);
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&devices.phone), 0);
    assert!(devices.phone.state_group_record(&chat).is_some());
    assert!(!key_package_issued(&devices.phone, &again));
}

/// The phone stashes only a sibling Welcome addressed to it, from a sibling
/// the roster lists, with a valid relay list and a KeyPackage it issued to
/// that sibling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_stashes_only_a_sibling_welcome_it_can_trust() {
    let (mut devices, group, [chat]) = tagging_devices_with_chats::<1>().await;
    let welcome = adding_the_phone(&mut devices, &chat).await;
    let (phone_slot, laptop_slot) = (slot(&devices.phone), slot(&devices.laptop));
    let refs = |client: &AppClient| -> Vec<Vec<u8>> {
        issued(client)
            .into_iter()
            .map(|record| record.key_package_ref)
            .collect()
    };
    let issued_before = refs(&devices.phone);

    let many: Vec<String> = (0..=NOSTR_ROUTING_MAX_RELAYS)
        .map(|index| format!("wss://relay{index}.example"))
        .collect();
    let refused = [
        // From a slot the roster does not list, and from the phone's own.
        SiblingWelcome {
            from: [0x77; 32],
            ..welcome.clone()
        },
        SiblingWelcome {
            from: phone_slot,
            ..welcome.clone()
        },
        // Addressed to the laptop.
        SiblingWelcome {
            to: laptop_slot,
            ..welcome.clone()
        },
        // A KeyPackage the phone never issued.
        SiblingWelcome {
            key_package_ref: vec![5; 32],
            ..welcome.clone()
        },
        // No relay, one off the relay URL profile, one repeated (as
        // spelled, or once parsed), too many.
        SiblingWelcome {
            relays: Vec::new(),
            ..welcome.clone()
        },
        SiblingWelcome {
            relays: vec!["http://relay.example".into()],
            ..welcome.clone()
        },
        SiblingWelcome {
            relays: vec!["wss://relay.example".into(); 2],
            ..welcome.clone()
        },
        SiblingWelcome {
            relays: vec!["wss://relay.example".into(), "wss://relay.example/".into()],
            ..welcome.clone()
        },
        SiblingWelcome {
            relays: vec!["wss://Relay.Example".into(), "wss://relay.example".into()],
            ..welcome.clone()
        },
        SiblingWelcome {
            relays: vec![
                "wss://relay.example:443".into(),
                "wss://relay.example".into(),
            ],
            ..welcome.clone()
        },
        SiblingWelcome {
            relays: many,
            ..welcome.clone()
        },
    ];
    for sibling_welcome in &refused {
        send_sibling_welcome(&mut devices.laptop, &group, sibling_welcome).await;
    }
    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&devices.phone), 0);
    assert!(devices.phone.state_group_record(&chat).is_none());
    assert_eq!(refs(&devices.phone), issued_before);

    send_sibling_welcome(&mut devices.laptop, &group, &welcome).await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 1);
}

/// A sibling Welcome whose carrier is withdrawn before the phone's next
/// maintenance pass, by a branch switch or a rollback that drops it, joins
/// nothing and leaves its KeyPackage issued. The same Welcome sent again, and
/// still delivered, joins, even behind a stash row whose id is corrupt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawn_sibling_welcome_joins_nothing() {
    use cgka_traits::storage::MessageStorage as _;
    let (mut devices, group, [chat]) = tagging_devices_with_chats::<1>().await;
    let welcome = adding_the_phone(&mut devices, &chat).await;
    let issued_before = issued(&devices.phone);
    fn invalidate(client: &AppClient, carrier: &MessageId) {
        let storage = client.app.account_storage("alice").unwrap();
        storage
            .update_message_state(carrier, cgka_traits::MessageState::EpochInvalidated)
            .unwrap();
    }
    fn drop_carrier(client: &AppClient, carrier: &MessageId) {
        let storage = client.app.account_storage("alice").unwrap();
        storage.delete_message(carrier).unwrap();
    }
    for withdraw in [invalidate, drop_carrier] {
        send_sibling_welcome(&mut devices.laptop, &group, &welcome).await;
        deliver_all(&mut devices.phone, &devices.relay).await;
        let [record] = <[_; 1]>::try_from(
            devices_storage(&devices.phone)
                .stashed_sibling_welcomes()
                .unwrap(),
        )
        .unwrap();
        withdraw(
            &devices.phone,
            &MessageId::new(hex::decode(&record.message_id_hex).unwrap()),
        );
        devices.phone.run_due_maintenance().await.unwrap();
        assert_eq!(stashed(&devices.phone), 0);
        assert!(devices.phone.state_group_record(&chat).is_none());
        assert_eq!(issued(&devices.phone), issued_before);
    }

    assert!(
        devices_storage(&devices.phone)
            .stash_sibling_welcome(&StashedSiblingWelcome {
                message_id_hex: "not hex".into(),
                content: welcome.encode().unwrap(),
                created_at: 0,
                received_at: 0,
                held_group_id_hex: None,
            })
            .unwrap()
    );
    send_sibling_welcome(&mut devices.laptop, &group, &welcome).await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 2);
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&devices.phone), 0);
    assert!(devices.phone.state_group_record(&chat).is_some());
}

/// Deliver every group message on `relay` to `client`, whatever projecting
/// it does.
async fn deliver_group_messages_letting_projection_fail(
    client: &mut AppClient,
    relay: &ScriptedPushRelayClient,
) -> usize {
    let events = relay.published_events.lock().unwrap().clone();
    let account = client
        .app
        .account_home()
        .account(&client.state.label)
        .unwrap();
    let mut failed = 0;
    for event in events
        .iter()
        .filter(|event| event.kind == transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
    {
        let delivery = cgka_traits::TransportDelivery {
            account_id: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
            group_id_hint: None,
            message: event.to_transport_message().unwrap(),
            received_at: cgka_traits::Timestamp(unix_now_seconds()),
            source: cgka_traits::TransportDeliverySource {
                transport: cgka_traits::transport::TransportSource("nostr".into()),
                plane: cgka_traits::TransportDeliveryPlane::Group,
                endpoint: None,
                subscription_id: None,
                wire: None,
            },
        };
        failed += usize::from(client.ingest_received_delivery(delivery).await.is_err());
    }
    failed
}

/// A second connection to the phone's account database, for a test to make
/// one of its writes or reads fail.
fn phone_database(devices: &Devices) -> rusqlite::Connection {
    account_database(&devices.phone_app)
}

/// A second connection to `app`'s account database.
fn account_database(app: &MarmotApp) -> rusqlite::Connection {
    let path = app.account_storage_path("alice");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let key = app
        .sqlcipher_key("alice", &keys, &path, SqlcipherDatabaseKind::Session)
        .unwrap();
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
}

/// A sibling Welcome that admission cannot check, because a read it makes
/// fails, is not refused: the event's projection fails, is retried once the
/// read works again, and the phone joins the chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_whose_admission_read_fails_is_kept_on_retry() {
    let (mut devices, group, [chat]) = tagging_devices_with_chats::<1>().await;
    let welcome = adding_the_phone(&mut devices, &chat).await;
    send_sibling_welcome(&mut devices.laptop, &group, &welcome).await;

    let connection = phone_database(&devices);
    connection
        .execute_batch("ALTER TABLE cgka_private_key_packages RENAME TO held_aside")
        .unwrap();
    let failed =
        deliver_group_messages_letting_projection_fail(&mut devices.phone, &devices.relay).await;
    assert!(failed > 0);
    assert_eq!(stashed(&devices.phone), 0);

    connection
        .execute_batch("ALTER TABLE held_aside RENAME TO cgka_private_key_packages")
        .unwrap();
    devices.phone.drain_pending_session_events().await.unwrap();
    assert_eq!(stashed(&devices.phone), 1);
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(devices.phone.state_group_record(&chat).is_some());
}

/// A sibling Welcome admitted while its stash write fails is not lost: the
/// event's projection fails, is retried once the write works again, and the
/// phone joins the chat once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_whose_stash_write_fails_is_kept_on_retry() {
    let (mut devices, group, [chat]) = tagging_devices_with_chats::<1>().await;
    let welcome = adding_the_phone(&mut devices, &chat).await;
    send_sibling_welcome(&mut devices.laptop, &group, &welcome).await;

    let connection = phone_database(&devices);
    connection
        .execute_batch(
            "CREATE TRIGGER fail_stash BEFORE INSERT ON sibling_welcomes_received
             BEGIN SELECT RAISE(ABORT, 'injected stash failure'); END;",
        )
        .unwrap();
    let failed =
        deliver_group_messages_letting_projection_fail(&mut devices.phone, &devices.relay).await;
    assert!(failed > 0);
    assert_eq!(stashed(&devices.phone), 0);

    connection.execute_batch("DROP TRIGGER fail_stash").unwrap();
    devices.phone.drain_pending_session_events().await.unwrap();
    assert_eq!(stashed(&devices.phone), 1);
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&devices.phone), 0);
    assert!(devices.phone.state_group_record(&chat).is_some());

    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&devices.phone), 0);
    assert_eq!(
        devices
            .phone
            .state
            .groups
            .iter()
            .filter(|record| record.group_id_hex == hex::encode(chat.as_slice()))
            .count(),
        1
    );
}

/// Adding the phone to a chat publishes the Add's Commit and then sends the
/// sibling Welcome it leaves owed as a 461, which settles it delivered: no
/// later pass sends it again. The phone stashes it and joins the chat,
/// consuming the KeyPackage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adding_a_sibling_sends_its_welcome_once_the_commit_is_published() {
    let (mut devices, _, [chat]) = tagging_devices_with_chats::<1>().await;
    let phone_slot = slot(&devices.phone);
    let before = devices.relay.published_events.lock().unwrap().len();
    devices
        .laptop
        .add_sibling_to_chat(
            &chat,
            &phone_slot,
            private_candidate(&devices.laptop, &phone_slot),
        )
        .await
        .unwrap();
    assert_eq!(group_messages_since(&devices.relay, before), 2);
    assert!(owed(&devices.laptop).is_empty());
    devices.laptop.run_due_maintenance().await.unwrap();

    deliver_all(&mut devices.phone, &devices.relay).await;
    let [stashed] = <[_; 1]>::try_from(
        devices_storage(&devices.phone)
            .stashed_sibling_welcomes()
            .unwrap(),
    )
    .unwrap();
    let welcome = SiblingWelcome::decode(&stashed.content).unwrap();
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(devices.phone.state_group_record(&chat).is_some());
    assert!(!key_package_issued(&devices.phone, &welcome));
}

/// A sibling Welcome whose 461 every relay refused stays owed, never
/// delivered, and the next pass sends it in a new 461, which the phone
/// joins from.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_whose_461_reached_no_one_is_sent_again() {
    use cgka_traits::MessageStorage as _;
    let (mut devices, _, [chat]) = tagging_devices_with_chats::<1>().await;
    add_the_phone_unpublished(&mut devices, &chat).await;
    let pending = owed(&devices.laptop).remove(0);
    let group = devices.laptop.runtime.device_tag_group().unwrap().clone();
    let event = devices
        .laptop
        .device_group_event(
            KIND_SIBLING_WELCOME,
            base64::engine::general_purpose::STANDARD.encode(&pending.content),
        )
        .unwrap();
    let event = cgka_traits::MarmotAppEvent::new(
        event.pubkey,
        event.created_at.saturating_sub(601),
        event.kind,
        event.tags,
        event.content,
    );
    let reserved = hex::decode(&event.id).unwrap();
    assert!(
        devices
            .laptop
            .runtime
            .reserve_sibling_welcome_carrier(
                &pending.id,
                &group,
                &slot(&devices.phone),
                &reserved,
                event.created_at,
            )
            .unwrap()
    );

    devices.relay.reject_next_publish();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    let [refused] = <[_; 1]>::try_from(owed(&devices.laptop)).unwrap();
    assert_eq!(refused.carrier, None);
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 0);

    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert!(owed(&devices.laptop).is_empty());
    let record = group_storage(&devices.laptop)
        .get_message(&pending.id)
        .unwrap();
    assert!(
        matches!(cgka_traits::StoredMessagePayload::decode(&record.payload).unwrap(),
        cgka_traits::StoredMessagePayload::OutboundSiblingWelcome { carrier: Some(carrier), .. }
        if carrier == reserved),
        "an unexposed reservation must retry the exact old carrier after clock movement"
    );
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 1);
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(devices.phone.state_group_record(&chat).is_some());
}

/// A sibling Welcome left owed when the app stops is sent once after the
/// restart, and so is one whose 461 was still in flight: a carrier this run
/// never sent is dropped, and the Welcome goes in a new 461.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_owed_across_a_restart_is_sent_once() {
    let (mut devices, _, [owed_chat, carried_chat]) = tagging_devices_with_chats::<2>().await;
    add_the_phone_unpublished(&mut devices, &owed_chat).await;
    add_the_phone_unpublished(&mut devices, &carried_chat).await;
    let carried = owed(&devices.laptop)
        .into_iter()
        .find(|owed| owed.group_id == carried_chat)
        .unwrap();
    assert!(
        devices
            .laptop
            .runtime
            .carry_sibling_welcome(&carried.id, &[0xfe; 32])
            .unwrap()
    );

    drop(devices.laptop);
    let mut laptop = devices.laptop_app.client("alice").await.unwrap();
    laptop.run_due_maintenance().await.unwrap();
    assert!(owed(&laptop).is_empty());
    laptop.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 2);
    devices.phone.run_due_maintenance().await.unwrap();
    for chat in [owed_chat, carried_chat] {
        assert!(devices.phone.state_group_record(&chat).is_some());
    }
}

/// A 461 this run sent stays in flight until the effects that publish or
/// fail it settle it: a pass that finds its carrier on the owed Welcome
/// leaves the carrier alone and sends no second 461.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_in_flight_is_not_sent_again() {
    let (mut devices, _, [chat]) = tagging_devices_with_chats::<1>().await;
    add_the_phone_unpublished(&mut devices, &chat).await;
    let [carried] = &owed(&devices.laptop)[..] else {
        panic!("one owed sibling Welcome");
    };
    assert!(
        devices
            .laptop
            .runtime
            .carry_sibling_welcome(&carried.id, &[0xfe; 32])
            .unwrap()
    );
    devices
        .laptop
        .sibling_welcome_carriers
        .insert(vec![0xfe; 32]);

    devices.laptop.run_due_maintenance().await.unwrap();
    let [still] = &owed(&devices.laptop)[..] else {
        panic!("the Welcome stays owed");
    };
    assert_eq!(still.carrier.as_deref(), Some(&[0xfe; 32][..]));
    assert!(
        devices
            .laptop
            .sibling_welcome_carriers
            .contains(&vec![0xfe; 32])
    );
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 0);
}

/// A source chat settling another Commit hides its Welcome from the send
/// list, but app effects still settle its exact existing carrier. A failed
/// one waits for Ready, and a published one never gets a second 461.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn carried_sibling_welcome_outcomes_settle_while_the_chat_is_held() {
    use cgka_traits::storage::MessageStorage as _;
    use cgka_traits::{MessageState, StoredMessagePayload};
    let (mut devices, device_group, chats) = tagging_devices_with_chats::<2>().await;
    let mut rows = Vec::new();
    let mut pending = Vec::new();
    for (chat, carrier) in chats.into_iter().zip([vec![0xfd; 32], vec![0xfe; 32]]) {
        add_the_phone_unpublished(&mut devices, &chat).await;
        let welcome = owed(&devices.laptop)
            .into_iter()
            .find(|row| row.group_id == chat)
            .unwrap();
        assert!(
            devices
                .laptop
                .runtime
                .carry_sibling_welcome(&welcome.id, &carrier)
                .unwrap()
        );
        devices
            .laptop
            .sibling_welcome_carriers
            .insert(carrier.clone());
        let effects = devices
            .laptop
            .runtime
            .session_mut()
            .send(SendIntent::SelfUpdate { group_id: chat })
            .await
            .unwrap();
        let Some(PublishWork::GroupEvolution { pending: token, .. }) =
            effects.publish.into_iter().next()
        else {
            panic!("expected a pending Commit");
        };
        pending.push(token);
        rows.push((welcome.id, carrier));
    }
    assert!(owed(&devices.laptop).is_empty());
    let effects = marmot_session::AccountDeviceEffects {
        published_app_messages: vec![marmot_session::PublishedApplicationMessage {
            publication_observation: None,
            group_id: device_group.clone(),
            app_event_id: hex::encode(&rows[0].1),
            message_id: MessageId::new(vec![1]),
            source_epoch: cgka_traits::EpochId(0),
            retention: cgka_traits::app_event::AppMessageRetentionDecision::new(10, 0),
            authority: None,
        }],
        failed_app_messages: vec![marmot_session::FailedApplicationMessage {
            group_id: device_group,
            app_event_id: hex::encode(&rows[1].1),
            message_id: MessageId::new(vec![2]),
            reason: "every target refused".into(),
        }],
        ..Default::default()
    };
    devices
        .laptop
        .settle_sibling_welcome_carriers(&effects)
        .unwrap();
    let storage = group_storage(&devices.laptop);
    assert_eq!(
        storage.get_message(&rows[0].0).unwrap().state,
        MessageState::Processed
    );
    let failed = storage.get_message(&rows[1].0).unwrap();
    assert_eq!(failed.state, MessageState::Sent);
    assert!(matches!(
        StoredMessagePayload::decode(&failed.payload).unwrap(),
        StoredMessagePayload::OutboundSiblingWelcome { carrier: None, .. }
    ));
    assert!(devices.laptop.sibling_welcome_carriers.is_empty());
    // A stale ready selection may now find this chat held. The real engine
    // callback declines, rolling back its carrier-time reservation on the
    // same runtime connection instead of self-locking against the app handle.
    let error = devices
        .laptop
        .runtime
        .reserve_sibling_welcome_carrier(
            &rows[1].0,
            devices.laptop.runtime.device_tag_group().unwrap(),
            &slot(&devices.phone),
            b"declined-carrier",
            crate::unix_now_seconds(),
        )
        .unwrap_err();
    assert!(matches!(error.as_engine_error(),
        Some(cgka_traits::EngineError::Storage(cgka_traits::StorageError::Backend(message)))
        if message == "sibling Welcome readiness changed"));
    let reserved: bool = account_database(&devices.laptop_app)
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sibling_welcome_resends WHERE welcome_id = ?1)",
            rusqlite::params![rows[1].0.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !reserved,
        "declined engine attachment must commit no reservation metadata"
    );
    let before = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(group_messages_since(&devices.relay, before), 0);
    for token in pending {
        devices
            .laptop
            .runtime
            .session_mut()
            .publish_failed(token)
            .await
            .unwrap();
    }
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(group_messages_since(&devices.relay, before), 1);
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(group_messages_since(&devices.relay, before), 1);
    assert!(owed(&devices.laptop).is_empty());
}

/// A failed settlement keeps the accepted fanout replayable. No replacement
/// carrier is created before the original publication projects successfully;
/// retry settles that same accepted carrier without another send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_whose_settling_fails_replays_its_accepted_carrier() {
    let (mut devices, _, [chat]) = tagging_devices_with_chats::<1>().await;
    add_the_phone_unpublished(&mut devices, &chat).await;
    let [owed_welcome] = <[_; 1]>::try_from(owed(&devices.laptop)).unwrap();
    let connection = account_database(&devices.laptop_app);
    connection
        .execute_batch(&format!(
            "CREATE TRIGGER fail_settle BEFORE UPDATE ON cgka_messages
             WHEN OLD.id = X'{}' AND NEW.state <> OLD.state
             BEGIN SELECT RAISE(ABORT, 'injected settle failure'); END;",
            hex::encode(owed_welcome.id.as_slice())
        ))
        .unwrap();

    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    let [unsettled] = <[_; 1]>::try_from(owed(&devices.laptop)).unwrap();
    let carrier = unsettled.carrier.unwrap();
    assert!(!devices.laptop.sibling_welcome_carriers.contains(&carrier));

    let sent = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(devices.relay.published_events.lock().unwrap().len(), sent);
    connection
        .execute_batch("DROP TRIGGER fail_settle")
        .unwrap();
    devices.laptop.drain_pending_session_events().await.unwrap();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(devices.relay.published_events.lock().unwrap().len(), sent);
    assert!(owed(&devices.laptop).is_empty());
    assert!(devices.laptop.sibling_welcome_carriers.is_empty());
    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(devices.phone.state_group_record(&chat).is_some());
}

/// A 461 is pinned to the epoch whose tag was read, so the engine refuses
/// it rather than queue it behind a commit that may change that tag: a pass
/// while the laptop's own device-group Commit waits on its publication
/// queues nothing, leaves the Welcome owed with no carrier, and the pass
/// after that Commit fails sends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_pinned_sibling_welcome_is_sent_by_the_next_pass() {
    let (mut devices, group, [chat]) = tagging_devices_with_chats::<1>().await;
    add_the_phone_unpublished(&mut devices, &chat).await;
    let effects = devices
        .laptop
        .runtime
        .session_mut()
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    let Some(PublishWork::GroupEvolution { pending, .. }) = effects.publish.into_iter().next()
    else {
        panic!("expected a group evolution")
    };

    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    let [waiting] = <[_; 1]>::try_from(owed(&devices.laptop)).unwrap();
    assert_eq!(waiting.carrier, None);
    assert!(devices.laptop.sibling_welcome_carriers.is_empty());
    assert!(
        !devices
            .laptop
            .runtime
            .has_queued_outbound_intents(&group)
            .unwrap()
    );
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 0);

    devices
        .laptop
        .runtime
        .session_mut()
        .publish_failed(pending)
        .await
        .unwrap();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert!(owed(&devices.laptop).is_empty());
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 1);
}

/// A 461 is pinned to the branch its tag was read on, not only the epoch
/// number. A rival device-group commit from the same epoch that wins branch
/// selection inside the 461's own send refuses it before anything is
/// encrypted; the Welcome stays owed, and the next pass sends it on the
/// selected branch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_refused_by_a_same_number_rival_is_sent_by_the_next_pass() {
    let (mut devices, group, [chat]) = tagging_devices_with_chats::<1>().await;
    add_the_phone_unpublished(&mut devices, &chat).await;
    let settling = |ms| CanonicalizationPolicy {
        settlement_quiescence_ms: ms,
        ..CanonicalizationPolicy::default()
    };
    devices
        .laptop
        .runtime
        .session_mut()
        .set_convergence_policy(settling(3_600_000))
        .unwrap();

    // The laptop's own ordinary commit, and the phone's privileged one from
    // the same epoch, which wins branch selection whatever the digests.
    let source = devices.laptop.runtime.epoch_pin(&group).unwrap();
    confirm_unpublished(
        &mut devices.laptop,
        SendIntent::SelfUpdate {
            group_id: group.clone(),
        },
    )
    .await;
    let mut cursor = devices.relay.published_events.lock().unwrap().len();
    devices
        .phone
        .runtime
        .send(SendIntent::UpdateGroupData {
            group_id: group.clone(),
            name: Some("devices".into()),
            description: None,
        })
        .await
        .unwrap();
    deliver_new(&mut devices.laptop, &devices.relay, &mut cursor).await;
    let pin = devices.laptop.runtime.epoch_pin(&group).unwrap();
    assert_eq!(pin.epoch.0, source.epoch.0 + 1);
    let rival = devices.phone.runtime.epoch_pin(&group).unwrap();
    assert_eq!(rival.epoch, pin.epoch);
    assert_ne!(rival, pin);
    assert!(
        devices
            .laptop
            .device_group_exchange()
            .unwrap()
            .unwrap()
            .tagged
    );

    devices
        .laptop
        .runtime
        .session_mut()
        .set_convergence_policy(settling(0))
        .unwrap();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(
        devices.laptop.runtime.epoch_pin(&group).unwrap(),
        rival,
        "the 461's send must have selected the phone's branch"
    );
    let [waiting] = <[_; 1]>::try_from(owed(&devices.laptop)).unwrap();
    assert_eq!(waiting.carrier, None);
    assert!(devices.laptop.sibling_welcome_carriers.is_empty());
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 0);

    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert!(owed(&devices.laptop).is_empty());
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 1);
}

/// A sibling Welcome goes out only once its Add's Commit is published: an
/// Add whose Commit every relay refused fails, and neither it nor a later
/// Welcome-delivery pass sends that Welcome. The failed Add spent its
/// KeyPackage, which is not handed back. Adding the phone again goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_waits_for_its_commit() {
    let (mut devices, _, [chat]) = tagging_devices_with_chats::<1>().await;
    let phone_slot = slot(&devices.phone);
    let stock = received_from(&devices.laptop, &phone_slot).len();
    devices.relay.reject_next_publish();
    let error = devices
        .laptop
        .add_sibling_to_chat(
            &chat,
            &phone_slot,
            private_candidate(&devices.laptop, &phone_slot),
        )
        .await
        .unwrap_err();
    assert_eq!(error.privacy_safe_kind(), "publish");
    assert_eq!(received_from(&devices.laptop, &phone_slot).len(), stock - 1);
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 0);

    devices
        .laptop
        .add_sibling_to_chat(
            &chat,
            &phone_slot,
            private_candidate(&devices.laptop, &phone_slot),
        )
        .await
        .unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 1);
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(devices.phone.state_group_record(&chat).is_some());
}

/// An Add the engine refuses spends its KeyPackage too, and never hands it
/// back: a chat routed through two spellings of one relay, which the phone
/// would read as one, takes no sibling, and nothing is published or owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_sibling_add_spends_its_key_package() {
    let (mut devices, _) = tagging_devices().await;
    let chat = devices
        .laptop
        .create_group_with_options(
            "chat",
            &[],
            crate::AppCreateGroupOptions {
                relays: Some(vec![
                    "wss://relay.example".to_owned(),
                    "wss://relay.example/".to_owned(),
                ]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let phone_slot = slot(&devices.phone);
    let stock = received_from(&devices.laptop, &phone_slot).len();
    let before = devices.relay.published_events.lock().unwrap().len();
    let error = devices
        .laptop
        .add_sibling_to_chat(
            &chat,
            &phone_slot,
            private_candidate(&devices.laptop, &phone_slot),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("none repeated once parsed"),
        "{error}"
    );
    assert_eq!(received_from(&devices.laptop, &phone_slot).len(), stock - 1);
    assert_eq!(devices.relay.published_events.lock().unwrap().len(), before);
    assert!(owed(&devices.laptop).is_empty());
}

/// An Add queued behind the chat's convergence spends its KeyPackage
/// whatever the drain makes of it: with the laptop no longer tagged by the
/// time bob's Commit settles, the drain refuses the Add, and the KeyPackage
/// is not handed back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_sibling_add_the_drain_refuses_spends_its_key_package() {
    let (mut devices, _, [chat]) = tagging_devices_with_chats::<1>().await;
    let bob_id = AccountHome::open(devices._dirs[1].path())
        .create_account("bob")
        .unwrap()
        .account_id_hex;
    remember_test_member_inbox(&devices.laptop_app, &bob_id, "wss://relay.example");
    let mut bob = devices.laptop_app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();
    devices
        .laptop
        .invite_members(&chat, &[&bob_id])
        .await
        .unwrap();
    deliver_all(&mut bob, &devices.relay).await;
    bob.accept_group_invite(&chat).unwrap();

    let settling = |ms| CanonicalizationPolicy {
        settlement_quiescence_ms: ms,
        ..CanonicalizationPolicy::default()
    };
    devices
        .laptop
        .runtime
        .session_mut()
        .set_convergence_policy(settling(3_600_000))
        .unwrap();
    let mut cursor = devices.relay.published_events.lock().unwrap().len();
    bob.runtime
        .send(SendIntent::SelfUpdate {
            group_id: chat.clone(),
        })
        .await
        .unwrap();
    deliver_new(&mut devices.laptop, &devices.relay, &mut cursor).await;
    let phone_slot = slot(&devices.phone);
    let stock = received_from(&devices.laptop, &phone_slot).len();
    devices
        .laptop
        .add_sibling_to_chat(
            &chat,
            &phone_slot,
            private_candidate(&devices.laptop, &phone_slot),
        )
        .await
        .unwrap();
    assert!(
        devices
            .laptop
            .runtime
            .has_queued_outbound_intents(&chat)
            .unwrap()
    );
    assert_eq!(received_from(&devices.laptop, &phone_slot).len(), stock - 1);

    let session = devices.laptop.runtime.session_mut();
    session.set_device_tag_group(None).unwrap();
    session.set_convergence_policy(settling(0)).unwrap();
    devices.laptop.retry_group_convergence(&chat).await.unwrap();
    assert!(
        !devices
            .laptop
            .runtime
            .has_queued_outbound_intents(&chat)
            .unwrap()
    );
    assert_eq!(devices.laptop.runtime.members(&chat).unwrap().len(), 2);
    assert_eq!(received_from(&devices.laptop, &phone_slot).len(), stock - 1);
    assert!(owed(&devices.laptop).is_empty());
}

/// Holding a sibling's private stock does not make this device's own leaf
/// ready to carry its Welcome. Founding skips siblings until the leaf is
/// tagged, and a later loss of readiness holds the initial carrier unsent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn founding_and_initial_welcome_wait_for_the_senders_own_tag() {
    let (mut devices, group) = linked_devices().await;
    let (phone_slot, laptop_slot) = (slot(&devices.phone), slot(&devices.laptop));
    devices.phone.sibling_key_package_upkeep(&[]).await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let held = received_from(&devices.laptop, &phone_slot).len();
    assert!(
        held > 0,
        "the sibling handed over real private stock before this device tagged"
    );
    assert!(
        !devices
            .laptop
            .device_group_exchange()
            .unwrap()
            .unwrap()
            .tagged
    );
    let alone = devices
        .laptop
        .create_group("before sender ready", &[])
        .await
        .unwrap();
    assert_eq!(
        devices
            .laptop
            .runtime
            .group_record(&alone)
            .unwrap()
            .members
            .len(),
        1
    );
    assert_eq!(received_from(&devices.laptop, &phone_slot).len(), held);

    devices.laptop.set_device_tag_key().await.unwrap();
    assert!(
        devices
            .laptop
            .device_group_exchange()
            .unwrap()
            .unwrap()
            .tagged
    );
    // The host's maintenance pause keeps the initial Welcome unsent while
    // the creator's device-group tag is lost after canonical creation.
    devices.laptop.pause_maintenance();
    let chat = devices
        .laptop
        .create_group("sender ready", &[])
        .await
        .unwrap();
    assert_eq!(
        devices
            .laptop
            .runtime
            .group_record(&chat)
            .unwrap()
            .members
            .len(),
        2
    );
    devices
        .laptop
        .runtime
        .edit_device_roster_entry(&group, &laptop_slot, &[], |entry| {
            entry.tag_signature_key = None;
        })
        .await
        .unwrap();
    assert!(
        !devices
            .laptop
            .device_group_exchange()
            .unwrap()
            .unwrap()
            .tagged
    );
    devices.laptop.resume_maintenance();
    let before = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(devices.relay.published_events.lock().unwrap().len(), before);
    let owed = devices
        .laptop
        .runtime
        .owed_sibling_welcomes(Timestamp(unix_now_seconds()))
        .unwrap();
    assert_eq!(
        owed.iter()
            .filter(|welcome| welcome.group_id == chat)
            .count(),
        1
    );
    assert!(
        owed.iter()
            .filter(|welcome| welcome.group_id == chat)
            .all(|welcome| welcome.carrier.is_none())
    );
    devices.laptop.set_device_tag_key().await.unwrap();
    // A damaged optional activity fact must not suppress this INITIAL send.
    // Real DG selected-state/tag/hold reads above remain independently required.
    let source_store = account_database(&devices.laptop_app);
    let damaged = source_store.query_row(
        "SELECT id, source_proof, source_resolved FROM cgka_processed_transport_ids WHERE source_has_leaf=1 LIMIT 1",
        [], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?)),
    ).unwrap();
    source_store.execute("UPDATE cgka_processed_transport_ids SET source_proof=x'ff', source_resolved=0 WHERE id=?1", [&damaged.0]).unwrap();
    let projection_error = devices
        .laptop
        .observe_pending_sibling_welcome_activity()
        .unwrap_err();
    assert!(
        matches!(
            projection_error.as_engine_error(),
            Some(cgka_traits::EngineError::Storage(
                cgka_traits::StorageError::Serialization(_)
            ))
        ) || matches!(
            projection_error,
            crate::AppError::Storage(cgka_traits::StorageError::Serialization(_))
        ),
        "must reach the corrupt optional proof: {projection_error:?}"
    );
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    source_store.execute("UPDATE cgka_processed_transport_ids SET source_proof=?2, source_resolved=?3 WHERE id=?1", rusqlite::params![damaged.0, damaged.1, damaged.2]).unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.phone.join_stashed_sibling_welcomes().await;
    assert!(devices.phone.state_group_record(&chat).is_some());
}

/// The target's real trusted-DG traffic arms repair even though the lost
/// Welcome's Add already installed its tag. Once due, orchestration sends the
/// retained Welcome through a new 461 without a new Add or private KeyPackage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_published_sibling_welcome_is_repaired_after_new_authenticated_device_group_activity()
 {
    use cgka_traits::message::{MessageState, StoredMessagePayload};
    use cgka_traits::storage::MessageStorage as _;
    let (mut devices, device_group, [chat]) = tagging_devices_with_chats::<1>().await;
    let phone_slot = slot(&devices.phone);
    devices
        .phone
        .update_linked_device_settings(&hex::encode(phone_slot), Some(false), None, None)
        .await
        .unwrap();
    deliver_all(&mut devices.laptop, &devices.relay).await;
    assert!(
        !roster(&devices.laptop, &device_group).devices[&phone_slot]
            .settings
            .add_to_all_chats
    );
    add_the_phone_unpublished(&mut devices, &chat).await;
    let original_owed = owed(&devices.laptop).remove(0);
    // A delayed first publication carries a legitimately older rumor, but
    // activity/timing must begin after durable publication, not created_at.
    let event = devices
        .laptop
        .device_group_event(
            KIND_SIBLING_WELCOME,
            base64::engine::general_purpose::STANDARD.encode(&original_owed.content),
        )
        .unwrap();
    let event = cgka_traits::MarmotAppEvent::new(
        event.pubkey,
        event.created_at.saturating_sub(601),
        event.kind,
        event.tags,
        event.content,
    );
    let carrier = hex::decode(&event.id).unwrap();
    devices
        .laptop
        .runtime
        .reserve_sibling_welcome_carrier(
            &original_owed.id,
            &device_group,
            &phone_slot,
            &carrier,
            event.created_at,
        )
        .unwrap();
    devices
        .laptop
        .send_device_group_event(&device_group, event)
        .await
        .unwrap();
    let store = group_storage(&devices.laptop);
    let originals: Vec<_> = store
        .list_messages_in_states(&chat, &[MessageState::Processed], cgka_traits::EpochId(0))
        .unwrap()
        .into_iter()
        .filter_map(
            |record| match StoredMessagePayload::decode(&record.payload).unwrap() {
                StoredMessagePayload::OutboundSiblingWelcome { welcome, .. } => {
                    Some((record.id, welcome))
                }
                _ => None,
            },
        )
        .collect();
    let [(welcome_id, original)] = &originals[..] else {
        panic!("one delivered retained Welcome");
    };
    let storage = devices_storage(&devices.laptop);
    let now = crate::client::recovery::wall_now_ms().unwrap();
    assert!(
        storage
            .due_sibling_welcome_resends(now + 600_000)
            .unwrap()
            .is_empty(),
        "old link/stock activity does not arm repair"
    );
    assert!(
        devices.phone.state_group_record(&chat).is_none(),
        "the published Welcome has been lost to the target"
    );
    devices
        .phone
        .send_device_group_message(&device_group, 49_999, "any authenticated traffic".into())
        .await
        .unwrap();
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let [(due, _)] = &storage.due_sibling_welcome_resends(now + 601_000).unwrap()[..] else {
        panic!("first authenticated target activity arms one timer");
    };
    assert_eq!(due.as_slice(), welcome_id.as_slice());
    let epoch = devices.laptop.runtime.group_record(&chat).unwrap().epoch;
    let stock = received_from(&devices.laptop, &phone_slot);
    let before = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(
        devices.relay.published_events.lock().unwrap().len(),
        before,
        "not before its fixed wait"
    );
    // The storage owner proves 600-second timing. Advance only the produced
    // due schedule here to isolate orchestration without a real wall-clock wait.
    account_database(&devices.laptop_app)
        .execute(
            "UPDATE sibling_welcome_resends SET due_at_ms = 0
         WHERE welcome_id = ?1",
            rusqlite::params![welcome_id.as_slice()],
        )
        .unwrap();
    let connection = account_database(&devices.laptop_app);
    connection
        .execute_batch(
            "CREATE TRIGGER fail_reservation BEFORE UPDATE OF prepared_carrier
        ON sibling_welcome_resends BEGIN SELECT RAISE(ABORT, 'injected reservation failure'); END;",
        )
        .unwrap();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(
        devices.relay.published_events.lock().unwrap().len(),
        before,
        "failed durable reservation must expose no new carrier"
    );
    assert!(matches!(
        StoredMessagePayload::decode(&store.get_message(welcome_id).unwrap().payload).unwrap(),
        StoredMessagePayload::OutboundSiblingWelcome { carrier: None, .. }
    ));
    connection
        .execute_batch("DROP TRIGGER fail_reservation")
        .unwrap();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(
        group_messages_since(&devices.relay, before),
        1,
        "repair creates one carrier and no new Add"
    );
    assert_eq!(
        devices.laptop.runtime.group_record(&chat).unwrap().epoch,
        epoch
    );
    assert_eq!(received_from(&devices.laptop, &phone_slot), stock);
    let record = store.get_message(welcome_id).unwrap();
    assert_eq!(record.state, MessageState::Processed);
    assert!(
        matches!(StoredMessagePayload::decode(&record.payload).unwrap(),
        StoredMessagePayload::OutboundSiblingWelcome { welcome, .. } if &welcome == original)
    );
    assert!(
        storage
            .due_sibling_welcome_resends(now + 2_000_000)
            .unwrap()
            .is_empty(),
        "a successful generation needs fresh activity"
    );
    devices
        .phone
        .runtime
        .send(SendIntent::SelfUpdate {
            group_id: device_group.clone(),
        })
        .await
        .unwrap();
    deliver_all(&mut devices.laptop, &devices.relay).await;
    assert_eq!(
        storage
            .due_sibling_welcome_resends(crate::client::recovery::wall_now_ms().unwrap() + 600_001)
            .unwrap()
            .len(),
        1,
        "a real target Commit with no app message arms the next successful generation"
    );
    devices
        .phone
        .runtime
        .edit_device_roster_entry(&device_group, &phone_slot, &[], |entry| {
            entry.status = cgka_traits::app_components::DeviceStatusV1::Leaving;
        })
        .await
        .unwrap();
    deliver_all(&mut devices.laptop, &devices.relay).await;
    account_database(&devices.laptop_app)
        .execute(
            "UPDATE sibling_welcome_resends SET due_at_ms = 0 WHERE welcome_id = ?1",
            rusqlite::params![welcome_id.as_slice()],
        )
        .unwrap();
    let before_leaving = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(
        devices.relay.published_events.lock().unwrap().len(),
        before_leaving,
        "Leaving cannot start another carrier"
    );
    // A real accepted roster can omit a slot without a removal record. If
    // its remembered keys aged out, that absence is not authoritative gone.
    // The key-retention owner covers the clock; age only its produced rows.
    use cgka_traits::app_components::{
        AppComponentData, DEVICE_ROSTER_COMPONENT_ID, DeviceRosterOperationV1,
        DeviceRosterUpdateV1, encode_device_roster_update_v1,
    };
    let old_entry = roster(&devices.laptop, &device_group).devices[&phone_slot].clone();
    let roster_change = |operation| SendIntent::UpdateAppComponents {
        group_id: device_group.clone(),
        updates: vec![AppComponentData {
            component_id: DEVICE_ROSTER_COMPONENT_ID,
            data: encode_device_roster_update_v1(
                &DeviceRosterUpdateV1::new(vec![operation]).unwrap(),
            )
            .unwrap(),
        }],
    };
    devices
        .laptop
        .runtime
        .send(roster_change(DeviceRosterOperationV1::RemoveDevice(
            phone_slot,
        )))
        .await
        .unwrap();
    assert!(
        !roster(&devices.laptop, &device_group)
            .devices
            .contains_key(&phone_slot)
    );
    assert!(matches!(
        devices.laptop.runtime.epoch_state(&device_group),
        Some(cgka_traits::EpochState::Stable { .. })
    ));
    assert!(
        !devices
            .laptop
            .runtime
            .has_pending_convergence_inputs(&device_group)
            .unwrap()
    );
    let key_cutoff = crate::unix_now_seconds()
        .saturating_sub(cgka_traits::storage::ROSTER_TAG_KEY_RETENTION_SECS);
    assert!(
        cgka_traits::storage::RosterTagKeyStorage::roster_tag_keys(
            &store,
            &device_group,
            key_cutoff,
        )
        .unwrap()
        .iter()
        .any(|key| key.slot == phone_slot),
        "the actual roster supplied remembered device keys"
    );
    connection
        .execute(
            "UPDATE cgka_roster_tag_keys SET last_seen_at=0 WHERE group_id=?1 AND slot=?2",
            rusqlite::params![device_group.as_slice(), phone_slot.as_slice()],
        )
        .unwrap();
    assert!(
        cgka_traits::storage::RosterTagKeyStorage::roster_tag_keys(
            &store,
            &device_group,
            crate::unix_now_seconds()
                .saturating_sub(cgka_traits::storage::ROSTER_TAG_KEY_RETENTION_SECS),
        )
        .unwrap()
        .iter()
        .all(|key| key.slot != phone_slot)
    );
    let before_unknown = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(
        store.get_message(welcome_id).unwrap().state,
        MessageState::Processed,
        "unproven roster absence must not retire the retained Welcome"
    );
    assert_eq!(
        devices.relay.published_events.lock().unwrap().len(),
        before_unknown
    );
    assert_eq!(
        storage
            .due_sibling_welcome_resends(now + 2_000_000)
            .unwrap()
            .len(),
        1,
        "unproven absence retains its original due obligation"
    );
    // Restore this non-user state byte-for-byte, including its user marker.
    // A real accepted roster sighting refreshes the remembered key again.
    devices
        .laptop
        .runtime
        .send(roster_change(DeviceRosterOperationV1::SetDevice(
            phone_slot, old_entry,
        )))
        .await
        .unwrap();
    assert_eq!(
        store.get_message(welcome_id).unwrap().state,
        MessageState::Processed,
        "explicit removal starts with live retained repair debt"
    );
    assert_eq!(
        storage
            .due_sibling_welcome_resends(now + 2_000_000)
            .unwrap()
            .len(),
        1
    );
    devices
        .laptop
        .remove_linked_device(&hex::encode(phone_slot))
        .await
        .unwrap();
    let before_gone = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert_eq!(
        devices.relay.published_events.lock().unwrap().len(),
        before_gone,
        "gone target cannot start another carrier"
    );
    assert_eq!(
        store.get_message(welcome_id).unwrap().state,
        MessageState::Failed,
        "proven removal permanently retires the previously live Welcome"
    );
    assert!(
        storage
            .due_sibling_welcome_resends(now + 2_000_000)
            .unwrap()
            .is_empty()
    );
}

/// Real external admission, authenticated account-state ingress, zero-ack
/// Leave, and reopen belong together here; pure comparison is owned below.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shared_decline_keeps_native_leave_work_across_a_later_accept_and_restart() {
    use crate::small_state::{KIND_SMALL_STATE_UPDATE, encode_invitation_decision_updates};
    use cgka_traits::storage::{GroupStorage as _, LeaveRequestStorage as _};
    let (mut devices, device_group) = tagging_devices().await;
    published_key_package(&mut devices.phone, &devices.relay).await;
    published_key_package(&mut devices.laptop, &devices.relay).await;
    let alice = devices
        .phone_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let bob_dir = tempfile::tempdir().unwrap();
    AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap();
    let bob_app = crate::tests::canonical_membership::app_at(&bob_dir, devices.relay.clone());
    remember_test_member_inbox(&bob_app, &alice, "wss://relay.example");
    let mut bob = bob_app.client("bob").await.unwrap();
    let chat = bob
        .create_group("shared external admission", &[&alice])
        .await
        .unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let chat_hex = hex::encode(chat.as_slice());
    let phone_store = group_storage(&devices.phone);
    let laptop_store = group_storage(&devices.laptop);
    let original = phone_store.invitation_admission(&chat).unwrap().unwrap();
    assert_eq!(
        laptop_store
            .invitation_admission(&chat)
            .unwrap()
            .unwrap()
            .generation,
        original.generation
    );
    assert!(!original.created_locally);
    assert!(
        devices
            .phone
            .state_group_record(&chat)
            .unwrap()
            .pending_confirmation
    );
    assert!(
        devices
            .laptop
            .state_group_record(&chat)
            .unwrap()
            .pending_confirmation
    );
    devices.phone.set_group_archived(&chat, true).unwrap();
    assert!(devices.phone.accept_group_invite(&chat).unwrap().archived);
    assert_eq!(
        phone_store
            .app_storage()
            .invitation_decision(&chat_hex, &original.generation)
            .unwrap()
            .unwrap()
            .version,
        1
    );

    devices.relay.fail_publishes_as_unavailable();
    let pending = devices.laptop.decline_group_invite(&chat).await.unwrap();
    assert_eq!(pending.summary.published, 0);
    assert_eq!(
        pending.summary.accept_disposition,
        cgka_traits::SendAcceptDisposition::CompletionUnknown
    );
    assert!(laptop_store.leave_request(&chat).unwrap().is_some());
    let declined = laptop_store
        .app_storage()
        .invitation_decision(&chat_hex, &original.generation)
        .unwrap()
        .unwrap();
    assert!(declined.declined && declined.version == 1);
    devices.relay.allow_publishes();
    devices.laptop.drive_small_state().await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert!(
        phone_store
            .app_storage()
            .invitation_decision(&chat_hex, &original.generation)
            .unwrap()
            .unwrap()
            .declined
    );
    assert!(
        phone_store.leave_request(&chat).unwrap().is_none(),
        "remote intent has not been handed to Leave yet"
    );

    // These are authenticated peer inputs, not local confirmation actions.
    // A peer may rebroadcast a retained winner originally changed elsewhere.
    let accepted = storage_sqlite::InvitationDecision {
        version: 2,
        declined: false,
        ..declined.clone()
    };
    let [(content, _)] = <[_; 1]>::try_from(encode_invitation_decision_updates(
        std::slice::from_ref(&accepted),
    ))
    .unwrap();
    assert!(
        devices
            .laptop
            .send_device_group_message(&device_group, KIND_SMALL_STATE_UPDATE, content)
            .await
            .unwrap()
    );
    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.phone.drive_invitation_decisions().await;
    assert!(
        phone_store.leave_request(&chat).unwrap().is_none(),
        "a higher accept stops unrequested decline work"
    );
    assert!(devices.phone.state_group_record(&chat).unwrap().archived);
    assert_eq!(
        phone_store
            .app_storage()
            .invitation_decision(&chat_hex, &original.generation)
            .unwrap(),
        Some(accepted.clone()),
        "receiving acceptance is not a fresh local change"
    );

    // A deliberately nonmatching generation is retained but never acts on
    // this installed admission. It is not used as a positive admission seed.
    let mut unrelated = accepted.clone();
    unrelated.generation[0] ^= 1;
    unrelated.declined = true;
    unrelated.version = 9;
    let [(content, _)] =
        <[_; 1]>::try_from(encode_invitation_decision_updates(&[unrelated])).unwrap();
    assert!(
        devices
            .laptop
            .send_device_group_message(&device_group, KIND_SMALL_STATE_UPDATE, content)
            .await
            .unwrap()
    );
    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.phone.drive_invitation_decisions().await;
    assert!(phone_store.leave_request(&chat).unwrap().is_none());

    let winner = storage_sqlite::InvitationDecision {
        version: 3,
        declined: true,
        ..accepted.clone()
    };
    let [(content, _)] = <[_; 1]>::try_from(encode_invitation_decision_updates(&[winner])).unwrap();
    assert!(
        devices
            .laptop
            .send_device_group_message(&device_group, KIND_SMALL_STATE_UPDATE, content)
            .await
            .unwrap()
    );
    deliver_all(&mut devices.phone, &devices.relay).await;
    devices.relay.fail_publishes_as_unavailable();
    devices.phone.drive_invitation_decisions().await;
    assert!(
        phone_store.leave_request(&chat).unwrap().is_some(),
        "the matching projected copy enters durable Leave despite zero acknowledgements"
    );
    assert!(devices.phone.state_group_record(&chat).is_some());
    devices.relay.allow_publishes();

    let later = storage_sqlite::InvitationDecision {
        version: 4,
        ..accepted
    };
    let [(content, _)] = <[_; 1]>::try_from(encode_invitation_decision_updates(
        std::slice::from_ref(&later),
    ))
    .unwrap();
    assert!(
        devices
            .phone
            .send_device_group_message(&device_group, KIND_SMALL_STATE_UPDATE, content)
            .await
            .unwrap()
    );
    deliver_all(&mut devices.laptop, &devices.relay).await;
    drop(devices.laptop);
    let mut laptop = devices.laptop_app.client("alice").await.unwrap();
    laptop.drive_invitation_decisions().await;
    assert_eq!(
        laptop_store
            .app_storage()
            .invitation_decision(&chat_hex, &original.generation)
            .unwrap(),
        Some(later)
    );
    assert!(
        laptop_store.leave_request(&chat).unwrap().is_some(),
        "a newer accepted value and restart never cancel an already requested Leave"
    );

    // Keep this additional admission's large async operation out of the
    // existing lifecycle/restart owner's inline future frame.
    Box::pin(async {
        // A held maximum cannot create a newer local decision. Once local
        // blocking is lifted, an explicit action may still apply that SAME
        // winning acceptance without writing or broadcasting another value.
        let maximum_chat = bob.create_group("maximum invitation", &[]).await.unwrap();
        let key = published_key_package(&mut devices.phone, &devices.relay).await;
        let effects = bob
            .runtime
            .send(SendIntent::Invite {
                group_id: maximum_chat.clone(),
                key_packages: vec![key],
                initial_admins: Vec::new(),
            })
            .await
            .unwrap();
        bob.observe_drained_session_events(&effects).await.unwrap();
        deliver_all(&mut devices.phone, &devices.relay).await;
        let maximum_hex = hex::encode(maximum_chat.as_slice());
        let maximum_admission = phone_store
            .invitation_admission(&maximum_chat)
            .unwrap()
            .unwrap();
        let bob_id = bob_app
            .account_home()
            .account("bob")
            .unwrap()
            .account_id_hex;
        devices
            .phone_app
            .set_user_blocked("alice", &bob_id, true)
            .await
            .unwrap();
        let maximum = storage_sqlite::InvitationDecision {
            group_id_hex: maximum_hex.clone(),
            generation: maximum_admission.generation,
            version: storage_sqlite::MAX_SMALL_STATE_NUMBER,
            declined: false,
        };
        let [(content, _)] = <[_; 1]>::try_from(encode_invitation_decision_updates(
            std::slice::from_ref(&maximum),
        ))
        .unwrap();
        assert!(
            laptop
                .send_device_group_message(&device_group, KIND_SMALL_STATE_UPDATE, content)
                .await
                .unwrap()
        );
        deliver_all(&mut devices.phone, &devices.relay).await;
        devices.phone.drive_invitation_decisions().await;
        assert!(
            devices
                .phone
                .state_group_record(&maximum_chat)
                .unwrap()
                .pending_confirmation
        );
        assert_eq!(
            phone_store
                .app_storage()
                .invitation_decision(&maximum_hex, &maximum.generation)
                .unwrap(),
            Some(maximum.clone())
        );
        devices
            .phone_app
            .set_user_blocked("alice", &bob_id, false)
            .await
            .unwrap();
        let unsent = phone_store
            .app_storage()
            .unsent_invitation_decisions()
            .unwrap();
        assert!(
            devices
                .phone
                .decline_group_invite(&maximum_chat)
                .await
                .is_err()
        );
        assert!(phone_store.leave_request(&maximum_chat).unwrap().is_none());
        assert!(
            devices
                .phone
                .state_group_record(&maximum_chat)
                .unwrap()
                .pending_confirmation
        );
        assert!(
            !devices
                .phone
                .accept_group_invite(&maximum_chat)
                .unwrap()
                .pending_confirmation
        );
        assert_eq!(
            phone_store
                .app_storage()
                .invitation_decision(&maximum_hex, &maximum.generation)
                .unwrap(),
            Some(maximum.clone())
        );
        assert_eq!(
            phone_store
                .app_storage()
                .unsent_invitation_decisions()
                .unwrap(),
            unsent
        );

        // Local deletion is an explicit limit: retain/replicate a later
        // winner without acting on the hidden native membership or restoring UI.
        assert!(
            devices
                .phone
                .delete_group_local(&maximum_chat)
                .await
                .unwrap()
        );
        assert!(
            phone_store
                .invitation_admission(&maximum_chat)
                .unwrap()
                .is_some()
        );
        assert!(
            devices
                .phone
                .runtime
                .canonical_group_membership(&maximum_chat)
                .unwrap()
                .local_leaf_active
        );
        let declined = storage_sqlite::InvitationDecision {
            declined: true,
            ..maximum
        };
        let [(content, _)] = <[_; 1]>::try_from(encode_invitation_decision_updates(
            std::slice::from_ref(&declined),
        ))
        .unwrap();
        assert!(
            laptop
                .send_device_group_message(&device_group, KIND_SMALL_STATE_UPDATE, content)
                .await
                .unwrap()
        );
        deliver_all(&mut devices.phone, &devices.relay).await;
        devices.phone.drive_invitation_decisions().await;
        assert_eq!(
            phone_store
                .app_storage()
                .invitation_decision(&maximum_hex, &declined.generation)
                .unwrap(),
            Some(declined)
        );
        assert!(phone_store.leave_request(&maximum_chat).unwrap().is_none());
        assert!(
            devices
                .phone
                .runtime
                .canonical_group_membership(&maximum_chat)
                .unwrap()
                .local_leaf_active
        );
        assert!(devices.phone.state_group_record(&maximum_chat).is_none());
        assert!(
            devices
                .phone_app
                .group("alice", &maximum_hex)
                .unwrap()
                .is_none()
        );
        assert!(
            phone_store
                .app_storage()
                .invitation_decision_work()
                .unwrap()
                .iter()
                .all(|work| work.decision.group_id_hex != maximum_hex)
        );
    })
    .await;
}
