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

/// A chat the laptop makes and adds the phone to, and the sibling Welcome
/// that Add leaves owed.
async fn chat_adding_the_phone(devices: &mut Devices) -> (GroupId, SiblingWelcome) {
    let chat = devices.laptop.create_group("chat", &[]).await.unwrap();
    let welcome = adding_the_phone(devices, &chat).await;
    (chat, welcome)
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
    let key_package = devices
        .laptop
        .take_private_key_package(&phone_slot)
        .unwrap()
        .unwrap();
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
) -> (GroupId, SiblingWelcome, NostrTransportEvent) {
    let (chat, welcome) = chat_adding_the_phone(devices).await;
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
    let (mut devices, group) = tagging_devices().await;
    let (chat, welcome) = chat_adding_the_phone(&mut devices).await;

    send_sibling_welcome(&mut devices.laptop, &group, &welcome).await;
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 1);
    assert!(devices.phone.state_group_record(&chat).is_none());

    drop(devices.phone);
    let mut phone = devices.phone_app.client("alice").await.unwrap();
    assert_eq!(stashed(&phone), 1);
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(stashed(&phone), 0);
    assert!(phone.state_group_record(&chat).is_some());
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
    let (mut devices, group) = tagging_devices().await;
    let (_, welcome) = chat_adding_the_phone(&mut devices).await;
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
    let (mut devices, group) = tagging_devices().await;
    let (chat, again, removal) = chat_re_adding_the_phone(&mut devices, &group).await;
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
    let (mut devices, group) = tagging_devices().await;
    let (chat, again, _) = chat_re_adding_the_phone(&mut devices, &group).await;
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
    let (mut devices, group) = tagging_devices().await;
    let (chat, again, _) = chat_re_adding_the_phone(&mut devices, &group).await;
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
    let (mut devices, group) = tagging_devices().await;
    let (withdrawn, withdrawn_welcome, _) = chat_re_adding_the_phone(&mut devices, &group).await;
    let (expired, expired_welcome, _) = chat_re_adding_the_phone(&mut devices, &group).await;
    let (disbanded, disbanded_welcome, _) = chat_re_adding_the_phone(&mut devices, &group).await;
    let (forgotten, forgotten_welcome, _) = chat_re_adding_the_phone(&mut devices, &group).await;
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
    let (mut devices, group) = tagging_devices().await;
    let (chat, again, _) = chat_re_adding_the_phone(&mut devices, &group).await;
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
    let (mut devices, group) = tagging_devices().await;
    let (chat, welcome) = chat_adding_the_phone(&mut devices).await;
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
    let (mut devices, group) = tagging_devices().await;
    let (chat, welcome) = chat_adding_the_phone(&mut devices).await;
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
    let (mut devices, group) = tagging_devices().await;
    let (chat, welcome) = chat_adding_the_phone(&mut devices).await;
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
    let (mut devices, group) = tagging_devices().await;
    let (chat, welcome) = chat_adding_the_phone(&mut devices).await;
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
    let (mut devices, _) = tagging_devices().await;
    let chat = devices.laptop.create_group("chat", &[]).await.unwrap();
    let phone_slot = slot(&devices.phone);
    let before = devices.relay.published_events.lock().unwrap().len();
    devices
        .laptop
        .add_sibling_to_chat(&chat, &phone_slot)
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
    let (mut devices, _) = tagging_devices().await;
    let chat = devices.laptop.create_group("chat", &[]).await.unwrap();
    add_the_phone_unpublished(&mut devices, &chat).await;

    devices.relay.reject_next_publish();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    let [refused] = <[_; 1]>::try_from(owed(&devices.laptop)).unwrap();
    assert_eq!(refused.carrier, None);
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 0);

    devices.laptop.send_owed_sibling_welcomes(&[]).await;
    assert!(owed(&devices.laptop).is_empty());
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
    let (mut devices, _) = tagging_devices().await;
    let (owed_chat, carried_chat) = (
        devices.laptop.create_group("owed", &[]).await.unwrap(),
        devices.laptop.create_group("carried", &[]).await.unwrap(),
    );
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
    let (mut devices, _) = tagging_devices().await;
    let chat = devices.laptop.create_group("chat", &[]).await.unwrap();
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

/// A 461 whose publication cannot be settled, because the engine write
/// fails, leaves the in-flight set anyway: the next pass finds its carrier
/// from no 461 of this run, so it sends the Welcome again, and settles that
/// one delivered. The phone joins the chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_whose_settling_fails_is_sent_again() {
    let (mut devices, _) = tagging_devices().await;
    let chat = devices.laptop.create_group("chat", &[]).await.unwrap();
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

    connection
        .execute_batch("DROP TRIGGER fail_settle")
        .unwrap();
    devices.laptop.send_owed_sibling_welcomes(&[]).await;
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
    let (mut devices, group) = tagging_devices().await;
    let chat = devices.laptop.create_group("chat", &[]).await.unwrap();
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

/// A sibling Welcome goes out only once its Add's Commit is published: an
/// Add whose Commit every relay refused fails, and neither it nor a later
/// pass sends the Welcome. The failed Add spent its KeyPackage, which is not
/// handed back. Adding the phone again goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_waits_for_its_commit() {
    let (mut devices, _) = tagging_devices().await;
    let chat = devices.laptop.create_group("chat", &[]).await.unwrap();
    let phone_slot = slot(&devices.phone);
    let stock = received_from(&devices.laptop, &phone_slot).len();
    devices.relay.reject_next_publish();
    let error = devices
        .laptop
        .add_sibling_to_chat(&chat, &phone_slot)
        .await
        .unwrap_err();
    assert_eq!(error.privacy_safe_kind(), "publish");
    assert_eq!(received_from(&devices.laptop, &phone_slot).len(), stock - 1);
    devices.laptop.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 0);

    devices
        .laptop
        .add_sibling_to_chat(&chat, &phone_slot)
        .await
        .unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(stashed(&devices.phone), 1);
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(devices.phone.state_group_record(&chat).is_some());
}
