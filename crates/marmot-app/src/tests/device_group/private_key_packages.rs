//! Private KeyPackages (mdk#2628 item 3.4b): once their leaves are tagged
//! (3.1d), siblings hand each other single-use KeyPackages inside the device
//! group, never publish them, take only a sibling's own, repair a lost
//! hand-off by asking again, and send again what reached no relay. A sibling
//! Welcome (3.5b) adds a device to a chat with one of them.

use super::*;
use base64::Engine as _;
use cgka_traits::app_components::DeviceSlotId;
use cgka_traits::app_components::{
    AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NOSTR_ROUTING_MAX_RELAYS, encode_nostr_routing_v1,
};
use cgka_traits::engine::CreateGroupRequest;
use cgka_traits::storage::IssuedPrivateKeyPackage;
use marmot_session::{
    KIND_PRIVATE_KEY_PACKAGE_HAND_OFF, KIND_PRIVATE_KEY_PACKAGE_REQUEST, KIND_SIBLING_WELCOME,
    MAX_HAND_OFF_KEY_PACKAGES, PrivateKeyPackageHandOff, PrivateKeyPackageRequest, PublishWork,
    SiblingWelcome,
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

/// A chat the laptop makes with one of the phone's private KeyPackages, and
/// the sibling Welcome that adds the phone to it, built by hand until the
/// laptop sends one itself (3.5b-2). Until then the laptop wraps every
/// Welcome for the transport, so the KeyPackage names a stand-in event and
/// the test unwraps the Welcome from a gift wrap it never publishes.
async fn chat_adding_the_phone(devices: &mut Devices) -> (GroupId, SiblingWelcome) {
    let (phone_slot, laptop_slot) = (slot(&devices.phone), slot(&devices.laptop));
    let private = devices
        .laptop
        .take_private_key_package(&phone_slot)
        .unwrap()
        .unwrap();
    let key_package_ref = issued(&devices.phone)
        .into_iter()
        .find(|record| record.key_package == private.bytes())
        .unwrap()
        .key_package_ref;
    let private = KeyPackage {
        source: Some(cgka_traits::engine::KeyPackageSource {
            event_id: MessageId::new(vec![0x42; 32]),
        }),
        ..private
    };
    let routing = devices.laptop.app.new_nostr_routing(None).unwrap();
    let created = devices
        .laptop
        .runtime
        .session_mut()
        .create_group(CreateGroupRequest {
            name: "chat".into(),
            description: String::new(),
            members: vec![private],
            required_features: Vec::new(),
            app_components: vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: encode_nostr_routing_v1(&routing).unwrap(),
            }],
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let wrap = created
        .effects
        .publish
        .iter()
        .find_map(|work| match work {
            PublishWork::GroupCreated { welcomes, .. }
            | PublishWork::FoundingGroupCreated { welcomes } => welcomes.first().cloned(),
            _ => None,
        })
        .unwrap();
    let keys = devices
        .laptop_app
        .account_home()
        .load_signing_keys("alice")
        .unwrap();
    let wrap = transport_nostr_peeler::NostrTransportEvent::from_transport_message(&wrap)
        .unwrap()
        .to_verified_nostr_event()
        .unwrap();
    let rumor = nostr::nips::nip59::extract_rumor(&keys, &wrap)
        .unwrap()
        .rumor;
    let welcome = base64::engine::general_purpose::STANDARD
        .decode(&rumor.content)
        .unwrap();
    (
        created.group_id,
        SiblingWelcome {
            from: laptop_slot,
            to: phone_slot,
            key_package_ref,
            welcome,
            relays: vec!["wss://relay.example".into()],
        },
    )
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
        // No relay, one off the relay URL profile, one repeated, too many.
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

/// A sibling Welcome admitted while its stash write fails is not lost: the
/// event's projection fails, is retried once the write works again, and the
/// phone joins the chat once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_welcome_whose_stash_write_fails_is_kept_on_retry() {
    let (mut devices, group) = tagging_devices().await;
    let (chat, welcome) = chat_adding_the_phone(&mut devices).await;
    send_sibling_welcome(&mut devices.laptop, &group, &welcome).await;

    let app = &devices.phone_app;
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
