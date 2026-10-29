//! The account's device group (mdk#2628 item 3.1): a confirmed link creates
//! it under the id the link chose, adding only the confirmed KeyPackage. Both
//! devices trust it, and neither ever projects it as a chat. A device group no
//! link named stays untrusted and hidden. Pairing does not reach the app yet,
//! so the test-policy hooks stand in for a confirmed link.

use super::canonical_membership::{deliver_new, published_key_package};
use super::*;
use crate::{ConfirmedDeviceLink, LinkedDevice, LinkedDeviceStatus};
use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterOperationV1, DeviceRosterUpdateV1,
    DeviceRosterV1, DeviceSettingsV1, DeviceStatusV1, decode_device_roster_v1,
    encode_device_roster_update_v1,
};
use cgka_traits::engine::SendIntent;
use storage_sqlite::DeviceGroupTrust;

fn device_group_app_at(dir: &tempfile::TempDir, relay: Arc<ScriptedPushRelayClient>) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0)
            .with_dev_device_groups(true),
    )
    .with_test_relay_client(relay)
}

/// Alice's phone and laptop, each with a published KeyPackage, and the link
/// confirming the laptop's under `device_group_id`.
struct Devices {
    _dirs: [tempfile::TempDir; 2],
    relay: Arc<ScriptedPushRelayClient>,
    phone_app: MarmotApp,
    laptop_app: MarmotApp,
    phone: AppClient,
    laptop: AppClient,
    link: ConfirmedDeviceLink,
}

async fn phone_and_laptop() -> Devices {
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let home = AccountHome::open(dirs[0].path());
    let alice_id = home.create_account("alice").unwrap().account_id_hex;
    let secret = home
        .load_signing_keys("alice")
        .unwrap()
        .secret_key()
        .to_secret_hex();
    AccountHome::open(dirs[1].path())
        .import_account("alice", &secret)
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let phone_app = device_group_app_at(&dirs[0], relay.clone());
    let laptop_app = device_group_app_at(&dirs[1], relay.clone());
    for app in [&phone_app, &laptop_app] {
        remember_test_member_inbox(app, &alice_id, "wss://relay.example");
    }
    let mut phone = phone_app.client("alice").await.unwrap();
    published_key_package(&mut phone, &relay).await;
    let mut laptop = laptop_app.client("alice").await.unwrap();
    let key_package = published_key_package(&mut laptop, &relay).await;
    let link = ConfirmedDeviceLink {
        key_package_event_id_hex: hex::encode(
            key_package.source.as_ref().unwrap().event_id.as_slice(),
        ),
        key_package_ref_hex: marmot_session::key_package_metadata(&key_package)
            .unwrap()
            .key_package_ref_hex,
        device_group_id: GroupId::new(vec![0x5a; 16]),
    };
    Devices {
        _dirs: dirs,
        relay,
        phone_app,
        laptop_app,
        phone,
        laptop,
        link,
    }
}

fn trust(app: &MarmotApp, group: &GroupId) -> Option<DeviceGroupTrust> {
    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .device_group(&hex::encode(group.as_slice()))
        .unwrap()
        .map(|record| record.trust)
}

fn roster(client: &AppClient, group: &GroupId) -> DeviceRosterV1 {
    let bytes = client
        .runtime
        .app_component(group, DEVICE_ROSTER_COMPONENT_ID)
        .unwrap()
        .unwrap();
    decode_device_roster_v1(&bytes).unwrap()
}

fn roster_devices(client: &AppClient, group: &GroupId) -> usize {
    roster(client, group).devices.len()
}

/// Nothing projects the group: no group row, chat-list row, pending invite or
/// in-memory projection, while its route stays live.
fn assert_hidden(app: &MarmotApp, client: &AppClient, group: &GroupId) {
    let group_hex = hex::encode(group.as_slice());
    assert!(
        app.groups("alice")
            .unwrap()
            .iter()
            .all(|row| row.group_id_hex != group_hex)
    );
    assert!(app.chat_list_row("alice", &group_hex).unwrap().is_none());
    assert!(app.pending_group_invites("alice").unwrap().is_empty());
    assert!(client.state_group_record(group).is_none());
    assert!(
        client
            .routing
            .group_subscriptions()
            .iter()
            .any(|route| &route.group_id == group),
        "the device group keeps its route"
    );
}

/// The existing device creates the device group under the id the link chose,
/// adding exactly the confirmed KeyPackage. The new device joins through the
/// Welcome the link named, both devices trust the group, and neither ever
/// projects it, through a roster update and a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_confirmed_link_creates_a_hidden_device_group_both_devices_trust() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        laptop_app,
        mut phone,
        mut laptop,
        link,
    } = phone_and_laptop().await;
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    assert_eq!(
        trust(&laptop_app, &link.device_group_id),
        Some(DeviceGroupTrust::AwaitingWelcome)
    );

    let group = phone.dev_create_device_group(link.clone()).await.unwrap();
    assert_eq!(group, link.device_group_id);
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();

    assert_eq!(trust(&phone_app, &group), Some(DeviceGroupTrust::Created));
    assert_eq!(trust(&laptop_app, &group), Some(DeviceGroupTrust::Linked));
    for (app, client) in [(&phone_app, &phone), (&laptop_app, &laptop)] {
        assert_eq!(client.trusted_device_group().unwrap(), Some(group.clone()));
        assert_eq!(roster_devices(client, &group), 2);
        assert_hidden(app, client, &group);
    }
    // The creating device draws the tag key at random, and the laptop holds the
    // same one.
    let leaf_tag_key = roster(&phone, &group).leaf_tag_key;
    assert_ne!(leaf_tag_key, [0; 32]);
    assert_eq!(roster(&laptop, &group).leaf_tag_key, leaf_tag_key);

    // A roster update reaches the laptop and is never projected either.
    let update = encode_device_roster_update_v1(
        &DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetDevice(
            [9; 32],
            DeviceEntryV1::default(),
        )])
        .unwrap(),
    )
    .unwrap();
    let effects = phone
        .runtime
        .send(SendIntent::UpdateAppComponents {
            group_id: group.clone(),
            updates: vec![cgka_traits::app_components::AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: update,
            }],
        })
        .await
        .unwrap();
    phone
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    for (app, client) in [(&phone_app, &phone), (&laptop_app, &laptop)] {
        assert_eq!(roster(client, &group).leaf_tag_key, leaf_tag_key);
        assert_eq!(roster_devices(client, &group), 3);
        assert_hidden(app, client, &group);
    }

    // A restart reconciles live engine groups; the device group stays hidden.
    drop(laptop);
    let laptop = laptop_app.client("alice").await.unwrap();
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group.clone()));
    assert_hidden(&laptop_app, &laptop, &group);
}

/// A Welcome into a device group no confirmed link named installs a group the
/// device holds but never trusts or projects. A link that names it later,
/// once its Welcome won the race, makes it the account's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_group_no_link_named_stays_untrusted_and_hidden() {
    let Devices {
        _dirs,
        relay,
        laptop_app,
        mut phone,
        mut laptop,
        link,
        ..
    } = phone_and_laptop().await;
    let group = phone.dev_create_device_group(link.clone()).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();

    assert_eq!(
        trust(&laptop_app, &group),
        Some(DeviceGroupTrust::Untrusted)
    );
    assert_eq!(laptop.trusted_device_group().unwrap(), None);
    assert!(laptop.linked_devices().unwrap().is_empty());
    assert_hidden(&laptop_app, &laptop, &group);

    laptop.take_linked_devices_changed();
    laptop.dev_record_confirmed_device_link(link).unwrap();
    assert_eq!(trust(&laptop_app, &group), Some(DeviceGroupTrust::Linked));
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group));
    assert!(laptop.take_linked_devices_changed());
    assert_eq!(laptop.linked_devices().unwrap().len(), 2);
}

/// The founding Add takes only the KeyPackage the link confirmed, and only
/// from a device that advertises the roster and has no device group yet. Each
/// refusal comes before anything is published or recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_founding_add_takes_only_the_confirmed_key_package() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        link,
        ..
    } = phone_and_laptop().await;
    let before = relay.published_events.lock().unwrap().len();
    let other_ref = ConfirmedDeviceLink {
        key_package_ref_hex: "00".repeat(32),
        ..link.clone()
    };
    let other_event = ConfirmedDeviceLink {
        key_package_event_id_hex: "00".repeat(32),
        ..link.clone()
    };
    for refused in [other_ref, other_event] {
        let result = phone.dev_create_device_group(refused).await;
        assert!(
            matches!(
                result,
                Err(AppError::DeviceGroupRefused("key_package_not_published"))
            ),
            "{result:?}"
        );
    }
    assert_eq!(relay.published_events.lock().unwrap().len(), before);
    assert_eq!(trust(&phone_app, &link.device_group_id), None);

    let group = phone.dev_create_device_group(link.clone()).await.unwrap();
    let second = ConfirmedDeviceLink {
        device_group_id: GroupId::new(vec![0x6b; 16]),
        ..link
    };
    let result = phone.dev_create_device_group(second.clone()).await;
    assert!(
        matches!(
            result,
            Err(AppError::DeviceGroupRefused("device_group_exists"))
        ),
        "{result:?}"
    );
    assert_eq!(trust(&phone_app, &second.device_group_id), None);
    assert_eq!(phone.trusted_device_group().unwrap(), Some(group));
}

/// A device that does not advertise the roster can neither create a device
/// group nor record a link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_without_the_roster_takes_no_link() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = super::canonical_membership::app_at(&dir, relay);
    assert!(
        !app.supported_app_component_ids()
            .contains(&DEVICE_ROSTER_COMPONENT_ID)
    );
    let mut client = app.client("alice").await.unwrap();
    let link = ConfirmedDeviceLink {
        key_package_event_id_hex: "11".repeat(32),
        key_package_ref_hex: "22".repeat(32),
        device_group_id: GroupId::new(vec![0x5a; 16]),
    };
    let result = client.dev_create_device_group(link.clone()).await;
    assert!(
        matches!(
            result,
            Err(AppError::DeviceGroupRefused("roster_unsupported"))
        ),
        "{result:?}"
    );
    let result = client.dev_record_confirmed_device_link(link);
    assert!(
        matches!(
            result,
            Err(AppError::DeviceGroupRefused("roster_unsupported"))
        ),
        "{result:?}"
    );
}

/// A creation a crash interrupted after recording its id settles on restart:
/// `created` only if the engine holds the group as this device created it,
/// gone otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_creation_settles_on_restart() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        laptop_app,
        mut phone,
        mut laptop,
        link,
    } = phone_and_laptop().await;
    let group = phone.dev_create_device_group(link).await.unwrap();
    let storage = phone_app.account_storage("alice").unwrap().app_storage();
    let creating = |id: &GroupId| storage_sqlite::DeviceGroupRecord {
        group_id_hex: hex::encode(id.as_slice()),
        trust: DeviceGroupTrust::Creating,
        key_package_ref_hex: Some("ab".into()),
        recorded_at: 1,
    };
    let group_hex = hex::encode(group.as_slice());

    // The engine holds the group.
    assert!(
        storage
            .delete_device_group(&group_hex, DeviceGroupTrust::Created)
            .unwrap()
    );
    assert!(storage.insert_device_group(&creating(&group)).unwrap());
    phone.take_linked_devices_changed();
    phone.reconcile_device_groups().unwrap();
    assert_eq!(trust(&phone_app, &group), Some(DeviceGroupTrust::Created));
    assert!(phone.take_linked_devices_changed());

    // The engine never created it.
    let never = GroupId::new(vec![0x7c; 16]);
    assert!(
        storage
            .delete_device_group(&group_hex, DeviceGroupTrust::Created)
            .unwrap()
    );
    assert!(storage.insert_device_group(&creating(&never)).unwrap());
    phone.reconcile_device_groups().unwrap();
    assert_eq!(trust(&phone_app, &never), None);
    assert!(!phone.take_linked_devices_changed());

    // The engine holds a chat under the id: the chat stays a chat.
    let chat = phone.create_group("chat", &[]).await.unwrap();
    assert!(storage.insert_device_group(&creating(&chat)).unwrap());
    phone.reconcile_hydrated_account_state().unwrap();
    assert_eq!(trust(&phone_app, &chat), None);
    assert!(phone.state_group_record(&chat).is_some());

    // The engine holds the device group as a Welcome installed it: the row
    // goes, and the group settles as one no link named.
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    let laptop_storage = laptop_app.account_storage("alice").unwrap().app_storage();
    assert!(
        laptop_storage
            .delete_device_group(&group_hex, DeviceGroupTrust::Untrusted)
            .unwrap()
    );
    assert!(
        laptop_storage
            .insert_device_group(&creating(&group))
            .unwrap()
    );
    laptop.reconcile_hydrated_account_state().unwrap();
    assert_eq!(
        trust(&laptop_app, &group),
        Some(DeviceGroupTrust::Untrusted)
    );
    assert_hidden(&laptop_app, &laptop, &group);
}

/// A deferred open answers every live group read with `GroupNotHydrated`
/// until hydration runs, and the reconcile can run before it does. An
/// interrupted creation settles from the engine's durable record all the
/// same; an unhydrated group never costs it its row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_creation_settles_before_hydration() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        link,
        ..
    } = phone_and_laptop().await;
    let group = phone.dev_create_device_group(link).await.unwrap();
    assert!(
        phone_app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .set_device_group_trust(
                &hex::encode(group.as_slice()),
                DeviceGroupTrust::Created,
                DeviceGroupTrust::Creating,
                None,
                1,
            )
            .unwrap()
    );
    drop(phone);
    let plane = MarmotRelayPlane::new(None, relay.clone());
    let mut phone = phone_app
        .local_client_with_relay_plane_and_hydration("alice", &plane, None, true, None)
        .await
        .unwrap();
    assert!(
        phone.runtime.group_record(&group).is_err(),
        "the group is not hydrated yet"
    );
    phone.reconcile_device_groups().unwrap();
    assert_eq!(trust(&phone_app, &group), Some(DeviceGroupTrust::Created));
    assert!(phone.is_device_group(&group).unwrap());
}

/// A join the app never saw, because a crash came between the engine's join
/// and the app's observation, settles on restart, or at once when the link
/// arrives after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_the_app_never_saw_settles() {
    let Devices {
        _dirs,
        relay,
        laptop_app,
        mut phone,
        mut laptop,
        link,
        ..
    } = phone_and_laptop().await;
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link.clone()).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    let storage = || laptop_app.account_storage("alice").unwrap().app_storage();
    let group_hex = hex::encode(group.as_slice());

    // The link was recorded and the join never seen.
    assert!(
        storage()
            .set_device_group_trust(
                &group_hex,
                DeviceGroupTrust::Linked,
                DeviceGroupTrust::AwaitingWelcome,
                None,
                1,
            )
            .unwrap()
    );
    drop(laptop);
    let laptop = laptop_app.client("alice").await.unwrap();
    assert_eq!(trust(&laptop_app, &group), Some(DeviceGroupTrust::Linked));
    assert_hidden(&laptop_app, &laptop, &group);

    // No link and no row.
    assert!(
        storage()
            .delete_device_group(&group_hex, DeviceGroupTrust::Linked)
            .unwrap()
    );
    drop(laptop);
    let mut laptop = laptop_app.client("alice").await.unwrap();
    assert_eq!(
        trust(&laptop_app, &group),
        Some(DeviceGroupTrust::Untrusted)
    );

    // The link arrives after a join the app never saw.
    assert!(
        storage()
            .delete_device_group(&group_hex, DeviceGroupTrust::Untrusted)
            .unwrap()
    );
    laptop.take_linked_devices_changed();
    laptop.dev_record_confirmed_device_link(link).unwrap();
    assert_eq!(trust(&laptop_app, &group), Some(DeviceGroupTrust::Linked));
    assert!(laptop.take_linked_devices_changed());
    assert_hidden(&laptop_app, &laptop, &group);
}

/// A link never names a chat: either device refuses one that does before
/// anything is published or recorded, and a group that does not require the
/// roster is never trusted: settling it drops the row that waited for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_never_names_a_chat() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        laptop_app,
        mut phone,
        mut laptop,
        link,
    } = phone_and_laptop().await;
    let chat = phone.create_group("chat", &[]).await.unwrap();
    let before = relay.published_events.lock().unwrap().len();
    let result = phone
        .dev_create_device_group(ConfirmedDeviceLink {
            device_group_id: chat.clone(),
            ..link.clone()
        })
        .await;
    assert!(
        matches!(
            result,
            Err(AppError::DeviceGroupRefused("device_group_exists"))
        ),
        "{result:?}"
    );
    assert_eq!(relay.published_events.lock().unwrap().len(), before);
    assert_eq!(trust(&phone_app, &chat), None);
    assert!(phone.state_group_record(&chat).is_some());

    let laptop_chat = laptop.create_group("chat", &[]).await.unwrap();
    let result = laptop.dev_record_confirmed_device_link(ConfirmedDeviceLink {
        device_group_id: laptop_chat.clone(),
        ..link
    });
    assert!(
        matches!(
            result,
            Err(AppError::DeviceGroupRefused("device_group_exists"))
        ),
        "{result:?}"
    );
    assert_eq!(trust(&laptop_app, &laptop_chat), None);

    assert!(
        laptop_app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .insert_device_group(&storage_sqlite::DeviceGroupRecord {
                group_id_hex: hex::encode(laptop_chat.as_slice()),
                trust: DeviceGroupTrust::AwaitingWelcome,
                key_package_ref_hex: Some("ab".into()),
                recorded_at: 1,
            })
            .unwrap()
    );
    assert!(!laptop.settle_held_device_group(&laptop_chat).unwrap());
    assert_eq!(trust(&laptop_app, &laptop_chat), None);
    assert!(laptop.state_group_record(&laptop_chat).is_some());
}

/// A Welcome into the id a confirmed link named, for a group that does not
/// require the roster, is no device group. Whether the join is seen live or
/// only on a restart, the link's waiting row goes and the group projects as
/// any other, and a later link can still claim the account.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chat_welcome_under_a_linked_id_is_no_device_group() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        laptop_app,
        mut phone,
        mut laptop,
        link,
    } = phone_and_laptop().await;
    let alice_id = laptop_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let bob_dir = tempfile::tempdir().unwrap();
    AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap();
    let bob_app = device_group_app_at(&bob_dir, relay.clone());
    remember_test_member_inbox(&bob_app, &alice_id, "wss://relay.example");
    let mut bob = bob_app.client("bob").await.unwrap();
    let chat = bob.create_group("chat", &[&alice_id]).await.unwrap();
    for client in [&mut phone, &mut laptop] {
        client
            .dev_record_confirmed_device_link(ConfirmedDeviceLink {
                device_group_id: chat.clone(),
                ..link.clone()
            })
            .unwrap();
    }
    let invited = |app: &MarmotApp| {
        app.pending_group_invites("alice")
            .unwrap()
            .iter()
            .any(|invite| invite.group_id == chat)
    };

    // The laptop sees the join live.
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(trust(&laptop_app, &chat), None);
    assert!(invited(&laptop_app));
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    assert_eq!(
        trust(&laptop_app, &link.device_group_id),
        Some(DeviceGroupTrust::AwaitingWelcome)
    );

    // The phone's engine joins, and the app never sees it before a restart.
    let events = relay.published_events.lock().unwrap().clone();
    for event in events {
        if event.kind != 1059
            || !event.tags.iter().any(|tag| {
                tag.first().is_some_and(|name| name == "p") && tag.get(1) == Some(&alice_id)
            })
        {
            continue;
        }
        let _ = phone
            .runtime
            .ingest_delivery(&cgka_traits::TransportDelivery {
                account_id: MemberId::new(hex::decode(&alice_id).unwrap()),
                group_id_hint: None,
                message: event.to_transport_message().unwrap(),
                received_at: cgka_traits::Timestamp(unix_now_seconds()),
                source: cgka_traits::TransportDeliverySource {
                    transport: cgka_traits::transport::TransportSource("nostr".into()),
                    plane: cgka_traits::TransportDeliveryPlane::AccountInbox,
                    endpoint: None,
                    subscription_id: None,
                    wire: None,
                },
            })
            .await;
    }
    assert!(phone.runtime.live_group_ids().unwrap().contains(&chat));
    assert!(phone.state_group_record(&chat).is_none());
    drop(phone);
    let phone = phone_app.client("alice").await.unwrap();
    assert_eq!(trust(&phone_app, &chat), None);
    assert!(phone.state_group_record(&chat).is_some());
}

/// A deferred open holds the device group before hydration gives it a route.
/// A routing rebuild then skips it rather than failing, so a KeyPackage still
/// publishes, and hydration restores the route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deferred_open_routes_before_the_device_group_hydrates() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        link,
        ..
    } = phone_and_laptop().await;
    let group = phone.dev_create_device_group(link).await.unwrap();
    drop(phone);
    let plane = MarmotRelayPlane::new(None, relay.clone());
    let mut phone = phone_app
        .local_client_with_relay_plane_and_hydration("alice", &plane, None, true, None)
        .await
        .unwrap();
    assert!(
        phone.runtime.group_record(&group).is_err(),
        "the group is not hydrated yet"
    );
    phone.refresh_routing().unwrap();
    phone.publish_key_package().await.unwrap();
    crate::runtime::account_worker::drain_deferred_hydration(&mut phone)
        .await
        .unwrap();
    assert_hidden(&phone_app, &phone, &group);
}

/// A founding Welcome that fails to publish stays queued for the startup
/// retry, but the host never sees it: neither the pending-Welcome list nor its
/// events name the device group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_group_welcome_stays_out_of_host_redelivery() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        link,
        ..
    } = phone_and_laptop().await;
    relay.fail_publishes_of_kind(1059);
    let group = phone.dev_create_device_group(link).await.unwrap();
    let group_hex = hex::encode(group.as_slice());
    assert!(
        phone_app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .list_pending_welcome_deliveries()
            .unwrap()
            .iter()
            .any(|record| record.group_id_hex == group_hex),
        "the Welcome stays queued"
    );
    assert!(phone.pending_welcome_deliveries().unwrap().is_empty());
    assert!(phone.take_pending_welcome_delivery_events().is_empty());
}

/// The host never learns of the device group through a surface built from
/// engine or recovery state rather than the projection: epoch-stall
/// escalations, recovery-status and superseded-change updates, history
/// notices and their changes, and quarantine. A chat on the same surfaces
/// still shows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_never_learns_of_the_device_group() {
    let Devices {
        _dirs,
        phone_app,
        mut phone,
        link,
        ..
    } = phone_and_laptop().await;
    let group = phone.dev_create_device_group(link).await.unwrap();
    let chat = phone.create_group("chat", &[]).await.unwrap();
    let chat_hex = hex::encode(chat.as_slice());

    phone.pending_epoch_stall_escalations.clear();
    phone.pending_recovery_status_updates.clear();
    phone.pending_superseded_change_events.clear();
    let mut effects = marmot_session::AccountDeviceEffects::default();
    for id in [&group, &chat] {
        phone.report_epoch_stall_escalation(id, 1, 3, 3, "test");
        phone.mark_recovery_status_changed(id);
        effects
            .superseded_intents
            .push(cgka_traits::engine::SupersededIntentReport {
                group_id: id.clone(),
                commit_id: cgka_traits::MessageId::new(id.as_slice().to_vec()),
                kind: cgka_traits::engine::SupersededIntentKind::AppComponents,
                outcome: cgka_traits::engine::SupersededIntentOutcome::Conflict,
                reason: "test",
            });
    }
    phone.note_superseded_intent_reports(&effects);
    let escalated: Vec<_> = phone
        .pending_epoch_stall_escalations
        .iter()
        .map(|escalation| escalation.group_id.clone())
        .collect();
    assert_eq!(escalated, vec![chat.clone()]);
    let status: Vec<_> = phone
        .pending_recovery_status_updates
        .iter()
        .cloned()
        .collect();
    assert_eq!(status, vec![chat.clone()]);
    let superseded: Vec<_> = phone
        .take_pending_superseded_change_events()
        .into_iter()
        .map(|report| report.group_id)
        .collect();
    assert_eq!(superseded, vec![chat.clone()]);

    // An epoch gap each group's recovery parked.
    let storage = phone_app.account_storage("alice").unwrap();
    phone.take_history_notice_changes();
    let intents: Vec<_> = [&group, &chat]
        .into_iter()
        .map(|id| storage_sqlite::StoredEpochBackfillIntent {
            group_id_hex: hex::encode(id.as_slice()),
            stalled_epoch: phone.runtime.group_record(id).unwrap().epoch.0,
        })
        .collect();
    storage
        .app_storage()
        .arm_epoch_backfill_intents(&intents)
        .unwrap();
    let gaps: Vec<_> = storage
        .app_storage()
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .filter(|demand| demand.cause == storage_sqlite::RecoveryCause::EpochGap)
        .map(|demand| demand.ticket.id)
        .collect();
    assert_eq!(gaps.len(), 2);
    for gap in gaps {
        crate::client::history_notices::park_recovery_for_test(&storage, gap);
    }
    let notices: Vec<_> = phone
        .history_notices()
        .unwrap()
        .into_iter()
        .map(|notice| notice.group_id_hex)
        .collect();
    assert_eq!(notices, vec![Some(chat_hex.clone())]);
    assert_eq!(
        phone.take_history_notice_changes(),
        Some(vec![chat.clone()])
    );

    // Both groups fail hydration on the next open.
    for id in [&group, &chat] {
        let mut damaged = cgka_traits::storage::GroupStorage::get_group(&storage, id).unwrap();
        damaged.protocol_profile = cgka_traits::group::ProtocolProfile::Legacy;
        cgka_traits::storage::GroupStorage::put_group(&storage, &damaged).unwrap();
    }
    drop(phone);
    let phone = phone_app.client("alice").await.unwrap();
    assert_eq!(phone.runtime.quarantined_groups().len(), 2);
    let quarantined: Vec<_> = phone
        .quarantined_groups()
        .into_iter()
        .map(|quarantined| quarantined.group_id_hex)
        .collect();
    assert_eq!(quarantined, vec![chat_hex]);
}

fn stable_slot(app: &MarmotApp) -> String {
    app.account_storage("alice")
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap()
        .stable_slot_id
}

/// Each device lists the trusted roster's devices, itself first, then by when
/// each was linked. Every roster field reaches the host, and every hidden
/// device-group event raises the change flag.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_device_lists_the_trusted_roster_itself_first() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        laptop_app,
        mut phone,
        mut laptop,
        link,
    } = phone_and_laptop().await;
    let phone_slot = stable_slot(&phone_app);
    let laptop_slot = stable_slot(&laptop_app);
    // An open owes hosts one announcement; reading raises none.
    assert!(phone.take_linked_devices_changed());
    assert!(phone.linked_devices().unwrap().is_empty());
    assert!(!phone.take_linked_devices_changed());
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    assert!(laptop.linked_devices().unwrap().is_empty());

    let group = phone.dev_create_device_group(link).await.unwrap();
    assert!(phone.take_linked_devices_changed());
    laptop.take_linked_devices_changed();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert!(laptop.take_linked_devices_changed());

    let founding = phone.linked_devices().unwrap();
    let linked_at = founding[0].linked_at;
    assert!(linked_at > 0);
    let founder = |this| LinkedDevice {
        slot_id_hex: phone_slot.clone(),
        is_this_device: this,
        label: String::new(),
        client: String::new(),
        platform: String::new(),
        linked_at,
        linked_by_slot_id_hex: None,
        status: LinkedDeviceStatus::Active,
        add_to_all_chats: false,
        bring_history: false,
        keep_while_inactive: false,
    };
    let new_device = |this| LinkedDevice {
        slot_id_hex: laptop_slot.clone(),
        is_this_device: this,
        linked_by_slot_id_hex: Some(phone_slot.clone()),
        ..founder(this)
    };
    assert_eq!(founding, vec![founder(true), new_device(false)]);
    assert_eq!(
        laptop.linked_devices().unwrap(),
        vec![new_device(true), founder(false)]
    );

    // Two more devices, linked earlier than both, with every field set.
    let phone_slot_bytes: [u8; 32] = hex::decode(&phone_slot).unwrap().try_into().unwrap();
    let entry = |label: &str, linked_at, status, settings| DeviceEntryV1 {
        label: label.into(),
        client: format!("{label} client"),
        platform: format!("{label} platform"),
        linked_at,
        linked_by: Some(phone_slot_bytes),
        settings,
        status,
        announced_key_package: Some(vec![7; 32]),
        tag_signature_key: Some(label.as_bytes().to_vec()),
        history_key: Some(vec![8; 32]),
    };
    let update = encode_device_roster_update_v1(
        &DeviceRosterUpdateV1::new(vec![
            DeviceRosterOperationV1::SetDevice(
                [9; 32],
                entry(
                    "Tablet",
                    1,
                    DeviceStatusV1::Inactive,
                    DeviceSettingsV1 {
                        add_to_all_chats: true,
                        bring_history: true,
                        keep_while_inactive: false,
                    },
                ),
            ),
            DeviceRosterOperationV1::SetDevice(
                [8; 32],
                entry(
                    "Desk",
                    2,
                    DeviceStatusV1::Leaving,
                    DeviceSettingsV1 {
                        add_to_all_chats: false,
                        bring_history: true,
                        keep_while_inactive: true,
                    },
                ),
            ),
        ])
        .unwrap(),
    )
    .unwrap();
    let effects = phone
        .runtime
        .send(SendIntent::UpdateAppComponents {
            group_id: group.clone(),
            updates: vec![cgka_traits::app_components::AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: update,
            }],
        })
        .await
        .unwrap();
    phone
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert!(laptop.take_linked_devices_changed());

    let tablet = LinkedDevice {
        slot_id_hex: "09".repeat(32),
        is_this_device: false,
        label: "Tablet".into(),
        client: "Tablet client".into(),
        platform: "Tablet platform".into(),
        linked_at: 1,
        linked_by_slot_id_hex: Some(phone_slot.clone()),
        status: LinkedDeviceStatus::Inactive,
        add_to_all_chats: true,
        bring_history: true,
        keep_while_inactive: false,
    };
    let desk = LinkedDevice {
        slot_id_hex: "08".repeat(32),
        label: "Desk".into(),
        client: "Desk client".into(),
        platform: "Desk platform".into(),
        linked_at: 2,
        status: LinkedDeviceStatus::Leaving,
        add_to_all_chats: false,
        bring_history: true,
        keep_while_inactive: true,
        ..tablet.clone()
    };
    assert_eq!(
        laptop.linked_devices().unwrap(),
        vec![
            new_device(true),
            tablet.clone(),
            desk.clone(),
            founder(false)
        ]
    );
    assert_eq!(
        phone.linked_devices().unwrap(),
        vec![founder(true), tablet, desk, new_device(false)]
    );

    // A restart reads the same roster.
    drop(laptop);
    let mut laptop = laptop_app.client("alice").await.unwrap();
    assert_eq!(laptop.linked_devices().unwrap()[0], new_device(true));
    assert_eq!(laptop.linked_devices().unwrap().len(), 4);
}

/// With device groups switched off, as in every release build until the
/// roster's spec lands, nothing is listed and no change is announced, even on
/// a device that trusts a device group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_groups_off_list_no_devices() {
    let Devices {
        _dirs,
        relay,
        mut phone,
        link,
        ..
    } = phone_and_laptop().await;
    phone.dev_create_device_group(link).await.unwrap();
    assert_eq!(phone.linked_devices().unwrap().len(), 2);
    drop(phone);

    let phone_app = MarmotApp::with_relay_and_config(
        _dirs[0].path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
    .with_test_relay_client(relay);
    let mut phone = phone_app.client("alice").await.unwrap();
    assert!(phone.linked_devices().unwrap().is_empty());
    assert!(phone.linked_devices_changed);
    assert!(!phone.take_linked_devices_changed());
}

/// Through the runtime, the new device's account worker announces the join it
/// hid, and `linked_devices` reads the roster the Welcome brought.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_announces_a_device_group_join_and_lists_its_devices() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        laptop_app,
        mut phone,
        mut laptop,
        link,
    } = phone_and_laptop().await;
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    drop(laptop);
    let account_id_hex = laptop_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let _eose = scripted_eose_pump(
        laptop_app.relay_plane.clone(),
        relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(laptop_app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    assert!(runtime.linked_devices("alice").await.unwrap().is_empty());
    next_linked_devices_changed(&mut events, &account_id_hex).await;

    phone.dev_create_device_group(link).await.unwrap();
    // Separate apps share no live relay: route the founding Welcome in.
    let welcome = relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .find(|event| {
            event.kind == 1059
                && event.tags.iter().any(|tag| {
                    tag.first().is_some_and(|v| v == "p") && tag.get(1) == Some(&account_id_hex)
                })
        })
        .cloned()
        .expect("the founding Welcome");
    laptop_app
        .relay_plane
        .handle_relay_event_for_test(NostrRelayEvent {
            endpoint: TransportEndpoint("wss://relay.example".to_owned()),
            subscription_id: Some("device-group-welcome".to_owned()),
            event: welcome,
        })
        .await
        .unwrap();
    next_linked_devices_changed(&mut events, &account_id_hex).await;

    let devices = runtime.linked_devices("alice").await.unwrap();
    assert_eq!(
        devices
            .iter()
            .map(|device| (device.slot_id_hex.clone(), device.is_this_device))
            .collect::<Vec<_>>(),
        vec![
            (stable_slot(&laptop_app), true),
            (stable_slot(&phone_app), false)
        ]
    );
    runtime.shutdown().await;
}

/// A trusted device group whose roster cannot be read refuses with a fixed
/// code that never names the group, whether the read's own hydration or the
/// open quarantined it, and a terminal one lists nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_roster_never_names_the_group_and_a_terminal_one_lists_nothing() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        link,
        ..
    } = phone_and_laptop().await;
    let group = phone.dev_create_device_group(link).await.unwrap();
    let storage = phone_app.account_storage("alice").unwrap();
    let stored = || cgka_traits::storage::GroupStorage::get_group(&storage, &group).unwrap();
    let unavailable = |phone: &mut AppClient| {
        let error = phone.linked_devices().unwrap_err();
        assert!(matches!(
            error,
            AppError::DeviceGroupRefused("roster_unavailable")
        ));
        assert!(!error.to_string().contains(&hex::encode(group.as_slice())));
    };

    // The group fails hydration: first in the read itself, on a deferred
    // open, then at an eager one.
    let mut damaged = stored();
    damaged.protocol_profile = cgka_traits::group::ProtocolProfile::Legacy;
    cgka_traits::storage::GroupStorage::put_group(&storage, &damaged).unwrap();
    drop(phone);
    let plane = MarmotRelayPlane::new(None, relay);
    let mut phone = phone_app
        .local_client_with_relay_plane_and_hydration("alice", &plane, None, true, None)
        .await
        .unwrap();
    assert!(phone.runtime.group_record(&group).is_err());
    unavailable(&mut phone);
    unavailable(&mut phone);
    drop(phone);
    let mut phone = phone_app.client("alice").await.unwrap();
    unavailable(&mut phone);

    let mut removed = stored();
    removed.removed = true;
    cgka_traits::storage::GroupStorage::put_group(&storage, &removed).unwrap();
    assert!(phone.linked_devices().unwrap().is_empty());
}

/// A restart that settles device-group trust announces it with no command or
/// delivery after the open: an interrupted creation becomes `created` in the
/// worker's startup reconcile, and the end of startup says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_that_settles_trust_announces_it() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        link,
        ..
    } = phone_and_laptop().await;
    let group = phone.dev_create_device_group(link).await.unwrap();
    assert!(
        phone_app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .set_device_group_trust(
                &hex::encode(group.as_slice()),
                DeviceGroupTrust::Created,
                DeviceGroupTrust::Creating,
                None,
                1,
            )
            .unwrap()
    );
    drop(phone);
    let account_id_hex = phone_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let _eose = scripted_eose_pump(phone_app.relay_plane.clone(), relay, every_subscription);
    let runtime = MarmotAppRuntime::new(phone_app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    next_linked_devices_changed(&mut events, &account_id_hex).await;
    assert_eq!(trust(&phone_app, &group), Some(DeviceGroupTrust::Created));
    runtime.shutdown().await;
}

/// A reconnect opens a new client, which announces once with no command or
/// delivery after it. A reconnect attempt that settles trust and then fails
/// transport drops its client, flag and all; the client that replaces it
/// cannot see that change, so every open announces.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reconnect_announces_again() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        link,
        ..
    } = phone_and_laptop().await;
    phone.dev_create_device_group(link).await.unwrap();
    drop(phone);
    let account_id_hex = phone_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let _eose = scripted_eose_pump(phone_app.relay_plane.clone(), relay, every_subscription);
    let runtime = MarmotAppRuntime::new(phone_app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    next_linked_devices_changed(&mut events, &account_id_hex).await;
    assert_eq!(runtime.linked_devices("alice").await.unwrap().len(), 2);

    runtime
        .shared_services()
        .relay_plane()
        .simulate_notification_consumer_exit_for_test();
    next_linked_devices_changed(&mut events, &account_id_hex).await;
    assert_eq!(runtime.linked_devices("alice").await.unwrap().len(), 2);
    runtime.shutdown().await;
}

/// Waits for the account's next `LinkedDevicesChanged`. The device group's own
/// events must never reach the host meanwhile.
async fn next_linked_devices_changed(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    account_id_hex: &str,
) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match events.recv().await {
                Ok(MarmotAppEvent::LinkedDevicesChanged {
                    account_id_hex: changed,
                    account_label,
                }) if changed == account_id_hex && account_label == "alice" => break,
                Ok(MarmotAppEvent::GroupJoined { .. }) => {
                    panic!("the device group reached the host")
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => panic!("events closed"),
            }
        }
    })
    .await
    .expect("LinkedDevicesChanged");
}
