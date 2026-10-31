//! The account's device group (mdk#2628 item 3.1): a confirmed link creates
//! it under the id the link chose, adding only the confirmed KeyPackage. Both
//! devices trust it, and neither ever projects it as a chat. The new device
//! joins it only through the Welcome its link waits for, from the leaf the
//! link names (D28, D30); every other Welcome into the id is refused before
//! the join. The test-policy hooks stand in for a confirmed link here;
//! `device_pairing.rs` runs pairing itself.

use super::canonical_membership::{deliver_new, published_key_package};
use super::*;
use crate::{ConfirmedDeviceLink, LinkedDevice, LinkedDeviceStatus};
use cgka_traits::TransportFanoutAttemptState;
use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterOperationV1, DeviceRosterUpdateV1,
    DeviceRosterV1, DeviceSettingsV1, DeviceStatusV1, DeviceTagClaim, RejectedSlotReasonV1,
    RejectedSlotV1, decode_device_roster_v1, encode_device_roster_update_v1,
};
use cgka_traits::engine::SendIntent;
use marmot_session::DeviceRosterEdit;
use storage_sqlite::DeviceGroupTrust;

mod backups;
mod chat_kinds;
mod devices;
mod heartbeats;
mod history;
mod history_delivery;
mod private_key_packages;
mod removal;

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
pub(super) struct Devices {
    pub(super) _dirs: [tempfile::TempDir; 2],
    pub(super) relay: Arc<ScriptedPushRelayClient>,
    pub(super) phone_app: MarmotApp,
    pub(super) laptop_app: MarmotApp,
    pub(super) phone: AppClient,
    pub(super) laptop: AppClient,
    pub(super) link: ConfirmedDeviceLink,
}

pub(super) async fn phone_and_laptop() -> Devices {
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
        welcome_sender_key: phone.runtime.own_signature_key(),
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

/// The device never joined `group`: its Welcome was refused before the join,
/// so nothing holds, trusts or projects it.
fn assert_not_held(app: &MarmotApp, client: &AppClient, group: &GroupId) {
    assert!(!client.runtime.live_group_ids().unwrap().contains(group));
    assert!(client.state_group_record(group).is_none());
    assert_eq!(client.trusted_device_group().unwrap(), None);
    assert!(app.pending_group_invites("alice").unwrap().is_empty());
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
    // A withdrawal after the join finds the link done and leaves it.
    assert!(!laptop.dev_withdraw_confirmed_device_link(&group).unwrap());
    assert_eq!(trust(&laptop_app, &group), Some(DeviceGroupTrust::Linked));
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

/// A Welcome into a device group no confirmed link waits for is refused
/// before the join, so the device never holds the group, and a link recorded
/// after it cannot claim a group someone else founded first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_group_welcome_no_link_waits_for_is_refused() {
    let Devices {
        _dirs,
        relay,
        laptop_app,
        mut phone,
        mut laptop,
        link,
        ..
    } = phone_and_laptop().await;
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();

    assert_eq!(trust(&laptop_app, &group), None);
    assert_not_held(&laptop_app, &laptop, &group);
}

/// Someone holding the account key reads the id a link confirmed and founds
/// a device group under it first, with the new device's KeyPackage. The new
/// device refuses that Welcome, whose sender is not the leaf the link names,
/// and the link still waits for, and joins, the real one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_welcome_from_another_device_is_refused_and_the_real_one_still_joins() {
    let Devices {
        _dirs,
        relay,
        laptop_app,
        mut phone,
        mut laptop,
        link,
        ..
    } = phone_and_laptop().await;
    let home = laptop_app.account_home();
    let alice_id = home.account("alice").unwrap().account_id_hex;
    let secret = home
        .load_signing_keys("alice")
        .unwrap()
        .secret_key()
        .to_secret_hex();
    let holder_dir = tempfile::tempdir().unwrap();
    AccountHome::open(holder_dir.path())
        .import_account("alice", &secret)
        .unwrap();
    let holder_app = device_group_app_at(&holder_dir, relay.clone());
    remember_test_member_inbox(&holder_app, &alice_id, "wss://relay.example");
    let mut holder = holder_app.client("alice").await.unwrap();
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();

    let forged = holder.dev_create_device_group(link.clone()).await.unwrap();
    assert_eq!(forged, link.device_group_id);
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(
        trust(&laptop_app, &forged),
        Some(DeviceGroupTrust::AwaitingWelcome)
    );
    assert_not_held(&laptop_app, &laptop, &forged);

    let group = phone.dev_create_device_group(link).await.unwrap();
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(trust(&laptop_app, &group), Some(DeviceGroupTrust::Linked));
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group.clone()));
    assert_eq!(roster_devices(&laptop, &group), 2);
    assert_hidden(&laptop_app, &laptop, &group);
}

/// A link whose wait ran out, or that was withdrawn, joins no Welcome. The
/// engine stops waiting before the row goes, so the Welcome that comes after
/// is refused like any other no link waits for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_or_withdrawn_link_joins_no_welcome() {
    let Devices {
        _dirs,
        relay,
        laptop_app,
        mut phone,
        mut laptop,
        link,
        ..
    } = phone_and_laptop().await;

    // The wait counts from when the link was recorded, and an open ends it.
    let expired = GroupId::new(vec![0x6b; 16]);
    laptop
        .dev_record_confirmed_device_link(ConfirmedDeviceLink {
            device_group_id: expired.clone(),
            ..link.clone()
        })
        .unwrap();
    assert!(
        laptop_app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .set_device_group_trust(
                &hex::encode(expired.as_slice()),
                DeviceGroupTrust::AwaitingWelcome,
                DeviceGroupTrust::AwaitingWelcome,
                None,
                1,
            )
            .unwrap()
    );
    drop(laptop);
    let mut laptop = laptop_app.client("alice").await.unwrap();
    assert_eq!(trust(&laptop_app, &expired), None);
    assert!(
        !laptop
            .runtime
            .withdraw_device_group_welcome(&expired)
            .unwrap(),
        "the open withdrew the engine's expectation"
    );

    // A withdrawn link.
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    assert!(
        laptop
            .dev_withdraw_confirmed_device_link(&link.device_group_id)
            .unwrap()
    );
    assert_eq!(trust(&laptop_app, &link.device_group_id), None);
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(trust(&laptop_app, &group), None);
    assert_not_held(&laptop_app, &laptop, &group);
}

/// A waiting row with no engine expectation behind it, as a crash between
/// a record's two writes leaves, admits nothing. The next open drops it, so
/// it never refuses a new link until its wait runs out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_waiting_row_left_without_its_expectation_is_dropped() {
    let Devices {
        _dirs,
        relay,
        laptop_app,
        mut phone,
        laptop,
        link,
        ..
    } = phone_and_laptop().await;
    assert!(
        laptop_app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .insert_device_group(&storage_sqlite::DeviceGroupRecord {
                group_id_hex: hex::encode(link.device_group_id.as_slice()),
                trust: DeviceGroupTrust::AwaitingWelcome,
                key_package_ref_hex: Some(link.key_package_ref_hex.clone()),
                recorded_at: crate::unix_now_seconds(),
            })
            .unwrap()
    );
    drop(laptop);
    let mut laptop = laptop_app.client("alice").await.unwrap();
    assert_eq!(trust(&laptop_app, &link.device_group_id), None);

    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(trust(&laptop_app, &group), Some(DeviceGroupTrust::Linked));
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
        welcome_sender_key: client.runtime.own_signature_key(),
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
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
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
    // goes, and the group settles as one no row names.
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    let laptop_storage = laptop_app.account_storage("alice").unwrap().app_storage();
    assert!(
        laptop_storage
            .delete_device_group(&group_hex, DeviceGroupTrust::Linked)
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
/// and the app's observation, settles on restart: linked when its link
/// waited for it, even past the wait, since the engine joins nothing after
/// it. A link never claims a group the device already holds.
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

    // A link that names the held group is refused.
    laptop.take_linked_devices_changed();
    let result = laptop.dev_record_confirmed_device_link(link);
    assert!(
        matches!(
            result,
            Err(AppError::DeviceGroupRefused("device_group_exists"))
        ),
        "{result:?}"
    );
    assert_eq!(
        trust(&laptop_app, &group),
        Some(DeviceGroupTrust::Untrusted)
    );
    assert!(!laptop.take_linked_devices_changed());
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

/// A Welcome into the id a waiting link reserved, for a group that does not
/// require the roster, is refused: the new device neither joins the chat nor
/// lists its invite, and the device group's Welcome still joins under the id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chat_welcome_under_a_waiting_link_is_refused() {
    let Devices {
        _dirs,
        relay,
        laptop_app,
        mut phone,
        mut laptop,
        link,
        ..
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
    let link = ConfirmedDeviceLink {
        device_group_id: chat.clone(),
        ..link
    };
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();

    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(
        trust(&laptop_app, &chat),
        Some(DeviceGroupTrust::AwaitingWelcome)
    );
    assert_not_held(&laptop_app, &laptop, &chat);

    assert_eq!(phone.dev_create_device_group(link).await.unwrap(), chat);
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(trust(&laptop_app, &chat), Some(DeviceGroupTrust::Linked));
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(chat.clone()));
    assert_hidden(&laptop_app, &laptop, &chat);
}

/// A deferred open holds the device group before hydration gives it a route.
/// A routing rebuild then skips it rather than failing, so a KeyPackage still
/// publishes, and hydration restores the route. The phone has already
/// replaced its untagged KeyPackage, so the one it republishes is announced.
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
    phone.run_due_maintenance().await.unwrap();
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
/// escalations, recovery-status and superseded-change updates, convergence
/// park notices, history notices and their changes, and quarantine. A chat on
/// the same surfaces still shows.
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

    // A convergence pass each group parked (mdk#2684).
    phone.take_convergence_park_notices();
    for id in [&group, &chat] {
        phone.note_convergence_park(id, true);
    }
    assert_eq!(phone.take_convergence_park_notices(), vec![chat.clone()]);

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

pub(super) fn stable_slot(app: &MarmotApp) -> String {
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
        add_to_all_chats: true,
        bring_history: true,
        keep_while_inactive: false,
        last_active_at: None,
        inactive: false,
        removal_pending: false,
    };
    // The dev hook links the new device with both settings off.
    let new_device = |this| LinkedDevice {
        slot_id_hex: laptop_slot.clone(),
        is_this_device: this,
        linked_by_slot_id_hex: Some(phone_slot.clone()),
        add_to_all_chats: false,
        bring_history: false,
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
        rename_id: Some([6; 16]),
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
        last_active_at: None,
        inactive: false,
        removal_pending: false,
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
        removal_pending: false,
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
async fn device_groups_off_list_no_devices_and_no_overdue_refresh() {
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
    assert!(!phone.key_package_refresh_overdue().unwrap());
    assert!(phone.key_package_refresh_overdue_changed);
    assert!(!phone.take_key_package_refresh_overdue_changed());
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
/// cannot see that change, so every open announces. The overdue-refresh
/// answer is announced the same way.
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
    next_key_package_refresh_overdue_changed(&mut events, &account_id_hex).await;
    assert_eq!(runtime.linked_devices("alice").await.unwrap().len(), 2);
    assert!(!runtime.key_package_refresh_overdue("alice").await.unwrap());

    runtime
        .shared_services()
        .relay_plane()
        .simulate_notification_consumer_exit_for_test();
    next_linked_devices_changed(&mut events, &account_id_hex).await;
    next_key_package_refresh_overdue_changed(&mut events, &account_id_hex).await;
    assert_eq!(runtime.linked_devices("alice").await.unwrap().len(), 2);
    runtime.shutdown().await;
}

/// Waits for the account's next `LinkedDevicesChanged`.
async fn next_linked_devices_changed(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    account_id_hex: &str,
) {
    next_device_group_change(events, "LinkedDevicesChanged", |event| {
        matches!(event, MarmotAppEvent::LinkedDevicesChanged {
            account_id_hex: changed,
            account_label,
        } if changed == account_id_hex && account_label == "alice")
    })
    .await;
}

/// Waits for the account's next `KeyPackageRefreshOverdueChanged`.
async fn next_key_package_refresh_overdue_changed(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    account_id_hex: &str,
) {
    next_device_group_change(events, "KeyPackageRefreshOverdueChanged", |event| {
        matches!(event, MarmotAppEvent::KeyPackageRefreshOverdueChanged {
            account_id_hex: changed,
            account_label,
        } if changed == account_id_hex && account_label == "alice")
    })
    .await;
}

/// Waits for the next event `wanted` accepts. The device group's own events
/// must never reach the host meanwhile.
async fn next_device_group_change(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    name: &str,
    wanted: impl Fn(&MarmotAppEvent) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match events.recv().await {
                Ok(event) if wanted(&event) => break,
                Ok(MarmotAppEvent::GroupJoined { .. }) => {
                    panic!("the device group reached the host")
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => panic!("events closed"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{name}"));
}

/// [`tagging_devices`] once they have handed each other private KeyPackages
/// (3.4b), so a maintenance pass sends nothing in the device group unless a
/// test makes it owe something. In [`tagging_devices`] the phone served the
/// laptop and asked for its own; the laptop's pass here hands those over.
async fn settled_linked_devices() -> (Devices, GroupId) {
    let (mut devices, group) = tagging_devices().await;
    devices.laptop.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    (devices, group)
}

pub(super) async fn deliver_all(client: &mut AppClient, relay: &ScriptedPushRelayClient) {
    let mut cursor = 0;
    deliver_new(client, relay, &mut cursor).await;
    client.sync().await.unwrap();
}

/// A phone and laptop in one device group, the laptop joined.
async fn linked_devices() -> (Devices, GroupId) {
    let mut devices = phone_and_laptop().await;
    devices
        .laptop
        .dev_record_confirmed_device_link(devices.link.clone())
        .unwrap();
    let group = devices
        .phone
        .dev_create_device_group(devices.link.clone())
        .await
        .unwrap();
    let mut cursor = 0;
    deliver_new(&mut devices.laptop, &devices.relay, &mut cursor).await;
    // Settling the join names the group to tag from at once (mdk#2628 3.1d).
    assert_eq!(devices.laptop.runtime.device_tag_group(), Some(&group));
    devices.laptop.sync().await.unwrap();
    assert_eq!(
        trust(&devices.laptop_app, &group),
        Some(DeviceGroupTrust::Linked)
    );
    // Each device starts small state (mdk#2628 4.3a), sending the broadcast
    // request it owes at start, so a test's first maintenance pass publishes
    // only what that test is about.
    for client in [&mut devices.phone, &mut devices.laptop] {
        client.drive_small_state().await;
    }
    (devices, group)
}

/// [`linked_devices`] once both devices tag (mdk#2628 3.1d). One
/// maintenance pass each replaces its untagged KeyPackage, the laptop's after
/// it sets its tag signature key; the phone's founding entry carries its key.
/// Each new KeyPackage is announced before it is published, and both devices
/// see every roster commit.
async fn tagging_devices() -> (Devices, GroupId) {
    let (mut devices, group) = linked_devices().await;
    let start = devices.relay.published_events.lock().unwrap().len();
    let (mut phone_cursor, mut laptop_cursor) = (start, start);
    devices.laptop.run_due_maintenance().await.unwrap();
    deliver_new(&mut devices.phone, &devices.relay, &mut phone_cursor).await;
    devices.phone.sync().await.unwrap();
    devices.phone.run_due_maintenance().await.unwrap();
    deliver_new(&mut devices.laptop, &devices.relay, &mut laptop_cursor).await;
    devices.laptop.sync().await.unwrap();
    for device in [&devices.phone, &devices.laptop] {
        for reader in [&devices.phone, &devices.laptop] {
            assert_eq!(announced(reader, &group, device), current_ref(device));
        }
        assert_eq!(
            key_package_claim(device, &roster(device, &group)),
            DeviceTagClaim::Device(slot_of(device))
        );
    }
    (devices, group)
}

fn own_slot(client: &AppClient) -> String {
    client
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .stable_slot_id
}

/// The KeyPackage `reader`'s copy of the roster announces for `device`.
fn announced(reader: &AppClient, group: &GroupId, device: &AppClient) -> Option<String> {
    let bytes = reader
        .runtime
        .app_component(group, DEVICE_ROSTER_COMPONENT_ID)
        .unwrap()
        .unwrap();
    let slot: [u8; 32] = hex::decode(own_slot(device)).unwrap().try_into().unwrap();
    decode_device_roster_v1(&bytes).unwrap().devices[&slot]
        .announced_key_package
        .as_ref()
        .map(hex::encode)
}

fn current_ref(client: &AppClient) -> Option<String> {
    client
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .current_key_package_ref
        .map(hex::encode)
}

/// The kinds published since `since`, in order.
fn published_kinds(relay: &ScriptedPushRelayClient, since: usize) -> Vec<u64> {
    relay.published_events.lock().unwrap()[since..]
        .iter()
        .map(|event| event.kind)
        .collect()
}

/// A device's roster entry names each KeyPackage before it reaches the slot.
/// Once both devices tag, the roster names both devices' current ones, so
/// maintenance owes no commit. A rotation sends the roster commit first, then
/// the KeyPackage the sibling sees announced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_package_is_announced_before_it_reaches_the_slot() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = settled_linked_devices().await;
    for client in [&phone, &laptop] {
        assert_eq!(announced(client, &group, &laptop), current_ref(&laptop));
        assert_eq!(announced(client, &group, &phone), current_ref(&phone));
    }
    let mut phone_cursor = relay.published_events.lock().unwrap().len();
    phone.run_due_maintenance().await.unwrap();
    assert!(published_kinds(&relay, phone_cursor).is_empty());

    let rotated = laptop.rotate_key_package().await.unwrap();
    let rotated_ref = marmot_session::key_package_metadata(&rotated)
        .unwrap()
        .key_package_ref_hex;
    assert_eq!(current_ref(&laptop), Some(rotated_ref.clone()));
    assert_eq!(
        published_kinds(&relay, phone_cursor),
        vec![transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE, 30443],
        "the roster commit goes out before the KeyPackage"
    );
    deliver_new(&mut phone, &relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    assert_eq!(announced(&phone, &group, &laptop), Some(rotated_ref));
}

/// A KeyPackage whose announcement fails never reaches the slot. The relay
/// rejects the roster commit, so nothing is published; the next maintenance
/// pass announces again and then publishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_package_waits_for_its_announcement() {
    let (
        Devices {
            _dirs,
            relay,
            mut laptop,
            ..
        },
        group,
    ) = settled_linked_devices().await;
    let before = relay.published_events.lock().unwrap().len();
    let announced_before = announced(&laptop, &group, &laptop);
    relay.reject_next_publish();
    let error = laptop.rotate_key_package().await.unwrap_err();
    assert_eq!(
        error.privacy_safe_kind(),
        "account_key_package_announcement_pending"
    );
    assert!(published_kinds(&relay, before).is_empty());
    assert_eq!(announced(&laptop, &group, &laptop), announced_before);
    let pending = laptop
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .pending_replacement
        .unwrap();

    laptop.run_due_maintenance().await.unwrap();
    let pending_ref = hex::encode(&pending.key_package_ref);
    assert_eq!(current_ref(&laptop), Some(pending_ref.clone()));
    assert_eq!(announced(&laptop, &group, &laptop), Some(pending_ref));
    assert_eq!(
        published_kinds(&relay, before),
        vec![transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE, 30443]
    );
}

/// A host publication that must send a fresh KeyPackage announces that one,
/// not the current one, and sends it in the same call: here because the
/// device group's Welcome consumed the laptop's KeyPackage. The laptop sets
/// its tag signature key first, so the fresh one is tagged. The phone has
/// already replaced its untagged one, so its current one still serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_republish_that_needs_a_fresh_key_package_announces_that_one() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let mut laptop_cursor = relay.published_events.lock().unwrap().len();
    phone.run_due_maintenance().await.unwrap();
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert!(laptop.runtime.key_package_republish_falls_back().unwrap());
    assert_fresh_publication_is_announced(&mut laptop, &relay, &group, 0, 1).await;
    assert_eq!(
        key_package_claim(&laptop, &roster(&laptop, &group)),
        DeviceTagClaim::Device(slot_of(&laptop))
    );
    assert!(!phone.runtime.key_package_republish_falls_back().unwrap());
}

/// One host `publish_key_package` call commits the announcement of a fresh
/// KeyPackage newer than `newer_than`, then publishes it, after
/// `tag_key_commits` roster commits setting the device's tag signature key.
async fn assert_fresh_publication_is_announced(
    device: &mut AppClient,
    relay: &ScriptedPushRelayClient,
    group: &GroupId,
    newer_than: u64,
    tag_key_commits: usize,
) {
    let previous = current_ref(device);
    let before = relay.published_events.lock().unwrap().len();
    let published = device.publish_key_package().await.unwrap();
    let published_ref = marmot_session::key_package_metadata(&published)
        .unwrap()
        .key_package_ref_hex;
    assert_ne!(previous, Some(published_ref.clone()));
    assert_eq!(current_ref(device), Some(published_ref.clone()));
    assert_eq!(announced(device, group, device), Some(published_ref));
    assert!(
        device
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .authored_event_created_at
            .unwrap()
            .0
            > newer_than
    );
    let mut kinds = vec![transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE; tag_key_commits + 1];
    kinds.push(30443);
    assert_eq!(published_kinds(relay, before), kinds);
}

/// Without a readable device group the runtime would see nothing to
/// announce in, so a host publication is refused instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_device_group_refuses_publication() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        ..
    } = phone_and_laptop().await;
    let storage = phone_app.account_storage("alice").unwrap().app_storage();
    assert!(
        storage
            .insert_device_group(&storage_sqlite::DeviceGroupRecord {
                group_id_hex: "not a group id".to_owned(),
                trust: DeviceGroupTrust::Creating,
                key_package_ref_hex: Some("00".repeat(32)),
                recorded_at: 1,
            })
            .unwrap()
    );
    assert!(
        storage
            .trust_device_group(
                "not a group id",
                DeviceGroupTrust::Creating,
                DeviceGroupTrust::Created,
                None,
                1,
                &storage_sqlite::FirstTrustedRoster {
                    own: &[],
                    roster: &[],
                    now: 1,
                },
            )
            .unwrap()
            .is_some()
    );

    let before = relay.published_events.lock().unwrap().len();
    assert!(phone.publish_key_package().await.is_err());
    assert!(published_kinds(&relay, before).is_empty());
}

/// Make this device's newest slot publication `days` days old.
fn age_publication(app: &MarmotApp, days: u64) {
    let storage = app.account_storage("alice").unwrap();
    let mut lifecycle = storage.key_package_lifecycle().unwrap().unwrap();
    let now = unix_now_seconds();
    lifecycle.authored_event_created_at = Some(Timestamp(now - days * 24 * 60 * 60));
    storage.put_key_package_lifecycle(&lifecycle).unwrap();
}

/// A refresh is overdue once the device group has held its announcement back
/// and the slot's publication is a week old. A routine refresh announces and
/// publishes in one pass, so it never shows; nor does a held-back one while
/// the publication is younger than a week. The maintenance pass that finds it
/// overdue owes hosts a change, and so does the one that publishes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_held_back_a_week_is_overdue_until_it_publishes() {
    let (
        Devices {
            _dirs,
            relay,
            laptop_app,
            mut laptop,
            ..
        },
        _group,
    ) = settled_linked_devices().await;
    assert!(laptop.take_key_package_refresh_overdue_changed());
    laptop.run_due_maintenance().await.unwrap();
    let _ = laptop.take_key_package_refresh_overdue_changed();

    age_publication(&laptop_app, 8);
    let before = relay.published_events.lock().unwrap().len();
    laptop.run_due_maintenance().await.unwrap();
    assert_eq!(
        published_kinds(&relay, before),
        vec![transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE, 30443]
    );
    assert!(!laptop.key_package_refresh_overdue().unwrap());
    assert!(!laptop.take_key_package_refresh_overdue_changed());

    relay.reject_next_publish();
    laptop.rotate_key_package().await.unwrap_err();
    assert!(!laptop.key_package_refresh_overdue().unwrap());

    age_publication(&laptop_app, 8);
    relay.reject_next_publish();
    let before = relay.published_events.lock().unwrap().len();
    laptop.run_due_maintenance().await.unwrap();
    assert!(published_kinds(&relay, before).is_empty());
    assert!(laptop.key_package_refresh_overdue().unwrap());
    assert!(laptop.take_key_package_refresh_overdue_changed());

    // Retry backoff at the relays doesn't hide it: here every target was
    // just tried, so maintenance owes nothing until the backoff ends.
    let storage = laptop_app.account_storage("alice").unwrap();
    let mut lifecycle = storage.key_package_lifecycle().unwrap().unwrap();
    let pending = lifecycle.pending_replacement.as_mut().unwrap();
    assert!(pending.signed_event.is_some());
    for target in &mut pending.targets {
        target.state = TransportFanoutAttemptState::AttemptedFailed;
        target.attempt_count = 1;
        target.last_attempt_at = Some(Timestamp(unix_now_seconds()));
    }
    storage.put_key_package_lifecycle(&lifecycle).unwrap();
    assert!(
        !laptop
            .runtime
            .key_package_network_maintenance_due()
            .unwrap()
    );
    assert!(laptop.key_package_refresh_overdue().unwrap());

    laptop.run_due_maintenance().await.unwrap();
    assert!(!laptop.key_package_refresh_overdue().unwrap());
    assert!(laptop.take_key_package_refresh_overdue_changed());
}

/// The roster slot `client` publishes its KeyPackages in.
fn slot_of(client: &AppClient) -> [u8; 32] {
    hex::decode(own_slot(client)).unwrap().try_into().unwrap()
}

/// What `reader`'s copy of the device group says `device`'s leaf there is.
fn leaf_claim(
    reader: &AppClient,
    group: &GroupId,
    device: &AppClient,
    roster: &DeviceRosterV1,
) -> Option<DeviceTagClaim> {
    let epoch = reader.runtime.group_record(group).unwrap().epoch;
    let leaf_index = device.runtime.own_leaf_index(group).unwrap();
    reader
        .runtime
        .member_device_tag_claim(group, epoch, leaf_index, roster)
        .unwrap()
}

/// What `client`'s current KeyPackage says it is, read against `roster`.
fn key_package_claim(client: &AppClient, roster: &DeviceRosterV1) -> DeviceTagClaim {
    use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn, ProtocolVersion};
    use tls_codec::Deserialize as _;
    let key_package = client
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .current_key_package
        .unwrap();
    let MlsMessageBodyIn::KeyPackage(key_package) =
        MlsMessageIn::tls_deserialize_exact(key_package.bytes())
            .unwrap()
            .extract()
    else {
        panic!("expected a KeyPackage")
    };
    let key_package = key_package
        .validate(
            &openmls_rust_crypto::RustCrypto::default(),
            ProtocolVersion::Mls10,
        )
        .unwrap();
    cgka_engine::device_tag::device_tag_claim(key_package.leaf_node(), roster)
}

/// Each device tags from the device group it trusts (mdk#2628 3.1d). The
/// founder's founding entry carries its tag signature key, so its leaf reads
/// as its slot from the start. The laptop sets its own key on its next
/// maintenance pass, in a roster commit whose own leaf already carries the
/// tag, before it stages anything; the same pass then announces and
/// publishes a tagged KeyPackage. The phone's next pass replaces its
/// untagged one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_device_tags_from_the_device_group_it_trusts() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let (phone_slot, laptop_slot) = (slot_of(&phone), slot_of(&laptop));
    let founding = roster(&laptop, &group);
    assert_eq!(
        founding.devices[&phone_slot].tag_signature_key,
        Some(phone.runtime.own_signature_key())
    );
    assert_eq!(founding.devices[&laptop_slot].tag_signature_key, None);
    assert_eq!(
        leaf_claim(&laptop, &group, &phone, &founding),
        Some(DeviceTagClaim::Device(phone_slot))
    );
    assert_eq!(
        leaf_claim(&laptop, &group, &laptop, &founding),
        Some(DeviceTagClaim::Unclaimed)
    );

    assert_eq!(
        key_package_claim(&laptop, &founding),
        DeviceTagClaim::Unclaimed
    );
    let mut phone_cursor = relay.published_events.lock().unwrap().len();
    let since = phone_cursor;
    laptop.run_due_maintenance().await.unwrap();
    assert_eq!(
        published_kinds(&relay, since),
        vec![
            transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE,
            transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE,
            30443
        ],
        "the key goes out before the KeyPackage's announcement"
    );
    deliver_new(&mut phone, &relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    for reader in [&phone, &laptop] {
        let roster = roster(reader, &group);
        assert_eq!(
            roster.devices[&laptop_slot].tag_signature_key,
            Some(laptop.runtime.own_signature_key())
        );
        assert_eq!(
            leaf_claim(reader, &group, &laptop, &roster),
            Some(DeviceTagClaim::Device(laptop_slot))
        );
    }
    assert_eq!(
        key_package_claim(&laptop, &roster(&laptop, &group)),
        DeviceTagClaim::Device(laptop_slot)
    );

    assert_eq!(
        key_package_claim(&phone, &roster(&phone, &group)),
        DeviceTagClaim::Unclaimed
    );
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(
        key_package_claim(&phone, &roster(&phone, &group)),
        DeviceTagClaim::Device(phone_slot)
    );
}

/// Each device's own roster entry carries its history key (mdk#2628 4.1),
/// with no commit of its own: the founder's founding entry, and the new
/// device's first commit, which sets its tag signature key. A sibling seals
/// to the key the roster holds, and only that device opens it. A device whose
/// entry lost the key writes it again with its next announcement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_device_keeps_its_history_key_in_its_own_entry() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let (phone_slot, laptop_slot) = (slot_of(&phone), slot_of(&laptop));
    let phone_key = phone.runtime.history_public_key().unwrap();
    let laptop_key = laptop.runtime.history_public_key().unwrap();
    assert_ne!(phone_key, laptop_key);
    let founding = roster(&laptop, &group);
    assert_eq!(
        founding.devices[&phone_slot].history_key,
        Some(phone_key.clone())
    );
    assert_eq!(founding.devices[&laptop_slot].history_key, None);

    let mut phone_cursor = relay.published_events.lock().unwrap().len();
    let since = phone_cursor;
    laptop.run_due_maintenance().await.unwrap();
    assert_eq!(
        published_kinds(&relay, since),
        vec![
            transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE,
            transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE,
            30443
        ],
        "the history key rides on the tag-key commit"
    );
    deliver_new(&mut phone, &relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    for reader in [&phone, &laptop] {
        let entry = &roster(reader, &group).devices[&laptop_slot];
        assert_eq!(
            entry.tag_signature_key,
            Some(laptop.runtime.own_signature_key())
        );
        assert_eq!(entry.history_key, Some(laptop_key.clone()));
    }

    let context = b"history for the laptop";
    let sealed = phone
        .runtime
        .seal_history(
            roster(&phone, &group).devices[&laptop_slot]
                .history_key
                .as_deref()
                .unwrap(),
            context,
            b"bundle",
        )
        .unwrap();
    assert_eq!(
        laptop.runtime.open_history(context, &sealed).unwrap(),
        Some(b"bundle".to_vec())
    );
    assert_eq!(phone.runtime.open_history(context, &sealed).unwrap(), None);

    // The phone clears the laptop's key; the laptop's next announcement
    // writes it back.
    let mut laptop_cursor = relay.published_events.lock().unwrap().len();
    let cleared = phone
        .runtime
        .edit_device_roster_entry(&group, &laptop_slot, &[], |entry| {
            entry.history_key = None;
        })
        .await
        .unwrap();
    assert!(matches!(cleared, DeviceRosterEdit::Committed(_)));
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(
        roster(&laptop, &group).devices[&laptop_slot].history_key,
        None
    );
    let mut phone_cursor = relay.published_events.lock().unwrap().len();
    laptop.run_due_maintenance().await.unwrap();
    deliver_new(&mut phone, &relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    for reader in [&phone, &laptop] {
        assert_eq!(
            roster(reader, &group).devices[&laptop_slot].history_key,
            Some(laptop_key.clone())
        );
    }
}

/// A KeyPackage staged while this device's tag signature key is due would go
/// out untagged once the key is set (mdk#2628 3.1d), so nothing is staged
/// until the merged roster carries it. When the relay refuses the roster
/// commit, neither maintenance nor a host publication stages or publishes a
/// KeyPackage. Once it accepts, one host rotation sets the key, then
/// announces and publishes a tagged KeyPackage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_package_waits_for_the_tag_signature_key() {
    let (
        Devices {
            _dirs,
            relay,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let laptop_slot = slot_of(&laptop);
    let current = current_ref(&laptop);
    let before = relay.published_events.lock().unwrap().len();
    relay.reject_next_publish();
    laptop.run_due_maintenance().await.unwrap();
    relay.reject_next_publish();
    let error = laptop.publish_key_package().await.unwrap_err();
    assert_eq!(
        error.privacy_safe_kind(),
        "account_key_package_announcement_pending"
    );
    assert!(published_kinds(&relay, before).is_empty());
    let status = laptop.key_package_maintenance_status().unwrap().unwrap();
    assert!(status.pending_replacement.is_none(), "nothing is staged");
    assert_eq!(current_ref(&laptop), current);
    assert_eq!(
        roster(&laptop, &group).devices[&laptop_slot].tag_signature_key,
        None
    );

    laptop.rotate_key_package().await.unwrap();
    assert_eq!(
        roster(&laptop, &group).devices[&laptop_slot].tag_signature_key,
        Some(laptop.runtime.own_signature_key())
    );
    assert_ne!(current_ref(&laptop), current);
    assert_eq!(announced(&laptop, &group, &laptop), current_ref(&laptop));
    assert_eq!(
        key_package_claim(&laptop, &roster(&laptop, &group)),
        DeviceTagClaim::Device(laptop_slot)
    );
    assert_eq!(
        published_kinds(&relay, before),
        vec![
            transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE,
            transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE,
            30443
        ],
        "the key goes out before the KeyPackage's announcement"
    );
}

/// A replacement staged before this device tags is superseded once it does
/// (mdk#2628 3.1d), so it never reaches the slot untagged. The phone's
/// rotation is refused at the relay, leaving its replacement staged; once
/// the phone founds its device group, its next maintenance pass announces and
/// publishes a tagged KeyPackage in its place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_untagged_staged_key_package_is_replaced_once_the_device_tags() {
    let Devices {
        _dirs,
        relay,
        mut phone,
        link,
        ..
    } = phone_and_laptop().await;
    relay.reject_next_publish();
    phone.rotate_key_package().await.unwrap_err();
    let untagged = phone
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .pending_replacement
        .expect("the refused replacement stays staged")
        .key_package_ref;

    let group = phone.dev_create_device_group(link).await.unwrap();
    phone.run_due_maintenance().await.unwrap();
    assert_ne!(current_ref(&phone), Some(hex::encode(&untagged)));
    assert_eq!(announced(&phone, &group, &phone), current_ref(&phone));
    assert_eq!(
        key_package_claim(&phone, &roster(&phone, &group)),
        DeviceTagClaim::Device(slot_of(&phone))
    );
}

/// A refresh waiting for this device's tag signature key (mdk#2628 3.1d) is
/// held back like one waiting for its announcement: once the slot's
/// publication is a week old it is overdue, though the current KeyPackage is
/// announced. It clears once the key is set and a tagged KeyPackage publishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_waiting_for_the_tag_signature_key_is_overdue_after_a_week() {
    let (
        Devices {
            _dirs,
            relay,
            laptop_app,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let laptop_slot = slot_of(&laptop);
    let _ = laptop.take_key_package_refresh_overdue_changed();
    age_publication(&laptop_app, 8);
    assert_eq!(announced(&laptop, &group, &laptop), current_ref(&laptop));
    relay.reject_next_publish();
    laptop.run_due_maintenance().await.unwrap();
    assert_eq!(
        roster(&laptop, &group).devices[&laptop_slot].tag_signature_key,
        None
    );
    assert!(laptop.key_package_refresh_overdue().unwrap());
    assert!(laptop.take_key_package_refresh_overdue_changed());

    laptop.run_due_maintenance().await.unwrap();
    assert_eq!(
        key_package_claim(&laptop, &roster(&laptop, &group)),
        DeviceTagClaim::Device(laptop_slot)
    );
    assert!(!laptop.key_package_refresh_overdue().unwrap());
    assert!(laptop.take_key_package_refresh_overdue_changed());
}

/// While another device's entry carries this device's tag signature key, this
/// device cannot set the key in its own entry, since a roster gives each key
/// one device (mdk#2628 3.1d). The engine tags only from this device's own
/// entry, so maintenance does not hold the refresh back: it announces and
/// publishes an untagged KeyPackage, never one that reads as that device's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_held_by_another_device_leaves_key_packages_untagged() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let laptop_slot = slot_of(&laptop);
    let update = encode_device_roster_update_v1(
        &DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetDevice(
            [9; 32],
            DeviceEntryV1 {
                tag_signature_key: Some(laptop.runtime.own_signature_key()),
                ..DeviceEntryV1::default()
            },
        )])
        .unwrap(),
    )
    .unwrap();
    let mut laptop_cursor = relay.published_events.lock().unwrap().len();
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
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    let current = current_ref(&laptop);

    let before = relay.published_events.lock().unwrap().len();
    laptop.run_due_maintenance().await.unwrap();
    assert_ne!(current_ref(&laptop), current);
    assert_eq!(announced(&laptop, &group, &laptop), current_ref(&laptop));
    assert_eq!(
        key_package_claim(&laptop, &roster(&laptop, &group)),
        DeviceTagClaim::Unclaimed
    );
    assert_eq!(
        published_kinds(&relay, before),
        vec![transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE, 30443]
    );
    assert_eq!(
        roster(&laptop, &group).devices[&laptop_slot].tag_signature_key,
        None
    );
}

/// An eager open names the device group to tag from before it returns; a
/// deferred one only once hydration has run, since naming hydrates it. Each
/// maintenance pass names it again, as it does the group it announces in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_open_names_the_device_group_to_tag_from_once_it_is_hydrated() {
    let (
        Devices {
            _dirs,
            relay,
            phone_app,
            phone,
            ..
        },
        group,
    ) = linked_devices().await;
    assert_eq!(phone.runtime.device_tag_group(), Some(&group));
    drop(phone);
    let phone = phone_app.client("alice").await.unwrap();
    assert_eq!(phone.runtime.device_tag_group(), Some(&group));
    drop(phone);

    let plane = MarmotRelayPlane::new(None, relay.clone());
    let mut phone = phone_app
        .local_client_with_relay_plane_and_hydration("alice", &plane, None, true, None)
        .await
        .unwrap();
    assert_eq!(phone.runtime.device_tag_group(), None);
    crate::runtime::account_worker::drain_deferred_hydration(&mut phone)
        .await
        .unwrap();
    assert_eq!(phone.runtime.device_tag_group(), Some(&group));

    phone.runtime.set_device_tag_group(None).unwrap();
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(phone.runtime.device_tag_group(), Some(&group));
}

/// A `removed` slot record is dropped once 30 days have passed since its
/// `rejected_at`, by the dropping device's own clock (mdk#2628 3.1d), so the
/// roster does not keep every device the account ever removed. Any device
/// drops it, in one commit, once the device group can take a commit from it.
/// A younger record and every `not_me` record stay, and once the expired one
/// is gone, maintenance owes the roster nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_device_record_is_dropped_after_30_days() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = settled_linked_devices().await;
    let now = unix_now_seconds();
    let rejected = |reason, days_ago: u64, tag_signature_key| RejectedSlotV1 {
        reason,
        rejected_at: now - days_ago * 24 * 60 * 60,
        tag_signature_key,
    };
    let (expired, young, not_me) = ([7; 32], [8; 32], [9; 32]);
    let update = encode_device_roster_update_v1(
        &DeviceRosterUpdateV1::new(vec![
            DeviceRosterOperationV1::SetRejectedSlot(
                expired,
                rejected(RejectedSlotReasonV1::Removed, 31, Some(vec![7; 32])),
            ),
            DeviceRosterOperationV1::SetRejectedSlot(
                young,
                rejected(RejectedSlotReasonV1::Removed, 29, Some(vec![8; 32])),
            ),
            DeviceRosterOperationV1::SetRejectedSlot(
                not_me,
                rejected(RejectedSlotReasonV1::NotMe, 31, None),
            ),
        ])
        .unwrap(),
    )
    .unwrap();
    let mut laptop_cursor = relay.published_events.lock().unwrap().len();
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
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();

    let mut phone_cursor = relay.published_events.lock().unwrap().len();
    // A held device group takes no roster commit from this device.
    laptop
        .runtime
        .run_due_maintenance_holding(std::slice::from_ref(&group))
        .await
        .unwrap();
    assert!(published_kinds(&relay, phone_cursor).is_empty());
    assert_eq!(roster(&laptop, &group).rejected_slots.len(), 3);

    laptop.run_due_maintenance().await.unwrap();
    assert_eq!(
        published_kinds(&relay, phone_cursor),
        vec![transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE]
    );
    deliver_new(&mut phone, &relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    for client in [&phone, &laptop] {
        let kept: Vec<_> = roster(client, &group).rejected_slots.into_keys().collect();
        assert_eq!(kept, vec![young, not_me]);
    }

    let before = relay.published_events.lock().unwrap().len();
    phone.run_due_maintenance().await.unwrap();
    laptop.run_due_maintenance().await.unwrap();
    assert!(published_kinds(&relay, before).is_empty());
}
