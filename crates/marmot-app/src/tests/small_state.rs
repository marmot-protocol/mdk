//! Small state between an account's devices (mdk#2628 item 4.3). A pass on
//! one device records what its user changed there and applies the values
//! its siblings sent, once that device trusts its account's device group.

use super::canonical_membership::{app_at, deliver_new, published_key_package};
use super::device_group::{Devices, phone_and_laptop, stable_slot};
use super::*;
use crate::small_state::encode_snapshot_request;
use storage_sqlite::{MuteSetting, SmallStateItem, SmallStateValue, SmallStateVersion};

/// Bob, with a published KeyPackage on `relay`, and a chat the phone starts
/// with him.
async fn chat_with_bob(
    phone_app: &MarmotApp,
    phone: &mut AppClient,
    relay: &Arc<ScriptedPushRelayClient>,
) -> (tempfile::TempDir, GroupId) {
    let bob_dir = tempfile::tempdir().unwrap();
    let bob_id = AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap()
        .account_id_hex;
    let bob_app = app_at(&bob_dir, relay.clone());
    let mut bob = bob_app.client("bob").await.unwrap();
    published_key_package(&mut bob, relay).await;
    remember_test_member_inbox(phone_app, &bob_id, "wss://relay.example");
    let chat = phone
        .create_group("Bob and Alice", &[&bob_id])
        .await
        .unwrap();
    (bob_dir, chat)
}

/// The laptop joins the device group the phone creates for their link.
async fn link(devices: &mut Devices) {
    devices
        .laptop
        .dev_record_confirmed_device_link(devices.link.clone())
        .unwrap();
    devices
        .phone
        .dev_create_device_group(devices.link.clone())
        .await
        .unwrap();
    let mut cursor = 0;
    deliver_new(&mut devices.laptop, &devices.relay, &mut cursor).await;
    devices.laptop.sync().await.unwrap();
    assert!(devices.laptop.trusted_device_group().unwrap().is_some());
}

fn sibling_value(chat_hex: &str, value: SmallStateValue) -> SmallStateItem {
    SmallStateItem {
        group_id_hex: chat_hex.to_owned(),
        value,
        version: Some(SmallStateVersion {
            version: 1,
            change_id: [7; 16],
        }),
    }
}

fn triggers(client: &mut AppClient) -> Vec<(String, ChatListUpdateTrigger)> {
    client
        .take_pending_projection_updates()
        .into_iter()
        .inspect(|update| assert!(update.chat_list_row.is_some()))
        .map(|update| (update.group_id_hex, update.chat_list_trigger))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_records_this_devices_changes_and_applies_its_siblings() {
    let mut devices = phone_and_laptop().await;
    let (_bob_dir, chat) =
        chat_with_bob(&devices.phone_app, &mut devices.phone, &devices.relay).await;
    let chat_hex = hex::encode(chat.as_slice());
    let phone_app = devices.phone_app.clone();
    let storage = || phone_app.account_storage("alice").unwrap().app_storage();
    phone_app.set_chat_pinned("alice", &chat_hex, true).unwrap();

    // Before the phone trusts a device group, a pass does nothing.
    devices.phone.sync_small_state(&[]).unwrap();
    assert!(!storage().small_state_started().unwrap());

    // Its first pass after that starts small state: the pin is owed to the
    // laptop at version 1, and so is a snapshot request.
    link(&mut devices).await;
    let phone = &mut devices.phone;
    phone.take_pending_projection_updates();
    phone.sync_small_state(&[]).unwrap();
    assert!(storage().small_state_snapshot_owed().unwrap());
    let owed = storage().unsent_small_state_items().unwrap();
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].value, SmallStateValue::Pin(true));
    assert_eq!(owed[0].version.unwrap().version, 1);
    assert!(triggers(phone).is_empty());

    // A sibling's mute is applied, and hosts hear of it.
    let mute = sibling_value(&chat_hex, SmallStateValue::Mute(MuteSetting::Muted));
    phone.sync_small_state(&[mute]).unwrap();
    assert!(
        phone_app
            .chat_notification_settings("alice", &chat_hex)
            .unwrap()
            .muted
    );
    assert_eq!(
        triggers(phone),
        vec![(chat_hex.clone(), ChatListUpdateTrigger::MuteChanged)]
    );

    // A sibling's archive goes through the account state. Archiving unpins,
    // and that unpin is the phone's own change, owed at the next version.
    let archive = sibling_value(&chat_hex, SmallStateValue::Archive(true));
    phone.sync_small_state(&[archive]).unwrap();
    assert!(phone.state_group_record(&chat).unwrap().archived);
    assert_eq!(
        triggers(phone),
        vec![(chat_hex.clone(), ChatListUpdateTrigger::ArchiveChanged)]
    );
    phone.sync_small_state(&[]).unwrap();
    let owed = storage().unsent_small_state_items().unwrap();
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].value, SmallStateValue::Pin(false));
    assert_eq!(owed[0].version.unwrap().version, 2);
    phone.sync_small_state(&[]).unwrap();
    assert_eq!(storage().unsent_small_state_items().unwrap(), owed);
    assert!(triggers(phone).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_snapshot_request_is_answered_only_by_the_device_it_names() {
    let mut devices = phone_and_laptop().await;
    link(&mut devices).await;
    let phone_slot: [u8; 32] = hex::decode(stable_slot(&devices.phone_app))
        .unwrap()
        .try_into()
        .unwrap();
    let laptop_slot: [u8; 32] = hex::decode(stable_slot(&devices.laptop_app))
        .unwrap()
        .try_into()
        .unwrap();
    let phone = &mut devices.phone;

    let (group, roster) = phone.trusted_device_roster().unwrap().unwrap();
    assert_eq!(
        phone.small_state_snapshot_target(&roster).unwrap(),
        Some(laptop_slot)
    );

    phone
        .receive_small_state_snapshot_request(&group, &encode_snapshot_request(&laptop_slot))
        .unwrap();
    assert!(!phone.small_state_snapshot_answer_owed);
    assert!(
        phone
            .receive_small_state_snapshot_request(&group, "{\"v\":1}")
            .is_err()
    );
    // Only the trusted device group carries small state.
    let elsewhere = GroupId::new(vec![0x11; 16]);
    let asks_phone = encode_snapshot_request(&phone_slot);
    assert!(
        phone
            .receive_small_state_snapshot_request(&elsewhere, &asks_phone)
            .is_err()
    );
    assert!(!phone.small_state_snapshot_answer_owed);
    phone
        .receive_small_state_snapshot_request(&group, &asks_phone)
        .unwrap();
    assert!(phone.small_state_snapshot_answer_owed);
}
