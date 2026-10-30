//! Small state between an account's devices (mdk#2628 item 4.3). A pass on
//! one device records what its user changed there and applies the values
//! its siblings sent, once that device trusts its account's device group.

use super::canonical_membership::{app_at, deliver_new, published_key_package};
use super::device_group::{Devices, phone_and_laptop};
use super::*;
use crate::small_state::{
    BROADCAST_REQUEST, KIND_SMALL_STATE_BROADCAST_REQUEST, KIND_SMALL_STATE_UPDATE,
};
use storage_sqlite::{
    MuteSetting, SmallStateBroadcast, SmallStateItem, SmallStateValue, SmallStateVersion,
};

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
    // laptop at version 1, and so is a broadcast request.
    link(&mut devices).await;
    let phone = &mut devices.phone;
    phone.take_pending_projection_updates();
    phone.sync_small_state(&[]).unwrap();
    assert!(
        storage()
            .small_state_schedule()
            .unwrap()
            .unwrap()
            .request_owed
    );
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
async fn broadcasts_follow_their_schedule_and_withdrawals_owe_again() {
    const HOUR: u64 = 60 * 60;
    let mut devices = phone_and_laptop().await;
    link(&mut devices).await;
    let phone_app = devices.phone_app.clone();
    let storage = || phone_app.account_storage("alice").unwrap().app_storage();
    let phone = &mut devices.phone;
    let (group, _) = phone.trusted_device_roster().unwrap().unwrap();
    let tip = phone_app
        .account_storage("alice")
        .unwrap()
        .get_group(&group)
        .unwrap()
        .epoch
        .0;
    let schedule = || storage().small_state_schedule().unwrap().unwrap();

    // The first pass starts small state, and the first broadcast is due at
    // once, at the device group's tip.
    phone.sync_small_state(&[]).unwrap();
    let now = 1_000_000;
    phone.begin_small_state_broadcast_when_due(now).unwrap();
    assert_eq!(
        schedule().last_broadcast,
        Some(SmallStateBroadcast { at: now, tip })
    );
    phone.begin_small_state_broadcast_when_due(now + 1).unwrap();
    assert_eq!(schedule().last_broadcast.unwrap().at, now);

    // A sibling's request is answered once an hour has passed since the
    // last broadcast. Only the trusted device group carries one.
    let elsewhere = GroupId::new(vec![0x11; 16]);
    assert!(
        phone
            .receive_small_state_broadcast_request(&elsewhere, BROADCAST_REQUEST)
            .is_err()
    );
    assert!(
        phone
            .receive_small_state_broadcast_request(&group, "{\"v\":1,\"to\":\"5a\"}")
            .is_err()
    );
    assert!(!schedule().answer_owed);
    phone
        .receive_small_state_broadcast_request(&group, BROADCAST_REQUEST)
        .unwrap();
    assert!(schedule().answer_owed);
    phone
        .begin_small_state_broadcast_when_due(now + HOUR - 1)
        .unwrap();
    assert_eq!(schedule().last_broadcast.unwrap().at, now);
    phone
        .begin_small_state_broadcast_when_due(now + HOUR)
        .unwrap();
    assert_eq!(schedule().last_broadcast.unwrap().at, now + HOUR);
    assert!(!schedule().answer_owed);

    // A withdrawn request owes a new one.
    storage().small_state_broadcast_request_sent().unwrap();
    phone
        .small_state_message_withdrawn(&group, KIND_SMALL_STATE_BROADCAST_REQUEST)
        .unwrap();
    assert!(schedule().request_owed);

    // A withdrawn update owes every item held again, whoever sent it.
    let chat_hex = "0a".repeat(16);
    let pin = sibling_value(&chat_hex, SmallStateValue::Pin(true));
    phone.sync_small_state(std::slice::from_ref(&pin)).unwrap();
    storage()
        .mark_small_state_sent(&storage().unsent_small_state_items().unwrap())
        .unwrap();
    assert!(storage().unsent_small_state_items().unwrap().is_empty());
    phone
        .small_state_message_withdrawn(&group, KIND_SMALL_STATE_UPDATE)
        .unwrap();
    assert_eq!(storage().unsent_small_state_items().unwrap(), vec![pin]);
    assert!(
        phone
            .small_state_message_withdrawn(&elsewhere, KIND_SMALL_STATE_UPDATE)
            .is_err()
    );
}
