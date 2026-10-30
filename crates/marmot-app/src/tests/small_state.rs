//! Small state between an account's devices (mdk#2628 item 4.3). A pass on
//! one device records what its user changed there and applies the values
//! its siblings sent, once that device trusts its account's device group.

use super::canonical_membership::{app_at, deliver_new, published_key_package};
use super::device_group::{Devices, deliver_all, phone_and_laptop};
use super::*;
use crate::small_state::{
    BROADCAST_REQUEST, KIND_SMALL_STATE_BROADCAST_REQUEST, KIND_SMALL_STATE_UPDATE,
};
use std::collections::BTreeMap;
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
    // and that unpin is the phone's own change, owed at the next version
    // from the same pass.
    let archive = sibling_value(&chat_hex, SmallStateValue::Archive(true));
    phone.sync_small_state(&[archive]).unwrap();
    assert!(phone.state_group_record(&chat).unwrap().archived);
    assert_eq!(
        triggers(phone),
        vec![(chat_hex.clone(), ChatListUpdateTrigger::ArchiveChanged)]
    );
    let owed = storage().unsent_small_state_items().unwrap();
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].value, SmallStateValue::Pin(false));
    assert_eq!(owed[0].version.unwrap().version, 2);
    phone.sync_small_state(&[]).unwrap();
    assert_eq!(storage().unsent_small_state_items().unwrap(), owed);
    assert!(triggers(phone).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unarchive_right_after_a_siblings_archive_is_this_devices_change() {
    let mut devices = phone_and_laptop().await;
    let (_bob_dir, chat) =
        chat_with_bob(&devices.phone_app, &mut devices.phone, &devices.relay).await;
    let chat_hex = hex::encode(chat.as_slice());
    link(&mut devices).await;
    let storage = devices
        .phone_app
        .account_storage("alice")
        .unwrap()
        .app_storage();
    let phone = &mut devices.phone;
    phone.sync_small_state(&[]).unwrap();
    storage
        .mark_small_state_sent(&storage.unsent_small_state_items().unwrap())
        .unwrap();

    let archive = sibling_value(&chat_hex, SmallStateValue::Archive(true));
    phone.sync_small_state(&[archive]).unwrap();
    assert!(phone.state_group_record(&chat).unwrap().archived);
    phone.set_group_archived(&chat, false).unwrap();
    phone.sync_small_state(&[]).unwrap();
    assert!(!phone.state_group_record(&chat).unwrap().archived);
    let owed = storage.unsent_small_state_items().unwrap();
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].value, SmallStateValue::Archive(false));
    assert_eq!(owed[0].version.unwrap().version, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pin_that_comes_with_an_unarchive_is_applied_with_it() {
    let mut devices = phone_and_laptop().await;
    let (_bob_dir, chat) =
        chat_with_bob(&devices.phone_app, &mut devices.phone, &devices.relay).await;
    devices.phone.set_group_archived(&chat, true).unwrap();
    let chat_hex = hex::encode(chat.as_slice());
    link(&mut devices).await;
    let storage = devices
        .phone_app
        .account_storage("alice")
        .unwrap()
        .app_storage();
    let phone = &mut devices.phone;
    // The phone's archive is owed at version 1.
    phone.sync_small_state(&[]).unwrap();
    storage
        .mark_small_state_sent(&storage.unsent_small_state_items().unwrap())
        .unwrap();
    phone.take_pending_projection_updates();

    let unarchive = SmallStateItem {
        version: Some(SmallStateVersion {
            version: 2,
            change_id: [7; 16],
        }),
        ..sibling_value(&chat_hex, SmallStateValue::Archive(false))
    };
    let pin = sibling_value(&chat_hex, SmallStateValue::Pin(true));
    phone.sync_small_state(&[unarchive, pin]).unwrap();
    let updates = phone.take_pending_projection_updates();
    assert_eq!(updates.len(), 1);
    let row = updates[0].chat_list_row.as_ref().unwrap();
    assert!(!row.archived && row.pinned);
    assert_eq!(
        updates[0].chat_list_trigger,
        ChatListUpdateTrigger::ArchiveChanged
    );
    phone.sync_small_state(&[]).unwrap();
    assert!(storage.unsent_small_state_items().unwrap().is_empty());
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

/// The device-group messages `client` recorded, by app event id: the
/// message id its own engine names it by, and its kind. A sender names its
/// own message by its transport id, a reader by its content.
fn recorded(client: &AppClient, group: &GroupId) -> BTreeMap<String, (MessageId, u64)> {
    client
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .device_group_messages()
        .unwrap()
        .into_iter()
        .filter(|(group_hex, ..)| *group_hex == hex::encode(group.as_slice()))
        .map(|(_, event, message, kind)| {
            let message = MessageId::new(hex::decode(message.expect("message id known")).unwrap());
            (event, (message, kind))
        })
        .collect()
}

fn kinds(recorded: &BTreeMap<String, (MessageId, u64)>) -> Vec<u64> {
    let mut kinds: Vec<_> = recorded.values().map(|(_, kind)| *kind).collect();
    kinds.sort_unstable();
    kinds
}

fn withdrawn(group: &GroupId, message_id: &MessageId) -> cgka_traits::engine::GroupEvent {
    cgka_traits::engine::GroupEvent::AppMessageInvalidated {
        group_id: group.clone(),
        message_id: message_id.clone(),
        epoch: cgka_traits::EpochId(0),
        reason: cgka_traits::engine::AppMessageInvalidationReason::LosingBranch,
        decrypted_payload_ref: None,
    }
}

/// Siblings exchange small state through the device group. A device that
/// starts broadcasts every item it holds, split into updates that each fit,
/// and asks its siblings to broadcast; a sibling merges every item, whether
/// or not it is in the chat, and owes an answer. A device that sent or read
/// an update owes its items again when branch selection withdraws it, and a
/// withdrawn request owes a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn siblings_exchange_small_state_through_the_device_group() {
    let mut devices = phone_and_laptop().await;
    let (_bob_dir, chat) =
        chat_with_bob(&devices.phone_app, &mut devices.phone, &devices.relay).await;
    let chat_hex = hex::encode(chat.as_slice());
    devices
        .phone_app
        .set_chat_pinned("alice", &chat_hex, true)
        .unwrap();
    link(&mut devices).await;
    let (group, _) = devices.phone.trusted_device_roster().unwrap().unwrap();
    let phone_app = devices.phone_app.clone();
    let laptop_app = devices.laptop_app.clone();
    let phone_storage = || phone_app.account_storage("alice").unwrap().app_storage();
    let laptop_storage = || laptop_app.account_storage("alice").unwrap().app_storage();

    // Enough items held from elsewhere that one broadcast takes two updates.
    let held: Vec<_> = (0u16..400)
        .map(|index| {
            let mut chat = [0x0b; 16];
            chat[..2].copy_from_slice(&index.to_be_bytes());
            sibling_value(&hex::encode(chat), SmallStateValue::Archive(true))
        })
        .collect();
    devices.phone.sync_small_state(&held).unwrap();

    devices.phone.run_due_maintenance().await.unwrap();
    assert!(
        phone_storage()
            .unsent_small_state_items()
            .unwrap()
            .is_empty()
    );
    let schedule = phone_storage().small_state_schedule().unwrap().unwrap();
    assert!(schedule.last_broadcast.is_some());
    assert!(!schedule.request_owed);
    let sent = recorded(&devices.phone, &group);
    assert_eq!(
        kinds(&sent),
        [
            KIND_SMALL_STATE_UPDATE,
            KIND_SMALL_STATE_UPDATE,
            KIND_SMALL_STATE_BROADCAST_REQUEST
        ]
    );

    deliver_all(&mut devices.laptop, &devices.relay).await;
    let phone_items = phone_storage().small_state_items().unwrap();
    assert_eq!(phone_items.len(), 401);
    assert_eq!(laptop_storage().small_state_items().unwrap(), phone_items);
    let laptop_schedule = laptop_storage().small_state_schedule().unwrap().unwrap();
    assert!(laptop_schedule.answer_owed);
    // Merged items are not owed back: their sender has them.
    assert!(
        laptop_storage()
            .unsent_small_state_items()
            .unwrap()
            .is_empty()
    );
    let read = recorded(&devices.laptop, &group);
    let by_event = |recorded: &BTreeMap<String, (MessageId, u64)>| {
        recorded
            .iter()
            .map(|(event, (_, kind))| (event.clone(), *kind))
            .collect::<Vec<_>>()
    };
    assert_eq!(by_event(&read), by_event(&sent));

    // The laptop starts too: it broadcasts what it holds and asks.
    devices.laptop.run_due_maintenance().await.unwrap();
    assert!(
        laptop_storage()
            .unsent_small_state_items()
            .unwrap()
            .is_empty()
    );
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(phone_storage().small_state_items().unwrap(), phone_items);
    assert!(
        phone_storage()
            .small_state_schedule()
            .unwrap()
            .unwrap()
            .answer_owed
    );

    // A withdrawn update owes every item again, on the device that sent it
    // and on the one that merged it, each naming it by its own id; a message
    // no one recorded owes nothing.
    let of_kind = |kind| {
        sent.iter()
            .find(|(_, (_, sent_kind))| *sent_kind == kind)
            .map(|(event, _)| event.clone())
            .unwrap()
    };
    let (update, request) = (
        of_kind(KIND_SMALL_STATE_UPDATE),
        of_kind(KIND_SMALL_STATE_BROADCAST_REQUEST),
    );
    devices
        .phone
        .observe_device_group_event(&withdrawn(&group, &MessageId::new(vec![0x77; 32])));
    assert!(
        phone_storage()
            .unsent_small_state_items()
            .unwrap()
            .is_empty()
    );
    devices
        .phone
        .observe_device_group_event(&withdrawn(&group, &sent[&update].0));
    devices
        .laptop
        .observe_device_group_event(&withdrawn(&group, &read[&update].0));
    assert_eq!(
        phone_storage().unsent_small_state_items().unwrap().len(),
        401
    );
    assert_eq!(
        laptop_storage().unsent_small_state_items().unwrap().len(),
        401
    );

    // A withdrawn request owes a new one, on both.
    devices
        .phone
        .observe_device_group_event(&withdrawn(&group, &sent[&request].0));
    devices
        .laptop
        .observe_device_group_event(&withdrawn(&group, &read[&request].0));
    for storage in [phone_storage(), laptop_storage()] {
        assert!(
            storage
                .small_state_schedule()
                .unwrap()
                .unwrap()
                .request_owed
        );
    }
}

/// An update that reaches no relay leaves its items owed, and the next pass
/// sends them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_update_that_reached_no_one_is_sent_again() {
    let mut devices = phone_and_laptop().await;
    let (_bob_dir, chat) =
        chat_with_bob(&devices.phone_app, &mut devices.phone, &devices.relay).await;
    let chat_hex = hex::encode(chat.as_slice());
    link(&mut devices).await;
    let phone_app = devices.phone_app.clone();
    let storage = || phone_app.account_storage("alice").unwrap().app_storage();
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(storage().unsent_small_state_items().unwrap().is_empty());

    phone_app.set_chat_pinned("alice", &chat_hex, true).unwrap();
    devices.relay.reject_next_publish();
    devices.phone.run_due_maintenance().await.unwrap();
    let owed = storage().unsent_small_state_items().unwrap();
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].value, SmallStateValue::Pin(true));

    devices.phone.run_due_maintenance().await.unwrap();
    assert!(storage().unsent_small_state_items().unwrap().is_empty());
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let held = devices
        .laptop
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .small_state_items()
        .unwrap();
    assert!(held.contains(&owed[0]));
}
