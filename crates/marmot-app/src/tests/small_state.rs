//! Small state between an account's devices (mdk#2628 item 4.3). A pass on
//! one device records what its user changed there and applies the values
//! its siblings sent, once that device trusts its account's device group.

use super::canonical_membership::{app_at, deliver_new, published_key_package};
use super::device_group::{Devices, deliver_all, phone_and_laptop};
use super::*;
use crate::client::boxed;
use crate::small_state::{
    BROADCAST_REQUEST, KIND_SMALL_STATE_BROADCAST_REQUEST, KIND_SMALL_STATE_UPDATE,
};
use cgka_traits::storage::GroupStorage as _;
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
        .unwrap()
        .operation
        .expect("eligible fixture members");
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

/// A pass saves its siblings' archives together. If that save fails, every
/// flag goes back, hosts hear of none, and the next pass applies them all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn siblings_archives_are_saved_together_or_not_at_all() {
    let mut devices = phone_and_laptop().await;
    let (_bob_dir, chat) =
        chat_with_bob(&devices.phone_app, &mut devices.phone, &devices.relay).await;
    let notes = devices
        .phone
        .create_group("Notes", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    link(&mut devices).await;
    let app = devices.phone_app.clone();
    let path = app.account_storage_path("alice");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let key = app
        .sqlcipher_key("alice", &keys, &path, crate::SqlcipherDatabaseKind::Session)
        .unwrap();
    storage_sqlite::expect_uncounted_writes_for_test(&path);
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    let phone = &mut devices.phone;
    phone.sync_small_state(&[]).unwrap();
    phone.take_pending_projection_updates();

    // The save fails on the second chat it archives.
    connection
        .execute_batch(&format!(
            "CREATE TRIGGER fail_archive BEFORE UPDATE OF archived ON account_groups
             WHEN NEW.archived = 1 AND NEW.group_id_hex = '{}'
             BEGIN SELECT RAISE(FAIL, 'injected archive save failure'); END;",
            hex::encode(notes.as_slice())
        ))
        .unwrap();
    let archives = [&chat, &notes].map(|group| {
        sibling_value(
            &hex::encode(group.as_slice()),
            SmallStateValue::Archive(true),
        )
    });
    phone.sync_small_state(&archives).unwrap();
    for group in [&chat, &notes] {
        assert!(!phone.state_group_record(group).unwrap().archived);
    }
    assert!(triggers(phone).is_empty());

    connection
        .execute_batch("DROP TRIGGER fail_archive")
        .unwrap();
    phone.sync_small_state(&[]).unwrap();
    for group in [&chat, &notes] {
        assert!(phone.state_group_record(group).unwrap().archived);
    }
    let announced: BTreeMap<_, _> = triggers(phone).into_iter().collect();
    let expected: BTreeMap<_, _> = [&chat, &notes]
        .map(|group| {
            (
                hex::encode(group.as_slice()),
                ChatListUpdateTrigger::ArchiveChanged,
            )
        })
        .into();
    assert_eq!(announced, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pin_for_an_archived_chat_is_applied_once_it_is_unarchived() {
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

    // Archived here again, a sibling's newer pin waits; once this device's
    // user unarchives the chat, the next maintenance pass applies it.
    phone.set_group_archived(&chat, true).unwrap();
    phone.sync_small_state(&[]).unwrap();
    let pin = SmallStateItem {
        version: Some(SmallStateVersion {
            version: 3,
            change_id: [7; 16],
        }),
        ..sibling_value(&chat_hex, SmallStateValue::Pin(true))
    };
    phone.sync_small_state(std::slice::from_ref(&pin)).unwrap();
    phone.take_pending_projection_updates();
    phone.set_group_archived(&chat, false).unwrap();
    phone.take_pending_projection_updates();
    phone.drive_small_state().await;
    let row = phone
        .take_pending_projection_updates()
        .into_iter()
        .rev()
        .find_map(|update| update.chat_list_row)
        .unwrap();
    assert!(!row.archived && row.pinned);
    assert!(storage.small_state_items().unwrap().contains(&pin));
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
    let (group, roster) = phone.trusted_device_roster().unwrap().unwrap();
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
        Some(SmallStateBroadcast {
            at: now,
            tip,
            devices: crate::small_state::broadcast_devices(&roster),
        })
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

    // A decision read from an update sent before the last broadcast began
    // is owed again: a device that broadcast was made for may have joined
    // since, and that broadcast did not carry it (mdk#3556). One sent at the
    // broadcast's tip or later reached every device it was made for.
    let tip = schedule().last_broadcast.unwrap().tip;
    let decision = |chat: &str| storage_sqlite::InvitationDecision {
        group_id_hex: chat.repeat(16),
        generation: [7; 32],
        version: 1,
        declined: false,
    };
    let update = |decision| {
        crate::small_state::encode_invitation_decision_updates(&[decision])
            .remove(0)
            .0
    };
    phone
        .receive_small_state_update(&group, tip, &update(decision("0b")))
        .unwrap();
    phone
        .receive_small_state_update(&group, tip - 1, &update(decision("0c")))
        .unwrap();
    assert_eq!(
        storage().unsent_invitation_decisions().unwrap(),
        vec![decision("0c")]
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
            KIND_SMALL_STATE_UPDATE,
            KIND_SMALL_STATE_BROADCAST_REQUEST
        ]
    );

    deliver_all(&mut devices.laptop, &devices.relay).await;
    let admission = phone_app
        .account_storage("alice")
        .unwrap()
        .invitation_admission(&chat)
        .unwrap()
        .unwrap();
    let decision = phone_storage()
        .invitation_decision(&chat_hex, &admission.generation)
        .unwrap()
        .unwrap();
    assert_eq!(decision.version, 1);
    assert!(!decision.declined);
    assert_eq!(
        laptop_storage()
            .invitation_decision(&chat_hex, &admission.generation)
            .unwrap(),
        Some(decision.clone())
    );
    assert!(
        devices.laptop.state_group_record(&chat).is_none(),
        "a decision before its Welcome must not create membership"
    );
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

    // The laptop starts too, once its leaf is tagged: siblings read small
    // state only from a tagged leaf (mdk#3680). Its first pass tags it only
    // after small state ran, so that pass holds what it owes and the phone
    // reads nothing; the next broadcasts what it holds and asks.
    assert!(
        !devices
            .laptop
            .device_group_exchange()
            .unwrap()
            .unwrap()
            .tagged
    );
    devices.laptop.run_due_maintenance().await.unwrap();
    assert!(
        devices
            .laptop
            .device_group_exchange()
            .unwrap()
            .unwrap()
            .tagged
    );
    assert_eq!(
        laptop_storage().unsent_small_state_items().unwrap().len(),
        401
    );
    assert!(
        laptop_storage()
            .small_state_schedule()
            .unwrap()
            .unwrap()
            .request_owed
    );
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert!(!answer_owed(&phone_app));
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
    // and on the one that merged it, each naming it by its own id.
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
        .observe_device_group_event(&withdrawn(&group, &sent[&update].0))
        .unwrap();
    devices
        .laptop
        .observe_device_group_event(&withdrawn(&group, &read[&update].0))
        .unwrap();
    assert_eq!(
        phone_storage().unsent_small_state_items().unwrap().len(),
        401
    );
    assert_eq!(
        laptop_storage().unsent_small_state_items().unwrap().len(),
        401
    );

    assert_eq!(
        phone_storage()
            .unsent_invitation_decisions()
            .unwrap()
            .as_slice(),
        std::slice::from_ref(&decision)
    );
    assert_eq!(
        laptop_storage().unsent_invitation_decisions().unwrap(),
        std::slice::from_ref(&decision)
    );
    // The answer it carried goes out again on the worker's next turn, as the
    // answer first did, not at the next maintenance pass (mdk#3566). While
    // the device group's epoch is still settling, as when the fork that
    // withdrew it resolves, the engine refuses that send; it goes out on
    // the turn after the epoch settles (mdk#3573).
    devices.relay.fail_publishes_as_possibly_exposed();
    devices
        .phone
        .runtime
        .send(cgka_traits::engine::SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    assert!(matches!(
        devices.phone.runtime.epoch_state(&group),
        Some(cgka_traits::EpochState::PendingPublish(_))
    ));
    assert!(devices.phone.drive_changed_invitation_decisions().await);
    assert_eq!(
        phone_storage().unsent_invitation_decisions().unwrap(),
        std::slice::from_ref(&decision),
        "refused while the epoch settles"
    );
    devices.relay.allow_publishes();
    assert!(devices.phone.note_connectivity_restored().unwrap() > 0);
    devices
        .phone
        .advance_convergence_after_runtime_sync(&group)
        .await
        .unwrap();
    assert!(
        devices.phone.drive_changed_invitation_decisions().await,
        "the turn after the epoch settles sends it"
    );
    assert!(
        phone_storage()
            .unsent_invitation_decisions()
            .unwrap()
            .is_empty()
    );

    // A withdrawn request owes a new one, on both.
    devices
        .phone
        .observe_device_group_event(&withdrawn(&group, &sent[&request].0))
        .unwrap();
    devices
        .laptop
        .observe_device_group_event(&withdrawn(&group, &read[&request].0))
        .unwrap();
    for storage in [phone_storage(), laptop_storage()] {
        assert!(
            storage
                .small_state_schedule()
                .unwrap()
                .unwrap()
                .request_owed
        );
    }

    // Records go after a week. A withdrawal whose record is gone owes both,
    // as does one of a message never recorded.
    let phone = phone_storage();
    let settle = || {
        phone
            .mark_small_state_sent(&phone.unsent_small_state_items().unwrap())
            .unwrap();
        phone
            .mark_invitation_decisions_sent(&phone.unsent_invitation_decisions().unwrap())
            .unwrap();
        phone.small_state_broadcast_request_sent().unwrap();
    };
    settle();
    phone
        .record_device_group_message(
            &hex::encode(group.as_slice()),
            "a week on",
            Some(&"ee".repeat(32)),
            KIND_SMALL_STATE_BROADCAST_REQUEST,
            crate::unix_now_seconds() + 8 * 24 * 60 * 60,
        )
        .unwrap();
    assert!(!recorded(&devices.phone, &group).contains_key(&request));
    devices
        .phone
        .observe_device_group_event(&withdrawn(&group, &sent[&request].0))
        .unwrap();
    assert_eq!(phone.unsent_small_state_items().unwrap().len(), 401);
    assert!(phone.small_state_schedule().unwrap().unwrap().request_owed);
    settle();
    devices
        .phone
        .observe_device_group_event(&withdrawn(&group, &MessageId::new(vec![0x77; 32])))
        .unwrap();
    assert_eq!(phone.unsent_small_state_items().unwrap().len(), 401);
    assert!(phone.small_state_schedule().unwrap().unwrap().request_owed);

    // A withdrawn commit owes every item again, and its answer goes out on
    // the next turn: an update sent on the commit's branch is parked with
    // that branch, never withdrawn on its own (mdk#3594).
    settle();
    devices
        .phone
        .observe_device_group_event(&cgka_traits::engine::GroupEvent::GroupStateInvalidated {
            group_id: group.clone(),
            epoch: cgka_traits::EpochId(0),
            invalidated_commit_id: MessageId::new(vec![0x66; 32]),
            reason: cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection,
        })
        .unwrap();
    assert_eq!(phone.unsent_small_state_items().unwrap().len(), 401);
    assert_eq!(phone.unsent_invitation_decisions().unwrap().len(), 1);
    assert!(devices.phone.drive_changed_invitation_decisions().await);
    assert!(phone.unsent_invitation_decisions().unwrap().is_empty());
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

/// Both devices tagged, a chat the phone started with Bob, and no broadcast
/// answer owed on the phone, so what the phone reads next is the laptop's.
async fn tagged_pair_with_chat() -> (Devices, GroupId, tempfile::TempDir, GroupId) {
    let (mut devices, group) = boxed(super::device_group::tagging_devices).await;
    let (bob_dir, chat) =
        boxed(|| chat_with_bob(&devices.phone_app, &mut devices.phone, &devices.relay)).await;
    boxed(|| devices.phone.drive_small_state()).await;
    assert!(!answer_owed(&devices.phone_app));
    (devices, group, bob_dir, chat)
}

fn answer_owed(app: &MarmotApp) -> bool {
    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .small_state_schedule()
        .unwrap()
        .unwrap()
        .answer_owed
}

fn muted(app: &MarmotApp, chat: &GroupId) -> bool {
    app.chat_notification_settings("alice", &hex::encode(chat.as_slice()))
        .unwrap()
        .muted
}

/// Send each of `messages` from `client` in `group`.
async fn send_all(client: &mut AppClient, group: &GroupId, messages: Vec<(u64, String)>) {
    for (kind, content) in messages {
        assert!(
            client
                .send_device_group_message(group, kind, content)
                .await
                .unwrap()
        );
    }
}

/// A sibling's update muting `chat`, and a broadcast request.
fn mute_and_request(chat: &GroupId) -> Vec<(u64, String)> {
    let mute = sibling_value(
        &hex::encode(chat.as_slice()),
        SmallStateValue::Mute(MuteSetting::Muted),
    );
    vec![
        (
            KIND_SMALL_STATE_UPDATE,
            crate::small_state::encode_small_state_update(&[mute])
                .remove(0)
                .0,
        ),
        (
            KIND_SMALL_STATE_BROADCAST_REQUEST,
            BROADCAST_REQUEST.to_owned(),
        ),
    ]
}

/// A removed device keeps its last epoch's keys for the app-message window,
/// so it can still send small state from that epoch. The phone refuses all of
/// it, as the sending leaf's tag reads as a removed slot (mdk#3680): a mute,
/// a decline at the highest version, which no later decision could beat, and
/// a broadcast request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_devices_small_state_is_refused() {
    let (devices, group, _bob_dir, chat) = boxed(tagged_pair_with_chat).await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        laptop_app,
        mut phone,
        mut laptop,
        ..
    } = devices;
    let chat_hex = hex::encode(chat.as_slice());
    let generation = phone_app
        .account_storage("alice")
        .unwrap()
        .invitation_admission(&chat)
        .unwrap()
        .unwrap()
        .generation;
    let decision = || {
        phone_app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .invitation_decision(&chat_hex, &generation)
            .unwrap()
            .unwrap()
    };
    let accepted = decision();
    assert!(!accepted.declined);
    let laptop_epoch = laptop.runtime.group_record(&group).unwrap().epoch;
    let laptop_slot = super::device_group::stable_slot(&laptop_app);
    boxed(|| phone.remove_linked_device(&laptop_slot))
        .await
        .unwrap();
    assert!(phone.runtime.group_record(&group).unwrap().epoch.0 > laptop_epoch.0);

    let mut cursor = relay.published_events.lock().unwrap().len();
    let decline = storage_sqlite::InvitationDecision {
        version: storage_sqlite::MAX_SMALL_STATE_NUMBER,
        declined: true,
        ..accepted.clone()
    };
    let mut messages = mute_and_request(&chat);
    messages.push((
        KIND_SMALL_STATE_UPDATE,
        crate::small_state::encode_invitation_decision_updates(&[decline])
            .remove(0)
            .0,
    ));
    send_all(&mut laptop, &group, messages).await;
    assert_eq!(
        laptop.runtime.group_record(&group).unwrap().epoch,
        laptop_epoch
    );
    deliver_new(&mut phone, &relay, &mut cursor).await;
    phone.sync().await.unwrap();
    boxed(|| phone.run_due_maintenance()).await.unwrap();
    assert_eq!(
        (
            muted(&phone_app, &chat),
            decision(),
            answer_owed(&phone_app)
        ),
        (false, accepted, false)
    );
}

/// An update and a broadcast request a linked sibling sent before the device
/// group moved on are read at their own epoch, from its retained anchor, and
/// applied (mdk#3680).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_linked_siblings_delayed_small_state_is_applied() {
    let (devices, group, _bob_dir, chat) = boxed(tagged_pair_with_chat).await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        mut laptop,
        ..
    } = devices;
    let laptop_epoch = laptop.runtime.group_record(&group).unwrap().epoch;
    let mut cursor = relay.published_events.lock().unwrap().len();
    send_all(&mut laptop, &group, mute_and_request(&chat)).await;
    phone
        .rename_linked_device(&super::device_group::stable_slot(&phone_app), "Phone")
        .await
        .unwrap();
    assert!(phone.runtime.group_record(&group).unwrap().epoch.0 > laptop_epoch.0);
    deliver_new(&mut phone, &relay, &mut cursor).await;
    phone.sync().await.unwrap();
    assert_eq!(
        (muted(&phone_app, &chat), answer_owed(&phone_app)),
        (true, true)
    );
}

/// Small state goes out pinned to the branch the laptop's tag was read on, as
/// a sibling Welcome does, so it never leaves from a leaf that lost its tag
/// (mdk#3680). While the laptop's own device-group commit waits on its
/// publication, the engine refuses it before encrypting anything: the pass
/// queues nothing and its items stay owed. The pass after that commit fails
/// sends them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn small_state_waits_out_this_devices_unsettled_device_group_commit() {
    let (devices, group) = boxed(super::device_group::tagging_devices).await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        laptop_app,
        mut phone,
        mut laptop,
        ..
    } = devices;
    let notes = boxed(|| laptop.create_group("Notes", &[]))
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let notes_hex = hex::encode(notes.as_slice());
    laptop_app
        .set_chat_pinned("alice", &notes_hex, true)
        .unwrap();
    let holds_pin = |app: &MarmotApp, unsent: bool| {
        let storage = app.account_storage("alice").unwrap().app_storage();
        let items = if unsent {
            storage.unsent_small_state_items()
        } else {
            storage.small_state_items()
        };
        items
            .unwrap()
            .iter()
            .any(|item| item.group_id_hex == notes_hex && item.value == SmallStateValue::Pin(true))
    };
    let effects = laptop
        .runtime
        .session_mut()
        .send(cgka_traits::engine::SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    let Some(marmot_session::PublishWork::GroupEvolution { pending, .. }) =
        effects.publish.into_iter().next()
    else {
        panic!("expected a group evolution")
    };

    boxed(|| laptop.drive_small_state()).await;
    assert!(holds_pin(&laptop_app, true));
    assert!(!laptop.runtime.has_queued_outbound_intents(&group).unwrap());
    deliver_all(&mut phone, &relay).await;
    assert!(!holds_pin(&phone_app, false));

    laptop
        .runtime
        .session_mut()
        .publish_failed(pending)
        .await
        .unwrap();
    boxed(|| laptop.drive_small_state()).await;
    assert!(!holds_pin(&laptop_app, true));
    deliver_all(&mut phone, &relay).await;
    assert!(holds_pin(&phone_app, false));
}
