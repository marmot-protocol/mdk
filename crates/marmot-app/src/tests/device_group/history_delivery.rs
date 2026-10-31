//! Sealed history deliveries (mdk#2628 4.2b, D76): a chat's history sent
//! through the device group to one sibling, by the device whose own Commit
//! added it. The sender owes the history before it sends anything, and keeps
//! owing it until every delivery reached a relay; a delivery withdrawn, or
//! whose publish fails for good, makes it owed again. The receiver imports a delivery it can open once it holds
//! the chat, and parks it until then.

use super::*;
use crate::history_delivery::{KIND_HISTORY_DELIVERY, MAX_INLINE_BUNDLES};
use crate::messages::AppMessageIntent;
use cgka_traits::storage::SiblingAddStorage as _;
use storage_sqlite::SqliteAppStorage;

fn storage(app: &MarmotApp) -> SqliteAppStorage {
    app.account_storage("alice").unwrap().app_storage()
}

fn published_count(relay: &ScriptedPushRelayClient) -> usize {
    relay.published_events.lock().unwrap().len()
}

async fn send_text(client: &mut AppClient, chat: &GroupId, content: &str) -> String {
    client
        .send_app_event(
            chat,
            AppMessageIntent::Chat {
                content: content.to_owned(),
            },
        )
        .await
        .unwrap()
        .0
        .id
}

/// The phone edits the laptop's roster entry and the laptop takes the
/// commit.
async fn edit_laptop_entry(
    devices: &mut Devices,
    group: &GroupId,
    edit: impl FnOnce(&mut DeviceEntryV1),
) {
    let laptop_slot = slot_of(&devices.laptop);
    let mut cursor = published_count(&devices.relay);
    let edited = devices
        .phone
        .runtime
        .edit_device_roster_entry(group, &laptop_slot, &[], edit)
        .await
        .unwrap();
    assert!(matches!(edited, DeviceRosterEdit::Committed(_)));
    deliver_new(&mut devices.laptop, &devices.relay, &mut cursor).await;
    devices.laptop.sync().await.unwrap();
}

/// The phone adds the laptop's tagged KeyPackage to `chat`; the laptop joins.
async fn add_laptop(devices: &mut Devices, chat: &GroupId) {
    let mut cursor = published_count(&devices.relay);
    let key_package = published_key_package(&mut devices.laptop, &devices.relay).await;
    let effects = devices
        .phone
        .runtime
        .send(SendIntent::Invite {
            group_id: chat.clone(),
            key_packages: vec![key_package],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    devices
        .phone
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    deliver_new(&mut devices.laptop, &devices.relay, &mut cursor).await;
    devices.laptop.sync().await.unwrap();
    devices.laptop.accept_group_invite(chat).unwrap();
}

/// Tagging devices whose laptop asks for history, and a chat the phone has
/// one message in.
async fn history_devices() -> (Devices, GroupId, GroupId, String) {
    let (mut devices, group) = tagging_devices().await;
    assert!(
        roster(&devices.phone, &group).devices[&slot_of(&devices.laptop)]
            .history_key
            .is_some(),
        "the laptop's history key rides on its tag-key commit"
    );
    edit_laptop_entry(&mut devices, &group, |entry| {
        entry.settings.bring_history = true;
    })
    .await;
    let chat = devices.phone.create_group("team", &[]).await.unwrap();
    let first = send_text(&mut devices.phone, &chat, "before the laptop").await;
    (devices, group, chat, first)
}

/// The phone's confirmed Commit that adds the laptop to a chat owes the
/// laptop that chat's history, once its entry asks for history. One delivery
/// carries it; the laptop imports it, marked with the phone's slot, even
/// though it holds a later device-group epoch than the delivery's. An add
/// while the entry asks for none sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_device_that_adds_a_sibling_to_a_chat_sends_it_the_history() {
    let (mut devices, group) = tagging_devices().await;
    let phone_storage = storage(&devices.phone_app);
    let quiet = devices.phone.create_group("quiet", &[]).await.unwrap();
    send_text(&mut devices.phone, &quiet, "never sent").await;
    add_laptop(&mut devices, &quiet).await;
    let adds = devices
        .phone_app
        .account_storage("alice")
        .unwrap()
        .sibling_adds()
        .unwrap();
    assert_eq!(adds.len(), 1, "the add commit records the laptop");
    assert_eq!(adds[0].slot, slot_of(&devices.laptop));
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(
        published_count(&devices.relay),
        before,
        "the laptop's entry asks for no history"
    );
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );

    edit_laptop_entry(&mut devices, &group, |entry| {
        entry.settings.bring_history = true;
    })
    .await;
    let chat = devices.phone.create_group("team", &[]).await.unwrap();
    let chat_hex = hex::encode(chat.as_slice());
    let first = send_text(&mut devices.phone, &chat, "before the laptop").await;
    add_laptop(&mut devices, &chat).await;
    let laptop_storage = storage(&devices.laptop_app);
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_none()
    );
    // The laptop's second KeyPackage moved the device group on, and the phone
    // sends before it takes that commit: the laptop reads who sent the
    // delivery at the delivery's epoch, not its own later one.
    assert!(
        devices.laptop.runtime.group_record(&group).unwrap().epoch
            > devices.phone.runtime.group_record(&group).unwrap().epoch
    );
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before + 1, "one delivery");
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
    assert!(
        devices
            .phone_app
            .account_storage("alice")
            .unwrap()
            .sibling_adds()
            .unwrap()
            .is_empty()
    );
    devices.laptop.take_pending_projection_updates();
    deliver_all(&mut devices.laptop, &devices.relay).await;

    let imported = laptop_storage
        .timeline_message(&chat_hex, &first)
        .unwrap()
        .expect("imported");
    assert_eq!(imported.plaintext, "before the laptop");
    assert_eq!(
        laptop_storage
            .app_event_import_source(&chat_hex, &first)
            .unwrap(),
        Some(slot_of(&devices.phone))
    );
    assert!(
        devices
            .laptop
            .take_pending_projection_updates()
            .iter()
            .any(|update| update.group_id_hex == chat_hex)
    );
    assert!(
        laptop_storage
            .device_group_messages()
            .unwrap()
            .iter()
            .any(|(.., kind)| *kind == KIND_HISTORY_DELIVERY),
        "the reader records the delivery, so its withdrawal owes no small state"
    );
    assert!(
        devices
            .laptop_app
            .account_storage("alice")
            .unwrap()
            .sibling_adds()
            .unwrap()
            .is_empty(),
        "only the adder owes the history"
    );
}

/// A delivery the laptop reads before it holds the chat waits for it, and the
/// laptop's next maintenance pass after joining imports it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_read_before_the_chat_waits_until_the_sibling_joins() {
    let (mut devices, _group, chat, first) = history_devices().await;
    let chat_hex = hex::encode(chat.as_slice());
    // The delivery overtakes the Welcome.
    devices
        .phone
        .dev_record_sibling_add(&chat, &slot_of(&devices.laptop))
        .unwrap();
    devices.phone.drive_history_deliveries().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let laptop_storage = storage(&devices.laptop_app);
    assert_eq!(
        laptop_storage.parked_history_delivery_chats().unwrap(),
        std::slice::from_ref(&chat_hex)
    );

    add_laptop(&mut devices, &chat).await;
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_none()
    );
    devices.laptop.drive_history_deliveries().await;
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_some()
    );
    assert!(
        laptop_storage
            .parked_history_delivery_chats()
            .unwrap()
            .is_empty()
    );
}

/// A delivery sealed to a key other than the laptop's is refused: nothing is
/// imported or parked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_the_receiver_cannot_open_is_refused() {
    let (mut devices, group, chat, first) = history_devices().await;
    let chat_hex = hex::encode(chat.as_slice());
    add_laptop(&mut devices, &chat).await;
    let phone_key = devices.phone.runtime.history_public_key().unwrap();
    edit_laptop_entry(&mut devices, &group, |entry| {
        entry.history_key = Some(phone_key);
    })
    .await;
    devices.phone.drive_history_deliveries().await;
    assert!(
        storage(&devices.phone_app)
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let laptop_storage = storage(&devices.laptop_app);
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_none()
    );
    assert!(
        laptop_storage
            .parked_history_delivery_chats()
            .unwrap()
            .is_empty()
    );
}

/// A history whose delivery reached no relay stays owed and goes at the
/// next pass. Withdrawing a sent delivery, or a later drain reporting that
/// its publish failed for good, makes it owed again; the receiver imports
/// the copies without adding a row twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_history_stays_owed_until_it_reaches_a_relay_and_again_once_withdrawn_or_failed() {
    let (mut devices, group, chat, first) = history_devices().await;
    let chat_hex = hex::encode(chat.as_slice());
    add_laptop(&mut devices, &chat).await;
    let phone_storage = storage(&devices.phone_app);

    devices.relay.reject_next_publish();
    devices.phone.drive_history_deliveries().await;
    assert_eq!(phone_storage.unsent_history_deliveries().unwrap().len(), 1);
    devices.phone.drive_history_deliveries().await;
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );

    let (_, _, message_id, _) = phone_storage
        .device_group_messages()
        .unwrap()
        .into_iter()
        .rfind(|(.., kind)| *kind == KIND_HISTORY_DELIVERY)
        .expect("the delivery is recorded");
    let message_id = MessageId::new(hex::decode(message_id.unwrap()).unwrap());
    devices
        .phone
        .observe_device_group_event(&GroupEvent::AppMessageInvalidated {
            group_id: group.clone(),
            message_id,
            epoch: cgka_traits::EpochId(0),
            reason: cgka_traits::engine::AppMessageInvalidationReason::LosingBranch,
            decrypted_payload_ref: None,
        })
        .unwrap();
    assert_eq!(phone_storage.unsent_history_deliveries().unwrap().len(), 1);
    devices.phone.drive_history_deliveries().await;
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );

    let (_, app_event_id, message_id, _) = phone_storage
        .device_group_messages()
        .unwrap()
        .into_iter()
        .rfind(|(.., kind)| *kind == KIND_HISTORY_DELIVERY)
        .expect("the second delivery is recorded");
    let failed = marmot_session::AccountDeviceEffects {
        failed_app_messages: vec![marmot_session::FailedApplicationMessage {
            group_id: group.clone(),
            app_event_id,
            message_id: MessageId::new(hex::decode(message_id.unwrap()).unwrap()),
            reason: "every relay refused it".to_owned(),
        }],
        ..Default::default()
    };
    let _ = devices.phone.observe_drained_session_events(&failed).await;
    assert_eq!(phone_storage.unsent_history_deliveries().unwrap().len(), 1);
    devices.phone.drive_history_deliveries().await;
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );

    deliver_all(&mut devices.laptop, &devices.relay).await;
    let laptop_storage = storage(&devices.laptop_app);
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        laptop_storage
            .history_export_page(&chat_hex, None, crate::unix_now_seconds(), 64)
            .unwrap()
            .iter()
            .filter(|row| row.message_id_hex == first)
            .count(),
        1,
        "imported once"
    );
}

/// A history that fills the inline bundles a link may send goes out, one
/// delivery per bundle. One that needs more is forgotten without sending any
/// of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_history_too_long_to_send_inline_is_forgotten() {
    let (mut devices, _group, chat, _first) = history_devices().await;
    let phone_storage = storage(&devices.phone_app);
    // Two of these overflow one inline bundle, so each takes its own; the
    // first shares its bundle with the short message before it. Each differs,
    // so none shares another's id.
    let long = "x".repeat(15_000);
    for index in 0..MAX_INLINE_BUNDLES {
        send_text(&mut devices.phone, &chat, &format!("{index}{long}")).await;
    }
    add_laptop(&mut devices, &chat).await;
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before + MAX_INLINE_BUNDLES);
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );

    let longer = devices.phone.create_group("longer", &[]).await.unwrap();
    for index in 0..=MAX_INLINE_BUNDLES {
        send_text(&mut devices.phone, &longer, &format!("{index}{long}")).await;
    }
    add_laptop(&mut devices, &longer).await;
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before);
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
}

/// An add this device recorded a week ago, before it stopped for longer than
/// that, is forgotten without owing or sending anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_add_a_week_old_is_forgotten_unsent() {
    let (mut devices, _group, chat, _first) = history_devices().await;
    let account = devices.phone_app.account_storage("alice").unwrap();
    let week_old = crate::unix_now_seconds() - storage_sqlite::HISTORY_DELIVERY_RETENTION_SECS - 1;
    account
        .record_sibling_adds(&chat, &[slot_of(&devices.laptop)], week_old)
        .unwrap();
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before);
    assert!(account.sibling_adds().unwrap().is_empty());
    assert!(
        storage(&devices.phone_app)
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
}

/// An add recorded for the device group itself, which the engine skips, owes
/// nothing: the device group is no chat whose history goes anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_add_to_the_device_group_owes_no_history() {
    let (mut devices, group, _chat, _first) = history_devices().await;
    devices
        .phone
        .dev_record_sibling_add(&group, &slot_of(&devices.laptop))
        .unwrap();
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before);
    assert!(
        storage(&devices.phone_app)
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
}
