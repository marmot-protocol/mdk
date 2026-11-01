//! Adding a newly linked device to chats (mdk#2628 3.5c, D70): once a link
//! is made, the device that approved it, and only that device, adds the new
//! device to each of its chats that takes a same-account Add, with one of the
//! new device's private KeyPackages and a sibling Welcome, when the new
//! device's "add to all my chats" is on. A chat that takes no same-account
//! Add is counted and takes no KeyPackage.

use super::*;
use crate::AppCreateGroupOptions;
use crate::client::linked_device_chats::{LINK_CHAT_ADD_SECS, LINK_CHAT_ADDS_PER_PASS};

/// `count` chats `device` makes on its own.
async fn chats(device: &mut Device, count: usize) -> Vec<GroupId> {
    let mut chats = Vec::with_capacity(count);
    for index in 0..count {
        chats.push(
            device
                .client
                .create_group(&format!("chat {index}"), &[])
                .await
                .unwrap(),
        );
    }
    chats
}

/// `rounds` times, each of `devices` in turn reads what the relay holds and
/// runs a maintenance pass.
async fn passes(relay: &ScriptedPushRelayClient, devices: &mut [&mut Device], rounds: usize) {
    for _ in 0..rounds {
        for device in devices.iter_mut() {
            deliver_new(&mut device.client, relay, &mut device.cursor).await;
            device.client.run_due_maintenance().await.unwrap();
        }
    }
}

/// How many leaves `new` holds in `chat`, as `device` reads it.
fn leaves_of(device: &Device, new: &Device, chat: &GroupId, group: &GroupId) -> usize {
    let key = new.client.runtime.own_signature_key();
    device
        .client
        .runtime
        .own_account_leaf_claims(chat, &device.roster(group))
        .unwrap()
        .into_iter()
        .filter(|(leaf_key, _)| *leaf_key == key)
        .count()
}

fn joined(device: &Device, chat: &GroupId) -> bool {
    device.client.state_group_record(chat).is_some()
}

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

/// How many of `issuer`'s private KeyPackages `device` has taken.
fn taken_from(device: &Device, issuer: &Device) -> usize {
    account_database(&device.app)
        .query_row(
            "SELECT COUNT(*) FROM private_key_packages_received
             WHERE issuer_slot_hex = ?1 AND taken_at IS NOT NULL",
            [issuer.slot_hex()],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| usize::try_from(count).unwrap())
        .unwrap()
}

/// How many of `issuer`'s private KeyPackages `device` holds unused.
fn held_from(device: &Device, issuer: &Device) -> usize {
    device
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .received_private_key_packages()
        .unwrap()
        .into_iter()
        .filter(|record| record.issuer_slot_hex == issuer.slot_hex())
        .count()
}

/// The phone links the laptop, and the laptop joins each of the chats the
/// phone was in, each from a sibling Welcome the phone sent with one of the
/// laptop's private KeyPackages. A restart partway changes nothing, and
/// later passes add nothing more: the laptop holds one leaf in each chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_approving_device_adds_a_new_device_to_its_chats() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let chats = chats(&mut phone, 3).await;
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;

    // The phone asks the laptop for KeyPackages, takes them, and adds the
    // laptop to each chat.
    passes(&relay, &mut [&mut phone, &mut laptop], 2).await;
    passes(&relay, &mut [&mut phone], 1).await;
    assert_eq!(taken_from(&phone, &laptop), chats.len());
    let mut phone = reopen(phone).await;
    let mut laptop = reopen(laptop).await;
    passes(&relay, &mut [&mut laptop, &mut phone], 3).await;

    for chat in &chats {
        assert!(joined(&laptop, chat));
        assert_eq!(leaves_of(&phone, &laptop, chat, &group), 1);
    }
    assert_eq!(taken_from(&phone, &laptop), chats.len());
    assert_eq!(phone.client.chats_closed_to_linked_devices().unwrap(), 0);
}

/// Only the device that approved a link adds the new device to chats. The
/// laptop, linked earlier and in the phone's chats, holds the tablet's
/// KeyPackages but adds it to none; the phone, which approved the tablet,
/// adds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_device_that_approved_a_link_adds_the_new_device() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let chats = chats(&mut phone, 2).await;
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    passes(&relay, &mut [&mut phone, &mut laptop], 4).await;
    assert!(chats.iter().all(|chat| joined(&laptop, chat)));

    link(&relay, &mut phone, &mut tablet, "Tablet").await;
    passes(&relay, &mut [&mut laptop, &mut tablet], 4).await;
    assert!(held_from(&laptop, &tablet) > 0);
    assert_eq!(taken_from(&laptop, &tablet), 0);
    assert!(!chats.iter().any(|chat| joined(&tablet, chat)));

    passes(&relay, &mut [&mut phone, &mut tablet, &mut laptop], 3).await;
    for chat in &chats {
        assert!(joined(&tablet, chat));
        assert_eq!(leaves_of(&phone, &tablet, chat, &group), 1);
    }
}

/// With "add to all my chats" off, the new device is added to no chat,
/// though the phone holds its KeyPackages.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_device_without_add_to_all_my_chats_is_added_to_none() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let chats = chats(&mut phone, 2).await;
    let choices = DeviceLinkChoices {
        add_to_all_chats: false,
        ..DeviceLinkChoices::new("Laptop")
    };
    link_with(&relay, &mut phone, &mut laptop, choices).await;
    passes(&relay, &mut [&mut phone, &mut laptop], 4).await;

    assert!(held_from(&phone, &laptop) > 0);
    assert_eq!(taken_from(&phone, &laptop), 0);
    assert!(!chats.iter().any(|chat| joined(&laptop, chat)));
}

/// A chat whose relays a sibling Welcome cannot carry takes no same-account
/// Add: the phone counts it, never takes a KeyPackage for it, and adds the
/// laptop to its other chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chat_closed_to_linked_devices_is_counted_and_takes_no_key_package() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let open = phone.client.create_group("open", &[]).await.unwrap();
    // One relay named twice, spelled two ways.
    let closed = phone
        .client
        .create_group_with_options(
            "closed",
            &[],
            AppCreateGroupOptions {
                relays: Some(vec![
                    "wss://relay.example".into(),
                    "wss://relay.example/".into(),
                ]),
                ..AppCreateGroupOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(phone.client.chats_closed_to_linked_devices().unwrap(), 0);
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    assert_eq!(phone.client.chats_closed_to_linked_devices().unwrap(), 1);
    passes(&relay, &mut [&mut phone, &mut laptop], 5).await;

    assert!(joined(&laptop, &open));
    assert!(!joined(&laptop, &closed));
    assert_eq!(leaves_of(&phone, &laptop, &closed, &group), 0);
    assert_eq!(taken_from(&phone, &laptop), 1);
    assert_eq!(phone.client.chats_closed_to_linked_devices().unwrap(), 1);
}

/// A chat the laptop was invited to before its link already holds it: the
/// phone adds it there again to no chat, only to the chat it made alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chat_that_already_holds_the_new_device_gets_no_add() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let alice_id = phone
        .app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let bob_dir = tempfile::tempdir().unwrap();
    AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap();
    let bob_app = MarmotApp::with_relay_and_config(
        bob_dir.path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0)
            .with_dev_device_groups(true),
    )
    .with_test_relay_client(relay.clone());
    remember_test_member_inbox(&bob_app, &alice_id, "wss://relay.example");
    let mut bob = bob_app.client("bob").await.unwrap();
    let invited = bob.create_group("invited", &[&alice_id]).await.unwrap();
    passes(&relay, &mut [&mut phone, &mut laptop], 1).await;
    for device in [&mut phone, &mut laptop] {
        device.client.accept_group_invite(&invited).unwrap();
    }
    let alone = phone.client.create_group("alone", &[]).await.unwrap();
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    assert_eq!(leaves_of(&phone, &laptop, &invited, &group), 1);
    passes(&relay, &mut [&mut phone, &mut laptop], 4).await;

    assert!(joined(&laptop, &alone));
    assert_eq!(leaves_of(&phone, &laptop, &invited, &group), 1);
    assert_eq!(taken_from(&phone, &laptop), 1);
}

/// The phone adds the new device to its chats for a week after the link is
/// made; gap filling covers a link older than that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_made_over_a_week_ago_adds_the_new_device_to_no_chat() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let chats = chats(&mut phone, 1).await;
    link(&relay, &mut phone, &mut laptop, "Laptop").await;
    let week = i64::try_from(LINK_CHAT_ADD_SECS).unwrap();
    account_database(&phone.app)
        .execute(
            "UPDATE device_links SET decided_at = decided_at - ?1",
            [week],
        )
        .unwrap();
    passes(&relay, &mut [&mut phone, &mut laptop], 4).await;

    assert!(held_from(&phone, &laptop) > 0);
    assert_eq!(taken_from(&phone, &laptop), 0);
    assert!(!joined(&laptop, &chats[0]));
}

/// A chat with a commit of the phone's own still staged takes no Add and no
/// KeyPackage: an Add there could not go through, and one queued behind the
/// commit could not yet show in the chat, so a later pass would add the
/// laptop again. Once that commit is gone, the next pass adds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chat_busy_with_the_approving_devices_commit_waits_for_it() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let chat = phone.client.create_group("busy", &[]).await.unwrap();
    link(&relay, &mut phone, &mut laptop, "Laptop").await;
    let marmot_session::PreparedSessionSend::Commit(staged) = phone
        .client
        .runtime
        .confirm_commit_without_publish_with_audit_context(
            SendIntent::SelfUpdate {
                group_id: chat.clone(),
            },
            marmot_forensics::AuditEventContext::default(),
        )
        .await
        .unwrap()
    else {
        panic!("a stable chat stages the commit");
    };
    passes(&relay, &mut [&mut phone, &mut laptop], 4).await;
    assert!(held_from(&phone, &laptop) > 0);
    assert_eq!(taken_from(&phone, &laptop), 0);

    let effects = phone
        .client
        .runtime
        .rollback_prepared_session_commit(staged)
        .await
        .unwrap();
    phone
        .client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    passes(&relay, &mut [&mut phone, &mut laptop], 2).await;
    assert!(joined(&laptop, &chat));
    assert_eq!(taken_from(&phone, &laptop), 1);
}

/// One pass adds the new device to at most `LINK_CHAT_ADDS_PER_PASS` chats,
/// in the order the chat list shows them, and the next pass to the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_adds_the_new_device_to_at_most_its_cap_of_chats() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let chats = chats(&mut phone, LINK_CHAT_ADDS_PER_PASS + 1).await;
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    // The phone asks for a KeyPackage per chat; the laptop answers.
    passes(&relay, &mut [&mut phone, &mut laptop], 1).await;
    deliver_new(&mut phone.client, &relay, &mut phone.cursor).await;
    assert!(held_from(&phone, &laptop) > LINK_CHAT_ADDS_PER_PASS);

    let listed: Vec<GroupId> = phone
        .app
        .chat_list("alice", true)
        .unwrap()
        .into_iter()
        .map(|row| GroupId::new(hex::decode(row.group_id_hex).unwrap()))
        .collect();
    assert_eq!(listed.len(), chats.len());
    phone.client.run_due_maintenance().await.unwrap();
    let added: Vec<bool> = listed
        .iter()
        .map(|chat| leaves_of(&phone, &laptop, chat, &group) == 1)
        .collect();
    let mut first = vec![true; LINK_CHAT_ADDS_PER_PASS];
    first.push(false);
    assert_eq!(added, first, "the chat the list shows last waits");

    phone.client.run_due_maintenance().await.unwrap();
    assert!(
        chats
            .iter()
            .all(|chat| leaves_of(&phone, &laptop, chat, &group) == 1)
    );
}
