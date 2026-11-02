//! Private sibling chat Adds (mdk#2628 3.5c/3.5e, D70, D82–D84). The
//! approver's initial burst and another holder's claim-based gap filling
//! compose private stock, a real Add, and sibling Welcome delivery. The
//! shared cap, old-chat toggle, current removal state, and chat readiness
//! govern spending; a lower claim holds only its own chat. Engine tests own
//! the authoritative duplicate-presence check at actual Add preparation.

use super::*;
use crate::AppCreateGroupOptions;
use crate::client::linked_device_chats::{LINK_CHAT_ADD_SECS, LINK_CHAT_ADDS_PER_PASS};
use crate::tests::device_group::{commit_removal_decided_elsewhere, converge_device_group};
use cgka_traits::EpochId;

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

/// The phone asks for the laptop's KeyPackages, and holds them, before any
/// add pass of its own runs.
async fn hold_key_packages(
    relay: &ScriptedPushRelayClient,
    phone: &mut Device,
    laptop: &mut Device,
) {
    // Direct clients have no account worker to advance scheduled convergence.
    // Drive that work too, and await the hand-off rather than assuming a fixed
    // number of maintenance passes settles every replay slice (mdk#2861).
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            deliver_new(&mut phone.client, relay, &mut phone.cursor).await;
            phone.client.sibling_key_package_upkeep(&[]).await;
            deliver_new(&mut laptop.client, relay, &mut laptop.cursor).await;
            laptop.client.run_due_maintenance().await.unwrap();
            for client in [&mut phone.client, &mut laptop.client] {
                for group in client.take_pending_convergence_groups() {
                    client
                        .advance_convergence_with_projection_progress_and_yield(
                            &group,
                            None,
                            std::future::pending(),
                        )
                        .await
                        .unwrap();
                }
            }
            deliver_new(&mut phone.client, relay, &mut phone.cursor).await;
            if held_from(phone, laptop) > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the phone receives the laptop's private KeyPackage hand-off");
}

/// A removal of the laptop another device decided reaches the phone, which
/// applies it with no decision of its own recorded, and, after a maintenance
/// pass when `pass_between`, is dropped: the laptop, which has not received
/// that branch yet, renames itself from the epoch before it until its branch is
/// the deeper, and the phone adopts that branch, whose roster lists the
/// laptop again.
async fn drop_a_removal_decided_elsewhere(
    relay: &ScriptedPushRelayClient,
    phone: &mut Device,
    laptop: &mut Device,
    group: &GroupId,
    pass_between: bool,
) {
    let slot: [u8; 32] = hex::decode(laptop.slot_hex()).unwrap().try_into().unwrap();
    commit_removal_decided_elsewhere(&mut phone.client, group, slot).await;
    assert!(phone.roster(group).rejected_slots.contains_key(&slot));
    if pass_between {
        phone.client.run_due_maintenance().await.unwrap();
    }
    let epoch = |device: &Device| device.client.runtime.group_record(group).unwrap().epoch;
    let phone_epoch = epoch(phone);
    let mut renames = 0;
    while epoch(laptop) <= phone_epoch {
        renames += 1;
        let slot_hex = laptop.slot_hex();
        laptop
            .client
            .rename_linked_device(&slot_hex, &format!("Laptop {renames}"))
            .await
            .unwrap();
    }
    converge_device_group(&mut phone.client, relay, &mut phone.cursor, group, 8).await;
    let roster = phone.roster(group);
    assert!(
        !roster.rejected_slots.contains_key(&slot),
        "branch selection dropped the removal"
    );
    assert!(roster.devices.contains_key(&slot));
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

/// The direct post-link burst belongs to the approver. A different sibling
/// can still fill the missing chats through the advisory claim flow while
/// that approver is offline; the returning approver adds no duplicate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_fills_missing_chats_while_the_approver_is_offline() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let chats = chats(&mut phone, 2).await;
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    passes(&relay, &mut [&mut phone, &mut laptop], 4).await;
    assert!(chats.iter().all(|chat| joined(&laptop, chat)));

    link(&relay, &mut phone, &mut tablet, "Tablet").await;
    hold_key_packages(&relay, &mut laptop, &mut tablet).await;
    laptop.client.add_linked_devices_to_chats(&[]).await;
    assert!(held_from(&laptop, &tablet) > 0);
    assert_eq!(taken_from(&laptop, &tablet), 0);
    assert!(!chats.iter().any(|chat| joined(&tablet, chat)));

    tokio::time::timeout(Duration::from_secs(30), async {
        while !chats.iter().all(|chat| joined(&tablet, chat)) {
            passes(&relay, &mut [&mut laptop, &mut tablet], 1).await;
            for client in [&mut laptop.client, &mut tablet.client] {
                for group in client.take_pending_convergence_groups() {
                    client
                        .advance_convergence_with_projection_progress_and_yield(
                            &group,
                            None,
                            std::future::pending(),
                        )
                        .await
                        .unwrap();
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the online sibling fills both missing chats");
    assert_eq!(taken_from(&laptop, &tablet), chats.len());

    passes(&relay, &mut [&mut phone, &mut tablet, &mut laptop], 3).await;
    for chat in &chats {
        assert!(joined(&tablet, chat));
        assert_eq!(leaves_of(&phone, &tablet, chat, &group), 1);
    }
    assert_eq!(taken_from(&phone, &tablet), 0);
}

/// A live claim from a lower slot holds just that chat's Add. Another chat
/// still fills through a real private-package Add and sibling Welcome. A
/// leaving claimant neither sends a new claim nor holds the first chat back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lower_sibling_claim_holds_only_its_chat() {
    let (relay, [first, second, mut target]) = alice_devices::<3>().await;
    let (mut low, mut high) = if first.slot_hex() < second.slot_hex() {
        (first, second)
    } else {
        (second, first)
    };
    let chats = chats(&mut low, 2).await;
    let group = link(&relay, &mut low, &mut high, "Other device").await;
    passes(&relay, &mut [&mut low, &mut high], 4).await;
    assert!(chats.iter().all(|chat| joined(&high, chat)));
    link(&relay, &mut low, &mut target, "New device").await;
    let target_slot: [u8; 32] = hex::decode(target.slot_hex()).unwrap().try_into().unwrap();
    // Observe the completed link without running this holder's maintenance:
    // it has no private stock yet. Gap filling must request it, then a
    // hand-off must wake the waiting chat even with no membership change.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            converge_device_group(&mut high.client, &relay, &mut high.cursor, &group, 1).await;
            if high
                .roster(&group)
                .devices
                .get(&target_slot)
                .is_some_and(|entry| entry.tag_signature_key.is_some())
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the holder observes the target's first tagged Commit");
    assert_eq!(held_from(&high, &target), 0);
    assert!(!chats.iter().any(|chat| joined(&target, chat)));
    let content = format!(
        "{{\"v\":1,\"from\":\"{}\",\"to\":\"{}\",\"chat\":\"{}\"}}",
        low.slot_hex(),
        target.slot_hex(),
        hex::encode(chats[0].as_slice())
    );
    assert!(
        low.client
            .send_device_group_message(&group, 458, content)
            .await
            .unwrap()
    );
    // The target cannot impersonate that lower claimant to hold another
    // chat: authenticating `from` uses the MLS sender's actual device tag.
    let forged = format!(
        "{{\"v\":1,\"from\":\"{}\",\"to\":\"{}\",\"chat\":\"{}\"}}",
        low.slot_hex(),
        target.slot_hex(),
        hex::encode(chats[1].as_slice())
    );
    assert!(
        target
            .client
            .send_device_group_message(&group, 458, forged)
            .await
            .unwrap()
    );
    tokio::time::timeout(Duration::from_secs(30), async {
        while !joined(&target, &chats[1]) {
            passes(&relay, &mut [&mut high, &mut target], 1).await;
            for client in [&mut high.client, &mut target.client] {
                for group in client.take_pending_convergence_groups() {
                    client
                        .advance_convergence_with_projection_progress_and_yield(
                            &group,
                            None,
                            std::future::pending(),
                        )
                        .await
                        .unwrap();
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a claim for the first chat never blocks the second chat");
    assert!(!joined(&target, &chats[0]));
    assert_eq!(taken_from(&high, &target), 1);
    assert_eq!(leaves_of(&high, &target, &chats[0], &group), 0);
    assert_eq!(leaves_of(&high, &target, &chats[1], &group), 1);

    // A claimant that starts leaving no longer holds this chat back. Give
    // it usable stock first so its own no-claim assertion is not vacuous.
    hold_key_packages(&relay, &mut low, &mut target).await;
    let low_slot: [u8; 32] = hex::decode(low.slot_hex()).unwrap().try_into().unwrap();
    let marmot_session::DeviceRosterEdit::Committed(effects) = low
        .client
        .runtime
        .edit_device_roster_entry(&group, &low_slot, &[], |entry| {
            entry.status = cgka_traits::app_components::DeviceStatusV1::Leaving;
        })
        .await
        .unwrap()
    else {
        panic!("the claimant commits its leaving status")
    };
    low.client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    let before = relay.published_events.lock().unwrap().len();
    let stock = held_from(&low, &target);
    assert!(stock > 0);
    low.client.fill_sibling_chat_gaps(&[], 1).await;
    assert_eq!(relay.published_events.lock().unwrap().len(), before);
    assert_eq!(held_from(&low, &target), stock);

    tokio::time::timeout(Duration::from_secs(30), async {
        while !joined(&target, &chats[0]) {
            converge_device_group(&mut high.client, &relay, &mut high.cursor, &group, 1).await;
            // Run the actual gap/Welcome paths without the separate removal
            // driver: the assertion must hold while the claimant is Leaving,
            // before its ordinary removal could also invalidate the claim.
            high.client
                .fill_sibling_chat_gaps(&[], LINK_CHAT_ADDS_PER_PASS)
                .await;
            deliver_new(&mut target.client, &relay, &mut target.cursor).await;
            target.client.join_stashed_sibling_welcomes().await;
            for client in [&mut high.client, &mut target.client] {
                for group in client.take_pending_convergence_groups() {
                    client
                        .advance_convergence_with_projection_progress_and_yield(
                            &group,
                            None,
                            std::future::pending(),
                        )
                        .await
                        .unwrap();
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a claimant that is leaving no longer suppresses its chat");
    assert_eq!(
        high.roster(&group).devices[&low_slot].status,
        cgka_traits::app_components::DeviceStatusV1::Leaving
    );
    assert_eq!(taken_from(&high, &target), 2);
    assert_eq!(leaves_of(&high, &target, &chats[0], &group), 1);
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

/// A device the phone's user decided to remove gets no Add from the phone
/// while that removal waits to commit, though its link is made and the
/// phone holds its KeyPackages.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_being_removed_is_added_to_no_chat() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let chat = phone.client.create_group("chat", &[]).await.unwrap();
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    phone
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .record_device_removal(
            &hex::encode(group.as_slice()),
            &laptop.slot_hex(),
            crate::unix_now_seconds(),
        )
        .unwrap();

    let founded = phone
        .client
        .create_group("new while removing", &[])
        .await
        .unwrap();
    assert_eq!(leaves_of(&phone, &laptop, &founded, &group), 0);
    phone.client.add_linked_devices_to_chats(&[]).await;
    assert_eq!(taken_from(&phone, &laptop), 0);
    assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 0);
}

/// A removal another device decided, which the phone applied and saw branch
/// selection drop with no maintenance pass between, stops the phone adding
/// the device, and still does after a restart: a roster state the phone
/// applied held the laptop's slot as `removed`. The roster lists the laptop
/// again, its link is made and the phone holds its KeyPackages.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_a_dropped_removal_held_as_removed_is_added_to_no_chat() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let chat = phone.client.create_group("chat", &[]).await.unwrap();
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    drop_a_removal_decided_elsewhere(&relay, &mut phone, &mut laptop, &group, false).await;
    let mut phone = reopen(phone).await;

    let founded = phone
        .client
        .create_group("new after dropped removal", &[])
        .await
        .unwrap();
    assert_eq!(leaves_of(&phone, &laptop, &founded, &group), 0);
    phone.client.add_linked_devices_to_chats(&[]).await;
    assert_eq!(taken_from(&phone, &laptop), 0);
    assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 0);
}

/// The phone runs a maintenance pass after applying a removal another device
/// decided, which branch selection then drops. Asked for KeyPackages only
/// after the drop, the again-listed laptop hands the phone some, and the
/// phone still adds it to no chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_that_answers_after_its_removal_is_dropped_is_added_to_no_chat() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let chat = phone.client.create_group("chat", &[]).await.unwrap();
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    drop_a_removal_decided_elsewhere(&relay, &mut phone, &mut laptop, &group, true).await;
    assert_eq!(held_from(&phone, &laptop), 0);
    hold_key_packages(&relay, &mut phone, &mut laptop).await;

    phone.client.add_linked_devices_to_chats(&[]).await;
    assert_eq!(taken_from(&phone, &laptop), 0);
    assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 0);
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
async fn gap_filling_covers_a_link_older_than_the_approvers_burst() {
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
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    assert_eq!(phone.client.add_linked_devices_to_chats(&[]).await, 0);
    assert!(held_from(&phone, &laptop) > 0);
    assert_eq!(taken_from(&phone, &laptop), 0);
    assert!(!joined(&laptop, &chats[0]));

    passes(&relay, &mut [&mut phone, &mut laptop], 4).await;
    assert!(joined(&laptop, &chats[0]));
    assert_eq!(taken_from(&phone, &laptop), 1);
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

/// The old-chat opt-out does not exclude a linked sibling from a new
/// chat's founding Add. The private Welcome is owed at canonical creation,
/// and its normal 461 delivery installs epoch 1 without a follow-up Add.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_chat_founds_with_its_linked_sibling_even_with_old_chats_off() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let group = link_with(
        &relay,
        &mut phone,
        &mut laptop,
        DeviceLinkChoices {
            add_to_all_chats: false,
            ..DeviceLinkChoices::new("Laptop")
        },
    )
    .await;
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    let before = taken_from(&phone, &laptop);
    let chat = phone.client.create_group("new chat", &[]).await.unwrap();
    assert_eq!(phone.client.runtime.device_tag_group(), Some(&group));
    assert_eq!(
        leaves_of(&phone, &laptop, &chat, &group),
        1,
        "the sibling belongs to the founding Add, before maintenance"
    );
    assert_eq!(
        phone.client.runtime.group_record(&chat).unwrap().epoch,
        EpochId(1)
    );
    assert_eq!(taken_from(&phone, &laptop), before + 1);
    let owed = phone
        .client
        .runtime
        .owed_sibling_welcomes(Timestamp(crate::unix_now_seconds()))
        .unwrap();
    assert_eq!(
        owed.iter()
            .filter(|welcome| welcome.group_id == chat)
            .count(),
        0,
        "canonical founding drives the initial carrier before returning"
    );
    deliver_new(&mut laptop.client, &relay, &mut laptop.cursor).await;
    laptop.client.run_due_maintenance().await.unwrap();
    assert!(joined(&laptop, &chat));
    assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 1);

    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    let before = taken_from(&phone, &laptop);
    // A deferred open has not yet named the engine's trusted tag source.
    // Creation must synchronize it before spending durable private stock.
    let Device {
        _dir,
        app,
        client,
        cursor,
    } = phone;
    drop(client);
    let plane = MarmotRelayPlane::new(None, relay.clone());
    let client = app
        .local_client_with_relay_plane_and_hydration("alice", &plane, None, true, None)
        .await
        .unwrap();
    let mut phone = Device {
        _dir,
        app,
        client,
        cursor,
    };
    assert_eq!(phone.client.runtime.device_tag_group(), None);
    let chat = phone
        .client
        .create_group("after deferred open", &[])
        .await
        .unwrap();
    assert_eq!(phone.client.runtime.device_tag_group(), Some(&group));
    assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 1);
    assert_eq!(taken_from(&phone, &laptop), before + 1);
}

/// Missing private stock never falls back to the sibling's public slot or
/// blocks creation. Active and inactive linked entries qualify once stock
/// exists; leaving and keyless entries do not consume it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn founding_sibling_selection_uses_private_stock_and_linked_status() {
    use cgka_traits::app_components::DeviceStatusV1;
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let group = link_with(
        &relay,
        &mut phone,
        &mut laptop,
        DeviceLinkChoices {
            add_to_all_chats: false,
            ..DeviceLinkChoices::new("Laptop")
        },
    )
    .await;
    let slot = hex::decode(laptop.slot_hex()).unwrap().try_into().unwrap();
    // No hand-off has arrived yet, though the laptop's public slot is valid.
    let missing = phone
        .client
        .create_group("no private stock", &[])
        .await
        .unwrap();
    assert_eq!(leaves_of(&phone, &laptop, &missing, &group), 0);
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    let before = taken_from(&phone, &laptop);
    let database = account_database(&phone.app);
    // Optional stock reads and consumption writes can fail independently.
    // Neither failure prevents an ordinary chat or spends unchecked stock.
    for (break_stock, restore_stock) in [
        (
            "ALTER TABLE private_key_packages_received RENAME TO held_aside",
            "ALTER TABLE held_aside RENAME TO private_key_packages_received",
        ),
        (
            "CREATE TRIGGER refuse_founding_take BEFORE UPDATE ON private_key_packages_received
             BEGIN SELECT RAISE(ABORT, 'private stock unavailable'); END;",
            "DROP TRIGGER refuse_founding_take",
        ),
    ] {
        database.execute_batch(break_stock).unwrap();
        let result = phone
            .client
            .create_group("unavailable private stock", &[])
            .await;
        database.execute_batch(restore_stock).unwrap();
        let chat = result.unwrap();
        assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 0);
        assert_eq!(phone.client.runtime.members(&chat).unwrap().len(), 1);
        assert_eq!(taken_from(&phone, &laptop), before);
    }
    drop(database);
    // The routing is valid for a chat, but repeats a relay once parsed, so
    // no sibling Welcome can carry it. Creation spends no private package.
    let before = taken_from(&phone, &laptop);
    let closed = phone
        .client
        .create_group_with_options(
            "closed routing",
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
    assert_eq!(leaves_of(&phone, &laptop, &closed, &group), 0);
    assert_eq!(taken_from(&phone, &laptop), before);
    let key = laptop.client.runtime.own_signature_key();
    for (status, tagged, expected) in [
        (DeviceStatusV1::Inactive, true, 1),
        (DeviceStatusV1::Leaving, true, 0),
        (DeviceStatusV1::Active, false, 0),
    ] {
        phone
            .client
            .runtime
            .edit_device_roster_entry(&group, &slot, &[], |entry| {
                entry.status = status;
                entry.tag_signature_key = tagged.then(|| key.clone());
            })
            .await
            .unwrap();
        let before = taken_from(&phone, &laptop);
        let chat = phone.client.create_group("status", &[]).await.unwrap();
        assert_eq!(leaves_of(&phone, &laptop, &chat, &group), expected);
        assert_eq!(taken_from(&phone, &laptop), before + expected);
    }
    phone
        .client
        .runtime
        .edit_device_roster_entry(&group, &slot, &[], |entry| {
            entry.status = DeviceStatusV1::Active;
            entry.tag_signature_key = Some(key.clone());
        })
        .await
        .unwrap();
    // The durable link verdict, written by the linking lifecycle, beats a
    // current roster key. Exercise both unfinished and terminal failures
    // through that storage boundary without asking maintenance to remove it.
    let link = link_record(&phone, &group, &laptop.slot_hex());
    let storage = phone.app.account_storage("alice").unwrap().app_storage();
    storage
        .record_device_link(
            &link.group_id_hex,
            &link.slot_hex,
            &link.key_package_ref_hex,
            &link.leaf_signature_key_hex,
            link.linked_at,
        )
        .unwrap();
    for outcome in [DeviceLinkOutcome::Pending, DeviceLinkOutcome::Failed] {
        if outcome == DeviceLinkOutcome::Failed {
            assert!(
                storage
                    .decide_device_link(
                        &link.group_id_hex,
                        &link.slot_hex,
                        outcome,
                        crate::unix_now_seconds()
                    )
                    .unwrap()
            );
        }
        let before = taken_from(&phone, &laptop);
        let chat = phone.client.create_group("unmade link", &[]).await.unwrap();
        assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 0);
        assert_eq!(taken_from(&phone, &laptop), before);
    }
}

/// A local failed link belongs to the entry this device approved. Another
/// sibling can link that slot later, and the old approver must include the
/// newly linked device when it creates a chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_link_by_another_approver_outlives_a_local_failed_link() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let group = link(&relay, &mut phone, &mut tablet, "Tablet").await;
    let slot = choose_link(&relay, &mut phone, &mut laptop).await;
    laptop.op(DeviceLinkOp::ConfirmMatch).await;
    laptop.step(&relay).await;
    phone.step(&relay).await;
    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + LINK_DEADLINE_SECS + 1)
        .await;
    phone.step(&relay).await;
    let ended = laptop.step(&relay).await;
    assert_eq!(
        ended.new_device,
        Some(NewDeviceLinkState::Ended {
            reason: DeviceLinkEndReason::LinkFailed
        })
    );
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Failed
    );
    tablet.step(&relay).await;
    published_key_package(&mut laptop.client, &relay).await;
    assert_eq!(
        link_with(
            &relay,
            &mut tablet,
            &mut laptop,
            DeviceLinkChoices {
                add_to_all_chats: false,
                ..DeviceLinkChoices::new("Laptop linked by tablet")
            }
        )
        .await,
        group
    );
    phone.step(&relay).await;
    let laptop_slot: [u8; 32] = hex::decode(&slot).unwrap().try_into().unwrap();
    let tablet_slot: [u8; 32] = hex::decode(tablet.slot_hex()).unwrap().try_into().unwrap();
    assert_eq!(
        phone.roster(&group).devices[&laptop_slot].linked_by,
        Some(tablet_slot)
    );
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Failed,
        "another approver's link does not rewrite this device's old record"
    );
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    let chat = phone
        .client
        .create_group("after another approver linked", &[])
        .await
        .unwrap();
    assert_eq!(
        leaves_of(&phone, &laptop, &chat, &group),
        1,
        "the current entry's approver owns its link outcome"
    );
}
