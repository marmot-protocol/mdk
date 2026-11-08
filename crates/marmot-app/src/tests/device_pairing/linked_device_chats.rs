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

/// Lose a real opt-out to a sibling's longer non-user branch. Its retained
/// intention must wait for D37 recovery or a covered user cancellation.
async fn lose_gap_opt_out(
    relay: &ScriptedPushRelayClient,
    editor: &mut Device,
    target: &mut Device,
    group: &GroupId,
) {
    for device in [&mut *editor, &mut *target] {
        converge_device_group(&mut device.client, relay, &mut device.cursor, group, 8).await;
    }
    let slot_hex = target.slot_hex();
    let slot = hex::decode(&slot_hex).unwrap().try_into().unwrap();
    editor
        .client
        .update_linked_device_settings(&slot_hex, Some(false), None, None)
        .await
        .unwrap();
    for platform in ["held-claim-fork-a", "held-claim-fork-b"] {
        let edit = target
            .client
            .runtime
            .edit_device_roster_entry(group, &slot, &[], |entry| {
                entry.platform = platform.to_owned();
            })
            .await
            .unwrap();
        assert!(matches!(
            edit,
            marmot_session::DeviceRosterEdit::Committed(_)
        ));
    }
    for device in [&mut *editor, &mut *target] {
        converge_device_group(&mut device.client, relay, &mut device.cursor, group, 8).await;
    }
    assert!(
        editor.roster(group).devices[&slot]
            .settings
            .add_to_all_chats
    );
}

/// Keep the device group genuinely busy so ordinary maintenance cannot
/// replay the lost opt-out before the gap pass examines its claims.
async fn hold_gap_edit_recovery(
    editor: &mut Device,
    group: &GroupId,
) -> marmot_session::PreparedSessionCommit {
    let marmot_session::PreparedSessionSend::Commit(staged) = editor
        .client
        .runtime
        .confirm_commit_without_publish_with_audit_context(
            SendIntent::SelfUpdate {
                group_id: group.clone(),
            },
            marmot_forensics::AuditEventContext::default(),
        )
        .await
        .unwrap()
    else {
        panic!("the device group stages its hold");
    };
    staged
}

async fn release_and_cancel_gap_opt_out(
    relay: &ScriptedPushRelayClient,
    editor: &mut Device,
    target: &Device,
    group: &GroupId,
    staged: marmot_session::PreparedSessionCommit,
) {
    let effects = editor
        .client
        .runtime
        .rollback_prepared_session_commit(staged)
        .await
        .unwrap();
    editor
        .client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    converge_device_group(&mut editor.client, relay, &mut editor.cursor, group, 8).await;
    let pin = editor.client.runtime.epoch_pin(group).unwrap();
    // Cancel before the next maintenance pass can replay. A cancellation
    // while the Commit was still held would correctly be refused as Busy.
    editor
        .client
        .update_linked_device_settings(&target.slot_hex(), Some(true), None, None)
        .await
        .unwrap();
    assert_eq!(editor.client.runtime.epoch_pin(group).unwrap(), pin);
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

pub(super) fn account_database(app: &MarmotApp) -> rusqlite::Connection {
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

/// A real linked sender rebroadcasts a retained winning choice. It need not
/// have this ordinary chat installed to authenticate its account's choice.
async fn receive_account_choice(
    relay: &ScriptedPushRelayClient,
    source: &mut Device,
    receiver: &mut Device,
    chat: &GroupId,
    version: u64,
    declined: bool,
) {
    use cgka_traits::storage::GroupStorage as _;
    let group = receiver.client.trusted_device_group().unwrap().unwrap();
    let store = receiver.app.account_storage("alice").unwrap();
    let generation = store
        .invitation_admission(chat)
        .unwrap()
        .unwrap()
        .generation;
    let decision = storage_sqlite::InvitationDecision {
        group_id_hex: hex::encode(chat.as_slice()),
        generation,
        version,
        declined,
    };
    let [(content, _)] = <[_; 1]>::try_from(
        crate::small_state::encode_invitation_decision_updates(std::slice::from_ref(&decision)),
    )
    .unwrap();
    assert!(source.client.send_device_group_message(
        &group, crate::small_state::KIND_SMALL_STATE_UPDATE, content,
    ).await.unwrap());
    // Direct clients have no worker. Await the real authenticated winner,
    // not a fixed count of convergence passes.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            converge_device_group(&mut source.client, relay, &mut source.cursor, &group, 1).await;
            converge_device_group(&mut receiver.client, relay, &mut receiver.cursor, &group, 1)
                .await;
            if store
                .app_storage()
                .invitation_decision(&decision.group_id_hex, &generation)
                .unwrap()
                .as_ref()
                == Some(&decision)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the authenticated choice reaches the matching installed copy");
}

/// One real external Add admits both linked copies with one generation.
async fn invite_account_pending(
    relay: &Arc<ScriptedPushRelayClient>,
    phone: &mut Device,
    laptop: &mut Device,
    admin: bool,
    relays: Option<Vec<String>>,
) -> (tempfile::TempDir, AppClient, GroupId) {
    let alice = phone
        .app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path()).create_account("bob").unwrap();
    let app = crate::tests::canonical_membership::app_at(&dir, relay.clone());
    remember_test_member_inbox(&app, &alice, "wss://relay.example");
    let mut bob = app.client("bob").await.unwrap();
    let chat = bob
        .create_group_with_options(
            "account departure",
            &[],
            AppCreateGroupOptions {
                relays,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let keys = vec![
        published_key_package(&mut phone.client, relay).await,
        published_key_package(&mut laptop.client, relay).await,
    ];
    let effects = bob
        .runtime
        .send(SendIntent::Invite {
            group_id: chat.clone(),
            key_packages: keys,
            initial_admins: if admin {
                vec![MemberId::new(hex::decode(&alice).unwrap())]
            } else {
                vec![]
            },
        })
        .await
        .unwrap();
    bob.observe_drained_session_events(&effects).await.unwrap();
    for device in [&mut *phone, &mut *laptop] {
        deliver_new(&mut device.client, relay, &mut device.cursor).await;
        device.client.sync().await.unwrap();
    }
    (dir, bob, chat)
}

async fn invite_account_for_leave(
    relay: &Arc<ScriptedPushRelayClient>,
    phone: &mut Device,
    laptop: &mut Device,
    admin: bool,
    relays: Option<Vec<String>>,
) -> (tempfile::TempDir, AppClient, GroupId) {
    let invitation = invite_account_pending(relay, phone, laptop, admin, relays).await;
    for device in [phone, laptop] {
        device.client.accept_group_invite(&invitation.2).unwrap();
    }
    invitation
}

async fn await_account_departure(
    relay: &ScriptedPushRelayClient,
    phone: &mut Device,
    laptop: &mut Device,
    bob: &mut AppClient,
    chat: &GroupId,
) {
    let mut bob_cursor = 0;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            for device in [&mut *phone, &mut *laptop] {
                deliver_new(&mut device.client, relay, &mut device.cursor).await;
                device.client.run_due_maintenance().await.unwrap();
            }
            deliver_new(bob, relay, &mut bob_cursor).await;
            bob.run_due_maintenance().await.unwrap();
            // Direct clients have no worker to advance scheduled convergence.
            for client in [&mut phone.client, &mut laptop.client, &mut *bob] {
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
            if phone.client.runtime.group_record(chat).unwrap().removed
                && laptop.client.runtime.group_record(chat).unwrap().removed
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both matching copies must leave through ordinary native work");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_leave_takes_matching_account_copies_out() {
    user_account_leave_case(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_leave_demotes_a_nonlast_admin_account_before_all_copies_leave() {
    user_account_leave_case(true).await;
}

async fn user_account_leave_case(admin: bool) {
    use cgka_traits::storage::GroupStorage as _;
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    link(&relay, &mut phone, &mut laptop, "Laptop").await;
    let (_bob_dir, mut bob, chat) =
        invite_account_for_leave(&relay, &mut phone, &mut laptop, admin, None).await;
    let chat_hex = hex::encode(chat.as_slice());
    let store = phone.app.account_storage("alice").unwrap();
    let admission = store.invitation_admission(&chat).unwrap().unwrap();
    assert_eq!(
        laptop
            .app
            .account_storage("alice")
            .unwrap()
            .invitation_admission(&chat)
            .unwrap()
            .unwrap()
            .generation,
        admission.generation
    );
    relay.block_next_publish();
    let mut leaving = Box::pin(phone.client.leave_group(&chat));
    tokio::select! {
        result = &mut leaving => panic!("Leave must reach its real departure publication: {result:?}"),
        _ = relay.wait_for_blocked_publish() => {}
    }
    let choice_before_publish = store
        .app_storage()
        .invitation_decision(&chat_hex, &admission.generation)
        .unwrap()
        .unwrap();
    relay.release_publish();
    leaving.await.unwrap();
    assert!(
        choice_before_publish.declined,
        "UserLeave must durably record the current generation's decline before its first departure publication"
    );
    assert_eq!(choice_before_publish.version, 2);
    await_account_departure(&relay, &mut phone, &mut laptop, &mut bob, &chat).await;
    let alice = phone
        .app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    assert!(
        !bob.runtime
            .admin_pubkeys(&chat)
            .unwrap()
            .iter()
            .any(|key| hex::encode(key) == alice)
    );
    for _ in 0..2 {
        passes(&relay, &mut [&mut phone, &mut laptop], 1).await;
        assert!(
            !bob.runtime
                .members(&chat)
                .unwrap()
                .iter()
                .any(|member| hex::encode(member.id.as_slice()) == alice)
        );
        for device in [&phone, &laptop] {
            assert!(device.client.runtime.group_record(&chat).unwrap().removed);
            assert_eq!(
                device
                    .app
                    .group("alice", &chat_hex)
                    .unwrap()
                    .unwrap()
                    .self_membership,
                crate::SelfMembership::Left
            );
        }
    }
}

/// A user's one real delivery acknowledgment admits the whole account Leave,
/// including its admin demotion, rather than being consumed twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_undelivered_commit_ack_admits_an_admin_account_leave() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    link(&relay, &mut phone, &mut laptop, "Laptop").await;
    let (_dir, _bob, chat) = invite_account_for_leave(
        &relay,
        &mut phone,
        &mut laptop,
        true,
        Some(vec![
            "wss://relay-a.example".into(),
            "wss://relay-b.example".into(),
        ]),
    )
    .await;
    phone.client.commit_delivery_gate_grace_secs = 0;
    relay.make_endpoints_unavailable(&["wss://relay-b.example"]);
    phone
        .client
        .update_group_profile(&chat, Some("one relay still owes this"), None)
        .await
        .unwrap();
    let delivery = phone.client.group_commit_delivery(&chat).unwrap().unwrap();
    assert_eq!(
        delivery.owed_relay_urls,
        vec!["wss://relay-b.example".to_owned()]
    );
    assert_eq!(delivery.relay_count, 2);
    let store = phone.app.account_storage("alice").unwrap();
    let generation = store
        .invitation_admission(&chat)
        .unwrap()
        .unwrap()
        .generation;
    let chat_hex = hex::encode(chat.as_slice());
    let choice = store
        .app_storage()
        .invitation_decision(&chat_hex, &generation)
        .unwrap();
    let published = relay.published_event_ids().len();
    assert!(matches!(phone.client.leave_group(&chat).await,
        Err(AppError::GroupCommitUndelivered(ref held)) if held == &chat_hex));
    assert_eq!(
        store
            .app_storage()
            .invitation_decision(&chat_hex, &generation)
            .unwrap(),
        choice
    );
    assert_eq!(relay.published_event_ids().len(), published);
    assert!(store.leave_request(&chat).unwrap().is_none());
    assert!(
        phone
            .client
            .acknowledge_group_commit_undelivered(&chat)
            .unwrap()
    );
    phone
        .client
        .leave_group(&chat)
        .await
        .expect("one public acknowledgment must admit demotion and departure");
    assert!(
        store
            .app_storage()
            .invitation_decision(&chat_hex, &generation)
            .unwrap()
            .unwrap()
            .declined
    );
    assert!(store.leave_request(&chat).unwrap().is_some());
    let own = phone.client.runtime.self_id();
    assert!(
        !phone
            .client
            .runtime
            .admin_pubkeys(&chat)
            .unwrap()
            .iter()
            .any(|admin| admin.as_slice() == own.as_slice())
    );
}

/// Two leaves of the sole admin account are one admin, not two. Refusal
/// precedes the replicated choice, push removal and any demotion publication.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_last_admin_account_cannot_leave_from_either_device() {
    use cgka_traits::storage::{GroupStorage as _, LeaveRequestStorage as _};
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    link(&relay, &mut phone, &mut laptop, "Laptop").await;
    let (_dir, mut bob, chat) =
        invite_account_for_leave(&relay, &mut phone, &mut laptop, true, None).await;
    bob.self_demote_admin(&chat).await.unwrap();
    for device in [&mut phone, &mut laptop] {
        deliver_new(&mut device.client, &relay, &mut device.cursor).await;
        device.client.sync().await.unwrap();
    }
    let before_publications = relay.published_event_ids();
    let before_attempts = relay.attempted_event_ids();
    for device in [&mut phone, &mut laptop] {
        let store = device.app.account_storage("alice").unwrap();
        let generation = store
            .invitation_admission(&chat)
            .unwrap()
            .unwrap()
            .generation;
        let chat_hex = hex::encode(chat.as_slice());
        let decision = store
            .app_storage()
            .invitation_decision(&chat_hex, &generation)
            .unwrap();
        let unsent = store.app_storage().unsent_invitation_decisions().unwrap();
        let error = device.client.leave_group(&chat).await.unwrap_err();
        assert!(
            matches!(
                error.as_engine_error(),
                Some(cgka_traits::EngineError::AdminDepletion { .. })
            ),
            "{error}"
        );
        assert_eq!(
            store
                .app_storage()
                .invitation_decision(&chat_hex, &generation)
                .unwrap(),
            decision
        );
        assert_eq!(
            store.app_storage().unsent_invitation_decisions().unwrap(),
            unsent
        );
        assert!(store.leave_request(&chat).unwrap().is_none());
        assert!(
            device
                .app
                .pending_push_registration_removals("alice")
                .unwrap()
                .is_empty()
        );
        assert!(!device.client.runtime.group_record(&chat).unwrap().removed);
        assert_eq!(
            device
                .app
                .group("alice", &chat_hex)
                .unwrap()
                .unwrap()
                .self_membership,
            crate::SelfMembership::Member
        );
    }
    assert_eq!(relay.attempted_event_ids(), before_attempts);
    assert_eq!(relay.published_event_ids(), before_publications);
}

/// A held maximum does not manufacture a new version or block ordinary
/// UserLeave. Sign-out uses its own leaf path and creates no account decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maximum_choice_and_signout_keep_ordinary_leaf_departure() {
    use cgka_traits::storage::{GroupStorage as _, LeaveRequestStorage as _};
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    link(&relay, &mut phone, &mut laptop, "Laptop").await;
    let (_dir, _bob, chat) =
        invite_account_for_leave(&relay, &mut phone, &mut laptop, false, None).await;
    receive_account_choice(
        &relay,
        &mut laptop,
        &mut phone,
        &chat,
        storage_sqlite::MAX_SMALL_STATE_NUMBER,
        false,
    )
    .await;
    let chat_hex = hex::encode(chat.as_slice());
    let laptop_store = laptop.app.account_storage("alice").unwrap();
    let generation = laptop_store
        .invitation_admission(&chat)
        .unwrap()
        .unwrap()
        .generation;
    let laptop_choice = laptop_store
        .app_storage()
        .invitation_decision(&chat_hex, &generation)
        .unwrap();
    let account = laptop.app.account_home().account("alice").unwrap();
    let _signing_out = laptop.app.begin_signing_out(&account.account_id_hex);
    laptop.client.leave_group_for_sign_out(&chat).await.unwrap();
    assert!(laptop_store.leave_request(&chat).unwrap().is_some());
    assert_eq!(
        laptop_store
            .app_storage()
            .invitation_decision(&chat_hex, &generation)
            .unwrap(),
        laptop_choice
    );
    let store = phone.app.account_storage("alice").unwrap();
    let held = store
        .app_storage()
        .invitation_decision(&chat_hex, &generation)
        .unwrap()
        .unwrap();
    assert!(!held.declined && held.version == storage_sqlite::MAX_SMALL_STATE_NUMBER);
    let unsent = store.app_storage().unsent_invitation_decisions().unwrap();
    phone.client.leave_group(&chat).await.unwrap();
    assert!(store.leave_request(&chat).unwrap().is_some());
    assert_eq!(
        store
            .app_storage()
            .invitation_decision(&chat_hex, &generation)
            .unwrap(),
        Some(held)
    );
    assert_eq!(
        store.app_storage().unsent_invitation_decisions().unwrap(),
        unsent
    );
}

/// A real accepted SelfRemove-bearing Commit is confirmed by the deferred
/// worker's startup drain. Its trusted tag context must already be named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deferred_worker_attributes_an_accepted_sibling_departure() {
    use cgka_traits::storage::{GroupStorage as _, OutboundFanoutStorage as _};
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let device_group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    let (_bob_dir, _bob, chat) =
        invite_account_for_leave(&relay, &mut phone, &mut laptop, false, None).await;
    let slot: [u8; 32] = hex::decode(laptop.slot_hex()).unwrap().try_into().unwrap();
    let store = phone.app.account_storage("alice").unwrap();
    let mut persisted_groups = store.list_groups().unwrap();
    persisted_groups.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    let mut expected_groups = vec![device_group.clone(), chat.clone()];
    expected_groups.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    assert_eq!(persisted_groups, expected_groups);
    assert!(
        persisted_groups.len()
            <= crate::runtime::account_worker::STARTUP_HYDRATION_BATCH_SIZE_FOR_TEST
    );
    let db = account_database(&phone.app);
    db.execute_batch(&format!(
        "CREATE TRIGGER hold_departure_confirmation BEFORE INSERT ON cgka_groups
         WHEN NEW.id = x'{}' AND instr(CAST(NEW.record AS TEXT), 'self_removed_sibling_slots') > 0
         BEGIN SELECT RAISE(FAIL, 'accepted departure confirmation held'); END;",
        hex::encode(chat.as_slice()),
    ))
    .unwrap();
    let cursor = relay.published_events.lock().unwrap().len();
    laptop.client.leave_group_for_sign_out(&chat).await.unwrap();
    let proposals: Vec<_> = relay.published_events.lock().unwrap()[cursor..]
        .iter()
        .filter(|event| event.kind == transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
        .cloned()
        .collect();
    assert!(
        !proposals.is_empty(),
        "the actual sibling SelfRemove must publish"
    );
    let account = phone.app.account_home().account("alice").unwrap();
    let mut held = false;
    for event in proposals {
        let result = phone
            .client
            .ingest_received_delivery(cgka_traits::TransportDelivery {
                account_id: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
                group_id_hint: Some(chat.clone()),
                message: event.to_transport_message().unwrap(),
                received_at: cgka_traits::Timestamp(crate::unix_now_seconds()),
                source: cgka_traits::TransportDeliverySource {
                    transport: cgka_traits::transport::TransportSource("nostr".into()),
                    plane: cgka_traits::TransportDeliveryPlane::Group,
                    endpoint: None,
                    subscription_id: None,
                    wire: None,
                },
            })
            .await;
        if let Err(error) = result {
            assert!(
                error
                    .to_string()
                    .contains("accepted departure confirmation held"),
                "{error}"
            );
            held = true;
        }
    }
    if !held {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match phone
                    .client
                    .advance_convergence_with_projection_progress_and_yield(
                        &chat,
                        None,
                        std::future::pending(),
                    )
                    .await
                {
                    Ok(_) => tokio::task::yield_now().await,
                    Err(error) => {
                        assert!(
                            error
                                .to_string()
                                .contains("accepted departure confirmation held"),
                            "{error}"
                        );
                        break;
                    }
                }
            }
        })
        .await
        .expect("the real accepted Commit reaches its fallible confirmation");
    }
    let fanout = store
        .list_outbound_fanouts_for_group(&chat)
        .unwrap()
        .into_iter()
        .find(|fanout| {
            matches!(fanout.mls_state(), cgka_traits::FanoutMlsState::Pending(_))
                && fanout.outcome().accepted_targets > 0
        })
        .expect("actual relay acceptance is durable before failed MLS confirmation");
    assert!(fanout.outcome().accepted_targets >= fanout.request().required_acks.max(1));
    let publication = fanout.message_id().clone();
    assert!(
        !store
            .get_group(&chat)
            .unwrap()
            .self_removed_sibling_slots
            .contains(&slot)
    );
    assert_eq!(phone.client.runtime.device_tag_group(), Some(&device_group));
    db.execute_batch("DROP TRIGGER hold_departure_confirmation")
        .unwrap();
    drop(db);
    drop(store);
    drop(phone.client);
    phone.app.close_storage().unwrap();
    // Reopen the real encrypted account on a new application/worker, not a
    // copied receipt or an engine-only approximation of startup ordering.
    let reopened = MarmotApp::with_relay_and_config(
        phone._dir.path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0)
            .with_dev_device_groups(true),
    )
    .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(reopened.clone());
    runtime.reconcile_accounts().await.unwrap();
    let reopened_store = reopened.account_storage("alice").unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let pending = reopened_store
                .list_outbound_fanouts_for_group(&chat)
                .unwrap()
                .into_iter()
                .any(|fanout| {
                    fanout.message_id() == &publication
                        && matches!(fanout.mls_state(), cgka_traits::FanoutMlsState::Pending(_))
                });
            if !pending {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the real deferred worker confirms its accepted pending publication");
    let recorded = reopened_store
        .get_group(&chat)
        .unwrap()
        .self_removed_sibling_slots
        .contains(&slot);
    // Finish cleanup before the intended before-fix assertion can fail.
    drop(reopened_store);
    runtime.shutdown_and_close().await.unwrap();
    assert!(
        recorded,
        "the first deferred startup drain must retain the authenticated sibling departure"
    );
}

/// A canonical disband can keep a pending Member projection. A later
/// authenticated Accept retains its value but owes no acceptance of that tombstone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delayed_accept_retires_only_its_disbanded_invitation_work() {
    use cgka_traits::storage::{GroupStorage as _, LeaveRequestStorage as _};

    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    link(&relay, &mut phone, &mut laptop, "Laptop").await;
    let (_bob_dir, mut bob, chat) =
        invite_account_pending(&relay, &mut phone, &mut laptop, false, None).await;
    let chat_hex = hex::encode(chat.as_slice());
    let account = phone.app.account_storage("alice").unwrap();
    let generation = account
        .invitation_admission(&chat)
        .unwrap()
        .unwrap()
        .generation;
    assert!(
        phone
            .client
            .state_group_record(&chat)
            .unwrap()
            .pending_confirmation
    );

    bob.disband_group(&chat).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let effects = bob.runtime.advance_convergence(&chat).await.unwrap();
            bob.observe_drained_session_events(&effects).await.unwrap();
            deliver_new(&mut phone.client, &relay, &mut phone.cursor).await;
            let effects = phone
                .client
                .runtime
                .advance_convergence(&chat)
                .await
                .unwrap();
            phone
                .client
                .observe_drained_session_events(&effects)
                .await
                .unwrap();
            if phone
                .client
                .runtime
                .group_record(&chat)
                .unwrap()
                .disbanded
                .is_some()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the actual external-admin disband canonically settles");
    let native = phone.client.runtime.group_record(&chat).unwrap();
    assert!(native.disbanded.is_some());
    assert!(!native.removed && !native.unrecoverable);
    let saved = phone.app.group("alice", &chat_hex).unwrap().unwrap();
    assert!(saved.disbanded && saved.pending_confirmation);
    assert_eq!(saved.self_membership, crate::SelfMembership::Member);
    assert!(account.leave_request(&chat).unwrap().is_none());
    assert_eq!(
        account
            .invitation_admission(&chat)
            .unwrap()
            .unwrap()
            .generation,
        generation
    );

    receive_account_choice(&relay, &mut laptop, &mut phone, &chat, 1, false).await;
    let storage = account.app_storage();
    let decision = storage
        .invitation_decision(&chat_hex, &generation)
        .unwrap()
        .unwrap();
    assert_eq!(decision.version, 1);
    assert!(!decision.declined);
    assert!(
        storage
            .invitation_decision_work()
            .unwrap()
            .iter()
            .any(|work| work.decision == decision && work.apply_owed && !work.decline_owed)
    );
    let unsent = storage.unsent_invitation_decisions().unwrap();

    phone.client.drive_invitation_decisions().await;
    assert!(
        !storage
            .invitation_decision_work()
            .unwrap()
            .iter()
            .any(|work| work.decision == decision && work.apply_owed),
        "canonical disband ends only this acceptance work"
    );
    assert_eq!(
        storage.invitation_decision(&chat_hex, &generation).unwrap(),
        Some(decision)
    );
    assert_eq!(storage.unsent_invitation_decisions().unwrap(), unsent);
    assert!(account.leave_request(&chat).unwrap().is_none());
    let saved = phone.app.group("alice", &chat_hex).unwrap().unwrap();
    assert!(
        saved.disbanded && saved.pending_confirmation,
        "retiring work does not accept or rewrite the terminal projection"
    );
    phone.client.drive_invitation_decisions().await;
    assert!(
        !storage
            .invitation_decision_work()
            .unwrap()
            .iter()
            .any(|work| work.decision.group_id_hex == chat_hex
                && work.decision.generation == generation
                && work.apply_owed)
    );
}

/// A real native metadata update is newer than the saved chat while its App
/// checkpoint fails. Owed invitation work must not overwrite that queued write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invitation_work_preserves_a_pending_chat_projection() {
    use cgka_traits::storage::{GroupStorage as _, LeaveRequestStorage as _, MessageStorage as _};

    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    link(&relay, &mut phone, &mut laptop, "Laptop").await;
    let alice = phone
        .app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let bob_dir = tempfile::tempdir().unwrap();
    AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap();
    let bob_app = crate::tests::canonical_membership::app_at(&bob_dir, relay.clone());
    remember_test_member_inbox(&bob_app, &alice, "wss://relay.example");
    let mut bob = bob_app.client("bob").await.unwrap();
    let chat = bob
        .create_group("old invitation profile", &[])
        .await
        .unwrap();
    let key = published_key_package(&mut phone.client, &relay).await;
    let effects = bob
        .runtime
        .send(SendIntent::Invite {
            group_id: chat.clone(),
            key_packages: vec![key],
            initial_admins: vec![MemberId::new(hex::decode(&alice).unwrap())],
        })
        .await
        .unwrap();
    bob.observe_drained_session_events(&effects).await.unwrap();
    deliver_new(&mut phone.client, &relay, &mut phone.cursor).await;
    phone.client.sync().await.unwrap();
    receive_account_choice(&relay, &mut laptop, &mut phone, &chat, 1, true).await;
    let chat_hex = hex::encode(chat.as_slice());
    let store = phone.app.account_storage("alice").unwrap();
    let generation = store
        .invitation_admission(&chat)
        .unwrap()
        .unwrap()
        .generation;
    assert!(store.leave_request(&chat).unwrap().is_none());
    assert!(
        store
            .app_storage()
            .invitation_decision_work()
            .unwrap()
            .iter()
            .any(|work| work.decision.generation == generation && work.decline_owed)
    );
    assert_eq!(
        phone
            .app
            .group("alice", &chat_hex)
            .unwrap()
            .unwrap()
            .profile
            .name,
        "old invitation profile"
    );

    let cursor = relay.published_events.lock().unwrap().len();
    bob.update_group_profile(&chat, Some("new native profile"), None)
        .await
        .unwrap();
    // Bob authors the profile while still admin, then leaves Alice's account
    // as the sole active admin. A received decline owes work but cannot leave.
    bob.self_demote_admin(&chat).await.unwrap();
    // The real application following the Commit also leaves an actual native
    // output acknowledgment pending at this same failed App checkpoint.
    bob.send(&chat, b"checkpoint companion").await.unwrap();
    let deliveries: Vec<_> = relay.published_events.lock().unwrap()[cursor..]
        .iter()
        .filter(|event| event.kind == transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
        .cloned()
        .collect();
    assert!(deliveries.len() >= 2);
    let db = account_database(&phone.app);
    db.execute_batch("CREATE TRIGGER reject_pending_profile BEFORE INSERT ON account_state BEGIN SELECT RAISE(FAIL, 'pending profile checkpoint held'); END;").unwrap();
    for event in deliveries {
        let error = phone
            .client
            .ingest_received_delivery(cgka_traits::TransportDelivery {
                account_id: MemberId::new(hex::decode(&alice).unwrap()),
                group_id_hint: Some(chat.clone()),
                message: event.to_transport_message().unwrap(),
                received_at: cgka_traits::Timestamp(crate::unix_now_seconds()),
                source: cgka_traits::TransportDeliverySource {
                    transport: cgka_traits::transport::TransportSource("nostr".into()),
                    plane: cgka_traits::TransportDeliveryPlane::Group,
                    endpoint: None,
                    subscription_id: None,
                    wire: None,
                },
            })
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("pending profile checkpoint held"),
            "{error}"
        );
    }
    assert_eq!(
        phone.client.runtime.group_record(&chat).unwrap().name,
        "new native profile"
    );
    assert_eq!(
        phone.client.state_group_record(&chat).unwrap().profile.name,
        "new native profile"
    );
    assert_eq!(
        phone
            .app
            .group("alice", &chat_hex)
            .unwrap()
            .unwrap()
            .profile
            .name,
        "old invitation profile"
    );
    assert!(
        phone
            .client
            .pending_group_projection_updates
            .contains(&chat_hex)
    );
    assert!(!phone.client.pending_application_event_acks.is_empty());
    assert!(store.list_pending_application_events().unwrap().iter().any(|event| matches!(event, cgka_traits::GroupEvent::MessageReceived { group_id, .. } if group_id == &chat)));
    assert!(phone.client.arm_failed_receive_projection_retry());

    if let Err(error) = phone.client.run_due_maintenance().await {
        assert!(
            error
                .to_string()
                .contains("pending profile checkpoint held"),
            "{error}"
        );
    }
    let retained_profile = phone.client.state_group_record(&chat).unwrap().profile.name;
    assert!(
        phone
            .client
            .pending_group_projection_updates
            .contains(&chat_hex)
    );
    assert!(store.leave_request(&chat).unwrap().is_none());
    assert!(
        store
            .app_storage()
            .invitation_decision_work()
            .unwrap()
            .iter()
            .any(|work| work.decision.generation == generation && work.decline_owed)
    );
    db.execute_batch("DROP TRIGGER reject_pending_profile")
        .unwrap();
    drop(db);
    assert_eq!(
        retained_profile, "new native profile",
        "invitation maintenance must not replace an uncheckpointed native profile with the older saved row"
    );

    phone.client.run_due_maintenance().await.unwrap();
    assert_eq!(
        phone
            .app
            .group("alice", &chat_hex)
            .unwrap()
            .unwrap()
            .profile
            .name,
        "new native profile"
    );
    assert!(
        !phone
            .client
            .pending_group_projection_updates
            .contains(&chat_hex)
    );
    assert!(phone.client.pending_application_event_acks.is_empty());
    assert!(!store.list_pending_application_events().unwrap().iter().any(|event| matches!(event, cgka_traits::GroupEvent::MessageReceived { group_id, .. } if group_id == &chat)));
    assert!(store.leave_request(&chat).unwrap().is_none());
    drop(phone.client);
    phone.client = phone.app.client("alice").await.unwrap();
    assert_eq!(
        phone.client.state_group_record(&chat).unwrap().profile.name,
        "new native profile"
    );

    // A clean client's DB-only archive still needs the saved-row adoption.
    assert!(
        !phone
            .client
            .pending_group_projection_updates
            .contains(&chat_hex)
    );
    assert!(!phone.client.state_group_record(&chat).unwrap().archived);
    phone
        .app
        .set_group_archived("alice", &chat_hex, true)
        .unwrap();
    phone.client.drive_invitation_decisions().await;
    assert!(phone.client.state_group_record(&chat).unwrap().archived);
    assert!(
        phone
            .app
            .group("alice", &chat_hex)
            .unwrap()
            .unwrap()
            .archived
    );
    assert!(store.leave_request(&chat).unwrap().is_none());
}

/// A real pending admin invitation can be declined while ordinary Leave is
/// refused before a native request exists. Both automatic Add paths must hold
/// it; a real sibling's later acceptance wakes only that generation's gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declined_generation_holds_automatic_adds_until_a_later_accept() {
    use cgka_traits::storage::{GroupStorage as _, LeaveRequestStorage as _};
    async fn exchange_decision(
        relay: &ScriptedPushRelayClient,
        source: &mut Device,
        receiver: &mut Device,
        group: &GroupId,
        chat: &GroupId,
        expected: ([u8; 32], u64, bool),
    ) {
        let (generation, version, declined) = expected;
        // Direct clients have no worker to advance scheduled convergence.
        // Await the real replicated value, not a fixed number of passes.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                source.client.drive_small_state().await;
                converge_device_group(&mut source.client, relay, &mut source.cursor, group, 1)
                    .await;
                converge_device_group(&mut receiver.client, relay, &mut receiver.cursor, group, 1)
                    .await;
                let held = receiver
                    .app
                    .account_storage("alice")
                    .unwrap()
                    .app_storage()
                    .invitation_decision(&hex::encode(chat.as_slice()), &generation)
                    .unwrap();
                if held.is_some_and(|held| held.version == version && held.declined == declined) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the authenticated decision reaches its sibling");
    }
    let (relay, [first, second, mut laptop]) = alice_devices::<3>().await;
    let (mut tablet, mut phone) = if first.slot_hex() < second.slot_hex() {
        (first, second)
    } else {
        (second, first)
    };
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    link(&relay, &mut phone, &mut tablet, "Tablet").await;
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    hold_key_packages(&relay, &mut phone, &mut tablet).await;
    phone.client.sibling_key_package_upkeep(&[]).await;
    let store = phone.app.account_storage("alice").unwrap();
    let stock = store.app_storage();
    let laptop_slot: [u8; 32] = hex::decode(laptop.slot_hex()).unwrap().try_into().unwrap();
    assert!(held_from(&phone, &laptop) > 0);
    assert!(
        stock
            .private_key_package_need(&laptop.slot_hex())
            .unwrap()
            .is_none()
    );

    // The real external admin selects Phone and Tablet in ONE Add batch;
    // Laptop remains missing. Promoting their account in that Add makes a
    // pending invitation whose ordinary Leave is refused without busy state.
    let bob_dir = tempfile::tempdir().unwrap();
    AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap();
    let bob_app = crate::tests::canonical_membership::app_at(&bob_dir, relay.clone());
    let alice = phone
        .app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    remember_test_member_inbox(&bob_app, &alice, "wss://relay.example");
    let mut bob = bob_app.client("bob").await.unwrap();
    let mut invitations = Vec::new();
    for name in ["direct declined invitation", "gap declined invitation"] {
        let chat = bob.create_group(name, &[]).await.unwrap();
        let phone_key = published_key_package(&mut phone.client, &relay).await;
        let tablet_key = published_key_package(&mut tablet.client, &relay).await;
        let effects = bob
            .runtime
            .send(SendIntent::Invite {
                group_id: chat.clone(),
                key_packages: vec![phone_key, tablet_key],
                initial_admins: vec![MemberId::new(hex::decode(&alice).unwrap())],
            })
            .await
            .unwrap();
        bob.observe_drained_session_events(&effects).await.unwrap();
        deliver_new(&mut phone.client, &relay, &mut phone.cursor).await;
        phone.client.sync().await.unwrap();
        deliver_new(&mut tablet.client, &relay, &mut tablet.cursor).await;
        tablet.client.sync().await.unwrap();
        assert!(
            phone
                .client
                .state_group_record(&chat)
                .unwrap()
                .pending_confirmation
        );
        assert!(!joined(&laptop, &chat));
        assert_eq!(
            phone
                .client
                .runtime
                .chat_sibling_add_refusal(&chat)
                .unwrap(),
            None,
            "the pending admin chat otherwise admits same-account Adds"
        );
        bob.self_demote_admin(&chat).await.unwrap();
        deliver_new(&mut phone.client, &relay, &mut phone.cursor).await;
        deliver_new(&mut tablet.client, &relay, &mut tablet.cursor).await;
        receive_account_choice(&relay, &mut tablet, &mut phone, &chat, 1, true).await;
        assert!(store.leave_request(&chat).unwrap().is_none());
        assert!(phone.client.group_quiet(&chat).unwrap());
        invitations.push(chat);
    }
    let [direct, gap] = <[_; 2]>::try_from(invitations).unwrap();
    // Tablet has not learned the decline yet. Its real authenticated lower
    // claim is advisory and must survive Phone's later semantic hold.
    let claim = format!(
        "{{\"v\":1,\"from\":\"{}\",\"to\":\"{}\",\"chat\":\"{}\"}}",
        tablet.slot_hex(),
        laptop.slot_hex(),
        hex::encode(direct.as_slice())
    );
    assert!(
        tablet
            .client
            .send_device_group_message(&group, 458, claim)
            .await
            .unwrap()
    );
    converge_device_group(&mut tablet.client, &relay, &mut tablet.cursor, &group, 1).await;
    converge_device_group(&mut phone.client, &relay, &mut phone.cursor, &group, 1).await;
    for chat in [&direct, &gap] {
        let generation = store
            .invitation_admission(chat)
            .unwrap()
            .unwrap()
            .generation;
        exchange_decision(
            &relay,
            &mut phone,
            &mut tablet,
            &group,
            chat,
            (generation, 1, true),
        )
        .await;
    }
    phone.app.set_native_push_enabled("alice", true).unwrap();
    phone
        .app
        .upsert_push_registration(
            "alice",
            crate::PushPlatform::Fcm,
            "phone-token",
            &::nostr::prelude::Keys::generate().public_key().to_hex(),
            Some("wss://relay.example".to_owned()),
        )
        .unwrap();
    phone.client.share_push_registration().await.unwrap();
    let before = relay.published_event_ids().len();
    for _ in 0..2 {
        phone.client.drive_invitation_decisions().await;
        assert_eq!(
            relay.published_event_ids().len(),
            before,
            "an admin's owed decline must not remove and re-share its push token on retry"
        );
        for chat in [&direct, &gap] {
            assert!(store.leave_request(chat).unwrap().is_none());
            let generation = store
                .invitation_admission(chat)
                .unwrap()
                .unwrap()
                .generation;
            assert!(
                stock
                    .invitation_decision(&hex::encode(chat.as_slice()), &generation)
                    .unwrap()
                    .unwrap()
                    .declined
            );
            assert!(
                stock
                    .invitation_decision_work()
                    .unwrap()
                    .iter()
                    .any(|work| { work.decision.generation == generation && work.decline_owed }),
                "a refused native Leave keeps its exact decline work owed"
            );
        }
    }
    let held = held_from(&phone, &laptop);
    let tablet_taken = taken_from(&phone, &tablet);
    phone
        .client
        .add_linked_devices_to_chats(&[], &mut Default::default())
        .await;
    phone
        .client
        .fill_sibling_chat_gaps(&[], 10, &mut Default::default())
        .await;
    assert_eq!(
        taken_from(&phone, &laptop),
        0,
        "known Decline must not spend private stock on a new automatic Add"
    );
    assert_eq!(leaves_of(&phone, &laptop, &direct, &group), 0);
    assert_eq!(
        relay.published_event_ids().len(),
        before,
        "no new Add or claim on the automatic Add paths"
    );
    assert_eq!(held_from(&phone, &laptop), held);
    assert_eq!(taken_from(&phone, &laptop), 0);
    assert_eq!(taken_from(&phone, &tablet), tablet_taken);
    // Exercise final preparation independently of candidate selection: it
    // must still refuse before claiming the exact valid private package.
    let candidate = stock
        .received_private_key_packages_from(&laptop.slot_hex(), crate::unix_now_seconds())
        .unwrap()
        .remove(0);
    phone
        .client
        .add_sibling_to_chat(&direct, &laptop_slot, candidate)
        .await
        .unwrap();
    assert_eq!(
        held_from(&phone, &laptop),
        held,
        "final preparation also holds its allocation"
    );
    assert_eq!(taken_from(&phone, &laptop), 0);
    assert_eq!(relay.published_event_ids().len(), before);

    tablet.client.accept_group_invite(&direct).unwrap();
    let generation = store
        .invitation_admission(&direct)
        .unwrap()
        .unwrap()
        .generation;
    exchange_decision(
        &relay,
        &mut tablet,
        &mut phone,
        &group,
        &direct,
        (generation, 2, false),
    )
    .await;
    // An authenticated retained decision for a DIFFERENT generation does
    // not block the current one. This is negative input, never a native seed.
    let mut unrelated = stock
        .invitation_decision(
            &hex::encode(direct.as_slice()),
            &store
                .invitation_admission(&direct)
                .unwrap()
                .unwrap()
                .generation,
        )
        .unwrap()
        .unwrap();
    assert!(!unrelated.declined, "the genuine higher Accept is current");
    unrelated.generation[0] ^= 1;
    unrelated.version = 9;
    unrelated.declined = true;
    let unrelated_generation = unrelated.generation;
    let [(content, _)] =
        <[_; 1]>::try_from(crate::small_state::encode_invitation_decision_updates(&[
            unrelated,
        ]))
        .unwrap();
    assert!(
        tablet
            .client
            .send_device_group_message(&group, crate::small_state::KIND_SMALL_STATE_UPDATE, content)
            .await
            .unwrap()
    );
    exchange_decision(
        &relay,
        &mut tablet,
        &mut phone,
        &group,
        &direct,
        (unrelated_generation, 9, true),
    )
    .await;
    phone.client.drive_invitation_decisions().await;
    assert!(
        phone.client.group_quiet(&direct).unwrap(),
        "acceptance leaves no native Leave or held Commit"
    );
    assert!(
        phone.client.group_quiet(&group).unwrap(),
        "the device group is ready for an automatic Add"
    );
    let before = relay.published_event_ids().len();
    phone
        .client
        .fill_sibling_chat_gaps(&[], 10, &mut Default::default())
        .await;
    assert_eq!(
        taken_from(&phone, &laptop),
        0,
        "the original live lower claim still holds this gap after decline and accept"
    );
    assert_eq!(
        relay.published_event_ids().len(),
        before,
        "no renewed claim before its original expiry"
    );
    // The approver's independent direct flow does not use advisory gap claims.
    phone
        .client
        .add_linked_devices_to_chats(&[], &mut Default::default())
        .await;
    assert_eq!(taken_from(&phone, &laptop), 1);
    assert_eq!(leaves_of(&phone, &laptop, &direct, &group), 1);
    assert_eq!(leaves_of(&phone, &laptop, &gap, &group), 0);
    phone.client.sibling_key_package_upkeep(&[]).await;
    phone
        .client
        .fill_sibling_chat_gaps(&[], 10, &mut Default::default())
        .await;

    // Both the global eligibility snapshot and the declined chat's due pass
    // were consumed above. Only a winning app decision changes now: no chat
    // epoch, device-group pin, stock hand-off or new claimant wakes this gap.
    let pin = phone.client.runtime.epoch_pin(&group).unwrap();
    let chat_pin = phone.client.runtime.epoch_pin(&gap).unwrap();
    tablet.client.accept_group_invite(&gap).unwrap();
    let generation = store
        .invitation_admission(&gap)
        .unwrap()
        .unwrap()
        .generation;
    exchange_decision(
        &relay,
        &mut tablet,
        &mut phone,
        &group,
        &gap,
        (generation, 2, false),
    )
    .await;
    phone.client.drive_invitation_decisions().await;
    assert_eq!(phone.client.runtime.epoch_pin(&group).unwrap(), pin);
    assert_eq!(phone.client.runtime.epoch_pin(&gap).unwrap(), chat_pin);
    assert!(store.leave_request(&gap).unwrap().is_none());
    phone
        .client
        .fill_sibling_chat_gaps(&[], 10, &mut Default::default())
        .await;
    assert_eq!(
        taken_from(&phone, &laptop),
        2,
        "a higher Accept wakes the already permitted gap"
    );
    assert_eq!(leaves_of(&phone, &laptop, &gap, &group), 1);
    assert_eq!(leaves_of(&phone, &laptop, &direct, &group), 1);
    assert_eq!(taken_from(&phone, &tablet), tablet_taken);
    assert!(
        stock
            .private_key_package_need(&tablet.slot_hex())
            .unwrap()
            .is_none()
    );
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
    laptop
        .client
        .add_linked_devices_to_chats(&[], &mut Default::default())
        .await;
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
    lose_gap_opt_out(&relay, &mut high, &mut target, &group).await;
    converge_device_group(&mut low.client, &relay, &mut low.cursor, &group, 8).await;
    let staged = hold_gap_edit_recovery(&mut high, &group).await;
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
    // This valid lower claim arrives while local settings recovery is held.
    // It must survive both receipt and ordinary maintenance bookkeeping.
    deliver_new(&mut high.client, &relay, &mut high.cursor).await;
    high.client.run_due_maintenance().await.unwrap();
    assert!(
        high.roster(&group).devices[&target_slot]
            .settings
            .add_to_all_chats
    );
    release_and_cancel_gap_opt_out(&relay, &mut high, &target, &group, staged).await;
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
    low.client
        .fill_sibling_chat_gaps(&[], 1, &mut Default::default())
        .await;
    assert_eq!(relay.published_events.lock().unwrap().len(), before);
    assert_eq!(held_from(&low, &target), stock);

    tokio::time::timeout(Duration::from_secs(30), async {
        while !joined(&target, &chats[0]) {
            converge_device_group(&mut high.client, &relay, &mut high.cursor, &group, 1).await;
            // Run the actual gap/Welcome paths without the separate removal
            // driver: the assertion must hold while the claimant is Leaving,
            // before its ordinary removal could also invalidate the claim.
            high.client
                .fill_sibling_chat_gaps(&[], LINK_CHAT_ADDS_PER_PASS, &mut Default::default())
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

/// A terminally rejected Add rolls back to a quiet chat, but the live own
/// claim still prevents another stock spend. An independent chat progresses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_terminal_gap_add_waits_for_its_existing_claim_before_retrying() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let mut chats = chats(&mut phone, 2).await;
    chats.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    assert_eq!(taken_from(&phone, &laptop), 0);
    assert!(
        chats
            .iter()
            .all(|chat| leaves_of(&phone, &laptop, chat, &group) == 0)
    );

    // Accept the claim, then definitively reject the first chat's Commit.
    // The fixture gates actual publishes; it supplies no retry decision.
    let blocked = relay
        .blocked_publish_count
        .load(std::sync::atomic::Ordering::SeqCst);
    relay.block_next_publishes(2);
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut selection = Default::default();
        tokio::join!(
            phone.client.fill_sibling_chat_gaps(&[], 2, &mut selection),
            async {
                relay.wait_for_blocked_publishes(blocked + 1).await;
                relay.release_publish();
                relay.wait_for_blocked_publishes(blocked + 2).await;
                relay.reject_next_publish();
                relay.release_publish();
            }
        );
    })
    .await
    .expect("the claim and terminally rejected Commit complete");
    assert!(phone.client.group_quiet(&chats[0]).unwrap());
    assert_eq!(leaves_of(&phone, &laptop, &chats[0], &group), 0);
    assert_eq!(leaves_of(&phone, &laptop, &chats[1], &group), 1);
    assert_eq!(taken_from(&phone, &laptop), 2);
    let published = relay.published_event_ids();
    phone
        .client
        .fill_sibling_chat_gaps(&[], 2, &mut Default::default())
        .await;
    assert_eq!(
        relay.published_event_ids(),
        published,
        "no fresh claim or Add"
    );
    assert_eq!(
        taken_from(&phone, &laptop),
        2,
        "no fresh private stock spend"
    );
    lose_gap_opt_out(&relay, &mut phone, &mut laptop, &group).await;
    let staged = hold_gap_edit_recovery(&mut phone, &group).await;
    phone.client.run_due_maintenance().await.unwrap();
    let laptop_slot: [u8; 32] = hex::decode(laptop.slot_hex()).unwrap().try_into().unwrap();
    assert!(
        phone.roster(&group).devices[&laptop_slot]
            .settings
            .add_to_all_chats
    );
    release_and_cancel_gap_opt_out(&relay, &mut phone, &laptop, &group, staged).await;
    let published = relay.published_event_ids();
    phone
        .client
        .fill_sibling_chat_gaps(&[], 2, &mut Default::default())
        .await;
    assert_eq!(
        relay.published_event_ids().len(),
        published.len(),
        "a transient settings hold keeps the original live claim"
    );
    assert_eq!(
        taken_from(&phone, &laptop),
        2,
        "cancelling the hold cannot spend before the original claim expires"
    );
    assert_eq!(leaves_of(&phone, &laptop, &chats[0], &group), 0);
}

/// An unreadable target row cannot prevent a healthy later sibling from
/// filling the same chat. Both stock and settings readiness fail locally;
/// the approver's direct post-link pass also isolates settings read errors.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_target_state_does_not_starve_another_sibling_in_the_same_chat() {
    for (corrupt_settings, direct) in [(false, false), (true, false), (true, true)] {
        let (relay, [mut phone, first, second]) = alice_devices::<3>().await;
        let (mut first, mut second) = if first.slot_hex() < second.slot_hex() {
            (first, second)
        } else {
            (second, first)
        };
        let chat = chats(&mut phone, 1).await.remove(0);
        let group = link(&relay, &mut phone, &mut first, "First").await;
        hold_key_packages(&relay, &mut phone, &mut first).await;
        link(&relay, &mut phone, &mut second, "Second").await;
        hold_key_packages(&relay, &mut phone, &mut second).await;
        assert_eq!(leaves_of(&phone, &first, &chat, &group), 0);
        assert_eq!(leaves_of(&phone, &second, &chat, &group), 0);
        if corrupt_settings {
            for device in [&mut phone, &mut first, &mut second] {
                converge_device_group(&mut device.client, &relay, &mut device.cursor, &group, 8)
                    .await;
            }
            phone
                .client
                .rename_linked_device(&first.slot_hex(), "Unreadable settings")
                .await
                .unwrap();
            // Corrupt a row written by the real host command, not a synthetic
            // intention that supplies the standing this owner should derive.
            account_database(&phone.app)
                .execute(
                    "UPDATE device_renames SET label = x'00' WHERE slot_id_hex = ?1",
                    [first.slot_hex()],
                )
                .unwrap();
        } else {
            account_database(&phone.app)
                .execute(
                    "UPDATE private_key_packages_received
                 SET not_before = 'unreadable', not_after = 'unreadable'
                 WHERE issuer_slot_hex = ?1",
                    [first.slot_hex()],
                )
                .unwrap();
        }
        if direct {
            let links = phone
                .app
                .account_storage("alice")
                .unwrap()
                .app_storage()
                .device_links()
                .unwrap();
            let linked_slots: Vec<_> = links
                .iter()
                .filter(|link| link.group_id_hex == hex::encode(group.as_slice()))
                .map(|link| link.slot_hex.as_str())
                .collect();
            assert_eq!(
                linked_slots,
                vec![first.slot_hex().as_str(), second.slot_hex().as_str()],
                "the unreadable device precedes the healthy device in the direct pass"
            );
            phone
                .client
                .add_linked_devices_to_chats(&[], &mut Default::default())
                .await;
        } else {
            phone
                .client
                .fill_sibling_chat_gaps(&[], 2, &mut Default::default())
                .await;
        }
        assert_eq!(taken_from(&phone, &first), 0);
        assert_eq!(
            taken_from(&phone, &second),
            1,
            "the healthy target progresses, settings row corrupt: {corrupt_settings}, direct: {direct}"
        );
        assert_eq!(leaves_of(&phone, &second, &chat, &group), 1);
    }
}

/// A settings journal read failure retains only that receiver's debt. The
/// healthy later receiver still receives its actual inline or Blossom history.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_history_target_does_not_starve_another_sibling() {
    use crate::tests::device_group::history_delivery::{local_blossom, send_text, use_blossom};
    use cgka_traits::app_components::BLOSSOM_LOCATOR_KIND_V1;
    use cgka_traits::storage::SiblingAddStorage as _;

    for blossom in [false, true] {
        let (relay, [mut phone, first, second]) = alice_devices::<3>().await;
        let (mut first, mut second) = if first.slot_hex() < second.slot_hex() {
            (first, second)
        } else {
            (second, first)
        };
        if blossom {
            // Only this real HTTP fixture needs the existing dev dial opt-in;
            // reopen so both transports are built with that configuration.
            phone.app.config.allow_loopback_blob_endpoints = true;
            second.app.config.allow_loopback_blob_endpoints = true;
            phone = reopen(phone).await;
            second = reopen(second).await;
        }
        let chat = chats(&mut phone, 1).await.remove(0);
        let server = blossom.then(local_blossom);
        if let Some(server) = &server {
            use_blossom(
                &mut phone.client,
                &chat,
                BLOSSOM_LOCATOR_KIND_V1,
                &server.url,
            )
            .await;
        }
        let content = if blossom {
            "history".repeat(20_000)
        } else {
            "before either sibling".to_owned()
        };
        let message = send_text(&mut phone.client, &chat, &content).await;
        let group = link(&relay, &mut phone, &mut first, "First").await;
        hold_key_packages(&relay, &mut phone, &mut first).await;
        link(&relay, &mut phone, &mut second, "Second").await;
        hold_key_packages(&relay, &mut phone, &mut second).await;
        phone
            .client
            .fill_sibling_chat_gaps(&[], 2, &mut Default::default())
            .await;
        for receiver in [&first, &second] {
            assert_eq!(leaves_of(&phone, receiver, &chat, &group), 1);
        }
        let account = phone.app.account_storage("alice").unwrap();
        let storage = account.app_storage();
        let adds = account.sibling_adds().unwrap();
        assert_eq!(
            adds.len(),
            2,
            "real confirmed Adds owe both receivers history"
        );
        assert!(adds.iter().all(|add| add.group_id == chat));
        if blossom {
            phone.client.drive_history_deliveries().await;
            let due = storage
                .due_blossom_history_deliveries(u64::MAX / 2)
                .unwrap();
            assert_eq!(due.len(), 2, "both real histories exceed the inline limit");
            assert_eq!(due[0].receiver_slot_hex, first.slot_hex());
        }
        for device in [&mut phone, &mut first, &mut second] {
            converge_device_group(&mut device.client, &relay, &mut device.cursor, &group, 8).await;
        }
        phone
            .client
            .rename_linked_device(&first.slot_hex(), "Unreadable history settings")
            .await
            .unwrap();
        assert_eq!(
            account_database(&phone.app)
                .execute(
                    "UPDATE device_renames SET label = x'00' WHERE slot_id_hex = ?1",
                    [first.slot_hex()],
                )
                .unwrap(),
            1,
            "fault a journal row produced by the actual host edit"
        );
        if blossom {
            let before = storage.unsent_history_deliveries().unwrap();
            let bad = before
                .iter()
                .find(|owed| owed.receiver_slot_hex == first.slot_hex())
                .unwrap();
            let upload = phone
                .client
                .prepare_history_upload()
                .unwrap()
                .expect("the healthy later history is prepared");
            let after = storage.unsent_history_deliveries().unwrap();
            let deferred = after
                .iter()
                .find(|owed| owed.receiver_slot_hex == first.slot_hex())
                .unwrap();
            assert_eq!(
                deferred.owed_at, bad.owed_at,
                "backoff does not renew retention"
            );
            assert_eq!(deferred.blossom_attempts, bad.blossom_attempts + 1);
            assert!(deferred.blossom_due_at > bad.blossom_due_at);
            let outcome = upload.run().await;
            assert!(phone.client.finish_history_upload(outcome).await);
        } else {
            phone.client.drive_history_deliveries().await;
        }
        let remaining = storage.unsent_history_deliveries().unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "only the unreadable receiver stays owed, Blossom: {blossom}"
        );
        assert_eq!(remaining[0].receiver_slot_hex, first.slot_hex());
        assert_eq!(
            remaining[0].owed_at,
            adds.iter()
                .find(|add| hex::encode(add.slot) == first.slot_hex())
                .unwrap()
                .added_at
        );
        deliver_new(&mut second.client, &relay, &mut second.cursor).await;
        second.client.join_stashed_sibling_welcomes().await;
        assert!(
            joined(&second, &chat),
            "the receiver joins its actual sibling Welcome"
        );
        second.client.drive_history_deliveries().await;
        if blossom {
            second.client.drive_history_blobs().await;
        }
        let imported = second
            .app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .timeline_message(&hex::encode(chat.as_slice()), &message)
            .unwrap()
            .expect("the healthy sibling imports the actual history");
        assert_eq!(imported.plaintext, content);
        assert_eq!(
            second
                .app
                .account_storage("alice")
                .unwrap()
                .app_storage()
                .app_event_import_source(&hex::encode(chat.as_slice()), &message)
                .unwrap(),
            Some(hex::decode(phone.slot_hex()).unwrap().try_into().unwrap()),
            "the message came from the history delivery, not ordinary relay backlog"
        );
    }
}

/// A successful send call may retain an unconfirmed Commit. The next
/// sibling must not publish a claim for this already-busy chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_gap_add_does_not_claim_the_next_sibling() {
    let (relay, [mut phone, first, second]) = alice_devices::<3>().await;
    let (mut first, mut second) = if first.slot_hex() < second.slot_hex() {
        (first, second)
    } else {
        (second, first)
    };
    let chat = chats(&mut phone, 1).await.remove(0);
    let group = link(&relay, &mut phone, &mut first, "First").await;
    hold_key_packages(&relay, &mut phone, &mut first).await;
    link(&relay, &mut phone, &mut second, "Second").await;
    hold_key_packages(&relay, &mut phone, &mut second).await;
    assert_eq!(leaves_of(&phone, &first, &chat, &group), 0);
    assert_eq!(leaves_of(&phone, &second, &chat, &group), 0);
    assert!(phone.client.group_quiet(&chat).unwrap());
    let before = relay.published_event_ids().len();
    let blocked = relay
        .blocked_publish_count
        .load(std::sync::atomic::Ordering::SeqCst);
    relay.block_next_publishes(2);
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut selection = Default::default();
        tokio::join!(
            phone.client.fill_sibling_chat_gaps(&[], 2, &mut selection),
            async {
                relay.wait_for_blocked_publishes(blocked + 1).await;
                relay.release_publish();
                relay.wait_for_blocked_publishes(blocked + 2).await;
                relay.zero_ack_next_publish();
                relay.release_publish();
            }
        );
    })
    .await
    .expect("the claim is accepted but the Commit is unconfirmed");
    assert!(!phone.client.group_quiet(&chat).unwrap());
    assert_eq!(taken_from(&phone, &first), 1);
    assert_eq!(taken_from(&phone, &second), 0);
    assert_eq!(
        relay.published_event_ids().len(),
        before + 1,
        "only the first sibling's claim was published"
    );
}

/// Recovering a quarantined chat wakes its missing-membership work without
/// a device-group or chat epoch change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovering_a_quarantined_chat_wakes_gap_filling() {
    use cgka_traits::storage::GroupStorage;

    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let chat = chats(&mut phone, 1).await.remove(0);
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    let storage = phone.app.account_storage("alice").unwrap();
    let original = storage.get_group(&chat).unwrap();
    let mut damaged = original.clone();
    damaged.protocol_profile = cgka_traits::group::ProtocolProfile::Legacy;
    storage.put_group(&damaged).unwrap();
    let mut phone = reopen(phone).await;
    assert_eq!(phone.client.quarantined_groups().len(), 1);
    assert_eq!(taken_from(&phone, &laptop), 0);
    let pin = phone.client.runtime.epoch_pin(&group).unwrap();
    phone
        .client
        .fill_sibling_chat_gaps(&[], 1, &mut Default::default())
        .await;
    assert_eq!(taken_from(&phone, &laptop), 0);

    storage.put_group(&original).unwrap();
    assert!(phone.client.retry_hydrate_quarantined_group(&chat).unwrap());
    phone.client.drain_pending_session_events().await.unwrap();
    assert_eq!(phone.client.runtime.epoch_pin(&group).unwrap(), pin);
    assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 0);
    phone
        .client
        .fill_sibling_chat_gaps(&[], 1, &mut Default::default())
        .await;
    assert_eq!(taken_from(&phone, &laptop), 1);
    assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 1);
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
    phone
        .client
        .add_linked_devices_to_chats(&[], &mut Default::default())
        .await;
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
    phone
        .client
        .add_linked_devices_to_chats(&[], &mut Default::default())
        .await;
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

    phone
        .client
        .add_linked_devices_to_chats(&[], &mut Default::default())
        .await;
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
    assert_eq!(
        phone
            .client
            .add_linked_devices_to_chats(&[], &mut Default::default())
            .await,
        0
    );
    assert!(held_from(&phone, &laptop) > 0);
    assert_eq!(taken_from(&phone, &laptop), 0);
    assert!(!joined(&laptop, &chats[0]));

    passes(&relay, &mut [&mut phone, &mut laptop], 4).await;
    assert!(joined(&laptop, &chats[0]));
    assert_eq!(taken_from(&phone, &laptop), 1);
}

/// Both automatic Add paths leave private stock untouched while a local
/// opt-out still needs replay. Once the user enables the settled setting,
/// either path can proceed; retaining the applied edit never blocks it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_adds_wait_for_a_lost_local_old_chat_toggle() {
    for resume_with_gap in [false, true] {
        let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
        let chat = chats(&mut phone, 1).await.remove(0);
        let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
        hold_key_packages(&relay, &mut phone, &mut laptop).await;
        for device in [&mut phone, &mut laptop] {
            converge_device_group(&mut device.client, &relay, &mut device.cursor, &group, 8).await;
        }
        let slot_hex = laptop.slot_hex();
        let slot: [u8; 32] = hex::decode(&slot_hex).unwrap().try_into().unwrap();
        phone
            .client
            .update_linked_device_settings(&slot_hex, Some(false), None, None)
            .await
            .unwrap();
        for platform in ["fork-a", "fork-b"] {
            let edit = laptop
                .client
                .runtime
                .edit_device_roster_entry(&group, &slot, &[], |entry| {
                    entry.platform = platform.to_owned();
                })
                .await
                .unwrap();
            assert!(matches!(
                edit,
                marmot_session::DeviceRosterEdit::Committed(_)
            ));
        }
        for device in [&mut phone, &mut laptop] {
            converge_device_group(&mut device.client, &relay, &mut device.cursor, &group, 8).await;
        }
        assert!(
            phone.roster(&group).devices[&slot]
                .settings
                .add_to_all_chats,
            "the opt-out lost to the longer non-user branch"
        );
        assert!(held_from(&phone, &laptop) > 0);
        assert_eq!(
            phone
                .client
                .add_linked_devices_to_chats(&[], &mut Default::default())
                .await,
            0
        );
        phone
            .client
            .fill_sibling_chat_gaps(&[], 1, &mut Default::default())
            .await;
        assert_eq!(
            taken_from(&phone, &laptop),
            0,
            "neither path spends stock for a pending opt-out"
        );
        assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 0);

        phone.client.try_device_rename_upkeep().await.unwrap();
        for device in [&mut phone, &mut laptop] {
            converge_device_group(&mut device.client, &relay, &mut device.cursor, &group, 8).await;
        }
        assert!(
            !phone.roster(&group).devices[&slot]
                .settings
                .add_to_all_chats
        );
        phone
            .client
            .update_linked_device_settings(&slot_hex, Some(true), None, None)
            .await
            .unwrap();
        if resume_with_gap {
            account_database(&phone.app)
                .execute(
                    "UPDATE device_links SET decided_at = decided_at - ?1",
                    [i64::try_from(LINK_CHAT_ADD_SECS).unwrap()],
                )
                .unwrap();
            assert_eq!(
                phone
                    .client
                    .add_linked_devices_to_chats(&[], &mut Default::default())
                    .await,
                0
            );
            phone
                .client
                .fill_sibling_chat_gaps(&[], 1, &mut Default::default())
                .await;
        } else {
            assert_eq!(
                phone
                    .client
                    .add_linked_devices_to_chats(&[], &mut Default::default())
                    .await,
                1
            );
        }
        assert_eq!(taken_from(&phone, &laptop), 1);
        assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 1);
    }
}

/// Cancelling a pending opt-out changes only local intention state. With a
/// second eligible sibling keeping sender readiness true, the effective target
/// set must wake the missing sibling even though the DG pin never changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_a_lost_toggle_wakes_gap_targets_without_a_roster_change() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let chat = chats(&mut phone, 1).await.remove(0);
    let group = link(&relay, &mut phone, &mut tablet, "Tablet").await;
    passes(&relay, &mut [&mut phone, &mut tablet], 4).await;
    assert!(joined(&tablet, &chat));
    assert_eq!(leaves_of(&phone, &tablet, &chat, &group), 1);
    assert_eq!(link(&relay, &mut phone, &mut laptop, "Laptop").await, group);
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    for device in [&mut phone, &mut laptop, &mut tablet] {
        converge_device_group(&mut device.client, &relay, &mut device.cursor, &group, 8).await;
    }
    let slot_hex = laptop.slot_hex();
    let slot: [u8; 32] = hex::decode(&slot_hex).unwrap().try_into().unwrap();
    phone
        .client
        .update_linked_device_settings(&slot_hex, Some(false), None, None)
        .await
        .unwrap();
    for platform in ["fork-a", "fork-b"] {
        let edit = laptop
            .client
            .runtime
            .edit_device_roster_entry(&group, &slot, &[], |entry| {
                entry.platform = platform.to_owned();
            })
            .await
            .unwrap();
        assert!(matches!(
            edit,
            marmot_session::DeviceRosterEdit::Committed(_)
        ));
    }
    for device in [&mut phone, &mut laptop, &mut tablet] {
        converge_device_group(&mut device.client, &relay, &mut device.cursor, &group, 8).await;
    }
    assert!(
        phone.roster(&group).devices[&slot]
            .settings
            .add_to_all_chats
    );
    assert!(held_from(&phone, &laptop) > 0);
    let pin = phone.client.runtime.epoch_pin(&group).unwrap();
    let tablet_taken = taken_from(&phone, &tablet);
    phone
        .client
        .fill_sibling_chat_gaps(&[], 1, &mut Default::default())
        .await;
    let published = relay.published_event_ids();
    phone
        .client
        .fill_sibling_chat_gaps(&[], 1, &mut Default::default())
        .await;
    assert_eq!(
        relay.published_event_ids(),
        published,
        "pending work starts no claim or Add"
    );
    assert_eq!(taken_from(&phone, &laptop), 0);
    assert_eq!(taken_from(&phone, &tablet), tablet_taken);
    assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 0);

    // This covered no-op cancels the lost disable before recovery can replay
    // it. The other eligible target and claimant set remain exactly the same.
    phone
        .client
        .update_linked_device_settings(&slot_hex, Some(true), None, None)
        .await
        .unwrap();
    assert_eq!(phone.client.runtime.epoch_pin(&group).unwrap(), pin);
    phone
        .client
        .fill_sibling_chat_gaps(&[], 1, &mut Default::default())
        .await;
    assert_eq!(
        taken_from(&phone, &laptop),
        1,
        "local target eligibility wakes the chat without a DG epoch event"
    );
    assert_eq!(taken_from(&phone, &tablet), tablet_taken);
    assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 1);
    assert_eq!(leaves_of(&phone, &tablet, &chat, &group), 1);
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
    assert!(!phone.client.runtime.unhydrated_group_ids().is_empty());
    assert!(
        phone.client.group_quiet(&group).unwrap(),
        "unrelated unhydrated chats do not hide the quiet device group"
    );
    assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 1);
    assert_eq!(taken_from(&phone, &laptop), before + 1);
    assert_eq!(
        phone
            .client
            .runtime
            .owed_sibling_welcomes(Timestamp(crate::unix_now_seconds()))
            .unwrap()
            .iter()
            .filter(|welcome| welcome.group_id == chat)
            .count(),
        1,
        "the deferred device-group route is not installed yet; the Welcome stays durable"
    );

    // The foreground creation above hydrated/tagged the device group. Use
    // its existing route installer, as the post-hydration reconcile does,
    // while leaving the unrelated old chat unhydrated. Initial delivery for
    // the next creation must not depend on that old chat's readiness.
    assert!(phone.client.ensure_device_group_route(&group).unwrap());
    let ready = phone
        .client
        .create_group("ready device group", &[])
        .await
        .unwrap();
    assert!(!phone.client.runtime.unhydrated_group_ids().is_empty());
    assert_eq!(leaves_of(&phone, &laptop, &ready, &group), 1);
    assert_eq!(taken_from(&phone, &laptop), before + 2);
    assert!(
        phone
            .client
            .runtime
            .owed_sibling_welcomes(Timestamp(crate::unix_now_seconds()))
            .unwrap()
            .iter()
            .all(|welcome| welcome.group_id != ready && welcome.group_id != chat),
        "the ready device group carries both the new and retained initial Welcomes"
    );
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

/// Older clients can participate in the device group without supporting a
/// chat's optional retention component. Mint that client's authentic private
/// package with its persisted signer and private bundle, never altered bytes.
fn private_package_with_lifetime(
    issuer: &Device,
    receiver: &Device,
    group: &GroupId,
    template: &cgka_traits::storage::IssuedPrivateKeyPackage,
    retention: bool,
    lifetime: (u64, u64),
) -> KeyPackage {
    use cgka_engine::device_tag::seal_device_tag;
    use cgka_engine::provider::EngineOpenMlsProvider;
    use cgka_traits::app_components::{
        APP_COMPONENTS_COMPONENT_ID, DEVICE_TAG_COMPONENT_ID, GROUP_MESSAGE_RETENTION_COMPONENT_ID,
        decode_components_list, encode_components_list,
    };
    use cgka_traits::storage::{AccountDeviceSignerStorage as _, StorageProvider as _};
    use openmls::extensions::{AppDataDictionaryExtension, Extension};
    use openmls::prelude::{
        CredentialWithKey, KeyPackage as MlsKeyPackage, Lifetime, MlsMessageBodyIn, MlsMessageIn,
        MlsMessageOut, ProtocolVersion,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use tls_codec::{Deserialize as _, Serialize as _};

    let storage = issuer.app.account_storage("alice").unwrap();
    let account = issuer.app.account_home().account("alice").unwrap();
    let identity = MemberId::new(hex::decode(account.account_id_hex).unwrap());
    let binding = storage.account_device_signer(&identity).unwrap().unwrap();
    let suite = cgka_engine::DEFAULT_CIPHERSUITE;
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        suite.signature_algorithm(),
    )
    .unwrap();
    let MlsMessageBodyIn::KeyPackage(template) =
        MlsMessageIn::tls_deserialize_exact(&template.key_package)
            .unwrap()
            .extract()
    else {
        panic!("expected a KeyPackage")
    };
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let template = template.validate(&crypto, ProtocolVersion::Mls10).unwrap();
    let leaf = template.leaf_node();
    let mut dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .unwrap()
        .dictionary()
        .clone();
    let mut supported =
        decode_components_list(dictionary.get(&APP_COMPONENTS_COMPONENT_ID).unwrap()).unwrap();
    if !retention {
        supported.remove(&GROUP_MESSAGE_RETENTION_COMPONENT_ID);
    }
    dictionary.insert(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&supported),
    );
    let slot = hex::decode(issuer.slot_hex()).unwrap().try_into().unwrap();
    dictionary.insert(
        DEVICE_TAG_COMPONENT_ID,
        seal_device_tag(
            &crypto,
            &issuer.roster(group).leaf_tag_key,
            &slot,
            &signer,
            signer.public(),
        )
        .unwrap(),
    );
    let mut extensions = leaf.extensions().clone();
    extensions
        .add_or_replace(Extension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ))
        .unwrap();
    let now = crate::unix_now_seconds();
    let bundle = MlsKeyPackage::builder()
        .leaf_node_capabilities(leaf.capabilities().clone())
        .leaf_node_extensions(extensions)
        .key_package_lifetime(Lifetime::init(lifetime.0, lifetime.1))
        .build(
            suite,
            &EngineOpenMlsProvider::<storage_sqlite::SqliteAccountStorage>::new(
                &crypto,
                storage.mls_storage(),
            ),
            &signer,
            CredentialWithKey {
                credential: leaf.credential().clone(),
                signature_key: signer.public().into(),
            },
        )
        .unwrap();
    let message: MlsMessageOut = bundle.key_package().clone().into();
    let package = KeyPackage::new(message.tls_serialize_detached().unwrap())
        .with_protocol_profile(cgka_traits::group::ProtocolProfile::Current);
    let metadata = marmot_session::key_package_metadata(&package).unwrap();
    storage
        .private_key_package_storage()
        .unwrap()
        .put_issued_private_key_package(&cgka_traits::storage::IssuedPrivateKeyPackage {
            key_package_ref: hex::decode(&metadata.key_package_ref_hex).unwrap(),
            recipient_slot: hex::decode(receiver.slot_hex())
                .unwrap()
                .try_into()
                .unwrap(),
            not_before: metadata.not_before,
            not_after: metadata.not_after,
            key_package: package.bytes().to_vec(),
            issued_at: now,
            hand_off_queued: true,
            counted: true,
            request_id: None,
        })
        .unwrap();
    package
}

fn older_private_package_without_retention(
    issuer: &Device,
    receiver: &Device,
    group: &GroupId,
    template: &cgka_traits::storage::IssuedPrivateKeyPackage,
) -> KeyPackage {
    let now = crate::unix_now_seconds();
    private_package_with_lifetime(
        issuer,
        receiver,
        group,
        template,
        false,
        (now - 3600, now + 29 * 24 * 3600),
    )
}

async fn hand_over_stock(
    relay: &ScriptedPushRelayClient,
    phone: &mut Device,
    laptop: &mut Device,
    group: &GroupId,
    key_packages: Vec<KeyPackage>,
) {
    use base64::Engine as _;
    let hand_off = marmot_session::PrivateKeyPackageHandOff {
        from: hex::decode(laptop.slot_hex()).unwrap().try_into().unwrap(),
        to: hex::decode(phone.slot_hex()).unwrap().try_into().unwrap(),
        key_packages,
    };
    laptop
        .client
        .send_device_group_message(
            group,
            marmot_session::KIND_PRIVATE_KEY_PACKAGE_HAND_OFF,
            base64::engine::general_purpose::STANDARD.encode(hand_off.encode().unwrap()),
        )
        .await
        .unwrap();
    deliver_new(&mut phone.client, relay, &mut phone.cursor).await;
}

async fn compatible_private_stock_reaches_the_chat(founding: bool) {
    use cgka_traits::app_components::GROUP_MESSAGE_RETENTION_COMPONENT_ID;
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let options = || AppCreateGroupOptions {
        disappearing_message_secs: 60,
        ..AppCreateGroupOptions::default()
    };
    let existing = if founding {
        None
    } else {
        Some(
            phone
                .client
                .create_group_with_options("existing retention", &[], options())
                .await
                .unwrap(),
        )
    };
    let plain = if let Some(retention) = &existing {
        let plain = phone.client.create_group("plain", &[]).await.unwrap();
        phone
            .app
            .set_chat_pinned("alice", &hex::encode(retention.as_slice()), true)
            .unwrap();
        let order = phone
            .app
            .chat_list("alice", true)
            .unwrap()
            .into_iter()
            .map(|row| row.group_id_hex)
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                hex::encode(retention.as_slice()),
                hex::encode(plain.as_slice())
            ]
        );
        Some(plain)
    } else {
        None
    };
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    let issuer = laptop.slot_hex();
    let receiver = phone.slot_hex();
    let newer = laptop
        .client
        .runtime
        .issued_private_key_packages()
        .unwrap()
        .into_iter()
        .find(|record| hex::encode(record.recipient_slot) == receiver)
        .unwrap();
    let older = older_private_package_without_retention(&laptop, &phone, &group, &newer);
    let older_metadata = marmot_session::key_package_metadata(&older).unwrap();
    let mut older_refs = vec![older_metadata.key_package_ref_hex.clone()];
    let mut older_stock = vec![older];
    if plain.is_some() {
        let second = older_private_package_without_retention(&laptop, &phone, &group, &newer);
        older_refs.push(
            marmot_session::key_package_metadata(&second)
                .unwrap()
                .key_package_ref_hex,
        );
        older_stock.push(second);
    }
    let newer_package = KeyPackage::new(newer.key_package)
        .with_protocol_profile(cgka_traits::group::ProtocolProfile::Current);
    let newer_metadata = marmot_session::key_package_metadata(&newer_package).unwrap();
    assert!(older_metadata.not_after < newer_metadata.not_after);
    assert!(
        !older_metadata
            .app_components
            .contains(&GROUP_MESSAGE_RETENTION_COMPONENT_ID)
    );
    assert!(
        newer_metadata
            .app_components
            .contains(&GROUP_MESSAGE_RETENTION_COMPONENT_ID)
    );
    let storage = phone.app.account_storage("alice").unwrap().app_storage();
    storage
        .delete_received_private_key_packages_from(&issuer)
        .unwrap();
    hand_over_stock(&relay, &mut phone, &mut laptop, &group, older_stock).await;
    assert_eq!(
        held_from(&phone, &laptop),
        older_refs.len(),
        "the real trusted hand-off admits the older stock"
    );
    let no_compatible = if founding {
        phone
            .client
            .create_group_with_options("no compatible stock", &[], options())
            .await
            .unwrap()
    } else {
        phone
            .client
            .add_linked_devices_to_chats(&[], &mut Default::default())
            .await;
        existing.clone().unwrap()
    };
    assert_eq!(leaves_of(&phone, &laptop, &no_compatible, &group), 0);
    let prior_adds = usize::from(plain.is_some());
    if let Some(plain) = &plain {
        assert_eq!(
            leaves_of(&phone, &laptop, plain, &group),
            1,
            "the retention chat is first but must not hide the later plain chat"
        );
    }
    assert_eq!(taken_from(&phone, &laptop), prior_adds);
    assert!(storage.private_key_package_need(&issuer).unwrap().is_some());
    hand_over_stock(&relay, &mut phone, &mut laptop, &group, vec![newer_package]).await;
    assert_eq!(held_from(&phone, &laptop), 2);
    let chat = if founding {
        phone
            .client
            .create_group_with_options("compatible stock", &[], options())
            .await
            .unwrap()
    } else {
        phone
            .client
            .add_linked_devices_to_chats(&[], &mut Default::default())
            .await;
        existing.unwrap()
    };
    assert_eq!(
        leaves_of(&phone, &laptop, &chat, &group),
        1,
        "newer compatible B must be reached behind older incompatible A (#2869)"
    );
    let remaining = storage
        .received_private_key_packages()
        .unwrap()
        .into_iter()
        .filter(|row| row.issuer_slot_hex == issuer)
        .collect::<Vec<_>>();
    assert_eq!(remaining.len(), 1);
    assert!(
        older_refs.contains(&remaining[0].key_package_ref_hex),
        "B is spent while the remaining incompatible allocation is retained"
    );
    assert_eq!(taken_from(&phone, &laptop), prior_adds + 1);
    assert!(
        phone
            .client
            .runtime
            .app_component(&chat, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .unwrap()
            .is_some(),
        "selection preserves the chat requirement"
    );
    deliver_new(&mut laptop.client, &relay, &mut laptop.cursor).await;
    laptop.client.run_due_maintenance().await.unwrap();
    assert!(
        joined(&laptop, &chat),
        "the selected B has its real private bundle and Welcome"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_link_add_reaches_compatible_private_stock_behind_older_stock() {
    compatible_private_stock_reaches_the_chat(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn founding_add_reaches_compatible_private_stock_behind_older_stock() {
    compatible_private_stock_reaches_the_chat(true).await;
}

/// A retention chat on `phone`, linked `laptop`, and the phone holding only
/// one time-usable KeyPackage from the laptop that lacks retention, with no
/// stock need recorded: the chat, the device group and that KeyPackage's ref.
async fn hold_only_stock_lacking_retention(
    relay: &ScriptedPushRelayClient,
    phone: &mut Device,
    laptop: &mut Device,
) -> (GroupId, GroupId, String) {
    let chat = phone
        .client
        .create_group_with_options(
            "retention",
            &[],
            AppCreateGroupOptions {
                disappearing_message_secs: 60,
                ..AppCreateGroupOptions::default()
            },
        )
        .await
        .unwrap();
    let group = link(relay, phone, laptop, "Laptop").await;
    hold_key_packages(relay, phone, laptop).await;
    // Held stock settles the first request's need, so a later request is
    // not paced behind it.
    phone.client.sibling_key_package_upkeep(&[]).await;
    let issuer = laptop.slot_hex();
    let template = laptop
        .client
        .runtime
        .issued_private_key_packages()
        .unwrap()
        .into_iter()
        .find(|record| hex::encode(record.recipient_slot) == phone.slot_hex())
        .unwrap();
    let older = older_private_package_without_retention(laptop, phone, &group, &template);
    let older_ref = marmot_session::key_package_metadata(&older)
        .unwrap()
        .key_package_ref_hex;
    let storage = phone.app.account_storage("alice").unwrap().app_storage();
    storage
        .delete_received_private_key_packages_from(&issuer)
        .unwrap();
    hand_over_stock(relay, phone, laptop, &group, vec![older]).await;
    let held = storage
        .received_private_key_packages_from(&issuer, crate::unix_now_seconds())
        .unwrap();
    assert_eq!(held.len(), 1);
    assert!(held[0].usable_at(crate::unix_now_seconds()));
    assert_eq!(storage.private_key_package_need(&issuer).unwrap(), None);
    (chat, group, older_ref)
}

/// A chat that finds only time-usable stock lacking what it requires keeps
/// its demand (mdk#2883): upkeep asks the sibling, whose device-group leaf
/// advertises the requirement, at the usual hourly pace, and the sibling's
/// ordinary answer completes the waiting Add while the older stock stays for
/// chats it fits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_compatibility_miss_asks_the_sibling_for_stock_it_can_use() {
    use cgka_traits::app_components::GROUP_MESSAGE_RETENTION_COMPONENT_ID;
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let (chat, group, older_ref) =
        hold_only_stock_lacking_retention(&relay, &mut phone, &mut laptop).await;
    let issuer = laptop.slot_hex();
    let storage = phone.app.account_storage("alice").unwrap().app_storage();

    // The request time is written before the send and put back when the
    // publication reaches no one, so a request time means it went out.
    phone.client.run_due_maintenance().await.unwrap();
    assert_eq!(leaves_of(&phone, &laptop, &chat, &group), 0);
    assert_eq!(taken_from(&phone, &laptop), 0, "A is never spent here");
    let requested = storage
        .private_key_package_need(&issuer)
        .unwrap()
        .and_then(|need| need.requested_at)
        .expect("the compatibility miss reaches the sibling as a request");
    phone.client.run_due_maintenance().await.unwrap();
    assert_eq!(
        storage
            .private_key_package_need(&issuer)
            .unwrap()
            .and_then(|need| need.requested_at),
        Some(requested),
        "a request for the same need waits an hour"
    );

    tokio::time::timeout(Duration::from_secs(30), async {
        while leaves_of(&phone, &laptop, &chat, &group) == 0 {
            deliver_new(&mut laptop.client, &relay, &mut laptop.cursor).await;
            laptop.client.run_due_maintenance().await.unwrap();
            deliver_new(&mut phone.client, &relay, &mut phone.cursor).await;
            phone.client.run_due_maintenance().await.unwrap();
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the sibling's answer completes the waiting Add");
    assert_eq!(taken_from(&phone, &laptop), 1);
    assert!(
        storage
            .received_private_key_packages_from(&issuer, crate::unix_now_seconds())
            .unwrap()
            .iter()
            .any(|record| record.key_package_ref_hex == older_ref),
        "A stays for chats it fits"
    );
    assert!(
        phone
            .client
            .runtime
            .app_component(&chat, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .unwrap()
            .is_some()
    );
    deliver_new(&mut laptop.client, &relay, &mut laptop.cursor).await;
    laptop.client.run_due_maintenance().await.unwrap();
    assert!(joined(&laptop, &chat));
}

/// A chat left waiting for compatible stock asks nothing while gap filling
/// would not add the sibling now (mdk#2883): here, while this device's
/// opt-out from "add to all my chats" is lost to a longer branch and its
/// intention still waits to settle. The waiter stays for once it settles.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_compatibility_miss_asks_nothing_while_a_settings_edit_waits() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let (_, group, _) = hold_only_stock_lacking_retention(&relay, &mut phone, &mut laptop).await;
    let issuer = laptop.slot_hex();
    let storage = phone.app.account_storage("alice").unwrap().app_storage();
    phone.client.run_due_maintenance().await.unwrap();
    assert!(
        storage
            .private_key_package_need(&issuer)
            .unwrap()
            .and_then(|need| need.requested_at)
            .is_some(),
        "the chat waits on the laptop's stock"
    );
    storage.delete_private_key_package_need(&issuer).unwrap();

    lose_gap_opt_out(&relay, &mut phone, &mut laptop, &group).await;
    assert_eq!(held_from(&phone, &laptop), 1, "no compatible stock arrived");
    phone.client.sibling_key_package_upkeep(&[]).await;
    assert_eq!(storage.private_key_package_need(&issuer).unwrap(), None);
}

/// The shared app preference runs after compatibility filtering. Repeated
/// advisory peeks reuse one batch; only actual claims retire its allocations.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compatible_private_stock_keeps_usable_order_and_longest_fallback() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let chat = phone
        .client
        .create_group_with_options(
            "retention",
            &[],
            AppCreateGroupOptions {
                disappearing_message_secs: 60,
                ..AppCreateGroupOptions::default()
            },
        )
        .await
        .unwrap();
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    hold_key_packages(&relay, &mut phone, &mut laptop).await;
    let issuer = hex::decode(laptop.slot_hex()).unwrap().try_into().unwrap();
    let template = laptop
        .client
        .runtime
        .issued_private_key_packages()
        .unwrap()
        .into_iter()
        .find(|row| hex::encode(row.recipient_slot) == phone.slot_hex())
        .unwrap();
    let now = crate::unix_now_seconds();
    let day = 24 * 3600;
    let definitions = [
        (false, now - 3600, now + 7 * day),
        (true, now - 3600, now + 8 * day),
        (true, now - 3600, now + 8 * day),
        (true, now - 3600, now + 10 * day),
        (true, now - 40 * day, now + 9 * day),
        (true, now - 40 * day, now + 11 * day),
    ];
    let packages = definitions
        .into_iter()
        .map(|(retention, before, after)| {
            private_package_with_lifetime(
                &laptop,
                &phone,
                &group,
                &template,
                retention,
                (before, after),
            )
        })
        .collect::<Vec<_>>();
    let references = packages
        .iter()
        .map(|package| {
            marmot_session::key_package_metadata(package)
                .unwrap()
                .key_package_ref_hex
        })
        .collect::<Vec<_>>();
    let mut tied = [references[1].clone(), references[2].clone()];
    tied.sort();
    let expected = [
        tied[0].clone(),
        tied[1].clone(),
        references[3].clone(),
        references[5].clone(),
        references[4].clone(),
    ];
    let storage = phone.app.account_storage("alice").unwrap().app_storage();
    storage
        .delete_received_private_key_packages_from(&laptop.slot_hex())
        .unwrap();
    let mut empty = Default::default();
    assert!(
        phone
            .client
            .next_private_key_package_for_chat(&chat, &issuer, &mut empty)
            .unwrap()
            .is_none()
    );
    hand_over_stock(&relay, &mut phone, &mut laptop, &group, packages).await;
    let mut selection = Default::default();
    for (index, expected) in expected.iter().enumerate() {
        let candidate = phone
            .client
            .next_private_key_package_for_chat(&chat, &issuer, &mut selection)
            .unwrap()
            .unwrap();
        assert_eq!(&candidate.key_package_ref_hex, expected);
        if index == 0 {
            // An advisory second peek (E's post-claim-effect check) must not
            // reread received stock or silently discard its first candidate.
            let database = account_database(&phone.app);
            database
                .execute_batch("ALTER TABLE private_key_packages_received RENAME TO held_aside")
                .unwrap();
            let again =
                phone
                    .client
                    .next_private_key_package_for_chat(&chat, &issuer, &mut selection);
            database
                .execute_batch("ALTER TABLE held_aside RENAME TO private_key_packages_received")
                .unwrap();
            assert_eq!(
                again.unwrap().unwrap().key_package_ref_hex,
                candidate.key_package_ref_hex
            );
        }
        selection.record_attempt(&issuer, &candidate.key_package_ref_hex);
        assert!(
            phone
                .client
                .take_private_key_package_exact(&issuer, &candidate)
                .unwrap()
        );
    }
    assert!(
        phone
            .client
            .next_private_key_package_for_chat(&chat, &issuer, &mut selection)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        storage
            .received_private_key_packages_from(&hex::encode(issuer), now)
            .unwrap()
            .into_iter()
            .map(|record| record.key_package_ref_hex)
            .collect::<Vec<_>>(),
        vec![references[0].clone()]
    );
    // Native projection can finish a previously failed hand-off while a
    // maintenance pass holds either empty or all-incompatible cached stock.
    // A new arrival must invalidate both, before E registers another waiter.
    let fresh = KeyPackage::new(template.key_package.clone())
        .with_protocol_profile(cgka_traits::group::ProtocolProfile::Current);
    let fresh_ref = marmot_session::key_package_metadata(&fresh)
        .unwrap()
        .key_package_ref_hex;
    hand_over_stock(&relay, &mut phone, &mut laptop, &group, vec![fresh.clone()]).await;
    let empty_after = phone
        .client
        .next_private_key_package_for_chat(&chat, &issuer, &mut empty)
        .unwrap()
        .map(|candidate| candidate.key_package_ref_hex);
    let incompatible_after = phone
        .client
        .next_private_key_package_for_chat(&chat, &issuer, &mut selection)
        .unwrap()
        .map(|candidate| candidate.key_package_ref_hex);
    assert_eq!(
        [empty_after, incompatible_after],
        [Some(fresh_ref.clone()), Some(fresh_ref.clone())]
    );
    let before_duplicate = storage
        .received_private_key_packages_from(&hex::encode(issuer), now)
        .unwrap();
    hand_over_stock(&relay, &mut phone, &mut laptop, &group, vec![fresh]).await;
    assert_eq!(
        storage
            .received_private_key_packages_from(&hex::encode(issuer), now)
            .unwrap(),
        before_duplicate
    );
    assert_eq!(
        phone
            .client
            .next_private_key_package_for_chat(&chat, &issuer, &mut selection)
            .unwrap()
            .unwrap()
            .key_package_ref_hex,
        fresh_ref,
        "duplicate reception preserves the selected allocation"
    );
}
