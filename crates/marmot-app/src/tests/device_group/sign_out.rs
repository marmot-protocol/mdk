//! Signing out through siblings (mdk#2628 item 3.6b, D67(2)). A device that
//! signs out commits its own roster entry as `leaving`, leaves itself only
//! the chats no sibling takes it out of, and wipes. A sibling that finds it
//! `leaving` removes it after a random delay, as if its user had decided to.
//! A device removed while signing out is not unlinked: it finishes signing
//! out instead.

use super::removal::{chat_with_both, pending_removals, published_count};
use super::*;
use crate::client::sign_out::SiblingSignOut;
use crate::messages::AppMessageIntent;
use crate::notifications::PushPlatform;
use crate::tests::canonical_membership::deliver_events;
use marmot_session::DeviceRosterEdit;

fn account_id_hex(app: &MarmotApp) -> String {
    app.account_home().account("alice").unwrap().account_id_hex
}

fn status_of(client: &AppClient, group: &GroupId, device: &AppClient) -> DeviceStatusV1 {
    roster(client, group).devices[&slot_of(device)].status
}

/// Run `phone`'s maintenance until it has decided a removal, passing its
/// random delay.
async fn decide_after_delay(phone: &mut AppClient, phone_app: &MarmotApp, laptop_slot: [u8; 32]) {
    let before = crate::unix_now_seconds();
    phone.run_due_maintenance().await.unwrap();
    if pending_removals(phone_app) == 0 {
        let decide_at = phone.leaving_siblings[&laptop_slot];
        assert!(
            (before..=crate::unix_now_seconds() + 30).contains(&decide_at),
            "a delay of up to 30 seconds"
        );
        phone.backdate_leaving_siblings(31);
        phone.run_due_maintenance().await.unwrap();
    }
    assert_eq!(pending_removals(phone_app), 1);
    assert!(phone.leaving_siblings.is_empty());
}

/// The laptop signs out through the phone. It commits its own entry as
/// `leaving`, and once that commit is confirmed it leaves the chat both are
/// in to the phone. The
/// phone sees the laptop `leaving` and, after its delay, removes it from the
/// device group and from the chat, recording the slot as `removed` at the
/// time it decided.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_signs_out_through_its_sibling() {
    let (mut devices, group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        laptop_app,
        mut laptop,
        ..
    } = devices;
    let laptop_slot = slot_of(&laptop);
    let mut phone_cursor = published_count(&relay);
    let _laptop_signing_out = laptop_app.begin_signing_out(&account_id_hex(&laptop_app));

    assert_eq!(
        laptop.sign_out_through_siblings_step().await.unwrap(),
        SiblingSignOut::Pending
    );
    assert_eq!(
        laptop.sign_out_through_siblings_step().await.unwrap(),
        SiblingSignOut::Confirmed {
            left_to_siblings: vec![hex::encode(chat.as_slice())],
        }
    );
    let entry = &roster(&laptop, &group).devices[&laptop_slot];
    assert_eq!(entry.status, DeviceStatusV1::Leaving);
    assert!(entry.tag_signature_key.is_some(), "every other field stays");

    deliver_new(&mut phone, &relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    assert_eq!(status_of(&phone, &group, &laptop), DeviceStatusV1::Leaving);
    assert!(
        phone
            .linked_devices()
            .unwrap()
            .iter()
            .any(|device| device.status == LinkedDeviceStatus::Leaving)
    );
    let before = crate::unix_now_seconds();
    decide_after_delay(&mut phone, &phone_app, laptop_slot).await;

    let after = roster(&phone, &group);
    assert!(!after.devices.contains_key(&laptop_slot));
    let record = &after.rejected_slots[&laptop_slot];
    assert_eq!(record.reason, RejectedSlotReasonV1::Removed);
    assert!(record.rejected_at >= before, "dated when the phone decided");
    assert!(
        phone
            .runtime
            .own_account_leaf_claims(&chat, &after)
            .unwrap()
            .is_empty(),
        "the phone took the laptop out of the chat"
    );
}

/// Only a chat where a sibling that is not `leaving` has a tagged leaf is
/// left to it. The laptop's own chat has no other leaf of the account, so the
/// laptop leaves it itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chat_with_no_sibling_in_it_is_left_by_the_device() {
    let (mut devices, _group) = tagging_devices().await;
    let shared = chat_with_both(&mut devices).await;
    let own = devices.laptop.create_group("notes", &[]).await.unwrap();
    assert!(devices.laptop.group_requires_account_devices(&own).unwrap());
    let _laptop_signing_out = devices
        .laptop_app
        .begin_signing_out(&account_id_hex(&devices.laptop_app));

    devices
        .laptop
        .sign_out_through_siblings_step()
        .await
        .unwrap();
    let SiblingSignOut::Confirmed { left_to_siblings } = devices
        .laptop
        .sign_out_through_siblings_step()
        .await
        .unwrap()
    else {
        panic!("the leaving commit is confirmed");
    };
    assert_eq!(left_to_siblings, [hex::encode(shared.as_slice())]);
}

/// The phone signs out first, so its entry is `leaving`. The laptop then has
/// no sibling that stays, so it signs out on its own and commits nothing; a
/// device that is signing out never decides another's removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_whose_only_sibling_is_leaving_signs_out_on_its_own() {
    let (devices, group) = tagging_devices().await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        laptop_app,
        mut laptop,
        ..
    } = devices;
    let mut laptop_cursor = published_count(&relay);
    let _phone_signing_out = phone_app.begin_signing_out(&account_id_hex(&phone_app));
    phone.sign_out_through_siblings_step().await.unwrap();
    assert!(matches!(
        phone.sign_out_through_siblings_step().await.unwrap(),
        SiblingSignOut::Confirmed { .. }
    ));
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(status_of(&laptop, &group, &phone), DeviceStatusV1::Leaving);

    let _laptop_signing_out = laptop_app.begin_signing_out(&account_id_hex(&laptop_app));
    let published = published_count(&relay);
    assert_eq!(
        laptop.sign_out_through_siblings_step().await.unwrap(),
        SiblingSignOut::OnItsOwn
    );
    laptop.drive_device_removals().await;
    assert_eq!(published_count(&relay), published, "nothing goes out");
    assert_eq!(pending_removals(&laptop_app), 0);
}

/// A device with no device group, or whose own link is not made yet, signs
/// out on its own at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_without_a_made_link_signs_out_on_its_own() {
    let mut devices = phone_and_laptop().await;
    let _phone_signing_out = devices
        .phone_app
        .begin_signing_out(&account_id_hex(&devices.phone_app));
    assert_eq!(
        devices
            .phone
            .sign_out_through_siblings_step()
            .await
            .unwrap(),
        SiblingSignOut::OnItsOwn,
        "no device group"
    );

    let (mut devices, group) = linked_devices().await;
    assert!(
        roster(&devices.laptop, &group).devices[&slot_of(&devices.laptop)]
            .tag_signature_key
            .is_none(),
        "the laptop has not made its first commit"
    );
    let _laptop_signing_out = devices
        .laptop_app
        .begin_signing_out(&account_id_hex(&devices.laptop_app));
    let published = published_count(&devices.relay);
    assert_eq!(
        devices
            .laptop
            .sign_out_through_siblings_step()
            .await
            .unwrap(),
        SiblingSignOut::OnItsOwn
    );
    assert_eq!(published_count(&devices.relay), published);
}

/// The laptop starts signing out, then the phone's user removes it. The
/// removal reaches the laptop, which is not unlinked and is told nothing.
/// Every publish of its account is held back but its sign-out's own steps:
/// it can still delete its own slot, and sends nothing else. A chat message
/// does not go out, no maintenance pass or push token retry runs, and the
/// engine refuses to let an admin's device leave the chat its account
/// administers, a refusal that comes without the push token removal a leave
/// sends first. While the slot's deletion waits on its relay, a
/// profile published beside it, in the same task or a spawned one, is still
/// refused. When its sign-out ends without a wipe, the next pairing drive
/// finds the stored removal and unlinks it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_removed_while_signing_out_is_not_unlinked() {
    let (devices, group) = tagging_devices().await;
    let Devices {
        _dirs,
        relay,
        mut phone,
        laptop_app,
        mut laptop,
        ..
    } = devices;
    laptop
        .drive_device_pairing_at(crate::unix_now_seconds())
        .await;
    let notes = laptop.create_group("notes", &[]).await.unwrap();
    laptop
        .upsert_and_share_push_registration(
            PushPlatform::Fcm,
            "laptop-token",
            &nostr::prelude::Keys::generate().public_key().to_hex(),
            None,
        )
        .await
        .unwrap();
    let mut laptop_cursor = published_count(&relay);
    let account_id_hex = account_id_hex(&laptop_app);
    let laptop_signing_out = laptop_app.begin_signing_out(&account_id_hex);

    phone
        .remove_linked_device(&hex::encode(slot_of(&laptop)))
        .await
        .unwrap();
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert!(laptop.runtime.group_record(&group).unwrap().removed);
    assert!(!laptop.device_unlinked());
    let account = laptop_app.account_home().account("alice").unwrap();
    assert!(!account.unlinked && !account.signed_out);
    assert!(
        laptop_app.account_publishing_stopped(&account_id_hex),
        "all but its sign-out is held back"
    );
    assert_eq!(
        laptop.sign_out_through_siblings_step().await.unwrap(),
        SiblingSignOut::OnItsOwn
    );

    let published = published_count(&relay);
    let _ = laptop
        .send_app_event(
            &notes,
            AppMessageIntent::Chat {
                content: "after the removal".to_owned(),
            },
        )
        .await;
    laptop.run_due_maintenance().await.unwrap();
    assert!(
        !laptop
            .retry_pending_push_registration_shares_best_effort()
            .await
    );
    let refused = laptop.leave_group(&notes).await.unwrap_err();
    assert!(matches!(
        refused.as_engine_error(),
        Some(cgka_traits::error::EngineError::AdminCannotSelfRemove { .. })
    ));
    assert_eq!(published_count(&relay), published, "nothing goes out");

    let publish_profile = |app: MarmotApp| async move {
        app.publish_user_profile(
            "alice",
            nostr_directory::UserProfileMetadata::default(),
            AccountRelayListBootstrap::new(
                vec![TransportEndpoint("wss://relay.example".to_owned())],
                Vec::new(),
            ),
        )
        .await
    };
    let published = published_count(&relay);
    relay.block_next_publish();
    let (withdrawn, beside) = tokio::join!(laptop.withdraw_key_package_slot(), async {
        tokio::time::timeout(Duration::from_secs(10), relay.wait_for_blocked_publish())
            .await
            .expect("the slot's deletion reaches its relay");
        let beside = (
            publish_profile(laptop_app.clone()).await,
            tokio::spawn(publish_profile(laptop_app.clone()))
                .await
                .unwrap(),
        );
        relay.release_publish();
        beside
    });
    assert_eq!(withdrawn.unwrap(), 1);
    for refused in [beside.0, beside.1] {
        assert!(
            matches!(
                refused,
                Err(AppError::Transport(cgka_traits::TransportAdapterError::Publish(ref reason)))
                    if reason == "this device is unlinked"
            ),
            "{refused:?}"
        );
    }
    assert_eq!(
        published_count(&relay),
        published + 1,
        "its slot's deletion goes out, and nothing beside it"
    );
    assert!(laptop_app.account_publishing_stopped(&account_id_hex));

    drop(laptop_signing_out);
    laptop
        .drive_device_pairing_at(crate::unix_now_seconds())
        .await;
    assert!(laptop.device_unlinked());
}

/// A sibling's `leaving` entry without its tag signature key is never
/// decided: no device may remove an entry that has none. The phone sets the
/// laptop's entry, whose first commit has not landed, to `leaving`, as a
/// faulty device might.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leaving_entry_without_its_key_is_not_removed() {
    let (mut devices, group) = linked_devices().await;
    let laptop_slot = slot_of(&devices.laptop);
    assert!(
        roster(&devices.phone, &group).devices[&laptop_slot]
            .tag_signature_key
            .is_none()
    );
    assert!(matches!(
        devices
            .phone
            .runtime
            .edit_device_roster_entry(&group, &laptop_slot, &[], |entry| {
                entry.status = DeviceStatusV1::Leaving;
            })
            .await
            .unwrap(),
        DeviceRosterEdit::Committed(_)
    ));
    assert_eq!(
        status_of(&devices.phone, &group, &devices.laptop),
        DeviceStatusV1::Leaving
    );

    devices.phone.decide_leaving_siblings().unwrap();
    devices.phone.backdate_leaving_siblings(31);
    devices.phone.decide_leaving_siblings().unwrap();
    assert!(devices.phone.leaving_siblings.is_empty());
    assert_eq!(pending_removals(&devices.phone_app), 0);
}

/// `sign_out_and_wipe` on a running laptop: its `leaving` commit is
/// confirmed, so it leaves the chat both are in to the phone, deletes its
/// slot and wipes. The phone then removes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_out_and_wipe_leaves_a_shared_chat_to_the_sibling() {
    let (mut devices, group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        laptop_app,
        laptop,
        ..
    } = devices;
    let laptop_slot = slot_of(&laptop);
    drop(laptop);
    let mut phone_cursor = published_count(&relay);
    let _eose = scripted_eose_pump(
        laptop_app.relay_plane.clone(),
        relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(laptop_app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();

    let outcome = runtime.sign_out_and_wipe("alice").await.unwrap();
    assert_eq!(outcome.groups_left_to_siblings, 1);
    assert_eq!(outcome.groups_left, 0);
    assert!(outcome.group_leave_failures.is_empty());
    assert!(!outcome.siblings_not_reached);
    assert_eq!(outcome.key_packages_deleted, 1);
    assert!(outcome.local_cleanup.completed);
    assert!(!laptop_app.signing_out(&account_id_hex(&phone_app)));
    runtime.shutdown().await;

    deliver_new(&mut phone, &relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    assert_eq!(
        roster(&phone, &group).devices[&laptop_slot].status,
        DeviceStatusV1::Leaving
    );
    decide_after_delay(&mut phone, &phone_app, laptop_slot).await;
    assert!(
        phone
            .runtime
            .own_account_leaf_claims(&chat, &roster(&phone, &group))
            .unwrap()
            .is_empty()
    );
}

/// The laptop's `leaving` commit cannot go out, so it is not confirmed in
/// time: the laptop says its siblings could not be asked and leaves every
/// chat itself, reporting the one its account administers as one it could
/// not leave.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_out_and_wipe_leaves_every_chat_when_siblings_are_not_reached() {
    let (mut devices, _group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let Devices {
        _dirs,
        relay,
        laptop_app,
        laptop,
        ..
    } = devices;
    drop(laptop);
    let _eose = scripted_eose_pump(
        laptop_app.relay_plane.clone(),
        relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(laptop_app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    laptop_app.set_sign_out_leaving_wait(Duration::from_secs(1));
    relay.fail_publishes_of_kind(445);

    let outcome = runtime.sign_out_and_wipe("alice").await.unwrap();
    assert!(outcome.siblings_not_reached);
    assert_eq!(outcome.groups_left_to_siblings, 0);
    // Its account administers the chat, so it cannot leave it itself: the
    // chat keeps its leaf and is reported to its user.
    assert_eq!(outcome.groups_left, 0);
    let [failure] = outcome.group_leave_failures.as_slice() else {
        panic!("one chat it could not leave: {outcome:?}");
    };
    assert_eq!(failure.group_id_hex, hex::encode(chat.as_slice()));
    assert!(outcome.local_cleanup.completed);
    runtime.shutdown().await;
}

/// A step that answers after the `leaving` deadline counts as not reached,
/// a confirmation included, so a busy worker does not stretch the wait. The
/// laptop's entry already reads `leaving`, so the wipe's first step would
/// confirm it, but that step waits behind a message held at its relay until
/// the deadline has passed: the laptop leaves every chat itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_confirmation_after_the_deadline_counts_as_not_reached() {
    let (mut devices, group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let Devices {
        _dirs,
        relay,
        laptop_app,
        mut laptop,
        ..
    } = devices;
    assert_eq!(
        laptop.sign_out_through_siblings_step().await.unwrap(),
        SiblingSignOut::Pending
    );
    assert_eq!(status_of(&laptop, &group, &laptop), DeviceStatusV1::Leaving);
    drop(laptop);
    let _eose = scripted_eose_pump(
        laptop_app.relay_plane.clone(),
        relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(laptop_app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    // The worker's first maintenance pass sends before the message is held.
    runtime.run_due_maintenance("alice").await.unwrap();
    let wait = Duration::from_millis(500);
    laptop_app.set_sign_out_leaving_wait(wait);
    relay.block_next_publish();
    let send = tokio::spawn({
        let runtime = runtime.clone();
        let chat = chat.clone();
        async move { runtime.send_message("alice", &chat, b"held".to_vec()).await }
    });
    tokio::time::timeout(Duration::from_secs(10), relay.wait_for_blocked_publish())
        .await
        .expect("the message reaches its relay");

    let mut wipe = Box::pin(runtime.sign_out_and_wipe("alice"));
    tokio::select! {
        _ = &mut wipe => panic!("the wipe's steps wait behind the held message"),
        // Past the deadline, which starts once the wipe has started.
        () = tokio::time::sleep(wait * 4) => {}
    }
    relay.release_publish();
    let outcome = wipe.await.unwrap();
    assert!(outcome.siblings_not_reached);
    assert_eq!(outcome.groups_left_to_siblings, 0);
    let [failure] = outcome.group_leave_failures.as_slice() else {
        panic!("one chat it could not leave: {outcome:?}");
    };
    assert_eq!(failure.group_id_hex, hex::encode(chat.as_slice()));
    assert!(outcome.local_cleanup.completed);
    send.await.unwrap().unwrap();
    runtime.shutdown().await;
}

/// The laptop's `sign_out_and_wipe` sends its `leaving` commit, and the
/// phone sees it and removes the laptop before the laptop learns that the
/// commit went out, and out of the chat both are in. The removal reaches
/// the laptop mid-wait: it is not unlinked but signs out on its own, does
/// not try to leave the chat it is no longer in, and from then on sends
/// only its SelfRemove from a chat bob administers and its slot's
/// deletion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_out_and_wipe_finishes_when_removed_mid_wait() {
    let (mut devices, group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        laptop_app,
        mut laptop,
        ..
    } = devices;
    let laptop_slot = slot_of(&laptop);
    // A chat with bob that bob administers and no sibling is in: the laptop
    // leaves it itself, even once removed.
    let bob_dir = tempfile::tempdir().unwrap();
    let bob_id = AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap()
        .account_id_hex;
    let bob_app = device_group_app_at(&bob_dir, relay.clone());
    let mut bob = bob_app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();
    remember_test_member_inbox(&laptop_app, &bob_id, "wss://relay.example");
    let with_bob = laptop.create_group("with bob", &[&bob_id]).await.unwrap();
    laptop.promote_admin(&with_bob, &bob_id).await.unwrap();
    laptop.self_demote_admin(&with_bob).await.unwrap();
    drop(laptop);
    let mut phone_cursor = published_count(&relay);
    let _eose = scripted_eose_pump(
        laptop_app.relay_plane.clone(),
        relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(laptop_app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    // The worker's first maintenance pass sends before the wipe starts.
    runtime.run_due_maintenance("alice").await.unwrap();
    let account_id_hex = account_id_hex(&laptop_app);

    relay.block_next_publish();
    let mut wipe = Box::pin(runtime.sign_out_and_wipe("alice"));
    tokio::select! {
        _ = &mut wipe => panic!("the wipe waits on its siblings"),
        () = relay.wait_for_blocked_publish() => {}
    }
    let leaving = relay.attempted_events().pop().unwrap();
    assert_eq!(leaving.kind, 445, "the laptop's `leaving` commit");
    deliver_new(&mut phone, &relay, &mut phone_cursor).await;
    deliver_events(&mut phone, &[leaving]).await;
    phone.sync().await.unwrap();
    decide_after_delay(&mut phone, &phone_app, laptop_slot).await;
    assert!(
        phone
            .runtime
            .own_account_leaf_claims(&chat, &roster(&phone, &group))
            .unwrap()
            .is_empty(),
        "the phone takes the laptop out of the chat too"
    );
    // Separate apps share no live relay: route the removal in.
    let removal = relay.published_events.lock().unwrap()[phone_cursor..].to_vec();
    for event in removal {
        laptop_app
            .relay_plane
            .handle_relay_event_for_test(NostrRelayEvent {
                endpoint: TransportEndpoint("wss://relay.example".to_owned()),
                subscription_id: Some("removal-mid-wait".to_owned()),
                event,
            })
            .await
            .unwrap();
    }
    relay.release_publish();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !laptop_app.account_publishing_stopped(&account_id_hex) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the removal reaches the laptop");
    let attempted = relay.attempted_events().len();

    let outcome = wipe.await.unwrap();
    assert!(!outcome.siblings_not_reached);
    assert_eq!(outcome.groups_left_to_siblings, 0);
    // It leaves bob's chat; the shared chat it is no longer in is neither
    // left nor reported.
    assert_eq!(outcome.groups_left, 1);
    assert!(
        outcome.group_leave_failures.is_empty(),
        "{:?}",
        outcome.group_leave_failures
    );
    assert_eq!(outcome.key_packages_deleted, 1);
    assert!(outcome.local_cleanup.completed);
    assert_eq!(
        relay.attempted_events()[attempted..]
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        vec![445, 5],
        "only its SelfRemove in bob's chat and its slot's deletion go out"
    );
    runtime.shutdown().await;
}

/// A Rust caller that drops a wipe while it waits on its siblings, here
/// before its `leaving` commit could go out, leaves the account not signing
/// out, so its maintenance and removal note run again. MarmotKit's export
/// keeps the wipe running instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_sign_out_leaves_the_account_not_signing_out() {
    let (mut devices, _group) = tagging_devices().await;
    chat_with_both(&mut devices).await;
    let Devices {
        _dirs,
        relay,
        laptop_app,
        laptop,
        ..
    } = devices;
    drop(laptop);
    let _eose = scripted_eose_pump(
        laptop_app.relay_plane.clone(),
        relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(laptop_app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    relay.fail_publishes_of_kind(445);
    let account_id_hex = account_id_hex(&laptop_app);

    let mut wipe = Box::pin(runtime.sign_out_and_wipe("alice"));
    tokio::select! {
        _ = &mut wipe => panic!("the wipe waits on the siblings"),
        () = async {
            while !laptop_app.signing_out(&account_id_hex) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        } => {}
    }
    drop(wipe);

    assert!(!laptop_app.signing_out(&account_id_hex));
    runtime.shutdown().await;
}

/// A host that cancels a wipe and starts another overlaps two sign-outs of
/// one account: it stays signing out until the last of them ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_account_signs_out_until_its_last_sign_out_ends() {
    let dir = tempfile::tempdir().unwrap();
    let app = device_group_app_at(&dir, Arc::new(ScriptedPushRelayClient::default()));
    let account_id_hex = "aa".repeat(32);
    let first = app.begin_signing_out(&account_id_hex);
    let second = app.begin_signing_out(&account_id_hex);
    drop(first);
    assert!(app.signing_out(&account_id_hex));
    drop(second);
    assert!(!app.signing_out(&account_id_hex));
}

/// An account signed out without a wipe has no worker to ask its siblings
/// through, so wiping it signs out on its own at once instead of waiting out
/// the `leaving` deadline and reporting its siblings not reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wiping_a_signed_out_account_does_not_wait_on_siblings() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = device_group_app_at(&dir, relay.clone());
    let _eose = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime
        .sign_out(
            "alice",
            crate::runtime::SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    app.set_sign_out_leaving_wait(Duration::from_secs(1));

    let outcome = runtime.sign_out_and_wipe("alice").await.unwrap();
    assert!(!outcome.siblings_not_reached);
    assert!(outcome.local_cleanup.completed);
    runtime.shutdown().await;
}
