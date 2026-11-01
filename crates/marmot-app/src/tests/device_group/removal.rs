//! Removing a device (mdk#2628 item 3.6b). The user removes another device
//! of the account from any device: one device-group commit takes its leaf and
//! entry and records its slot as `removed`, the deciding device then deletes
//! the removed device's KeyPackage slot (D22), and each device removes the
//! removed device's leaves from the chats that take a same-account removal.
//! The decision is recorded first and kept while this device trusts the
//! device group, so a busy device group only delays it, and a removal that
//! branch selection drops is committed again. A device refills its emptied
//! slot (3.4) only while its roster lists it, so a removed one never does.
//! A device the roster stops listing with no `removed` record is cleaned up
//! after by the tag signature key this device remembers for it (mdk#2761).

use super::*;
use crate::tests::sign_ins::{
    commit_roster, publish_two_days_ago, published_at, relay_empties_slot, relay_serves_slot,
};

pub(super) fn published_count(relay: &ScriptedPushRelayClient) -> usize {
    relay.published_events.lock().unwrap().len()
}

fn refusal(error: AppError) -> &'static str {
    match error {
        AppError::DeviceGroupRefused(reason) => reason,
        other => panic!("expected a device-group refusal, got {other:?}"),
    }
}

/// How many private KeyPackages `client` issued to `recipient`.
fn issued_to(client: &AppClient, recipient: &[u8; 32]) -> usize {
    client
        .runtime
        .issued_private_key_packages()
        .unwrap()
        .iter()
        .filter(|record| &record.recipient_slot == recipient)
        .count()
}

pub(super) fn pending_removals(app: &MarmotApp) -> usize {
    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .device_removals()
        .unwrap()
        .len()
}

/// Whether each recorded removal has had its slot deleted.
fn slots_withdrawn(app: &MarmotApp) -> Vec<bool> {
    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .device_removals()
        .unwrap()
        .into_iter()
        .map(|removal| removal.slot_withdrawn_at.is_some())
        .collect()
}

/// The deletions published for `slot` of `account_id_hex`'s KeyPackages.
fn slot_deletions(relay: &ScriptedPushRelayClient, account_id_hex: &str, slot: &str) -> usize {
    let address = format!("30443:{account_id_hex}:{slot}");
    relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| {
            event.kind == 5
                && event.tags.iter().any(|tag| {
                    tag.first().is_some_and(|name| name == "a") && tag.get(1) == Some(&address)
                })
        })
        .count()
}

/// The phone founds a chat, which requires account-devices, and adds the
/// laptop's tagged KeyPackage; the laptop joins.
pub(super) async fn chat_with_both(devices: &mut Devices) -> GroupId {
    let chat = devices.phone.create_group("team", &[]).await.unwrap();
    let mut laptop_cursor = published_count(&devices.relay);
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
    deliver_new(&mut devices.laptop, &devices.relay, &mut laptop_cursor).await;
    devices.laptop.sync().await.unwrap();
    devices.laptop.accept_group_invite(&chat).unwrap();
    chat
}

/// The phone founds a chat with Bob, whose KeyPackage does not advertise
/// account-devices, so the chat does not require it, and adds the laptop's
/// tagged KeyPackage; the laptop joins. No device can remove the laptop's
/// leaf from it with a same-account removal.
async fn chat_without_account_devices(devices: &mut Devices) -> (tempfile::TempDir, GroupId) {
    let dir = tempfile::tempdir().unwrap();
    let bob = AccountHome::open(dir.path()).create_account("bob").unwrap();
    let bob_app = device_group_app_at(&dir, devices.relay.clone());
    let components = bob_app
        .supported_app_component_ids()
        .into_iter()
        .filter(|id| *id != ACCOUNT_DEVICES_COMPONENT_ID)
        .collect();
    let mut bob_key_package =
        crate::tests::fresh_key_package_with_components(&bob_app, &bob, false, components).await;
    // The Welcome names the event that served the KeyPackage; Bob never
    // reads it.
    bob_key_package.source = Some(cgka_traits::engine::KeyPackageSource {
        event_id: MessageId::new(vec![0x55; 32]),
    });
    let mut laptop_cursor = published_count(&devices.relay);
    let laptop_key_package = published_key_package(&mut devices.laptop, &devices.relay).await;
    let route = NostrRoutingV1::new([0x44; 32], vec!["wss://relay.example".to_owned()]).unwrap();
    let (chat, effects) = devices
        .phone
        .runtime
        .create_group(cgka_traits::engine::CreateGroupRequest {
            name: "legacy".into(),
            description: String::new(),
            members: vec![bob_key_package, laptop_key_package],
            required_features: Vec::new(),
            app_components: vec![cgka_traits::app_components::AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: cgka_traits::app_components::encode_nostr_routing_v1(&route).unwrap(),
            }],
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    devices
        .phone
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    devices.phone.refresh_group(&chat);
    assert!(!devices.phone.group_requires_account_devices(&chat).unwrap());
    deliver_new(&mut devices.laptop, &devices.relay, &mut laptop_cursor).await;
    devices.laptop.sync().await.unwrap();
    devices.laptop.accept_group_invite(&chat).unwrap();
    (dir, chat)
}

/// Commit the removal of the device in `slot` on `phone` as a removal
/// another device decided reaches it: the commit alone, with no decision
/// recorded here and no clean-up run.
async fn commit_removal_decided_elsewhere(phone: &mut AppClient, group: &GroupId, slot: [u8; 32]) {
    let before = roster(phone, group);
    phone
        .unlink_device_from_group(
            group,
            device_group_leaf(phone, group, slot),
            vec![
                DeviceRosterOperationV1::RemoveDevice(slot),
                DeviceRosterOperationV1::SetRejectedSlot(
                    slot,
                    RejectedSlotV1 {
                        reason: RejectedSlotReasonV1::Removed,
                        rejected_at: crate::unix_now_seconds() - 60,
                        tag_signature_key: before.devices[&slot].tag_signature_key.clone(),
                    },
                ),
            ],
        )
        .await
        .unwrap();
}

/// The device-group leaf whose tag reads as the device in `slot`.
fn device_group_leaf(phone: &AppClient, group: &GroupId, slot: [u8; 32]) -> Vec<u8> {
    phone
        .runtime
        .own_account_leaf_claims(group, &roster(phone, group))
        .unwrap()
        .into_iter()
        .find_map(|(key, claim)| (claim == DeviceTagClaim::Device(slot)).then_some(key))
        .expect("the device's leaf")
}

/// What `phone`'s trusted roster reads each other leaf of its account in
/// `chat` as.
fn chat_claims(phone: &AppClient, chat: &GroupId, group: &GroupId) -> Vec<DeviceTagClaim> {
    phone
        .runtime
        .own_account_leaf_claims(chat, &roster(phone, group))
        .unwrap()
        .into_iter()
        .map(|(_, claim)| claim)
        .collect()
}

/// Commit, on `phone`, the removal of the device in `slot`'s entry and leaf
/// with no `removed` record, as a failed link's undo does. A `removed` record
/// dropped before this device cleans up, or a later branch that drops a made
/// link, leaves the same roster. Nothing is recorded or cleaned up here.
async fn unlist_without_record(phone: &mut AppClient, group: &GroupId, slot: [u8; 32]) {
    let leaf = device_group_leaf(phone, group, slot);
    phone
        .unlink_device_from_group(
            group,
            leaf,
            vec![DeviceRosterOperationV1::RemoveDevice(slot)],
        )
        .await
        .unwrap();
}

/// Deliver what the relay has to the phone and advance its device group's
/// convergence until `listed` reads the laptop's entry with `label`, at most
/// eight times. The device group is hidden, so convergence runs through the
/// runtime, and adopting a deeper branch can take more than one pass.
async fn converge_until_labelled(
    phone: &mut AppClient,
    relay: &ScriptedPushRelayClient,
    cursor: &mut usize,
    group: &GroupId,
    slot: &[u8; 32],
    label: &str,
) {
    for _ in 0..8 {
        deliver_new(phone, relay, cursor).await;
        let effects = phone.runtime.advance_convergence(group).await.unwrap();
        phone
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
        if roster(phone, group)
            .devices
            .get(slot)
            .is_some_and(|device| device.label == label)
        {
            return;
        }
    }
    panic!("the phone never adopted the branch that labels the device {label:?}");
}

/// Removing the laptop on the phone is one device-group commit that drops
/// its leaf and entry and records its slot as `removed` with the tag key its
/// entry had, and one same-account Remove of its leaf in the chat both are
/// in. The phone discards the private KeyPackages it issued the laptop. The
/// next maintenance pass deletes the laptop's KeyPackage slot once; the
/// decision stays recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_device_takes_it_out_of_the_device_group_and_its_chats() {
    let (mut devices, group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        laptop,
        ..
    } = devices;
    let laptop_slot = own_slot(&laptop);
    let laptop_slot_bytes = slot_of(&laptop);
    let tag_key = roster(&phone, &group).devices[&laptop_slot_bytes]
        .tag_signature_key
        .clone()
        .expect("the laptop tags");
    let claims = phone
        .runtime
        .own_account_leaf_claims(&chat, &roster(&phone, &group))
        .unwrap();
    assert_eq!(
        claims.iter().map(|(_, claim)| *claim).collect::<Vec<_>>(),
        [DeviceTagClaim::Device(laptop_slot_bytes)]
    );
    assert!(issued_to(&phone, &laptop_slot_bytes) > 0);
    let account_id_hex = phone_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;

    phone.remove_linked_device(&laptop_slot).await.unwrap();

    let after = roster(&phone, &group);
    assert!(!after.devices.contains_key(&laptop_slot_bytes));
    let record = &after.rejected_slots[&laptop_slot_bytes];
    assert_eq!(record.reason, RejectedSlotReasonV1::Removed);
    assert_eq!(record.tag_signature_key, Some(tag_key));
    assert!(record.rejected_at > 0);
    assert!(
        phone
            .runtime
            .own_account_leaf_claims(&chat, &after)
            .unwrap()
            .is_empty(),
        "the laptop's chat leaf is gone"
    );
    assert_eq!(
        phone
            .linked_devices()
            .unwrap()
            .into_iter()
            .map(|device| device.slot_id_hex)
            .collect::<Vec<_>>(),
        [own_slot(&phone)]
    );
    assert_eq!(phone.removed_device_leftover_chats().unwrap(), 0);
    assert_eq!(issued_to(&phone, &laptop_slot_bytes), 0, "keys included");
    assert_eq!(slot_deletions(&relay, &account_id_hex, &laptop_slot), 0);
    assert_eq!(slots_withdrawn(&phone_app), [false]);

    // A sibling whose clock runs ahead drops the record before the phone's
    // next pass. The phone saw it when it committed the removal, so it does
    // not commit it again on its own (mdk#2761).
    commit_roster(
        &mut phone,
        &group,
        vec![DeviceRosterOperationV1::RemoveRejectedSlot(
            laptop_slot_bytes,
        )],
    )
    .await;
    let epoch = phone.runtime.group_record(&group).unwrap().epoch;
    let before_deletion = crate::unix_now_seconds();
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(phone.runtime.group_record(&group).unwrap().epoch, epoch);
    assert!(slot_deletions(&relay, &account_id_hex, &laptop_slot) > 0);
    assert!(
        relay
            .published_events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.kind == 5)
            .all(|event| event.created_at >= before_deletion + 5 * 60),
        "the deletion covers publications stamped up to the publish skew ahead"
    );
    assert_eq!(slots_withdrawn(&phone_app), [true]);
    let deletions = slot_deletions(&relay, &account_id_hex, &laptop_slot);
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(
        slot_deletions(&relay, &account_id_hex, &laptop_slot),
        deletions,
        "a finished removal sends nothing more"
    );
}

/// A device that did not decide a removal cleans up after it all the same.
/// Once its roster records the laptop's slot as `removed`, its maintenance
/// pass discards the private KeyPackages it issued the laptop and removes
/// the laptop's leaf from the chat both are in. Only the deciding device
/// deletes the laptop's KeyPackage slot, so this one sends no deletion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_that_did_not_decide_cleans_up_after_a_removal() {
    let (mut devices, group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        laptop,
        ..
    } = devices;
    let laptop_slot = own_slot(&laptop);
    let laptop_slot_bytes = slot_of(&laptop);
    let account_id_hex = phone_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    // The commit of a removal another device decided: nothing is recorded
    // here.
    commit_removal_decided_elsewhere(&mut phone, &group, laptop_slot_bytes).await;
    assert_eq!(pending_removals(&phone_app), 0);
    assert!(issued_to(&phone, &laptop_slot_bytes) > 0);
    let after = roster(&phone, &group);
    assert_eq!(
        phone
            .runtime
            .own_account_leaf_claims(&chat, &after)
            .unwrap()
            .into_iter()
            .map(|(_, claim)| claim)
            .collect::<Vec<_>>(),
        [DeviceTagClaim::RejectedSlot(laptop_slot_bytes)]
    );

    phone.run_due_maintenance().await.unwrap();
    assert_eq!(issued_to(&phone, &laptop_slot_bytes), 0);
    assert!(
        phone
            .runtime
            .own_account_leaf_claims(&chat, &after)
            .unwrap()
            .is_empty(),
        "the laptop's chat leaf is gone"
    );
    assert_eq!(slot_deletions(&relay, &account_id_hex, &laptop_slot), 0);
}

/// A slot both gone rules cover is read by every key either names
/// (mdk#2761). The laptop's entry moves to a newer key before the removal,
/// so the `removed` record carries only that key, while the laptop's chat
/// leaf is still tagged under the older one and reads as unclaimed. The
/// phone kept both keys, so its maintenance pass removes the leaf.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_slot_is_read_by_every_key_the_device_keeps() {
    let (mut devices, group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let Devices {
        _dirs,
        mut phone,
        laptop,
        ..
    } = devices;
    let laptop_slot = slot_of(&laptop);
    let leaf = device_group_leaf(&phone, &group, laptop_slot);
    let newer_key = vec![0x77; 32];
    let entry = DeviceEntryV1 {
        tag_signature_key: Some(newer_key.clone()),
        ..roster(&phone, &group).devices[&laptop_slot].clone()
    };
    commit_roster(
        &mut phone,
        &group,
        vec![DeviceRosterOperationV1::SetDevice(laptop_slot, entry)],
    )
    .await;
    phone
        .unlink_device_from_group(
            &group,
            leaf,
            vec![
                DeviceRosterOperationV1::RemoveDevice(laptop_slot),
                DeviceRosterOperationV1::SetRejectedSlot(
                    laptop_slot,
                    RejectedSlotV1 {
                        reason: RejectedSlotReasonV1::Removed,
                        rejected_at: crate::unix_now_seconds() - 60,
                        tag_signature_key: Some(newer_key),
                    },
                ),
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        chat_claims(&phone, &chat, &group),
        [DeviceTagClaim::Unclaimed],
        "the record's key reads no leaf"
    );

    phone.run_due_maintenance().await.unwrap();
    assert!(
        chat_claims(&phone, &chat, &group).is_empty(),
        "the leaf under the older key is gone"
    );
}

/// The phone removes only the laptop's leaf from a chat both are in. The
/// account stays in the chat through the phone, so the laptop records the
/// chat as `DeviceRemoved`, not as a removal of the account from it (D62):
/// it stops sending and routing there like any departed chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_removed_from_a_chat_its_account_stays_in_is_not_removed_from_it() {
    let (mut devices, group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let mut laptop_cursor = published_count(&devices.relay);
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        laptop_app,
        mut laptop,
        ..
    } = devices;
    let chat_hex = hex::encode(chat.as_slice());
    let leaves = phone
        .runtime
        .own_account_leaf_claims(&chat, &roster(&phone, &group))
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    assert_eq!(leaves.len(), 1, "the laptop's leaf");

    phone
        .remove_own_account_leaves(&chat, leaves)
        .await
        .unwrap();
    assert!(
        phone
            .runtime
            .own_account_leaf_claims(&chat, &roster(&phone, &group))
            .unwrap()
            .is_empty(),
        "the laptop's chat leaf is gone"
    );
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.retry_group_convergence(&chat).await.unwrap();

    assert!(laptop.runtime.group_record(&chat).unwrap().removed);
    assert_eq!(
        laptop_app
            .stored_group_self_membership("alice", &chat_hex)
            .unwrap(),
        Some(SelfMembership::DeviceRemoved)
    );
    assert_eq!(installed_group_routes(&laptop, &chat), 0);
    let removal_rows = laptop_app
        .timeline_messages_with_query(
            "alice",
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some(chat_hex.clone()),
                ..storage_sqlite::TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages
        .into_iter()
        .filter_map(|row| row.group_system)
        .filter(|row| row.system_type == cgka_traits::app_event::GROUP_SYSTEM_TYPE_MEMBER_REMOVED)
        .count();
    assert_eq!(removal_rows, 0, "no row says the account was removed");
    assert_eq!(
        phone_app
            .stored_group_self_membership("alice", &chat_hex)
            .unwrap(),
        Some(SelfMembership::Member)
    );
}

/// The phone removes the laptop from the device group long after its link
/// was made. The laptop is unlinked as it applies the removal: the account
/// is marked unlinked, and so signed out for good, and its next pairing
/// drive forgets its device-group copy. Nothing more goes out from it, and
/// signing in again is refused (D67).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_its_device_group_removes_is_unlinked_from_the_account() {
    let (devices, group) = tagging_devices().await;
    let mut laptop_cursor = published_count(&devices.relay);
    let Devices {
        _dirs,
        relay,
        mut phone,
        laptop_app,
        mut laptop,
        ..
    } = devices;
    let laptop_storage = laptop_app.account_storage("alice").unwrap().app_storage();
    laptop
        .drive_device_pairing_at(crate::unix_now_seconds())
        .await;
    assert!(
        laptop_storage.device_group_joins().unwrap().is_empty(),
        "the laptop's link is settled, so its removal is not a failed link"
    );

    phone
        .remove_linked_device(&own_slot(&laptop))
        .await
        .unwrap();
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert!(laptop.runtime.group_record(&group).unwrap().removed);
    assert!(
        laptop.device_unlinked(),
        "it stops as it applies the removal"
    );
    let account = laptop_app.account_home().account("alice").unwrap();
    assert!(account.unlinked && account.signed_out);
    assert!(trust(&laptop_app, &group).is_some());

    let published = published_count(&relay);
    laptop
        .drive_device_pairing_at(crate::unix_now_seconds())
        .await;
    assert!(
        trust(&laptop_app, &group).is_none(),
        "its copy is forgotten"
    );
    laptop
        .drive_device_pairing_at(crate::unix_now_seconds())
        .await;
    assert_eq!(published_count(&relay), published, "nothing goes out");
    assert!(matches!(
        laptop_app
            .account_home()
            .set_account_signed_out("alice", false),
        Err(marmot_account::AccountHomeError::AccountUnlinked(_))
    ));
    drop(laptop);
    assert!(
        matches!(
            laptop_app.client("alice").await.err(),
            Some(AppError::AccountHome(
                marmot_account::AccountHomeError::AccountUnlinked(_)
            ))
        ),
        "an unlinked account never opens again"
    );
    assert_eq!(published_count(&relay), published);

    // A later process finds no removal stored, since the copy is gone: the
    // record alone stops the account's publishers.
    drop(laptop_app);
    let laptop_app = device_group_app_at(&_dirs[1], relay.clone());
    let attempted = relay.attempted_events().len();
    laptop_app
        .publish_user_profile("alice", UserProfileMetadata::default(), profile_bootstrap())
        .await
        .unwrap_err();
    assert_eq!(relay.attempted_events().len(), attempted);
}

/// The laptop sends its first commit in the device group and is closed
/// before a later pairing drive settles its link, so it still holds its
/// join. The phone sees that commit and removes the laptop, and the laptop
/// applies the removal with its join still held. The removal left a
/// `removed` record for its slot, so it was unlinked, not a failed link
/// (D40, D67).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_found_with_the_join_still_held_unlinks() {
    let (devices, group) = tagging_devices().await;
    let mut laptop_cursor = published_count(&devices.relay);
    let Devices {
        _dirs,
        relay,
        mut phone,
        laptop_app,
        mut laptop,
        ..
    } = devices;
    let laptop_storage = laptop_app.account_storage("alice").unwrap().app_storage();
    assert!(
        !laptop_storage.device_group_joins().unwrap().is_empty(),
        "no drive has settled the laptop's link yet"
    );

    phone
        .remove_linked_device(&own_slot(&laptop))
        .await
        .unwrap();
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert!(laptop.runtime.group_record(&group).unwrap().removed);
    assert!(
        !laptop_storage.device_group_joins().unwrap().is_empty(),
        "the join is still held when the removal is applied"
    );
    assert!(laptop.device_unlinked());
    let account = laptop_app.account_home().account("alice").unwrap();
    assert!(account.unlinked && account.signed_out);

    laptop
        .drive_device_pairing_at(crate::unix_now_seconds())
        .await;
    assert!(trust(&laptop_app, &group).is_none());
    assert!(
        !matches!(
            laptop
                .device_link(DeviceLinkOp::Read)
                .await
                .unwrap()
                .new_device,
            Some(NewDeviceLinkState::Ended {
                reason: DeviceLinkEndReason::LinkFailed
            })
        ),
        "it is not shown as a failed link"
    );
}

/// The laptop can't write its account record when it applies its removal.
/// It stops all the same, and keeps its device-group copy, so its next
/// client finds the removal again and makes the mark then (D67).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_unlink_mark_still_stops_and_is_made_again() {
    let (devices, group) = tagging_devices().await;
    let mut laptop_cursor = published_count(&devices.relay);
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
    phone
        .remove_linked_device(&own_slot(&laptop))
        .await
        .unwrap();
    laptop_app
        .test_fail_unlink_mark
        .store(true, Ordering::Relaxed);
    let published = published_count(&relay);
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    laptop
        .drive_device_pairing_at(crate::unix_now_seconds())
        .await;
    assert!(laptop.runtime.group_record(&group).unwrap().removed);

    assert!(
        laptop.device_unlinked(),
        "it stops although the mark failed"
    );
    assert!(!laptop_app.account_home().account("alice").unwrap().unlinked);
    assert!(
        trust(&laptop_app, &group).is_some(),
        "it keeps its copy until the mark lands"
    );
    assert_eq!(published_count(&relay), published, "nothing goes out");

    drop(laptop);
    laptop_app
        .test_fail_unlink_mark
        .store(false, Ordering::Relaxed);
    let mut laptop = laptop_app.client("alice").await.unwrap();
    laptop
        .drive_device_pairing_at(crate::unix_now_seconds())
        .await;
    assert!(laptop.device_unlinked());
    let account = laptop_app.account_home().account("alice").unwrap();
    assert!(account.unlinked && account.signed_out);
    assert!(
        trust(&laptop_app, &group).is_none(),
        "its copy is forgotten"
    );
}

/// The laptop can't read its device-group roster when it applies its
/// removal with its join still held, so it can't tell an unlink from a
/// failed link. It counts the removal as an unlink and stops (D67).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_whose_roster_cannot_be_read_unlinks() {
    let (devices, group) = tagging_devices().await;
    let mut laptop_cursor = published_count(&devices.relay);
    let Devices {
        _dirs,
        relay,
        mut phone,
        laptop_app,
        mut laptop,
        ..
    } = devices;
    phone
        .remove_linked_device(&own_slot(&laptop))
        .await
        .unwrap();
    laptop.test_fail_roster_read = true;
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    assert!(laptop.runtime.group_record(&group).unwrap().removed);
    assert!(
        laptop.device_unlinked(),
        "an unreadable roster counts as an unlink"
    );
    let account = laptop_app.account_home().account("alice").unwrap();
    assert!(account.unlinked && account.signed_out);
}

/// A caller keeps the laptop's client after its unlink and calls it again.
/// The laptop is still in the chat, as the removal reached it before any
/// clean-up, so a send would go out. Nothing reaches a relay: every
/// publisher of the account refuses once the device is unlinked, and
/// maintenance refuses outright (D67).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_kept_after_its_unlink_publishes_nothing() {
    let (mut devices, group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let mut laptop_cursor = published_count(&devices.relay);
    let Devices {
        _dirs,
        relay,
        mut phone,
        mut laptop,
        ..
    } = devices;
    laptop
        .drive_device_pairing_at(crate::unix_now_seconds())
        .await;
    commit_removal_decided_elsewhere(&mut phone, &group, slot_of(&laptop)).await;
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    assert!(laptop.device_unlinked());
    assert!(
        !laptop.runtime.group_record(&chat).unwrap().removed,
        "the laptop is still in the chat"
    );

    let published = published_count(&relay);
    let sent = laptop.send(&chat, b"still here").await.unwrap();
    assert_eq!(sent.published, 0, "the message is not published");
    assert!(laptop.rotate_key_package().await.is_err());
    assert!(matches!(
        laptop.run_due_maintenance().await,
        Err(AppError::AccountHome(
            marmot_account::AccountHomeError::AccountUnlinked(_)
        ))
    ));
    assert_eq!(
        published_count(&relay),
        published,
        "nothing reaches a relay"
    );

    // Push triggers go out through the anonymous publisher, not the
    // account's, so they are refused before it.
    let token = crate::notifications::GroupPushTokenRecord {
        group_id_hex: hex::encode(chat.as_slice()),
        member_id_hex: "cc".repeat(32),
        leaf_index: 0,
        platform: crate::notifications::PushPlatform::Apns,
        token_fingerprint: "fingerprint".to_owned(),
        server_pubkey_hex: "bb".repeat(32),
        relay_hint: Some("wss://push.example".to_owned()),
        encrypted_token: vec![1, 2, 3],
        owner_ts: 1,
        owner_sig: String::new(),
        updated_at_ms: 1,
    };
    assert!(matches!(
        laptop
            .publish_notification_trigger_tokens(vec![token])
            .await,
        Err(AppError::AccountHome(
            marmot_account::AccountHomeError::AccountUnlinked(_)
        ))
    ));
    assert_eq!(published_count(&relay), published);
}

/// The laptop's engine applies its removal but the app never notes it, as
/// after a crash between the two (here, device groups are off when it is
/// applied). A caller then opens its client directly, without the runtime or
/// a pairing drive. The open notes the removal, so the client is stopped
/// before the caller can send in the chat it is still in (D67).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_opened_after_an_unnoted_removal_is_stopped() {
    let (mut devices, group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let mut laptop_cursor = published_count(&devices.relay);
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
    commit_removal_decided_elsewhere(&mut phone, &group, slot_of(&laptop)).await;
    drop((laptop, laptop_app, phone));
    let off = MarmotApp::with_relay_and_config(
        _dirs[1].path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
    .with_test_relay_client(relay.clone());
    let mut laptop = off.client("alice").await.unwrap();
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    assert!(laptop.runtime.group_record(&group).unwrap().removed);
    assert!(!laptop.device_unlinked());
    drop((laptop, off));

    let laptop_app = device_group_app_at(&_dirs[1], relay.clone());
    let attempted = relay.attempted_events().len();
    let mut laptop = laptop_app.client("alice").await.unwrap();
    assert!(laptop.device_unlinked(), "the open notes the removal");
    let account = laptop_app.account_home().account("alice").unwrap();
    assert!(account.unlinked && account.signed_out);
    assert!(
        !laptop.runtime.group_record(&chat).unwrap().removed,
        "the laptop is still in the chat"
    );
    let sent = laptop.send(&chat, b"still here").await.unwrap();
    assert_eq!(sent.published, 0, "the message is not published");
    assert_eq!(
        relay.attempted_events().len(),
        attempted,
        "nothing goes out"
    );
}

fn profile_bootstrap() -> AccountRelayListBootstrap {
    AccountRelayListBootstrap::new(
        vec![TransportEndpoint("wss://relay.example".into())],
        vec![TransportEndpoint("wss://relay.example".into())],
    )
}

/// The same unnoted removal, and the reopened app publishes the account's
/// profile and relay lists before any client opens. The app looks for the
/// stored removal before it hands out a publisher, so nothing goes out; the
/// client opened next tells it was an unlink (D67).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_app_publish_after_an_unnoted_removal_is_refused() {
    let (devices, group) = tagging_devices().await;
    let mut laptop_cursor = published_count(&devices.relay);
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
    commit_removal_decided_elsewhere(&mut phone, &group, slot_of(&laptop)).await;
    drop((laptop, laptop_app, phone));
    let off = MarmotApp::with_relay_and_config(
        _dirs[1].path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
    .with_test_relay_client(relay.clone());
    let mut laptop = off.client("alice").await.unwrap();
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    assert!(laptop.runtime.group_record(&group).unwrap().removed);
    drop((laptop, off));

    let laptop_app = device_group_app_at(&_dirs[1], relay.clone());
    let attempted = relay.attempted_events().len();
    laptop_app
        .publish_user_profile("alice", UserProfileMetadata::default(), profile_bootstrap())
        .await
        .unwrap_err();
    laptop_app
        .publish_account_relay_lists("alice", profile_bootstrap())
        .await
        .unwrap_err();
    assert_eq!(
        relay.attempted_events().len(),
        attempted,
        "nothing goes out"
    );
    let laptop = laptop_app.client("alice").await.unwrap();
    assert!(laptop.device_unlinked());
    assert!(laptop_app.account_home().account("alice").unwrap().unlinked);
}

/// The app looks for a stored removal once per account per process: the
/// client open looks, and the publishers handed out after it do not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stored_removal_is_looked_for_once_per_process() {
    let (devices, _group) = tagging_devices().await;
    let Devices {
        _dirs,
        relay,
        laptop_app,
        laptop,
        ..
    } = devices;
    let account_id_hex = laptop_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    drop((laptop, laptop_app));

    let laptop_app = device_group_app_at(&_dirs[1], relay.clone());
    assert_eq!(laptop_app.stored_device_group_checks(&account_id_hex), 0);
    let laptop = laptop_app.client("alice").await.unwrap();
    assert_eq!(laptop_app.stored_device_group_checks(&account_id_hex), 1);
    for _ in 0..2 {
        laptop_app
            .publish_user_profile("alice", UserProfileMetadata::default(), profile_bootstrap())
            .await
            .unwrap();
    }
    assert_eq!(laptop_app.stored_device_group_checks(&account_id_hex), 1);
    drop(laptop);
}

/// The laptop's engine applies its removal but the app never notes it, as
/// after a crash between the two (here, device groups are off when it is
/// applied). Started again under the runtime, its worker follows the removal
/// before its catch-up: the account is unlinked and deactivated, and nothing
/// goes out from it (D67).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_applied_before_a_restart_unlinks_before_catch_up() {
    let (devices, group) = tagging_devices().await;
    let mut laptop_cursor = published_count(&devices.relay);
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
    phone
        .remove_linked_device(&own_slot(&laptop))
        .await
        .unwrap();
    drop((laptop, laptop_app, phone));
    let off = MarmotApp::with_relay_and_config(
        _dirs[1].path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
    .with_test_relay_client(relay.clone());
    let mut laptop = off.client("alice").await.unwrap();
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert!(laptop.runtime.group_record(&group).unwrap().removed);
    assert!(!laptop.device_unlinked());
    drop((laptop, off));
    let laptop_app = device_group_app_at(&_dirs[1], relay.clone());
    let account_id_hex = laptop_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;

    let attempted = relay.attempted_events().len();
    let subscriptions = relay.subscription_count();
    let _eose = scripted_eose_pump(
        laptop_app.relay_plane.clone(),
        relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(laptop_app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    next_device_group_change(&mut events, "DeviceUnlinked", |event| {
        matches!(event, MarmotAppEvent::DeviceUnlinked {
            account_id_hex: unlinked,
            account_label,
        } if *unlinked == account_id_hex && account_label == "alice")
    })
    .await;
    let managed = || runtime.accounts().managed_accounts().unwrap().remove(0);
    tokio::time::timeout(Duration::from_secs(10), async {
        while managed().running {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the runtime deactivates the account");
    let account = managed();
    assert!(account.unlinked && account.signed_out);
    assert!(
        trust(&laptop_app, &group).is_none(),
        "its copy is forgotten"
    );
    assert_eq!(
        relay.attempted_events().len(),
        attempted,
        "nothing goes out before the stop"
    );
    assert_eq!(
        relay.subscription_count(),
        subscriptions,
        "it stops before its catch-up subscribes"
    );
    runtime.shutdown().await;
}

/// The laptop runs under the runtime when its removal arrives live. The
/// ingest that applies it stops the account: the runtime deactivates it,
/// and nothing more goes out from it (D67).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_arriving_live_stops_the_running_account() {
    removal_arriving_live(false).await;
}

/// As above, but the worker's client can't write the unlink mark. The
/// runtime makes it as it deactivates the account, so the account is not
/// left merely signed out, which signing in would undo (D67).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_unlink_mark_is_made_as_the_runtime_deactivates() {
    removal_arriving_live(true).await;
}

async fn removal_arriving_live(fail_unlink_mark: bool) {
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
    let slot = own_slot(&laptop);
    drop(laptop);
    let account_id_hex = laptop_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    laptop_app
        .test_fail_unlink_mark
        .store(fail_unlink_mark, Ordering::Relaxed);

    let _eose = scripted_eose_pump(
        laptop_app.relay_plane.clone(),
        relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(laptop_app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();

    // The worker starts with a maintenance pass, whose sends (small state, a
    // private KeyPackage hand-off, a heartbeat) can land after a quiet spell
    // on a loaded machine. The worker takes one turn at a time and commands
    // first, so a pass run as a command either waits for that one or goes
    // before it and leaves it nothing owed: the removal arrives once the
    // laptop has nothing more to send.
    runtime.run_due_maintenance("alice").await.unwrap();
    let removal_start = published_count(&relay);
    phone.remove_linked_device(&slot).await.unwrap();
    drop(phone);
    let removal: Vec<_> = relay.published_events.lock().unwrap()[removal_start..].to_vec();
    let attempted = relay.attempted_events().len();
    // Separate apps share no live relay: route the removal in.
    for event in removal {
        laptop_app
            .relay_plane
            .handle_relay_event_for_test(NostrRelayEvent {
                endpoint: TransportEndpoint("wss://relay.example".to_owned()),
                subscription_id: Some("live-removal-test".to_owned()),
                event,
            })
            .await
            .unwrap();
    }
    next_device_group_change(&mut events, "DeviceUnlinked", |event| {
        matches!(event, MarmotAppEvent::DeviceUnlinked {
            account_id_hex: unlinked,
            ..
        } if *unlinked == account_id_hex)
    })
    .await;
    let managed = || runtime.accounts().managed_accounts().unwrap().remove(0);
    tokio::time::timeout(Duration::from_secs(10), async {
        while managed().running {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the runtime deactivates the account");
    let account = managed();
    assert!(account.unlinked && account.signed_out);
    assert!(matches!(
        runtime.accounts().sign_in_account("alice").await,
        Err(AppError::AccountHome(AccountHomeError::AccountUnlinked(_)))
    ));
    if !fail_unlink_mark {
        assert!(
            trust(&laptop_app, &group).is_none(),
            "its copy is forgotten"
        );
    }
    assert_eq!(
        relay.attempted_events().len(),
        attempted,
        "nothing more goes out"
    );
    runtime.shutdown().await;
}

/// The phone removes the laptop, and deletes its slot, while the laptop
/// renames itself twice from the same epoch. The laptop's longer branch wins
/// and drops the removal, so the laptop is listed again. The phone's next
/// maintenance pass commits the recorded removal again, and the pass after
/// deletes the laptop's slot again, since the laptop could publish to it
/// while it was listed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_branch_selection_drops_is_committed_again() {
    let (
        Devices {
            _dirs,
            relay,
            phone_app,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = tagging_devices().await;
    let laptop_slot = own_slot(&laptop);
    let laptop_slot_bytes = slot_of(&laptop);
    let account_id_hex = phone_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let mut phone_cursor = published_count(&relay);

    phone.remove_linked_device(&laptop_slot).await.unwrap();
    phone.run_due_maintenance().await.unwrap();
    let deletions = slot_deletions(&relay, &account_id_hex, &laptop_slot);
    assert!(deletions > 0);
    assert_eq!(slots_withdrawn(&phone_app), [true]);
    for label in ["Mine", "Still mine"] {
        laptop
            .rename_linked_device(&laptop_slot, label)
            .await
            .unwrap();
    }
    converge_until_labelled(
        &mut phone,
        &relay,
        &mut phone_cursor,
        &group,
        &laptop_slot_bytes,
        "Still mine",
    )
    .await;

    assert!(
        !roster(&phone, &group)
            .rejected_slots
            .contains_key(&laptop_slot_bytes)
    );
    assert_eq!(
        phone
            .linked_devices()
            .unwrap()
            .iter()
            .map(|device| device.removal_pending)
            .collect::<Vec<_>>(),
        [false, true]
    );

    phone.run_due_maintenance().await.unwrap();
    assert!(
        !roster(&phone, &group)
            .devices
            .contains_key(&laptop_slot_bytes),
        "the removal is committed again"
    );
    assert_eq!(slots_withdrawn(&phone_app), [false]);
    assert_eq!(
        slot_deletions(&relay, &account_id_hex, &laptop_slot),
        deletions
    );
    phone.run_due_maintenance().await.unwrap();
    assert!(slot_deletions(&relay, &account_id_hex, &laptop_slot) > deletions);
    let after = roster(&phone, &group);
    assert_eq!(
        after.rejected_slots[&laptop_slot_bytes].reason,
        RejectedSlotReasonV1::Removed
    );
    assert_eq!(slots_withdrawn(&phone_app), [true]);
}

/// A decision is kept for as long as the phone trusts the device group, even
/// once the `removed` record has expired. The phone carries out a removal it
/// decided 31 days ago, and its expiry pass then drops the record, so the
/// roster neither lists nor records the laptop; the slot is deleted all the
/// same. The laptop, which saw neither commit, renames itself three times;
/// its deeper branch wins and the laptop is listed again. The phone's next
/// maintenance pass removes it again, and the one after deletes its slot
/// again, though that removal's record expires at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_whose_record_expired_is_made_again() {
    let (
        Devices {
            _dirs,
            relay,
            phone_app,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = tagging_devices().await;
    let laptop_slot = own_slot(&laptop);
    let laptop_slot_bytes = slot_of(&laptop);
    let account_id_hex = phone_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let mut phone_cursor = published_count(&relay);
    phone_app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .record_device_removal(
            &hex::encode(group.as_slice()),
            &laptop_slot,
            crate::unix_now_seconds() - 31 * 24 * 60 * 60,
        )
        .unwrap();

    phone.run_due_maintenance().await.unwrap();
    phone.run_due_maintenance().await.unwrap();
    let expired = roster(&phone, &group);
    assert!(!expired.devices.contains_key(&laptop_slot_bytes));
    assert!(!expired.rejected_slots.contains_key(&laptop_slot_bytes));
    assert_eq!(pending_removals(&phone_app), 1, "the decision is kept");
    let deletions = slot_deletions(&relay, &account_id_hex, &laptop_slot);
    assert!(deletions > 0, "the slot is deleted without the record");
    assert_eq!(slots_withdrawn(&phone_app), [true]);

    for label in ["Mine", "Still mine", "Mine again"] {
        laptop
            .rename_linked_device(&laptop_slot, label)
            .await
            .unwrap();
    }
    converge_until_labelled(
        &mut phone,
        &relay,
        &mut phone_cursor,
        &group,
        &laptop_slot_bytes,
        "Mine again",
    )
    .await;

    phone.run_due_maintenance().await.unwrap();
    assert!(
        !roster(&phone, &group)
            .devices
            .contains_key(&laptop_slot_bytes),
        "the laptop is removed again"
    );
    assert_eq!(slots_withdrawn(&phone_app), [false]);
    phone.run_due_maintenance().await.unwrap();
    assert!(
        slot_deletions(&relay, &account_id_hex, &laptop_slot) > deletions,
        "and its slot deleted again"
    );
    assert_eq!(slots_withdrawn(&phone_app), [true]);
}

/// A decision lasts as long as the phone trusts the device group, not as
/// long as it can read it. While the phone's copy of the device group is
/// terminal and its trust row stays, the decision is kept and nothing is
/// sent for it; once the copy is readable again, the removal is committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_waits_while_the_device_group_copy_is_terminal() {
    let (
        Devices {
            _dirs,
            phone_app,
            mut phone,
            laptop,
            ..
        },
        group,
    ) = tagging_devices().await;
    let laptop_slot_bytes = slot_of(&laptop);
    let storage = phone_app.account_storage("alice").unwrap();
    let stored = cgka_traits::storage::GroupStorage::get_group(&storage, &group).unwrap();
    storage
        .app_storage()
        .record_device_removal(
            &hex::encode(group.as_slice()),
            &own_slot(&laptop),
            crate::unix_now_seconds() - 60,
        )
        .unwrap();
    let mut removed = stored.clone();
    removed.removed = true;
    cgka_traits::storage::GroupStorage::put_group(&storage, &removed).unwrap();

    phone.run_due_maintenance().await.unwrap();
    assert!(trust(&phone_app, &group).is_some_and(DeviceGroupTrust::is_trusted));
    assert_eq!(pending_removals(&phone_app), 1, "the decision is kept");

    cgka_traits::storage::GroupStorage::put_group(&storage, &stored).unwrap();
    phone.run_due_maintenance().await.unwrap();
    assert!(
        !roster(&phone, &group)
            .devices
            .contains_key(&laptop_slot_bytes),
        "the removal is committed once the copy is readable"
    );
}

/// Switching device groups off and on again keeps a decision: while they are
/// off nothing is carried out, and once they are on the removal commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_survives_device_groups_switched_off_and_on() {
    let (
        Devices {
            _dirs,
            relay,
            phone_app,
            phone,
            laptop,
            ..
        },
        group,
    ) = tagging_devices().await;
    let laptop_slot_bytes = slot_of(&laptop);
    phone_app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .record_device_removal(
            &hex::encode(group.as_slice()),
            &own_slot(&laptop),
            crate::unix_now_seconds() - 60,
        )
        .unwrap();
    drop((phone, phone_app));

    let off = MarmotApp::with_relay_and_config(
        _dirs[0].path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
    .with_test_relay_client(relay.clone());
    let mut phone = off.client("alice").await.unwrap();
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(pending_removals(&off), 1, "the decision is kept");
    drop((phone, off));

    let phone_app = device_group_app_at(&_dirs[0], relay);
    let mut phone = phone_app.client("alice").await.unwrap();
    phone.run_due_maintenance().await.unwrap();
    assert!(
        !roster(&phone, &group)
            .devices
            .contains_key(&laptop_slot_bytes),
        "the removal commits once device groups are on"
    );
}

/// Each recorded removal is carried on its own. A removal that fails on
/// every pass (here a row whose slot cannot be read, recorded first) never
/// holds back a later one: removing the laptop still commits, and the
/// failing row stays for the next pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_removal_does_not_hold_back_another() {
    let (
        Devices {
            _dirs,
            phone_app,
            mut phone,
            laptop,
            ..
        },
        group,
    ) = tagging_devices().await;
    phone_app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .record_device_removal(&hex::encode(group.as_slice()), "not a slot", 0)
        .unwrap();

    phone
        .remove_linked_device(&own_slot(&laptop))
        .await
        .unwrap();

    let after = roster(&phone, &group);
    assert!(!after.devices.contains_key(&slot_of(&laptop)));
    assert_eq!(
        after.rejected_slots[&slot_of(&laptop)].reason,
        RejectedSlotReasonV1::Removed
    );
    assert_eq!(pending_removals(&phone_app), 2);
}

/// Each chat is cleaned up on its own. When the same-account Remove the
/// phone sends first is refused, its other chat is still cleaned up in the
/// same pass, and the refused one keeps the laptop's leaf until a later pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chat_that_fails_does_not_hold_back_the_others() {
    let (mut devices, group) = tagging_devices().await;
    let chats = [
        chat_with_both(&mut devices).await,
        chat_with_both(&mut devices).await,
    ];
    let Devices {
        _dirs,
        relay,
        mut phone,
        laptop,
        ..
    } = devices;
    let laptop_slot_bytes = slot_of(&laptop);
    commit_removal_decided_elsewhere(&mut phone, &group, laptop_slot_bytes).await;
    let after = roster(&phone, &group);
    let holding = |phone: &AppClient| {
        chats
            .iter()
            .filter(|chat| {
                !phone
                    .runtime
                    .own_account_leaf_claims(chat, &after)
                    .unwrap()
                    .is_empty()
            })
            .count()
    };
    assert_eq!(holding(&phone), 2);

    relay.reject_next_publish();
    phone.run_due_maintenance().await.unwrap();

    assert_eq!(holding(&phone), 1, "the other chat is cleaned up");
}

/// A removal decided while the device group has a commit of this device's
/// staged is recorded, listed as pending and sends nothing. Once that commit
/// is gone, the next maintenance pass commits the removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_while_the_device_group_is_busy_waits_for_it() {
    let (
        Devices {
            _dirs,
            relay,
            phone_app,
            mut phone,
            laptop,
            ..
        },
        group,
    ) = tagging_devices().await;
    let laptop_slot = own_slot(&laptop);
    let marmot_session::PreparedSessionSend::Commit(staged) = phone
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
        panic!("a stable device group stages the commit");
    };
    assert!(!phone.group_quiet(&group).unwrap());
    let before = published_count(&relay);

    phone.remove_linked_device(&laptop_slot).await.unwrap();

    assert_eq!(published_count(&relay), before, "nothing is sent yet");
    assert_eq!(pending_removals(&phone_app), 1);
    let listed = phone.linked_devices().unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|device| (device.is_this_device, device.removal_pending))
            .collect::<Vec<_>>(),
        [(true, false), (false, true)]
    );
    assert!(phone.take_linked_devices_changed());

    let effects = phone
        .runtime
        .rollback_prepared_session_commit(staged)
        .await
        .unwrap();
    phone
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    assert!(phone.group_quiet(&group).unwrap());

    phone.run_due_maintenance().await.unwrap();
    assert!(
        !roster(&phone, &group)
            .devices
            .contains_key(&slot_of(&laptop))
    );
    assert!(
        phone
            .linked_devices()
            .unwrap()
            .iter()
            .all(|device| !device.removal_pending)
    );
}

/// A removal recorded while the device's entry had its tag signature key,
/// which branch selection then dropped, waits: committing it would leave the
/// device's untagged leaf and record no key. Once the device sets its key
/// again, the next maintenance pass removes it with the key recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_waits_for_the_devices_tag_signature_key() {
    let (
        Devices {
            _dirs,
            relay,
            phone_app,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let laptop_slot = own_slot(&laptop);
    let laptop_slot_bytes = slot_of(&laptop);
    assert_eq!(
        roster(&phone, &group).devices[&laptop_slot_bytes].tag_signature_key,
        None
    );
    // The decision the user took a minute ago, before the key was dropped.
    let decided_at = crate::unix_now_seconds() - 60;
    phone_app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .record_device_removal(&hex::encode(group.as_slice()), &laptop_slot, decided_at)
        .unwrap();
    let start = published_count(&relay);
    let (mut phone_cursor, mut laptop_cursor) = (start, start);

    phone.run_due_maintenance().await.unwrap();
    assert!(
        roster(&phone, &group)
            .devices
            .contains_key(&laptop_slot_bytes)
    );
    assert_eq!(pending_removals(&phone_app), 1);

    // The laptop sees the phone's pass, which announces the phone's new
    // KeyPackage, then sets its key; once the phone settles that commit, its
    // next maintenance pass removes the laptop. The device group is hidden,
    // so convergence runs through the runtime.
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    laptop.run_due_maintenance().await.unwrap();
    let tag_key = roster(&laptop, &group).devices[&laptop_slot_bytes]
        .tag_signature_key
        .clone()
        .expect("the laptop tags");
    deliver_new(&mut phone, &relay, &mut phone_cursor).await;
    let effects = phone.runtime.advance_convergence(&group).await.unwrap();
    phone
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    assert_eq!(
        roster(&phone, &group).devices[&laptop_slot_bytes].tag_signature_key,
        Some(tag_key.clone())
    );
    assert!(phone.group_quiet(&group).unwrap());
    phone.run_due_maintenance().await.unwrap();
    let after = roster(&phone, &group);
    assert!(!after.devices.contains_key(&laptop_slot_bytes));
    assert_eq!(
        after.rejected_slots[&laptop_slot_bytes].tag_signature_key,
        Some(tag_key)
    );
    assert_eq!(
        after.rejected_slots[&laptop_slot_bytes].rejected_at,
        decided_at
    );
}

/// Removal is refused, with nothing recorded or sent, for this device, for a
/// slot the roster doesn't list, for a device whose link may still fail
/// (no tag signature key yet), and without a device group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_is_refused_with_nothing_recorded() {
    let (
        Devices {
            _dirs,
            relay,
            phone_app,
            mut phone,
            laptop,
            ..
        },
        _group,
    ) = linked_devices().await;
    let before = published_count(&relay);
    let phone_slot = own_slot(&phone);
    assert_eq!(
        refusal(phone.remove_linked_device(&phone_slot).await.unwrap_err()),
        "this_device"
    );
    for slot in ["07".repeat(32), "not a slot".to_owned()] {
        assert_eq!(
            refusal(phone.remove_linked_device(&slot).await.unwrap_err()),
            "unknown_device"
        );
    }
    assert_eq!(
        refusal(
            phone
                .remove_linked_device(&own_slot(&laptop))
                .await
                .unwrap_err()
        ),
        "device_link_pending"
    );
    assert_eq!(pending_removals(&phone_app), 0);
    assert_eq!(published_count(&relay), before);

    let Devices {
        _dirs,
        phone_app,
        mut phone,
        laptop,
        ..
    } = phone_and_laptop().await;
    assert_eq!(
        refusal(
            phone
                .remove_linked_device(&own_slot(&laptop))
                .await
                .unwrap_err()
        ),
        "no_device_group"
    );
    assert_eq!(pending_removals(&phone_app), 0);
}

/// A device its trusted roster lists refills its emptied slot like any
/// other (mdk#2628 3.4), announcing the new KeyPackage first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_its_roster_lists_refills_its_slot() {
    let (
        Devices {
            _dirs,
            relay,
            mut laptop,
            ..
        },
        _group,
    ) = tagging_devices().await;
    let laptop_slot = own_slot(&laptop);
    let published = publish_two_days_ago(&laptop);
    relay_empties_slot(&relay, &laptop_slot);

    assert!(laptop.check_sign_ins().await.unwrap().refilling);
    laptop.run_due_maintenance().await.unwrap();
    assert!(published_at(&laptop) > published);
    assert!(relay_serves_slot(&relay, &laptop_slot));
}

/// A device its siblings removed refills nothing in its emptied slot
/// (mdk#2628 3.4): they deleted that slot, and a KeyPackage dated after the
/// deletion reads to them as the removed device trying to come back. Here
/// the removal took the laptop's leaf, so its copy of the device group
/// ended there and it reads no roster; the removal unlinked it (D67), so
/// its maintenance refuses and publishes nothing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_device_never_refills_its_slot() {
    let (
        Devices {
            _dirs,
            relay,
            laptop_app,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = tagging_devices().await;
    let laptop_slot = own_slot(&laptop);
    let mut laptop_cursor = published_count(&relay);
    phone.remove_linked_device(&laptop_slot).await.unwrap();
    phone.run_due_maintenance().await.unwrap();
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    let storage = laptop_app.account_storage("alice").unwrap();
    assert!(
        cgka_traits::storage::GroupStorage::get_group(&storage, &group)
            .unwrap()
            .removed
    );
    let unlinked = |result: Result<_, AppError>| {
        matches!(
            result,
            Err(AppError::AccountHome(
                marmot_account::AccountHomeError::AccountUnlinked(_)
            ))
        )
    };
    assert!(unlinked(laptop.run_due_maintenance().await));

    let published = publish_two_days_ago(&laptop);
    relay_empties_slot(&relay, &laptop_slot);
    assert!(!laptop.check_sign_ins().await.unwrap().refilling);
    assert!(unlinked(laptop.run_due_maintenance().await));
    assert_eq!(published_at(&laptop), published);
    assert!(!relay_serves_slot(&relay, &laptop_slot));
}

/// [`a_removed_device_never_refills_its_slot`] for a removal that took no
/// leaf, as one does when no leaf's tag reads as the slot: the laptop still
/// reads the roster, which records its slot as `removed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_its_roster_records_as_removed_never_refills_its_slot() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = tagging_devices().await;
    let laptop_slot = own_slot(&laptop);
    let laptop_slot_bytes = slot_of(&laptop);
    let removed = RejectedSlotV1 {
        reason: RejectedSlotReasonV1::Removed,
        rejected_at: crate::unix_now_seconds(),
        tag_signature_key: roster(&phone, &group).devices[&laptop_slot_bytes]
            .tag_signature_key
            .clone(),
    };
    let update = encode_device_roster_update_v1(
        &DeviceRosterUpdateV1::new(vec![
            DeviceRosterOperationV1::RemoveDevice(laptop_slot_bytes),
            DeviceRosterOperationV1::SetRejectedSlot(laptop_slot_bytes, removed),
        ])
        .unwrap(),
    )
    .unwrap();
    let mut laptop_cursor = published_count(&relay);
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
    assert_eq!(
        roster(&laptop, &group).rejected_slots[&laptop_slot_bytes].reason,
        RejectedSlotReasonV1::Removed
    );

    let published = publish_two_days_ago(&laptop);
    relay_empties_slot(&relay, &laptop_slot);
    assert!(!laptop.check_sign_ins().await.unwrap().refilling);
    laptop.run_due_maintenance().await.unwrap();
    assert_eq!(published_at(&laptop), published);
    assert!(!relay_serves_slot(&relay, &laptop_slot));
}

/// A device the roster stops listing with no `removed` record is cleaned up
/// after all the same, by the tag signature key this device remembers a
/// roster listing for it (mdk#2761). While the laptop is listed, a
/// maintenance pass leaves its leaf and private KeyPackages alone. Once the
/// roster neither lists nor records it, its chat leaf reads as unclaimed,
/// and while the device group is unsettled, which could still list the
/// laptop again, nothing is cleaned up. Once it settles, the phone discards
/// the private KeyPackages it issued the laptop and removes the laptop's
/// leaf from the chat. A chat that takes no same-account removal keeps the
/// leaf, and the leftover count reports it. Only a deciding device deletes
/// the slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_the_roster_stops_listing_is_cleaned_up_after_by_its_remembered_key() {
    let (mut devices, group) = tagging_devices().await;
    let chat = chat_with_both(&mut devices).await;
    let (_bob_dir, leftover) = chat_without_account_devices(&mut devices).await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        laptop,
        ..
    } = devices;
    let laptop_slot = slot_of(&laptop);
    let account_id_hex = phone_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    phone.run_due_maintenance().await.unwrap();
    assert!(issued_to(&phone, &laptop_slot) > 0);
    assert_eq!(
        chat_claims(&phone, &chat, &group),
        [DeviceTagClaim::Device(laptop_slot)]
    );
    assert_eq!(phone.removed_device_leftover_chats().unwrap(), 0);

    unlist_without_record(&mut phone, &group, laptop_slot).await;
    assert_eq!(
        chat_claims(&phone, &chat, &group),
        [DeviceTagClaim::Unclaimed]
    );
    let marmot_session::PreparedSessionSend::Commit(staged) = phone
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
        panic!("a stable device group stages the commit");
    };
    assert!(!matches!(
        phone.runtime.epoch_state(&group),
        Some(cgka_traits::EpochState::Stable { .. })
    ));
    phone.drive_device_removals().await;
    assert!(issued_to(&phone, &laptop_slot) > 0, "unsettled");
    assert_eq!(chat_claims(&phone, &chat, &group).len(), 1, "unsettled");
    let effects = phone
        .runtime
        .rollback_prepared_session_commit(staged)
        .await
        .unwrap();
    phone
        .observe_drained_session_events(&effects)
        .await
        .unwrap();

    phone.run_due_maintenance().await.unwrap();
    assert_eq!(issued_to(&phone, &laptop_slot), 0);
    assert!(
        chat_claims(&phone, &chat, &group).is_empty(),
        "the laptop's chat leaf is gone"
    );
    // The chat that takes no same-account removal keeps the laptop's leaf,
    // and the count reports it, with no `removed` record to read it by.
    assert_eq!(
        chat_claims(&phone, &leftover, &group),
        [DeviceTagClaim::Unclaimed]
    );
    assert_eq!(phone.removed_device_leftover_chats().unwrap(), 1);
    assert_eq!(
        slot_deletions(&relay, &account_id_hex, &own_slot(&laptop)),
        0
    );
}

/// Deliver what the relay has to `client` and advance its device group's
/// convergence `passes` times. The device group is hidden, so convergence
/// runs through the runtime.
async fn converge_device_group(
    client: &mut AppClient,
    relay: &ScriptedPushRelayClient,
    cursor: &mut usize,
    group: &GroupId,
    passes: usize,
) {
    deliver_new(client, relay, cursor).await;
    for _ in 0..passes {
        let effects = client.runtime.advance_convergence(group).await.unwrap();
        client
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
    }
}

/// The lone `removed` record loses a fork: the laptop, whose entry the
/// roster no longer lists but whose leaf stays, never applied the record and
/// commits twice from the epoch before it, so its branch is the deeper one
/// and the phone adopts it. The phone applied the record, so neither the
/// re-issue of its lost commit nor its next maintenance pass makes the
/// record again (mdk#2761): only that pass makes it, and only until a state
/// the phone applied held it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lone_removed_record_a_fork_drops_is_not_made_again() {
    let (
        Devices {
            _dirs,
            relay,
            phone_app,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = tagging_devices().await;
    let laptop_slot = slot_of(&laptop);
    phone_app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .record_device_removal(
            &hex::encode(group.as_slice()),
            &own_slot(&laptop),
            crate::unix_now_seconds() - 60,
        )
        .unwrap();
    let mut laptop_cursor = published_count(&relay);
    commit_roster(
        &mut phone,
        &group,
        vec![DeviceRosterOperationV1::RemoveDevice(laptop_slot)],
    )
    .await;
    converge_device_group(&mut laptop, &relay, &mut laptop_cursor, &group, 1).await;
    phone.run_due_maintenance().await.unwrap();
    let mut phone_cursor = published_count(&relay);
    assert!(
        roster(&phone, &group)
            .rejected_slots
            .contains_key(&laptop_slot),
        "the phone makes the record"
    );

    for _ in 0..2 {
        let effects = laptop
            .runtime
            .send(SendIntent::SelfUpdate {
                group_id: group.clone(),
            })
            .await
            .unwrap();
        laptop
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
    }
    let laptop_epoch = laptop.runtime.group_record(&group).unwrap().epoch;
    // Adopting the laptop's branch re-issues what the phone lost there; the
    // maintenance pass after it is where the record would be made again.
    converge_device_group(&mut phone, &relay, &mut phone_cursor, &group, 8).await;
    for stage in ["after the fork", "after maintenance"] {
        if stage == "after maintenance" {
            phone.run_due_maintenance().await.unwrap();
            converge_device_group(&mut phone, &relay, &mut phone_cursor, &group, 2).await;
        }
        assert!(
            !roster(&phone, &group)
                .rejected_slots
                .contains_key(&laptop_slot),
            "a record a fork dropped is not made again ({stage})"
        );
        assert_eq!(
            phone.runtime.group_record(&group).unwrap().epoch,
            laptop_epoch,
            "the phone is on the laptop's branch and commits nothing ({stage})"
        );
    }
}

/// A failed link's undo can take the entry of a device the user decided to
/// remove, and it writes no `removed` record. The deciding device commits
/// that record alone, with the tag signature key it remembers for the slot
/// and the decision's time, so devices that never applied a roster listing
/// the key learn it (mdk#2761). Once the phone has seen the record it does
/// not make it again this run: a sibling whose clock drops it early gets no
/// second one. A decision 30 days old makes no record, since the next expiry
/// pass would drop it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_a_failed_link_undid_is_recorded_alone() {
    for (days_ago, recorded) in [(0, true), (31, false)] {
        let (
            Devices {
                _dirs,
                relay,
                phone_app,
                mut phone,
                laptop,
                ..
            },
            group,
        ) = tagging_devices().await;
        let laptop_slot = slot_of(&laptop);
        // Later roster states list another key for the laptop's slot, then
        // its own again: the record carries the key listed last, not the
        // one listed first.
        let entry = roster(&phone, &group).devices[&laptop_slot].clone();
        let tag_signature_key = entry.tag_signature_key.clone();
        for key in [Some(vec![0x01; 32]), tag_signature_key.clone()] {
            let entry = DeviceEntryV1 {
                tag_signature_key: key,
                ..entry.clone()
            };
            commit_roster(
                &mut phone,
                &group,
                vec![DeviceRosterOperationV1::SetDevice(laptop_slot, entry)],
            )
            .await;
        }
        let decided_at = crate::unix_now_seconds() - days_ago * 24 * 60 * 60 - 60;
        phone_app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .record_device_removal(
                &hex::encode(group.as_slice()),
                &own_slot(&laptop),
                decided_at,
            )
            .unwrap();
        unlist_without_record(&mut phone, &group, laptop_slot).await;
        let epoch = phone.runtime.group_record(&group).unwrap().epoch;

        phone.run_due_maintenance().await.unwrap();
        let record = roster(&phone, &group).rejected_slots.remove(&laptop_slot);
        if !recorded {
            assert_eq!(record, None, "{days_ago} days");
            assert_eq!(
                phone.runtime.group_record(&group).unwrap().epoch,
                epoch,
                "nothing is committed for it"
            );
            continue;
        }
        assert_eq!(
            record,
            Some(RejectedSlotV1 {
                reason: RejectedSlotReasonV1::Removed,
                rejected_at: decided_at,
                tag_signature_key,
            })
        );
        commit_roster(
            &mut phone,
            &group,
            vec![DeviceRosterOperationV1::RemoveRejectedSlot(laptop_slot)],
        )
        .await;
        // A roster state the phone applied held the record, so it is not
        // made again, not even after a restart.
        drop((phone, phone_app));
        let phone_app = device_group_app_at(&_dirs[0], relay.clone());
        let mut phone = phone_app.client("alice").await.unwrap();
        phone.run_due_maintenance().await.unwrap();
        assert!(
            !roster(&phone, &group)
                .rejected_slots
                .contains_key(&laptop_slot),
            "the record is made once"
        );
        // Four later states list newer keys for the slot, then it is unlisted
        // again. The key the record carried is no longer among the slot's
        // four newest, and still the record is not made again.
        for key in 2..=5 {
            let entry = DeviceEntryV1 {
                tag_signature_key: Some(vec![key; 32]),
                ..entry.clone()
            };
            commit_roster(
                &mut phone,
                &group,
                vec![DeviceRosterOperationV1::SetDevice(laptop_slot, entry)],
            )
            .await;
        }
        commit_roster(
            &mut phone,
            &group,
            vec![DeviceRosterOperationV1::RemoveDevice(laptop_slot)],
        )
        .await;
        phone.run_due_maintenance().await.unwrap();
        assert!(
            !roster(&phone, &group)
                .rejected_slots
                .contains_key(&laptop_slot),
            "newer keys past the cap leave the record made once"
        );
    }
}
