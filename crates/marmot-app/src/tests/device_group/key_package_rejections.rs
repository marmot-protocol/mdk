//! Rejected KeyPackages (mdk#2628 item 3.7b, D52, D59). A device rejects a
//! valid KeyPackage of the account that someone holding the account key
//! published in its own slot, and each one a complete check finds in a slot
//! the user rejected as not theirs. It never rejects one it made, one a
//! roster announced or one a device's tag claims. It keeps each rejection,
//! warns, and commits it to the roster, again whenever the roster loses it.

use std::collections::BTreeSet;

use super::*;
use crate::client::key_package_rejections::RejectionGuard;
use crate::client::sign_ins::SlotOutcome;
use crate::tests::sign_ins::{Account, commit_roster, link_for, published_at};
use crate::{CompromiseWarningReason, SignInResponse};
use nostr_directory::{AccountRelayListStatus, CurrentKeyPackage, FetchedKeyPackage};
use storage_sqlite::KeptKeyPackageRejection;

/// Publish the newest KeyPackage event in slot `from` again in slot `into`,
/// at `created_at`, as whoever holds the account key can.
fn copy_key_package(relay: &ScriptedPushRelayClient, from: &str, into: &str, created_at: u64) {
    let mut events = relay.published_events.lock().unwrap();
    let original = events
        .iter()
        .rev()
        .find(|event| event.kind == 30443 && event.tag_value("d") == Some(from))
        .unwrap()
        .clone();
    let mut tags = original.tags;
    tags.iter_mut().find(|tag| tag[0] == "d").unwrap()[1] = into.to_owned();
    events.push(NostrTransportEvent::new_unsigned_at(
        original.pubkey,
        original.kind,
        tags,
        original.content,
        created_at,
    ));
}

fn kept(client: &AppClient) -> Vec<KeptKeyPackageRejection> {
    client
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .kept_rejected_key_packages()
        .unwrap()
}

/// What a rejection of `key_package` in `slot` records: its ref, the slot
/// and its leaf signature key.
fn rejection(key_package: &cgka_traits::KeyPackage, slot: &str) -> (String, String, Vec<u8>) {
    let metadata = marmot_session::key_package_metadata(key_package).unwrap();
    (
        metadata.key_package_ref_hex,
        slot.to_owned(),
        metadata.leaf_signature_key,
    )
}

fn kept_records(client: &AppClient) -> Vec<(String, String, Vec<u8>)> {
    kept(client)
        .into_iter()
        .map(|kept| {
            (
                kept.key_package_ref_hex,
                kept.slot_id_hex,
                kept.leaf_signature_key,
            )
        })
        .collect()
}

fn roster_records(client: &AppClient, group: &GroupId) -> Vec<(String, String, Vec<u8>)> {
    roster(client, group)
        .rejected_key_packages
        .into_iter()
        .map(|(key_package_ref, record)| {
            (
                hex::encode(key_package_ref),
                hex::encode(record.slot),
                record.leaf_signature_key,
            )
        })
        .collect()
}

fn warns_of(client: &mut AppClient, (key_package_ref, slot, _): &(String, String, Vec<u8>)) {
    let warning = client.compromise_warning().unwrap();
    assert!(
        warning.iter().any(|item| {
            item.reason == CompromiseWarningReason::RejectedKeyPackage
                && item.key_package_ref_hex.as_ref() == Some(key_package_ref)
                && item.slot_id_hex == *slot
        }),
        "{warning:?}"
    );
}

fn published_count(relay: &ScriptedPushRelayClient) -> usize {
    relay.published_events.lock().unwrap().len()
}

/// Alice's phone and laptop in one device group, the laptop trusting it,
/// on an account with room for more devices. Returns the laptop's cursor.
async fn linked(account: &Account) -> (AppClient, AppClient, GroupId, usize) {
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    phone.check_sign_ins().await.unwrap();
    laptop.check_sign_ins().await.unwrap();
    let link = link_for(&laptop_key_package, 0x5a, &phone);
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut laptop_cursor = 0;
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group.clone()));
    (phone, laptop, group, laptop_cursor)
}

/// Someone holding the account key publishes a KeyPackage of a device
/// outside the device group in this device's own slot. The device replaces
/// it, as before (3.4), and rejects it (D52): it keeps the rejection, warns,
/// and commits the KeyPackage's ref, its own slot and the KeyPackage's leaf
/// signature key, which a sibling then holds and warns of too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreign_key_package_in_its_own_slot_is_rejected() {
    let account = Account::new(3, true);
    let relay = &account.relay;
    let (mut phone, mut laptop, group, mut laptop_cursor) = linked(&account).await;
    let mut tablet = account.open(2).await;
    let tablet_key_package = published_key_package(&mut tablet, relay).await;
    let phone_slot = own_slot(&phone);
    let forged_at = published_at(&phone) + 2;
    copy_key_package(relay, &own_slot(&tablet), &phone_slot, forged_at);

    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&phone_slot], SlotOutcome::OwnSlotForeign);
    assert!(report.foreign.replacing);
    let expected = rejection(&tablet_key_package, &phone_slot);
    assert_eq!(kept_records(&phone), vec![expected.clone()]);
    assert!(roster_records(&phone, &group).is_empty());
    warns_of(&mut phone, &expected);

    phone.commit_key_package_rejections().await.unwrap();
    assert_eq!(roster_records(&phone, &group), vec![expected.clone()]);
    // Once the roster holds it, nothing more is committed, and the device
    // still keeps it.
    let before = published_count(relay);
    phone.commit_key_package_rejections().await.unwrap();
    assert_eq!(published_count(relay), before);
    assert_eq!(kept_records(&phone), vec![expected.clone()]);
    // Checking again finds the same publication and keeps it once.
    phone.check_sign_ins().await.unwrap();
    assert_eq!(kept_records(&phone), vec![expected.clone()]);

    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(roster_records(&laptop, &group), vec![expected.clone()]);
    warns_of(&mut laptop, &expected);

    phone.run_due_maintenance().await.unwrap();
    assert!(published_at(&phone) > forged_at);
}

/// A copy of a KeyPackage this device made, published in its own slot by
/// someone else, is replaced and never rejected, even with no device group
/// to announce or tag it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_copy_of_its_own_key_package_is_replaced_not_rejected() {
    let account = Account::new(1, true);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    let slot = own_slot(&phone);
    let forged_at = published_at(&phone) + 2;
    copy_key_package(&account.relay, &slot, &slot, forged_at);

    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&slot], SlotOutcome::OwnSlotForeign);
    assert!(report.foreign.replacing);
    assert!(kept(&phone).is_empty());
    phone.run_due_maintenance().await.unwrap();
    assert!(published_at(&phone) > forged_at);
}

/// A copy of a sibling's KeyPackage that a roster announced, published in
/// this device's own slot, is replaced and never rejected: rejecting it
/// would reject the sibling's own KeyPackage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_copy_of_an_announced_key_package_is_replaced_not_rejected() {
    let account = Account::new(2, true);
    let (mut phone, laptop, group, _) = linked(&account).await;
    let laptop_slot = own_slot(&laptop);
    let phone_slot = own_slot(&phone);
    // The founding roster announced the KeyPackage the link added.
    assert!(
        roster(&phone, &group).devices[&slot_of(&laptop)]
            .announced_key_package
            .is_some()
    );
    let forged_at = published_at(&phone) + 2;
    copy_key_package(&account.relay, &laptop_slot, &phone_slot, forged_at);

    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&phone_slot], SlotOutcome::OwnSlotForeign);
    assert!(report.foreign.replacing);
    assert!(kept(&phone).is_empty());
}

/// A KeyPackage whose LeafNode carries a device's tag is never rejected,
/// even where no roster this device held announced it, as for a device
/// linked after the announcement. Read against a roster with no tag key for
/// that device, the same KeyPackage is rejectable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_package_a_device_tag_claims_is_never_rejected() {
    let (
        Devices {
            _dirs,
            mut phone,
            laptop,
            ..
        },
        group,
    ) = tagging_devices().await;
    let key_package = laptop
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .current_key_package
        .unwrap();
    let metadata = marmot_session::key_package_metadata(&key_package).unwrap();
    let found = CurrentKeyPackage {
        fetched: FetchedKeyPackage {
            account_id_hex: hex::encode(phone.runtime.self_id().as_slice()),
            key_package,
            key_package_id: own_slot(&laptop),
            key_package_ref_hex: metadata.key_package_ref_hex,
            key_package_event_id: "00".repeat(32),
            created_at: unix_now_seconds(),
            source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
        },
        leaf_signature_key: metadata.leaf_signature_key,
    };
    let mut unannounced = roster(&phone, &group);
    for device in unannounced.devices.values_mut() {
        device.announced_key_package = None;
    }
    let guard = |roster: &DeviceRosterV1| RejectionGuard {
        roster: Some(roster.clone()),
        announced: BTreeSet::new(),
        own: BTreeSet::new(),
    };
    assert!(
        !phone
            .reject_found_key_package(&found, &guard(&unannounced))
            .unwrap()
    );
    assert!(kept(&phone).is_empty());

    unannounced
        .devices
        .get_mut(&slot_of(&laptop))
        .unwrap()
        .tag_signature_key = None;
    assert!(
        phone
            .reject_found_key_package(&found, &guard(&unannounced))
            .unwrap()
    );
}

/// This wasn't me makes a check due at once (D59). That check, complete,
/// finds the slot's KeyPackage there and nowhere else, so the device rejects
/// it, and the next drive commits it. When the roster loses it, the device
/// that keeps it commits it again, even across a restart in between: it
/// compares what it keeps with the roster rather than remember a loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn this_wasnt_me_rejects_the_key_package_in_that_slot() {
    let account = Account::new(3, true);
    let relay = &account.relay;
    let (mut phone, mut laptop, group, mut laptop_cursor) = linked(&account).await;
    let mut tablet = account.open(2).await;
    let tablet_key_package = published_key_package(&mut tablet, relay).await;
    let tablet_slot = own_slot(&tablet);
    phone.check_sign_ins().await.unwrap();
    assert!(kept(&phone).is_empty());

    phone
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    assert!(kept(&phone).is_empty());
    phone.drive_sign_ins().await;
    let expected = rejection(&tablet_key_package, &tablet_slot);
    assert_eq!(kept_records(&phone), vec![expected.clone()]);
    assert_eq!(roster_records(&phone, &group), vec![expected.clone()]);
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(roster_records(&laptop, &group), vec![expected.clone()]);

    let key_package_ref = hex::decode(&expected.0).unwrap();
    commit_roster(
        &mut laptop,
        &group,
        vec![DeviceRosterOperationV1::RemoveRejectedKeyPackage(
            key_package_ref,
        )],
    )
    .await;
    let mut phone_cursor = 0;
    deliver_new(&mut phone, relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    assert!(roster_records(&phone, &group).is_empty());
    drop(phone);
    let mut phone = account.open(0).await;
    assert_eq!(kept_records(&phone), vec![expected.clone()]);
    phone.commit_key_package_rejections().await.unwrap();
    assert_eq!(roster_records(&phone, &group), vec![expected.clone()]);
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(roster_records(&laptop, &group), vec![expected]);
}

/// A check cut short may have missed the slot a copy came from, so it
/// rejects nothing in a rejected sign-in's slot (D59). The next complete
/// check does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_incomplete_check_rejects_nothing() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.check_sign_ins().await.unwrap();
    let mut tablet = account.open(1).await;
    let tablet_key_package = published_key_package(&mut tablet, relay).await;
    let tablet_slot = own_slot(&tablet);
    phone.check_sign_ins().await.unwrap();
    phone
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();

    // A full page of the account's publications cuts the read short.
    let flood_from = published_count(relay);
    {
        let mut events = relay.published_events.lock().unwrap();
        for n in 0..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT {
            events.push(NostrTransportEvent::new_unsigned_at(
                account.alice_id.clone(),
                30443,
                vec![vec!["d".to_owned(), format!("{n:064x}")]],
                "not a key package".to_owned(),
                1,
            ));
        }
    }
    let report = phone.check_sign_ins().await.unwrap();
    assert!(!report.complete);
    assert!(kept(&phone).is_empty());

    relay
        .published_events
        .lock()
        .unwrap()
        .drain(flood_from..flood_from + transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT);
    let report = phone.check_sign_ins().await.unwrap();
    assert!(report.complete);
    assert_eq!(
        kept_records(&phone),
        [rejection(&tablet_key_package, &tablet_slot)]
    );
}

/// A device with no device group keeps the KeyPackages it rejects and warns.
/// Once it trusts a device group it joined, it commits them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_joining_device_commits_the_key_packages_it_rejected() {
    let account = Account::new(3, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    laptop.check_sign_ins().await.unwrap();
    let mut tablet = account.open(2).await;
    let tablet_key_package = published_key_package(&mut tablet, relay).await;
    let tablet_slot = own_slot(&tablet);
    laptop.check_sign_ins().await.unwrap();
    laptop
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    laptop.check_sign_ins().await.unwrap();
    let expected = rejection(&tablet_key_package, &tablet_slot);
    assert_eq!(kept_records(&laptop), vec![expected.clone()]);
    warns_of(&mut laptop, &expected);
    // With no device group there is nowhere to commit it.
    let before = published_count(relay);
    laptop.commit_key_package_rejections().await.unwrap();
    assert_eq!(published_count(relay), before);
    assert_eq!(kept_records(&laptop), vec![expected.clone()]);

    let link = link_for(&laptop_key_package, 0x5a, &phone);
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    assert!(roster_records(&phone, &group).is_empty());
    let mut laptop_cursor = 0;
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group.clone()));
    laptop.commit_key_package_rejections().await.unwrap();
    assert_eq!(roster_records(&laptop, &group), vec![expected.clone()]);
    let mut phone_cursor = 0;
    deliver_new(&mut phone, relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    assert_eq!(roster_records(&phone, &group), vec![expected]);
}
