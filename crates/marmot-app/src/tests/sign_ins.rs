//! New sign-ins (mdk#2628 item 3.2): a device checks its account's
//! KeyPackage slots, tells a device that was here before it from a new
//! sign-in, and records rejections in the device group's roster, or here
//! until it has one.

use std::collections::BTreeSet;

use super::canonical_membership::{deliver_new, published_key_package};
use super::*;
use crate::client::sign_ins::{Announcement, SlotOutcome};
use crate::{ConfirmedDeviceLink, SignInResponse, UnrecognizedSignIn, UnrecognizedSignInState};
use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DeviceRosterOperationV1, DeviceRosterV1, RejectedSlotReasonV1,
    decode_device_roster_v1,
};
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
use storage_sqlite::SignInAnswer;

fn sign_in_app_at(
    dir: &tempfile::TempDir,
    relay: Arc<ScriptedPushRelayClient>,
    device_groups: bool,
) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0)
            .with_dev_device_groups(device_groups),
    )
    .with_test_relay_client(relay)
}

/// Alice's account on `N` devices sharing one relay. A device signs in,
/// and publishes its KeyPackage, only when a test opens it.
struct Account {
    _dirs: Vec<tempfile::TempDir>,
    alice_id: String,
    keys: Keys,
    relay: Arc<ScriptedPushRelayClient>,
    apps: Vec<MarmotApp>,
}

impl Account {
    fn new(devices: usize, device_groups: bool) -> Self {
        let dirs: Vec<_> = (0..devices).map(|_| tempfile::tempdir().unwrap()).collect();
        let home = AccountHome::open(dirs[0].path());
        let alice_id = home.create_account("alice").unwrap().account_id_hex;
        let keys = home.load_signing_keys("alice").unwrap();
        for dir in &dirs[1..] {
            AccountHome::open(dir.path())
                .import_account("alice", &keys.secret_key().to_secret_hex())
                .unwrap();
        }
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let apps = dirs
            .iter()
            .map(|dir| sign_in_app_at(dir, relay.clone(), device_groups))
            .collect();
        Self {
            _dirs: dirs,
            alice_id,
            keys,
            relay,
            apps,
        }
    }

    /// Sign in on device `index`.
    async fn open(&self, index: usize) -> AppClient {
        let app = &self.apps[index];
        remember_test_member_inbox(app, &self.alice_id, "wss://relay.example");
        app.client("alice").await.unwrap()
    }
}

fn own_slot(client: &AppClient) -> String {
    client
        .app
        .account_storage("alice")
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap()
        .stable_slot_id
}

/// The link `creator` confirms for `key_package`, naming device group
/// `group`, whose Welcome comes from `creator`'s leaf.
fn link_for(
    key_package: &cgka_traits::KeyPackage,
    group: u8,
    creator: &AppClient,
) -> ConfirmedDeviceLink {
    ConfirmedDeviceLink {
        key_package_event_id_hex: hex::encode(
            key_package.source.as_ref().unwrap().event_id.as_slice(),
        ),
        key_package_ref_hex: key_package_ref(key_package),
        device_group_id: GroupId::new(vec![group; 16]),
        welcome_sender_key: creator.runtime.own_signature_key(),
    }
}

fn key_package_ref(key_package: &cgka_traits::KeyPackage) -> String {
    marmot_session::key_package_metadata(key_package)
        .unwrap()
        .key_package_ref_hex
}

fn roster(client: &AppClient, group: &GroupId) -> DeviceRosterV1 {
    decode_device_roster_v1(
        &client
            .runtime
            .app_component(group, DEVICE_ROSTER_COMPONENT_ID)
            .unwrap()
            .unwrap(),
    )
    .unwrap()
}

fn listed(client: &mut AppClient) -> Vec<(String, bool, UnrecognizedSignInState)> {
    client
        .unrecognized_sign_ins()
        .unwrap()
        .into_iter()
        .map(|sign_in| {
            (
                sign_in.slot_id_hex,
                sign_in.before_this_device,
                sign_in.state,
            )
        })
        .collect()
}

/// Each device's first check takes its baseline. The laptop, signing in
/// after the phone, sees the phone as a device that was here before it; the
/// phone sees the laptop as a new sign-in. Neither lists itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_here_first_and_a_new_sign_in_are_told_apart() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(
        report.slots.into_iter().collect::<Vec<_>>(),
        [(own_slot(&phone), SlotOutcome::OwnSlot)]
    );
    assert!(report.complete);
    assert!(phone.unrecognized_sign_ins().unwrap().is_empty());

    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    let report = laptop.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&own_slot(&laptop)], SlotOutcome::OwnSlot);
    assert_eq!(
        listed(&mut laptop),
        [(own_slot(&phone), true, UnrecognizedSignInState::Prompt)]
    );

    phone.check_sign_ins().await.unwrap();
    let sign_ins = phone.unrecognized_sign_ins().unwrap();
    let [
        UnrecognizedSignIn {
            slot_id_hex,
            before_this_device: false,
            signed_in: true,
            state: UnrecognizedSignInState::Prompt,
            appeared_at,
            last_seen_at,
            ..
        },
    ] = sign_ins.as_slice()
    else {
        panic!("{sign_ins:?}");
    };
    assert_eq!(*slot_id_hex, own_slot(&laptop));
    assert!(appeared_at <= last_seen_at);
    // The prompt names the KeyPackage the slot published.
    let record = phone
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .sign_in(slot_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(
        record.key_package_ref_hex,
        key_package_ref(&laptop_key_package)
    );

    // Not now keeps it listed, with no prompt.
    phone
        .answer_sign_in(slot_id_hex, SignInResponse::NotNow)
        .await
        .unwrap();
    assert_eq!(
        listed(&mut phone),
        [(own_slot(&laptop), false, UnrecognizedSignInState::NotNow)]
    );
    let result = phone
        .answer_sign_in(slot_id_hex, SignInResponse::Dismiss)
        .await;
    assert!(
        matches!(
            result,
            Err(AppError::DeviceGroupRefused("sign_in_unanswered"))
        ),
        "{result:?}"
    );
}

/// Only a fresh, valid KeyPackage under the account's key is a sign-in. A
/// malformed publication in a new slot, or one another key signed, never
/// prompts, whatever its client tag says.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_valid_key_package_is_a_sign_in() {
    let account = Account::new(1, true);
    let (keys, relay) = (&account.keys, &account.relay);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.check_sign_ins().await.unwrap();
    let publish = |keys: &Keys, slot: &str, content: &str, created_at: u64| {
        let event = EventBuilder::new(Kind::Custom(30443), content)
            .tags([
                Tag::parse(["d", slot]).unwrap(),
                Tag::parse(["client", "Totally Legit"]).unwrap(),
                Tag::parse(["mls_protocol_version", "1.0"]).unwrap(),
                Tag::parse(["i", &"ab".repeat(32)]).unwrap(),
            ])
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(keys)
            .unwrap();
        relay
            .published_events
            .lock()
            .unwrap()
            .push(NostrTransportEvent::from_nostr_event(&event).unwrap());
    };
    publish(
        keys,
        &"11".repeat(32),
        "bm90IGEga2V5IHBhY2thZ2U=",
        unix_now_seconds(),
    );
    publish(
        &Keys::generate(),
        &"22".repeat(32),
        "bm90IGEga2V5IHBhY2thZ2U=",
        unix_now_seconds(),
    );
    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots.len(), 1, "{report:?}");
    assert!(phone.unrecognized_sign_ins().unwrap().is_empty());
}

/// Whoever holds the account key can publish a copy of this device's
/// KeyPackage in any slot. Each copy is a sign-in, whatever its `d` looks
/// like, and rejecting one never rejects this device's slot or KeyPackage:
/// another spelling of the slot, or a `d` the roster cannot name, stays
/// rejected here only, and a copy in a new slot rejects that slot alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_copy_of_this_devices_key_package_never_rejects_it() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.check_sign_ins().await.unwrap();
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    let phone_slot = own_slot(&phone);
    let original = relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|event| event.kind == 30443 && event.tag_value("d") == Some(phone_slot.as_str()))
        .unwrap()
        .clone();
    let copy_into = |slot: &str| {
        let mut tags = original.tags.clone();
        tags.iter_mut().find(|tag| tag[0] == "d").unwrap()[1] = slot.into();
        let copy = NostrTransportEvent::new_unsigned_at(
            original.pubkey.clone(),
            original.kind,
            tags,
            original.content.clone(),
            unix_now_seconds(),
        );
        relay.published_events.lock().unwrap().push(copy);
    };
    let aliases = [phone_slot.to_uppercase(), "not-a-slot".to_owned()];
    for alias in &aliases {
        copy_into(alias);
    }
    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&phone_slot], SlotOutcome::OwnSlot);
    for alias in &aliases {
        assert_eq!(report.slots[alias], SlotOutcome::Unrecognized);
        phone
            .answer_sign_in(alias, SignInResponse::Reject)
            .await
            .unwrap();
    }

    let link = link_for(&laptop_key_package, 0x5a, &phone);
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let founded = roster(&phone, &group);
    assert!(founded.rejected_slots.is_empty(), "{founded:?}");
    assert!(founded.rejected_key_packages.is_empty(), "{founded:?}");
    let mut cursor = 0;
    deliver_new(&mut laptop, relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    phone.commit_sign_in_rejections().await.unwrap();
    assert!(roster(&phone, &group).rejected_slots.is_empty());

    let new_slot = "c0".repeat(32);
    copy_into(&new_slot);
    phone.check_sign_ins().await.unwrap();
    phone
        .answer_sign_in(&new_slot, SignInResponse::Reject)
        .await
        .unwrap();
    let roster = roster(&phone, &group);
    assert_eq!(
        roster
            .rejected_slots
            .keys()
            .map(hex::encode)
            .collect::<Vec<_>>(),
        [new_slot]
    );
    assert!(roster.rejected_key_packages.is_empty(), "{roster:?}");
    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&phone_slot], SlotOutcome::OwnSlot);
}

/// Someone holding the account key copies a real device's KeyPackage into a
/// new slot. Rejecting that slot leaves the real device a sign-in, and the
/// founding roster rejects the slot only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_copy_of_another_devices_key_package_rejects_only_its_slot() {
    let account = Account::new(3, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.check_sign_ins().await.unwrap();
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    let mut tablet = account.open(2).await;
    published_key_package(&mut tablet, relay).await;
    let tablet_slot = own_slot(&tablet);
    let original = relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|event| event.kind == 30443 && event.tag_value("d") == Some(tablet_slot.as_str()))
        .unwrap()
        .clone();
    let copy_slot = "c1".repeat(32);
    let mut tags = original.tags.clone();
    tags.iter_mut().find(|tag| tag[0] == "d").unwrap()[1] = copy_slot.clone();
    relay
        .published_events
        .lock()
        .unwrap()
        .push(NostrTransportEvent::new_unsigned_at(
            original.pubkey.clone(),
            original.kind,
            tags,
            original.content.clone(),
            unix_now_seconds(),
        ));

    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&tablet_slot], SlotOutcome::Unrecognized);
    assert_eq!(report.slots[&copy_slot], SlotOutcome::Unrecognized);
    phone
        .answer_sign_in(&copy_slot, SignInResponse::Reject)
        .await
        .unwrap();
    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&copy_slot], SlotOutcome::Rejected);
    assert_eq!(report.slots[&tablet_slot], SlotOutcome::Unrecognized);

    let link = link_for(&laptop_key_package, 0x5a, &phone);
    let group = phone.dev_create_device_group(link).await.unwrap();
    let founded = roster(&phone, &group);
    assert_eq!(
        founded
            .rejected_slots
            .keys()
            .map(hex::encode)
            .collect::<Vec<_>>(),
        [copy_slot]
    );
    assert!(founded.rejected_key_packages.is_empty(), "{founded:?}");
    assert!(
        listed(&mut phone)
            .iter()
            .any(|(slot, _, _)| *slot == tablet_slot)
    );
}

/// A sign-in whose slot a complete read finds empty stays listed, marked as
/// no longer signed in, and can still be rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sign_in_that_signs_out_stays_listed() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.check_sign_ins().await.unwrap();
    let mut laptop = account.open(1).await;
    published_key_package(&mut laptop, relay).await;
    phone.check_sign_ins().await.unwrap();
    let slot = own_slot(&laptop);
    // The laptop signs out: its slot's deletion request, signed as a relay
    // holds it (the scripted relay keeps what it is handed unsigned).
    let deletion = EventBuilder::new(Kind::Custom(5), "")
        .tags([
            Tag::parse(["a", &format!("30443:{}:{slot}", account.alice_id)]).unwrap(),
            Tag::parse(["k", "30443"]).unwrap(),
        ])
        .custom_created_at(Timestamp::from_secs(unix_now_seconds()))
        .finalize(&account.keys)
        .unwrap();
    relay
        .published_events
        .lock()
        .unwrap()
        .push(NostrTransportEvent::from_nostr_event(&deletion).unwrap());

    phone.check_sign_ins().await.unwrap();
    let sign_ins = phone.unrecognized_sign_ins().unwrap();
    assert_eq!(sign_ins.len(), 1);
    assert_eq!(sign_ins[0].slot_id_hex, slot);
    assert!(!sign_ins[0].signed_in);
    assert_eq!(sign_ins[0].state, UnrecognizedSignInState::Prompt);
    phone
        .answer_sign_in(&slot, SignInResponse::Reject)
        .await
        .unwrap();
    assert!(phone.unrecognized_sign_ins().unwrap().is_empty());
}

/// A device with no device group keeps its rejection and never prompts about
/// that slot again. When it creates a device group, the founding roster
/// carries the rejection, and nothing is left to commit. A rejection of the
/// slot it links ends instead: the user confirmed that link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejection_before_any_device_group_founds_the_roster() {
    let account = Account::new(3, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.check_sign_ins().await.unwrap();
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    let mut tablet = account.open(2).await;
    published_key_package(&mut tablet, relay).await;
    phone.check_sign_ins().await.unwrap();
    let tablet_slot = own_slot(&tablet);
    phone
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    let storage = phone.app.account_storage("alice").unwrap().app_storage();
    assert!(
        storage
            .sign_in(&tablet_slot)
            .unwrap()
            .unwrap()
            .roster_pending
    );
    assert_eq!(
        listed(&mut phone),
        [(own_slot(&laptop), false, UnrecognizedSignInState::Prompt)]
    );
    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&tablet_slot], SlotOutcome::Rejected);
    let laptop_slot = own_slot(&laptop);
    phone
        .answer_sign_in(&laptop_slot, SignInResponse::Reject)
        .await
        .unwrap();
    assert!(phone.unrecognized_sign_ins().unwrap().is_empty());

    let link = link_for(&laptop_key_package, 0x5a, &phone);
    let group = phone.dev_create_device_group(link).await.unwrap();
    let roster = roster(&phone, &group);
    let tablet_slot_id: [u8; 32] = hex::decode(&tablet_slot).unwrap().try_into().unwrap();
    assert_eq!(
        roster.rejected_slots[&tablet_slot_id].reason,
        RejectedSlotReasonV1::NotMe
    );
    assert_eq!(roster.rejected_slots.len(), 1);
    // The slot alone: its KeyPackage could be a copy of a real device's.
    assert!(roster.rejected_key_packages.is_empty(), "{roster:?}");
    assert_eq!(roster.devices.len(), 2);

    let before = relay.published_events.lock().unwrap().len();
    phone.commit_sign_in_rejections().await.unwrap();
    assert_eq!(relay.published_events.lock().unwrap().len(), before);
    let tablet_record = storage.sign_in(&tablet_slot).unwrap().unwrap();
    assert_eq!(tablet_record.answer, SignInAnswer::Rejected);
    assert!(!tablet_record.roster_pending);
    let laptop_record = storage.sign_in(&laptop_slot).unwrap().unwrap();
    assert_eq!(laptop_record.answer, SignInAnswer::Dismissed);
    assert!(!laptop_record.roster_pending);
    // The laptop it linked is a roster device now, and leaves the list.
    assert!(phone.unrecognized_sign_ins().unwrap().is_empty());
    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(
        report.slots[&laptop_slot],
        SlotOutcome::KnownDevice {
            announced: Announcement::Matches
        }
    );
}

/// Rejecting a sign-in in a device group is one roster commit. A sibling
/// whose prompt waited for it says it was rejected elsewhere until
/// dismissed, and prompts about it again only while the roster has lost it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejection_in_the_device_group_reaches_every_sibling() {
    let account = Account::new(3, true);
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
    let mut cursor = 0;
    deliver_new(&mut laptop, relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group.clone()));
    // Each knows the other from the roster now.
    assert!(phone.unrecognized_sign_ins().unwrap().is_empty());
    assert!(laptop.unrecognized_sign_ins().unwrap().is_empty());

    let mut tablet = account.open(2).await;
    published_key_package(&mut tablet, relay).await;
    let tablet_slot = own_slot(&tablet);
    for client in [&mut phone, &mut laptop] {
        client.check_sign_ins().await.unwrap();
        assert_eq!(
            listed(client),
            [(tablet_slot.clone(), false, UnrecognizedSignInState::Prompt)]
        );
    }

    let before = relay.published_events.lock().unwrap().len();
    phone
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    assert!(relay.published_events.lock().unwrap().len() > before);
    assert!(phone.unrecognized_sign_ins().unwrap().is_empty());
    let tablet_slot_id: [u8; 32] = hex::decode(&tablet_slot).unwrap().try_into().unwrap();
    assert!(
        roster(&phone, &group)
            .rejected_slots
            .contains_key(&tablet_slot_id)
    );
    phone.commit_sign_in_rejections().await.unwrap();
    assert!(
        !account.apps[0]
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .sign_in(&tablet_slot)
            .unwrap()
            .unwrap()
            .roster_pending
    );

    deliver_new(&mut laptop, relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(
        listed(&mut laptop),
        [(
            tablet_slot.clone(),
            false,
            UnrecognizedSignInState::RejectedElsewhere
        )]
    );
    let result = laptop
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await;
    assert!(
        matches!(
            result,
            Err(AppError::DeviceGroupRefused("sign_in_answered_elsewhere"))
        ),
        "{result:?}"
    );
    laptop
        .answer_sign_in(&tablet_slot, SignInResponse::Dismiss)
        .await
        .unwrap();
    assert!(laptop.unrecognized_sign_ins().unwrap().is_empty());
    let report = laptop.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&tablet_slot], SlotOutcome::Rejected);

    // The roster loses the rejection: the laptop has none of its own, so it
    // asks again, until the phone, which keeps its rejection, restores it.
    laptop
        .commit_device_roster_update(
            group.clone(),
            vec![DeviceRosterOperationV1::RemoveRejectedSlot(tablet_slot_id)],
            "remove_rejected_slot",
        )
        .await
        .unwrap();
    assert_eq!(
        listed(&mut laptop),
        [(tablet_slot.clone(), false, UnrecognizedSignInState::Prompt)]
    );
    laptop
        .answer_sign_in(&tablet_slot, SignInResponse::NotNow)
        .await
        .unwrap();
    let mut phone_cursor = 0;
    deliver_new(&mut phone, relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    phone.commit_sign_in_rejections().await.unwrap();
    assert!(
        roster(&phone, &group)
            .rejected_slots
            .contains_key(&tablet_slot_id)
    );
    deliver_new(&mut laptop, relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert!(laptop.unrecognized_sign_ins().unwrap().is_empty());
}

/// A rejection the roster loses after this device settled it is committed
/// again by this device, with no report that a commit of its own lost. Here
/// another device's roster update removes it, as a winning branch that lacks
/// it would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejection_the_roster_loses_is_committed_again() {
    let account = Account::new(3, true);
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
    let (mut phone_cursor, mut laptop_cursor) = (0, 0);
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group.clone()));

    let mut tablet = account.open(2).await;
    published_key_package(&mut tablet, relay).await;
    let tablet_slot = own_slot(&tablet);
    let tablet_slot_id: [u8; 32] = hex::decode(&tablet_slot).unwrap().try_into().unwrap();
    phone.check_sign_ins().await.unwrap();
    phone
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    phone.commit_sign_in_rejections().await.unwrap();
    let pending = || {
        account.apps[0]
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .sign_in(&tablet_slot)
            .unwrap()
            .unwrap()
            .roster_pending
    };
    assert!(!pending());
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    let holds_it = |client: &AppClient| {
        roster(client, &group)
            .rejected_slots
            .contains_key(&tablet_slot_id)
    };
    assert!(holds_it(&laptop));

    laptop
        .commit_device_roster_update(
            group.clone(),
            vec![DeviceRosterOperationV1::RemoveRejectedSlot(tablet_slot_id)],
            "remove_rejected_slot",
        )
        .await
        .unwrap();
    deliver_new(&mut phone, relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    assert!(!holds_it(&phone));
    assert!(pending());
    phone.commit_sign_in_rejections().await.unwrap();
    assert!(holds_it(&phone));
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert!(holds_it(&laptop));
}

/// Two devices reject different sign-ins at once. Convergence keeps one of
/// the two roster updates; the device whose update lost commits its
/// rejection again, so both reach the roster.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejections_made_at_once_both_reach_the_roster() {
    let account = Account::new(4, true);
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
    let (mut phone_cursor, mut laptop_cursor) = (0, 0);
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group.clone()));

    let mut tablet = account.open(2).await;
    published_key_package(&mut tablet, relay).await;
    let mut tv = account.open(3).await;
    published_key_package(&mut tv, relay).await;
    let (tablet_slot, tv_slot) = (own_slot(&tablet), own_slot(&tv));
    phone.check_sign_ins().await.unwrap();
    laptop.check_sign_ins().await.unwrap();
    phone
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    laptop
        .answer_sign_in(&tv_slot, SignInResponse::Reject)
        .await
        .unwrap();
    // Each sees its own rejection in its roster and settles it.
    phone.commit_sign_in_rejections().await.unwrap();
    laptop.commit_sign_in_rejections().await.unwrap();

    let both = BTreeSet::from([tablet_slot, tv_slot]);
    let rejected = |client: &AppClient| {
        roster(client, &group)
            .rejected_slots
            .keys()
            .map(hex::encode)
            .collect::<BTreeSet<_>>()
    };
    for _ in 0..5 {
        deliver_new(&mut phone, relay, &mut phone_cursor).await;
        phone.sync().await.unwrap();
        deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
        laptop.sync().await.unwrap();
        if rejected(&phone) == both && rejected(&laptop) == both {
            return;
        }
        phone.commit_sign_in_rejections().await.unwrap();
        laptop.commit_sign_in_rejections().await.unwrap();
    }
    panic!(
        "phone {:?}, laptop {:?}",
        rejected(&phone),
        rejected(&laptop)
    );
}

/// A live KeyPackage of the account brings the next check forward to a
/// minute after the last one, instead of six hours.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_key_package_brings_the_check_forward() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.drive_sign_ins().await;
    let mut laptop = account.open(1).await;
    published_key_package(&mut laptop, relay).await;
    // Not due yet.
    phone.drive_sign_ins().await;
    assert!(phone.unrecognized_sign_ins().unwrap().is_empty());

    nostr_directory::DirectoryResources::account_key_package_published(
        &account.apps[0],
        &account.alice_id,
    );
    // Due a minute after the last check: pretend that minute passed.
    phone.sign_in_schedule.last = Some(
        std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(61))
            .unwrap(),
    );
    phone.drive_sign_ins().await;
    assert_eq!(phone.unrecognized_sign_ins().unwrap().len(), 1);
}

/// With device groups off, nothing is checked, listed or answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_ins_stay_off_without_device_groups() {
    let account = Account::new(2, false);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    let mut laptop = account.open(1).await;
    published_key_package(&mut laptop, relay).await;
    assert_eq!(phone.check_sign_ins().await.unwrap(), Default::default());
    assert!(phone.unrecognized_sign_ins().unwrap().is_empty());
    let result = phone
        .answer_sign_in(&own_slot(&laptop), SignInResponse::Reject)
        .await;
    assert!(
        matches!(
            result,
            Err(AppError::DeviceGroupRefused("roster_unsupported"))
        ),
        "{result:?}"
    );
    assert_eq!(
        phone
            .app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .sign_in_baseline()
            .unwrap(),
        None
    );
}
