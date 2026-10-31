//! New sign-ins (mdk#2628 item 3.2): a device checks its account's
//! KeyPackage slots, tells a device that was here before it from a new
//! sign-in, and records rejections in the device group's roster, or here
//! until it has one.

use std::collections::BTreeSet;

use super::canonical_membership::{deliver_events, deliver_new, published_key_package};
use super::*;
use crate::client::sign_ins::{Announcement, SlotOutcome};
use crate::{ConfirmedDeviceLink, SignInResponse, UnrecognizedSignIn, UnrecognizedSignInState};
use cgka_traits::app_components::{
    AppComponentData, DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterOperationV1,
    DeviceRosterUpdateV1, DeviceRosterV1, RejectedSlotReasonV1, RejectedSlotV1,
    decode_device_roster_v1, encode_device_roster_update_v1,
};
use cgka_traits::engine::SendIntent;
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
pub(super) struct Account {
    _dirs: Vec<tempfile::TempDir>,
    pub(super) alice_id: String,
    keys: Keys,
    pub(super) relay: Arc<ScriptedPushRelayClient>,
    pub(super) apps: Vec<MarmotApp>,
}

impl Account {
    pub(super) fn new(devices: usize, device_groups: bool) -> Self {
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
    pub(super) async fn open(&self, index: usize) -> AppClient {
        let app = &self.apps[index];
        remember_test_member_inbox(app, &self.alice_id, "wss://relay.example");
        app.client("alice").await.unwrap()
    }
}

pub(super) fn own_slot(client: &AppClient) -> String {
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
pub(super) fn link_for(
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

pub(super) fn roster(client: &AppClient, group: &GroupId) -> DeviceRosterV1 {
    decode_device_roster_v1(
        &client
            .runtime
            .app_component(group, DEVICE_ROSTER_COMPONENT_ID)
            .unwrap()
            .unwrap(),
    )
    .unwrap()
}

/// One roster commit by `client` in `group`, standing in for another
/// device's change of the roster or a link.
pub(super) async fn commit_roster(
    client: &mut AppClient,
    group: &GroupId,
    operations: Vec<DeviceRosterOperationV1>,
) {
    let update =
        encode_device_roster_update_v1(&DeviceRosterUpdateV1::new(operations).unwrap()).unwrap();
    let effects = client
        .runtime
        .send(SendIntent::UpdateAppComponents {
            group_id: group.clone(),
            updates: vec![AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: update,
            }],
        })
        .await
        .unwrap();
    client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
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

/// A listed sign-in whose publication is still valid but no longer fresh is
/// still signed in: it has not signed out, it just has not been opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sign_in_that_goes_stale_stays_signed_in() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.check_sign_ins().await.unwrap();
    let mut laptop = account.open(1).await;
    published_key_package(&mut laptop, relay).await;
    phone.check_sign_ins().await.unwrap();
    let slot = own_slot(&laptop);
    // Every publication in the laptop's slot ages past freshness, signed as
    // a relay holds it.
    let stale_at = unix_now_seconds() - nostr_directory::KEY_PACKAGE_FRESHNESS.as_secs() - 60;
    let mut aged = 0;
    for event in relay
        .published_events
        .lock()
        .unwrap()
        .iter_mut()
        .filter(|event| {
            event.kind == 30443
                && event
                    .tags
                    .iter()
                    .any(|tag| tag.len() >= 2 && tag[0] == "d" && tag[1] == slot)
        })
    {
        let stale = EventBuilder::new(Kind::Custom(30443), event.content.clone())
            .tags(
                event
                    .tags
                    .iter()
                    .map(|tag| Tag::parse(tag.clone()).unwrap()),
            )
            .custom_created_at(Timestamp::from_secs(stale_at))
            .finalize(&account.keys)
            .unwrap();
        *event = NostrTransportEvent::from_nostr_event(&stale).unwrap();
        aged += 1;
    }
    assert!(aged > 0);

    let report = phone.check_sign_ins().await.unwrap();
    assert!(report.complete);
    let sign_ins = phone.unrecognized_sign_ins().unwrap();
    assert_eq!(sign_ins.len(), 1);
    assert_eq!(sign_ins[0].slot_id_hex, slot);
    assert!(sign_ins[0].signed_in);
}

/// An account that lists no relays has its KeyPackages read from the
/// configured directory relays, and that read is never complete: they need
/// not be where its KeyPackages are, so it signs no sign-in out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_of_relays_the_account_does_not_list_is_never_complete() {
    let account = Account::new(1, true);
    let app = &account.apps[0];
    assert!(
        !app.read_account_key_package_slots("alice", None)
            .await
            .unwrap()
            .complete
    );
    let mut relay_lists = AccountRelayListStatus::empty();
    relay_lists.nip65.created_at = 1;
    relay_lists.nip65.relays = vec!["wss://relay.example".to_owned()];
    relay_lists.refresh();
    app.directory()
        .remember_directory_relay_lists(&account.alice_id, &relay_lists)
        .unwrap();
    assert!(
        app.read_account_key_package_slots("alice", None)
            .await
            .unwrap()
            .complete
    );
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
    let tablet_key_package = published_key_package(&mut tablet, relay).await;
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
    // The complete check after the answer found the tablet's KeyPackage in
    // that slot and in no other, so this device rejected it too (D59).
    let tablet_metadata = marmot_session::key_package_metadata(&tablet_key_package).unwrap();
    assert_eq!(
        roster
            .rejected_key_packages
            .iter()
            .map(|(key_package_ref, record)| (
                hex::encode(key_package_ref),
                record.slot,
                record.leaf_signature_key.clone()
            ))
            .collect::<Vec<_>>(),
        [(
            tablet_metadata.key_package_ref_hex,
            tablet_slot_id,
            tablet_metadata.leaf_signature_key
        )]
    );
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

    // The phone's roster commit is what tells the laptop's host to re-read.
    laptop.take_unrecognized_sign_ins_changed();
    deliver_new(&mut laptop, relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert!(laptop.take_unrecognized_sign_ins_changed());
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
    commit_roster(
        &mut laptop,
        &group,
        vec![DeviceRosterOperationV1::RemoveRejectedSlot(tablet_slot_id)],
    )
    .await;
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

    commit_roster(
        &mut laptop,
        &group,
        vec![DeviceRosterOperationV1::RemoveRejectedSlot(tablet_slot_id)],
    )
    .await;
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

/// A link of a slot this device rejected ends the rejection as soon as this
/// device sees it, not at its next pass. When the link is gone again before
/// that pass, as branch selection can drop it, the device asks about the
/// slot again and commits nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_dropped_before_the_next_pass_asks_again() {
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
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();

    // The laptop links the tablet, and the link is gone again.
    commit_roster(
        &mut laptop,
        &group,
        vec![
            DeviceRosterOperationV1::SetDevice(tablet_slot_id, DeviceEntryV1::default()),
            DeviceRosterOperationV1::RemoveRejectedSlot(tablet_slot_id),
        ],
    )
    .await;
    commit_roster(
        &mut laptop,
        &group,
        vec![DeviceRosterOperationV1::RemoveDevice(tablet_slot_id)],
    )
    .await;
    deliver_new(&mut phone, relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    let record = account.apps[0]
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .sign_in(&tablet_slot)
        .unwrap()
        .unwrap();
    assert_eq!(record.answer, SignInAnswer::Dismissed);
    assert!(!record.roster_pending);
    assert_eq!(
        listed(&mut phone),
        [(tablet_slot.clone(), false, UnrecognizedSignInState::Prompt)]
    );
    let before = relay.published_events.lock().unwrap().len();
    phone.commit_sign_in_rejections().await.unwrap();
    assert_eq!(relay.published_events.lock().unwrap().len(), before);
    let roster = roster(&phone, &group);
    assert!(!roster.devices.contains_key(&tablet_slot_id));
    assert!(!roster.rejected_slots.contains_key(&tablet_slot_id));
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

/// The runtime's rejected-slot write records only slots the merged roster has
/// no entry for: a device's slot and a `removed` record stay as they are. A
/// held device group takes nothing, and a write with nothing left to record
/// sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_slot_write_never_replaces_a_roster_entry() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    let link = link_for(&laptop_key_package, 0x5a, &phone);
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut laptop_cursor = 0;
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();

    let now = unix_now_seconds();
    let laptop_slot: [u8; 32] = hex::decode(own_slot(&laptop)).unwrap().try_into().unwrap();
    let (removed, fresh) = ([7; 32], [9; 32]);
    let removed_record = RejectedSlotV1 {
        reason: RejectedSlotReasonV1::Removed,
        rejected_at: now,
        tag_signature_key: Some(vec![7; 32]),
    };
    let mut phone_cursor = relay.published_events.lock().unwrap().len();
    commit_roster(
        &mut laptop,
        &group,
        vec![DeviceRosterOperationV1::SetRejectedSlot(
            removed,
            removed_record.clone(),
        )],
    )
    .await;
    deliver_new(&mut phone, relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();

    let not_me = RejectedSlotV1 {
        reason: RejectedSlotReasonV1::NotMe,
        rejected_at: now,
        tag_signature_key: None,
    };
    let context = || AppClient::local_human_action_context("reject_sign_in", vec![], vec![], None);
    let before = relay.published_events.lock().unwrap().len();
    phone
        .runtime
        .reject_device_slots(
            &group,
            std::slice::from_ref(&group),
            vec![(fresh, not_me.clone())],
            context(),
        )
        .await
        .unwrap();
    assert_eq!(relay.published_events.lock().unwrap().len(), before);

    let effects = phone
        .runtime
        .reject_device_slots(
            &group,
            &[],
            vec![
                (laptop_slot, not_me.clone()),
                (removed, not_me.clone()),
                (fresh, not_me.clone()),
            ],
            context(),
        )
        .await
        .unwrap();
    phone
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    let held = roster(&phone, &group);
    assert!(held.devices.contains_key(&laptop_slot));
    assert!(!held.rejected_slots.contains_key(&laptop_slot));
    assert_eq!(held.rejected_slots[&removed], removed_record);
    assert_eq!(held.rejected_slots[&fresh], not_me);

    let before = relay.published_events.lock().unwrap().len();
    phone
        .runtime
        .reject_device_slots(&group, &[], vec![(fresh, not_me)], context())
        .await
        .unwrap();
    assert_eq!(relay.published_events.lock().unwrap().len(), before);
}

/// A roster update of this device's that loses to another branch tells the
/// host to re-read its devices and sign-ins, which now read the winner's
/// roster. One in a chat does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_superseded_roster_update_tells_the_host_sign_ins_changed() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    let link = link_for(&laptop_key_package, 0x5a, &phone);
    let group = phone.dev_create_device_group(link).await.unwrap();
    let chat = phone.create_group("chat", &[]).await.unwrap();

    let superseded = |group_id: &GroupId| {
        let mut effects = marmot_session::AccountDeviceEffects::default();
        effects
            .superseded_intents
            .push(cgka_traits::engine::SupersededIntentReport {
                group_id: group_id.clone(),
                commit_id: cgka_traits::MessageId::new(group_id.as_slice().to_vec()),
                kind: cgka_traits::engine::SupersededIntentKind::AppComponents,
                outcome: cgka_traits::engine::SupersededIntentOutcome::Conflict,
                reason: "test",
            });
        effects
    };
    phone.take_unrecognized_sign_ins_changed();
    phone.take_linked_devices_changed();
    phone.note_superseded_intent_reports(&superseded(&chat));
    assert!(!phone.take_unrecognized_sign_ins_changed());
    assert!(!phone.take_linked_devices_changed());

    phone.note_superseded_intent_reports(&superseded(&group));
    assert!(phone.take_unrecognized_sign_ins_changed());
    assert!(phone.take_linked_devices_changed());
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

/// The deliveries published after `cursor`, with the Welcome rumors that name
/// `own` first or last and the order otherwise kept. Advances `cursor`.
async fn welcomes_ordered(
    account: &Account,
    cursor: &mut usize,
    own: &MessageId,
    own_first: bool,
) -> Vec<NostrTransportEvent> {
    let events = account.relay.published_events.lock().unwrap()[*cursor..].to_vec();
    *cursor += events.len();
    let peeler =
        transport_nostr_peeler::NostrMlsPeeler::new().with_welcome_signer(account.keys.clone());
    let (mut named, mut own_rumors, mut other_rumors) = (Vec::new(), 0, 0);
    for event in events {
        let names_own = match peeler
            .peel_welcome_with_provenance(&event.to_transport_message().unwrap())
            .await
        {
            Ok((_, provenance)) => {
                let names_own = provenance.key_package_event_id.as_slice() == own.as_slice();
                if names_own {
                    own_rumors += 1;
                } else {
                    other_rumors += 1;
                }
                names_own
            }
            Err(_) => false,
        };
        named.push((names_own != own_first, event));
    }
    assert!(own_rumors > 0 && other_rumors > 0, "both devices' rumors");
    named.sort_by_key(|(later, _)| *later);
    named.into_iter().map(|(_, event)| event).collect()
}

/// A Welcome that names another KeyPackage of the account brings the check
/// forward too (mdk#2628 3.2). Bob invites Alice, so the phone also receives
/// the delivery made for the laptop's KeyPackage, which is not addressed to
/// it, and checks within the minute, whichever delivery comes first. Anyone
/// can send such a Welcome: a burst right after a check waits its minute,
/// then makes one check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_welcome_naming_another_key_package_brings_the_check_forward() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    let phones = published_key_package(&mut phone, relay)
        .await
        .source
        .unwrap()
        .event_id;
    phone.drive_sign_ins().await;
    let mut laptop = account.open(1).await;
    published_key_package(&mut laptop, relay).await;
    let a_minute = std::time::Duration::from_secs(61);
    // Whether a pass a minute on from the last check runs one.
    let checks_a_minute_on = async |phone: &mut AppClient| {
        phone.sign_in_schedule.rewind(a_minute);
        let before = phone.sign_in_schedule.last;
        phone.drive_sign_ins().await;
        phone.sign_in_schedule.last != before
    };
    assert!(!checks_a_minute_on(&mut phone).await, "nothing nudged it");

    let bob_dir = tempfile::tempdir().unwrap();
    AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap();
    let bob_app = sign_in_app_at(&bob_dir, relay.clone(), false);
    remember_test_member_inbox(&bob_app, &account.alice_id, "wss://relay.example");
    let mut bob = bob_app.client("bob").await.unwrap();
    let mut cursor = relay.published_events.lock().unwrap().len();
    // The phone's own deliveries first: it joins each group before the
    // laptop's delivery of the same Welcome arrives.
    for name in ["one", "two", "three"] {
        bob.create_group(name, &[&account.alice_id]).await.unwrap();
    }
    let burst = welcomes_ordered(&account, &mut cursor, &phones, true).await;
    let delivered = deliver_events(&mut phone, &burst).await;
    assert_eq!(delivered.joined_groups.len(), 3);
    assert!(phone.unrecognized_sign_ins().unwrap().is_empty());
    assert!(checks_a_minute_on(&mut phone).await);
    assert_eq!(
        listed(&mut phone),
        [(own_slot(&laptop), false, UnrecognizedSignInState::Prompt)]
    );

    // A burst right after a check, the laptop's deliveries first, waits its
    // minute, then makes one check and leaves none pending.
    for name in ["four", "five", "six"] {
        bob.create_group(name, &[&account.alice_id]).await.unwrap();
    }
    let burst = welcomes_ordered(&account, &mut cursor, &phones, false).await;
    let delivered = deliver_events(&mut phone, &burst).await;
    assert_eq!(delivered.joined_groups.len(), 3);
    let checked = phone.sign_in_schedule.last;
    phone.drive_sign_ins().await;
    assert_eq!(
        phone.sign_in_schedule.last, checked,
        "not within the minute"
    );
    assert!(checks_a_minute_on(&mut phone).await);
    assert!(!checks_a_minute_on(&mut phone).await, "one check per burst");
}

/// Sign a publication into `slot` with the account's key at `created_at`,
/// holding `content`, as if whoever holds the key published it there.
fn publish_into_slot(account: &Account, slot: &str, content: &str, created_at: u64) -> String {
    let event = EventBuilder::new(Kind::Custom(30443), content)
        .tags([Tag::parse(["d", slot]).unwrap()])
        .custom_created_at(Timestamp::from_secs(created_at))
        .finalize(&account.keys)
        .unwrap();
    let event = NostrTransportEvent::from_nostr_event(&event).unwrap();
    let id = event.id.clone();
    account.relay.published_events.lock().unwrap().push(event);
    id
}

pub(super) fn published_at(client: &AppClient) -> u64 {
    client
        .runtime
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .authored_event_created_at
        .unwrap()
        .0
}

/// A publication in this device's own slot that it did not make, valid or
/// not, is replaced by a newer KeyPackage of its own, even with no device
/// group: `foundation/key-packages.md`, "A publication the device did not
/// make" (mdk#2628 3.4). One that holds no valid KeyPackage is not rejected
/// (3.7b): there is nothing to name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreign_publication_in_its_own_slot_is_replaced() {
    let account = Account::new(1, true);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    let slot = own_slot(&phone);
    let forged_at = published_at(&phone) + 2;
    publish_into_slot(&account, &slot, "not a key package", forged_at);

    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&slot], SlotOutcome::OwnSlotForeign);
    assert!(report.foreign.replacing);
    assert!(report.own_slot_complete);
    assert!(phone.unrecognized_sign_ins().unwrap().is_empty());
    assert!(
        phone
            .app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .kept_rejected_key_packages()
            .unwrap()
            .is_empty()
    );
    phone.run_due_maintenance().await.unwrap();
    assert!(published_at(&phone) > forged_at);

    // Its own publication, now the slot's newest, is never mistaken for a
    // foreign one.
    let before = account.relay.published_events.lock().unwrap().len();
    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&slot], SlotOutcome::OwnSlot);
    assert!(!report.foreign.replacing);
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(account.relay.published_events.lock().unwrap().len(), before);
}

/// A host's check while maintenance is paused cannot replace a foreign
/// publication in this device's slot, so it leaves the schedule alone: the
/// first pass after resume checks again and replaces it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_check_now_while_paused_leaves_the_own_slot_repair_due() {
    let account = Account::new(1, true);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    let slot = own_slot(&phone);
    let forged_at = published_at(&phone) + 2;
    publish_into_slot(&account, &slot, "not a key package", forged_at);

    phone.pause_maintenance();
    phone.check_sign_ins_now().await.unwrap();
    phone.resume_maintenance();
    phone.run_due_maintenance().await.unwrap();
    assert!(published_at(&phone) > forged_at);
}

/// A foreign publication dated further ahead than this device would sign
/// cannot be outranked. The device asks the relays to delete that event by
/// id (D63), publishes again to fill the slot, and its refreshes go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreign_publication_dated_far_ahead_is_deleted_by_id() {
    let account = Account::new(1, true);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    let slot = own_slot(&phone);
    let published = published_at(&phone);
    let far = publish_into_slot(
        &account,
        &slot,
        "not a key package",
        unix_now_seconds() + 864_000,
    );

    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.slots[&slot], SlotOutcome::OwnSlotForeign);
    assert_eq!(report.foreign.beyond_skew, 1);
    assert_eq!(report.foreign.deleted, 1);
    let deletions = account
        .relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.kind == 5)
        .cloned()
        .collect::<Vec<_>>();
    let [deletion] = deletions.as_slice() else {
        panic!("{deletions:?}");
    };
    assert_eq!(deletion.pubkey, account.alice_id);
    assert_eq!(
        deletion.tags,
        vec![
            vec!["e".to_owned(), far],
            vec!["k".to_owned(), "30443".to_owned()],
        ]
    );

    phone.run_due_maintenance().await.unwrap();
    let lifecycle = phone
        .runtime
        .key_package_maintenance_status()
        .unwrap()
        .unwrap();
    assert!(lifecycle.authored_event_created_at.unwrap().0 > published);
    assert!(lifecycle.authored_event_created_at.unwrap().0 <= unix_now_seconds() + 300);
    assert_ne!(
        lifecycle.phase,
        cgka_traits::MaintenancePhase::ClockSkewBlocked
    );
}

/// The relay stops serving anything in `slot`, as one that honored a
/// deletion there does, whether or not it said so.
pub(super) fn relay_empties_slot(relay: &ScriptedPushRelayClient, slot: &str) {
    relay.published_events.lock().unwrap().retain(|event| {
        event.kind != KIND_MARMOT_KEY_PACKAGE || event.tag_value("d") != Some(slot)
    });
}

/// Whether the relay serves a publication in `slot`.
pub(super) fn relay_serves_slot(relay: &ScriptedPushRelayClient, slot: &str) -> bool {
    relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == KIND_MARMOT_KEY_PACKAGE && event.tag_value("d") == Some(slot))
}

/// Record this device's current publication as made two days ago: a slot
/// emptied of one less than a day old waits. Returns its new time.
pub(super) fn publish_two_days_ago(client: &AppClient) -> u64 {
    let storage = client.app.account_storage(&client.state.label).unwrap();
    let mut lifecycle = storage.key_package_lifecycle().unwrap().unwrap();
    let published = lifecycle.authored_event_created_at.as_mut().unwrap();
    published.0 -= 2 * 24 * 60 * 60;
    let aged = published.0;
    storage.put_key_package_lifecycle(&lifecycle).unwrap();
    aged
}

/// A deletion by id that the relay honored but never acknowledged leaves it
/// serving nothing in this device's slot, though it accepted the device's
/// KeyPackage. The next check reads the slot empty there and publishes a new
/// KeyPackage (mdk#2628 3.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unacknowledged_deletion_that_emptied_the_slot_is_refilled() {
    let account = Account::new(1, true);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    let slot = own_slot(&phone);
    let published = publish_two_days_ago(&phone);
    publish_into_slot(
        &account,
        &slot,
        "not a key package",
        unix_now_seconds() + 864_000,
    );

    account.relay.zero_ack_next_publish();
    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!((report.foreign.beyond_skew, report.foreign.deleted), (1, 0));
    assert!(!report.refilling);
    assert!(
        !phone.runtime.key_package_network_maintenance_due().unwrap(),
        "no relay said it deleted"
    );

    relay_empties_slot(&account.relay, &slot);
    let report = phone.check_sign_ins().await.unwrap();
    assert!(report.own_slot_complete);
    assert_eq!(report.foreign, Default::default());
    assert!(report.refilling);
    phone.run_due_maintenance().await.unwrap();
    assert!(published_at(&phone) > published);
    assert!(relay_serves_slot(&account.relay, &slot));
}

/// A slot withdrawal no relay acknowledged rolls back, though a relay may
/// have honored it and emptied the slot. The withdrawing runtime publishes
/// nothing more; the account's next one reads the slot empty there and
/// publishes a new KeyPackage, since the withdrawal covers the current one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawal_that_rolled_back_is_refilled_by_the_next_runtime() {
    let account = Account::new(1, true);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    let slot = own_slot(&phone);
    let published = publish_two_days_ago(&phone);

    account.relay.zero_ack_next_publish();
    phone.withdraw_key_package_slot().await.unwrap_err();
    relay_empties_slot(&account.relay, &slot);
    assert!(!phone.check_sign_ins().await.unwrap().refilling);
    drop(phone);

    let mut phone = account.open(0).await;
    assert_eq!(
        published_at(&phone),
        published,
        "the withdrawal rolled back"
    );
    let report = phone.check_sign_ins().await.unwrap();
    assert!(report.refilling);
    phone.run_due_maintenance().await.unwrap();
    assert!(published_at(&phone) > published);
    assert!(relay_serves_slot(&account.relay, &slot));
}

/// Whoever holds the account key can delete this device's slot by its
/// address. A relay that honors that serves nothing there and refuses any
/// publication in the slot dated up to the deletion, the device's current
/// one included, so the device publishes a new KeyPackage dated after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreign_deletion_of_its_own_slot_is_refilled() {
    let account = Account::new(1, true);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    let slot = own_slot(&phone);
    let deleted_at = publish_two_days_ago(&phone) + 60;
    let address = format!("{KIND_MARMOT_KEY_PACKAGE}:{}:{slot}", account.alice_id);
    let deletion = EventBuilder::new(Kind::Custom(5), "")
        .tags([
            Tag::parse(["a", address.as_str()]).unwrap(),
            Tag::parse(["k", "30443"]).unwrap(),
        ])
        .custom_created_at(Timestamp::from_secs(deleted_at))
        .finalize(&account.keys)
        .unwrap();
    account
        .relay
        .published_events
        .lock()
        .unwrap()
        .push(NostrTransportEvent::from_nostr_event(&deletion).unwrap());
    relay_empties_slot(&account.relay, &slot);

    let report = phone.check_sign_ins().await.unwrap();
    assert_eq!(report.foreign, Default::default());
    assert!(report.refilling);
    phone.run_due_maintenance().await.unwrap();
    assert!(published_at(&phone) > deleted_at);
    assert!(relay_serves_slot(&account.relay, &slot));
}

/// Only a relay's finished read shows the slot empty. A read that reached no
/// relay, or one that stopped short, never refills it: the slot may hold
/// what the read missed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unfinished_read_never_refills_the_slot() {
    use std::sync::atomic::Ordering::SeqCst;

    let account = Account::new(1, true);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    let slot = own_slot(&phone);
    let published = publish_two_days_ago(&phone);
    relay_empties_slot(&account.relay, &slot);
    account.relay.unfinished_directory_reads.store(true, SeqCst);

    phone.check_sign_ins().await.unwrap_err();
    // Another slot's publication shows the read reached the relay, though it
    // did not finish.
    publish_into_slot(
        &account,
        &"ab".repeat(32),
        "not a key package",
        unix_now_seconds(),
    );
    let report = phone.check_sign_ins().await.unwrap();
    assert!(!report.own_slot_complete);
    assert!(!report.refilling);
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(published_at(&phone), published);
    assert!(!relay_serves_slot(&account.relay, &slot));

    account
        .relay
        .unfinished_directory_reads
        .store(false, SeqCst);
    assert!(phone.check_sign_ins().await.unwrap().refilling);
}

/// A relay whose own read finished shows the slot empty even while another
/// relay is down and no relay returned any of the account's publications:
/// the check cannot count sign-ins then, but it still refills the slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finished_empty_relay_is_refilled_while_another_is_down() {
    use std::sync::atomic::Ordering::SeqCst;

    let account = Account::new(1, true);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    let slot = own_slot(&phone);
    let published = publish_two_days_ago(&phone);
    relay_empties_slot(&account.relay, &slot);
    account
        .relay
        .other_directory_relays_down
        .store(true, SeqCst);

    let result = phone.check_sign_ins().await;
    assert!(
        matches!(
            result,
            Err(AppError::DeviceGroupRefused("key_packages_unreachable"))
        ),
        "{result:?}"
    );
    assert!(phone.runtime.key_package_network_maintenance_due().unwrap());
    phone.run_due_maintenance().await.unwrap();
    assert!(published_at(&phone) > published);
    assert!(relay_serves_slot(&account.relay, &slot));
}

/// Only a publication at least a day old is refilled. A refill is a new
/// publication, so a relay that accepts this device's KeyPackages and keeps
/// none costs one a day, not one per check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_that_keeps_nothing_is_refilled_once_a_day() {
    let account = Account::new(1, true);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    let slot = own_slot(&phone);
    publish_two_days_ago(&phone);
    relay_empties_slot(&account.relay, &slot);
    assert!(phone.check_sign_ins().await.unwrap().refilling);
    phone.run_due_maintenance().await.unwrap();
    let refilled = published_at(&phone);

    relay_empties_slot(&account.relay, &slot);
    assert!(!phone.check_sign_ins().await.unwrap().refilling);
    phone.run_due_maintenance().await.unwrap();
    assert_eq!(published_at(&phone), refilled);
    assert!(!relay_serves_slot(&account.relay, &slot));
}

/// A device with no slot yet, as a Welcome join records it before the
/// device first publishes, still checks its account's sign-ins: it just has
/// no slot of its own to read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_with_no_slot_yet_still_checks_sign_ins() {
    let account = Account::new(2, true);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    let mut laptop = account.open(1).await;
    laptop
        .app
        .account_storage("alice")
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            String::new(),
        ))
        .unwrap();

    let report = laptop.check_sign_ins().await.unwrap();
    assert!(report.complete);
    assert!(report.own_slot_complete);
    assert_eq!(report.foreign, Default::default());
    assert!(report.slots.contains_key(&own_slot(&phone)));
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

/// Hosts reach sign-ins through the runtime: the list, a check on request,
/// answers and their refusals, and an `UnrecognizedSignInsChanged` at open
/// and after each change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_lists_checks_and_answers_sign_ins() {
    let account = Account::new(2, true);
    drop(account.open(0).await);
    let phone_app = &account.apps[0];
    let _eose = scripted_eose_pump(
        phone_app.relay_plane.clone(),
        account.relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(phone_app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    next_sign_ins_changed(&mut events, &account.alice_id).await;
    // This first check takes the phone's baseline: only its own slot.
    assert!(runtime.check_sign_ins("alice").await.unwrap().is_empty());

    let mut tablet = account.open(1).await;
    published_key_package(&mut tablet, &account.relay).await;
    let tablet_slot = own_slot(&tablet);
    drop(tablet);
    let state = |sign_ins: Vec<UnrecognizedSignIn>| {
        sign_ins
            .into_iter()
            .map(|sign_in| {
                (
                    sign_in.slot_id_hex,
                    sign_in.before_this_device,
                    sign_in.state,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        state(runtime.check_sign_ins("alice").await.unwrap()),
        [(tablet_slot.clone(), false, UnrecognizedSignInState::Prompt)]
    );
    next_sign_ins_changed(&mut events, &account.alice_id).await;

    let refused = |result: Result<(), AppError>, code: &str| {
        assert!(
            matches!(result, Err(AppError::DeviceGroupRefused(refused)) if refused == code),
            "{code}"
        );
    };
    refused(
        runtime
            .answer_sign_in("alice", &tablet_slot, SignInResponse::Dismiss)
            .await,
        "sign_in_unanswered",
    );
    refused(
        runtime
            .answer_sign_in("alice", &"ef".repeat(32), SignInResponse::NotNow)
            .await,
        "sign_in_unknown",
    );

    runtime
        .answer_sign_in("alice", &tablet_slot, SignInResponse::NotNow)
        .await
        .unwrap();
    next_sign_ins_changed(&mut events, &account.alice_id).await;
    assert_eq!(
        state(runtime.unrecognized_sign_ins("alice").await.unwrap()),
        [(tablet_slot.clone(), false, UnrecognizedSignInState::NotNow)]
    );
    refused(
        runtime
            .answer_sign_in("alice", &tablet_slot, SignInResponse::NotNow)
            .await,
        "sign_in_answered",
    );

    runtime
        .answer_sign_in("alice", &tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    next_sign_ins_changed(&mut events, &account.alice_id).await;
    assert!(
        runtime
            .unrecognized_sign_ins("alice")
            .await
            .unwrap()
            .is_empty()
    );
    runtime.shutdown().await;
}

/// With device groups off, the runtime lists nothing, checks nothing, and
/// never announces a change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_sees_no_sign_ins_without_device_groups() {
    let account = Account::new(2, false);
    drop(account.open(0).await);
    drop(account.open(1).await);
    let phone_app = &account.apps[0];
    let _eose = scripted_eose_pump(
        phone_app.relay_plane.clone(),
        account.relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(phone_app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    assert!(runtime.check_sign_ins("alice").await.unwrap().is_empty());
    assert!(
        runtime
            .unrecognized_sign_ins("alice")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        runtime
            .answer_sign_in("alice", &"ef".repeat(32), SignInResponse::NotNow)
            .await,
        Err(AppError::DeviceGroupRefused("roster_unsupported"))
    ));
    runtime.shutdown().await;
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, MarmotAppEvent::UnrecognizedSignInsChanged { .. }),
            "{event:?}"
        );
    }
}

/// Waits for the account's next `UnrecognizedSignInsChanged`.
async fn next_sign_ins_changed(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    account_id_hex: &str,
) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match events.recv().await {
                Ok(MarmotAppEvent::UnrecognizedSignInsChanged {
                    account_id_hex: changed,
                    account_label,
                }) if changed == account_id_hex && account_label == "alice" => break,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => panic!("events closed"),
            }
        }
    })
    .await
    .expect("UnrecognizedSignInsChanged");
}
