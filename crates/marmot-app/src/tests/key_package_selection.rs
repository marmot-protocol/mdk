use super::invite_recovery::package_expiring_at;
use super::*;
use crate::key_package_records::select_key_packages_from_records;
use nostr_directory::{
    FollowAvailabilityState, KEY_PACKAGE_FRESHNESS, KeyPackageSelection,
    MAX_KEY_PACKAGES_PER_ACCOUNT,
};
use std::collections::BTreeMap;

fn candidate(
    account: &AccountSummary,
    package: KeyPackage,
    slot: &str,
    client: Option<&str>,
    timestamp: u64,
) -> NostrTransportEvent {
    let event = member_resolution_key_package_event(account, package);
    let mut tags = event.tags;
    tags.iter_mut().find(|tag| tag[0] == "d").unwrap()[1] = slot.into();
    if let Some(client) = client {
        tags.push(vec!["client".into(), client.into()]);
    }
    NostrTransportEvent::new_unsigned_at(event.pubkey, event.kind, tags, event.content, timestamp)
}

/// A package for a new device: its own leaf signature key, valid for the test.
fn device_package(app: &MarmotApp, account: &AccountSummary, last_resort: bool) -> KeyPackage {
    package_expiring_at(app, account, unix_now_seconds() + 3_000, last_resort)
}

fn select(
    app: &MarmotApp,
    account: &AccountSummary,
    events: &[&NostrTransportEvent],
) -> Result<KeyPackageSelection, DirectoryError> {
    let records = events
        .iter()
        .map(|event| RelayEventRecord {
            event: (*event).clone(),
            endpoints: vec![],
        })
        .collect::<Vec<_>>();
    select_key_packages_from_records(
        &account.account_id_hex,
        &records,
        app.directory().directory_freshness_for_test(),
        None,
    )
}

fn selected(
    app: &MarmotApp,
    account: &AccountSummary,
    events: &[&NostrTransportEvent],
) -> Vec<String> {
    select(app, account, events)
        .unwrap()
        .value
        .into_iter()
        .map(|fetched| fetched.key_package_event_id)
        .collect()
}

fn ids(events: &[&NostrTransportEvent]) -> Vec<String> {
    events.iter().map(|event| event.id.clone()).collect()
}

fn selection_availability_states(
    app: &MarmotApp,
    owner: &AccountSummary,
) -> BTreeMap<String, FollowAvailabilityState> {
    app.directory()
        .follow_availability_page(
            &crate::directory_resources::directory_account(owner),
            None,
            100,
        )
        .unwrap()
        .rows
        .into_iter()
        .map(|row| (row.account_id_hex, row.state))
        .collect()
}

fn signed_deletion(
    app: &MarmotApp,
    account: &AccountSummary,
    tags: Vec<Vec<String>>,
    created_at: u64,
) -> NostrTransportEvent {
    let event = EventBuilder::new(Kind::from(5), "")
        .tags(tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
        .custom_created_at(NostrTimestamp::from_secs(created_at))
        .finalize(
            &app.account_home()
                .load_signing_keys(&account.label)
                .unwrap(),
        )
        .unwrap();
    NostrTransportEvent::from_nostr_event(&event).unwrap()
}

/// `event` signed by `account`, as relays serve real publications.
fn signed(
    app: &MarmotApp,
    account: &AccountSummary,
    event: NostrTransportEvent,
) -> NostrTransportEvent {
    let signed = EventBuilder::new(Kind::from(event.kind as u16), event.content)
        .tags(event.tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
        .custom_created_at(NostrTimestamp::from_secs(event.created_at))
        .finalize(
            &app.account_home()
                .load_signing_keys(&account.label)
                .unwrap(),
        )
        .unwrap();
    NostrTransportEvent::from_nostr_event(&signed).unwrap()
}

/// Opens `account` so it publishes its own KeyPackage now, not when a later
/// runtime starts, then records every publication the journal knows for it
/// as deleted. A fixture's relays serve packages built for the test in place
/// of the account's own, and the journal would otherwise still expect those.
pub(super) async fn retire_journaled_key_packages(app: &MarmotApp, account: &AccountSummary) {
    drop(client_on_app_relay_plane(app, &account.label).await);
    let storage = app.shared_storage().unwrap();
    for publication in storage
        .public_key_package_replacements(&account.account_id_hex)
        .unwrap()
    {
        storage
            .put_public_key_package_barrier(&storage_sqlite::PublicKeyPackageBarrierRecord {
                account_id_hex: publication.account_id_hex,
                key_package_id: publication.key_package_id,
                event_id_hex: publication.event_id_hex.clone(),
                deleted_event_id: Some(publication.event_id_hex),
                event_created_at: publication.event_created_at,
                observed_at: unix_now_seconds(),
                kind: storage_sqlite::PublicKeyPackageBarrierKind::Deletion,
            })
            .unwrap();
    }
}

fn slot_address(account: &AccountSummary, slot: &str) -> Vec<String> {
    vec![
        "a".into(),
        format!(
            "{KIND_MARMOT_KEY_PACKAGE}:{}:{slot}",
            account.account_id_hex
        ),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_fresh_device_slot_is_selected_newest_first() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    // The client tag no longer ranks anything.
    let phone = candidate(
        account,
        device_package(&app, account, true),
        "phone",
        Some("amethyst"),
        now,
    );
    let laptop = candidate(
        account,
        device_package(&app, account, true),
        "laptop",
        Some("whitenoise"),
        now - 10,
    );
    let tablet = candidate(
        account,
        device_package(&app, account, true),
        "tablet",
        None,
        now - 20,
    );
    let expected = ids(&[&phone, &laptop, &tablet]);
    assert_eq!(
        selected(&app, account, &[&tablet, &phone, &laptop]),
        expected
    );
    // Malformed and future-dated slots are skipped, not fatal.
    let mut malformed = candidate(
        account,
        device_package(&app, account, true),
        "malformed",
        None,
        now,
    );
    malformed.content = "not base64".into();
    let mut future = candidate(
        account,
        device_package(&app, account, true),
        "future",
        None,
        now,
    );
    future.created_at = u64::MAX;
    assert_eq!(
        selected(
            &app,
            account,
            &[&malformed, &future, &tablet, &phone, &laptop]
        ),
        expected
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selection_keeps_the_highest_ranked_slots_up_to_the_cap() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let events = (0..MAX_KEY_PACKAGES_PER_ACCOUNT as u64 + 5)
        .map(|age| {
            candidate(
                account,
                device_package(&app, account, true),
                &format!("device-{age}"),
                None,
                now - age,
            )
        })
        .collect::<Vec<_>>();
    let all = events.iter().rev().collect::<Vec<_>>();
    assert_eq!(
        selected(&app, account, &all),
        ids(&events
            .iter()
            .take(MAX_KEY_PACKAGES_PER_ACCOUNT)
            .collect::<Vec<_>>())
    );
}

/// A device's read of its own account's slots (new sign-ins, mdk#2628 3.2)
/// keeps every fresh, valid slot: none past the inviter's cap, none dropped
/// for sharing a signature key with another slot, and none for a `d` the
/// device roster could not name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_account_slot_read_keeps_every_valid_slot() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let mut events = (0..MAX_KEY_PACKAGES_PER_ACCOUNT as u64 + 2)
        .map(|age| {
            candidate(
                account,
                device_package(&app, account, true),
                &format!("device-{age}"),
                None,
                now - age,
            )
        })
        .collect::<Vec<_>>();
    let package = device_package(&app, account, true);
    events.push(candidate(account, package.clone(), "first", None, now));
    events.push(candidate(account, package, "copy", None, now - 10));
    let stale = candidate(
        account,
        device_package(&app, account, true),
        "stale",
        None,
        now - KEY_PACKAGE_FRESHNESS.as_secs() - 60,
    );
    let records = events
        .iter()
        .chain([&stale])
        .map(|event| RelayEventRecord {
            event: event.clone(),
            endpoints: vec![],
        })
        .collect::<Vec<_>>();
    let slots = nostr_directory::account_key_package_slots_from_records(
        &account.account_id_hex,
        &records,
        true,
        &[],
        app.directory().directory_freshness_for_test(),
        None,
    );
    assert!(slots.complete && slots.reached);
    // Every slot the read returned, the stale one included, though only fresh
    // ones count.
    assert!(slots.returned_slots.contains("stale"));
    assert_eq!(slots.returned_slots.len(), events.len() + 1);
    // Every slot holding a valid publication, fresh or not: the slots still
    // signed in.
    assert!(slots.current_slots.contains("stale"));
    assert_eq!(slots.current_slots.len(), slots.key_packages.len() + 1);
    let mut read = slots
        .key_packages
        .into_iter()
        .map(|slot| slot.fetched.key_package_event_id)
        .collect::<Vec<_>>();
    read.sort();
    let mut every = ids(&events.iter().collect::<Vec<_>>());
    every.sort();
    assert_eq!(read, every);
}

/// The own-slot check (mdk#2628 3.4) reads what each relay serves as its
/// slot's current publication: the newest there, the lowest id on a tie,
/// whatever it holds and whenever it is dated, each publication once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_own_slot_read_takes_each_relays_current_publication() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let own = "own-slot";
    let published = |slot: &str, at: u64| {
        candidate(account, device_package(&app, account, true), slot, None, at)
    };
    let older = published(own, now - 10);
    let newer = published(own, now);
    let other_slot = published("other", now + 50);
    // Not a KeyPackage, and dated far ahead: it still occupies the slot.
    let future = NostrTransportEvent::new_unsigned_at(
        account.account_id_hex.clone(),
        older.kind,
        vec![vec!["d".into(), own.into()]],
        "not a key package".into(),
        now + 100_000,
    );
    let mut tied = [published(own, now - 5), published(own, now - 5)];
    tied.sort_by(|a, b| a.id.cmp(&b.id));
    let mut someone_else = published(own, now + 60);
    someone_else.pubkey = "ff".repeat(32);
    let served = |event: &NostrTransportEvent, relay: &str| RelayEventRecord {
        event: event.clone(),
        endpoints: vec![TransportEndpoint(relay.into())],
    };
    let records = [
        served(&older, "wss://a"),
        served(&newer, "wss://a"),
        served(&other_slot, "wss://a"),
        served(&older, "wss://b"),
        served(&future, "wss://c"),
        served(&older, "wss://c"),
        served(&tied[1], "wss://d"),
        served(&tied[0], "wss://d"),
        served(&newer, "wss://e"),
        served(&someone_else, "wss://e"),
    ];
    let read = |complete| {
        nostr_directory::account_key_package_slots_from_records(
            &account.account_id_hex,
            &records,
            complete,
            &[],
            app.directory().directory_freshness_for_test(),
            Some(own),
        )
        .own_slot
        .unwrap()
    };
    let own_slot = read(true);
    assert!(own_slot.complete);
    let mut current = own_slot
        .current
        .iter()
        .map(|publication| (publication.event_id.clone(), publication.created_at))
        .collect::<Vec<_>>();
    current.sort();
    let mut expected = [&newer, &older, &future, &tied[0]]
        .into_iter()
        .map(|event| (event.id.clone(), event.created_at))
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(current, expected);
    assert!(!read(false).complete);
}

/// A relay serves nothing in the own slot only when its own read finished
/// and returned nothing there (mdk#2628 3.4): another slot's publication, or
/// another account's under the same `d`, leaves the slot empty, and a relay
/// whose read did not finish proves nothing, whatever the others did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_finished_read_finds_the_own_slot_empty() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let own = "own-slot";
    let published = |slot: &str| {
        candidate(
            account,
            device_package(&app, account, true),
            slot,
            None,
            now,
        )
    };
    let in_slot = published(own);
    let other_slot = published("other");
    let mut someone_else = published(own);
    someone_else.pubkey = "ff".repeat(32);
    let relay = |name: &str| TransportEndpoint(name.into());
    let served = |event: &NostrTransportEvent, name: &str| RelayEventRecord {
        event: event.clone(),
        endpoints: vec![relay(name)],
    };
    let records = [
        served(&in_slot, "wss://serving"),
        served(&other_slot, "wss://other-slot"),
        served(&someone_else, "wss://other-account"),
        served(&other_slot, "wss://unfinished"),
    ];
    let finished = [
        relay("wss://serving"),
        relay("wss://other-slot"),
        relay("wss://other-account"),
        relay("wss://nothing"),
        relay("wss://nothing"),
    ];
    let own_slot = nostr_directory::account_key_package_slots_from_records(
        &account.account_id_hex,
        &records,
        false,
        &finished,
        app.directory().directory_freshness_for_test(),
        Some(own),
    )
    .own_slot
    .unwrap();
    assert!(!own_slot.complete);
    assert_eq!(
        own_slot.empty,
        [
            relay("wss://other-slot"),
            relay("wss://other-account"),
            relay("wss://nothing"),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_slots_are_a_single_fallback_only_when_none_is_fresh() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let stale_at = unix_now_seconds() - KEY_PACKAGE_FRESHNESS.as_secs() - 60;
    let stale = (0..3)
        .map(|age| {
            candidate(
                account,
                device_package(&app, account, true),
                &format!("stale-{age}"),
                None,
                stale_at - age,
            )
        })
        .collect::<Vec<_>>();
    let all = stale.iter().collect::<Vec<_>>();
    assert_eq!(selected(&app, account, &all), ids(&[&stale[0]]));
    let fresh = candidate(
        account,
        device_package(&app, account, true),
        "fresh",
        None,
        unix_now_seconds() - 60,
    );
    let mut with_fresh = all.clone();
    with_fresh.push(&fresh);
    assert_eq!(selected(&app, account, &with_fresh), ids(&[&fresh]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deletion_by_slot_address_or_event_id_skips_a_slot() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let phone = candidate(
        account,
        device_package(&app, account, true),
        "phone",
        None,
        now,
    );
    let older_laptop = candidate(
        account,
        device_package(&app, account, true),
        "laptop",
        None,
        now - 40,
    );
    let laptop = candidate(
        account,
        device_package(&app, account, true),
        "laptop",
        None,
        now - 10,
    );
    let tablet = candidate(
        account,
        device_package(&app, account, true),
        "tablet",
        None,
        now - 20,
    );
    let slots = [&phone, &older_laptop, &laptop, &tablet];
    let with = |deletion: &NostrTransportEvent| {
        let mut events = slots.to_vec();
        events.push(deletion);
        selected(&app, account, &events)
    };
    let by_id = signed_deletion(&app, account, vec![vec!["e".into(), phone.id.clone()]], now);
    assert_eq!(with(&by_id), ids(&[&laptop, &tablet]));
    // A deleted current publication still supersedes its slot's older one.
    let by_id = signed_deletion(
        &app,
        account,
        vec![vec!["e".into(), laptop.id.clone()]],
        now,
    );
    assert_eq!(with(&by_id), ids(&[&phone, &tablet]));
    let by_address = signed_deletion(
        &app,
        account,
        vec![slot_address(account, "laptop")],
        now - 10,
    );
    assert_eq!(with(&by_address), ids(&[&phone, &tablet]));
    // An address deletion covers only publications no newer than itself.
    let earlier = signed_deletion(
        &app,
        account,
        vec![slot_address(account, "laptop")],
        now - 30,
    );
    assert_eq!(with(&earlier), ids(&[&phone, &laptop, &tablet]));
}

/// One relay page short of full selects; a full page of `kind` fails the
/// lookup. Account 0 alone, then beside another account, whose batch defers
/// the decision to the single-author read and recovery.
async fn assert_a_full_page_fails_the_lookup(kind: u64) {
    const PAGE: usize = transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT;
    for count in [1, 2] {
        let (_dir, app, accounts, fetcher) = member_resolution_fixture(count, false).await;
        let account = &accounts[0];
        let now = unix_now_seconds();
        let package = device_package(&app, account, true);
        let page_event = |index: usize| {
            if kind == 5 {
                signed_deletion(
                    &app,
                    account,
                    vec![
                        slot_address(account, &format!("retired-{index}")),
                        vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
                    ],
                    now - 100,
                )
            } else {
                // A page counts whatever the relay returned, valid or not.
                let event = candidate(
                    account,
                    package.clone(),
                    &format!("slot-{index}"),
                    None,
                    now - 100 - index as u64,
                );
                NostrTransportEvent::new_unsigned_at(
                    event.pubkey,
                    event.kind,
                    event.tags,
                    "unparseable".into(),
                    event.created_at,
                )
            }
        };
        let existing = fetcher
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.kind == kind && event.pubkey == account.account_id_hex)
            .count();
        fetcher
            .events
            .lock()
            .unwrap()
            .extend((existing..PAGE - 1).map(&page_event));
        let refs = accounts
            .iter()
            .map(|account| account.account_id_hex.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            app.directory()
                .resolve_member_key_packages(&refs)
                .await
                .unwrap()
                .len(),
            count
        );
        fetcher.events.lock().unwrap().push(page_event(PAGE));
        let error = app
            .directory()
            .resolve_member_key_packages(&refs)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, DirectoryError::DirectoryLookupIncomplete(id) if *id == account.account_id_hex),
            "events past a full page may change the selection: {error:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_page_of_key_packages_fails_the_lookup() {
    assert_a_full_page_fails_the_lookup(KIND_MARMOT_KEY_PACKAGE).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_page_of_deletion_requests_fails_the_lookup() {
    assert_a_full_page_fails_the_lookup(5).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_older_device_behind_many_newer_slots_still_ranks_first() {
    // Beside another account, with the shared read refused, so account 0 is
    // decided by its single-author read, which carries the relay limit.
    let (_dir, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
    fetcher
        .reject_multi_author
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let account = &accounts[0];
    let now = unix_now_seconds();
    fetcher.events.lock().unwrap().retain(|event| {
        event.kind != KIND_MARMOT_KEY_PACKAGE || event.pubkey != account.account_id_hex
    });
    let oldest = candidate(
        account,
        device_package(&app, account, false),
        "oldest",
        None,
        now - 1_000,
    );
    let last_resort = device_package(&app, account, true);
    let newer = (0..3 * MAX_KEY_PACKAGES_PER_ACCOUNT as u64)
        .map(|index| {
            candidate(
                account,
                last_resort.clone(),
                &format!("newer-{index}"),
                None,
                now - index,
            )
        })
        .collect::<Vec<_>>();
    let expected = vec![oldest.id.clone(), newer[0].id.clone()];
    fetcher
        .events
        .lock()
        .unwrap()
        .extend(newer.into_iter().chain([oldest]));
    let selected = app
        .directory()
        .resolve_member_key_packages(&[
            accounts[0].account_id_hex.as_str(),
            accounts[1].account_id_hex.as_str(),
        ])
        .await
        .unwrap()
        .into_iter()
        .filter_map(|package| {
            let source = package.source.as_ref().unwrap();
            (cgka_engine::key_package::key_package_metadata(&package)
                .unwrap()
                .credential_identity_hex
                == account.account_id_hex)
                .then(|| hex::encode(source.event_id.as_slice()))
        })
        .collect::<Vec<_>>();
    assert_eq!(selected, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_resort_packages_rank_after_the_rest() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let last_resort = candidate(
        account,
        device_package(&app, account, true),
        "last-resort",
        None,
        now,
    );
    let single_use = candidate(
        account,
        device_package(&app, account, false),
        "single-use",
        None,
        now - 10,
    );
    assert_eq!(
        selected(&app, account, &[&last_resort, &single_use]),
        ids(&[&single_use, &last_resort])
    );
    // With none fresh, the single fallback is the one that is not last-resort.
    let stale_at = now - KEY_PACKAGE_FRESHNESS.as_secs() - 60;
    let mut stale_last_resort = last_resort.clone();
    stale_last_resort.created_at = stale_at;
    let mut stale_single_use = single_use.clone();
    stale_single_use.created_at = stale_at - 10;
    assert_eq!(
        selected(&app, account, &[&stale_last_resort, &stale_single_use]),
        vec![stale_single_use.id.clone()]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_device_in_several_slots_is_selected_once() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let package = device_package(&app, account, true);
    let newest = candidate(account, package.clone(), "first", None, now);
    let older = candidate(account, package, "second", None, now - 10);
    let other = candidate(
        account,
        device_package(&app, account, true),
        "other",
        None,
        now - 20,
    );
    // A Commit cannot add two leaves with one signature key.
    assert_eq!(
        selected(&app, account, &[&older, &other, &newest]),
        ids(&[&newest, &other])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn equal_timestamps_rank_by_key_package_ref_and_replace_by_lower_event_id() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let first = candidate(
        account,
        device_package(&app, account, true),
        "first",
        None,
        now,
    );
    let second = candidate(
        account,
        device_package(&app, account, true),
        "second",
        None,
        now,
    );
    let reference = |event: &NostrTransportEvent| event.tag_value("i").unwrap().to_owned();
    let mut expected = [&first, &second];
    expected.sort_by_key(|event| reference(event));
    assert_eq!(selected(&app, account, &[&second, &first]), ids(&expected));
    // Within one slot, the lower event id is the current publication.
    let mut replacement = second.clone();
    replacement
        .tags
        .iter_mut()
        .find(|tag| tag[0] == "d")
        .unwrap()[1] = "first".into();
    let replacement = NostrTransportEvent::new_unsigned_at(
        replacement.pubkey,
        replacement.kind,
        replacement.tags,
        replacement.content,
        now,
    );
    let lower = if replacement.id < first.id {
        &replacement
    } else {
        &first
    };
    assert_eq!(
        selected(&app, account, &[&first, &replacement]),
        ids(&[lower])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_replacement_suppresses_older_package_in_the_same_slot() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let package = fresh_key_package_for_account(&app, account, false).await;
    let now = unix_now_seconds();
    let old = candidate(
        account,
        package.clone(),
        "white",
        Some("whitenoise"),
        now - 10,
    );
    let fallback = candidate(
        account,
        package.clone(),
        "amethyst",
        Some("amethyst"),
        now - 20,
    );
    let replacement = candidate(account, package, "white", Some("whitenoise"), now);
    let mut bad_content = replacement.clone();
    bad_content.content = "not base64".into();
    let mut bad_metadata = replacement;
    bad_metadata
        .tags
        .iter_mut()
        .find(|tag| tag[0] == "i")
        .unwrap()[1] = "incorrect-reference".into();
    for malformed in [bad_content, bad_metadata] {
        // An independent slot remains usable, but the superseded package must
        // never be resurrected when its replacement is invalid.
        assert_eq!(
            selected(&app, account, &[&old, &malformed, &fallback]),
            vec![fallback.id.clone()],
        );
        assert!(select(&app, account, &[&old, &malformed]).is_err());
        // Freshness is checked before replacement: future events cannot hide
        // the current publication.
        let mut future = malformed;
        future.created_at = u64::MAX;
        assert_eq!(
            selected(&app, account, &[&old, &future]),
            vec![old.id.clone()]
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_device_is_resolved_from_a_single_author_read() {
    for (reject_batch, truncate_batch) in [(false, false), (true, false), (false, true)] {
        let (_dir, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
        fetcher
            .reject_multi_author
            .store(reject_batch, std::sync::atomic::Ordering::SeqCst);
        let mut expected = Vec::new();
        fetcher
            .events
            .lock()
            .unwrap()
            .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        for account in &accounts {
            let now = unix_now_seconds();
            let older = candidate(
                account,
                device_package(&app, account, true),
                "older",
                Some("whitenoise"),
                now - 10,
            );
            let newer = candidate(
                account,
                device_package(&app, account, true),
                "newer",
                Some("amethyst"),
                now,
            );
            // Deleted by a request that arrives only with the KeyPackage read.
            let deleted = candidate(
                account,
                device_package(&app, account, true),
                "deleted",
                None,
                now,
            );
            let deletion = signed_deletion(
                &app,
                account,
                vec![
                    slot_address(account, "deleted"),
                    vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
                ],
                now,
            );
            expected.extend([newer.id.clone(), older.id.clone()]);
            if truncate_batch {
                fetcher
                    .events_only_in_single_author
                    .lock()
                    .unwrap()
                    .insert(older.id.clone());
            }
            fetcher
                .events
                .lock()
                .unwrap()
                .extend([newer, older, deleted, deletion]);
        }
        let refs = accounts
            .iter()
            .map(|a| a.account_id_hex.as_str())
            .collect::<Vec<_>>();
        let actual = app
            .directory()
            .resolve_member_key_packages(&refs)
            .await
            .unwrap();
        let requests = fetcher.requests.lock().unwrap();
        let single_author_lookups = requests
            .iter()
            .filter(|request| {
                request
                    .queries
                    .iter()
                    .any(|query| query.kind == KIND_MARMOT_KEY_PACKAGE && query.authors.len() == 1)
            })
            .collect::<Vec<_>>();
        // A multi-author batch never proves an account's whole slot set, so
        // a Commit reads every account alone.
        assert_eq!(single_author_lookups.len(), 2);
        for request in single_author_lookups {
            assert!(request.queries.iter().any(|query| {
                query.kind == 5
                    && query.reference == Some(('k', KIND_MARMOT_KEY_PACKAGE.to_string()))
            }));
        }
        drop(requests);
        assert_eq!(
            actual
                .iter()
                .map(|kp| hex::encode(kp.source.as_ref().unwrap().event_id.as_slice()))
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_single_author_refetch_preserves_only_usable_current_batch_packages() {
    for batch_case in ["valid", "absent", "malformed", "incompatible"] {
        let (_dir, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
        app.account_home().create_account("inviter").unwrap();
        let mut inviter = client_on_app_relay_plane(&app, "inviter").await;
        let group = inviter
            .create_group("refetch failures", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        let requirements = inviter
            .runtime
            .session()
            .invite_key_package_requirements(&group)
            .unwrap();
        let refs = accounts
            .iter()
            .map(|account| account.account_id_hex.as_str())
            .collect::<Vec<_>>();
        // Ready prewarm reuses the batched existence answer; it must not
        // trigger per-author queries.
        app.directory()
            .prewarm_group_member_key_packages(&refs)
            .await
            .unwrap();
        assert!(!fetcher.requests.lock().unwrap().iter().any(|request| {
            request
                .queries
                .iter()
                .any(|query| query.kind == KIND_MARMOT_KEY_PACKAGE && query.authors.len() == 1)
        }));
        let account = &accounts[0];
        let expected = fetcher
            .events
            .lock()
            .unwrap()
            .iter()
            .find(|event| {
                event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == account.account_id_hex
            })
            .unwrap()
            .id
            .clone();
        if batch_case == "incompatible" {
            let package = fresh_key_package_with_components(
                &app,
                account,
                false,
                app.supported_app_component_ids()
                    .into_iter()
                    .filter(|id| *id != GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID)
                    .collect(),
            )
            .await;
            let replacement = candidate(account, package, "limited", None, unix_now_seconds());
            let mut events = fetcher.events.lock().unwrap();
            events.retain(|event| {
                event.kind != KIND_MARMOT_KEY_PACKAGE || event.pubkey != account.account_id_hex
            });
            events.push(replacement);
        } else if batch_case != "valid" {
            let mut events = fetcher.events.lock().unwrap();
            if batch_case == "absent" {
                events.retain(|event| {
                    event.kind != KIND_MARMOT_KEY_PACKAGE || event.pubkey != account.account_id_hex
                });
            } else {
                events
                    .iter_mut()
                    .find(|event| {
                        event.kind == KIND_MARMOT_KEY_PACKAGE
                            && event.pubkey == account.account_id_hex
                    })
                    .unwrap()
                    .content = "not base64".into();
            }
        }
        *fetcher.failing_single_author.lock().unwrap() = Some(account.account_id_hex.clone());
        fetcher.requests.lock().unwrap().clear();
        let result = app
            .directory()
            .resolve_compatible_member_key_packages(
                refs.iter().map(|member| (*member).to_owned()).collect(),
                &requirements,
                nostr_directory::MemberResolutionPurpose::Commit,
                nostr_directory::MemberResolutionPolicy::Atomic,
            )
            .await;
        assert!(fetcher.requests.lock().unwrap().iter().any(|request| {
            request.queries.iter().any(|query| {
                query.kind == KIND_MARMOT_KEY_PACKAGE
                    && query.authors == vec![account.account_id_hex.clone()]
            })
        }));
        if batch_case == "valid" {
            let resolved = result.unwrap();
            assert_eq!(resolved.key_packages.len(), 2);
            assert_eq!(
                hex::encode(
                    resolved.key_packages[0]
                        .source
                        .as_ref()
                        .unwrap()
                        .event_id
                        .as_slice()
                ),
                expected
            );
        } else {
            let error = result
                .err()
                .expect("unusable batch material must not become a fallback");
            match batch_case {
                "absent" | "incompatible" => assert!(matches!(
                    error,
                    DirectoryError::DirectoryLookupIncomplete(_)
                )),
                "malformed" => assert!(matches!(error, DirectoryError::InvalidKeyPackageEvent(_))),
                _ => unreachable!(),
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_author_refetch_preserves_slot_replacements_seen_in_batch() {
    let (_dir, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    let mut expected = Vec::new();
    for account in &accounts {
        let package = fresh_key_package_for_account(&app, account, false).await;
        let now = unix_now_seconds();
        let old = candidate(
            account,
            package.clone(),
            "white",
            Some("whitenoise"),
            now - 20,
        );
        let mut replacement = candidate(account, package.clone(), "white", Some("whitenoise"), now);
        replacement.content = "not base64".into();
        let fallback = candidate(account, package, "amethyst", Some("amethyst"), now - 10);
        fetcher
            .events_only_in_single_author
            .lock()
            .unwrap()
            .insert(old.id.clone());
        fetcher
            .events_only_in_multi_author
            .lock()
            .unwrap()
            .insert(replacement.id.clone());
        expected.push(fallback.id.clone());
        fetcher
            .events
            .lock()
            .unwrap()
            .extend([old, replacement, fallback]);
    }
    let refs = accounts
        .iter()
        .map(|a| a.account_id_hex.as_str())
        .collect::<Vec<_>>();
    let actual = app
        .directory()
        .resolve_member_key_packages(&refs)
        .await
        .unwrap();
    assert_eq!(
        actual
            .iter()
            .map(|kp| hex::encode(kp.source.as_ref().unwrap().event_id.as_slice()))
            .collect::<Vec<_>>(),
        expected
    );
}

const UPDATED_DIRECT_OUTBOX: &str = "wss://new-outbox.example";

async fn direct_start_outbox_fixture() -> (
    tempfile::TempDir,
    MarmotApp,
    AccountSummary,
    Arc<MemberResolutionDirectoryFetcher>,
) {
    let (dir, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let bob = accounts.into_iter().next().unwrap();
    app.account_home().create_account("alice").unwrap();
    let limited = fresh_key_package_with_components(
        &app,
        &bob,
        false,
        app.supported_app_component_ids()
            .into_iter()
            .filter(|id| *id != cgka_traits::app_components::GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .collect(),
    )
    .await;
    let mut known_records = fetcher.events.lock().unwrap().clone();
    known_records.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    known_records.push(candidate(
        &bob,
        limited,
        "limited",
        None,
        unix_now_seconds(),
    ));
    let mut new_outbox_records = known_records
        .iter()
        .filter(|event| event.kind == KIND_MARMOT_INBOX_RELAY_LIST)
        .cloned()
        .collect::<Vec<_>>();
    new_outbox_records.push(candidate(
        &bob,
        fresh_key_package_for_account(&app, &bob, false).await,
        "compatible",
        None,
        unix_now_seconds(),
    ));
    fetcher.events_by_endpoint.lock().unwrap().extend([
        ("wss://directory.example".into(), known_records.clone()),
        ("wss://shared.example".into(), known_records),
        (UPDATED_DIRECT_OUTBOX.into(), new_outbox_records),
    ]);
    retire_journaled_key_packages(&app, &bob).await;
    (dir, app, bob, fetcher)
}

fn advertise_updated_direct_outbox(
    fetcher: &MemberResolutionDirectoryFetcher,
    bob: &AccountSummary,
    write_relays: &[&str],
) {
    let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
    let records = by_endpoint.get_mut("wss://directory.example").unwrap();
    let outbox = records
        .iter_mut()
        .find(|event| event.kind == KIND_NIP65_RELAY_LIST)
        .unwrap();
    *outbox = NostrTransportEvent::new_unsigned_at(
        bob.account_id_hex.clone(),
        KIND_NIP65_RELAY_LIST,
        write_relays
            .iter()
            .map(|relay| vec!["r".into(), (*relay).into(), "write".into()])
            .collect(),
        String::new(),
        outbox.created_at + 1,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_start_retries_after_incomplete_outbox_discovery() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let options = crate::DirectConversationOptions {
        disappearing_message_secs: 300,
    };
    *fetcher.incomplete_query_kind.lock().unwrap() = Some(KIND_NIP65_RELAY_LIST);
    *fetcher.incomplete_endpoint.lock().unwrap() = Some("wss://directory.example".into());
    let error = runtime
        .start_direct_conversation_with_options("alice", &bob.account_id_hex, options)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, AppError::DirectoryLookupIncomplete(account) if account == &bob.account_id_hex),
        "{error}"
    );
    assert!(app.groups("alice").unwrap().is_empty());

    advertise_updated_direct_outbox(&fetcher, &bob, &[UPDATED_DIRECT_OUTBOX]);
    *fetcher.incomplete_endpoint.lock().unwrap() = None;
    let created = runtime
        .start_direct_conversation_with_options("alice", &bob.account_id_hex, options)
        .await
        .unwrap();
    let groups = app.groups("alice").unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].group_id_hex, hex::encode(created.as_slice()));
    runtime.shutdown().await;
    {
        let client = app.client("alice").await.unwrap();
        assert_eq!(client.runtime.live_group_ids().unwrap(), vec![created]);
    }
    app.close_storage().unwrap();
}

/// An incompatibility needs complete discovery, complete KeyPackage reads and
/// a completed read for a deletion of the refused slot. A recipient that
/// deleted its only slot has no KeyPackage, whichever relay still serves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_start_requires_complete_discovery_for_incompatibility() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let options = crate::DirectConversationOptions {
        disappearing_message_secs: 300,
    };
    *fetcher.incomplete_query_kind.lock().unwrap() = Some(KIND_MARMOT_KEY_PACKAGE);
    *fetcher.incomplete_endpoint.lock().unwrap() = Some("wss://directory.example".into());
    let error = runtime
        .start_direct_conversation_with_options("alice", &bob.account_id_hex, options)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, AppError::DirectoryLookupIncomplete(account) if account == &bob.account_id_hex),
        "{error}"
    );
    assert!(app.groups("alice").unwrap().is_empty());

    *fetcher.incomplete_endpoint.lock().unwrap() = None;
    let error = runtime
        .start_direct_conversation_with_options("alice", &bob.account_id_hex, options)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::IncompatibleKeyPackage(_)),
        "{error}"
    );
    assert!(matches!(
        error.as_engine_error(),
        Some(cgka_traits::EngineError::MissingRequiredCapabilities { .. })
    ));
    assert!(app.groups("alice").unwrap().is_empty());
    // That verdict followed a read for a deletion of the refused slot.
    let slot = slot_address(&bob, "limited").remove(1);
    assert!(fetcher.requests.lock().unwrap().iter().any(|request| {
        request
            .queries
            .iter()
            .any(|query| query.kind == 5 && query.reference == Some(('a', slot.clone())))
    }));

    // While that read does not finish, the slot may be deleted.
    *fetcher.incomplete_query_kind.lock().unwrap() = Some(5);
    *fetcher.incomplete_endpoint.lock().unwrap() = Some("wss://directory.example".into());
    let error = runtime
        .start_direct_conversation_with_options("alice", &bob.account_id_hex, options)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, AppError::DirectoryLookupIncomplete(account) if account == &bob.account_id_hex),
        "{error}"
    );
    assert!(app.groups("alice").unwrap().is_empty());

    // The recipient deleted its only slot. The outbox still serves the
    // package. The directory relay dropped it and holds the deletion
    // request, which names no kind, so no KeyPackage read returns it.
    *fetcher.incomplete_endpoint.lock().unwrap() = None;
    {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        let records = by_endpoint.get_mut("wss://directory.example").unwrap();
        let published_at = records
            .iter()
            .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .unwrap()
            .created_at;
        records.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        records.push(signed_deletion(
            &app,
            &bob,
            vec![slot_address(&bob, "limited")],
            published_at,
        ));
    }
    let error = runtime
        .start_direct_conversation_with_options("alice", &bob.account_id_hex, options)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::MissingKeyPackage { .. }),
        "{error}"
    );
    assert!(app.groups("alice").unwrap().is_empty());

    runtime.shutdown().await;
    {
        let client = app.client("alice").await.unwrap();
        assert!(client.runtime.live_group_ids().unwrap().is_empty());
    }
    app.close_storage().unwrap();
}

/// A recipient publishes two incompatible slots and deleted the newer one,
/// with a request no KeyPackage read returns. The newer slot drops out and
/// the older one is refused instead, once its own deletion read finds
/// nothing. With both deleted the recipient has no KeyPackage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_incompatible_slot_leaves_the_next_one_to_decide() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let directory = app.directory();
    let resolve = || {
        directory.resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
    };
    let older = fresh_key_package_with_components(
        &app,
        &bob,
        false,
        app.supported_app_component_ids()
            .into_iter()
            .filter(|id| *id != cgka_traits::app_components::GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .collect(),
    )
    .await;
    let now = unix_now_seconds();
    let older = candidate(&bob, older, "older", None, now - 60);
    let delete = |slot: &str| {
        let deletion = signed_deletion(&app, &bob, vec![slot_address(&bob, slot)], now);
        fetcher
            .events_by_endpoint
            .lock()
            .unwrap()
            .get_mut("wss://directory.example")
            .unwrap()
            .push(deletion);
    };
    let proof_reads = |slot: &str| {
        let slot = slot_address(&bob, slot).remove(1);
        fetcher
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| {
                request
                    .queries
                    .iter()
                    .any(|query| query.kind == 5 && query.reference == Some(('a', slot.clone())))
            })
            .count()
    };
    for relay in ["wss://shared.example", "wss://directory.example"] {
        fetcher
            .events_by_endpoint
            .lock()
            .unwrap()
            .get_mut(relay)
            .unwrap()
            .push(older.clone());
    }
    delete("limited");
    let refused = resolve().await;
    assert!(
        matches!(
            refused,
            Err(DirectoryError::KeyPackageRequirements(
                cgka_traits::EngineError::MissingRequiredCapabilities { .. }
            ))
        ),
        "{:?}",
        refused.err()
    );
    assert_eq!((proof_reads("limited"), proof_reads("older")), (1, 1));

    delete("older");
    let deleted = resolve().await;
    assert!(
        matches!(deleted, Err(DirectoryError::MissingKeyPackage { .. })),
        "{:?}",
        deleted.err()
    );
    app.close_storage().unwrap();
}

/// A prewarm does not pin a recipient's routes: a start after the recipient
/// moved outboxes discovers the new one on its first attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_start_after_prewarm_finds_a_moved_outbox() {
    let old_outbox = "wss://shared.example";
    for old_outbox_incomplete in [false, true] {
        let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
        app.directory()
            .prewarm_group_member_key_packages(&[bob.account_id_hex.as_str()])
            .await
            .unwrap();
        if old_outbox_incomplete {
            // The recipient keeps the old outbox alongside the new one.
            advertise_updated_direct_outbox(&fetcher, &bob, &[old_outbox, UPDATED_DIRECT_OUTBOX]);
            *fetcher.incomplete_query_kind.lock().unwrap() = Some(KIND_MARMOT_KEY_PACKAGE);
            *fetcher.incomplete_endpoint.lock().unwrap() = Some(old_outbox.into());
        } else {
            advertise_updated_direct_outbox(&fetcher, &bob, &[UPDATED_DIRECT_OUTBOX]);
        }
        fetcher.requests.lock().unwrap().clear();
        let runtime = MarmotAppRuntime::new(app.clone());
        let created = runtime
            .start_direct_conversation_with_options(
                "alice",
                &bob.account_id_hex,
                crate::DirectConversationOptions {
                    disappearing_message_secs: 300,
                },
            )
            .await
            .unwrap_or_else(|error| {
                panic!("old outbox incomplete={old_outbox_incomplete}: {error}")
            });
        let groups = app.groups("alice").unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].group_id_hex, hex::encode(created.as_slice()));
        if old_outbox_incomplete {
            assert!(fetcher.requests.lock().unwrap().iter().any(|request| {
                request
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.0 == old_outbox)
                    && request.queries.iter().any(|query| {
                        query.kind == KIND_MARMOT_KEY_PACKAGE
                            && query.authors.contains(&bob.account_id_hex)
                    })
            }));
        }
        runtime.shutdown().await;
        app.close_storage().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_start_after_prewarm_reports_incompatibility_on_first_attempt() {
    let (_dir, app, bob, _fetcher) = direct_start_outbox_fixture().await;
    app.directory()
        .prewarm_group_member_key_packages(&[bob.account_id_hex.as_str()])
        .await
        .unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());
    let error = runtime
        .start_direct_conversation_with_options(
            "alice",
            &bob.account_id_hex,
            crate::DirectConversationOptions {
                disappearing_message_secs: 300,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::IncompatibleKeyPackage(_)),
        "{error}"
    );
    assert!(matches!(
        error.as_engine_error(),
        Some(cgka_traits::EngineError::MissingRequiredCapabilities { .. })
    ));
    assert!(app.groups("alice").unwrap().is_empty());
    runtime.shutdown().await;
    {
        let client = app.client("alice").await.unwrap();
        assert!(client.runtime.live_group_ids().unwrap().is_empty());
    }
    app.close_storage().unwrap();
}

/// A start after a prewarm still reads the recipient's relay lists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_start_after_prewarm_reads_relay_lists() {
    let (_dir, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    app.account_home().create_account("alice").unwrap();
    let bob = &accounts[0];
    app.directory()
        .prewarm_group_member_key_packages(&[bob.account_id_hex.as_str()])
        .await
        .unwrap();
    fetcher.requests.lock().unwrap().clear();
    let runtime = MarmotAppRuntime::new(app.clone());
    let created = runtime
        .start_direct_conversation_with_options(
            "alice",
            &bob.account_id_hex,
            crate::DirectConversationOptions {
                disappearing_message_secs: 300,
            },
        )
        .await
        .unwrap();
    let groups = app.groups("alice").unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].group_id_hex, hex::encode(created.as_slice()));
    assert!(fetcher.requests.lock().unwrap().iter().any(|request| {
        request.queries.iter().any(|query| {
            query.kind == KIND_NIP65_RELAY_LIST && query.authors.contains(&bob.account_id_hex)
        })
    }));
    runtime.shutdown().await;
    app.close_storage().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_create_after_prewarm_decides_on_current_routes() {
    for status in [
        MemberResolutionStatus::IncompatibleKeyPackage,
        MemberResolutionStatus::Selected,
        MemberResolutionStatus::Incomplete,
    ] {
        let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
        app.directory()
            .prewarm_group_member_key_packages(&[bob.account_id_hex.as_str()])
            .await
            .unwrap();
        let selected = status == MemberResolutionStatus::Selected;
        if selected {
            advertise_updated_direct_outbox(&fetcher, &bob, &[UPDATED_DIRECT_OUTBOX]);
        }
        if status == MemberResolutionStatus::Incomplete {
            *fetcher.incomplete_query_kind.lock().unwrap() = Some(KIND_NIP65_RELAY_LIST);
            *fetcher.incomplete_endpoint.lock().unwrap() = Some("wss://directory.example".into());
        }
        fetcher.requests.lock().unwrap().clear();
        let runtime = MarmotAppRuntime::new(app.clone());
        let result = runtime
            .create_group_with_options_detailed(
                "alice",
                "Group",
                std::slice::from_ref(&bob.account_id_hex),
                crate::AppCreateGroupOptions {
                    disappearing_message_secs: 300,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(result.operation.is_some(), selected, "{status:?}");
        assert_eq!(
            result.member_outcomes,
            vec![MemberResolutionOutcome {
                account_id_hex: bob.account_id_hex.clone(),
                status,
                selected_device_count: if selected { 1 } else { 0 },
            }]
        );
        assert!(fetcher.requests.lock().unwrap().iter().any(|request| {
            request.queries.iter().any(|query| {
                query.kind == KIND_NIP65_RELAY_LIST && query.authors.contains(&bob.account_id_hex)
            })
        }));
        runtime.shutdown().await;
        app.close_storage().unwrap();
    }
}

/// Requirements for a new chat with a five-minute message timer.
async fn retention_requirements(
    app: &MarmotApp,
) -> cgka_engine::key_package::KeyPackageRequirements {
    client_on_app_relay_plane(app, "alice")
        .await
        .runtime
        .create_key_package_requirements(&cgka_traits::engine::CreateGroupRequest {
            name: "retention".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: vec![
                crate::AppGroupMessageRetentionComponent::new(300)
                    .to_app_component_data()
                    .unwrap(),
            ],
            initial_admins: Vec::new(),
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unread_outbox_defers_verdict() {
    const CURRENT_OUTBOX: &str = "wss://current-outbox.example";
    for deleted_slot in [None, Some("limited")] {
        let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
        let requirements = retention_requirements(&app).await;
        let compatible_id = {
            let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
            let directory = &by_endpoint["wss://directory.example"];
            let listed = directory
                .iter()
                .find(|event| event.kind == KIND_NIP65_RELAY_LIST)
                .unwrap()
                .created_at;
            let incompatible = directory
                .iter()
                .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
                .unwrap()
                .clone();
            let relay_list = |relay: &str, timestamp| {
                NostrTransportEvent::new_unsigned_at(
                    bob.account_id_hex.clone(),
                    KIND_NIP65_RELAY_LIST,
                    vec![vec!["r".into(), relay.into(), "write".into()]],
                    String::new(),
                    timestamp,
                )
            };
            let old_outbox = by_endpoint.get_mut("wss://shared.example").unwrap();
            old_outbox.retain(|event| event.kind != KIND_NIP65_RELAY_LIST);
            old_outbox.push(relay_list(UPDATED_DIRECT_OUTBOX, listed + 1));
            let new_outbox = by_endpoint.get_mut(UPDATED_DIRECT_OUTBOX).unwrap();
            let index = new_outbox
                .iter()
                .position(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
                .unwrap();
            let compatible = new_outbox.swap_remove(index);
            new_outbox.push(relay_list(CURRENT_OUTBOX, listed + 2));
            if let Some(slot) = deleted_slot {
                new_outbox.push(signed_deletion(
                    &app,
                    &bob,
                    vec![slot_address(&bob, slot)],
                    incompatible.created_at,
                ));
            }
            new_outbox.push(incompatible);
            let compatible_id = compatible.id.clone();
            by_endpoint.insert(CURRENT_OUTBOX.into(), vec![compatible]);
            compatible_id
        };
        let directory = app.directory();
        let resolve = || {
            directory.resolve_compatible_member_key_packages(
                vec![bob.account_id_hex.clone()],
                &requirements,
                nostr_directory::MemberResolutionPurpose::Commit,
                nostr_directory::MemberResolutionPolicy::Atomic,
            )
        };
        let result = resolve().await;
        assert!(
            matches!(
                &result,
                Err(DirectoryError::DirectoryLookupIncomplete(account)) if account == &bob.account_id_hex
            ),
            "deleted slot {deleted_slot:?}: {:?}",
            result.err()
        );
        let resolved = resolve().await.unwrap();
        let [selected] = resolved.key_packages.as_slice() else {
            panic!("retry should select one KeyPackage");
        };
        assert_eq!(
            hex::encode(selected.source.as_ref().unwrap().event_id.as_slice()),
            compatible_id
        );
        app.close_storage().unwrap();
    }
}

/// Prewarm reads the old outbox and journals a slot's newest publication.
/// When the recipient moves outboxes and the new one serves only an older copy
/// of that slot, the journal still bars it, so no chat is created. The
/// publication the journal knows went unread, so the lookup is incomplete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_moved_outbox_cannot_revive_a_package_prewarm_saw_replaced() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    // The journal records only signed publications.
    for relays in fetcher.events_by_endpoint.lock().unwrap().values_mut() {
        for event in relays
            .iter_mut()
            .filter(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
        {
            *event = signed(&app, &bob, event.clone());
        }
    }
    app.directory()
        .prewarm_group_member_key_packages(&[bob.account_id_hex.as_str()])
        .await
        .unwrap();
    let compatible = fresh_key_package_for_account(&app, &bob, false).await;
    {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        let records = by_endpoint.get_mut("wss://directory.example").unwrap();
        let incompatible = records
            .iter()
            .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .unwrap();
        let stale = candidate(
            &bob,
            compatible,
            incompatible.tag_value("d").unwrap(),
            None,
            incompatible.created_at - 1,
        );
        let outbox = records
            .iter_mut()
            .find(|event| event.kind == KIND_NIP65_RELAY_LIST)
            .unwrap();
        *outbox = NostrTransportEvent::new_unsigned_at(
            bob.account_id_hex.clone(),
            KIND_NIP65_RELAY_LIST,
            vec![vec![
                "r".into(),
                UPDATED_DIRECT_OUTBOX.into(),
                "write".into(),
            ]],
            String::new(),
            outbox.created_at + 1,
        );
        // The incompatible replacement is visible only on the old outbox.
        records.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        let updated = by_endpoint.get_mut(UPDATED_DIRECT_OUTBOX).unwrap();
        updated.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        updated.push(stale);
    }
    fetcher.requests.lock().unwrap().clear();
    let runtime = MarmotAppRuntime::new(app.clone());
    let error = runtime
        .start_direct_conversation_with_options(
            "alice",
            &bob.account_id_hex,
            crate::DirectConversationOptions {
                disappearing_message_secs: 300,
            },
        )
        .await
        .unwrap_err();
    // The new outbox was read, but its only copy was superseded and the
    // publication the journal knows went unread.
    assert!(
        matches!(error, AppError::DirectoryLookupIncomplete { .. }),
        "{error}"
    );
    assert!(fetcher.requests.lock().unwrap().iter().any(|request| {
        request
            .endpoints
            .iter()
            .any(|endpoint| endpoint.0 == UPDATED_DIRECT_OUTBOX)
            && request.queries.iter().any(|query| {
                query.kind == KIND_MARMOT_KEY_PACKAGE && query.authors.contains(&bob.account_id_hex)
            })
    }));
    assert!(app.groups("alice").unwrap().is_empty());
    runtime.shutdown().await;
    app.close_storage().unwrap();
}

/// Prewarm sees a compatible package in a slot. The recipient's outbox then
/// moves, and the new one serves an incompatible slot beside an older copy of
/// that slot, the incompatible slot alone, or no KeyPackage at all. The
/// package the journal knows went unread each time, so neither the other
/// slot's refusal nor the empty reply is a verdict. Once a deletion request
/// accounts for that package, the same replies are verdicts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacement_only_the_journal_knows_decides_no_incompatibility() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let replacement = candidate(
        &bob,
        fresh_key_package_for_account(&app, &bob, false).await,
        "x",
        None,
        unix_now_seconds(),
    );
    {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        for endpoint in ["wss://directory.example", "wss://shared.example"] {
            by_endpoint
                .get_mut(endpoint)
                .unwrap()
                .push(replacement.clone());
        }
        for relays in by_endpoint.values_mut() {
            for event in relays
                .iter_mut()
                .filter(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            {
                *event = signed(&app, &bob, event.clone());
            }
        }
    }
    let older = fresh_key_package_for_account(&app, &bob, false).await;
    retire_journaled_key_packages(&app, &bob).await;
    app.directory()
        .prewarm_group_member_key_packages(&[bob.account_id_hex.as_str()])
        .await
        .unwrap();
    let limited = {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        let records = by_endpoint.get_mut("wss://directory.example").unwrap();
        let limited = records
            .iter()
            .find(|event| {
                event.kind == KIND_MARMOT_KEY_PACKAGE && event.tag_value("d") == Some("limited")
            })
            .unwrap()
            .clone();
        let stale = candidate(&bob, older, "x", None, replacement.created_at - 1);
        let outbox = records
            .iter_mut()
            .find(|event| event.kind == KIND_NIP65_RELAY_LIST)
            .unwrap();
        *outbox = NostrTransportEvent::new_unsigned_at(
            bob.account_id_hex.clone(),
            KIND_NIP65_RELAY_LIST,
            vec![vec![
                "r".into(),
                UPDATED_DIRECT_OUTBOX.into(),
                "write".into(),
            ]],
            String::new(),
            outbox.created_at + 1,
        );
        records.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        let updated = by_endpoint.get_mut(UPDATED_DIRECT_OUTBOX).unwrap();
        updated.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        updated.push(stale);
        updated.push(limited.clone());
        limited
    };
    let runtime = MarmotAppRuntime::new(app.clone());
    let start = || {
        runtime.start_direct_conversation_with_options(
            "alice",
            &bob.account_id_hex,
            crate::DirectConversationOptions {
                disappearing_message_secs: 300,
            },
        )
    };
    for served in ["an older copy and another slot", "another slot", "nothing"] {
        fetcher
            .events_by_endpoint
            .lock()
            .unwrap()
            .get_mut(UPDATED_DIRECT_OUTBOX)
            .unwrap()
            .retain(|event| match served {
                "another slot" => event.tag_value("d") != Some("x"),
                "nothing" => event.kind != KIND_MARMOT_KEY_PACKAGE,
                _ => true,
            });
        let error = start().await.unwrap_err();
        assert!(
            matches!(error, AppError::DirectoryLookupIncomplete { .. }),
            "new outbox serves {served}: {error}"
        );
        assert!(app.groups("alice").unwrap().is_empty());
    }
    // Discovery and the reads were complete all along: once deletion requests
    // account for what the journal knows, the refusal and then the empty
    // reply each decide.
    let serve = |event: NostrTransportEvent| {
        fetcher
            .events_by_endpoint
            .lock()
            .unwrap()
            .get_mut(UPDATED_DIRECT_OUTBOX)
            .unwrap()
            .push(event)
    };
    let deletion_of_journaled = |slot: &str| {
        let journaled = app
            .shared_storage()
            .unwrap()
            .public_key_package_replacements(&bob.account_id_hex)
            .unwrap()
            .into_iter()
            .find(|publication| publication.key_package_id == slot)
            .unwrap();
        signed_deletion(
            &app,
            &bob,
            vec![
                vec!["e".into(), journaled.event_id_hex],
                vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
            ],
            unix_now_seconds(),
        )
    };
    serve(deletion_of_journaled("x"));
    serve(limited.clone());
    let error = start().await.unwrap_err();
    assert!(
        matches!(error, AppError::IncompatibleKeyPackage(_)),
        "{error}"
    );
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .get_mut(UPDATED_DIRECT_OUTBOX)
        .unwrap()
        .retain(|event| event.id != limited.id);
    serve(deletion_of_journaled("limited"));
    let error = start().await.unwrap_err();
    assert!(
        matches!(error, AppError::MissingKeyPackage { .. }),
        "{error}"
    );
    assert!(app.groups("alice").unwrap().is_empty());
    runtime.shutdown().await;
    app.close_storage().unwrap();
}

/// A package the journal knows stays selectable past the 30-day freshness
/// window, as the single fallback, and the journal keeps its row a little
/// longer. When the recipient's outbox moves and the reads omit it, it still
/// blocks a verdict. Served again, it starts the chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_journaled_package_past_the_freshness_window_still_blocks_a_verdict() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let aged = signed(
        &app,
        &bob,
        candidate(
            &bob,
            fresh_key_package_for_account(&app, &bob, false).await,
            "aged",
            None,
            unix_now_seconds() - nostr_directory::KEY_PACKAGE_FRESHNESS.as_secs() - 60,
        ),
    );
    retire_journaled_key_packages(&app, &bob).await;
    for endpoint in ["wss://directory.example", "wss://shared.example"] {
        fetcher
            .events_by_endpoint
            .lock()
            .unwrap()
            .get_mut(endpoint)
            .unwrap()
            .push(aged.clone());
    }
    app.directory()
        .prewarm_group_member_key_packages(&[bob.account_id_hex.as_str()])
        .await
        .unwrap();
    assert!(
        app.shared_storage()
            .unwrap()
            .public_key_package_replacements(&bob.account_id_hex)
            .unwrap()
            .iter()
            .any(|publication| publication.event_id_hex == aged.id)
    );
    advertise_updated_direct_outbox(&fetcher, &bob, &[UPDATED_DIRECT_OUTBOX]);
    let serve = |events: Vec<NostrTransportEvent>| {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        let updated = by_endpoint.get_mut(UPDATED_DIRECT_OUTBOX).unwrap();
        updated.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        updated.extend(events);
    };
    let limited = {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        let records = by_endpoint.get_mut("wss://directory.example").unwrap();
        let limited = records
            .iter()
            .find(|event| {
                event.kind == KIND_MARMOT_KEY_PACKAGE && event.tag_value("d") == Some("limited")
            })
            .unwrap()
            .clone();
        records.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        limited
    };
    let runtime = MarmotAppRuntime::new(app.clone());
    let start = || {
        runtime.start_direct_conversation_with_options(
            "alice",
            &bob.account_id_hex,
            crate::DirectConversationOptions {
                disappearing_message_secs: 300,
            },
        )
    };
    for (served, events) in [
        ("a newer incompatible package", vec![limited.clone()]),
        ("nothing", vec![]),
    ] {
        serve(events);
        let error = start().await.unwrap_err();
        assert!(
            matches!(error, AppError::DirectoryLookupIncomplete { .. }),
            "new outbox serves {served}: {error}"
        );
        assert!(app.groups("alice").unwrap().is_empty());
    }
    // Served beside the incompatible package, the aged one is selected.
    serve(vec![limited, aged]);
    start().await.unwrap();
    assert_eq!(app.groups("alice").unwrap().len(), 1);
    runtime.shutdown().await;
    app.close_storage().unwrap();
}

/// A deletion request dated past the clock-skew allowance still removes its
/// package from selection, but the journal does not record the request. The
/// lookup holds it, so the journal's row for the package is accounted for,
/// both when the relays still serve the package and when they serve the
/// request alone, and the recipient has none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_package_the_lookup_read_and_dropped_is_not_an_unread_one() {
    let (_dir, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let bob = &accounts[0];
    let now = unix_now_seconds();
    let package = signed(
        &app,
        bob,
        candidate(
            bob,
            fresh_key_package_for_account(&app, bob, false).await,
            "only",
            None,
            now,
        ),
    );
    let deletion = signed_deletion(
        &app,
        bob,
        vec![
            vec!["e".into(), package.id.clone()],
            vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
        ],
        now + 24 * 60 * 60,
    );
    {
        let mut events = fetcher.events.lock().unwrap();
        events.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        events.extend([package.clone(), deletion]);
    }
    // First the relays serve the package beside its deletion request, then
    // the request alone, which accounts for the row the journal now holds.
    for served in ["the package and its deletion", "the deletion alone"] {
        let error = app
            .directory()
            .resolve_member_key_packages(&[bob.account_id_hex.as_str()])
            .await
            .unwrap_err();
        assert!(
            matches!(error, DirectoryError::MissingKeyPackage { .. }),
            "relays serve {served}: {error:?}"
        );
        // The journal holds the package and no deletion of it.
        let storage = app.shared_storage().unwrap();
        assert!(
            storage
                .public_key_package_replacements(&bob.account_id_hex)
                .unwrap()
                .iter()
                .any(|publication| publication.event_id_hex == package.id)
        );
        assert!(
            storage
                .public_key_package_barriers(&bob.account_id_hex)
                .unwrap()
                .is_empty()
        );
        fetcher
            .events
            .lock()
            .unwrap()
            .retain(|event| event.id != package.id);
    }
    app.close_storage().unwrap();
}

/// The proof read for one package returns a deletion request that also covers
/// a slot the journal knows and no read returned. The request is dated past
/// the clock-skew allowance, so the journal records nothing for it, but the
/// lookup holds it: the recipient has no KeyPackage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deletion_only_the_proof_read_finds_accounts_for_another_slot() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let now = unix_now_seconds();
    app.shared_storage()
        .unwrap()
        .put_public_key_package_replacement(&storage_sqlite::PublicKeyPackageReplacementRecord {
            account_id_hex: bob.account_id_hex.clone(),
            key_package_id: "unread".into(),
            event_id_hex: "cd".repeat(32),
            event_created_at: now,
            observed_at: now,
        })
        .unwrap();
    let served = candidate(
        &bob,
        fresh_key_package_for_account(&app, &bob, false).await,
        "served",
        None,
        now,
    );
    // Without a `k` tag only the proof read's reference queries match it.
    let deletion = signed_deletion(
        &app,
        &bob,
        vec![
            vec!["e".into(), served.id.clone()],
            slot_address(&bob, "unread"),
        ],
        now + 24 * 60 * 60,
    );
    let deletion_id = deletion.id.clone();
    {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        for relay in ["wss://shared.example", "wss://directory.example"] {
            by_endpoint
                .get_mut(relay)
                .unwrap()
                .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        }
        // The outbox holds nothing, so recovery's read of the directory
        // relay finds the package and proves it.
        by_endpoint
            .get_mut("wss://directory.example")
            .unwrap()
            .extend([served, deletion]);
    }
    let result = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
        .await;
    assert!(
        matches!(result, Err(DirectoryError::MissingKeyPackage { .. })),
        "{:?}",
        result.err()
    );
    // The journal recorded nothing for the request.
    assert!(
        app.shared_storage()
            .unwrap()
            .public_key_package_barriers(&bob.account_id_hex)
            .unwrap()
            .iter()
            .all(|barrier| barrier.event_id_hex != deletion_id)
    );
    app.close_storage().unwrap();
}

/// The journal's size limits evict a recipient's package to a barrier and
/// then to the account's eviction marker, which still names it. Whether the
/// reads return no KeyPackage or an older copy of that slot, which the marker
/// still bars, the lookup is incomplete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_package_evicted_to_the_journals_marker_still_blocks_a_verdict() {
    let (_dir, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let bob = &accounts[0];
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    let storage = app.shared_storage().unwrap();
    let now = unix_now_seconds();
    let evicted = "cd".repeat(32);
    storage
        .put_public_key_package_replacement(&storage_sqlite::PublicKeyPackageReplacementRecord {
            account_id_hex: bob.account_id_hex.clone(),
            key_package_id: "evicted".into(),
            event_id_hex: evicted.clone(),
            event_created_at: now,
            observed_at: now - 100,
        })
        .unwrap();
    // Other accounts' newer evidence fills the replacement table, then the
    // barrier table.
    for other in 1..=1_000u64 {
        let id = format!("{other:064x}");
        storage
            .put_public_key_package_replacement(
                &storage_sqlite::PublicKeyPackageReplacementRecord {
                    account_id_hex: id.clone(),
                    key_package_id: "slot".into(),
                    event_id_hex: id,
                    event_created_at: now,
                    observed_at: now,
                },
            )
            .unwrap();
    }
    for other in 1_001..=2_000u64 {
        let id = format!("{other:064x}");
        storage
            .put_public_key_package_barrier(&storage_sqlite::PublicKeyPackageBarrierRecord {
                account_id_hex: id.clone(),
                key_package_id: "slot".into(),
                event_id_hex: id.clone(),
                deleted_event_id: Some(id),
                event_created_at: now,
                observed_at: now,
                kind: storage_sqlite::PublicKeyPackageBarrierKind::Deletion,
            })
            .unwrap();
    }
    let snapshot = storage
        .key_package_evidence_snapshot(&bob.account_id_hex)
        .unwrap();
    assert!(snapshot.replacements.is_empty() && snapshot.barriers.is_empty());
    assert_eq!(
        snapshot.watermark.map(|marker| marker.event_id_hex),
        Some(evicted)
    );
    let older = candidate(
        bob,
        fresh_key_package_for_account(&app, bob, false).await,
        "evicted",
        None,
        now - 1,
    );
    for served in ["nothing", "an older copy of the slot"] {
        if served != "nothing" {
            fetcher.events.lock().unwrap().push(older.clone());
        }
        let error = app
            .directory()
            .resolve_member_key_packages(&[bob.account_id_hex.as_str()])
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                DirectoryError::DirectoryLookupIncomplete(account) if account == &bob.account_id_hex
            ),
            "relays serve {served}: {error:?}"
        );
    }
    app.close_storage().unwrap();
}

/// The journal's size limits evict a deletion of a slot's address to the
/// account's eviction marker, which still names the slot and the request's
/// time, while the journal keeps the publication it covered. The marker
/// settles the slot: the recipient has no KeyPackage, whether the relays
/// serve nothing or serve the deleted publication again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_evicted_address_deletion_still_settles_its_slot() {
    let (_dir, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let bob = &accounts[0];
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    let storage = app.shared_storage().unwrap();
    let now = unix_now_seconds();
    let deleted = candidate(
        bob,
        fresh_key_package_for_account(&app, bob, false).await,
        "deleted",
        None,
        now - 1,
    );
    storage
        .put_public_key_package_replacement(&storage_sqlite::PublicKeyPackageReplacementRecord {
            account_id_hex: bob.account_id_hex.clone(),
            key_package_id: "deleted".into(),
            event_id_hex: deleted.id.clone(),
            event_created_at: now - 1,
            observed_at: now,
        })
        .unwrap();
    storage
        .put_public_key_package_barrier(&storage_sqlite::PublicKeyPackageBarrierRecord {
            account_id_hex: bob.account_id_hex.clone(),
            key_package_id: "deleted".into(),
            event_id_hex: "ef".repeat(32),
            deleted_event_id: None,
            event_created_at: now,
            observed_at: now - 100,
            kind: storage_sqlite::PublicKeyPackageBarrierKind::Deletion,
        })
        .unwrap();
    // Other accounts' newer barriers fill the barrier table.
    for other in 1..=1_000u64 {
        let id = format!("{other:064x}");
        storage
            .put_public_key_package_barrier(&storage_sqlite::PublicKeyPackageBarrierRecord {
                account_id_hex: id.clone(),
                key_package_id: "slot".into(),
                event_id_hex: id.clone(),
                deleted_event_id: Some(id),
                event_created_at: now,
                observed_at: now,
                kind: storage_sqlite::PublicKeyPackageBarrierKind::Deletion,
            })
            .unwrap();
    }
    let snapshot = storage
        .key_package_evidence_snapshot(&bob.account_id_hex)
        .unwrap();
    assert_eq!(snapshot.replacements.len(), 1);
    assert!(snapshot.barriers.is_empty());
    assert_eq!(
        snapshot.watermark.map(|marker| marker.kind),
        Some(storage_sqlite::PublicKeyPackageBarrierKind::Deletion)
    );
    for served in ["nothing", "the deleted publication"] {
        if served != "nothing" {
            fetcher.events.lock().unwrap().push(deleted.clone());
        }
        let error = app
            .directory()
            .resolve_member_key_packages(&[bob.account_id_hex.as_str()])
            .await
            .unwrap_err();
        assert!(
            matches!(error, DirectoryError::MissingKeyPackage { .. }),
            "relays serve {served}: {error:?}"
        );
    }
    app.close_storage().unwrap();
}

/// Points the directory's relay list for `bob` at `relays`, keeping its
/// timestamp, and drops the old outbox's own copy of the list.
fn tie_directory_relay_list(
    fetcher: &MemberResolutionDirectoryFetcher,
    bob: &AccountSummary,
    relays: &[&str],
) {
    let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
    let listed = by_endpoint
        .get_mut("wss://directory.example")
        .unwrap()
        .iter_mut()
        .find(|event| event.kind == KIND_NIP65_RELAY_LIST)
        .unwrap();
    *listed = NostrTransportEvent::new_unsigned_at(
        bob.account_id_hex.clone(),
        KIND_NIP65_RELAY_LIST,
        relays
            .iter()
            .map(|relay| vec!["r".into(), (*relay).into(), "write".into()])
            .collect(),
        String::new(),
        listed.created_at,
    );
    by_endpoint
        .get_mut("wss://shared.example")
        .unwrap()
        .retain(|event| event.kind != KIND_NIP65_RELAY_LIST);
}

/// Relay lists published in the same second tie, and the remembered list
/// keeps its routes on a tie. The same relay spelled with a trailing slash is
/// no conflict, so the verdict stands. A tied list naming another outbox is
/// read too: its compatible package is used, and the tie alone decides nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tied_relay_list_is_read_but_decides_nothing() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    // The first lookup remembers the list naming the old outbox.
    let first = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
        .await;
    assert!(
        matches!(first, Err(DirectoryError::KeyPackageRequirements(_))),
        "{:?}",
        first.err()
    );

    tie_directory_relay_list(&fetcher, &bob, &["wss://shared.example/"]);
    let same_relay = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
        .await;
    assert!(
        matches!(same_relay, Err(DirectoryError::KeyPackageRequirements(_))),
        "{:?}",
        same_relay.err()
    );

    tie_directory_relay_list(&fetcher, &bob, &[UPDATED_DIRECT_OUTBOX]);
    let compatible = {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        let incompatible = by_endpoint["wss://shared.example"]
            .iter()
            .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .unwrap()
            .clone();
        let new_outbox = by_endpoint.get_mut(UPDATED_DIRECT_OUTBOX).unwrap();
        let position = new_outbox
            .iter()
            .position(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .unwrap();
        std::mem::replace(&mut new_outbox[position], incompatible)
    };
    // With only incompatible packages on both outboxes, the tie decides nothing.
    let unresolved = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
        .await;
    assert!(
        matches!(
            &unresolved,
            Err(DirectoryError::DirectoryLookupIncomplete(account)) if account == &bob.account_id_hex
        ),
        "{:?}",
        unresolved.err()
    );
    {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        let new_outbox = by_endpoint.get_mut(UPDATED_DIRECT_OUTBOX).unwrap();
        new_outbox.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        new_outbox.push(compatible.clone());
    }
    let compatible = compatible.id;
    let resolved = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
        .await
        .unwrap();
    assert_eq!(
        resolved
            .key_packages
            .iter()
            .map(|package| hex::encode(package.source.as_ref().unwrap().event_id.as_slice()))
            .collect::<Vec<_>>(),
        vec![compatible]
    );
    app.close_storage().unwrap();
}

/// A same-second relay list on `endpoint` whose event id sorts after
/// `listed`'s, so `listed` wins the tie, naming `relay` with `marker`.
fn losing_relay_list(
    listed: &NostrTransportEvent,
    relay: &str,
    marker: &str,
) -> NostrTransportEvent {
    (0..)
        .map(|nonce| {
            NostrTransportEvent::new_unsigned_at(
                listed.pubkey.clone(),
                KIND_NIP65_RELAY_LIST,
                vec![vec!["r".into(), relay.into(), marker.into()]],
                nonce.to_string(),
                listed.created_at,
            )
        })
        .find(|event| event.id > listed.id)
        .unwrap()
}

/// Two relays can serve different relay lists published in the same second.
/// The lower event id wins the list, but the other list is a tie all the
/// same. Its outbox is read and a compatible package there is used. A tied
/// list naming only a read relay adds no outbox, yet it still blocks a
/// verdict on the remembered outbox's incompatible package.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_losing_same_second_relay_list_is_still_a_tie() {
    for marker in ["write", "read"] {
        let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
        let requirements = retention_requirements(&app).await;
        let compatible = {
            let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
            let listed = by_endpoint["wss://directory.example"]
                .iter()
                .find(|event| event.kind == KIND_NIP65_RELAY_LIST)
                .unwrap()
                .clone();
            let old_outbox = by_endpoint.get_mut("wss://shared.example").unwrap();
            old_outbox.retain(|event| event.kind != KIND_NIP65_RELAY_LIST);
            old_outbox.push(losing_relay_list(&listed, UPDATED_DIRECT_OUTBOX, marker));
            by_endpoint[UPDATED_DIRECT_OUTBOX]
                .iter()
                .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
                .unwrap()
                .id
                .clone()
        };
        let result = app
            .directory()
            .resolve_compatible_member_key_packages(
                vec![bob.account_id_hex.clone()],
                &requirements,
                nostr_directory::MemberResolutionPurpose::Commit,
                nostr_directory::MemberResolutionPolicy::Atomic,
            )
            .await;
        if marker == "write" {
            assert_eq!(
                result
                    .unwrap()
                    .key_packages
                    .iter()
                    .map(|package| hex::encode(
                        package.source.as_ref().unwrap().event_id.as_slice()
                    ))
                    .collect::<Vec<_>>(),
                vec![compatible]
            );
        } else {
            assert!(
                matches!(
                    &result,
                    Err(DirectoryError::DirectoryLookupIncomplete(account)) if account == &bob.account_id_hex
                ),
                "{:?}",
                result.err()
            );
        }
        app.close_storage().unwrap();
    }
}

/// When the winning relay list names no outbox, the configured directory
/// relays stay among the KeyPackage routes. A tied list's outbox only adds to
/// them, so its unfinished read cannot hide a compatible package on the
/// directory relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tied_outbox_does_not_displace_the_directory_relays() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let compatible = {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        let compatible = by_endpoint[UPDATED_DIRECT_OUTBOX]
            .iter()
            .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .unwrap()
            .clone();
        let directory = by_endpoint.get_mut("wss://directory.example").unwrap();
        let position = directory
            .iter()
            .position(|event| event.kind == KIND_NIP65_RELAY_LIST)
            .unwrap();
        let read_only = NostrTransportEvent::new_unsigned_at(
            bob.account_id_hex.clone(),
            KIND_NIP65_RELAY_LIST,
            vec![vec![
                "r".into(),
                "wss://shared.example".into(),
                "read".into(),
            ]],
            String::new(),
            directory[position].created_at,
        );
        let tied = losing_relay_list(&read_only, "wss://offline.example", "write");
        directory[position] = read_only;
        directory.push(tied);
        directory.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        directory.push(compatible.clone());
        compatible.id
    };
    *fetcher.incomplete_endpoint.lock().unwrap() = Some("wss://offline.example".into());
    *fetcher.incomplete_query_kind.lock().unwrap() = Some(KIND_MARMOT_KEY_PACKAGE);
    let resolved = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
        .await
        .unwrap();
    assert_eq!(
        resolved
            .key_packages
            .iter()
            .map(|package| hex::encode(package.source.as_ref().unwrap().event_id.as_slice()))
            .collect::<Vec<_>>(),
        vec![compatible]
    );
    app.close_storage().unwrap();
}

/// A tied relay list can name enough relays to push the recipient's routes
/// past the admission limit. The tie only adds reads, so the remembered outbox
/// is still read and its compatible package is used. While that outbox and
/// the directory relays hold none, the outboxes left unread keep the lookup
/// from reporting the recipient as having no KeyPackage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tied_relay_list_too_long_to_add_still_reads_the_remembered_outbox() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let directory = app.directory();
    let resolve = || {
        directory.resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
    };
    // The first lookup remembers the list naming the old outbox.
    let first = resolve().await;
    assert!(
        matches!(first, Err(DirectoryError::KeyPackageRequirements(_))),
        "{:?}",
        first.err()
    );
    let tied = (0..16)
        .map(|relay| format!("wss://tied-{relay}.example"))
        .collect::<Vec<_>>();
    tie_directory_relay_list(
        &fetcher,
        &bob,
        &tied.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let compatible = {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        let compatible = by_endpoint[UPDATED_DIRECT_OUTBOX]
            .iter()
            .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .unwrap()
            .clone();
        for relay in ["wss://shared.example", "wss://directory.example"] {
            by_endpoint
                .get_mut(relay)
                .unwrap()
                .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        }
        by_endpoint.insert(tied[0].clone(), vec![compatible.clone()]);
        compatible
    };
    let skipped = resolve().await;
    assert!(
        matches!(
            &skipped,
            Err(DirectoryError::DirectoryLookupIncomplete(account)) if account == &bob.account_id_hex
        ),
        "{:?}",
        skipped.err()
    );
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .get_mut("wss://shared.example")
        .unwrap()
        .push(compatible.clone());
    let compatible = compatible.id;
    let resolved = resolve().await.unwrap();
    assert_eq!(
        resolved
            .key_packages
            .iter()
            .map(|package| hex::encode(package.source.as_ref().unwrap().event_id.as_slice()))
            .collect::<Vec<_>>(),
        vec![compatible]
    );
    app.close_storage().unwrap();
}

/// A tied relay list can push the routes past the admission limit and still
/// leave nothing unread: its only outbox is a directory relay, which recovery
/// reads when the listed outboxes hold nothing. Every outbox either list names
/// was then read, so the recipient has no KeyPackage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tied_outbox_recovery_reads_leaves_absence_decided() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let directory = app.directory();
    let resolve = || {
        directory.resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
    };
    for events in fetcher.events_by_endpoint.lock().unwrap().values_mut() {
        events.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    }
    // The first lookup remembers a list naming as many outboxes as one read
    // admits.
    let listed = (0..16)
        .map(|relay| format!("wss://listed-{relay}.example"))
        .collect::<Vec<_>>();
    advertise_updated_direct_outbox(
        &fetcher,
        &bob,
        &listed.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let first = resolve().await;
    assert!(
        matches!(first, Err(DirectoryError::MissingKeyPackage { .. })),
        "{:?}",
        first.err()
    );
    tie_directory_relay_list(&fetcher, &bob, &["wss://directory.example"]);
    let tied = resolve().await;
    assert!(
        matches!(tied, Err(DirectoryError::MissingKeyPackage { .. })),
        "{:?}",
        tied.err()
    );
    app.close_storage().unwrap();
}

/// A tied relay list that repeats a listed relay with a trailing slash adds
/// no route for it. Fifteen more relays beside it still fit one read, so the
/// package on one of them is found.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tied_list_repeating_a_listed_relay_does_not_use_up_the_route_limit() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let directory = app.directory();
    let resolve = || {
        directory.resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
    };
    // The first lookup remembers the list naming the old outbox.
    let first = resolve().await;
    assert!(
        matches!(first, Err(DirectoryError::KeyPackageRequirements(_))),
        "{:?}",
        first.err()
    );
    let added = (0..15)
        .map(|relay| format!("wss://tied-{relay}.example"))
        .collect::<Vec<_>>();
    let tied = std::iter::once("wss://shared.example/")
        .chain(added.iter().map(String::as_str))
        .collect::<Vec<_>>();
    tie_directory_relay_list(&fetcher, &bob, &tied);
    let compatible = {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        let compatible = by_endpoint[UPDATED_DIRECT_OUTBOX]
            .iter()
            .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .unwrap()
            .clone();
        for relay in ["wss://shared.example", "wss://directory.example"] {
            by_endpoint
                .get_mut(relay)
                .unwrap()
                .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        }
        by_endpoint.insert(added[0].clone(), vec![compatible.clone()]);
        compatible.id
    };
    let resolved = resolve().await.unwrap();
    assert_eq!(
        resolved
            .key_packages
            .iter()
            .map(|package| hex::encode(package.source.as_ref().unwrap().event_id.as_slice()))
            .collect::<Vec<_>>(),
        vec![compatible]
    );
    app.close_storage().unwrap();
}

/// A recipient's list can name one relay twice, with and without a root
/// slash. It is one route, so fifteen listed relays and one a tied list adds
/// fit one read, and the package only the tied relay holds is found.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_listed_twice_counts_once_toward_the_route_limit() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let directory = app.directory();
    let resolve = || {
        directory.resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
    };
    let more = (0..14)
        .map(|relay| format!("wss://listed-{relay}.example"))
        .collect::<Vec<_>>();
    let listed = ["wss://shared.example", "wss://shared.example/"]
        .into_iter()
        .chain(more.iter().map(String::as_str))
        .collect::<Vec<_>>();
    advertise_updated_direct_outbox(&fetcher, &bob, &listed);
    // The first lookup remembers that list.
    let first = resolve().await;
    assert!(
        matches!(first, Err(DirectoryError::KeyPackageRequirements(_))),
        "{:?}",
        first.err()
    );
    tie_directory_relay_list(&fetcher, &bob, &["wss://tied.example"]);
    let compatible = {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        let compatible = by_endpoint[UPDATED_DIRECT_OUTBOX]
            .iter()
            .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .unwrap()
            .clone();
        for relay in ["wss://shared.example", "wss://directory.example"] {
            by_endpoint
                .get_mut(relay)
                .unwrap()
                .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        }
        by_endpoint.insert("wss://tied.example".into(), vec![compatible.clone()]);
        compatible.id
    };
    let resolved = resolve().await.unwrap();
    assert_eq!(
        resolved
            .key_packages
            .iter()
            .map(|package| hex::encode(package.source.as_ref().unwrap().event_id.as_slice()))
            .collect::<Vec<_>>(),
        vec![compatible]
    );
    app.close_storage().unwrap();
}

/// A list naming as many relays as one read admits can also name one of them
/// twice, with and without a root slash. Every relay it names is still read,
/// in the relay list hop and for KeyPackages, so the incompatibility stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_route_list_naming_one_relay_twice_is_still_read() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let more = (0..15)
        .map(|relay| format!("wss://listed-{relay}.example"))
        .collect::<Vec<_>>();
    let listed = ["wss://shared.example", "wss://shared.example/"]
        .into_iter()
        .chain(more.iter().map(String::as_str))
        .collect::<Vec<_>>();
    advertise_updated_direct_outbox(&fetcher, &bob, &listed);
    let result = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
        .await;
    assert!(
        matches!(result, Err(DirectoryError::KeyPackageRequirements(_))),
        "{:?}",
        result.err()
    );
    app.close_storage().unwrap();
}

/// Serves `relay`'s events at its spelling with a root slash too, and has
/// `source` serve a list for `bob`, one second newer, naming only that
/// spelling.
fn relist_with_a_root_slash(
    fetcher: &MemberResolutionDirectoryFetcher,
    bob: &AccountSummary,
    source: &str,
    relay: &str,
) {
    let slashed = format!("{relay}/");
    let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
    let listed = by_endpoint
        .get_mut(source)
        .unwrap()
        .iter_mut()
        .find(|event| event.kind == KIND_NIP65_RELAY_LIST)
        .unwrap();
    *listed = NostrTransportEvent::new_unsigned_at(
        bob.account_id_hex.clone(),
        KIND_NIP65_RELAY_LIST,
        vec![vec!["r".into(), slashed.clone(), "write".into()]],
        String::new(),
        listed.created_at + 1,
    );
    let served = by_endpoint[relay].clone();
    by_endpoint.insert(slashed, served);
}

/// Whether some read asked `endpoint` for relay lists.
fn relay_lists_were_read_from(fetcher: &MemberResolutionDirectoryFetcher, endpoint: &str) -> bool {
    fetcher.requests.lock().unwrap().iter().any(|request| {
        request
            .queries
            .iter()
            .any(|query| query.kind == KIND_NIP65_RELAY_LIST)
            && request.endpoints.iter().any(|read| read.0 == endpoint)
    })
}

/// The outbox a recipient's list names can serve a newer list that names the
/// same relay with a root slash. The lookup read that relay, so discovery is
/// complete and the incompatibility stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outbox_relisted_with_a_root_slash_was_already_read() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    relist_with_a_root_slash(
        &fetcher,
        &bob,
        "wss://shared.example",
        "wss://shared.example",
    );
    let result = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
        .await;
    assert!(
        matches!(result, Err(DirectoryError::KeyPackageRequirements(_))),
        "{:?}",
        result.err()
    );
    assert!(relay_lists_were_read_from(&fetcher, "wss://shared.example"));
    app.close_storage().unwrap();
}

/// A list can name a directory relay as the outbox, spelled with a root
/// slash. A complete first hop already read that relay, so no second relay
/// list read goes to it under the other spelling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_relay_listed_with_a_root_slash_is_not_read_again() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    relist_with_a_root_slash(
        &fetcher,
        &bob,
        "wss://directory.example",
        "wss://directory.example",
    );
    let result = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
        .await;
    assert!(
        matches!(result, Err(DirectoryError::KeyPackageRequirements(_))),
        "{:?}",
        result.err()
    );
    assert!(relay_lists_were_read_from(
        &fetcher,
        "wss://directory.example"
    ));
    assert!(!relay_lists_were_read_from(
        &fetcher,
        "wss://directory.example/"
    ));
    app.close_storage().unwrap();
}

/// A batch reply that stops early can still return the recipient's relay list
/// or package. When the single-author retry and the later reads then finish
/// without it, no completed read served it, so it supports no incompatibility
/// verdict. A replacement dated past the allowed clock skew confirms nothing
/// either. A retry that serves both again lets the verdict stand, and so does
/// a deletion request for the package, from a completed read or the journal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_only_an_unfinished_batch_returned_decides_nothing() {
    let (_dir, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
    app.account_home().create_account("alice").unwrap();
    let requirements = retention_requirements(&app).await;
    let (bob, carol) = (&accounts[0], &accounts[1]);
    let limited = fresh_key_package_with_components(
        &app,
        bob,
        false,
        app.supported_app_component_ids()
            .into_iter()
            .filter(|id| *id != cgka_traits::app_components::GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .collect(),
    )
    .await;
    let mut events = fetcher.events.lock().unwrap().clone();
    events.retain(|event| {
        event.kind != KIND_MARMOT_KEY_PACKAGE || event.pubkey != bob.account_id_hex
    });
    let bob_package = candidate(bob, limited, "limited", None, unix_now_seconds());
    let bob_package_id = bob_package.id.clone();
    events.push(bob_package);
    let bob_relay_list = events
        .iter()
        .find(|event| event.kind == KIND_NIP65_RELAY_LIST && event.pubkey == bob.account_id_hex)
        .unwrap()
        .id
        .clone();
    // The outbox serves packages and inbox lists, never relay lists.
    let outbox = events
        .iter()
        .filter(|event| event.kind != KIND_NIP65_RELAY_LIST)
        .cloned()
        .collect();
    fetcher.events_by_endpoint.lock().unwrap().extend([
        ("wss://directory.example".into(), events),
        ("wss://shared.example".into(), outbox),
    ]);
    let directory = app.directory();
    let resolve = || {
        directory.resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone(), carol.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::Commit,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
    };
    // Complete reads make the incompatible package the verdict.
    let complete = resolve().await;
    assert!(
        matches!(complete, Err(DirectoryError::KeyPackageRequirements(_))),
        "{:?}",
        complete.err()
    );

    // Batches that stop early alone decide nothing: the retries serve the
    // list and the package again.
    fetcher
        .closed_multi_author_reads
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let retried = resolve().await;
    assert!(
        matches!(retried, Err(DirectoryError::KeyPackageRequirements(_))),
        "{:?}",
        retried.err()
    );

    let future_replacement = candidate(
        bob,
        fresh_key_package_for_account(&app, bob, false).await,
        "limited",
        None,
        unix_now_seconds() + 24 * 60 * 60,
    );
    for (unserved, replacement) in [
        (bob_relay_list, None),
        (bob_package_id.clone(), None),
        (bob_package_id, Some(future_replacement)),
    ] {
        *fetcher.events_only_in_multi_author.lock().unwrap() = [unserved].into();
        if let Some(replacement) = replacement {
            fetcher
                .events_only_in_single_author
                .lock()
                .unwrap()
                .insert(replacement.id.clone());
            for events in fetcher.events_by_endpoint.lock().unwrap().values_mut() {
                events.push(replacement.clone());
            }
        }
        let unfinished = resolve().await;
        assert!(
            matches!(
                &unfinished,
                Err(DirectoryError::DirectoryLookupIncomplete(account)) if account == &bob.account_id_hex
            ),
            "{:?}",
            unfinished.err()
        );
    }
    // A legacy package only the unfinished batch returned decides no
    // absence either.
    let legacy = signed(
        &app,
        bob,
        candidate(
            bob,
            fresh_key_package_for_account(&app, bob, true).await,
            "legacy",
            None,
            unix_now_seconds(),
        ),
    );
    for events in fetcher.events_by_endpoint.lock().unwrap().values_mut() {
        events.retain(|event| {
            event.kind != KIND_MARMOT_KEY_PACKAGE || event.pubkey != bob.account_id_hex
        });
        events.push(legacy.clone());
    }
    *fetcher.events_only_in_multi_author.lock().unwrap() = [legacy.id.clone()].into();
    let obsolete = resolve().await;
    assert!(
        matches!(
            &obsolete,
            Err(DirectoryError::DirectoryLookupIncomplete(account)) if account == &bob.account_id_hex
        ),
        "{:?}",
        obsolete.err()
    );

    // A deletion request the completed retry returns accounts for that
    // package, so the recipient has none. The journal records this request
    // too; the post-dated one below is the case only the lookup holds.
    let deletion = signed_deletion(
        &app,
        bob,
        vec![
            vec!["e".into(), legacy.id],
            vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
        ],
        unix_now_seconds(),
    );
    fetcher
        .events_only_in_single_author
        .lock()
        .unwrap()
        .insert(deletion.id.clone());
    for events in fetcher.events_by_endpoint.lock().unwrap().values_mut() {
        events.push(deletion.clone());
    }
    let deleted = resolve().await;
    assert!(
        matches!(deleted, Err(DirectoryError::MissingKeyPackage { .. })),
        "{:?}",
        deleted.err()
    );

    // So does a deletion the journal already holds and no read returns.
    let journaled = signed(
        &app,
        bob,
        candidate(
            bob,
            fresh_key_package_for_account(&app, bob, true).await,
            "journaled",
            None,
            unix_now_seconds(),
        ),
    );
    for events in fetcher.events_by_endpoint.lock().unwrap().values_mut() {
        events.push(journaled.clone());
    }
    *fetcher.events_only_in_multi_author.lock().unwrap() = [journaled.id.clone()].into();
    let unconfirmed = resolve().await;
    assert!(
        matches!(
            &unconfirmed,
            Err(DirectoryError::DirectoryLookupIncomplete(account)) if account == &bob.account_id_hex
        ),
        "{:?}",
        unconfirmed.err()
    );
    let now = unix_now_seconds();
    app.shared_storage()
        .unwrap()
        .put_public_key_package_barrier(&storage_sqlite::PublicKeyPackageBarrierRecord {
            account_id_hex: bob.account_id_hex.clone(),
            key_package_id: "journaled".into(),
            event_id_hex: "ab".repeat(32),
            deleted_event_id: Some(journaled.id),
            event_created_at: now,
            observed_at: now,
            kind: storage_sqlite::PublicKeyPackageBarrierKind::Deletion,
        })
        .unwrap();
    let barred = resolve().await;
    assert!(
        matches!(barred, Err(DirectoryError::MissingKeyPackage { .. })),
        "{:?}",
        barred.err()
    );

    // And so does a request selection honors but the journal does not
    // record, because it is dated past the clock-skew allowance.
    let postdated = signed(
        &app,
        bob,
        candidate(
            bob,
            fresh_key_package_for_account(&app, bob, true).await,
            "postdated",
            None,
            unix_now_seconds(),
        ),
    );
    let deletion = signed_deletion(
        &app,
        bob,
        vec![
            vec!["e".into(), postdated.id.clone()],
            vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
        ],
        unix_now_seconds() + 24 * 60 * 60,
    );
    fetcher
        .events_only_in_single_author
        .lock()
        .unwrap()
        .insert(deletion.id.clone());
    *fetcher.events_only_in_multi_author.lock().unwrap() = [postdated.id.clone()].into();
    for events in fetcher.events_by_endpoint.lock().unwrap().values_mut() {
        events.extend([postdated.clone(), deletion.clone()]);
    }
    let unrecorded = resolve().await;
    assert!(
        matches!(unrecorded, Err(DirectoryError::MissingKeyPackage { .. })),
        "{:?}",
        unrecorded.err()
    );
    app.close_storage().unwrap();
}

/// When every relay-list read completes but none returns a list, the lookup
/// cannot confirm the remembered one, and a cold lookup has none to confirm,
/// so the incompatible packages it reads decide nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unconfirmed_remembered_relay_list_decides_no_incompatibility() {
    for remembered in [true, false] {
        let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
        let requirements = retention_requirements(&app).await;
        let directory = app.directory();
        let resolve = || {
            directory.resolve_compatible_member_key_packages(
                vec![bob.account_id_hex.clone()],
                &requirements,
                nostr_directory::MemberResolutionPurpose::Commit,
                nostr_directory::MemberResolutionPolicy::Atomic,
            )
        };
        if remembered {
            let first = resolve().await;
            assert!(
                matches!(first, Err(DirectoryError::KeyPackageRequirements(_))),
                "{:?}",
                first.err()
            );
        }
        for relays in fetcher.events_by_endpoint.lock().unwrap().values_mut() {
            relays.retain(|event| event.kind != KIND_NIP65_RELAY_LIST);
        }
        let result = resolve().await;
        assert!(
            matches!(
                &result,
                Err(DirectoryError::DirectoryLookupIncomplete(account)) if account == &bob.account_id_hex
            ),
            "remembered {remembered}: {:?}",
            result.err()
        );
        app.close_storage().unwrap();
    }
}

/// A prewarm can hold the only known route to a recipient's outbox. When the
/// directory relays stop serving relay lists before the start, the start still
/// reads that outbox for a fresh package.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_start_reads_a_prewarmed_outbox_when_discovery_fails() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .get_mut("wss://directory.example")
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    app.directory()
        .prewarm_group_member_key_packages(&[bob.account_id_hex.as_str()])
        .await
        .unwrap();
    *fetcher.failing_endpoint.lock().unwrap() = Some("wss://directory.example".into());
    *fetcher.failing_endpoint_kind.lock().unwrap() = Some(KIND_NIP65_RELAY_LIST);
    let runtime = MarmotAppRuntime::new(app.clone());
    // Without a message timer, the old outbox's package is compatible.
    let created = runtime
        .start_direct_conversation("alice", &bob.account_id_hex)
        .await
        .unwrap();
    let groups = app.groups("alice").unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].group_id_hex, hex::encode(created.as_slice()));
    runtime.shutdown().await;
    app.close_storage().unwrap();
}

/// A deletion another lookup journals while this one waits on a slow relay
/// still bars the package that relay then returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deletion_journaled_during_the_read_bars_the_package() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let package = fetcher.events_by_endpoint.lock().unwrap()["wss://shared.example"]
        .iter()
        .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
        .unwrap()
        .clone();
    let (entered, release) = fetcher.hold_fetches();
    let lookup = {
        let app = app.clone();
        let bob = bob.account_id_hex.clone();
        tokio::spawn(async move {
            app.directory()
                .resolve_member_key_packages(&[bob.as_str()])
                .await
                .map(|_| ())
        })
    };
    entered.notified().await;
    let now = unix_now_seconds();
    app.shared_storage()
        .unwrap()
        .put_public_key_package_barrier(&storage_sqlite::PublicKeyPackageBarrierRecord {
            account_id_hex: bob.account_id_hex.clone(),
            key_package_id: package.tag_value("d").unwrap().to_owned(),
            event_id_hex: "ab".repeat(32),
            deleted_event_id: Some(package.id.clone()),
            event_created_at: now,
            observed_at: now,
            kind: storage_sqlite::PublicKeyPackageBarrierKind::Deletion,
        })
        .unwrap();
    release.notify_one();
    let result = lookup.await.unwrap();
    assert!(
        matches!(result, Err(DirectoryError::MissingKeyPackage { .. })),
        "{result:?}"
    );
    app.close_storage().unwrap();
}

/// Recovery's supplementary read finds only an incompatible package, which
/// another lookup journals as deleted while that read is in flight. The newer
/// journal evidence bars the package, so the recipient has none rather than
/// an incompatible one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deletion_journaled_during_the_supplementary_read_bars_the_package() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let package = {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        by_endpoint
            .get_mut("wss://shared.example")
            .unwrap()
            .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        by_endpoint["wss://directory.example"]
            .iter()
            .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .unwrap()
            .clone()
    };
    let (mut entered, mut release) = fetcher.hold_fetches();
    let lookup = {
        let app = app.clone();
        let bob = bob.account_id_hex.clone();
        tokio::spawn(async move {
            app.directory()
                .resolve_compatible_member_key_packages(
                    vec![bob],
                    &requirements,
                    nostr_directory::MemberResolutionPurpose::Commit,
                    nostr_directory::MemberResolutionPolicy::Atomic,
                )
                .await
                .map(|_| ())
        })
    };
    // The batch and single-author reads of the outbox find nothing, so
    // recovery's read of the directory relay is the third KeyPackage read.
    for _ in 0..2 {
        entered.notified().await;
        let next = fetcher.hold_fetches();
        release.notify_one();
        (entered, release) = next;
    }
    entered.notified().await;
    let now = unix_now_seconds();
    app.shared_storage()
        .unwrap()
        .put_public_key_package_barrier(&storage_sqlite::PublicKeyPackageBarrierRecord {
            account_id_hex: bob.account_id_hex.clone(),
            key_package_id: package.tag_value("d").unwrap().to_owned(),
            event_id_hex: "ab".repeat(32),
            deleted_event_id: Some(package.id.clone()),
            event_created_at: now,
            observed_at: now,
            kind: storage_sqlite::PublicKeyPackageBarrierKind::Deletion,
        })
        .unwrap();
    release.notify_one();
    let result = lookup.await.unwrap();
    assert!(
        matches!(result, Err(DirectoryError::MissingKeyPackage { .. })),
        "{result:?}"
    );
    app.close_storage().unwrap();
}

/// Recovery finds one device's package in two slots, proves the preferred
/// slot undeleted and sets the other aside. Another lookup journals the
/// preferred slot's deletion while that proof is in flight. The slot set
/// aside was never checked, so the lookup is incomplete rather than empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deletion_journaled_during_the_proof_leaves_an_unproven_alternate() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let package = fresh_key_package_for_account(&app, &bob, false).await;
    let now = unix_now_seconds();
    let preferred = candidate(&bob, package.clone(), "preferred", None, now);
    {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        for relay in ["wss://shared.example", "wss://directory.example"] {
            by_endpoint
                .get_mut(relay)
                .unwrap()
                .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        }
        by_endpoint
            .get_mut("wss://directory.example")
            .unwrap()
            .extend([
                preferred.clone(),
                candidate(&bob, package, "alternate", None, now - 1),
            ]);
    }
    let (mut entered, mut release) = fetcher.hold_fetches();
    let lookup = {
        let app = app.clone();
        let bob = bob.account_id_hex.clone();
        tokio::spawn(async move {
            app.directory()
                .resolve_compatible_member_key_packages(
                    vec![bob],
                    &requirements,
                    nostr_directory::MemberResolutionPurpose::Commit,
                    nostr_directory::MemberResolutionPolicy::Atomic,
                )
                .await
                .map(|_| ())
        })
    };
    // The batch and single-author reads of the outbox find nothing and
    // recovery's read of the directory relay finds both slots, so the
    // deletion proof is the fourth read that asks for deletion requests.
    for read in 0..3 {
        entered.notified().await;
        let next = if read < 2 {
            fetcher.hold_fetches()
        } else {
            fetcher.hold_fetches_for_kind(5)
        };
        release.notify_one();
        (entered, release) = next;
    }
    entered.notified().await;
    app.shared_storage()
        .unwrap()
        .put_public_key_package_barrier(&storage_sqlite::PublicKeyPackageBarrierRecord {
            account_id_hex: bob.account_id_hex.clone(),
            key_package_id: "preferred".into(),
            event_id_hex: "ab".repeat(32),
            deleted_event_id: Some(preferred.id.clone()),
            event_created_at: now,
            observed_at: now,
            kind: storage_sqlite::PublicKeyPackageBarrierKind::Deletion,
        })
        .unwrap();
    release.notify_one();
    let result = lookup.await.unwrap();
    assert!(
        matches!(
            &result,
            Err(DirectoryError::DirectoryLookupIncomplete(account))
                if account == &bob.account_id_hex
        ),
        "{result:?}"
    );
    app.close_storage().unwrap();
}

/// Recovery returns a package from its first read without reading the
/// supplementary relays or any slot's deletion requests. If final selection
/// then loses that package, the incompatibility left behind refuses a slot
/// no deletion read covered, so it is no verdict, whether or not a
/// supplementary relay was skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_early_package_leaves_no_incompatibility_verdict() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let observed = {
        let by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        [UPDATED_DIRECT_OUTBOX, "wss://directory.example"]
            .map(|relay| RelayEventRecord {
                event: by_endpoint[relay]
                    .iter()
                    .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
                    .unwrap()
                    .clone(),
                endpoints: vec![],
            })
            .to_vec()
    };
    for skipped in [None, Some("wss://directory.example")] {
        let result = app
            .directory()
            .recover_then_lose_selection_for_test(
                &bob.account_id_hex,
                observed.clone(),
                Vec::new(),
                true,
                skipped
                    .map(|relay| TransportEndpoint(relay.into()))
                    .into_iter()
                    .collect(),
                &requirements,
            )
            .await;
        assert!(
            matches!(
                &result,
                Err(DirectoryError::DirectoryLookupIncomplete(account))
                    if account == &bob.account_id_hex
            ),
            "{result:?}"
        );
    }
    app.close_storage().unwrap();
}

/// An earlier read returned an incompatible package that no completed read
/// served again, and recovery proved another relay's compatible package
/// undeleted. Losing that package at final selection leaves the earlier one
/// unconfirmed, so the lookup is incomplete rather than empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_proven_package_decides_nothing_beside_an_unserved_hint() {
    let (_dir, app, bob, fetcher) = direct_start_outbox_fixture().await;
    let requirements = retention_requirements(&app).await;
    let hint = RelayEventRecord {
        event: fetcher.events_by_endpoint.lock().unwrap()["wss://directory.example"]
            .iter()
            .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .unwrap()
            .clone(),
        endpoints: vec![],
    };
    let result = app
        .directory()
        .recover_then_lose_selection_for_test(
            &bob.account_id_hex,
            Vec::new(),
            vec![hint],
            true,
            vec![TransportEndpoint(UPDATED_DIRECT_OUTBOX.into())],
            &requirements,
        )
        .await;
    assert!(
        matches!(
            &result,
            Err(DirectoryError::DirectoryLookupIncomplete(account))
                if account == &bob.account_id_hex
        ),
        "{result:?}"
    );
    app.close_storage().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incompatible_slot_is_skipped_for_create_and_invite() {
    let (_dir, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let bob = &accounts[0];
    app.account_home().create_account("alice").unwrap();
    let good = fresh_key_package_for_account(&app, bob, false).await;
    let limited = fresh_key_package_with_components(
        &app,
        bob,
        false,
        app.supported_app_component_ids()
            .into_iter()
            .filter(|id| *id != GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID)
            .collect(),
    )
    .await;
    let white = candidate(
        bob,
        limited,
        "white",
        Some("whitenoise"),
        unix_now_seconds(),
    );
    let fallback = candidate(
        bob,
        good.clone(),
        "other",
        Some("amethyst"),
        unix_now_seconds() - 10,
    );
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher
        .events
        .lock()
        .unwrap()
        .extend([white.clone(), fallback.clone()]);
    retire_journaled_key_packages(&app, bob).await;
    let mut alice = client_on_app_relay_plane(&app, "alice").await;
    let group = alice
        .create_group("compatible creation", &[bob.account_id_hex.as_str()])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    assert_eq!(alice.members(&group).unwrap().len(), 2);
    let empty = alice
        .create_group("compatible invite", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let requirements = alice
        .runtime
        .session()
        .invite_key_package_requirements(&empty)
        .unwrap();
    let reinvite = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![bob.account_id_hex.clone()],
            &requirements,
            nostr_directory::MemberResolutionPurpose::CommitFresh,
            nostr_directory::MemberResolutionPolicy::Atomic,
        )
        .await
        .unwrap();
    assert_eq!(
        hex::encode(
            reinvite.key_packages[0]
                .source
                .as_ref()
                .unwrap()
                .event_id
                .as_slice()
        ),
        fallback.id
    );
    alice
        .invite_members(&empty, &[bob.account_id_hex.as_str()])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    assert_eq!(alice.members(&empty).unwrap().len(), 2);
    // No compatible candidate means no group mutation, even with a newer
    // incompatible slot present.
    let no_fallback = alice
        .create_group("no compatible candidate", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.id != fallback.id);
    // The journal still knows the package the relay dropped, so the lookup
    // is incomplete until a deletion request accounts for it.
    for (deleted, status) in [
        (false, MemberResolutionStatus::Incomplete),
        (true, MemberResolutionStatus::IncompatibleKeyPackage),
    ] {
        if deleted {
            fetcher.events.lock().unwrap().push(signed_deletion(
                &app,
                bob,
                vec![
                    vec!["e".into(), fallback.id.clone()],
                    vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
                ],
                unix_now_seconds(),
            ));
        }
        let result = alice
            .invite_members(&no_fallback, &[bob.account_id_hex.as_str()])
            .await
            .unwrap();
        assert_eq!(result.operation, None);
        assert_eq!(
            result.member_outcomes,
            vec![MemberResolutionOutcome {
                account_id_hex: bob.account_id_hex.clone(),
                status,
                selected_device_count: 0,
            }]
        );
        assert_eq!(alice.members(&no_fallback).unwrap().len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_client_name_is_opt_in_and_signed_retries_keep_original_tags() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let account = app.account_home().create_account("alice").unwrap();
    let package = fresh_key_package_for_account(&app, &account, false).await;
    let publication = KeyPackagePublication {
        account_id: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
        key_package: package,
        slot_id: "slot".into(),
        created_at: Timestamp(unix_now_seconds()),
        endpoints: vec![TransportEndpoint("wss://relay.example".into())],
    };
    let publisher = |app: &MarmotApp| AppKeyPackagePublisher {
        app: app.clone(),
        account_label: account.label.clone(),
        signer: app.account_signer_for_summary(&account).unwrap(),
    };
    let original = publisher(&app)
        .prepare_key_package(publication.clone())
        .await
        .unwrap();
    let original_event: NostrTransportEvent = serde_json::from_slice(&original.bytes).unwrap();
    assert_eq!(original_event.tag_value("client"), None);
    app.config.key_package_client_name = Some("  whitenoise  ".into());
    publisher(&app)
        .publish_prepared_key_package(&publication, &original)
        .await
        .unwrap();
    assert_eq!(
        relay.published_events.lock().unwrap().last().unwrap(),
        &original_event
    );
    let tagged = publisher(&app)
        .prepare_key_package(publication.clone())
        .await
        .unwrap();
    let tagged_event: NostrTransportEvent = serde_json::from_slice(&tagged.bytes).unwrap();
    assert_eq!(tagged_event.tag_value("client"), Some("whitenoise"));
    app.config.key_package_client_name = None;
    publisher(&app)
        .publish_prepared_key_package(&publication, &tagged)
        .await
        .unwrap();
    assert_eq!(
        relay.published_events.lock().unwrap().last().unwrap(),
        &tagged_event
    );
    app.config.key_package_client_name = Some(" \t ".into());
    let blank = publisher(&app)
        .prepare_key_package(publication)
        .await
        .unwrap();
    let blank: NostrTransportEvent = serde_json::from_slice(&blank.bytes).unwrap();
    assert_eq!(blank.tag_value("client"), None);
}

/// MDK 0.8 published neither `app_components` nor a current account proof, so
/// legacy detection must not depend on today's transport tags.
fn mdk_0_8_publication(
    account: &AccountSummary,
    package: KeyPackage,
    slot: &str,
    timestamp: u64,
) -> NostrTransportEvent {
    let event = candidate(account, package, slot, Some("MDK/0.8.0"), timestamp);
    let mut tags = event.tags;
    tags.retain(|tag| tag[0] != "app_components");
    tags.push(vec!["encoding".into(), "base64".into()]);
    NostrTransportEvent::new_unsigned_at(event.pubkey, event.kind, tags, event.content, timestamp)
}

async fn legacy_only_fixture() -> (
    tempfile::TempDir,
    MarmotApp,
    AccountSummary,
    Arc<MemberResolutionDirectoryFetcher>,
) {
    let (dir, app, mut accounts, fetcher) = member_resolution_fixture(1, false).await;
    let account = accounts.remove(0);
    let now = unix_now_seconds();
    let mdk_0_8 = mdk_0_8_publication(
        &account,
        fresh_key_package_for_account(&app, &account, true).await,
        "mdk-0-8",
        now - 20,
    );
    let tagged = candidate(
        &account,
        fresh_key_package_for_account(&app, &account, true).await,
        "tagged-legacy",
        None,
        now - 10,
    );
    let mut events = fetcher.events.lock().unwrap();
    events.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    events.extend([mdk_0_8, tagged]);
    drop(events);
    (dir, app, account, fetcher)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_legacy_only_lookup_reports_obsolete_only() {
    let (_dir, app, account, _fetcher) = legacy_only_fixture().await;
    let error = app
        .directory()
        .resolve_member_key_packages(&[account.account_id_hex.as_str()])
        .await
        .unwrap_err();
    assert!(
        matches!(&error, DirectoryError::MissingKeyPackage { account: id, reason: crate::MissingKeyPackageReason::ObsoleteOnly } if *id == account.account_id_hex),
        "unexpected invite diagnosis: {error:?}"
    );
    assert!(!error.to_string().contains(&account.account_id_hex));

    let error = app
        .directory()
        .fetch_latest_key_package_for_account_id(&account.account_id_hex, Vec::new())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            DirectoryError::MissingKeyPackage {
                reason: crate::MissingKeyPackageReason::ObsoleteOnly,
                ..
            }
        ),
        "directory reads share the diagnosis: {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_legacy_only_lookup_claims_neither_absence_nor_obsolescence() {
    let (_dir, app, account, fetcher) = legacy_only_fixture().await;
    *fetcher.incomplete_endpoint.lock().unwrap() = Some("wss://shared.example".into());
    *fetcher.incomplete_query_kind.lock().unwrap() = Some(KIND_MARMOT_KEY_PACKAGE);
    let error = app
        .directory()
        .resolve_member_key_packages(&[account.account_id_hex.as_str()])
        .await
        .unwrap_err();
    assert!(
        matches!(&error, DirectoryError::DirectoryLookupIncomplete(id) if *id == account.account_id_hex),
        "an incomplete search stays retryable: {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_slots_never_select_or_mask_current_slots() {
    let (_dir, app, accounts, _) = member_resolution_fixture(1, false).await;
    let account = &accounts[0];
    let now = unix_now_seconds();
    let legacy = mdk_0_8_publication(
        account,
        fresh_key_package_for_account(&app, account, true).await,
        "legacy",
        now,
    );
    let current = candidate(
        account,
        fresh_key_package_for_account(&app, account, false).await,
        "current",
        None,
        now - 10,
    );
    let mut malformed = current.clone();
    malformed.content = BASE64_STANDARD.encode(b"not a key package");
    let select = |events: &[&NostrTransportEvent]| select(&app, account, events);

    // A newer legacy slot neither wins nor hides an older current slot.
    let selection = select(&[&legacy, &current]).unwrap();
    assert!(selection.legacy_slots);
    assert_eq!(selection.value.len(), 1);
    assert_eq!(
        selection.value[0].key_package.protocol_profile,
        cgka_traits::group::ProtocolProfile::Current
    );
    // A current slot's rejection outranks the obsolete diagnosis.
    assert!(matches!(
        select(&[&legacy, &malformed]),
        Err(DirectoryError::InvalidKeyPackageEvent(_))
    ));
    // A future-dated slot may be a skewed current publication.
    let mut future = current.clone();
    future.created_at = now + 3_600;
    assert!(matches!(
        select(&[&legacy, &future])
            .unwrap()
            .into_value_or_missing(&account.account_id_hex),
        Err(DirectoryError::MissingKeyPackage {
            reason: crate::MissingKeyPackageReason::NotFound,
            ..
        })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_expired() {
    let (_root, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    app.directory()
        .remember_directory_follow_list_for_test(
            &owner.account_id_hex,
            &nostr_directory::FetchedFollowList {
                follows: vec![accounts[0].account_id_hex.clone()],
                source_relays: Vec::new(),
                created_at: 0,
            },
        )
        .unwrap();
    let expired = package_expiring_at(&app, &accounts[0], unix_now_seconds() - 1, false);
    let mut publication = member_resolution_key_package_event(
        &accounts[0],
        fresh_key_package_for_account(&app, &accounts[0], false).await,
    );
    publication.content = BASE64_STANDARD.encode(expired.bytes());
    publication.id = "ee".repeat(32);
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    fetcher.events.lock().unwrap().push(publication);

    let status = app
        .directory()
        .refresh_follow_availability(&crate::directory_resources::directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(status.ready, 0);
    assert_eq!(status.unknown, 1);
    let page = app
        .directory()
        .follow_availability_page(
            &crate::directory_resources::directory_account(&owner),
            None,
            100,
        )
        .unwrap();
    assert_eq!(
        page.rows[0].state,
        nostr_directory::FollowAvailabilityState::Unknown
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_obsolete_only() {
    let (_root, mut app, account, fetcher) = legacy_only_fixture().await;
    let now = unix_now_seconds();
    let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(now));
    app.directory_test_clock = Some(clock.clone());
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    app.directory()
        .remember_directory_follow_list_for_test(
            &owner.account_id_hex,
            &nostr_directory::FetchedFollowList {
                follows: vec![account.account_id_hex.clone()],
                source_relays: Vec::new(),
                created_at: 0,
            },
        )
        .unwrap();

    let (entered, release) = fetcher.hold_fetches();
    let task_app = app.clone();
    let task_owner = owner.clone();
    let refresh = tokio::spawn(async move {
        task_app
            .directory()
            .refresh_follow_availability(&crate::directory_resources::directory_account(
                &task_owner,
            ))
            .await
    });
    entered.notified().await;
    clock.store(now + 5, std::sync::atomic::Ordering::SeqCst);
    release.notify_one();
    let status = refresh.await.unwrap().unwrap();
    assert_eq!(status.not_found, 1, "{status:?}");
    assert_eq!(
        selection_availability_states(&app, &owner)[&account.account_id_hex],
        nostr_directory::FollowAvailabilityState::NotFound
    );
    let checked_at = app
        .directory()
        .follow_availability_page(
            &crate::directory_resources::directory_account(&owner),
            None,
            100,
        )
        .unwrap()
        .rows[0]
        .checked_at
        .unwrap();
    app.shared_storage()
        .unwrap()
        .put_public_key_package_replacement(&storage_sqlite::PublicKeyPackageReplacementRecord {
            account_id_hex: account.account_id_hex.clone(),
            key_package_id: "later-evidence".into(),
            event_id_hex: "ff".repeat(32),
            event_created_at: now + 6,
            observed_at: checked_at,
        })
        .unwrap();
    assert_eq!(
        selection_availability_states(&app, &owner)[&account.account_id_hex],
        nostr_directory::FollowAvailabilityState::Unknown,
        "evidence written at the completion second invalidates the negative"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_multi_slot() {
    let (_root, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    app.directory()
        .remember_directory_follow_list_for_test(
            &owner.account_id_hex,
            &nostr_directory::FetchedFollowList {
                follows: vec![accounts[0].account_id_hex.clone()],
                source_relays: Vec::new(),
                created_at: 0,
            },
        )
        .unwrap();
    let last_resort = package_expiring_at(&app, &accounts[0], unix_now_seconds() + 3_000, true);
    let mut publication = member_resolution_key_package_event(&accounts[0], last_resort);
    publication.id = "bb".repeat(32);
    let created_at = publication.created_at;
    let publication_id = publication.id.clone();
    fetcher.events.lock().unwrap().push(publication);
    for event in fetcher.events.lock().unwrap().iter_mut() {
        if event.kind == KIND_MARMOT_KEY_PACKAGE
            && event.pubkey == accounts[0].account_id_hex
            && event.id != publication_id
        {
            event.created_at = created_at.saturating_sub(1);
        }
    }

    let selected = {
        let events = fetcher.events.lock().unwrap();
        let publications = events.iter().collect::<Vec<_>>();
        select(&app, &accounts[0], &publications).unwrap()
    };
    assert_eq!(selected.value.len(), 1);

    let status = app
        .directory()
        .refresh_follow_availability(&crate::directory_resources::directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(status.ready, 1, "{status:?}");
    let page = app
        .directory()
        .follow_availability_page(
            &crate::directory_resources::directory_account(&owner),
            None,
            100,
        )
        .unwrap();
    assert_eq!(
        page.rows[0].state,
        nostr_directory::FollowAvailabilityState::Ready,
        "a newer last-resort publication must not hide the preferred slot"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_fenced_first_slot_uses_alternative() {
    let (_root, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    app.directory()
        .remember_directory_follow_list_for_test(
            &owner.account_id_hex,
            &nostr_directory::FetchedFollowList {
                follows: vec![accounts[0].account_id_hex.clone()],
                source_relays: Vec::new(),
                created_at: 0,
            },
        )
        .unwrap();
    let first = fetcher
        .events
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
        .unwrap()
        .clone();
    let mut second = member_resolution_key_package_event(
        &accounts[0],
        device_package(&app, &accounts[0], false),
    );
    second.tags.iter_mut().find(|tag| tag[0] == "d").unwrap()[1] = "second-slot".into();
    let second = EventBuilder::new(
        Kind::Custom(KIND_MARMOT_KEY_PACKAGE as u16),
        second.content.clone(),
    )
    .tags(second.tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
    .custom_created_at(NostrTimestamp::from_secs(
        first.created_at.saturating_sub(1),
    ))
    .finalize(
        &app.account_home()
            .load_signing_keys(&accounts[0].label)
            .unwrap(),
    )
    .unwrap();
    let second = NostrTransportEvent::from_nostr_event(&second).unwrap();
    let second_id = second.id.clone();
    fetcher.events.lock().unwrap().push(second);
    let now = unix_now_seconds();
    app.shared_storage()
        .unwrap()
        .put_public_key_package_replacement(&storage_sqlite::PublicKeyPackageReplacementRecord {
            account_id_hex: accounts[0].account_id_hex.clone(),
            key_package_id: first.tag_value("d").unwrap().to_owned(),
            event_id_hex: "ff".repeat(32),
            event_created_at: now + 100,
            observed_at: now,
        })
        .unwrap();

    let status = app
        .directory()
        .refresh_follow_availability(&crate::directory_resources::directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(status.ready, 1, "{status:?}");
    let page = app
        .directory()
        .follow_availability_page(
            &crate::directory_resources::directory_account(&owner),
            None,
            100,
        )
        .unwrap();
    assert_eq!(
        page.rows[0].state,
        nostr_directory::FollowAvailabilityState::Ready
    );
    assert_eq!(
        page.rows[0].key_package_event_id.as_deref(),
        Some(second_id.as_str())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_recovery_stays_bounded() {
    let (_root, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    app.directory()
        .remember_directory_follow_list_for_test(
            &owner.account_id_hex,
            &nostr_directory::FetchedFollowList {
                follows: vec![accounts[0].account_id_hex.clone()],
                source_relays: Vec::new(),
                created_at: 0,
            },
        )
        .unwrap();

    let omitted = fetcher
        .events
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
        .unwrap()
        .clone();
    for event in fetcher.events.lock().unwrap().iter_mut() {
        if event.kind == transport_nostr_adapter::KIND_NIP65_RELAY_LIST
            && event.pubkey == accounts[0].account_id_hex
        {
            event.tags = (0..20)
                .map(|index| vec!["r".into(), format!("wss://outbox-{index}.example")])
                .collect();
        }
    }
    let relay_list = fetcher
        .events
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.kind == transport_nostr_adapter::KIND_NIP65_RELAY_LIST)
        .unwrap()
        .clone();
    fetcher.events.lock().unwrap().retain(|event| {
        event.kind != KIND_MARMOT_KEY_PACKAGE
            && event.kind != transport_nostr_adapter::KIND_NIP65_RELAY_LIST
    });
    {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        by_endpoint.insert("wss://directory.example".into(), vec![relay_list]);
        for index in 0..4 {
            by_endpoint.insert(format!("wss://outbox-{index}.example"), Vec::new());
        }
        by_endpoint.insert("wss://outbox-4.example".into(), vec![omitted]);
    }

    let status = app
        .directory()
        .refresh_follow_availability(&crate::directory_resources::directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(status.unknown, 1, "{status:?}");
    assert_eq!(status.not_found, 0, "{status:?}");
    let requests = fetcher.requests.lock().unwrap();
    assert!(requests.len() <= 2, "{}", requests.len());
    assert!(
        requests.iter().all(|request| request.endpoints.len()
            <= nostr_directory::MAX_FOLLOW_AVAILABILITY_RELAYS_PER_TARGET),
        "recovery must not widen the per-target relay set"
    );
    drop(requests);

    let page = app
        .directory()
        .follow_availability_page(
            &crate::directory_resources::directory_account(&owner),
            None,
            100,
        )
        .unwrap();
    assert_eq!(
        page.rows[0].state,
        nostr_directory::FollowAvailabilityState::Unknown,
        "a package on an omitted relay cannot support a clean negative"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_discovery_is_bounded() {
    let (_root, app, accounts, fetcher) = member_resolution_fixture_with_relays(
        1,
        false,
        (0..5)
            .map(|index| format!("wss://directory-{index}.example"))
            .collect(),
    )
    .await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    app.directory()
        .remember_directory_follow_list_for_test(
            &owner.account_id_hex,
            &nostr_directory::FetchedFollowList {
                follows: vec![accounts[0].account_id_hex.clone()],
                source_relays: Vec::new(),
                created_at: 0,
            },
        )
        .unwrap();
    let status = app
        .directory()
        .refresh_follow_availability(&crate::directory_resources::directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(status.ready, 1, "{status:?}");
    let requests = fetcher.requests.lock().unwrap();
    assert!(requests.iter().any(|request| {
        request
            .queries
            .iter()
            .any(|query| query.kind == transport_nostr_adapter::KIND_NIP65_RELAY_LIST)
    }));
    assert!(
        requests.iter().all(|request| request.endpoints.len()
            <= nostr_directory::MAX_FOLLOW_AVAILABILITY_RELAYS_PER_TARGET),
        "discovery must be bounded before its first fetch"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_unusable_cached_route_rediscovers() {
    let (_root, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    let account = &accounts[0];
    let mut relay_list = fetcher
        .events
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.kind == transport_nostr_adapter::KIND_NIP65_RELAY_LIST)
        .unwrap()
        .clone();
    relay_list.tags = vec![vec!["r".into(), "ws://127.0.0.1:9999".into()]];
    let package = fetcher
        .events
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
        .unwrap()
        .clone();
    *fetcher.events.lock().unwrap() = vec![relay_list.clone()];
    app.directory()
        .fetch_account_relay_list_status_for_account_id(&account.account_id_hex, Vec::new())
        .await
        .unwrap();

    relay_list.created_at += 1;
    relay_list.tags = vec![vec!["r".into(), "wss://usable.example".into()]];
    {
        let mut by_endpoint = fetcher.events_by_endpoint.lock().unwrap();
        by_endpoint.insert("wss://directory.example".into(), vec![relay_list]);
        by_endpoint.insert("wss://usable.example".into(), vec![package]);
    }
    app.directory()
        .remember_directory_follow_list_for_test(
            &owner.account_id_hex,
            &nostr_directory::FetchedFollowList {
                follows: vec![account.account_id_hex.clone()],
                source_relays: Vec::new(),
                created_at: 0,
            },
        )
        .unwrap();
    let status = app
        .directory()
        .refresh_follow_availability(&crate::directory_resources::directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(status.ready, 1, "{status:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_live_deletions_are_fenced() {
    let (_root, app, accounts, _fetcher) = member_resolution_fixture(2, false).await;
    let owner = app
        .account_home()
        .create_account("availability-live-delete-owner")
        .unwrap();
    app.directory()
        .remember_directory_follow_list_for_test(
            &owner.account_id_hex,
            &nostr_directory::FetchedFollowList {
                follows: accounts
                    .iter()
                    .map(|account| account.account_id_hex.clone())
                    .collect(),
                source_relays: Vec::new(),
                created_at: 0,
            },
        )
        .unwrap();
    app.directory()
        .refresh_follow_availability(&crate::directory_resources::directory_account(&owner))
        .await
        .unwrap();
    let rows = app
        .directory()
        .follow_availability_page(
            &crate::directory_resources::directory_account(&owner),
            None,
            100,
        )
        .unwrap()
        .rows;
    let selected = |index: usize| {
        rows.iter()
            .find(|row| row.account_id_hex == accounts[index].account_id_hex)
            .unwrap()
            .key_package_event_id
            .clone()
            .unwrap()
    };
    let event_deletion = signed_deletion(
        &app,
        &accounts[0],
        vec![vec!["e".into(), selected(0).to_ascii_uppercase()]],
        unix_now_seconds() + 10,
    );
    let address_deletion = signed_deletion(
        &app,
        &accounts[1],
        vec![vec![
            "a".into(),
            format!(
                "30443:{}:{}-slot",
                accounts[1].account_id_hex.to_ascii_uppercase(),
                accounts[1].label
            ),
        ]],
        unix_now_seconds() + 11,
    );
    for deletion in [event_deletion, address_deletion] {
        app.directory()
            .ingest_directory_relay_event(transport_nostr::DirectoryRelayEventRecord {
                endpoints: Vec::new(),
                event: deletion,
            })
            .unwrap();
    }
    let states = selection_availability_states(&app, &owner);
    for account in accounts {
        assert_eq!(
            states[&account.account_id_hex],
            nostr_directory::FollowAvailabilityState::Unknown
        );
    }
}

#[tokio::test]
async fn availability_deleted_stays_not_found() {
    let (_root, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    app.directory()
        .remember_directory_follow_list_for_test(
            &owner.account_id_hex,
            &nostr_directory::FetchedFollowList {
                follows: vec![accounts[0].account_id_hex.clone()],
                source_relays: Vec::new(),
                created_at: 0,
            },
        )
        .unwrap();
    app.directory()
        .refresh_follow_availability(&crate::directory_resources::directory_account(&owner))
        .await
        .unwrap();

    let selected = app
        .directory()
        .follow_availability_page(
            &crate::directory_resources::directory_account(&owner),
            None,
            100,
        )
        .unwrap()
        .rows[0]
        .key_package_event_id
        .clone()
        .unwrap();
    let deletion = signed_deletion(
        &app,
        &accounts[0],
        vec![
            vec!["e".into(), selected.clone()],
            vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
        ],
        unix_now_seconds() + 10,
    );
    fetcher.events.lock().unwrap().push(deletion.clone());
    app.directory()
        .reset_availability_for_test(&owner.account_id_hex);
    app.directory()
        .refresh_follow_availability(&crate::directory_resources::directory_account(&owner))
        .await
        .unwrap();
    let shared_revision = app
        .shared_storage()
        .unwrap()
        .key_package_evidence_revision(&accounts[0].account_id_hex)
        .unwrap();
    let stored_revision = app
        .directory()
        .availability_evidence_revision_for_test(
            &crate::directory_resources::directory_account(&owner),
            &accounts[0].account_id_hex,
        )
        .unwrap();
    assert_eq!(stored_revision, shared_revision);
    assert_eq!(
        selection_availability_states(&app, &owner)[&accounts[0].account_id_hex],
        nostr_directory::FollowAvailabilityState::NotFound
    );

    app.directory()
        .ingest_directory_relay_event(transport_nostr::DirectoryRelayEventRecord {
            endpoints: Vec::new(),
            event: deletion.clone(),
        })
        .unwrap();
    assert_eq!(
        selection_availability_states(&app, &owner)[&accounts[0].account_id_hex],
        nostr_directory::FollowAvailabilityState::NotFound,
        "replaying the same deletion must not invalidate the negative"
    );

    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.id != deletion.id);
    app.drop_account_caches(&owner.label);
    app.directory()
        .reset_availability_for_test(&owner.account_id_hex);
    app.directory()
        .refresh_follow_availability(&crate::directory_resources::directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(
        selection_availability_states(&app, &owner)[&accounts[0].account_id_hex],
        nostr_directory::FollowAvailabilityState::Unknown,
        "a stale relay cannot resurrect a deleted package"
    );
}
