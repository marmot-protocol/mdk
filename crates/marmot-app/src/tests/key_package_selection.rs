use super::invite_recovery::package_expiring_at;
use super::*;
use crate::key_package_records::select_key_packages_from_records;
use nostr_directory::{KEY_PACKAGE_FRESHNESS, KeyPackageSelection, MAX_KEY_PACKAGES_PER_ACCOUNT};

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
                    .key_packages_only_in_single_author
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
        let group = inviter.create_group("refetch failures", &[]).await.unwrap();
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
                "absent" => assert!(matches!(
                    error,
                    DirectoryError::DirectoryLookupIncomplete(_)
                )),
                "malformed" => assert!(matches!(error, DirectoryError::InvalidKeyPackageEvent(_))),
                "incompatible" => assert!(matches!(
                    error,
                    DirectoryError::KeyPackageRequirements(
                        cgka_traits::EngineError::MissingRequiredCapabilities { .. }
                    )
                )),
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
            .key_packages_only_in_single_author
            .lock()
            .unwrap()
            .insert(old.id.clone());
        fetcher
            .key_packages_only_in_multi_author
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
    let mut alice = client_on_app_relay_plane(&app, "alice").await;
    let group = alice
        .create_group("compatible creation", &[bob.account_id_hex.as_str()])
        .await
        .unwrap();
    assert_eq!(alice.members(&group).unwrap().len(), 2);
    let empty = alice.create_group("compatible invite", &[]).await.unwrap();
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
        .unwrap();
    assert_eq!(alice.members(&empty).unwrap().len(), 2);
    // No compatible candidate means no group mutation, even with a newer
    // incompatible slot present.
    let no_fallback = alice
        .create_group("no compatible candidate", &[])
        .await
        .unwrap();
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.id != fallback.id);
    assert!(
        alice
            .invite_members(&no_fallback, &[bob.account_id_hex.as_str()])
            .await
            .is_err()
    );
    assert_eq!(alice.members(&no_fallback).unwrap().len(), 1);
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
