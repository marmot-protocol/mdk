//! Direct-follow availability over the real app cache and scripted relay plane.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use marmot_account::AccountSummary;
use nostr_directory::{
    FetchedFollowList, FollowAvailabilityRefreshPhase, FollowAvailabilityState,
    MAX_FOLLOW_AVAILABILITY_RELAY_FETCHES, MAX_FOLLOW_AVAILABILITY_TARGETS,
};
use nostr_sdk::prelude::FinalizeEvent;
use transport_nostr_adapter::{KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST};

use crate::MarmotApp;
use crate::directory_resources::directory_account;

fn remember_follows(app: &MarmotApp, owner: &AccountSummary, follows: Vec<String>) {
    app.directory()
        .remember_directory_follow_list_for_test(
            &owner.account_id_hex,
            &FetchedFollowList {
                follows,
                source_relays: Vec::new(),
                created_at: 0,
            },
        )
        .unwrap();
}

fn availability_states(
    app: &MarmotApp,
    owner: &AccountSummary,
) -> BTreeMap<String, FollowAvailabilityState> {
    app.directory()
        .follow_availability_page(&directory_account(owner), None, 100)
        .unwrap()
        .rows
        .into_iter()
        .map(|row| (row.account_id_hex, row.state))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_mixed_outcomes() {
    let (_root, mut app, accounts, fetcher) =
        crate::tests::member_resolution_fixture(4, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    remember_follows(
        &app,
        &owner,
        accounts
            .iter()
            .map(|account| account.account_id_hex.clone())
            .collect(),
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    app.directory_test_clock = Some(Arc::new(std::sync::atomic::AtomicU64::new(now)));

    for event in fetcher.events.lock().unwrap().iter_mut() {
        if event.kind == KIND_NIP65_RELAY_LIST && event.pubkey == accounts[0].account_id_hex {
            event.tags = (0..20)
                .map(|index| vec!["r".into(), format!("wss://outbox-{index}.example")])
                .collect();
        }
    }

    let missing_publication = {
        let mut events = fetcher.events.lock().unwrap();
        let publication = events
            .iter()
            .find(|event| {
                event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == accounts[1].account_id_hex
            })
            .unwrap()
            .clone();
        events.retain(|event| {
            !(event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == accounts[1].account_id_hex)
        });
        events
            .iter_mut()
            .find(|event| {
                event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == accounts[3].account_id_hex
            })
            .unwrap()
            .content = "not-base64".into();
        publication
    };
    *fetcher.failing_single_author.lock().unwrap() = Some(accounts[2].account_id_hex.clone());

    let status = app
        .directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(status.phase, FollowAvailabilityRefreshPhase::Partial);
    assert_eq!(status.total, 4);
    assert_eq!(status.completed, 4);
    assert_eq!(status.ready, 1);
    assert_eq!(status.not_found, 1);
    assert_eq!(status.unknown, 2);
    assert_eq!(status.failed, 2);
    assert!(!status.truncated);
    assert_eq!(
        availability_states(&app, &owner)[&accounts[0].account_id_hex],
        FollowAvailabilityState::Ready
    );
    assert_eq!(
        availability_states(&app, &owner)[&accounts[1].account_id_hex],
        FollowAvailabilityState::NotFound
    );
    assert_eq!(
        availability_states(&app, &owner)[&accounts[2].account_id_hex],
        FollowAvailabilityState::Unknown
    );
    assert_eq!(
        availability_states(&app, &owner)[&accounts[3].account_id_hex],
        FollowAvailabilityState::Unknown
    );
    assert!(
        fetcher.requests.lock().unwrap().len()
            <= nostr_directory::MAX_FOLLOW_AVAILABILITY_RELAY_FETCHES
    );
    assert!(
        fetcher.requests.lock().unwrap().len() <= 4 * 2,
        "each target needs at most relay-list and primary KeyPackage reads"
    );
    assert!(
        fetcher
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.endpoints.len()
                <= nostr_directory::MAX_FOLLOW_AVAILABILITY_RELAYS_PER_TARGET),
        "advertised relay fan-out must stay within the per-target bound"
    );
    let negative = app
        .directory()
        .follow_availability_page(&directory_account(&owner), None, 100)
        .unwrap()
        .rows
        .into_iter()
        .find(|row| row.account_id_hex == accounts[1].account_id_hex)
        .unwrap();
    assert_eq!(negative.checked_at, Some(now));
    assert_eq!(
        negative.fresh_until,
        Some(now + nostr_directory::FOLLOW_AVAILABILITY_NEGATIVE_TTL.as_secs())
    );

    let request_count = fetcher.requests.lock().unwrap().len();
    let throttled = app
        .directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(throttled.phase, FollowAvailabilityRefreshPhase::Throttled);
    assert_eq!(fetcher.requests.lock().unwrap().len(), request_count);

    fetcher.events.lock().unwrap().push(missing_publication);
    app.directory()
        .reset_availability_for_test(&owner.account_id_hex);
    let refreshed = app
        .directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(refreshed.ready, 2);
    assert_eq!(refreshed.not_found, 0);
    assert_eq!(
        availability_states(&app, &owner)[&accounts[1].account_id_hex],
        FollowAvailabilityState::Ready
    );

    let replacement = {
        let mut events = fetcher.events.lock().unwrap();
        let mut replacement = events
            .iter()
            .find(|event| {
                event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == accounts[0].account_id_hex
            })
            .unwrap()
            .clone();
        replacement.id = "ff".repeat(32);
        replacement.created_at = replacement.created_at.saturating_add(1);
        replacement.content = "not-base64".into();
        let signed = nostr_sdk::prelude::EventBuilder::new(
            nostr_sdk::prelude::Kind::from(replacement.kind as u16),
            replacement.content.clone(),
        )
        .tags(
            replacement
                .tags
                .iter()
                .map(|tag| nostr_sdk::prelude::Tag::parse(tag.clone()).unwrap()),
        )
        .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(
            replacement.created_at,
        ))
        .finalize(
            &app.account_home()
                .load_signing_keys(&accounts[0].label)
                .unwrap(),
        )
        .unwrap();
        let replacement =
            transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&signed).unwrap();
        events.push(replacement.clone());
        replacement
    };
    let replacement_created_at = replacement.created_at;
    let error = app
        .directory()
        .ingest_directory_relay_event(transport_nostr::DirectoryRelayEventRecord {
            endpoints: Vec::new(),
            event: replacement,
        })
        .unwrap_err();
    assert!(matches!(
        error,
        nostr_directory::error::DirectoryError::InvalidKeyPackageEvent(_)
    ));
    assert_eq!(
        availability_states(&app, &owner)[&accounts[0].account_id_hex],
        FollowAvailabilityState::Unknown,
        "live replacement invalidates the previous ready row"
    );
    app.directory()
        .reset_availability_for_test(&owner.account_id_hex);
    app.directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(
        availability_states(&app, &owner)[&accounts[0].account_id_hex],
        FollowAvailabilityState::Unknown,
        "a malformed replacement must suppress the previously ready slot"
    );
    fetcher.events.lock().unwrap().retain(|event| {
        !(event.kind == KIND_MARMOT_KEY_PACKAGE
            && event.pubkey == accounts[0].account_id_hex
            && event.created_at == replacement_created_at)
    });
    app.directory()
        .reset_availability_for_test(&owner.account_id_hex);
    app.directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(
        availability_states(&app, &owner)[&accounts[0].account_id_hex],
        FollowAvailabilityState::Unknown,
        "a stale relay cannot resurrect the superseded package"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_replacement_fence() {
    let (_root, app, accounts, fetcher) = crate::tests::member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    remember_follows(&app, &owner, vec![accounts[0].account_id_hex.clone()]);
    app.directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(
        availability_states(&app, &owner)[&accounts[0].account_id_hex],
        FollowAvailabilityState::Ready
    );

    app.directory()
        .reset_availability_for_test(&owner.account_id_hex);
    let (entered, release) = fetcher.hold_fetches();
    let task_app = app.clone();
    let task_owner = owner.clone();
    let refresh = tokio::spawn(async move {
        task_app
            .directory()
            .refresh_follow_availability(&directory_account(&task_owner))
            .await
    });
    entered.notified().await;

    let replacement = {
        let mut replacement = fetcher
            .events
            .lock()
            .unwrap()
            .iter()
            .find(|event| {
                event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == accounts[0].account_id_hex
            })
            .unwrap()
            .clone();
        replacement.id = "ff".repeat(32);
        replacement.created_at = replacement.created_at.saturating_add(1);
        replacement.content = "not-base64".into();
        let signed = nostr_sdk::prelude::EventBuilder::new(
            nostr_sdk::prelude::Kind::from(replacement.kind as u16),
            replacement.content.clone(),
        )
        .tags(
            replacement
                .tags
                .iter()
                .map(|tag| nostr_sdk::prelude::Tag::parse(tag.clone()).unwrap()),
        )
        .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(
            replacement.created_at,
        ))
        .finalize(
            &app.account_home()
                .load_signing_keys(&accounts[0].label)
                .unwrap(),
        )
        .unwrap();
        transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&signed).unwrap()
    };
    assert!(
        app.directory()
            .ingest_directory_relay_event(transport_nostr::DirectoryRelayEventRecord {
                endpoints: Vec::new(),
                event: replacement,
            })
            .is_err()
    );
    release.notify_one();
    let status = refresh.await.unwrap().unwrap();
    assert_eq!(status.ready, 0, "{status:?}");
    assert_eq!(
        availability_states(&app, &owner)[&accounts[0].account_id_hex],
        FollowAvailabilityState::Unknown,
        "a refresh cannot overwrite a replacement received during its fetch"
    );

    fetcher.incomplete_key_packages();
    for _ in 0..2 {
        app.directory()
            .reset_availability_for_test(&owner.account_id_hex);
        app.directory()
            .refresh_follow_availability(&directory_account(&owner))
            .await
            .unwrap();
        assert_eq!(
            availability_states(&app, &owner)[&accounts[0].account_id_hex],
            FollowAvailabilityState::Unknown,
            "an incomplete read must preserve the replacement barrier"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_fetched_malformed_is_journaled() {
    let (_root, app, accounts, fetcher) = crate::tests::member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    remember_follows(&app, &owner, vec![accounts[0].account_id_hex.clone()]);
    let replacement = {
        let mut replacement = fetcher
            .events
            .lock()
            .unwrap()
            .iter()
            .find(|event| {
                event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == accounts[0].account_id_hex
            })
            .unwrap()
            .clone();
        replacement.id = "ff".repeat(32);
        replacement.created_at = replacement.created_at.saturating_add(1);
        replacement.content = "not-base64".into();
        let signed = nostr_sdk::prelude::EventBuilder::new(
            nostr_sdk::prelude::Kind::from(replacement.kind as u16),
            replacement.content.clone(),
        )
        .tags(
            replacement
                .tags
                .iter()
                .map(|tag| nostr_sdk::prelude::Tag::parse(tag.clone()).unwrap()),
        )
        .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(
            replacement.created_at,
        ))
        .finalize(
            &app.account_home()
                .load_signing_keys(&accounts[0].label)
                .unwrap(),
        )
        .unwrap();
        transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&signed).unwrap()
    };
    fetcher.events.lock().unwrap().push(replacement.clone());

    app.directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(
        availability_states(&app, &owner)[&accounts[0].account_id_hex],
        FollowAvailabilityState::Unknown
    );
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.id != replacement.id);
    app.drop_account_caches(&owner.label);
    app.directory()
        .reset_availability_for_test(&owner.account_id_hex);
    app.directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(
        availability_states(&app, &owner)[&accounts[0].account_id_hex],
        FollowAvailabilityState::Unknown,
        "an older relay cannot resurrect a fetched malformed replacement"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_cancel_fence() {
    let (_root, app, accounts, fetcher) = crate::tests::member_resolution_fixture(2, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    remember_follows(
        &app,
        &owner,
        accounts
            .iter()
            .map(|account| account.account_id_hex.clone())
            .collect(),
    );
    let (entered, release) = fetcher.hold_fetches();
    let task_app = app.clone();
    let task_owner = owner.clone();
    let refresh = tokio::spawn(async move {
        task_app
            .directory()
            .refresh_follow_availability(&directory_account(&task_owner))
            .await
    });
    entered.notified().await;
    let running = app
        .directory()
        .follow_availability_status(&owner.account_id_hex);
    assert_eq!(running.phase, FollowAvailabilityRefreshPhase::Running);
    let operation_id = running.operation_id.unwrap();
    assert!(
        !app.directory()
            .cancel_follow_availability(&owner.account_id_hex, operation_id + 1)
    );
    assert!(
        app.directory()
            .cancel_follow_availability(&owner.account_id_hex, operation_id)
    );
    let cancelled = refresh.await.unwrap().unwrap();
    assert_eq!(cancelled.phase, FollowAvailabilityRefreshPhase::Cancelled);
    release.notify_one();
    assert!(cancelled.completed <= 1);
    assert!(
        !app.directory()
            .cancel_follow_availability(&owner.account_id_hex, operation_id)
    );
    let states = availability_states(&app, &owner);
    assert_eq!(states.len(), 2);
    if cancelled.completed == 0 {
        assert!(
            states
                .values()
                .all(|state| *state == FollowAvailabilityState::Unknown)
        );
    } else {
        assert_eq!(
            states
                .values()
                .filter(|state| **state == FollowAvailabilityState::Ready)
                .count(),
            1,
            "a result committed before cancellation stays readable"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_detached_wait() {
    let (_root, app, accounts, fetcher) = crate::tests::member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    remember_follows(&app, &owner, vec![accounts[0].account_id_hex.clone()]);
    let (entered, release) = fetcher.hold_fetches();
    let task_app = app.clone();
    let task_owner = owner.clone();
    let leader = tokio::spawn(async move {
        task_app
            .directory()
            .refresh_follow_availability(&directory_account(&task_owner))
            .await
    });
    entered.notified().await;
    let admitted = app.directory().notify_availability_admission_for_test();
    let follower_app = app.clone();
    let follower_owner = owner.clone();
    let follower = tokio::spawn(async move {
        follower_app
            .directory()
            .refresh_follow_availability(&directory_account(&follower_owner))
            .await
    });
    admitted.notified().await;
    leader.abort();
    assert!(leader.await.unwrap_err().is_cancelled());
    release.notify_one();
    let status = follower.await.unwrap().unwrap();
    assert_eq!(
        status.phase,
        FollowAvailabilityRefreshPhase::Complete,
        "{status:?}"
    );
    assert_eq!(status.ready, 1);
    assert_eq!(
        availability_states(&app, &owner)[&accounts[0].account_id_hex],
        FollowAvailabilityState::Ready
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_cancel_early() {
    let (_root, app, accounts, fetcher) = crate::tests::member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    remember_follows(&app, &owner, vec![accounts[0].account_id_hex.clone()]);
    let (entered, release) = fetcher.hold_fetches();
    let task_app = app.clone();
    let task_owner = owner.clone();
    let refresh = tokio::spawn(async move {
        task_app
            .directory()
            .refresh_follow_availability(&directory_account(&task_owner))
            .await
    });
    entered.notified().await;
    let operation_id = app
        .directory()
        .follow_availability_status(&owner.account_id_hex)
        .operation_id
        .unwrap();
    assert!(
        app.directory()
            .cancel_follow_availability(&owner.account_id_hex, operation_id)
    );
    let cancelled = refresh.await.unwrap().unwrap();
    assert_eq!(cancelled.phase, FollowAvailabilityRefreshPhase::Cancelled);
    release.notify_one();
    assert!(!fetcher.requests.lock().unwrap().is_empty());

    let retried = app
        .directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_ne!(retried.phase, FollowAvailabilityRefreshPhase::Throttled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_bounds() {
    let (_root, app, _accounts, fetcher) = crate::tests::member_resolution_fixture(0, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    let follows = (1..=(MAX_FOLLOW_AVAILABILITY_TARGETS + 1))
        .map(|index| format!("{index:064x}"))
        .collect::<Vec<_>>();
    remember_follows(&app, &owner, follows);

    let status = app
        .directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(status.phase, FollowAvailabilityRefreshPhase::Partial);
    assert_eq!(status.total, MAX_FOLLOW_AVAILABILITY_TARGETS as u32);
    assert_eq!(status.completed, MAX_FOLLOW_AVAILABILITY_TARGETS as u32);
    assert_eq!(status.unknown, MAX_FOLLOW_AVAILABILITY_TARGETS as u32);
    assert!(status.truncated);
    assert!(fetcher.requests.lock().unwrap().len() <= MAX_FOLLOW_AVAILABILITY_RELAY_FETCHES);

    let first = app
        .directory()
        .follow_availability_page(&directory_account(&owner), None, usize::MAX)
        .unwrap();
    assert_eq!(first.rows.len(), MAX_FOLLOW_AVAILABILITY_TARGETS);
    assert!(first.rows.iter().all(|row| row.checked_at.is_some()));
    let second = app
        .directory()
        .follow_availability_page(
            &directory_account(&owner),
            first.next_cursor.as_deref(),
            100,
        )
        .unwrap();
    assert_eq!(second.rows.len(), 1);
    assert_eq!(second.rows[0].state, FollowAvailabilityState::Unknown);
    assert_eq!(second.next_cursor, None);
    app.directory()
        .reset_availability_for_test(&owner.account_id_hex);
    let remaining = app
        .directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(remaining.total, MAX_FOLLOW_AVAILABILITY_TARGETS as u32);
    assert_eq!(remaining.unknown, MAX_FOLLOW_AVAILABILITY_TARGETS as u32);
    let remaining_page = app
        .directory()
        .follow_availability_page(
            &directory_account(&owner),
            first.next_cursor.as_deref(),
            100,
        )
        .unwrap();
    assert!(remaining_page.rows[0].checked_at.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_shared_replacement() {
    let (_root, app, accounts, _fetcher) = crate::tests::member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    let followed = accounts[0].account_id_hex.clone();
    remember_follows(&app, &owner, vec![followed.clone()]);
    app.directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(
        availability_states(&app, &owner)[&followed],
        FollowAvailabilityState::Ready
    );

    let shared = app.shared_storage().unwrap();
    let mut record = shared.public_directory_user(&followed).unwrap().unwrap();
    let mut package: nostr_directory::DirectoryKeyPackage =
        serde_json::from_str(record.key_package_json.as_deref().unwrap()).unwrap();
    let selected_slot = package.key_package_id.clone();
    package.created_at += 1;
    package.key_package_event_id = "ff".repeat(32);
    record.key_package_json = Some(serde_json::to_string(&package).unwrap());
    shared.put_public_directory_user(&record).unwrap();
    app.drop_account_caches(&owner.label);
    assert_eq!(
        availability_states(&app, &owner)[&followed],
        FollowAvailabilityState::Unknown,
        "a newer shared publication suppresses a stale local ready row"
    );

    package.key_package_id = "other-slot".into();
    record.key_package_json = Some(serde_json::to_string(&package).unwrap());
    shared.put_public_directory_user(&record).unwrap();
    app.drop_account_caches(&owner.label);
    assert_eq!(
        availability_states(&app, &owner)[&followed],
        FollowAvailabilityState::Ready,
        "a shared publication in another slot does not suppress ready"
    );

    shared
        .put_public_key_package_replacement(&storage_sqlite::PublicKeyPackageReplacementRecord {
            account_id_hex: followed.clone(),
            key_package_id: "unrelated-slot".into(),
            event_id_hex: "ee".repeat(32),
            event_created_at: package.created_at + 100,
            observed_at: package.created_at + 100,
        })
        .unwrap();
    app.drop_account_caches(&owner.label);
    assert_eq!(
        availability_states(&app, &owner)[&followed],
        FollowAvailabilityState::Ready,
        "a replacement in another slot does not suppress ready"
    );

    shared
        .put_public_key_package_replacement(&storage_sqlite::PublicKeyPackageReplacementRecord {
            account_id_hex: followed.clone(),
            key_package_id: selected_slot,
            event_id_hex: "dd".repeat(32),
            event_created_at: package.created_at + 100,
            observed_at: package.created_at + 100,
        })
        .unwrap();
    app.drop_account_caches(&owner.label);
    assert_eq!(
        availability_states(&app, &owner)[&followed],
        FollowAvailabilityState::Unknown,
        "journal-only malformed replacements survive cache eviction"
    );
    for index in 0..500_u64 {
        shared
            .put_public_key_package_replacement(
                &storage_sqlite::PublicKeyPackageReplacementRecord {
                    account_id_hex: followed.clone(),
                    key_package_id: format!("later-{index:04}"),
                    event_id_hex: format!("{index:064x}"),
                    event_created_at: package.created_at + 200 + index,
                    observed_at: package.created_at + 200 + index,
                },
            )
            .unwrap();
    }
    app.drop_account_caches(&owner.label);
    assert_eq!(
        availability_states(&app, &owner)[&followed],
        FollowAvailabilityState::Unknown,
        "cap eviction cannot resurrect a ready row whose barrier was evicted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_live_replacement_survives_pruning() {
    let (_root, mut app, accounts, _fetcher) =
        crate::tests::member_resolution_fixture(1, false).await;
    let owner = app
        .account_home()
        .create_account("availability-owner")
        .unwrap();
    let followed = accounts[0].account_id_hex.clone();
    remember_follows(&app, &owner, vec![followed.clone()]);
    let now = crate::unix_now_seconds();
    let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(now - 1));
    app.directory_test_clock = Some(clock.clone());
    app.directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert_eq!(
        availability_states(&app, &owner)[&followed],
        FollowAvailabilityState::Ready
    );

    let selected = app
        .directory()
        .follow_availability_page(&directory_account(&owner), None, 100)
        .unwrap()
        .rows[0]
        .key_package_event_id
        .clone()
        .unwrap();
    let shared = app.shared_storage().unwrap();
    // Time the replacements from the selected publication, not the wall
    // clock: the first one, pruned into the eviction watermark, must stay
    // older than it even when a second passed since it was made.
    let selected_created_at = serde_json::from_str::<nostr_directory::DirectoryKeyPackage>(
        shared
            .public_directory_user(&followed)
            .unwrap()
            .unwrap()
            .key_package_json
            .as_deref()
            .unwrap(),
    )
    .unwrap()
    .created_at;
    for index in 0..500_u64 {
        shared
            .put_public_key_package_replacement(
                &storage_sqlite::PublicKeyPackageReplacementRecord {
                    account_id_hex: followed.clone(),
                    key_package_id: format!("later-{index:04}"),
                    event_id_hex: format!("{index:064x}"),
                    event_created_at: selected_created_at.saturating_sub(1).saturating_add(index),
                    observed_at: now + index,
                },
            )
            .unwrap();
    }
    app.drop_account_caches(&owner.label);
    assert_eq!(
        availability_states(&app, &owner)[&followed],
        FollowAvailabilityState::Ready,
        "a retained replacement barrier accepts the same live event"
    );

    clock.store(now + 1, std::sync::atomic::Ordering::SeqCst);
    app.directory()
        .reset_availability_for_test(&owner.account_id_hex);
    app.directory()
        .refresh_follow_availability(&directory_account(&owner))
        .await
        .unwrap();
    assert!(
        shared
            .public_key_package_barriers(&followed)
            .unwrap()
            .iter()
            .any(|barrier| barrier.event_id_hex == selected)
    );
    for index in 0..500_u64 {
        shared
            .put_public_key_package_barrier(&storage_sqlite::PublicKeyPackageBarrierRecord {
                account_id_hex: followed.clone(),
                key_package_id: format!("barrier-{index:04}"),
                event_id_hex: format!("{index:064x}"),
                deleted_event_id: None,
                event_created_at: now + 1_000 + index,
                observed_at: now + 1_000 + index,
                kind: storage_sqlite::PublicKeyPackageBarrierKind::Replacement,
            })
            .unwrap();
    }
    let watermark = shared
        .public_key_package_eviction_watermark(&followed)
        .unwrap()
        .unwrap();
    let barriers = shared.public_key_package_barriers(&followed).unwrap();
    assert_eq!(barriers.len(), 500);
    assert!(
        !barriers
            .iter()
            .any(|barrier| barrier.event_id_hex == selected)
    );
    assert_eq!(
        watermark.kind,
        storage_sqlite::PublicKeyPackageBarrierKind::Replacement
    );
    app.drop_account_caches(&owner.label);
    assert_eq!(
        availability_states(&app, &owner)[&followed],
        FollowAvailabilityState::Ready,
        "a replacement watermark accepts the same live event after barrier pruning"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn availability_account_isolation() {
    let (_root, app, accounts, _fetcher) = crate::tests::member_resolution_fixture(1, false).await;
    let first = app.account_home().create_account("first-owner").unwrap();
    let second = app.account_home().create_account("second-owner").unwrap();
    let followed = accounts[0].account_id_hex.clone();
    remember_follows(&app, &first, vec![followed.clone()]);
    remember_follows(&app, &second, vec![followed.clone()]);

    app.directory()
        .refresh_follow_availability(&directory_account(&first))
        .await
        .unwrap();
    assert_eq!(
        availability_states(&app, &first)[&followed],
        FollowAvailabilityState::Ready
    );
    assert_eq!(
        availability_states(&app, &second)[&followed],
        FollowAvailabilityState::Unknown
    );

    remember_follows(&app, &first, Vec::new());
    assert!(availability_states(&app, &first).is_empty());
    assert_eq!(
        availability_states(&app, &second)[&followed],
        FollowAvailabilityState::Unknown
    );
    app.directory()
        .refresh_follow_availability(&directory_account(&second))
        .await
        .unwrap();
    assert_eq!(
        availability_states(&app, &second)[&followed],
        FollowAvailabilityState::Ready
    );
}
