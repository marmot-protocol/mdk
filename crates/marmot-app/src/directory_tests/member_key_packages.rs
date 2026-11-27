//! Whole-roster KeyPackage resolution over a real `MarmotApp` and its relay
//! fixtures. The directory's own resolution tests stay with the directory.

use std::time::{Duration, Instant};

use nostr_directory::MEMBER_PREWARM_CACHE_TTL;
use nostr_directory::MemberResolutionPurpose;
use nostr_directory::{MemberResolutionOutcome, MemberResolutionPolicy, MemberResolutionStatus};
use nostr_sdk::prelude::FinalizeEvent;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_members_stay_fresh() {
    use nostr_directory::error::DirectoryError;
    use transport_nostr_adapter::{KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE};

    let (_directory, app, accounts, fetcher) =
        crate::tests::member_resolution_fixture(5, false).await;
    let client = crate::tests::client_on_app_relay_plane(&app, &accounts[0].label).await;
    let requirements = client
        .runtime
        .create_key_package_requirements(&cgka_traits::engine::CreateGroupRequest {
            name: "partial resolution".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .unwrap();
    let ordered = [2, 4, 1, 0, 3];
    let mut members = ordered
        .iter()
        .map(|index| accounts[*index].label.clone())
        .collect::<Vec<_>>();
    members.push(nostr_directory::npub_for_account_id(&accounts[2].account_id_hex).unwrap());
    members.push(accounts[4].account_id_hex.clone());

    fetcher.requests.lock().unwrap().clear();
    let invalid_request = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![
                accounts[0].account_id_hex.clone(),
                "not-a-public-key-or-label".into(),
            ],
            &requirements,
            MemberResolutionPurpose::Commit,
            MemberResolutionPolicy::Partial,
        )
        .await;
    assert!(matches!(
        invalid_request,
        Err(DirectoryError::InvalidPublicKey)
    ));
    assert!(fetcher.requests.lock().unwrap().is_empty());

    {
        let mut events = fetcher.events.lock().unwrap();
        events.retain(|event| {
            !(event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == accounts[1].account_id_hex
                || event.kind == KIND_MARMOT_INBOX_RELAY_LIST
                    && event.pubkey == accounts[3].account_id_hex)
        });
        events
            .iter_mut()
            .find(|event| {
                event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == accounts[2].account_id_hex
            })
            .unwrap()
            .content = "not-base64".into();
    }
    let partial = app
        .directory()
        .resolve_compatible_member_key_packages(
            members.clone(),
            &requirements,
            MemberResolutionPurpose::Commit,
            MemberResolutionPolicy::Partial,
        )
        .await
        .unwrap();
    assert_eq!(partial.stats.unique_members, 5);
    assert_eq!(
        partial.member_outcomes,
        ordered
            .into_iter()
            .zip([
                MemberResolutionStatus::InvalidKeyPackage,
                MemberResolutionStatus::Selected,
                MemberResolutionStatus::MissingKeyPackage,
                MemberResolutionStatus::Selected,
                MemberResolutionStatus::MissingInboxRoute,
            ])
            .map(|(index, status)| MemberResolutionOutcome {
                account_id_hex: accounts[index].account_id_hex.clone(),
                status,
                selected_device_count: u32::from(status == MemberResolutionStatus::Selected),
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        partial
            .key_packages
            .iter()
            .map(|package| {
                cgka_engine::key_package::key_package_metadata(package)
                    .unwrap()
                    .credential_identity_hex
            })
            .collect::<Vec<_>>(),
        vec![
            accounts[4].account_id_hex.clone(),
            accounts[0].account_id_hex.clone()
        ]
    );

    let atomic = app
        .directory()
        .resolve_compatible_member_key_packages(
            members.clone(),
            &requirements,
            MemberResolutionPurpose::Commit,
            MemberResolutionPolicy::Atomic,
        )
        .await;
    assert!(matches!(
        atomic,
        Err(DirectoryError::InvalidKeyPackageEvent(_))
    ));

    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    let absent = app
        .directory()
        .resolve_compatible_member_key_packages(
            members.clone(),
            &requirements,
            MemberResolutionPurpose::Commit,
            MemberResolutionPolicy::Partial,
        )
        .await
        .unwrap();
    assert!(
        absent.key_packages.is_empty(),
        "cached selections cannot authorize another invitation"
    );
    // The journal still knows the packages the earlier lookup read, and no
    // deletion request covers them, so their absence decides nothing. The
    // members it never read a valid package for have none.
    assert_eq!(
        absent.member_outcomes,
        ordered
            .into_iter()
            .zip([
                MemberResolutionStatus::MissingKeyPackage,
                MemberResolutionStatus::Incomplete,
                MemberResolutionStatus::MissingKeyPackage,
                MemberResolutionStatus::Incomplete,
                MemberResolutionStatus::Incomplete,
            ])
            .map(|(index, status)| MemberResolutionOutcome {
                account_id_hex: accounts[index].account_id_hex.clone(),
                status,
                selected_device_count: 0,
            })
            .collect::<Vec<_>>()
    );

    *fetcher.failing_single_author.lock().unwrap() = Some(accounts[4].account_id_hex.clone());
    let incomplete = app
        .directory()
        .resolve_compatible_member_key_packages(
            vec![accounts[4].account_id_hex.clone()],
            &requirements,
            MemberResolutionPurpose::Commit,
            MemberResolutionPolicy::Partial,
        )
        .await
        .unwrap();
    assert!(incomplete.key_packages.is_empty());
    assert_eq!(
        incomplete.member_outcomes,
        vec![MemberResolutionOutcome {
            account_id_hex: accounts[4].account_id_hex.clone(),
            status: MemberResolutionStatus::Incomplete,
            selected_device_count: 0,
        }]
    );
    *fetcher.failing_single_author.lock().unwrap() = None;

    let (entered, release) = fetcher.hold_fetches();
    let lookup_app = app.clone();
    let lookup = tokio::spawn(async move {
        lookup_app
            .directory()
            .resolve_compatible_member_key_packages(
                members,
                &requirements,
                MemberResolutionPurpose::Commit,
                MemberResolutionPolicy::Partial,
            )
            .await
    });
    entered.notified().await;
    app.close_storage().unwrap();
    release.notify_one();
    let error = match lookup.await.unwrap() {
        Err(DirectoryError::Resource(error)) => {
            error.into_inner().downcast::<crate::AppError>().unwrap()
        }
        Err(error) => panic!("expected carried storage failure, got {error:?}"),
        Ok(_) => panic!("closed storage cannot become a recipient outcome"),
    };
    assert!(matches!(
        *error,
        crate::AppError::Storage(cgka_traits::StorageError::Closed(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_recovery_refreshes_routes_for_fresh_commit_resolution() {
    let (_directory, app, accounts, fetcher) =
        crate::tests::invite_recovery::discovery_fixture(1).await;
    app.directory()
        .prewarm_group_member_key_packages(&[&accounts[0].account_id_hex])
        .await
        .unwrap();
    fetcher.requests.lock().unwrap().clear();
    let result = app
        .directory()
        .resolve_member_key_packages_for_purpose_for_test(
            vec![accounts[0].account_id_hex.clone()],
            MemberResolutionPurpose::CommitFresh,
            None,
        )
        .await
        .unwrap();
    assert_eq!(result.key_packages.len(), 1);
    assert!(fetcher.requests.lock().unwrap().iter().any(|r| {
        r.queries
            .iter()
            .any(|q| q.kind == transport_nostr_adapter::KIND_NIP65_RELAY_LIST)
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_recovery_journals_malformed_replacement() {
    let (_directory, app, accounts, fetcher) =
        crate::tests::member_resolution_fixture(1, false).await;
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
        .prewarm_group_member_key_packages(&[accounts[0].account_id_hex.as_str()])
        .await
        .unwrap();

    let replacement = {
        let mut replacement = fetcher
            .events
            .lock()
            .unwrap()
            .iter()
            .find(|event| {
                event.kind == transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE
                    && event.pubkey == accounts[0].account_id_hex
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
    let _ = app
        .directory()
        .resolve_member_key_packages_for_purpose_for_test(
            vec![accounts[0].account_id_hex.clone()],
            MemberResolutionPurpose::CommitFresh,
            None,
        )
        .await;
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.id != replacement.id);
    app.drop_account_caches(&owner.label);

    // The journal remembers the newer malformed publication, so the older
    // package it superseded is no longer offered either. No read returned
    // that publication again, so the lookup is incomplete.
    assert!(matches!(
        app.directory()
            .prewarm_group_member_key_packages(&[accounts[0].account_id_hex.as_str()])
            .await,
        Err(nostr_directory::error::DirectoryError::DirectoryLookupIncomplete(_))
    ));
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
        "supplementary recovery must retain malformed replacement evidence"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn composition_prewarm_route_reuse_preserves_original_freshness_deadline() {
    let (_directory, app, accounts, _fetcher) =
        crate::tests::member_resolution_fixture(1, false).await;
    let id = &accounts[0].account_id_hex;
    app.directory()
        .prewarm_group_member_key_packages(&[id.as_str()])
        .await
        .unwrap();
    let original = Instant::now() - Duration::from_secs(240);
    app.directory_state
        .member_key_package_prewarm_cache_for_test()
        .lock()
        .unwrap()
        .set_inserted_at(id, original);
    for _ in 0..3 {
        app.directory()
            .prewarm_group_member_key_packages(&[id.as_str()])
            .await
            .unwrap();
        app.directory()
            .resolve_member_key_packages(&[id.as_str()])
            .await
            .unwrap();
    }
    let mut cache = app
        .directory_state
        .member_key_package_prewarm_cache_for_test()
        .lock()
        .unwrap();
    assert_eq!(cache.inserted_at(id), Some(original));
    cache.set_inserted_at(
        id,
        Instant::now() - MEMBER_PREWARM_CACHE_TTL - Duration::from_secs(1),
    );
    assert!(cache.get(id).is_none());
}

/// The whole resolution budget, as callers see it.
const RESOLUTION_BUDGET: Duration = Duration::from_secs(50);
/// Under Partial, when each step that waits for the whole set stops waiting.
/// Each cut-off leaves every later step one worst-case wave of 8 s reads.
const FIRST_HOP_CUT_OFF: Duration = Duration::from_secs(18);
const OUTBOX_HOP_CUT_OFF: Duration = Duration::from_secs(34);
const KEY_PACKAGE_BATCH_CUT_OFF: Duration = Duration::from_secs(42);

/// On the paused clock, with every other read answered at once, a resolution
/// held at one step ends at that step's cut-off. Tokio rounds a deadline up
/// to its next millisecond.
fn assert_ends_at(elapsed: Duration, cut_off: Duration) {
    assert!(
        (cut_off..cut_off + Duration::from_millis(10)).contains(&elapsed),
        "ended at {elapsed:?}, cut-off {cut_off:?}"
    );
}

/// Resolves `members` for a commit while every fetch `held` matches goes
/// unanswered: first under Partial, then the same set under Atomic. Atomic
/// must wait out the whole budget and fail incomplete. Returns Partial's
/// outcomes and how long it took.
async fn resolve_past_held_fetch(
    app: &crate::MarmotApp,
    fetcher: &crate::tests::MemberResolutionDirectoryFetcher,
    requester: &str,
    members: Vec<String>,
    held: impl Fn(&transport_nostr::DirectoryFetchRequest) -> bool + Send + Sync + 'static,
) -> (Vec<MemberResolutionOutcome>, Duration) {
    let requirements = crate::tests::client_on_app_relay_plane(app, requester)
        .await
        .runtime
        .create_key_package_requirements(&cgka_traits::engine::CreateGroupRequest {
            name: "held fetch".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .unwrap();
    tokio::time::pause();
    fetcher.never_answer(held);

    let started = tokio::time::Instant::now();
    let partial = app
        .directory()
        .resolve_compatible_member_key_packages(
            members.clone(),
            &requirements,
            MemberResolutionPurpose::Commit,
            MemberResolutionPolicy::Partial,
        )
        .await
        .unwrap();
    let partial_elapsed = started.elapsed();

    let started = tokio::time::Instant::now();
    let atomic = app
        .directory()
        .resolve_compatible_member_key_packages(
            members,
            &requirements,
            MemberResolutionPurpose::Commit,
            MemberResolutionPolicy::Atomic,
        )
        .await;
    assert!(
        matches!(
            atomic,
            Err(nostr_directory::error::DirectoryError::DirectoryLookupIncomplete(_))
        ),
        "Atomic resolution must fail incomplete"
    );
    assert!(started.elapsed() >= RESOLUTION_BUDGET);
    (partial.member_outcomes, partial_elapsed)
}

fn outcome(account_id_hex: &str, status: MemberResolutionStatus) -> MemberResolutionOutcome {
    MemberResolutionOutcome {
        account_id_hex: account_id_hex.to_owned(),
        status,
        selected_device_count: u32::from(status == MemberResolutionStatus::Selected),
    }
}

fn asks_for(request: &transport_nostr::DirectoryFetchRequest, kind: u64, endpoint: &str) -> bool {
    request.endpoints.iter().any(|e| e.0 == endpoint)
        && request.queries.iter().any(|query| query.kind == kind)
}

/// A first-hop discovery batch that never answers holds only its own
/// members: another member clears both discovery hops and its single-author
/// read and is selected, and a prewarmed member goes straight to its
/// KeyPackage read.
#[test]
fn partial_resolution_passes_a_held_first_hop_batch() {
    // Pauses the clock, which Tokio allows only on one thread.
    crate::tests::run_composed_app_runtime_test_on_one_thread("held-first-hop", || async {
        let (_directory, app, accounts, fetcher) =
            crate::tests::member_resolution_fixture(2, false).await;
        let prewarmed = accounts[1].account_id_hex.clone();
        app.directory()
            .prewarm_group_member_key_packages(&[prewarmed.as_str()])
            .await
            .unwrap();
        // Thirty-two unknown accounts fill the first batch; the member that
        // must get through is alone in the second.
        let unknown = (0..32)
            .map(|_| nostr::prelude::Keys::generate().public_key().to_hex())
            .collect::<Vec<_>>();
        let held_author = unknown[0].clone();
        let mut members = unknown.clone();
        members.push(accounts[0].account_id_hex.clone());
        members.push(prewarmed.clone());

        let (outcomes, elapsed) = resolve_past_held_fetch(
            &app,
            &fetcher,
            &accounts[0].label,
            members,
            move |request| {
                asks_for(
                    request,
                    transport_nostr_adapter::KIND_NIP65_RELAY_LIST,
                    "wss://directory.example",
                ) && request.queries[0].authors.contains(&held_author)
            },
        )
        .await;

        let mut expected = unknown
            .iter()
            .map(|account| outcome(account, MemberResolutionStatus::Incomplete))
            .collect::<Vec<_>>();
        expected.push(outcome(
            &accounts[0].account_id_hex,
            MemberResolutionStatus::Selected,
        ));
        expected.push(outcome(&prewarmed, MemberResolutionStatus::Selected));
        assert_eq!(outcomes, expected);
        assert_ends_at(elapsed, FIRST_HOP_CUT_OFF);
    });
}

/// A first-hop batch that comes back incomplete falls back to one read per
/// author, and each member goes on when its own read answers: a member whose
/// retry answered is selected while its batch-mate's retry is still held.
#[test]
fn partial_resolution_keeps_a_finished_retry_beside_a_held_one() {
    // Pauses the clock, which Tokio allows only on one thread.
    crate::tests::run_composed_app_runtime_test_on_one_thread("held-retry", || async {
        let (_directory, app, accounts, fetcher) =
            crate::tests::member_resolution_fixture(3, false).await;
        // Every multi-author query fails, so the first hop's one batch is
        // incomplete and each of its authors gets a single-author retry.
        fetcher
            .reject_multi_author
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let held_author = accounts[1].account_id_hex.clone();
        let members = accounts
            .iter()
            .map(|account| account.account_id_hex.clone())
            .collect::<Vec<_>>();

        let (outcomes, elapsed) = resolve_past_held_fetch(
            &app,
            &fetcher,
            &accounts[0].label,
            members,
            move |request| {
                asks_for(
                    request,
                    transport_nostr_adapter::KIND_NIP65_RELAY_LIST,
                    "wss://directory.example",
                ) && request.queries[0].authors == [held_author.clone()]
            },
        )
        .await;

        assert_eq!(
            outcomes,
            vec![
                outcome(
                    &accounts[0].account_id_hex,
                    MemberResolutionStatus::Selected
                ),
                outcome(
                    &accounts[1].account_id_hex,
                    MemberResolutionStatus::Incomplete
                ),
                outcome(
                    &accounts[2].account_id_hex,
                    MemberResolutionStatus::Selected
                ),
            ]
        );
        assert_ends_at(elapsed, FIRST_HOP_CUT_OFF);
    });
}

/// A metadata hop judges its relay lists when it ends, as it did before cut-offs:
/// a list that arrives a little past the allowed clock skew still counts if
/// the clock has caught up by the time the hop's slowest reply lands.
#[test]
fn a_hop_judges_relay_list_freshness_when_it_ends() {
    // Pauses the clock, which Tokio allows only on one thread.
    crate::tests::run_composed_app_runtime_test_on_one_thread("hop-freshness", || async {
        // Member 0 publishes on split-a, member 1 on split-b.
        let (_directory, mut app, accounts, fetcher) =
            crate::tests::member_resolution_fixture(2, true).await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(now));
        app.directory_test_clock = Some(clock.clone());
        // Member 0 has no inbox list, so whether its lookup finished decides
        // its verdict. Its outbox serves a newer relay list dated five
        // seconds past the five-minute skew.
        let member = accounts[0].account_id_hex.clone();
        let mut events = fetcher.events.lock().unwrap().clone();
        events.retain(|event| {
            !(event.pubkey == member
                && event.kind == transport_nostr_adapter::KIND_MARMOT_INBOX_RELAY_LIST)
        });
        let mut ahead = events
            .iter()
            .find(|event| {
                event.pubkey == member
                    && event.kind == transport_nostr_adapter::KIND_NIP65_RELAY_LIST
            })
            .unwrap()
            .clone();
        ahead.created_at = now + 5 * 60 + 5;
        let mut split_a = events.clone();
        split_a.push(ahead);
        fetcher.events_by_endpoint.lock().unwrap().extend([
            ("wss://directory.example".to_owned(), events.clone()),
            ("wss://split-a.example".to_owned(), split_a),
            ("wss://split-b.example".to_owned(), events),
        ]);
        // Member 1's outbox answers 100 ms late, and the clock moves ten
        // seconds before it does.
        *fetcher.stalled_endpoint.lock().unwrap() = Some("wss://split-b.example".to_owned());
        let requirements = crate::tests::client_on_app_relay_plane(&app, &accounts[0].label)
            .await
            .runtime
            .create_key_package_requirements(&cgka_traits::engine::CreateGroupRequest {
                name: "hop freshness".into(),
                description: String::new(),
                members: Vec::new(),
                required_features: Vec::new(),
                app_components: Vec::new(),
                initial_admins: Vec::new(),
            })
            .unwrap();
        tokio::time::pause();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            clock.fetch_add(10, std::sync::atomic::Ordering::SeqCst);
        });

        let atomic = app
            .directory()
            .resolve_compatible_member_key_packages(
                accounts
                    .iter()
                    .map(|account| account.account_id_hex.clone())
                    .collect(),
                &requirements,
                MemberResolutionPurpose::Commit,
                MemberResolutionPolicy::Atomic,
            )
            .await;

        // The finished lookup gives a verdict: member 0 has no inbox route.
        assert!(
            matches!(
                atomic,
                Err(nostr_directory::error::DirectoryError::MissingMemberInboxRoute(ref account))
                    if *account == member
            ),
            "{:?}",
            atomic.as_ref().err()
        );
    });
}

/// An outbox hop that never answers holds only the members routed there.
/// A member whose discovery finished has its relay lists remembered even
/// though it has no KeyPackage; the held member's discovery-only snapshot is
/// not remembered.
#[test]
fn partial_resolution_passes_a_held_outbox_hop() {
    // Pauses the clock, which Tokio allows only on one thread.
    crate::tests::run_composed_app_runtime_test_on_one_thread("held-outbox-hop", || async {
        // Members 0 and 2 publish on split-a, member 1 on split-b.
        let (_directory, app, accounts, fetcher) =
            crate::tests::member_resolution_fixture(3, true).await;
        let without_package = accounts[2].account_id_hex.clone();
        fetcher.events.lock().unwrap().retain(|event| {
            !(event.kind == transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE
                && event.pubkey == without_package)
        });
        let members = accounts
            .iter()
            .map(|account| account.account_id_hex.clone())
            .collect::<Vec<_>>();

        let (outcomes, elapsed) =
            resolve_past_held_fetch(&app, &fetcher, &accounts[0].label, members, |request| {
                asks_for(
                    request,
                    transport_nostr_adapter::KIND_NIP65_RELAY_LIST,
                    "wss://split-b.example",
                )
            })
            .await;

        assert_eq!(
            outcomes,
            vec![
                outcome(
                    &accounts[0].account_id_hex,
                    MemberResolutionStatus::Selected
                ),
                outcome(
                    &accounts[1].account_id_hex,
                    MemberResolutionStatus::Incomplete
                ),
                outcome(&without_package, MemberResolutionStatus::MissingKeyPackage),
            ]
        );
        assert_ends_at(elapsed, OUTBOX_HOP_CUT_OFF);
        let remembered_inbox = |account: &str| {
            app.directory()
                .directory_entry_for_account_id(account)
                .unwrap()
                .map(|entry| entry.relay_lists.inbox.relays)
                .unwrap_or_default()
        };
        assert_eq!(
            remembered_inbox(&without_package),
            vec!["wss://split-a.example".to_owned()]
        );
        assert!(remembered_inbox(&accounts[1].account_id_hex).is_empty());
    });
}

/// A KeyPackage batch that never answers holds only its own members: the
/// members of a batch that answered go on to their single-author reads and
/// are selected.
#[test]
fn partial_resolution_passes_a_held_key_package_batch() {
    // Pauses the clock, which Tokio allows only on one thread.
    crate::tests::run_composed_app_runtime_test_on_one_thread("held-package-batch", || async {
        // Members 0 and 2 share a batch on split-a; member 1 is alone on
        // split-b.
        let (_directory, app, accounts, fetcher) =
            crate::tests::member_resolution_fixture(3, true).await;
        let members = accounts
            .iter()
            .map(|account| account.account_id_hex.clone())
            .collect::<Vec<_>>();

        let (outcomes, elapsed) =
            resolve_past_held_fetch(&app, &fetcher, &accounts[0].label, members, |request| {
                asks_for(
                    request,
                    transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE,
                    "wss://split-b.example",
                )
            })
            .await;

        assert_eq!(
            outcomes,
            vec![
                outcome(
                    &accounts[0].account_id_hex,
                    MemberResolutionStatus::Selected
                ),
                outcome(
                    &accounts[1].account_id_hex,
                    MemberResolutionStatus::Incomplete
                ),
                outcome(
                    &accounts[2].account_id_hex,
                    MemberResolutionStatus::Selected
                ),
            ]
        );
        assert_ends_at(elapsed, KEY_PACKAGE_BATCH_CUT_OFF);
    });
}

/// A member's KeyPackage read that one of its two relays leaves unfinished
/// still selects the package the other relay returned (D12), and counts as
/// incomplete, one relay of two answered. A read every relay answers counts
/// as complete. Create and invite both count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_a_relay_left_unfinished_still_selects_and_counts_incomplete() {
    use crate::RuntimePerformanceOperation as Op;

    let (_directory, app, accounts, fetcher) =
        crate::tests::member_resolution_fixture(3, false).await;
    fetcher
        .events
        .lock()
        .unwrap()
        .iter_mut()
        .find(|event| {
            event.kind == transport_nostr_adapter::KIND_NIP65_RELAY_LIST
                && event.pubkey == accounts[1].account_id_hex
        })
        .unwrap()
        .tags
        .push(vec!["r".into(), "wss://unanswered.example".into()]);
    fetcher.leave_unanswered("wss://unanswered.example");
    let mut client = crate::tests::client_on_app_relay_plane(&app, &accounts[0].label).await;
    let telemetry = marmot_observability::PerformanceRecorder::default();
    client.runtime_telemetry = Some(telemetry.clone());
    let counts = |operation: Op| {
        let snapshot = telemetry
            .snapshot()
            .runtime_operations
            .into_iter()
            .find(|snapshot| snapshot.operation == operation)
            .unwrap();
        (snapshot.successes, snapshot.failures)
    };

    let created = client
        .create_group("coverage", &[accounts[1].account_id_hex.as_str()])
        .await
        .unwrap();
    assert_eq!(
        created.member_outcomes,
        vec![outcome(
            &accounts[1].account_id_hex,
            MemberResolutionStatus::Selected
        )]
    );
    let group = created.operation.expect("the answering relay's package");
    assert_eq!(counts(Op::MemberKeyPackageRead), (0, 1));
    assert_eq!(counts(Op::MemberKeyPackageRelayRead), (1, 1));

    let invited = client
        .invite_members(&group, &[accounts[2].account_id_hex.as_str()])
        .await
        .unwrap();
    assert_eq!(
        invited.member_outcomes,
        vec![outcome(
            &accounts[2].account_id_hex,
            MemberResolutionStatus::Selected
        )]
    );
    assert!(invited.operation.is_some());
    assert_eq!(counts(Op::MemberKeyPackageRead), (1, 1));
    assert_eq!(counts(Op::MemberKeyPackageRelayRead), (2, 1));
}
