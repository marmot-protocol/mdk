use super::*;

const DISCOVERY: &str = "wss://directory.example";
const OUTBOX: &str = "wss://outbox.example";

pub(crate) async fn discovery_fixture(
    count: usize,
) -> (
    tempfile::TempDir,
    MarmotApp,
    Vec<AccountSummary>,
    Arc<MemberResolutionDirectoryFetcher>,
) {
    let fixture = member_resolution_fixture(count, false).await;
    let events = fixture.3.events.lock().unwrap().clone();
    let mut discovery = events
        .iter()
        .filter(|event| event.kind != KIND_NIP65_RELAY_LIST)
        .cloned()
        .collect::<Vec<_>>();
    for account in &fixture.2 {
        discovery.push(NostrTransportEvent::new_unsigned(
            account.account_id_hex.clone(),
            KIND_NIP65_RELAY_LIST,
            vec![vec!["r".into(), OUTBOX.into(), "write".into()]],
            String::new(),
        ));
    }
    let outbox = discovery
        .iter()
        .filter(|event| event.kind != KIND_MARMOT_KEY_PACKAGE)
        .cloned()
        .collect::<Vec<_>>();
    fixture
        .3
        .events_by_endpoint
        .lock()
        .unwrap()
        .extend([(DISCOVERY.into(), discovery), (OUTBOX.into(), outbox)]);
    fixture
}

fn package(
    fetcher: &MemberResolutionDirectoryFetcher,
    account: &AccountSummary,
) -> NostrTransportEvent {
    fetcher.events_by_endpoint.lock().unwrap()[DISCOVERY]
        .iter()
        .find(|event| {
            event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == account.account_id_hex
        })
        .unwrap()
        .clone()
}

fn signed_deletion(
    app: &MarmotApp,
    account: &AccountSummary,
    name: &str,
    value: String,
    created_at: u64,
) -> NostrTransportEvent {
    let event = EventBuilder::new(Kind::from(5), "")
        .tags([Tag::custom(name, [value])])
        .custom_created_at(NostrTimestamp::from_secs(created_at))
        .finalize(
            &app.account_home()
                .load_signing_keys(&account.label)
                .unwrap(),
        )
        .unwrap();
    NostrTransportEvent::from_nostr_event(&event).unwrap()
}

#[tokio::test]
async fn invite_recovery_supports_prewarm_and_multi_member_lookup() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(2).await;
    let refs = accounts
        .iter()
        .map(|account| account.account_id_hex.as_str())
        .collect::<Vec<_>>();
    app.prewarm_group_member_key_packages(&refs).await.unwrap();
    let packages = app.resolve_member_key_packages(&refs).await.unwrap();
    assert_eq!(packages.len(), 2);
    let requests = fetcher.requests.lock().unwrap();
    assert!(requests.iter().any(|request| {
        request.endpoints == vec![TransportEndpoint(DISCOVERY.into())]
            && request
                .queries
                .iter()
                .any(|query| query.kind == KIND_MARMOT_KEY_PACKAGE)
    }));
    assert!(
        requests
            .iter()
            .filter(|request| request.queries.iter().any(|query| query.kind == 5))
            .all(|request| request
                .endpoints
                .contains(&TransportEndpoint(OUTBOX.into()))
                && request
                    .endpoints
                    .contains(&TransportEndpoint(DISCOVERY.into())))
    );
}

#[tokio::test]
async fn invite_recovery_keeps_advertised_success_free_of_supplementary_reads() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let published = package(&fetcher, &accounts[0]);
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .get_mut(OUTBOX)
        .unwrap()
        .push(published);
    app.resolve_member_key_packages(&[&accounts[0].account_id_hex])
        .await
        .unwrap();
    {
        let requests = fetcher.requests.lock().unwrap();
        assert!(
            !requests
                .iter()
                .any(|r| r.queries.iter().any(|q| q.kind == 5))
        );
        assert!(!requests.iter().any(
            |r| r.endpoints.contains(&TransportEndpoint(DISCOVERY.into()))
                && r.queries.iter().any(|q| q.kind == KIND_MARMOT_KEY_PACKAGE)
        ));
    }
    // The direct diagnostic normal path also avoids supplementary package and
    // deletion reads once the advertised package succeeds.
    fetcher.requests.lock().unwrap().clear();
    app.fetch_latest_key_package_for_account_id(&accounts[0].account_id_hex, vec![])
        .await
        .unwrap();
    let requests = fetcher.requests.lock().unwrap();
    assert!(
        !requests
            .iter()
            .any(|request| request.queries.iter().any(|query| query.kind == 5))
    );
    assert!(!requests.iter().any(|request| {
        request
            .endpoints
            .contains(&TransportEndpoint(DISCOVERY.into()))
            && request
                .queries
                .iter()
                .any(|query| query.kind == KIND_MARMOT_KEY_PACKAGE)
    }));
}

#[tokio::test]
async fn invite_recovery_honors_signed_event_and_coordinate_deletions() {
    for name in ["e", "a"] {
        let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
        let account = &accounts[0];
        let published = package(&fetcher, account);
        let value = if name == "e" {
            published.id.clone()
        } else {
            format!(
                "30443:{}:{}",
                account.account_id_hex,
                published.tag_value("d").unwrap()
            )
        };
        let deletion = signed_deletion(&app, account, name, value, published.created_at);
        fetcher
            .events_by_endpoint
            .lock()
            .unwrap()
            .get_mut(OUTBOX)
            .unwrap()
            .push(deletion);
        assert!(matches!(
            app.resolve_member_key_packages(&[&account.account_id_hex])
                .await,
            Err(AppError::MissingKeyPackage(_))
        ));
        assert!(matches!(
            app.fetch_latest_key_package_for_account_id(&account.account_id_hex, vec![])
                .await,
            Err(AppError::MissingKeyPackage(_))
        ));
    }
}

#[tokio::test]
async fn invite_recovery_keeps_a_newer_package_after_coordinate_deletion() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let account = &accounts[0];
    let published = package(&fetcher, account);
    let deletion = signed_deletion(
        &app,
        account,
        "a",
        format!(
            "30443:{}:{}",
            account.account_id_hex,
            published.tag_value("d").unwrap()
        ),
        published.created_at - 1,
    );
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .get_mut(OUTBOX)
        .unwrap()
        .push(deletion);
    app.resolve_member_key_packages(&[&account.account_id_hex])
        .await
        .unwrap();
}

#[tokio::test]
async fn invite_recovery_does_not_revive_a_newer_malformed_or_deleted_slot() {
    for delete_newest in [false, true] {
        let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
        let account = &accounts[0];
        let mut newest = package(&fetcher, account);
        newest.created_at += 1;
        newest.id = "f1".repeat(32);
        if !delete_newest {
            newest.content = "not a KeyPackage".into();
        }
        fetcher
            .events_by_endpoint
            .lock()
            .unwrap()
            .get_mut(OUTBOX)
            .unwrap()
            .push(newest.clone());
        // A valid advertised winner is intentionally not subject to the new
        // recovery path. Force it to be rejected by the existing selector so
        // the discovery stage must retain its same-slot barrier.
        if delete_newest {
            newest.content = "not a KeyPackage".into();
            let mut endpoints = fetcher.events_by_endpoint.lock().unwrap();
            *endpoints.get_mut(OUTBOX).unwrap().last_mut().unwrap() = newest.clone();
            drop(endpoints);
            let deletion =
                signed_deletion(&app, account, "e", newest.id.clone(), newest.created_at);
            fetcher
                .events_by_endpoint
                .lock()
                .unwrap()
                .get_mut(OUTBOX)
                .unwrap()
                .push(deletion);
        }
        assert!(matches!(
            app.resolve_member_key_packages(&[&account.account_id_hex])
                .await,
            Err(AppError::InvalidKeyPackageEvent(_))
        ));
    }
}

#[tokio::test]
async fn invite_recovery_unknown_coverage_is_retryable_and_can_recover_after_route_repair() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    *fetcher.incomplete_endpoint.lock().unwrap() = Some(OUTBOX.into());
    *fetcher.incomplete_query_kind.lock().unwrap() = Some(5);
    assert!(matches!(
        app.resolve_member_key_packages(&[&accounts[0].account_id_hex])
            .await,
        Err(AppError::RelayDirectory(_))
    ));
    *fetcher.incomplete_endpoint.lock().unwrap() = None;
    app.resolve_member_key_packages(&[&accounts[0].account_id_hex])
        .await
        .unwrap();
}

#[tokio::test]
async fn invite_recovery_direct_lookup_uses_explicit_bootstrap_discovery() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let events = fetcher.events_by_endpoint.lock().unwrap()[DISCOVERY].clone();
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .insert("wss://explicit.example".into(), events);
    let fetched = app
        .fetch_latest_key_package_for_account_id(
            &npub_for_account_id_lossy(&accounts[0].account_id_hex),
            vec![TransportEndpoint("wss://explicit.example".into())],
        )
        .await
        .unwrap();
    assert_eq!(fetched.account_id_hex, accounts[0].account_id_hex);
    let requests = fetcher.requests.lock().unwrap();
    assert!(requests.iter().any(|request| {
        request.endpoints == vec![TransportEndpoint("wss://explicit.example".into())]
            && request
                .queries
                .iter()
                .any(|query| query.kind == KIND_MARMOT_KEY_PACKAGE)
    }));
}

#[tokio::test]
async fn invite_recovery_ignores_many_unrelated_deletions() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let account = &accounts[0];
    let created_at = package(&fetcher, account).created_at;
    let deletions = (0..64)
        .map(|index| signed_deletion(&app, account, "e", format!("{index:064x}"), created_at))
        .collect::<Vec<_>>();
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .get_mut(OUTBOX)
        .unwrap()
        .extend(deletions);
    app.resolve_member_key_packages(&[&account.account_id_hex])
        .await
        .unwrap();
    assert!(
        fetcher
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.queries.iter().any(|q| q.kind == 5))
            .all(|request| request.queries.len() == 2
                && request
                    .queries
                    .iter()
                    .all(|q| q.reference.is_some() && q.limit == 1))
    );
}

#[tokio::test]
async fn invite_recovery_ignores_wrong_author_and_unsigned_deletions() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(2).await;
    let account = &accounts[0];
    let published = package(&fetcher, account);
    let wrong_author = signed_deletion(
        &app,
        &accounts[1],
        "e",
        published.id.clone(),
        published.created_at,
    );
    let unsigned = NostrTransportEvent::new_unsigned_at(
        account.account_id_hex.clone(),
        5,
        vec![vec!["e".into(), published.id.clone()]],
        String::new(),
        published.created_at,
    );
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .get_mut(OUTBOX)
        .unwrap()
        .extend([wrong_author, unsigned]);
    app.resolve_member_key_packages(&[&account.account_id_hex])
        .await
        .unwrap();
}

#[tokio::test]
async fn invite_recovery_does_not_resurrect_an_older_slot_after_revoking_its_winner() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let account = &accounts[0];
    let old = package(&fetcher, account);
    let mut malformed = old.clone();
    malformed.created_at += 1;
    malformed.id = "f1".repeat(32);
    malformed.content = "invalid".into();
    let mut winner = old.clone();
    winner.created_at += 2;
    winner.id = "f2".repeat(32);
    let deletion = signed_deletion(&app, account, "e", winner.id.clone(), winner.created_at);
    {
        let mut endpoints = fetcher.events_by_endpoint.lock().unwrap();
        endpoints
            .get_mut(OUTBOX)
            .unwrap()
            .extend([malformed, deletion]);
        endpoints.get_mut(DISCOVERY).unwrap().push(winner);
    }
    assert!(matches!(
        app.resolve_member_key_packages(&[&account.account_id_hex])
            .await,
        Err(AppError::MissingKeyPackage(_))
    ));
}

#[tokio::test]
async fn invite_recovery_mixed_batch_preserves_first_failed_recipient() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(3).await;
    {
        let mut endpoints = fetcher.events_by_endpoint.lock().unwrap();
        endpoints.get_mut(DISCOVERY).unwrap().retain(|event| {
            event.kind != KIND_MARMOT_KEY_PACKAGE || event.pubkey == accounts[0].account_id_hex
        });
    }
    let result = app
        .resolve_member_key_packages(&[
            &accounts[0].account_id_hex,
            &accounts[2].account_id_hex,
            &accounts[1].account_id_hex,
        ])
        .await;
    assert!(
        matches!(result, Err(AppError::MissingKeyPackage(account)) if account == accounts[2].account_id_hex)
    );
}

#[tokio::test]
async fn invite_recovery_direct_lookup_and_membership_share_bounded_waits() {
    for (direct, kind) in [
        (true, KIND_MARMOT_KEY_PACKAGE),
        (false, KIND_MARMOT_KEY_PACKAGE),
        (true, 5),
        (false, 5),
    ] {
        let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
        let (entered, release) = fetcher.hold_fetches_for_kind(kind);
        tokio::time::pause();
        let target = accounts[0].account_id_hex.clone();
        let task = tokio::spawn(async move {
            if direct {
                app.fetch_latest_key_package_for_account_id(&target, vec![])
                    .await
                    .map(|_| ())
            } else {
                app.resolve_member_key_packages(&[&target])
                    .await
                    .map(|_| ())
            }
        });
        entered.notified().await;
        tokio::time::advance(Duration::from_secs(51)).await;
        assert!(matches!(
            task.await.unwrap(),
            Err(AppError::RelayDirectory(_))
        ));
        release.notify_one();
        tokio::time::resume();
    }
}

#[tokio::test]
async fn invite_recovery_cancellation_does_not_admit_an_unverified_package() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let id = accounts[0].account_id_hex.clone();
    let (entered, release) = fetcher.hold_fetches_for_kind(5);
    let copy = app.clone();
    let target = id.clone();
    let task = tokio::spawn(async move { copy.resolve_member_key_packages(&[&target]).await });
    entered.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        app.directory_entry_for_account_id(&id)
            .unwrap()
            .and_then(|entry| entry.key_package)
            .is_none()
    );
    release.notify_one();
    app.resolve_member_key_packages(&[&id]).await.unwrap();
    assert!(
        app.directory_entry_for_account_id(&id)
            .unwrap()
            .unwrap()
            .key_package
            .is_some()
    );
}

#[tokio::test]
async fn invite_recovery_limits_safe_canonical_supplementary_endpoints() {
    let (_directory, mut app, accounts, fetcher) = discovery_fixture(1).await;
    let id = &accounts[0].account_id_hex;
    app.fetch_account_relay_list_status_for_account_id(
        id,
        vec![TransportEndpoint(DISCOVERY.into())],
    )
    .await
    .unwrap();
    app.config.directory_relay_urls = vec![
        format!("{OUTBOX}/"),
        "ws://127.0.0.1:9876".into(),
        "not a relay".into(),
        DISCOVERY.into(),
        format!("{DISCOVERY}/"),
    ];
    app.config
        .directory_relay_urls
        .extend((0..20).map(|i| format!("wss://extra-{i}.example")));
    fetcher.requests.lock().unwrap().clear();
    app.fetch_latest_key_package_for_account_id(id, vec![])
        .await
        .unwrap();
    let requests = fetcher.requests.lock().unwrap();
    let supplementary = requests
        .iter()
        .find(|request| {
            request
                .queries
                .iter()
                .any(|query| query.kind == KIND_MARMOT_KEY_PACKAGE)
                && request
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.0 == DISCOVERY)
        })
        .unwrap();
    assert_eq!(supplementary.endpoints.len(), 8);
    assert_eq!(
        supplementary
            .endpoints
            .iter()
            .map(|endpoint| nostr_sdk::prelude::RelayUrl::parse(&endpoint.0).unwrap())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        8
    );
    assert!(
        !supplementary
            .endpoints
            .iter()
            .any(|endpoint| endpoint.0.contains("127.0.0.1")
                || nostr_sdk::prelude::RelayUrl::parse(&endpoint.0).ok()
                    == nostr_sdk::prelude::RelayUrl::parse(OUTBOX).ok()
                || endpoint.0 == "not a relay")
    );
}

#[tokio::test]
async fn invite_recovery_preserves_only_unrevoked_future_record_cache_fallback() {
    for revoke_cached in [false, true] {
        let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
        let account = &accounts[0];
        let cached = app
            .fetch_latest_key_package_for_account_id(&account.account_id_hex, vec![])
            .await
            .unwrap();
        let published = package(&fetcher, account);
        let mut future = published.clone();
        future.created_at = u64::MAX;
        future.id = "f3".repeat(32);
        let mut revoked = published.clone();
        if !revoke_cached {
            revoked
                .tags
                .iter_mut()
                .find(|tag| tag.first().is_some_and(|key| key == "d"))
                .unwrap()[1] = "independent-slot".into();
            revoked.id = "f4".repeat(32);
        }
        let deletion = signed_deletion(
            &app,
            account,
            "a",
            format!(
                "30443:{}:{}",
                account.account_id_hex,
                revoked.tag_value("d").unwrap()
            ),
            revoked.created_at,
        );
        {
            let mut endpoints = fetcher.events_by_endpoint.lock().unwrap();
            endpoints
                .get_mut(DISCOVERY)
                .unwrap()
                .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
            endpoints
                .get_mut(DISCOVERY)
                .unwrap()
                .extend([future, revoked, deletion]);
        }
        let result = app
            .fetch_latest_key_package_for_account_id(&account.account_id_hex, vec![])
            .await;
        if revoke_cached {
            assert!(matches!(result, Err(AppError::MissingKeyPackage(_))));
        } else {
            assert_eq!(
                result.unwrap().key_package_event_id,
                cached.key_package_event_id
            );
        }
    }
}

#[tokio::test]
async fn invite_recovery_group_preflight_keeps_failed_roster_unchanged_and_allows_retry() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let member = &accounts[0];
    let published = package(&fetcher, member);
    let deletion = signed_deletion(
        &app,
        member,
        "e",
        published.id.clone(),
        published.created_at,
    );
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .get_mut(OUTBOX)
        .unwrap()
        .push(deletion);
    let inviter = app.account_home().create_account("creator").unwrap();
    let mut client = app.client(&inviter.label).await.unwrap();
    let group = client
        .create_group("Recovery preflight", &[])
        .await
        .unwrap();
    let before = client.group_mls_state(&group).unwrap();
    assert!(matches!(
        client
            .invite_members(&group, &[&member.account_id_hex])
            .await,
        Err(AppError::MissingKeyPackage(_))
    ));
    let after = client.group_mls_state(&group).unwrap();
    assert_eq!(after.member_count, before.member_count);
    assert_eq!(after.epoch, before.epoch);
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .get_mut(OUTBOX)
        .unwrap()
        .retain(|event| event.kind != 5);
    client
        .invite_members(&group, &[&member.account_id_hex])
        .await
        .unwrap();
    assert_eq!(client.group_mls_state(&group).unwrap().member_count, 2);
}

#[tokio::test]
async fn invite_recovery_runtime_ready_account_group_creation_uses_discovery_only_packages() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    app.account_home().create_account("creator").unwrap();
    // This regression starts with ready local accounts; the separate cold-start
    // runtime test retains the production account-opening deadline.
    for label in [accounts[0].label.as_str(), "creator"] {
        drop(
            app.local_client_with_relay_plane(label, &app.relay_plane, None)
                .await
                .unwrap(),
        );
    }
    assert!(fetcher.requests.lock().unwrap().iter().all(|request| {
        request
            .queries
            .iter()
            .all(|query| query.kind != 5 && query.kind != KIND_MARMOT_KEY_PACKAGE)
    }));
    fetcher.requests.lock().unwrap().clear();
    let runtime = MarmotAppRuntime::new(app.clone());
    let group = runtime
        .create_group_with_options(
            "creator",
            "Discovery invitation",
            &[npub_for_account_id_lossy(&accounts[0].account_id_hex)],
            AppCreateGroupOptions::default(),
        )
        .await
        .unwrap();
    let roster = runtime.group_members("creator", &group).await.unwrap();
    assert_eq!(roster.len(), 2);
    assert!(
        roster
            .iter()
            .any(|entry| entry.member_id_hex == accounts[0].account_id_hex)
    );
    {
        let requests = fetcher.requests.lock().unwrap();
        for endpoint in [OUTBOX, DISCOVERY] {
            assert!(requests.iter().any(|request| {
                request.endpoints.iter().any(|route| route.0 == endpoint)
                    && request.queries.iter().any(|query| {
                        query.kind == KIND_MARMOT_KEY_PACKAGE
                            && query.authors.contains(&accounts[0].account_id_hex)
                    })
            }));
        }
        assert!(requests.iter().any(|request| {
            request
                .queries
                .iter()
                .any(|query| query.kind == 5 && query.reference.is_some())
        }));
    }
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn invite_recovery_preserves_known_malformed_error_on_incomplete_primary_empty_supplement() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let account = &accounts[0];
    let mut malformed = package(&fetcher, account);
    malformed.content = "invalid KeyPackage".into();
    {
        let mut routes = fetcher.events_by_endpoint.lock().unwrap();
        routes
            .get_mut(DISCOVERY)
            .unwrap()
            .retain(|e| e.kind != KIND_MARMOT_KEY_PACKAGE);
        routes.get_mut(OUTBOX).unwrap().push(malformed);
    }
    *fetcher.incomplete_endpoint.lock().unwrap() = Some(OUTBOX.into());
    *fetcher.incomplete_query_kind.lock().unwrap() = Some(KIND_MARMOT_KEY_PACKAGE);
    assert!(matches!(
        app.resolve_member_key_packages(&[&account.account_id_hex])
            .await,
        Err(AppError::InvalidKeyPackageEvent(_))
    ));
}

#[tokio::test]
async fn invite_recovery_incomplete_supplement_cannot_authorize_a_usable_copy() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    *fetcher.incomplete_endpoint.lock().unwrap() = Some(DISCOVERY.into());
    *fetcher.incomplete_query_kind.lock().unwrap() = Some(KIND_MARMOT_KEY_PACKAGE);
    assert!(matches!(
        app.resolve_member_key_packages(&[&accounts[0].account_id_hex])
            .await,
        Err(AppError::RelayDirectory(_))
    ));
}

#[tokio::test]
async fn invite_recovery_verified_deletion_rejects_despite_other_incomplete_routes() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let account = &accounts[0];
    let published = package(&fetcher, account);
    let deletion = signed_deletion(&app, account, "e", published.id, published.created_at);
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .get_mut(OUTBOX)
        .unwrap()
        .push(deletion);
    *fetcher.incomplete_endpoint.lock().unwrap() = Some(DISCOVERY.into());
    *fetcher.incomplete_query_kind.lock().unwrap() = Some(5);
    assert!(matches!(
        app.resolve_member_key_packages(&[&account.account_id_hex])
            .await,
        Err(AppError::MissingKeyPackage(_))
    ));
}

#[tokio::test]
async fn invite_recovery_revoked_preferred_slot_allows_an_independent_survivor() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let account = &accounts[0];
    let preferred = package(&fetcher, account);
    let mut alternate = preferred.clone();
    alternate.id = "a5".repeat(32);
    alternate.created_at -= 1;
    alternate
        .tags
        .iter_mut()
        .find(|t| t.first().is_some_and(|name| name == "d"))
        .unwrap()[1] = "alternative-slot".into();
    let deletion = signed_deletion(&app, account, "e", preferred.id, preferred.created_at);
    {
        let mut routes = fetcher.events_by_endpoint.lock().unwrap();
        routes.get_mut(DISCOVERY).unwrap().push(alternate.clone());
        routes.get_mut(OUTBOX).unwrap().push(deletion);
    }
    let recovered = app
        .fetch_latest_key_package_for_account_id(&account.account_id_hex, vec![])
        .await
        .unwrap();
    assert_eq!(recovered.key_package_event_id, alternate.id);
}

#[tokio::test]
async fn invite_recovery_future_only_cache_requires_its_own_completed_deletion_proof() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let account = &accounts[0];
    let cached = app
        .fetch_latest_key_package_for_account_id(&account.account_id_hex, vec![])
        .await
        .unwrap();
    let mut future = package(&fetcher, account);
    future.created_at = u64::MAX;
    future.id = "a6".repeat(32);
    {
        let mut routes = fetcher.events_by_endpoint.lock().unwrap();
        routes
            .get_mut(DISCOVERY)
            .unwrap()
            .retain(|e| e.kind != KIND_MARMOT_KEY_PACKAGE);
        routes.get_mut(OUTBOX).unwrap().push(future);
    }
    *fetcher.incomplete_endpoint.lock().unwrap() = Some(DISCOVERY.into());
    *fetcher.incomplete_query_kind.lock().unwrap() = Some(5);
    assert!(matches!(
        app.fetch_latest_key_package_for_account_id(&account.account_id_hex, vec![])
            .await,
        Err(AppError::RelayDirectory(_))
    ));
    *fetcher.incomplete_endpoint.lock().unwrap() = None;
    assert_eq!(
        app.fetch_latest_key_package_for_account_id(&account.account_id_hex, vec![])
            .await
            .unwrap()
            .key_package_event_id,
        cached.key_package_event_id
    );
    let deletion = signed_deletion(
        &app,
        account,
        "e",
        cached.key_package_event_id,
        cached.created_at,
    );
    fetcher
        .events_by_endpoint
        .lock()
        .unwrap()
        .get_mut(DISCOVERY)
        .unwrap()
        .push(deletion);
    assert!(matches!(
        app.fetch_latest_key_package_for_account_id(&account.account_id_hex, vec![])
            .await,
        Err(AppError::MissingKeyPackage(_))
    ));
}

#[tokio::test]
async fn invite_recovery_incomplete_negative_without_new_routes_is_unknown() {
    let (_directory, mut app, accounts, fetcher) = discovery_fixture(1).await;
    let id = &accounts[0].account_id_hex;
    app.fetch_account_relay_list_status_for_account_id(
        id,
        vec![TransportEndpoint(DISCOVERY.into())],
    )
    .await
    .unwrap();
    app.config.directory_relay_urls = vec![OUTBOX.into()];
    for events in fetcher.events_by_endpoint.lock().unwrap().values_mut() {
        events.retain(|e| e.kind != KIND_MARMOT_KEY_PACKAGE);
    }
    *fetcher.incomplete_endpoint.lock().unwrap() = Some(OUTBOX.into());
    *fetcher.incomplete_query_kind.lock().unwrap() = Some(KIND_MARMOT_KEY_PACKAGE);
    assert!(matches!(
        app.fetch_latest_key_package_for_account_id(id, vec![])
            .await,
        Err(AppError::RelayDirectory(_))
    ));
}

#[tokio::test]
async fn invite_recovery_candidate_budget_does_not_accept_an_unchecked_survivor() {
    let (_directory, mut app, accounts, fetcher) = discovery_fixture(1).await;
    let account = &accounts[0];
    let published = package(&fetcher, account);
    let mut copies = Vec::new();
    let mut deletions = Vec::new();
    for index in 0..14 {
        let mut event = published.clone();
        event.id = format!("{:064x}", 1000 + index);
        event.created_at -= index;
        event
            .tags
            .iter_mut()
            .find(|t| t.first().is_some_and(|name| name == "d"))
            .unwrap()[1] = format!("slot-{index}");
        if index < 13 {
            deletions.push(signed_deletion(
                &app,
                account,
                "e",
                event.id.clone(),
                event.created_at,
            ));
        }
        copies.push(event);
    }
    {
        let mut routes = fetcher.events_by_endpoint.lock().unwrap();
        routes
            .get_mut(DISCOVERY)
            .unwrap()
            .retain(|e| e.kind != KIND_MARMOT_KEY_PACKAGE);
        routes
            .get_mut(DISCOVERY)
            .unwrap()
            .extend(copies[..7].iter().cloned());
        routes.insert(
            "wss://second-discovery.example".into(),
            copies[7..].to_vec(),
        );
        routes.get_mut(OUTBOX).unwrap().extend(deletions);
    }
    app.config.directory_relay_urls =
        vec![DISCOVERY.into(), "wss://second-discovery.example".into()];
    assert!(matches!(
        app.resolve_member_key_packages(&[&account.account_id_hex])
            .await,
        Err(AppError::RelayDirectory(_))
    ));
}

#[tokio::test]
async fn invite_recovery_preserves_incompatible_errors_for_empty_and_failed_supplements() {
    let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
    let account = &accounts[0];
    app.account_home()
        .create_account("requirements-owner")
        .unwrap();
    let mut client = client_on_app_relay_plane(&app, "requirements-owner").await;
    let group = client
        .create_group("Compatibility diagnostics", &[])
        .await
        .unwrap();
    let requirements = client
        .runtime
        .session()
        .invite_key_package_requirements(&group)
        .unwrap();
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
    let incompatible = member_resolution_key_package_event(account, package);
    {
        let mut routes = fetcher.events_by_endpoint.lock().unwrap();
        routes
            .get_mut(DISCOVERY)
            .unwrap()
            .retain(|e| e.kind != KIND_MARMOT_KEY_PACKAGE);
        routes.get_mut(OUTBOX).unwrap().push(incompatible);
    }
    for supplement_error in [false, true] {
        *fetcher.incomplete_endpoint.lock().unwrap() = (!supplement_error).then(|| OUTBOX.into());
        *fetcher.incomplete_query_kind.lock().unwrap() = Some(KIND_MARMOT_KEY_PACKAGE);
        *fetcher.failing_endpoint.lock().unwrap() = supplement_error.then(|| DISCOVERY.into());
        *fetcher.failing_endpoint_kind.lock().unwrap() = Some(KIND_MARMOT_KEY_PACKAGE);
        let result = app
            .resolve_compatible_member_key_packages(
                vec![account.account_id_hex.clone()],
                &requirements,
                crate::directory::MemberResolutionPurpose::CommitFresh,
            )
            .await;
        assert!(matches!(
            result,
            Err(AppError::Session(cgka_session::SessionError::Engine(
                cgka_traits::EngineError::MissingRequiredCapabilities { .. }
            )))
        ));
    }
    {
        let mut routes = fetcher.events_by_endpoint.lock().unwrap();
        routes
            .get_mut(OUTBOX)
            .unwrap()
            .iter_mut()
            .find(|e| e.kind == KIND_MARMOT_KEY_PACKAGE)
            .unwrap()
            .content = "not base64".into();
    }
    assert!(matches!(
        app.resolve_member_key_packages(&[&account.account_id_hex])
            .await,
        Err(AppError::InvalidKeyPackageEvent(_))
    ));
}

#[tokio::test]
async fn invite_recovery_diagnostic_cache_event_ids_are_canonical_or_ineligible() {
    for empty in [false, true] {
        let (_directory, app, accounts, fetcher) = discovery_fixture(1).await;
        let account = &accounts[0];
        let mut cached = app
            .fetch_latest_key_package_for_account_id(&account.account_id_hex, vec![])
            .await
            .unwrap();
        let mut future = package(&fetcher, account);
        future.created_at = u64::MAX;
        future.id = "a7".repeat(32);
        {
            let mut routes = fetcher.events_by_endpoint.lock().unwrap();
            routes
                .get_mut(DISCOVERY)
                .unwrap()
                .retain(|e| e.kind != KIND_MARMOT_KEY_PACKAGE);
            routes.get_mut(OUTBOX).unwrap().push(future);
        }
        // A newer cache record makes the fixture's proposed cache metadata
        // win the existing merge policy without changing protocol bytes.
        cached.created_at += 1;
        let canonical_id = cached.key_package_event_id.clone();
        cached.key_package_event_id = if empty {
            String::new()
        } else {
            canonical_id.to_ascii_uppercase()
        };
        app.remember_directory_key_package(&cached).unwrap();
        let result = app
            .fetch_latest_key_package_for_account_id(&account.account_id_hex, vec![])
            .await;
        if empty {
            assert!(matches!(result, Err(AppError::MissingKeyPackage(_))));
        } else {
            assert_eq!(result.unwrap().key_package_event_id, canonical_id);
        }
    }
}

async fn assert_recovery_keeps_checked_candidate_across_clock_boundary(membership: bool) {
    let (_directory, mut app, accounts, fetcher) = discovery_fixture(1).await;
    let account = &accounts[0];
    let published = package(&fetcher, account);
    let now = published.created_at;
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(now));
    app.directory_test_clock = Some(clock.clone());
    let future_at = now + app.config.directory_max_future_skew.as_secs() + 1;
    let sign_candidate = |slot: &str, created_at: u64| {
        let mut tags = published.tags.clone();
        tags.iter_mut().find(|tag| tag[0] == "d").unwrap()[1] = slot.into();
        let event = EventBuilder::new(
            Kind::from(KIND_MARMOT_KEY_PACKAGE as u16),
            &published.content,
        )
        .tags(tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
        .custom_created_at(NostrTimestamp::from_secs(created_at))
        .finalize(
            &app.account_home()
                .load_signing_keys(&account.label)
                .unwrap(),
        )
        .unwrap();
        NostrTransportEvent::from_nostr_event(&event).unwrap()
    };
    let checked = sign_candidate("checked-slot", now);
    let future = sign_candidate("future-slot", future_at);
    let deletion = signed_deletion(&app, account, "e", future.id.clone(), future_at);
    {
        let mut routes = fetcher.events_by_endpoint.lock().unwrap();
        routes
            .get_mut(DISCOVERY)
            .unwrap()
            .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        routes
            .get_mut(DISCOVERY)
            .unwrap()
            .extend([checked.clone(), future.clone()]);
        routes.get_mut(OUTBOX).unwrap().push(deletion);
    }
    let (entered, release) = fetcher.hold_fetches_for_kind(5);
    let lookup = {
        let app = app.clone();
        let account_id = account.account_id_hex.clone();
        tokio::spawn(async move {
            if membership {
                let packages = app
                    .resolve_member_key_packages(&[&account_id])
                    .await
                    .unwrap();
                hex::encode(packages[0].source.as_ref().unwrap().event_id.as_slice())
            } else {
                app.fetch_latest_key_package_for_account_id(&account_id, vec![])
                    .await
                    .unwrap()
                    .key_package_event_id
            }
        })
    };
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    // This advances the actual selection clock, not just Tokio's timeout clock.
    clock.store(now + 2, std::sync::atomic::Ordering::SeqCst);
    let records = [checked.clone(), future.clone()]
        .into_iter()
        .map(|event| RelayEventRecord {
            event,
            endpoints: vec![TransportEndpoint(DISCOVERY.into())],
        })
        .collect::<Vec<_>>();
    assert_eq!(
        crate::key_package_records::preferred_fresh_key_package_from_records(
            &account.account_id_hex,
            &records,
            app.directory_freshness(),
            None,
        )
        .unwrap()
        .value
        .unwrap()
        .fetched
        .key_package_event_id,
        future.id
    );
    release.notify_one();
    let returned = tokio::time::timeout(Duration::from_secs(5), lookup)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        returned, checked.id,
        "must return the deletion-checked identity"
    );
    let requests = fetcher.requests.lock().unwrap();
    let proof_queries = requests
        .iter()
        .flat_map(|request| &request.queries)
        .filter(|query| query.kind == 5)
        .collect::<Vec<_>>();
    assert!(proof_queries.iter().any(|query| {
        query
            .reference
            .as_ref()
            .is_some_and(|(name, value)| *name == 'e' && value == &checked.id)
    }));
    assert!(!proof_queries.iter().any(|query| {
        query
            .reference
            .as_ref()
            .is_some_and(|(name, value)| *name == 'e' && value == &future.id)
    }));
}

#[tokio::test]
async fn invite_recovery_membership_keeps_checked_candidate_across_clock_boundary() {
    assert_recovery_keeps_checked_candidate_across_clock_boundary(true).await;
}

#[tokio::test]
async fn invite_recovery_direct_lookup_keeps_checked_candidate_across_clock_boundary() {
    assert_recovery_keeps_checked_candidate_across_clock_boundary(false).await;
}
