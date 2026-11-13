//! Whole-roster KeyPackage resolution over a real `MarmotApp` and its relay
//! fixtures. The directory's own resolution tests stay with the directory.

use std::time::{Duration, Instant};

use nostr_directory::MEMBER_PREWARM_CACHE_TTL;
use nostr_directory::MemberResolutionPurpose;
use nostr_directory::{MemberResolutionOutcome, MemberResolutionPolicy, MemberResolutionStatus};

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
    assert_eq!(
        absent.member_outcomes,
        ordered
            .into_iter()
            .map(|index| MemberResolutionOutcome {
                account_id_hex: accounts[index].account_id_hex.clone(),
                status: MemberResolutionStatus::MissingKeyPackage,
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
