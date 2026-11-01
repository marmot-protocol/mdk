// Refreshing a stale own leaf, driven by account maintenance: a group whose own
// leaf advertises fewer app components than the build supports gets a
// self-update at a persisted, randomized due time.
// `marmot.group.avatar-url.v1` stands in for the new component: it is optional
// for new groups, so a group created before the "upgrade" does not require it.

fn component_migration_session(
    path: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    identity: &[u8],
    upgraded: bool,
) -> AccountDeviceSession {
    use cgka_traits::app_components::GROUP_AVATAR_URL_COMPONENT_ID;
    let keys = deterministic_nostr_keys(identity);
    let mut components = default_group_components();
    if upgraded {
        components.insert(GROUP_AVATAR_URL_COMPONENT_ID);
    }
    AccountDeviceSession::open(
        SessionConfig::new(
            path,
            SqlCipherKey::new(key.as_secret_str()).unwrap(),
            pad32(identity),
            Box::new(MockPeeler),
        )
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner { keys }))
        .protocol_profile(ProtocolProfile::Current)
        .supported_app_components(components),
    )
    .unwrap()
}

#[tokio::test]
async fn maintenance_refreshes_a_stale_leaf_at_a_persisted_random_time() {
    use cgka_traits::app_components::GROUP_AVATAR_URL_COMPONENT_ID;
    const WINDOW_5_DAYS: u64 = 5 * 24 * 60 * 60;

    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("component migration key").unwrap();
    let mut old = AccountDeviceRuntime::new(
        component_migration_session(database.clone(), &key, b"alice", false),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        RecordingKeyPackages::default(),
    );
    let (group_id, created) = old
        .create_group(CreateGroupRequest {
            name: "predates the component".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    assert!(created.failures.is_empty());
    let mut state = old.session().group_maintenance(&group_id).unwrap().unwrap();
    // Not periodically enrolled: the refresh must not depend on enrollment,
    // and no periodic rotation can stand in for it.
    state.periodic_enrolled = false;
    state.next_periodic_rotation_at = None;
    old.session().put_group_maintenance(&state).unwrap();
    drop(old);

    let start = 100_000u64;
    let wall = Arc::new(TestWallClock::new(start));
    let mut runtime = AccountDeviceRuntime::new(
        component_migration_session(database.clone(), &key, b"alice", true),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .required_acks(1)
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![TransportEndpoint("wss://group-a.example".into())],
            ),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    )
    .with_maintenance_timing(MaintenanceTiming::immediate());
    assert_eq!(
        runtime
            .session()
            .own_leaf_missing_app_components(&group_id)
            .unwrap()
            .ids
            .into_iter()
            .collect::<Vec<_>>(),
        vec![GROUP_AVATAR_URL_COMPONENT_ID]
    );

    // The first tick samples a due time inside the window and does not rotate.
    runtime.run_due_maintenance().await.unwrap();
    let due = runtime
        .session()
        .group_maintenance(&group_id)
        .unwrap()
        .unwrap()
        .leaf_refresh_due_at
        .expect("a stale leaf schedules a refresh");
    assert!(due.0 >= start && due.0 <= start + WINDOW_5_DAYS);
    assert!(
        runtime
            .session()
            .maintenance_obligations_for_group(&group_id)
            .unwrap()
            .is_empty()
    );
    let epoch_before = runtime.session().epoch(&group_id).unwrap();

    // A restart keeps the sampled due time instead of resampling it.
    drop(runtime);
    let mut runtime = AccountDeviceRuntime::new(
        component_migration_session(database, &key, b"alice", true),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .required_acks(1)
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![TransportEndpoint("wss://group-a.example".into())],
            ),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(1_000)),
    )
    .with_maintenance_timing(MaintenanceTiming::immediate());
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        runtime
            .session()
            .group_maintenance(&group_id)
            .unwrap()
            .unwrap()
            .leaf_refresh_due_at,
        Some(due)
    );

    // At the due time the refresh becomes an ordinary periodic obligation;
    // once its contention jitter elapses the self-update runs and the leaf is
    // current.
    wall.set(due.0);
    for _ in 0..4 {
        runtime.run_due_maintenance().await.unwrap();
        if let Some(not_before) = runtime
            .session()
            .maintenance_obligations_for_group(&group_id)
            .unwrap()
            .iter()
            .find_map(|obligation| obligation.not_before)
        {
            wall.set(wall.now().0.max(not_before.0));
        }
        if runtime
            .session()
            .own_leaf_missing_app_components(&group_id)
            .unwrap()
            .is_empty()
        {
            break;
        }
    }
    assert!(
        runtime
            .session()
            .own_leaf_missing_app_components(&group_id)
            .unwrap()
            .is_empty(),
        "the refresh self-update re-advertised the supported set"
    );
    assert!(runtime.session().epoch(&group_id).unwrap() > epoch_before);
    assert_eq!(
        runtime
            .session()
            .group_maintenance(&group_id)
            .unwrap()
            .unwrap()
            .leaf_refresh_due_at,
        None
    );
}

#[tokio::test]
async fn a_current_leaf_in_a_group_without_a_maintenance_row_writes_no_row() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("component migration no-row key").unwrap();
    let mut runtime = AccountDeviceRuntime::new(
        component_migration_session(database.clone(), &key, b"alice", true),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        RecordingKeyPackages::default(),
    );
    let (group_id, _) = runtime
        .create_group(CreateGroupRequest {
            name: "no maintenance row".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    drop(runtime);
    // An old group with no enrollment row, whose leaf is already current.
    SqliteAccountStorage::open_encrypted(&database, &key)
        .unwrap()
        .delete_group_maintenance(&group_id)
        .unwrap();

    let mut runtime = AccountDeviceRuntime::new(
        component_migration_session(database, &key, b"alice", true),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        Arc::new(TestWallClock::new(100_000)),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    assert!(
        runtime
            .session()
            .own_leaf_missing_app_components(&group_id)
            .unwrap()
            .is_empty()
    );
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        runtime.session().group_maintenance(&group_id).unwrap(),
        None,
        "nothing to schedule, so no row is created"
    );
}
