// Enabling an app component in a group that predates it, driven by account
// maintenance: a stale own leaf is refreshed by a self-update at a persisted,
// randomized due time, and an admin device then activates an eligible
// automatic-mode component at a second persisted due time.
// `marmot.group.avatar-url.v1` stands in for the new component: it is optional
// for new groups, so a group created before the "upgrade" does not require it.

fn component_migration_session(
    path: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    identity: &[u8],
    upgraded: bool,
) -> AccountDeviceSession {
    use cgka_traits::app_components::{
        ActivatableAppComponent, ComponentActivationMode, GROUP_AVATAR_URL_COMPONENT_ID,
        GroupAvatarUrlV1, encode_group_avatar_url_v1,
    };
    let keys = deterministic_nostr_keys(identity);
    let mut components = default_group_components();
    let mut activatable = Vec::new();
    if upgraded {
        components.insert(GROUP_AVATAR_URL_COMPONENT_ID);
        activatable.push(ActivatableAppComponent {
            component_id: GROUP_AVATAR_URL_COMPONENT_ID,
            initial_state: encode_group_avatar_url_v1(&GroupAvatarUrlV1 {
                url: String::new(),
                dim: Vec::new(),
                thumbhash: Vec::new(),
            })
            .unwrap(),
            mode: ComponentActivationMode::Automatic,
        });
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
        .supported_app_components(components)
        .activatable_app_components(activatable),
    )
    .unwrap()
}

#[tokio::test]
async fn maintenance_refreshes_a_stale_leaf_then_activates_the_component() {
    use cgka_traits::app_components::{
        APP_COMPONENTS_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID, decode_components_list,
    };
    const WINDOW_72H: u64 = 72 * 60 * 60;
    const WINDOW_12H: u64 = 12 * 60 * 60;

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
    // Keep the periodic rotation out of the way so only the refresh rotates.
    state.periodic_enrolled = false;
    state.next_periodic_rotation_at = None;
    old.session().put_group_maintenance(&state).unwrap();
    drop(old);

    let start = 100_000u64;
    let wall = Arc::new(TestWallClock::new(start));
    let mut runtime = AccountDeviceRuntime::new(
        component_migration_session(database, &key, b"alice", true),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).required_acks(1).with_group_route(
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

    // First tick samples a refresh due time inside the window and does not
    // rotate yet.
    runtime.run_due_maintenance().await.unwrap();
    let due = runtime
        .session()
        .group_maintenance(&group_id)
        .unwrap()
        .unwrap()
        .leaf_refresh_due_at
        .expect("a stale leaf schedules a refresh");
    assert!(due.0 >= start && due.0 <= start + WINDOW_72H);
    assert!(
        runtime
            .session()
            .maintenance_obligations_for_group(&group_id)
            .unwrap()
            .is_empty()
    );
    let epoch_before = runtime.session().epoch(&group_id).unwrap();

    // At the due time the refresh self-update runs and the leaf is current.
    wall.set(due.0);
    for _ in 0..4 {
        runtime.run_due_maintenance().await.unwrap();
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

    // Every leaf now advertises the component and alice is the admin: the
    // next tick (the throttle allows it once the window passes) samples an
    // activation due time.
    wall.set(due.0 + 1);
    runtime = runtime.with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock(AtomicU64::new(60 * 60 * 1_000))),
        Arc::new(TestRandom::new(0)),
    );
    runtime.run_due_maintenance().await.unwrap();
    let state = runtime
        .session()
        .group_maintenance(&group_id)
        .unwrap()
        .unwrap();
    assert_eq!(state.leaf_refresh_due_at, None);
    let activation_due = state
        .component_activation_due_at
        .expect("an eligible automatic component schedules activation");
    let sampled_at = due.0 + 1;
    assert!(activation_due.0 >= sampled_at && activation_due.0 <= sampled_at + WINDOW_12H);

    wall.set(activation_due.0);
    runtime.run_due_maintenance().await.unwrap();
    let required = decode_components_list(
        &runtime
            .session()
            .app_component(&group_id, APP_COMPONENTS_COMPONENT_ID)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(
        required.contains(&GROUP_AVATAR_URL_COMPONENT_ID),
        "the admin device activated the eligible component"
    );
    assert_eq!(
        runtime
            .session()
            .group_maintenance(&group_id)
            .unwrap()
            .unwrap()
            .component_activation_due_at,
        None
    );
}
