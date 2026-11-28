// Refreshing a stale own leaf, driven by account maintenance: a group whose own
// leaf advertises fewer app components than the build supports gets a
// self-update with persisted contention jitter.
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
            Arc::new(MockSealer),
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

    let dir = relaxed_storage_dir().unwrap();
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
        Arc::new(TestRandom::new(15_000)),
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

    // The first tick persists the obligation but does not rotate yet.
    let epoch_before = runtime.session().epoch(&group_id).unwrap();
    runtime.run_due_maintenance().await.unwrap();
    let pending = runtime
        .session()
        .maintenance_obligations_for_group(&group_id)
        .unwrap();
    assert_eq!(pending.len(), 1);
    let due = pending[0]
        .not_before
        .expect("queued with contention jitter");
    assert!(due.0 > start && due.0 <= start + 15 * 60);
    assert_eq!(runtime.session().epoch(&group_id).unwrap(), epoch_before);

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
            .maintenance_obligations_for_group(&group_id)
            .unwrap(),
        pending
    );

    // The queued self-update publishes after its contention delay.
    wall.set(due.0);
    runtime.run_due_maintenance().await.unwrap();
    assert!(
        runtime
            .session()
            .own_leaf_missing_app_components(&group_id)
            .unwrap()
            .is_empty(),
        "the refresh self-update re-advertised the supported set"
    );
    assert_eq!(
        runtime.session().epoch(&group_id).unwrap().0,
        epoch_before.0 + 1
    );
}

#[tokio::test]
async fn a_current_leaf_in_a_group_without_a_maintenance_row_writes_no_row() {
    let dir = relaxed_storage_dir().unwrap();
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

fn migration_group_request(name: impl Into<String>) -> CreateGroupRequest {
    CreateGroupRequest {
        name: name.into(),
        description: String::new(),
        members: Vec::new(),
        required_features: Vec::new(),
        app_components: Vec::new(),
        initial_admins: Vec::new(),
    }
}

fn migration_runtime(
    database: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    wall: Arc<TestWallClock>,
    routed_groups: &[GroupId],
    jitter_ms: u64,
) -> AccountDeviceRuntime<RecordingAdapter, StaticTransportRouting, RecordingKeyPackages> {
    let mut routing = StaticTransportRouting::new(vec![]).required_acks(1);
    for group_id in routed_groups {
        routing = routing.with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![TransportEndpoint("wss://group-a.example".into())],
        );
    }
    AccountDeviceRuntime::new(
        component_migration_session(database, key, b"alice", true),
        RecordingAdapter::default(),
        routing,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(jitter_ms)),
    )
    .with_maintenance_timing(MaintenanceTiming::immediate())
}

#[tokio::test]
async fn maintenance_paces_overdue_self_updates_across_passes() {
    let dir = relaxed_storage_dir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("component migration pacing key").unwrap();
    let mut old = AccountDeviceRuntime::new(
        component_migration_session(database.clone(), &key, b"alice", false),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        RecordingKeyPackages::default(),
    );
    let mut periodic_groups = Vec::new();
    for index in 0..5 {
        let (group_id, created) = old
            .create_group(migration_group_request(format!(
                "predates the component {index}"
            )))
            .await
            .unwrap();
        assert!(created.failures.is_empty());
        let mut state = old.session().group_maintenance(&group_id).unwrap().unwrap();
        state.periodic_enrolled = false;
        state.next_periodic_rotation_at = None;
        old.session().put_group_maintenance(&state).unwrap();
        periodic_groups.push(group_id);
    }
    drop(old);

    let start = 100_000u64;
    let wall = Arc::new(TestWallClock::new(start));
    let mut runtime = migration_runtime(database.clone(), &key, wall.clone(), &periodic_groups, 15_000);

    // First pass queues all five periodic leaf-refresh obligations and moves
    // them from Quiet into Jitter (`not_before = start + 15`).
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(runtime.take_maintenance_activity().self_update_attempts, 0);

    // Create a current-leaf group after the periodic backlog so its manual
    // obligation has a later `created_at` than every periodic one.
    wall.set(start + 10);
    let (manual_due_group, _) = runtime
        .create_group(migration_group_request("manual due"))
        .await
        .unwrap();
    drop(runtime);

    let all_routed: Vec<GroupId> = periodic_groups
        .iter()
        .chain([&manual_due_group])
        .cloned()
        .collect();
    let mut runtime = migration_runtime(database, &key, wall.clone(), &all_routed, 15_000);

    // Advance `manual_due_group` into Jitter before the periodic backlog falls
    // due (`start + 15`).
    runtime
        .schedule_manual_self_update(&manual_due_group)
        .unwrap();
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(runtime.take_maintenance_activity().self_update_attempts, 0);

    // Enqueue a Periodic obligation in Quiet created at `start + 20` so it
    // sorts strictly AFTER the two budget-consuming obligations on pass 1.
    wall.set(start + 20);
    let (late_quiet_group, _) = runtime
        .create_group(migration_group_request("late quiet after cap"))
        .await
        .unwrap();
    let mut late_quiet_state = runtime
        .session()
        .group_maintenance(&late_quiet_group)
        .unwrap()
        .unwrap();
    late_quiet_state.periodic_enrolled = true;
    late_quiet_state.next_periodic_rotation_at = Some(Timestamp(start + 20));
    runtime
        .session()
        .put_group_maintenance(&late_quiet_state)
        .unwrap();

    let periodic_epochs_before: Vec<_> = periodic_groups
        .iter()
        .map(|group_id| runtime.session().epoch(group_id).unwrap().0)
        .collect();
    let manual_due_epoch_before = runtime.session().epoch(&manual_due_group).unwrap().0;
    let late_quiet_epoch_before = runtime.session().epoch(&late_quiet_group).unwrap().0;

    // Pass 1: six obligations are due in Jitter (one Manual + five Periodic),
    // and `late_quiet_group` is a Periodic obligation created at `start + 20`
    // (so it sorts strictly AFTER the two budget-consuming obligations).
    // Only two SelfUpdate commits fire: the Manual group first and one
    // Periodic group. The remaining four due Periodic obligations stay cleanly
    // in Jitter, and `late_quiet_group` still advances from Quiet to Jitter.
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(runtime.take_maintenance_activity().self_update_attempts, 2);
    assert_eq!(
        runtime.session().epoch(&manual_due_group).unwrap().0,
        manual_due_epoch_before + 1,
        "manual self-update must not starve behind an older periodic backlog"
    );
    assert_eq!(
        runtime.session().epoch(&late_quiet_group).unwrap().0,
        late_quiet_epoch_before
    );
    let late_quiet_obligations = runtime
        .session()
        .maintenance_obligations_for_group(&late_quiet_group)
        .unwrap();
    assert_eq!(late_quiet_obligations.len(), 1);
    assert_eq!(
        late_quiet_obligations[0].phase,
        cgka_traits::MaintenancePhase::Jitter,
        "non-sending transitions after the cap is exhausted must still advance"
    );

    let mut rotated_periodic = 0usize;
    let mut deferred_periodic = 0usize;
    for (group_id, before) in periodic_groups.iter().zip(&periodic_epochs_before) {
        let now_epoch = runtime.session().epoch(group_id).unwrap().0;
        if now_epoch == before + 1 {
            rotated_periodic += 1;
        } else {
            assert_eq!(now_epoch, *before);
            let pending = runtime
                .session()
                .maintenance_obligations_for_group(group_id)
                .unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(
                pending[0].phase,
                cgka_traits::MaintenancePhase::Jitter,
                "paced obligations stay in Jitter instead of faking a Retry failure"
            );
            assert_eq!(pending[0].attempt_count, 0);
            assert_eq!(pending[0].last_failure_code, None);
            deferred_periodic += 1;
        }
    }
    assert_eq!(rotated_periodic, 1);
    assert_eq!(deferred_periodic, 4);

    let due = runtime.maintenance_due(&[]).unwrap();
    assert!(
        due.at.is_some_and(|at| at.0 <= start + 20),
        "remaining paced obligations stay visible to maintenance_due: {due:?}"
    );

    // Subsequent passes drain the remaining four periodic obligations at <= 2
    // per pass (keeping `wall` before `late_quiet_group`'s `not_before`).
    wall.set(start + 21);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(runtime.take_maintenance_activity().self_update_attempts, 2);

    wall.set(start + 22);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(runtime.take_maintenance_activity().self_update_attempts, 2);

    for (group_id, before) in periodic_groups.iter().zip(&periodic_epochs_before) {
        assert_eq!(runtime.session().epoch(group_id).unwrap().0, before + 1);
        assert!(
            runtime
                .session()
                .own_leaf_missing_app_components(group_id)
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn failing_self_updates_do_not_starve_healthy_groups_under_pass_cap() {
    let dir = relaxed_storage_dir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("component migration failing starvation key").unwrap();
    let mut old = AccountDeviceRuntime::new(
        component_migration_session(database.clone(), &key, b"alice", false),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        RecordingKeyPackages::default(),
    );
    let mut broken_groups = Vec::new();
    for index in 0..2 {
        let (group_id, _) = old
            .create_group(migration_group_request(format!("unrouted {index}")))
            .await
            .unwrap();
        let mut state = old.session().group_maintenance(&group_id).unwrap().unwrap();
        state.periodic_enrolled = false;
        state.next_periodic_rotation_at = None;
        old.session().put_group_maintenance(&state).unwrap();
        broken_groups.push(group_id);
    }
    let mut healthy_groups = Vec::new();
    for index in 0..2 {
        let (group_id, _) = old
            .create_group(migration_group_request(format!("healthy {index}")))
            .await
            .unwrap();
        let mut state = old.session().group_maintenance(&group_id).unwrap().unwrap();
        state.periodic_enrolled = false;
        state.next_periodic_rotation_at = None;
        old.session().put_group_maintenance(&state).unwrap();
        healthy_groups.push(group_id);
    }
    drop(old);

    let start = 100_000u64;
    let wall = Arc::new(TestWallClock::new(start));
    // Only the healthy groups have routes; the two older broken groups fail on
    // every send attempt with `MissingGroupRoute` before retaining a fanout.
    let mut runtime =
        migration_runtime(database.clone(), &key, wall.clone(), &healthy_groups, 15_000);

    // Queue all four obligations. Give the two broken groups earlier
    // `not_before` deadlines and Manual priority so they sort strictly first
    // on pass 1 and consume both slots.
    runtime.run_due_maintenance().await.unwrap();
    for group_id in &broken_groups {
        let mut obligation = runtime
            .session()
            .maintenance_obligations_for_group(group_id)
            .unwrap()
            .pop()
            .unwrap();
        obligation.trigger = cgka_traits::MaintenanceTrigger::Manual;
        obligation.not_before = Some(Timestamp(start + 5));
        runtime
            .session()
            .put_maintenance_obligation(&obligation)
            .unwrap();
    }

    let healthy_epochs_before: Vec<_> = healthy_groups
        .iter()
        .map(|group_id| runtime.session().epoch(group_id).unwrap().0)
        .collect();

    // Pass 1: the two broken Manual obligations sort first, fail without
    // confirming, and consume both slots (`attempt_count` advances 0 -> 1).
    wall.set(start + 20);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(runtime.take_maintenance_activity().self_update_attempts, 2);
    for group_id in &broken_groups {
        let obligation = runtime
            .session()
            .maintenance_obligations_for_group(group_id)
            .unwrap()
            .pop()
            .unwrap();
        assert!(matches!(
            obligation.phase,
            cgka_traits::MaintenancePhase::PendingPublication
                | cgka_traits::MaintenancePhase::Retry
        ));
        assert_eq!(obligation.attempt_count, 1);
    }
    for (group_id, before) in healthy_groups.iter().zip(&healthy_epochs_before) {
        assert_eq!(runtime.session().epoch(group_id).unwrap().0, *before);
    }

    // Reopen to prove fairness is durable across restarts: on pass 2, the two
    // healthy obligations (`attempt_count == 0`) sort ahead of the failing
    // Manual obligations (`attempt_count == 1`) and both rotate.
    drop(runtime);
    let mut runtime = migration_runtime(database, &key, wall.clone(), &healthy_groups, 15_000);
    wall.set(start + 35);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(runtime.take_maintenance_activity().self_update_attempts, 2);
    for (group_id, before) in healthy_groups.iter().zip(&healthy_epochs_before) {
        assert_eq!(
            runtime.session().epoch(group_id).unwrap().0,
            before + 1,
            "healthy groups must rotate instead of starving behind repeatedly failing groups"
        );
        assert!(
            runtime
                .session()
                .own_leaf_missing_app_components(group_id)
                .unwrap()
                .is_empty()
        );
    }

    // Pass 3: with the healthy backlog drained, the broken obligations still
    // get retried rather than abandoned (`attempt_count` advances 1 -> 2).
    wall.set(start + 50);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(runtime.take_maintenance_activity().self_update_attempts, 2);
    for group_id in &broken_groups {
        let obligation = runtime
            .session()
            .maintenance_obligations_for_group(group_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(obligation.attempt_count, 2);
    }
}
