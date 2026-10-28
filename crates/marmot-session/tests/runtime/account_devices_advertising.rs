// Advertising `marmot.group.account-devices.v1` (mdk#2628, item 2.2). A build
// that starts advertising it replaces this device's published KeyPackage and
// refreshes its own leaf in each existing group through the randomized
// stale-leaf refresh. Nothing makes a group require it.

/// A current-profile device of `account`; its build advertises
/// account-devices when `upgraded`, on top of what it supported before.
fn account_devices_session(
    path: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    account: &[u8],
    upgraded: bool,
) -> AccountDeviceSession {
    use cgka_traits::app_components::ACCOUNT_DEVICES_COMPONENT_ID;
    let mut components = default_group_components();
    if upgraded {
        components.insert(ACCOUNT_DEVICES_COMPONENT_ID);
    }
    AccountDeviceSession::open(
        SessionConfig::new(
            path,
            SqlCipherKey::new(key.as_secret_str()).unwrap(),
            pad32(account),
            Box::new(MockPeeler),
        )
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
            keys: deterministic_nostr_keys(account),
        }))
        .protocol_profile(ProtocolProfile::Current)
        .supported_app_components(components),
    )
    .unwrap()
}

/// Accounts whose leaf in `group_id` does not advertise `component_id`, as
/// `session` sees the group.
fn not_advertising(
    session: &AccountDeviceSession,
    group_id: &GroupId,
    component_id: u16,
) -> Vec<MemberId> {
    session
        .app_component_support_blockers(group_id, component_id)
        .unwrap()
}

/// Maintenance randomness that steps a day per draw, so two groups that
/// sample a refresh time never draw the same one.
struct DayStepRandom(AtomicU64);

impl MaintenanceRandom for DayStepRandom {
    fn next_u64(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed) * 24 * 60 * 60
    }
}

#[tokio::test]
async fn an_upgrade_replaces_the_published_key_package_with_one_advertising_account_devices() {
    use cgka_traits::app_components::ACCOUNT_DEVICES_COMPONENT_ID;
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot account-devices upgrade").unwrap();
    let database = dir.path().join("alice.sqlite");
    // KeyPackage lifetimes come from the system clock.
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = RecordingKeyPackages::default();
    let open = |upgraded| {
        slot_runtime(
            account_devices_session(&database, &key, b"alice", upgraded),
            publisher.clone(),
            &wall,
            0,
            &[KEY_ENDPOINT],
        )
    };

    let mut runtime = open(false);
    let before = runtime.publish_fresh_key_package().await.unwrap();
    assert!(!advertised_components(&before).contains(&ACCOUNT_DEVICES_COMPONENT_ID));
    let published = slot_lifecycle(&runtime);
    drop(runtime);

    // The upgraded build owes a replacement, and its maintenance publishes
    // one advertising account-devices into the same slot.
    wall.set(wall.now().0 + 60);
    let mut runtime = open(true);
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    let upgraded = slot_lifecycle(&runtime);
    let current = upgraded.current_key_package.clone().unwrap();
    assert_ne!(current, before);
    assert!(advertised_components(&current).contains(&ACCOUNT_DEVICES_COMPONENT_ID));
    assert_eq!(upgraded.stable_slot_id, published.stable_slot_id);
    let publications = publisher.publications();
    assert_eq!(publications.len(), 2);
    assert!(
        publications
            .iter()
            .all(|publication| publication.slot_id == published.stable_slot_id),
        "the replacement takes the one slot's place"
    );

    // The superseded KeyPackage is not deleted: an inviter may still hold
    // it, so its key is held for the grace period after the replacement.
    let retained = retained_entry(&upgraded, &before);
    assert!(!retained.consumed);
    assert_eq!(retained.authored_event_id, published.authored_event_id);
    assert_eq!(
        retained.delete_at(),
        Timestamp(wall.now().0 + cgka_traits::KEY_PACKAGE_REPLACEMENT_GRACE_SECS)
    );

    // The new KeyPackage is current for the upgraded build.
    drop(runtime);
    let runtime = open(true);
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
}

/// An upgraded member's leaf in each existing group gains account-devices at
/// its own randomized time. The refresh is an ordinary self-update: the other
/// member accepts it, the leaf keeps every component the group requires, and
/// the group still does not require account-devices.
#[tokio::test]
async fn an_upgrade_refreshes_each_existing_leaf_at_its_own_random_time() {
    use cgka_traits::app_components::ACCOUNT_DEVICES_COMPONENT_ID;
    const WINDOW_5_DAYS: u64 = 5 * 24 * 60 * 60;

    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("leaf refresh account-devices upgrade").unwrap();
    let alice_database = dir.path().join("alice.sqlite");
    // Bob is already on the new build; Alice made both groups before she was.
    let mut bob = account_devices_session(dir.path().join("bob.sqlite"), &key, b"bob", true);
    let mut alice = account_devices_session(&alice_database, &key, b"alice", false);
    let mut groups = Vec::new();
    for name in ["first", "second"] {
        let bob_kp = bob.fresh_key_package().await.unwrap();
        let welcome = welcome_for_key_package(&mut alice, &bob.self_id(), bob_kp, name).await;
        let joined = bob.ingest(welcome).await.unwrap();
        assert_eq!(joined.outcome, cgka_traits::IngestOutcome::Processed);
        groups.push(joined_group(&joined));
    }
    let required: Vec<_> = groups
        .iter()
        .map(|group_id| {
            alice
                .group_record(group_id)
                .unwrap()
                .required_capabilities
                .app_components
        })
        .collect();
    for (group_id, required) in groups.iter().zip(&required) {
        assert!(!required.contains(ACCOUNT_DEVICES_COMPONENT_ID));
        assert_eq!(
            not_advertising(&bob, group_id, ACCOUNT_DEVICES_COMPONENT_ID),
            vec![alice.self_id()]
        );
    }
    drop(alice);

    let start = 100_000u64;
    let wall = Arc::new(TestWallClock::new(start));
    let adapter = RecordingAdapter::default();
    let mut routing = StaticTransportRouting::new(vec![]).required_acks(1);
    for group_id in &groups {
        routing = routing.with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![TransportEndpoint("wss://group.example".into())],
        );
    }
    let mut runtime = AccountDeviceRuntime::new(
        account_devices_session(&alice_database, &key, b"alice", true),
        adapter.clone(),
        routing,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(DayStepRandom(AtomicU64::new(1))),
    )
    .with_maintenance_timing(MaintenanceTiming::immediate());
    let epochs_before: Vec<_> = groups
        .iter()
        .map(|group_id| runtime.session().epoch(group_id).unwrap())
        .collect();

    // The first tick only samples a due time for each group.
    runtime.run_due_maintenance().await.unwrap();
    let mut order: Vec<_> = groups
        .iter()
        .map(|group_id| {
            let at = refresh_due_at(&runtime, group_id).expect("each stale leaf schedules a refresh");
            assert!(at.0 >= start && at.0 <= start + WINDOW_5_DAYS);
            (at, group_id.clone())
        })
        .collect();
    order.sort_by_key(|(at, _)| *at);
    let [(early_at, early), (late_at, late)] = &order[..] else {
        unreachable!()
    };
    assert!(late_at.0 > early_at.0 + 60 * 60, "{early_at:?} {late_at:?}");
    assert!(adapter.publishes().is_empty());

    // At the earlier time only that group's leaf is refreshed.
    wall.set(early_at.0);
    refresh_leaf(&mut runtime, &wall, early).await;
    assert!(leaf_is_stale(&runtime, late), "the other group waits for its own time");
    assert_eq!(refresh_due_at(&runtime, late), Some(*late_at));
    assert!(
        runtime
            .session()
            .maintenance_obligations_for_group(late)
            .unwrap()
            .is_empty()
    );
    let late_index = groups.iter().position(|group_id| group_id == late).unwrap();
    assert_eq!(
        runtime.session().epoch(late).unwrap(),
        epochs_before[late_index]
    );

    wall.set(late_at.0);
    refresh_leaf(&mut runtime, &wall, late).await;

    // Bob accepts both self-updates. Alice's leaf now advertises
    // account-devices and everything each group requires, and neither group
    // requires account-devices.
    let commits: Vec<_> = adapter
        .publishes()
        .into_iter()
        .map(|publish| publish.message)
        .filter(|message| matches!(message.envelope, TransportEnvelope::GroupMessage { .. }))
        .collect();
    assert_eq!(commits.len(), 2);
    for commit in commits {
        // Held for convergence settlement like any Commit, then applied.
        let ingested = bob.ingest(commit).await.unwrap();
        assert!(
            matches!(
                ingested.outcome,
                cgka_traits::IngestOutcome::Buffered { .. } | cgka_traits::IngestOutcome::Processed
            ),
            "{:?}",
            ingested.outcome
        );
    }
    tokio::time::sleep(std::time::Duration::from_millis(
        cgka_engine::canonicalization::V1_SETTLEMENT_QUIESCENCE_MS + 200,
    ))
    .await;
    for (group_id, required) in groups.iter().zip(&required) {
        bob.advance_convergence(group_id).await.unwrap();
        let alice_epoch = runtime.session().epoch(group_id).unwrap();
        assert_eq!(bob.epoch(group_id).unwrap(), alice_epoch);
        let index = groups.iter().position(|id| id == group_id).unwrap();
        assert_eq!(alice_epoch.0, epochs_before[index].0 + 1);
        for component_id in required.ids.iter().chain([&ACCOUNT_DEVICES_COMPONENT_ID]) {
            assert!(not_advertising(&bob, group_id, *component_id).is_empty());
        }
        for record in [
            bob.group_record(group_id).unwrap(),
            runtime.session().group_record(group_id).unwrap(),
        ] {
            assert_eq!(&record.required_capabilities.app_components, required);
        }
    }
}

/// A device that does not advertise account-devices joins a group whose
/// creator does, and the group does not require it.
#[tokio::test]
async fn a_device_that_does_not_advertise_account_devices_still_joins() {
    use cgka_traits::app_components::ACCOUNT_DEVICES_COMPONENT_ID;
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("account-devices mixed join").unwrap();
    let mut alice = account_devices_session(dir.path().join("alice.sqlite"), &key, b"alice", true);
    let mut carol = account_devices_session(dir.path().join("carol.sqlite"), &key, b"carol", false);
    let carol_kp = carol.fresh_key_package().await.unwrap();
    assert!(!advertised_components(&carol_kp).contains(&ACCOUNT_DEVICES_COMPONENT_ID));

    let welcome = welcome_for_key_package(&mut alice, &carol.self_id(), carol_kp, "mixed").await;
    let joined = carol.ingest(welcome).await.unwrap();
    assert_eq!(joined.outcome, cgka_traits::IngestOutcome::Processed);
    let group_id = joined_group(&joined);
    assert_eq!(
        carol.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap()
    );
    for record in [
        alice.group_record(&group_id).unwrap(),
        carol.group_record(&group_id).unwrap(),
    ] {
        assert!(
            !record
                .required_capabilities
                .app_components
                .contains(ACCOUNT_DEVICES_COMPONENT_ID)
        );
    }
    for session in [&alice, &carol] {
        assert_eq!(
            not_advertising(session, &group_id, ACCOUNT_DEVICES_COMPONENT_ID),
            vec![carol.self_id()]
        );
    }
}

type AdvertisingRuntime =
    AccountDeviceRuntime<RecordingAdapter, StaticTransportRouting, RecordingKeyPackages>;

fn refresh_due_at(runtime: &AdvertisingRuntime, group_id: &GroupId) -> Option<Timestamp> {
    runtime
        .session()
        .group_maintenance(group_id)
        .unwrap()
        .unwrap()
        .leaf_refresh_due_at
}

fn leaf_is_stale(runtime: &AdvertisingRuntime, group_id: &GroupId) -> bool {
    !runtime
        .session()
        .own_leaf_missing_app_components(group_id)
        .unwrap()
        .is_empty()
}

/// Run maintenance from a reached due time until the refresh self-update has
/// replaced the leaf, letting the clock reach its contention jitter.
async fn refresh_leaf(runtime: &mut AdvertisingRuntime, wall: &TestWallClock, group_id: &GroupId) {
    for _ in 0..4 {
        runtime.run_due_maintenance().await.unwrap();
        if let Some(not_before) = runtime
            .session()
            .maintenance_obligations_for_group(group_id)
            .unwrap()
            .iter()
            .find_map(|obligation| obligation.not_before)
        {
            wall.set(wall.now().0.max(not_before.0));
        }
        if !leaf_is_stale(runtime, group_id) {
            return;
        }
    }
    panic!("the refresh self-update did not run");
}

fn joined_group(effects: &marmot_session::IngestEffects) -> GroupId {
    effects
        .effects
        .events
        .iter()
        .find_map(|event| match event {
            GroupEvent::GroupJoined { group_id, .. } => Some(group_id.clone()),
            _ => None,
        })
        .expect("the Welcome joined a group")
}
