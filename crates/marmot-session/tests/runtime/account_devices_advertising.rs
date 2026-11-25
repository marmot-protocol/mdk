// Advertising `marmot.group.account-devices.v1` (mdk#2628, item 2.2). A build
// that starts advertising it replaces this device's published KeyPackage and
// refreshes its own leaf in each existing group through the randomized
// stale-leaf refresh. Neither makes an existing group require it; only an
// admin turns it on, when the user asks (item 2.4).

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

/// Give the two groups different contention delays.
struct FiveMinuteRandom(AtomicU64);

impl EntropySource for FiveMinuteRandom {
    fn fill_bytes(&self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let value = self.0.fetch_add(1, Ordering::Relaxed) * 5 * 60 * 1_000;
            chunk.copy_from_slice(&value.to_le_bytes()[..chunk.len()]);
        }
    }
}

#[tokio::test]
async fn an_upgrade_replaces_the_published_key_package_with_one_advertising_account_devices() {
    use cgka_traits::app_components::ACCOUNT_DEVICES_COMPONENT_ID;
    let dir = relaxed_storage_dir().unwrap();
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

    let dir = relaxed_storage_dir().unwrap();
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

    let start = 100_000u64;
    let mut old = alice.group_maintenance(&groups[0]).unwrap().unwrap();
    old.leaf_refresh_due_at = Some(Timestamp(start + 4 * 24 * 60 * 60));
    alice.put_group_maintenance(&old).unwrap();
    drop(alice);

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
        Arc::new(FiveMinuteRandom(AtomicU64::new(1))),
    )
    .with_maintenance_timing(MaintenanceTiming::immediate());
    let epochs_before: Vec<_> = groups
        .iter()
        .map(|group_id| runtime.session().epoch(group_id).unwrap())
        .collect();

    // Both groups queue a refresh on the first sweep, including the group
    // with a saved deadline far beyond the contention window.
    runtime.run_due_maintenance().await.unwrap();
    let mut order: Vec<_> = groups
        .iter()
        .map(|group_id| {
            let at = contention_deadline(&runtime, group_id);
            assert!(at.0 >= start && at.0 <= start + 15 * 60);
            (at, group_id.clone())
        })
        .collect();
    order.sort_by_key(|(at, _)| *at);
    let [(early_at, early), (late_at, late)] = &order[..] else {
        unreachable!()
    };
    assert!(late_at > early_at, "{early_at:?} {late_at:?}");
    assert!(adapter.publishes().is_empty());

    // At the earlier time only that group's leaf is refreshed.
    wall.set(early_at.0);
    runtime.run_due_maintenance().await.unwrap();
    let early_index = groups
        .iter()
        .position(|group_id| group_id == early)
        .unwrap();
    assert_eq!(
        runtime.session().epoch(early).unwrap().0,
        epochs_before[early_index].0 + 1
    );
    assert_eq!(contention_deadline(&runtime, late), *late_at);
    let late_index = groups.iter().position(|group_id| group_id == late).unwrap();
    assert_eq!(
        runtime.session().epoch(late).unwrap(),
        epochs_before[late_index]
    );

    wall.set(late_at.0);
    runtime.run_due_maintenance().await.unwrap();

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
    let dir = relaxed_storage_dir().unwrap();
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

fn contention_deadline(runtime: &AdvertisingRuntime, group_id: &GroupId) -> Timestamp {
    let obligations = runtime
        .session()
        .maintenance_obligations_for_group(group_id)
        .unwrap();
    assert_eq!(obligations.len(), 1);
    obligations[0]
        .not_before
        .expect("queued with contention jitter")
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

/// Turning account-devices on (mdk#2628 item 2.4) waits for the user and for
/// every leaf. An upgraded admin whose own leaf is still stale is told the
/// group has an unsupported leaf, not which; once the leaf is refreshed the
/// admin's activation goes out through the account runtime like any admin
/// Commit, and the other member follows. A non-admin is only told it cannot
/// decide.
#[tokio::test]
async fn an_admin_turns_account_devices_on_once_every_leaf_advertises_it() {
    use cgka_traits::app_components::ACCOUNT_DEVICES_COMPONENT_ID;
    use cgka_traits::error::AccountDevicesActivationRefusal as Refusal;

    let dir = relaxed_storage_dir().unwrap();
    let key = SqlCipherKey::new("account-devices activation").unwrap();
    let alice_database = dir.path().join("alice.sqlite");
    let mut bob = account_devices_session(dir.path().join("bob.sqlite"), &key, b"bob", true);
    let mut alice = account_devices_session(&alice_database, &key, b"alice", false);
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let welcome = welcome_for_key_package(&mut alice, &bob.self_id(), bob_kp, "activate").await;
    let joined = bob.ingest(welcome).await.unwrap();
    let group_id = joined_group(&joined);
    drop(alice);

    let adapter = RecordingAdapter::default();
    let routing = StaticTransportRouting::new(vec![])
        .required_acks(1)
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![TransportEndpoint("wss://group.example".into())],
        );
    let mut runtime = AccountDeviceRuntime::new(
        account_devices_session(&alice_database, &key, b"alice", true),
        adapter.clone(),
        routing,
        RecordingKeyPackages::default(),
    );
    assert_eq!(
        bob.account_devices_activation_refusal(&group_id).unwrap(),
        Some(Refusal::NotAdmin)
    );
    assert_eq!(
        runtime
            .account_devices_activation_refusal(&group_id)
            .unwrap(),
        Some(Refusal::UnsupportedLeaves)
    );
    let epoch = runtime.session().epoch(&group_id).unwrap();
    let refused = runtime
        .send(SendIntent::EnableAccountDevices {
            group_id: group_id.clone(),
        })
        .await;
    let error = refused.unwrap_err();
    assert!(matches!(
        error.as_engine_error(),
        Some(cgka_traits::EngineError::AccountDevicesActivationRefused {
            group_id: refused_group,
            reason: Refusal::UnsupportedLeaves,
        }) if refused_group == &group_id
    ));
    assert_eq!(runtime.session().epoch(&group_id).unwrap(), epoch);
    assert!(adapter.publishes().is_empty());

    runtime
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(
        runtime
            .account_devices_activation_refusal(&group_id)
            .unwrap(),
        None
    );
    runtime
        .send(SendIntent::EnableAccountDevices {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(runtime.session().epoch(&group_id).unwrap().0, epoch.0 + 2);
    assert_eq!(
        runtime
            .account_devices_activation_refusal(&group_id)
            .unwrap(),
        Some(Refusal::AlreadyRequired)
    );

    let commits: Vec<_> = adapter
        .publishes()
        .into_iter()
        .map(|publish| publish.message)
        .filter(|message| matches!(message.envelope, TransportEnvelope::GroupMessage { .. }))
        .collect();
    assert_eq!(commits.len(), 2);
    for commit in commits {
        bob.ingest(commit).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(
            cgka_engine::canonicalization::V1_SETTLEMENT_QUIESCENCE_MS + 200,
        ))
        .await;
        bob.advance_convergence(&group_id).await.unwrap();
    }
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        runtime.session().epoch(&group_id).unwrap()
    );
    for record in [
        bob.group_record(&group_id).unwrap(),
        runtime.session().group_record(&group_id).unwrap(),
    ] {
        assert!(
            record
                .required_capabilities
                .app_components
                .contains(ACCOUNT_DEVICES_COMPONENT_ID)
        );
    }
}
