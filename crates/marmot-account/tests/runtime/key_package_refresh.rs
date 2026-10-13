#[tokio::test]
async fn weekly_key_package_refresh_boundary_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("weekly refresh key").unwrap();
    let publisher = RecordingKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(50_000));
    let policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        policy.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let before = runtime.key_package_maintenance_status().unwrap().unwrap();
    let authored = before.authored_event_created_at.unwrap().0;
    wall.set(authored + 7 * 86400 - 3600);
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    assert!(!runtime.key_package_maintenance_requires_catch_up().unwrap());
    drop(runtime);
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database, &key, b"alice"),
        RecordingAdapter::default(),
        policy,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    wall.set(authored + 7 * 86400);
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    assert!(runtime.key_package_maintenance_requires_catch_up().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    let after = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(before.stable_slot_id, after.stable_slot_id);
    assert!(after.authored_event_created_at > before.authored_event_created_at);
    assert_ne!(
        before.current_key_package_ref,
        after.current_key_package_ref
    );
    assert_ne!(before.authored_event_id, after.authored_event_id);
    let publications = publisher.publications();
    assert_eq!(publications.len(), 2);
    assert_eq!(publications[0].slot_id, publications[1].slot_id);
    assert!(publications[1].created_at > publications[0].created_at);
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
}

#[tokio::test]
async fn replaced_key_package_retention_boundary_and_in_flight_welcome() {
    // Separate recipients ensure consuming the within-grace bundle cannot make
    // the after-grace rejection pass by triggering consumption cleanup instead.
    for within_grace in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("retention grace key").unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let wall = Arc::new(TestWallClock::new(now));
        let mut runtime = AccountDeviceRuntime::new(
            session(dir.path().join("alice.sqlite"), &key, b"alice"),
            RecordingAdapter::default(),
            StaticTransportRouting::new(vec![])
                .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
            RecordingKeyPackages::default(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(7)),
        );
        let old = runtime.publish_fresh_key_package().await.unwrap();
        let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob");
        let welcome = welcome_for_key_package(
            &mut bob,
            &runtime.session().self_id(),
            old.clone(),
            "in flight",
        )
        .await;
        runtime.publish_fresh_key_package().await.unwrap();
        runtime.pause_maintenance();
        wall.set(now + 86400 - 1);
        assert_eq!(
            runtime
                .sweep_expired_key_package_private_material()
                .unwrap(),
            0
        );
        assert!(runtime.durably_owned_key_packages().unwrap().contains(&old));
        if !within_grace {
            wall.set(now + 86400);
            assert_eq!(
                runtime
                    .sweep_expired_key_package_private_material()
                    .unwrap(),
                1
            );
            assert!(!runtime.durably_owned_key_packages().unwrap().contains(&old));
        }
        let result = runtime.session_mut().ingest(welcome).await.unwrap();
        if within_grace {
            assert!(
                result
                    .effects
                    .events
                    .iter()
                    .any(|event| matches!(event, GroupEvent::GroupJoined { .. }))
            );
        } else {
            assert!(matches!(
                result.outcome,
                cgka_traits::IngestOutcome::Ignored {
                    category: cgka_traits::ingest::InputRejectionCategory::MissingWelcomeKeyPackage
                }
            ));
        }
    }
}

#[tokio::test]
async fn foreign_slot_winner_coalesces_and_bounds_republish_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("slot conflict key").unwrap();
    let publisher = RecordingKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(90_000));
    let policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        policy.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let initial = runtime.key_package_maintenance_status().unwrap().unwrap();
    let slot = initial.stable_slot_id.clone();
    let echo = initial.authored_event_id.clone().unwrap();
    // Even a claimed newer time cannot turn a known authored artifact into a conflict.
    runtime
        .observe_key_package_slot_event(&slot, &echo, Timestamp(90_001))
        .unwrap();
    runtime
        .observe_key_package_slot_event(
            "another-device",
            &MessageId::new(vec![1; 32]),
            Timestamp(90_001),
        )
        .unwrap();
    runtime
        .observe_key_package_slot_event(&slot, &MessageId::new(vec![2; 32]), Timestamp(89_999))
        .unwrap();
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    let foreign = MessageId::new(vec![3; 32]);
    for _ in 0..3 {
        runtime
            .observe_key_package_slot_event(&slot, &foreign, Timestamp(90_001))
            .unwrap();
    }
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    let replacement = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(replacement.stable_slot_id, slot);
    assert_eq!(
        replacement.authored_event_created_at,
        Some(Timestamp(90_002))
    );
    assert_ne!(
        replacement.current_key_package_ref,
        initial.current_key_package_ref
    );
    assert!(replacement.slot_conflict_created_at.is_none());
    runtime
        .observe_key_package_slot_event(&slot, &echo, initial.authored_event_created_at.unwrap())
        .unwrap();
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    runtime
        .observe_key_package_slot_event(&slot, &MessageId::new(vec![4; 32]), Timestamp(90_003))
        .unwrap();
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(publisher.publications().len(), 2);
    drop(runtime);
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database, &key, b"alice"),
        RecordingAdapter::default(),
        policy,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    wall.set(90_000 + 3600 - 1);
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    wall.set(90_000 + 3600);
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(publisher.publications().len(), 3);
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
}

#[tokio::test]
async fn superseded_pending_key_package_has_same_short_retention_and_ignores_echo() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("superseded pending grace key").unwrap();
    let wall = Arc::new(TestWallClock::new(70_000));
    let mut runtime = AccountDeviceRuntime::new(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    let old = runtime
        .prepare_fresh_key_package(vec![TransportEndpoint("wss://keys.example".into())])
        .await
        .unwrap();
    let mut lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    let old_artifact = lifecycle
        .pending_replacement
        .as_ref()
        .unwrap()
        .signed_event
        .clone()
        .unwrap();
    lifecycle
        .pending_replacement
        .as_mut()
        .unwrap()
        .generation_revision = 0;
    runtime
        .session()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    runtime.publish_fresh_key_package().await.unwrap();
    let lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    let retained = &lifecycle.retained_private_material[0];
    assert_eq!(retained.key_package, old);
    wall.set(retained.replaced_at.unwrap().0 + 86400 - 1);
    runtime
        .observe_key_package_slot_event(
            &lifecycle.stable_slot_id,
            &old_artifact.id,
            old_artifact.created_at,
        )
        .unwrap();
    assert!(
        runtime
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .slot_conflict_created_at
            .is_none()
    );
    assert_eq!(
        runtime
            .sweep_expired_key_package_private_material()
            .unwrap(),
        0
    );
    wall.set(retained.replaced_at.unwrap().0 + 86400);
    assert_eq!(
        runtime
            .sweep_expired_key_package_private_material()
            .unwrap(),
        1
    );
    assert!(!runtime.durably_owned_key_packages().unwrap().contains(&old));
}

#[tokio::test]
async fn slot_conflict_intent_survives_failed_ack_and_retries_exact_pending_package() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("conflict retry key").unwrap();
    let publisher = FlakyKeyPackages::new(0);
    let wall = Arc::new(TestWallClock::new(60_000));
    let policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        policy.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let before = runtime.key_package_maintenance_status().unwrap().unwrap();
    runtime
        .observe_key_package_slot_event(
            &before.stable_slot_id,
            &MessageId::new(vec![9; 32]),
            Timestamp(60_001),
        )
        .unwrap();
    *publisher.remaining_failures.lock().unwrap() = 1;
    runtime.run_due_maintenance().await.unwrap();
    let failed = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(failed.slot_conflict_created_at, Some(Timestamp(60_001)));
    assert_eq!(
        failed.last_slot_conflict_republish_at,
        Some(Timestamp(60_000))
    );
    assert_eq!(
        failed.current_key_package_ref,
        before.current_key_package_ref
    );
    let pending = failed.pending_replacement.unwrap();
    drop(runtime);
    wall.set(63_600);
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database, &key, b"alice"),
        RecordingAdapter::default(),
        policy,
        publisher,
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    runtime.run_due_maintenance().await.unwrap();
    let promoted = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(promoted.authored_signed_event, pending.signed_event);
    assert_eq!(
        promoted.current_key_package_ref,
        Some(pending.key_package_ref)
    );
    assert!(promoted.slot_conflict_created_at.is_none());
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
}

#[tokio::test]
async fn review_later_foreign_winner_supersedes_failed_pending_after_hour() {
    for equal_timestamp in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("alice.sqlite");
        let key = SqlCipherKey::new("conflict retry key").unwrap();
        let publisher = FlakyKeyPackages::new(0);
        let wall = Arc::new(TestWallClock::new(60_000));
        let policy = StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
        let mut runtime = AccountDeviceRuntime::new(
            current_session(database.clone(), &key, b"alice"),
            RecordingAdapter::default(),
            policy.clone(),
            publisher.clone(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(7)),
        );

        runtime.publish_fresh_key_package().await.unwrap();
        let initial = runtime.key_package_maintenance_status().unwrap().unwrap();
        runtime
            .observe_key_package_slot_event(
                &initial.stable_slot_id,
                &MessageId::new(vec![9; 32]),
                Timestamp(60_001),
            )
            .unwrap();
        *publisher.remaining_failures.lock().unwrap() = 10;
        runtime.run_due_maintenance().await.unwrap();
        let failed = runtime.key_package_maintenance_status().unwrap().unwrap();
        let pending = failed.pending_replacement.unwrap();
        // A second foreign winner arrives AFTER the replacement's failed publication.
        runtime
            .observe_key_package_slot_event(
                &initial.stable_slot_id,
                &MessageId::new(vec![0; 32]),
                if equal_timestamp {
                    pending.authored_created_at
                } else {
                    Timestamp(60_003)
                },
            )
            .unwrap();
        wall.set(60_030);
        runtime.run_due_maintenance().await.unwrap();
        assert_eq!(
            runtime
                .key_package_maintenance_status()
                .unwrap()
                .unwrap()
                .pending_replacement
                .as_ref()
                .unwrap()
                .signed_event,
            pending.signed_event
        );
        wall.set(63_599);
        runtime.run_due_maintenance().await.unwrap();
        assert_eq!(
            runtime
                .key_package_maintenance_status()
                .unwrap()
                .unwrap()
                .pending_replacement
                .as_ref()
                .unwrap()
                .signed_event,
            pending.signed_event
        );
        wall.set(63_600);
        // The last exact retry's backoff has not elapsed, but fresh conflict work is due.
        assert!(runtime.key_package_network_maintenance_due().unwrap());
        runtime.pause_maintenance();
        runtime.run_due_maintenance().await.unwrap();
        assert_eq!(
            runtime
                .key_package_maintenance_status()
                .unwrap()
                .unwrap()
                .pending_replacement
                .as_ref()
                .unwrap()
                .signed_event,
            pending.signed_event
        );
        runtime.resume_maintenance();
        runtime.run_due_maintenance().await.unwrap();
        let staged = runtime.key_package_maintenance_status().unwrap().unwrap();
        assert_ne!(
            staged.pending_replacement.as_ref().unwrap().signed_event,
            pending.signed_event
        );
        assert_eq!(
            staged.retained_private_material.last().unwrap().key_package,
            pending.key_package
        );
        assert_eq!(
            staged.last_slot_conflict_republish_at,
            Some(Timestamp(63_600))
        );
        wall.set(63_630);
        runtime.run_due_maintenance().await.unwrap();
        assert_eq!(
            runtime
                .key_package_maintenance_status()
                .unwrap()
                .unwrap()
                .pending_replacement
                .as_ref()
                .unwrap()
                .signed_event,
            staged.pending_replacement.as_ref().unwrap().signed_event
        );
        wall.set(63_600 + 86400);
        runtime
            .sweep_expired_key_package_private_material()
            .unwrap();
        assert!(
            runtime
                .durably_owned_key_packages()
                .unwrap()
                .contains(&pending.key_package)
        );
        assert_eq!(
            runtime
                .key_package_maintenance_status()
                .unwrap()
                .unwrap()
                .retained_private_material
                .last()
                .unwrap()
                .replaced_at,
            None
        );
        *publisher.remaining_failures.lock().unwrap() = 0;
        runtime.publish_fresh_key_package().await.unwrap();
        let ack_time = 63_600 + 86400;
        wall.set(ack_time + 86400 - 1);
        assert_eq!(
            runtime
                .sweep_expired_key_package_private_material()
                .unwrap(),
            0
        );
        wall.set(ack_time + 86400);
        runtime
            .sweep_expired_key_package_private_material()
            .unwrap();
        assert!(
            !runtime
                .durably_owned_key_packages()
                .unwrap()
                .contains(&pending.key_package)
        );
    }
}

#[tokio::test]
async fn review_equal_timestamp_foreign_winner_and_own_echo() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("conflict retry key").unwrap();
    let publisher = FlakyKeyPackages::new(0);
    let wall = Arc::new(TestWallClock::new(60_000));
    let policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        policy.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );

    runtime.publish_fresh_key_package().await.unwrap();
    let initial = runtime.key_package_maintenance_status().unwrap().unwrap();
    let slot = &initial.stable_slot_id;
    let timestamp = initial.authored_event_created_at.unwrap();
    runtime
        .observe_key_package_slot_event(
            slot,
            initial.authored_event_id.as_ref().unwrap(),
            timestamp,
        )
        .unwrap();
    runtime
        .observe_key_package_slot_event(slot, &MessageId::new(vec![255; 32]), timestamp)
        .unwrap();
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    runtime
        .observe_key_package_slot_event(slot, &MessageId::new(vec![0; 32]), timestamp)
        .unwrap();
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    runtime
        .observe_key_package_slot_event(slot, &MessageId::new(vec![1; 32]), timestamp)
        .unwrap();
    drop(runtime);
    let runtime = AccountDeviceRuntime::new(
        current_session(database, &key, b"alice"),
        RecordingAdapter::default(),
        policy,
        publisher,
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    assert_eq!(
        runtime
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .slot_conflict_event_id,
        Some(MessageId::new(vec![0; 32]))
    );
}

#[tokio::test]
async fn review_authored_history_pruned_on_ack_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("conflict retry key").unwrap();
    let publisher = FlakyKeyPackages::new(0);
    let wall = Arc::new(TestWallClock::new(60_000));
    let policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        policy.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );

    runtime.publish_fresh_key_package().await.unwrap();
    let initial = runtime.key_package_maintenance_status().unwrap().unwrap();
    *publisher.remaining_failures.lock().unwrap() = 1;
    assert!(runtime.publish_fresh_key_package().await.is_err());
    let pending = runtime
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .pending_replacement
        .unwrap();
    runtime
        .observe_key_package_slot_event(
            &initial.stable_slot_id,
            &pending.signed_event.as_ref().unwrap().id,
            pending.authored_created_at,
        )
        .unwrap();
    assert!(
        runtime
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .slot_conflict_created_at
            .is_none()
    );
    runtime.publish_fresh_key_package().await.unwrap();
    drop(runtime);
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database, &key, b"alice"),
        RecordingAdapter::default(),
        policy,
        publisher,
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    let promoted = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(promoted.historical_authored_event_ids.is_empty());
    runtime
        .observe_key_package_slot_event(
            &initial.stable_slot_id,
            initial.authored_event_id.as_ref().unwrap(),
            initial.authored_event_created_at.unwrap(),
        )
        .unwrap();
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
}

#[tokio::test]
async fn round_two_no_ack_history_is_bounded_after_restart_and_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("no ack bounded history").unwrap();
    let publisher = FlakyKeyPackages::new(0);
    let wall = Arc::new(TestWallClock::new(60_000));
    let policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let open = || {
        AccountDeviceRuntime::new(
            current_session(database.clone(), &key, b"alice"),
            RecordingAdapter::default(),
            policy.clone(),
            publisher.clone(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(7)),
        )
    };
    let mut runtime = open();
    runtime.publish_fresh_key_package().await.unwrap();
    *publisher.remaining_failures.lock().unwrap() = 1000;
    let mut artifacts = Vec::new();
    for hour in 0..30 {
        wall.set(60_000 + hour * 3600);
        let state = runtime.key_package_maintenance_status().unwrap().unwrap();
        let floor = state
            .pending_replacement
            .as_ref()
            .map(|p| p.authored_created_at)
            .unwrap_or(state.authored_event_created_at.unwrap());
        runtime
            .observe_key_package_slot_event(
                &state.stable_slot_id,
                &MessageId::new(vec![0; 32]),
                Timestamp(floor.0 + 1),
            )
            .unwrap();
        runtime.run_due_maintenance().await.unwrap();
        artifacts.push(
            runtime
                .key_package_maintenance_status()
                .unwrap()
                .unwrap()
                .pending_replacement
                .unwrap()
                .signed_event
                .unwrap(),
        );
        drop(runtime);
        runtime = open();
    }
    let state = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(
        state.historical_authored_event_ids.len() <= 1,
        "unacknowledged history must stay bounded"
    );
    // Expiry removes the private bundle, but must preserve the newest authored floor.
    wall.set(state.pending_replacement.as_ref().unwrap().not_after.0);
    runtime
        .sweep_expired_key_package_private_material()
        .unwrap();
    drop(runtime);
    let mut runtime = open();
    let newest_time = artifacts.last().unwrap().created_at;
    for artifact in artifacts {
        runtime
            .observe_key_package_slot_event(
                &state.stable_slot_id,
                &artifact.id,
                artifact.created_at,
            )
            .unwrap();
    }
    // Losing equal-time foreign artifacts must also lose after the pending bundle expires.
    runtime
        .observe_key_package_slot_event(
            &state.stable_slot_id,
            &MessageId::new(vec![255; 32]),
            newest_time,
        )
        .unwrap();
    let after = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        after.slot_conflict_created_at,
        state.slot_conflict_created_at
    );
    assert_eq!(after.slot_conflict_event_id, state.slot_conflict_event_id);
}

#[tokio::test]
async fn pending_retention_starts_at_ack_wall_time_despite_future_authoring_time() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("future timestamp retention").unwrap();
    let wall = Arc::new(TestWallClock::new(70_000));
    let mut runtime = AccountDeviceRuntime::new(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    let old = runtime
        .prepare_fresh_key_package(vec![TransportEndpoint("wss://keys.example".into())])
        .await
        .unwrap();
    let mut state = runtime.key_package_maintenance_status().unwrap().unwrap();
    state
        .pending_replacement
        .as_mut()
        .unwrap()
        .generation_revision = 0;
    state.slot_conflict_created_at = Some(Timestamp(70_298));
    runtime.session().put_key_package_lifecycle(&state).unwrap();
    runtime.publish_fresh_key_package().await.unwrap();
    let state = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(state.authored_event_created_at, Some(Timestamp(70_299)));
    wall.set(70_000 + 86400 - 1);
    assert_eq!(
        runtime
            .sweep_expired_key_package_private_material()
            .unwrap(),
        0
    );
    wall.set(70_000 + 86400);
    assert_eq!(
        runtime
            .sweep_expired_key_package_private_material()
            .unwrap(),
        1
    );
    assert!(!runtime.durably_owned_key_packages().unwrap().contains(&old));
}

#[tokio::test]
async fn lost_ack_pending_supersession_retains_welcome_key_until_replacement_ack_grace() {
    // Exercise Welcome consumption and time-based retirement independently.
    for consume in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("alice.sqlite");
        let key = SqlCipherKey::new("lost ACK retention key").unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let wall = Arc::new(TestWallClock::new(now));
        let policy = StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
        let exposed = ExposedThenFailsKeyPackages::default();
        let mut runtime = AccountDeviceRuntime::new(
            session(database.clone(), &key, b"alice"),
            RecordingAdapter::default(),
            policy.clone(),
            exposed.clone(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(7)),
        );
        // A reaches a relay, but local confirmation is lost.
        assert!(runtime.publish_fresh_key_package().await.is_err());
        let old = exposed.publications()[0].key_package.clone();
        let mut state = runtime.key_package_maintenance_status().unwrap().unwrap();
        state
            .pending_replacement
            .as_mut()
            .unwrap()
            .generation_revision = 0;
        runtime.session().put_key_package_lifecycle(&state).unwrap();
        drop(runtime);
        let publisher = FlakyKeyPackages::new(1000);
        let open = || {
            AccountDeviceRuntime::new(
                session(database.clone(), &key, b"alice"),
                RecordingAdapter::default(),
                policy.clone(),
                publisher.clone(),
            )
            .with_maintenance_sources(
                wall.clone(),
                Arc::new(TestMonotonicClock::default()),
                Arc::new(TestRandom::new(7)),
            )
        };
        let mut runtime = open();
        // Generator upgrade supersedes pending A with B; B never reaches a relay.
        assert!(runtime.publish_fresh_key_package().await.is_err());
        let replacement = runtime
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .pending_replacement
            .unwrap();
        assert_ne!(replacement.key_package, old);
        assert_eq!(
            runtime
                .key_package_maintenance_status()
                .unwrap()
                .unwrap()
                .retained_private_material[0]
                .replaced_at,
            None
        );
        wall.set(now + 86401);
        assert!(runtime.publish_fresh_key_package().await.is_err());
        drop(runtime);
        let mut runtime = open();
        assert_eq!(
            runtime
                .sweep_expired_key_package_private_material()
                .unwrap(),
            0,
            "staging without an ACK must not start the retained bundle grace"
        );
        assert!(runtime.durably_owned_key_packages().unwrap().contains(&old));
        if consume {
            // A relay can still advertise A and issue a new Welcome after 24h.
            let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob");
            let welcome = welcome_for_key_package(
                &mut bob,
                &runtime.session().self_id(),
                old.clone(),
                "lost ACK invite",
            )
            .await;
            let joined = runtime.session_mut().ingest(welcome).await.unwrap();
            assert!(
                joined
                    .effects
                    .events
                    .iter()
                    .any(|event| matches!(event, GroupEvent::GroupJoined { .. }))
            );
            assert_eq!(
                runtime
                    .sweep_expired_key_package_private_material()
                    .unwrap(),
                1
            );
            assert!(!runtime.durably_owned_key_packages().unwrap().contains(&old));
        } else {
            // The ACK arrives well after staging/authoring, and survives restart.
            *publisher.remaining_failures.lock().unwrap() = 0;
            runtime.publish_fresh_key_package().await.unwrap();
            drop(runtime);
            let mut runtime = open();
            assert_eq!(
                runtime
                    .key_package_maintenance_status()
                    .unwrap()
                    .unwrap()
                    .retained_private_material[0]
                    .replaced_at,
                Some(Timestamp(now + 86401))
            );
            // A later same-slot promotion must not restart A's first-ACK grace.
            wall.set(now + 86401 + 3600);
            runtime.publish_fresh_key_package().await.unwrap();
            wall.set(now + 86401 + 86400 - 1);
            assert_eq!(
                runtime
                    .sweep_expired_key_package_private_material()
                    .unwrap(),
                0
            );
            assert!(runtime.durably_owned_key_packages().unwrap().contains(&old));
            wall.set(now + 86401 + 86400);
            assert_eq!(
                runtime
                    .sweep_expired_key_package_private_material()
                    .unwrap(),
                1
            );
            assert!(!runtime.durably_owned_key_packages().unwrap().contains(&old));
        }
    }
}
