// Generator migrations use actual private bundles and restartable SQLCipher
// state. Removing the revision fields models the pre-migration JSON format.
fn without_key_package_generation_revision(
    lifecycle: &cgka_traits::KeyPackageLifecycleState,
) -> cgka_traits::KeyPackageLifecycleState {
    let mut value = serde_json::to_value(lifecycle).unwrap();
    value.as_object_mut().unwrap().remove("generation_revision");
    if let Some(pending) = value["pending_replacement"].as_object_mut() {
        pending.remove("generation_revision");
    }
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn key_package_generation_upgrade_retries_across_restart_and_rotates_only_once() {
    use cgka_traits::maintenance::KEY_PACKAGE_GENERATION_REVISION;
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("generation upgrade key").unwrap();
    let policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let publisher = FlakyKeyPackages::new(0);
    let wall = Arc::new(TestWallClock::new(50_000));
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
    let old_package = runtime.publish_fresh_key_package().await.unwrap();
    let mut before = without_key_package_generation_revision(
        &runtime.key_package_maintenance_status().unwrap().unwrap(),
    );
    assert!(
        before.upgrade_rotation_recorded,
        "the old boolean alone cannot trigger this migration"
    );
    assert_eq!(before.generation_revision, 0);
    before.publication_targets[0].state = cgka_traits::TransportFanoutAttemptState::Unattempted;
    runtime
        .session()
        .put_key_package_lifecycle(&before)
        .unwrap();
    assert!(
        !runtime.key_package_has_pending_fanout().unwrap(),
        "superseded generator bytes must not fan out"
    );
    assert!(runtime.key_package_generation_upgrade_due().unwrap());
    assert!(runtime.key_package_maintenance_requires_catch_up().unwrap());
    *publisher.remaining_failures.lock().unwrap() = 1;
    runtime.run_due_maintenance().await.unwrap();
    let failed = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        failed.generation_revision, 0,
        "failure must not complete the migration"
    );
    assert_eq!(failed.current_key_package, Some(old_package.clone()));
    let pending = failed.pending_replacement.unwrap();
    assert_eq!(pending.generation_revision, KEY_PACKAGE_GENERATION_REVISION);
    assert_ne!(pending.key_package, old_package);
    assert!(
        !runtime.key_package_generation_upgrade_due().unwrap(),
        "a new pending bundle owns the retry"
    );
    drop(runtime);

    wall.set(50_060);
    let mut restarted = AccountDeviceRuntime::new(
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
    restarted.run_due_maintenance().await.unwrap();
    let promoted = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        promoted.generation_revision,
        KEY_PACKAGE_GENERATION_REVISION
    );
    assert_eq!(
        promoted.current_key_package,
        Some(pending.key_package.clone())
    );
    assert_eq!(promoted.authored_signed_event, pending.signed_event);
    assert_eq!(promoted.stable_slot_id, before.stable_slot_id);
    assert!(promoted.authored_event_created_at > before.authored_event_created_at);
    assert_eq!(promoted.retained_private_material.len(), 1);
    assert_eq!(
        promoted.retained_private_material[0].not_after,
        before.current_not_after.unwrap()
    );
    assert!(
        restarted
            .durably_owned_key_packages()
            .unwrap()
            .contains(&old_package)
    );
    assert_eq!(
        publisher.publications()[1],
        publisher.publications()[2],
        "retry must reuse exact publication intent"
    );

    // An invitation prepared using the previous package still joins after ACK.
    let mut bob = current_session(dir.path().join("bob.sqlite"), &key, b"bob");
    let welcome = welcome_for_key_package(
        &mut bob,
        &restarted.session().self_id(),
        old_package,
        "late invite",
    )
    .await;
    let joined = restarted.session_mut().ingest(welcome).await.unwrap();
    assert!(!matches!(
        joined.outcome,
        cgka_traits::IngestOutcome::Ignored { .. }
    ));
    drop(restarted);
    let mut reopened = AccountDeviceRuntime::new(
        current_session(database, &key, b"alice"),
        RecordingAdapter::default(),
        policy,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    assert!(!reopened.key_package_generation_upgrade_due().unwrap());
    reopened.run_due_maintenance().await.unwrap();
    assert_eq!(
        publisher.publications().len(),
        3,
        "reopening must not rotate the upgraded package again"
    );
}

#[tokio::test]
async fn key_package_generation_upgrade_supersedes_old_pending_bundles_without_deleting_them() {
    use cgka_traits::maintenance::KEY_PACKAGE_GENERATION_REVISION;
    for signed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("alice.sqlite");
        let key = SqlCipherKey::new("pending generation upgrade key").unwrap();
        let policy = StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
        let publisher = RecordingKeyPackages::default();
        let wall = Arc::new(TestWallClock::new(50_000));
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
        runtime
            .prepare_fresh_key_package(
                TransportRoutingPolicy::key_package_endpoints(&policy).to_vec(),
            )
            .await
            .unwrap();
        let mut old = without_key_package_generation_revision(
            &runtime.key_package_maintenance_status().unwrap().unwrap(),
        );
        let pending = old.pending_replacement.as_mut().unwrap();
        if !signed {
            pending.signed_event = None;
        }
        // Simulate a possible-exposure failure whose retry is not due yet.
        pending.targets[0].state = cgka_traits::TransportFanoutAttemptState::AttemptedFailed;
        pending.targets[0].last_attempt_at = Some(Timestamp(50_000));
        pending.targets[0].attempt_count = 1;
        let old_pending = pending.clone();
        runtime.session().put_key_package_lifecycle(&old).unwrap();
        drop(runtime);
        let mut restarted = AccountDeviceRuntime::new(
            current_session(database, &key, b"alice"),
            RecordingAdapter::default(),
            policy,
            publisher.clone(),
        )
        .with_maintenance_sources(
            wall,
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(7)),
        );
        assert!(restarted.key_package_generation_upgrade_due().unwrap());
        assert!(restarted.key_package_network_maintenance_due().unwrap());
        restarted.run_due_maintenance().await.unwrap();
        let upgraded = restarted.key_package_maintenance_status().unwrap().unwrap();
        assert_eq!(
            upgraded.generation_revision,
            KEY_PACKAGE_GENERATION_REVISION
        );
        assert_ne!(
            upgraded.current_key_package,
            Some(old_pending.key_package.clone())
        );
        assert_eq!(upgraded.authored_event_created_at, Some(Timestamp(50_001)));
        assert_eq!(upgraded.stable_slot_id, old.stable_slot_id);
        assert_eq!(
            upgraded.retained_private_material[0].key_package,
            old_pending.key_package
        );
        assert_eq!(
            upgraded.retained_private_material[0].not_after,
            old_pending.not_after
        );
        assert!(
            restarted
                .durably_owned_key_packages()
                .unwrap()
                .contains(&old_pending.key_package)
        );
        assert_eq!(
            publisher.publications().len(),
            1,
            "old pending artifact must never be republished"
        );
        let package = upgraded.current_key_package.unwrap();
        let metadata = cgka_engine::key_package::key_package_metadata(&package).unwrap();
        assert!(
            metadata
                .mls_extensions
                .iter()
                .all(|id| !(1..=5).contains(id))
        );
        assert!(
            metadata
                .mls_proposals
                .iter()
                .all(|id| !(1..=7).contains(id))
        );
    }
}

#[derive(Clone, Default)]
struct UpgradeAckKeyPackages(PartialFanoutKeyPackages);

#[async_trait]
impl KeyPackagePublisher for UpgradeAckKeyPackages {
    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<cgka_traits::SignedPublicationArtifact, KeyPackagePublishError> {
        Ok(test_key_package_artifact(&publication))
    }

    async fn publish_prepared_key_package(
        &self,
        publication: &KeyPackagePublication,
        artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        let mut calls = self.0.publications.lock().unwrap();
        calls.push((publication.clone(), artifact.clone()));
        let accepted_count = match calls.len() {
            1 => 0,
            2 => 1,
            _ => publication.endpoints.len(),
        };
        Ok(KeyPackagePublishReceipt {
            accepted: publication
                .endpoints
                .iter()
                .take(accepted_count)
                .cloned()
                .collect(),
            failed: publication
                .endpoints
                .iter()
                .skip(accepted_count)
                .cloned()
                .collect(),
        })
    }
}

#[tokio::test]
async fn key_package_generation_upgrade_requires_ack_and_resumes_remaining_fanout() {
    use cgka_traits::maintenance::KEY_PACKAGE_GENERATION_REVISION;
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("generation upgrade ack key").unwrap();
    let policy = StaticTransportRouting::new(vec![]).key_package_endpoints(vec![
        TransportEndpoint("wss://keys-a.example".into()),
        TransportEndpoint("wss://keys-b.example".into()),
    ]);
    let mut initial = AccountDeviceRuntime::new(
        current_session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        policy.clone(),
        RecordingKeyPackages::default(),
    );
    initial.publish_fresh_key_package().await.unwrap();
    let old = without_key_package_generation_revision(
        &initial.key_package_maintenance_status().unwrap().unwrap(),
    );
    initial.session().put_key_package_lifecycle(&old).unwrap();
    drop(initial);
    // Use the actual authoring time to stay within the monotonic event skew guard.
    let now = old.authored_event_created_at.unwrap().0;
    let wall = Arc::new(TestWallClock::new(now));
    let publisher = UpgradeAckKeyPackages::default();
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
    runtime.run_due_maintenance().await.unwrap();
    let unacknowledged = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(unacknowledged.generation_revision, 0);
    assert_eq!(
        unacknowledged.current_key_package_ref,
        old.current_key_package_ref
    );
    let replacement = unacknowledged.pending_replacement.unwrap();
    wall.set(now + 60);
    runtime.run_due_maintenance().await.unwrap();
    let acknowledged = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        acknowledged.generation_revision,
        KEY_PACKAGE_GENERATION_REVISION
    );
    assert_eq!(
        acknowledged.current_key_package_ref,
        Some(replacement.key_package_ref.clone())
    );
    assert!(runtime.key_package_has_pending_fanout().unwrap());
    assert_eq!(publisher.0.publications()[0], publisher.0.publications()[1]);
    drop(runtime);
    wall.set(now + 180);
    let mut restarted = AccountDeviceRuntime::new(
        current_session(database, &key, b"alice"),
        RecordingAdapter::default(),
        policy,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(7)),
    );
    restarted.run_due_maintenance().await.unwrap();
    let finished = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        finished.generation_revision,
        KEY_PACKAGE_GENERATION_REVISION
    );
    assert_eq!(
        finished.current_key_package_ref,
        Some(replacement.key_package_ref)
    );
    assert!(!restarted.key_package_has_pending_fanout().unwrap());
    let calls = publisher.0.publications();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[2].1, calls[0].1,
        "fanout after restart must reuse the upgraded artifact"
    );
    assert_eq!(
        calls[2].0.endpoints,
        vec![TransportEndpoint("wss://keys-b.example".into())]
    );
}
