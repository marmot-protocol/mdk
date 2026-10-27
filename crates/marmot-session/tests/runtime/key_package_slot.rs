// This device's KeyPackage slot (mdk#2628 item 1.2): a 30-day lifetime, a
// refresh at least weekly and on its other triggers, the replacement grace
// period for a superseded KeyPackage, and re-signing a signed KeyPackage the
// publisher can no longer send (D8). `foundation/key-packages.md`, "Refreshing
// a slot".

const DAY: u64 = 24 * 60 * 60;
const KEY_ENDPOINT: &str = "wss://keys.example";

/// A runtime over `session` whose maintenance clock is `wall`. `random` is
/// the first sampled value: 0 schedules the first refresh 6 days after
/// publication, `DAY` schedules it 7 days after.
fn slot_runtime<K: KeyPackagePublisher>(
    session: AccountDeviceSession,
    publisher: K,
    wall: &Arc<TestWallClock>,
    random: u64,
    endpoints: &[&str],
) -> AccountDeviceRuntime<RecordingAdapter, StaticTransportRouting, K> {
    AccountDeviceRuntime::new(
        session,
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(
            endpoints
                .iter()
                .map(|endpoint| TransportEndpoint((*endpoint).into()))
                .collect(),
        ),
        publisher,
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(random)),
    )
}

fn slot_lifecycle<A, R, K>(
    runtime: &AccountDeviceRuntime<A, R, K>,
) -> cgka_traits::KeyPackageLifecycleState
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    runtime.key_package_maintenance_status().unwrap().unwrap()
}

fn advertised_components(key_package: &cgka_traits::engine::KeyPackage) -> Vec<u16> {
    cgka_engine::key_package::key_package_metadata(key_package)
        .unwrap()
        .app_components
}

#[tokio::test]
async fn the_slot_is_republished_weekly_with_a_thirty_day_lifetime() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot weekly refresh").unwrap();
    // KeyPackage lifetimes come from the system clock.
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = RecordingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        DAY,
        &[KEY_ENDPOINT],
    );

    let first = runtime.publish_fresh_key_package().await.unwrap();
    let metadata = cgka_engine::key_package::key_package_metadata(&first).unwrap();
    assert_eq!(metadata.not_after - metadata.not_before, 2_595_600);
    let published = slot_lifecycle(&runtime);
    let published_at = published.authored_event_created_at.unwrap().0;
    assert_eq!(published.refresh_at, Some(Timestamp(published_at + 7 * DAY)));
    assert!(published.refresh_at < published.current_not_after);

    // Nothing is republished until the week is up.
    wall.set(published_at + 7 * DAY - 1);
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(publisher.publications().len(), 1);

    wall.set(published_at + 7 * DAY);
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    let refreshed = slot_lifecycle(&runtime);
    assert_ne!(
        refreshed.current_key_package_ref,
        published.current_key_package_ref
    );
    assert_eq!(
        refreshed.authored_event_created_at,
        Some(Timestamp(published_at + 7 * DAY))
    );
    let publications = publisher.publications();
    assert_eq!(publications.len(), 2);
    assert!(
        publications
            .iter()
            .all(|publication| publication.slot_id == published.stable_slot_id),
        "every refresh replaces the one slot"
    );
    // The next refresh is scheduled from the new publication.
    assert!(
        refreshed.refresh_at.unwrap().0 <= published_at + 14 * DAY,
        "refreshed at least weekly"
    );

    // An inviter may still hold the superseded KeyPackage, so it stays held
    // for the grace period after the confirmed replacement.
    let retained = retained_entry(&refreshed, &first);
    assert!(!retained.consumed);
    assert_eq!(retained.authored_event_id, published.authored_event_id);
    assert_eq!(
        retained.delete_at(),
        Timestamp(published_at + 7 * DAY + cgka_traits::KEY_PACKAGE_REPLACEMENT_GRACE_SECS)
    );
}

#[tokio::test]
async fn a_refresh_scheduled_under_the_old_lifetime_is_due_a_week_after_publication() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot legacy refresh schedule").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingKeyPackages::default(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.publish_fresh_key_package().await.unwrap();
    // Before 30-day lifetimes, a refresh fell due 63 to 70 days after
    // publication.
    let mut lifecycle = slot_lifecycle(&runtime);
    let published_at = lifecycle.authored_event_created_at.unwrap().0;
    lifecycle.refresh_at = Some(Timestamp(published_at + 63 * DAY));
    runtime
        .session()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();

    wall.set(published_at + 7 * DAY - 1);
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    assert!(!runtime.key_package_maintenance_requires_catch_up().unwrap());
    wall.set(published_at + 7 * DAY);
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    assert!(runtime.key_package_maintenance_requires_catch_up().unwrap());
}

#[tokio::test]
async fn a_change_in_supported_components_republishes_the_slot() {
    use cgka_traits::app_components::GROUP_AVATAR_URL_COMPONENT_ID;
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("kp slot capability change").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = RecordingKeyPackages::default();
    let open = |upgraded| {
        slot_runtime(
            component_migration_session(&database, &key, b"alice", upgraded),
            publisher.clone(),
            &wall,
            0,
            &[KEY_ENDPOINT],
        )
    };

    let mut runtime = open(false);
    let before = runtime.publish_fresh_key_package().await.unwrap();
    assert!(!advertised_components(&before).contains(&GROUP_AVATAR_URL_COMPONENT_ID));
    drop(runtime);

    // A build that supports the same components owes nothing.
    let runtime = open(false);
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    drop(runtime);

    // A build that supports one more replaces the KeyPackage rather than
    // republishing the old advertisement.
    let mut runtime = open(true);
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    let upgraded = runtime.republish_key_package().await.unwrap();
    assert_ne!(upgraded, before);
    assert!(advertised_components(&upgraded).contains(&GROUP_AVATAR_URL_COMPONENT_ID));
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    drop(runtime);

    // A build that drops it replaces it again, through maintenance.
    let mut runtime = open(false);
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    let downgraded = slot_lifecycle(&runtime).current_key_package.unwrap();
    assert!(!advertised_components(&downgraded).contains(&GROUP_AVATAR_URL_COMPONENT_ID));
    assert_eq!(publisher.publications().len(), 3);
}

#[tokio::test]
async fn a_welcome_that_consumes_the_current_key_package_republishes_the_slot() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot consumed welcome").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = RecordingKeyPackages::default();
    let mut alice = slot_runtime(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    let consumed = alice.publish_fresh_key_package().await.unwrap();
    assert!(!alice.key_package_network_maintenance_due().unwrap());

    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let alice_id = alice.session().self_id();
    let welcome = welcome_for_key_package(&mut bob, &alice_id, consumed.clone(), "invite").await;
    let joined = alice.session_mut().ingest(welcome).await.unwrap();
    assert_eq!(joined.outcome, cgka_traits::IngestOutcome::Processed);

    assert!(alice.key_package_network_maintenance_due().unwrap());
    alice.run_due_maintenance().await.unwrap();
    let lifecycle = slot_lifecycle(&alice);
    assert_ne!(lifecycle.current_key_package, Some(consumed.clone()));
    assert!(retained_entry(&lifecycle, &consumed).consumed);
    assert_eq!(publisher.publications().len(), 2);
    assert!(!alice.key_package_network_maintenance_due().unwrap());
}

#[tokio::test]
async fn a_welcome_built_before_a_refresh_opens_for_a_day_after_the_replacement_is_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot superseded welcome").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let mut alice = slot_runtime(
        nostr_device_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingKeyPackages::default(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    let superseded = alice.publish_fresh_key_package().await.unwrap();
    let published = slot_lifecycle(&alice);
    // The KeyPackage as inviters fetch it, carrying its publication's id for
    // the rumor to name.
    let fetched = cgka_traits::engine::KeyPackage {
        source: Some(cgka_traits::engine::KeyPackageSource {
            event_id: published.authored_event_id.clone().unwrap(),
        }),
        ..superseded.clone()
    };

    // Two inviters fetch it just before the weekly refresh.
    let mut bob = nostr_device_session(dir.path().join("bob.sqlite"), &key, b"bob");
    let (early_group, early) = create_group(&mut bob, &[&fetched], "early").await;
    let (_, late) = create_group(&mut bob, &[&fetched], "late").await;

    let confirmed_at = published.refresh_at.unwrap().0;
    wall.set(confirmed_at);
    alice.run_due_maintenance().await.unwrap();
    assert_ne!(
        slot_lifecycle(&alice).current_key_package,
        Some(superseded.clone())
    );

    // Inside the grace period the superseded KeyPackage still opens a Welcome
    // whose rumor names its publication.
    wall.set(confirmed_at + cgka_traits::KEY_PACKAGE_REPLACEMENT_GRACE_SECS - 1);
    alice.run_due_maintenance().await.unwrap();
    let opened = alice.session_mut().ingest(early[0].clone()).await.unwrap();
    assert_eq!(opened.outcome, cgka_traits::IngestOutcome::Processed);
    assert_eq!(
        joins(std::slice::from_ref(&opened)),
        vec![(early_group, early[0].id.clone())]
    );

    // Once it ends the private key is deleted, and a Welcome for it no longer
    // opens.
    wall.set(confirmed_at + cgka_traits::KEY_PACKAGE_REPLACEMENT_GRACE_SECS);
    alice.run_due_maintenance().await.unwrap();
    assert!(
        !alice
            .durably_owned_key_packages()
            .unwrap()
            .contains(&superseded)
    );
    let refused = alice.session_mut().ingest(late[0].clone()).await.unwrap();
    assert!(
        matches!(refused.outcome, cgka_traits::IngestOutcome::Ignored { .. }),
        "{:?}",
        refused.outcome
    );
    assert!(joins(std::slice::from_ref(&refused)).is_empty());
}

#[tokio::test]
async fn a_restart_during_a_refresh_keeps_one_slot_and_every_key() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("kp slot restart refresh").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        RecordingKeyPackages::default(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    let old = runtime.publish_fresh_key_package().await.unwrap();
    let before = slot_lifecycle(&runtime);
    drop(runtime);

    // The refresh is staged, signed and sent, and the process stops before an
    // acknowledgement is recorded.
    wall.set(before.refresh_at.unwrap().0);
    let interrupted_publisher = ExposedThenFailsKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        interrupted_publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.run_due_maintenance().await.unwrap();
    let interrupted = slot_lifecycle(&runtime);
    let pending = interrupted
        .pending_replacement
        .clone()
        .expect("the refresh is still owed");
    let sent = pending.signed_event.clone().unwrap();
    assert_eq!(interrupted.current_key_package, Some(old.clone()));
    drop(runtime);

    // After the restart the same signed refresh completes: no second
    // KeyPackage, no second slot.
    wall.set(before.refresh_at.unwrap().0 + 60 * 60);
    let publisher = PartialFanoutKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.run_due_maintenance().await.unwrap();
    let after = slot_lifecycle(&runtime);
    assert!(after.pending_replacement.is_none());
    assert_eq!(after.current_key_package, Some(pending.key_package.clone()));
    assert_eq!(after.authored_event_id, Some(sent.id.clone()));
    let publications = publisher.publications();
    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0].1, sent);
    assert_eq!(after.stable_slot_id, before.stable_slot_id);
    assert!(
        interrupted_publisher
            .publications()
            .iter()
            .chain(publications.iter().map(|(publication, _)| publication))
            .all(|publication| publication.slot_id == before.stable_slot_id)
    );

    // No key is lost: the superseded KeyPackage is retained under its
    // publication's id, and both private bundles are still held. Its grace
    // period runs from the confirmed replacement, not from the interrupted
    // attempt.
    let retained = retained_entry(&after, &old);
    assert_eq!(retained.authored_event_id, before.authored_event_id);
    assert_eq!(
        retained.replaced_at,
        Timestamp(before.refresh_at.unwrap().0 + 60 * 60)
    );
    let owned = runtime.durably_owned_key_packages().unwrap();
    assert!(owned.contains(&old));
    assert!(owned.contains(&pending.key_package));
}

/// Publisher that refuses chosen signed artifacts as unusable, as the Nostr
/// publisher refuses one an earlier build signed under rules this one no
/// longer accepts. Records each attempt as `(artifact id, sent)`.
#[derive(Clone, Default)]
struct RefusingKeyPackages {
    refused: Arc<Mutex<Vec<MessageId>>>,
    refuse_all: Arc<std::sync::atomic::AtomicBool>,
    /// Accept only the first endpoint of each publication.
    partial: Arc<std::sync::atomic::AtomicBool>,
    /// Never answer for an artifact it does not refuse, as if the process
    /// stopped while sending it.
    hang: Arc<std::sync::atomic::AtomicBool>,
    attempts: Arc<Mutex<Vec<(MessageId, bool)>>>,
}

impl RefusingKeyPackages {
    fn refuse(&self, id: &MessageId) {
        self.refused.lock().unwrap().push(id.clone());
    }

    fn attempts(&self) -> Vec<(MessageId, bool)> {
        self.attempts.lock().unwrap().clone()
    }
}

#[async_trait]
impl KeyPackagePublisher for RefusingKeyPackages {
    fn legacy_slot_id(
        &self,
        account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        Ok(Some(test_key_package_slot(account_id)))
    }

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
        let refused = self.refuse_all.load(Ordering::Relaxed)
            || self.refused.lock().unwrap().contains(&artifact.id);
        self.attempts
            .lock()
            .unwrap()
            .push((artifact.id.clone(), !refused));
        if refused {
            return Err(KeyPackagePublishError::unusable_artifact(
                "injected unusable artifact",
            ));
        }
        if self.hang.load(Ordering::Relaxed) {
            std::future::pending::<()>().await;
        }
        let accepted = if self.partial.load(Ordering::Relaxed) {
            1
        } else {
            publication.endpoints.len()
        };
        Ok(KeyPackagePublishReceipt {
            accepted: publication.endpoints[..accepted].to_vec(),
            failed: publication.endpoints[accepted..].to_vec(),
        })
    }
}

#[tokio::test]
async fn a_replacement_the_publisher_can_no_longer_send_is_resigned() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot unusable pending").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = RefusingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    // A replacement signed by an earlier build, which this one refuses to send.
    let stale = runtime
        .prepare_fresh_key_package(vec![TransportEndpoint(KEY_ENDPOINT.into())])
        .await
        .unwrap();
    let stale_event = slot_lifecycle(&runtime)
        .pending_replacement
        .unwrap()
        .signed_event
        .unwrap();
    publisher.refuse(&stale_event.id);

    let published = runtime.publish_fresh_key_package().await.unwrap();
    assert_ne!(published, stale);
    let lifecycle = slot_lifecycle(&runtime);
    let resigned = lifecycle.authored_event_id.clone().unwrap();
    assert_eq!(
        publisher.attempts(),
        vec![(stale_event.id.clone(), false), (resigned, true)]
    );
    assert!(lifecycle.authored_event_created_at.unwrap() > stale_event.created_at);

    // The refused replacement stays held under its own publication id, since
    // an earlier build may have sent it, and its grace period started with
    // the confirmed replacement.
    let retained = retained_entry(&lifecycle, &stale);
    assert_eq!(retained.authored_event_id, Some(stale_event.id.clone()));
    assert!(!retained.awaiting_confirmed_replacement);
    assert_eq!(retained.replaced_at, wall.now());
    assert!(
        lifecycle
            .held_publications()
            .any(|(id, _)| id == &stale_event.id)
    );
    assert!(runtime.durably_owned_key_packages().unwrap().contains(&stale));
}

#[tokio::test]
async fn a_publisher_that_refuses_its_own_artifacts_gets_one_resigned_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot refusing publisher").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = RefusingKeyPackages::default();
    publisher.refuse_all.store(true, Ordering::Relaxed);
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );

    let error = runtime.publish_fresh_key_package().await.unwrap_err();
    assert!(matches!(&error, AccountError::KeyPackage(error) if error.artifact_unusable));
    assert_eq!(publisher.attempts().len(), 2, "the original and one re-signed");
    let lifecycle = slot_lifecycle(&runtime);
    let pending = lifecycle.pending_replacement.as_ref().unwrap();
    assert_eq!(pending.last_failure_code.as_deref(), Some("artifact_unusable"));
    assert_eq!(runtime.durably_owned_key_packages().unwrap().len(), 2);

    // The re-signed bytes are not superseded again, so later attempts mint no
    // further private bundles.
    for _ in 0..3 {
        runtime.publish_fresh_key_package().await.unwrap_err();
        wall.set(wall.now().0 + 60 * 60);
        runtime.run_due_maintenance().await.unwrap();
    }
    assert_eq!(runtime.durably_owned_key_packages().unwrap().len(), 2);
    assert_eq!(
        slot_lifecycle(&runtime)
            .pending_replacement
            .unwrap()
            .key_package,
        pending.key_package
    );
}

#[tokio::test]
async fn paused_maintenance_leaves_an_unusable_replacement_for_resume() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot unusable while paused").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = RefusingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    let stale = runtime
        .prepare_fresh_key_package(vec![TransportEndpoint(KEY_ENDPOINT.into())])
        .await
        .unwrap();
    let stale_event = slot_lifecycle(&runtime)
        .pending_replacement
        .unwrap()
        .signed_event
        .unwrap();
    publisher.refuse(&stale_event.id);

    // Paused maintenance may retry the prepared replacement but generates no
    // new key, and the build keeps its one replacement.
    runtime.pause_maintenance();
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(publisher.attempts(), vec![(stale_event.id.clone(), false)]);
    let paused = slot_lifecycle(&runtime);
    assert_eq!(paused.pending_replacement.unwrap().key_package, stale);
    assert!(paused.unusable_artifact_replaced_by.is_none());
    assert_eq!(runtime.durably_owned_key_packages().unwrap().len(), 1);

    runtime.resume_maintenance();
    wall.set(wall.now().0 + 60 * 60);
    runtime.run_due_maintenance().await.unwrap();
    let resumed = slot_lifecycle(&runtime);
    assert!(resumed.pending_replacement.is_none());
    assert_ne!(resumed.current_key_package, Some(stale));
    assert_eq!(runtime.durably_owned_key_packages().unwrap().len(), 2);
}

#[tokio::test]
async fn a_restart_while_sending_the_resigned_replacement_does_not_resign_again() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("kp slot resign restart").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = RefusingKeyPackages::default();
    let open = || {
        slot_runtime(
            current_session(&database, &key, b"alice"),
            publisher.clone(),
            &wall,
            0,
            &[KEY_ENDPOINT],
        )
    };
    let mut runtime = open();
    runtime
        .prepare_fresh_key_package(vec![TransportEndpoint(KEY_ENDPOINT.into())])
        .await
        .unwrap();
    let stale_event = slot_lifecycle(&runtime)
        .pending_replacement
        .unwrap()
        .signed_event
        .unwrap();
    publisher.refuse(&stale_event.id);

    // The process stops while sending the re-signed replacement, before any
    // refusal of it is recorded.
    publisher.hang.store(true, Ordering::Relaxed);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            runtime.publish_fresh_key_package()
        )
        .await
        .is_err()
    );
    drop(runtime);

    // After the restart this build's publisher refuses everything, and the
    // build has spent its one replacement.
    publisher.hang.store(false, Ordering::Relaxed);
    publisher.refuse_all.store(true, Ordering::Relaxed);
    let mut runtime = open();
    assert_eq!(runtime.durably_owned_key_packages().unwrap().len(), 2);
    for _ in 0..3 {
        runtime.publish_fresh_key_package().await.unwrap_err();
    }
    assert_eq!(runtime.durably_owned_key_packages().unwrap().len(), 2);
}

#[tokio::test]
async fn a_later_build_replaces_an_artifact_an_earlier_build_could_not_send() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot later build").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = RefusingKeyPackages::default();
    publisher.refuse_all.store(true, Ordering::Relaxed);
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.publish_fresh_key_package().await.unwrap_err();
    let refused = slot_lifecycle(&runtime).pending_replacement.unwrap();
    let refused_event = refused.signed_event.clone().unwrap();

    // An earlier build used its one replacement; this build's publisher still
    // refuses the bytes that build signed, but sends what this build signs.
    let mut lifecycle = slot_lifecycle(&runtime);
    lifecycle.unusable_artifact_replaced_by = Some("0.0.0-earlier".into());
    runtime
        .session()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    publisher.refuse_all.store(false, Ordering::Relaxed);
    publisher.refuse(&refused_event.id);

    let published = runtime.publish_fresh_key_package().await.unwrap();
    assert_ne!(published, refused.key_package);
    let lifecycle = slot_lifecycle(&runtime);
    assert!(lifecycle.pending_replacement.is_none());
    assert_eq!(
        retained_entry(&lifecycle, &refused.key_package).authored_event_id,
        Some(refused_event.id)
    );
    assert_eq!(
        lifecycle.unusable_artifact_replaced_by.as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
}

#[tokio::test]
async fn a_superseded_replacement_recorded_by_an_earlier_build_waits_for_a_confirmed_one() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot legacy superseded").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = RefusingKeyPackages::default();
    publisher.refuse_all.store(true, Ordering::Relaxed);
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    // A replacement superseded by another that no relay has acknowledged.
    runtime.publish_fresh_key_package().await.unwrap_err();
    let lifecycle = slot_lifecycle(&runtime);
    let superseded = lifecycle.retained_private_material[0].key_package.clone();

    // Rewrite the record as a build before the confirmation flag stored it.
    let mut value = serde_json::to_value(&lifecycle).unwrap();
    value["retained_private_material"][0]
        .as_object_mut()
        .unwrap()
        .remove("awaiting_confirmed_replacement");
    runtime
        .session()
        .put_key_package_lifecycle(&serde_json::from_value(value).unwrap())
        .unwrap();

    // Days pass without a confirmed replacement, and the key is kept.
    wall.set(wall.now().0 + 3 * DAY);
    runtime.run_due_maintenance().await.unwrap();
    assert!(runtime.durably_owned_key_packages().unwrap().contains(&superseded));

    // Its grace period starts at the confirmed replacement.
    publisher.refuse_all.store(false, Ordering::Relaxed);
    wall.set(wall.now().0 + 60 * 60);
    runtime.run_due_maintenance().await.unwrap();
    let confirmed_at = wall.now().0;
    assert!(slot_lifecycle(&runtime).pending_replacement.is_none());
    wall.set(confirmed_at + cgka_traits::KEY_PACKAGE_REPLACEMENT_GRACE_SECS - 1);
    runtime.run_due_maintenance().await.unwrap();
    assert!(runtime.durably_owned_key_packages().unwrap().contains(&superseded));
    wall.set(confirmed_at + cgka_traits::KEY_PACKAGE_REPLACEMENT_GRACE_SECS);
    runtime.run_due_maintenance().await.unwrap();
    assert!(!runtime.durably_owned_key_packages().unwrap().contains(&superseded));
}

#[tokio::test]
async fn a_current_key_package_the_publisher_can_no_longer_send_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot unusable current").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = RefusingKeyPackages::default();
    publisher.partial.store(true, Ordering::Relaxed);
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT, "wss://keys-2.example"],
    );
    let first = runtime.publish_fresh_key_package().await.unwrap();
    let published = slot_lifecycle(&runtime);
    let first_event = published.authored_event_id.clone().unwrap();
    assert!(runtime.key_package_has_pending_fanout().unwrap());

    // Resending it to the relay that missed it is refused, so it is replaced
    // by a freshly signed KeyPackage in the same slot.
    publisher.partial.store(false, Ordering::Relaxed);
    publisher.refuse(&first_event);
    wall.set(wall.now().0 + 60 * 60);
    runtime.run_due_maintenance().await.unwrap();
    let replaced = slot_lifecycle(&runtime);
    let replacement_event = replaced.authored_event_id.clone().unwrap();
    assert_ne!(replacement_event, first_event);
    assert_eq!(replaced.stable_slot_id, published.stable_slot_id);
    assert_eq!(
        publisher.attempts(),
        vec![
            (first_event.clone(), true),
            (first_event.clone(), false),
            (replacement_event, true),
        ]
    );
    assert!(!runtime.key_package_has_pending_fanout().unwrap());
    assert_eq!(
        retained_entry(&replaced, &first).authored_event_id,
        Some(first_event)
    );
}
