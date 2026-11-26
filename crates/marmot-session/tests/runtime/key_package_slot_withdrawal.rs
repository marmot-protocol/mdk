// Withdrawing this device's KeyPackage slot at sign-out (mdk#2628 item 1.2):
// one request naming only this device's slot, recorded before it goes out and
// undone when no relay accepts it, then a republish once the device runs
// again. `foundation/key-packages.md`, "Stopping publication".

#[derive(Clone, Default)]
struct WithdrawingKeyPackages {
    publications: RecordingKeyPackages,
    withdrawals: Arc<Mutex<Vec<KeyPackageSlotWithdrawal>>>,
    next_publication_error: Arc<Mutex<Option<KeyPackagePublishError>>>,
    /// Endpoints answer the withdrawal without accepting it.
    refuse: Arc<std::sync::atomic::AtomicBool>,
    /// Never answer the withdrawal, as if the process stopped while sending it.
    hang: Arc<std::sync::atomic::AtomicBool>,
}

impl WithdrawingKeyPackages {
    fn withdrawals(&self) -> Vec<KeyPackageSlotWithdrawal> {
        self.withdrawals.lock().unwrap().clone()
    }
}

#[async_trait]
impl KeyPackagePublisher for WithdrawingKeyPackages {
    fn legacy_slot_id(
        &self,
        account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        self.publications.legacy_slot_id(account_id)
    }

    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<cgka_traits::SignedPublicationArtifact, KeyPackagePublishError> {
        self.publications.prepare_key_package(publication).await
    }

    async fn publish_prepared_key_package(
        &self,
        publication: &KeyPackagePublication,
        artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        let receipt = self
            .publications
            .publish_prepared_key_package(publication, artifact)
            .await?;
        self.next_publication_error
            .lock()
            .unwrap()
            .take()
            .map_or(Ok(receipt), Err)
    }

    async fn withdraw_key_package_slot(
        &self,
        withdrawal: &KeyPackageSlotWithdrawal,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        self.withdrawals.lock().unwrap().push(withdrawal.clone());
        if self.hang.load(Ordering::Relaxed) {
            std::future::pending::<()>().await;
        }
        Ok(if self.refuse.load(Ordering::Relaxed) {
            KeyPackagePublishReceipt {
                accepted: Vec::new(),
                failed: withdrawal.endpoints.clone(),
            }
        } else {
            KeyPackagePublishReceipt {
                accepted: withdrawal.endpoints.clone(),
                failed: Vec::new(),
            }
        })
    }
}

#[tokio::test]
async fn a_withdrawn_slot_stays_empty_until_the_device_runs_again() {
    let dir = relaxed_storage_dir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("kp slot withdrawn").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = WithdrawingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let published = slot_lifecycle(&runtime);

    // One request, naming this device's slot and covering its publication.
    assert_eq!(runtime.withdraw_key_package_slot().await.unwrap(), 1);
    let withdrawals = publisher.withdrawals();
    assert_eq!(withdrawals.len(), 1);
    let withdrawal = &withdrawals[0];
    assert_eq!(withdrawal.account_id, runtime.session().self_id());
    assert_eq!(withdrawal.slot_id, published.stable_slot_id);
    assert!(withdrawal.created_at >= published.authored_event_created_at.unwrap());
    assert_eq!(
        withdrawal.endpoints,
        vec![TransportEndpoint(KEY_ENDPOINT.into())]
    );
    assert_eq!(
        slot_lifecycle(&runtime).slot_withdrawn_at,
        Some(withdrawal.created_at)
    );

    // This runtime publishes nothing more, even once a refresh is due.
    wall.set(published.refresh_at.unwrap().0);
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    runtime.publish_fresh_key_package().await.unwrap_err();
    runtime.republish_key_package().await.unwrap_err();
    assert_eq!(publisher.publications.publications().len(), 1);
    drop(runtime);

    // Signed back in, the device republishes into its slot at once, after the
    // withdrawal.
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    let publications = publisher.publications.publications();
    assert_eq!(publications.len(), 2);
    assert_eq!(publications[1].slot_id, published.stable_slot_id);
    assert!(publications[1].created_at > withdrawal.created_at);
    assert_eq!(slot_lifecycle(&runtime).slot_withdrawn_at, None);
}

#[tokio::test]
async fn a_withdrawal_no_relay_accepts_leaves_the_slot_as_it_was() {
    let dir = relaxed_storage_dir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("kp slot withdrawal refused").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = WithdrawingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let before = slot_lifecycle(&runtime);

    publisher.refuse.store(true, Ordering::Relaxed);
    runtime.withdraw_key_package_slot().await.unwrap_err();
    assert_eq!(publisher.withdrawals().len(), 1);
    assert_eq!(slot_lifecycle(&runtime), before);

    // The device is signing out, so this runtime publishes nothing more ...
    wall.set(before.refresh_at.unwrap().0);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(publisher.publications.publications().len(), 1);
    drop(runtime);

    // ... and the slot is still this device's to keep fresh when it runs
    // again.
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(publisher.publications.publications().len(), 2);
}

#[tokio::test]
async fn a_refused_second_withdrawal_keeps_the_first_one() {
    let dir = relaxed_storage_dir().unwrap();
    let key = SqlCipherKey::new("kp slot second withdrawal refused").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = WithdrawingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let published = slot_lifecycle(&runtime);
    runtime.withdraw_key_package_slot().await.unwrap();
    let withdrawn = slot_lifecycle(&runtime);

    publisher.refuse.store(true, Ordering::Relaxed);
    runtime.withdraw_key_package_slot().await.unwrap_err();
    assert_eq!(slot_lifecycle(&runtime), withdrawn);

    // The first withdrawal still stands: this runtime publishes nothing.
    wall.set(published.refresh_at.unwrap().0);
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    runtime.publish_fresh_key_package().await.unwrap_err();
    runtime.republish_key_package().await.unwrap_err();
    assert_eq!(publisher.publications.publications().len(), 1);
}

#[tokio::test]
async fn a_restart_while_withdrawing_the_slot_republishes_it() {
    let dir = relaxed_storage_dir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("kp slot withdrawal restart").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = WithdrawingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.publish_fresh_key_package().await.unwrap();

    // The process stops while the request is out.
    publisher.hang.store(true, Ordering::Relaxed);
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        runtime.withdraw_key_package_slot(),
    )
    .await
    .unwrap_err();
    drop(runtime);
    publisher.hang.store(false, Ordering::Relaxed);

    // The withdrawal was recorded before it went out, so a relay may have
    // dropped the slot: the next run republishes into it.
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    let withdrawn_at = slot_lifecycle(&runtime).slot_withdrawn_at.unwrap();
    runtime.run_due_maintenance().await.unwrap();
    let publications = publisher.publications.publications();
    assert_eq!(publications.len(), 2);
    assert!(publications[1].created_at > withdrawn_at);
    assert_eq!(slot_lifecycle(&runtime).slot_withdrawn_at, None);
}

#[tokio::test]
async fn a_replacement_prepared_before_the_withdrawal_is_not_published_after_it() {
    let dir = relaxed_storage_dir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("kp slot withdrawal pending").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = WithdrawingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let prepared = runtime
        .prepare_fresh_key_package(vec![TransportEndpoint(KEY_ENDPOINT.into())])
        .await
        .unwrap();
    let staged_at = slot_lifecycle(&runtime)
        .pending_replacement
        .unwrap()
        .authored_created_at;

    runtime.withdraw_key_package_slot().await.unwrap();
    // The request also covers the prepared replacement, which a relay may
    // have received.
    assert!(publisher.withdrawals()[0].created_at >= staged_at);
    drop(runtime);

    // Relays drop it with the slot, so a newer one replaces it, and its key
    // is retained like any superseded replacement: for the grace period
    // after the newer one's confirmed publication.
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.run_due_maintenance().await.unwrap();
    let publications = publisher.publications.publications();
    assert_eq!(publications.len(), 2);
    assert_ne!(publications[1].key_package, prepared);
    let lifecycle = slot_lifecycle(&runtime);
    assert_eq!(lifecycle.slot_withdrawn_at, None);
    assert!(lifecycle.pending_replacement.is_none());
    let retained = retained_entry(&lifecycle, &prepared);
    assert_eq!(
        retained.delete_at(),
        Timestamp(wall.now().0 + cgka_traits::KEY_PACKAGE_REPLACEMENT_GRACE_SECS)
    );
    assert!(
        runtime
            .durably_owned_key_packages()
            .unwrap()
            .contains(&prepared)
    );
}

#[tokio::test]
async fn withdrawing_again_after_the_clock_moves_back_keeps_the_later_time() {
    let dir = relaxed_storage_dir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("kp slot withdrawal clock").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = WithdrawingKeyPackages::default();
    let runtime = |publisher: &WithdrawingKeyPackages| {
        slot_runtime(
            current_session(&database, &key, b"alice"),
            publisher.clone(),
            &wall,
            0,
            &[KEY_ENDPOINT],
        )
    };
    let mut first = runtime(&publisher);
    first.publish_fresh_key_package().await.unwrap();
    let start = wall.now().0;
    wall.set(start + 200);
    first.withdraw_key_package_slot().await.unwrap();
    drop(first);

    // Signed out again after the clock went back, the device asks again
    // without moving the deletion's time back.
    wall.set(start + 100);
    let mut second = runtime(&publisher);
    second.withdraw_key_package_slot().await.unwrap();
    drop(second);
    let withdrawals = publisher.withdrawals();
    assert_eq!(withdrawals.len(), 2);
    assert!(withdrawals[1].created_at >= withdrawals[0].created_at);

    // So the next publication is newer than both deletions.
    let mut third = runtime(&publisher);
    third.run_due_maintenance().await.unwrap();
    let publications = publisher.publications.publications();
    assert_eq!(publications.len(), 2);
    assert!(publications[1].created_at > withdrawals[0].created_at);
}

#[tokio::test]
async fn a_device_that_never_published_withdraws_nothing() {
    let dir = relaxed_storage_dir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("kp slot withdrawal unpublished").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = WithdrawingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    assert_eq!(runtime.withdraw_key_package_slot().await.unwrap(), 0);
    assert!(publisher.withdrawals().is_empty());

    // Signing out, this runtime publishes no first KeyPackage either.
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    runtime.publish_fresh_key_package().await.unwrap_err();
    assert!(publisher.publications.publications().is_empty());
    drop(runtime);

    // The device publishes once it runs again.
    let mut runtime = slot_runtime(
        current_session(&database, &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.publish_fresh_key_package().await.unwrap();
    assert_eq!(publisher.publications.publications().len(), 1);
}

#[tokio::test]
async fn a_rotated_setup_fallback_is_withdrawn_after_private_key_retirement() {
    assert_rotated_setup_fallback_withdrawal(None, false, true).await;
}

#[tokio::test]
async fn an_ambiguous_setup_fallback_is_withdrawn_after_rotation() {
    assert_rotated_setup_fallback_withdrawal(
        Some(KeyPackagePublishError::exposed("fallback acknowledgement lost")),
        false,
        true,
    )
    .await;
}

#[tokio::test]
async fn an_unexposed_setup_fallback_is_not_withdrawn_after_rotation() {
    assert_rotated_setup_fallback_withdrawal(
        Some(KeyPackagePublishError::unexposed("failed before transport")),
        false,
        false,
    )
    .await;
}

#[tokio::test]
async fn an_expired_setup_fallback_is_not_withdrawn_after_rotation() {
    assert_rotated_setup_fallback_withdrawal(None, true, false).await;
}

async fn assert_rotated_setup_fallback_withdrawal(
    fallback_error: Option<KeyPackagePublishError>,
    expire_fallback: bool,
    withdraw_fallback: bool,
) {
    use marmot_session::KeyPackagePublicationRoutes;

    let dir = relaxed_storage_dir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("kp historical setup fallback withdrawal").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = WithdrawingKeyPackages::default();
    let open = || {
        slot_runtime(
            current_session(&database, &key, b"alice"),
            publisher.clone(),
            &wall,
            0,
            &[KEY_ENDPOINT],
        )
    };
    let declared = TransportEndpoint(KEY_ENDPOINT.into());
    let fallback = TransportEndpoint("wss://fallback.example".into());
    let unattempted = TransportEndpoint("wss://never-sent.example".into());
    let fallback_failed = fallback_error.is_some();
    *publisher.next_publication_error.lock().unwrap() = fallback_error;

    let mut runtime = open();
    let result = runtime
        .publish_fresh_key_package_with_routes(Some(KeyPackagePublicationRoutes {
            attempt: std::slice::from_ref(&fallback),
            retain: &[declared.clone(), unattempted],
            via_fallback: true,
        }))
        .await;
    assert_eq!(result.is_err(), fallback_failed);
    if fallback_failed {
        // Recover through the current outbox after the fallback send failed.
        drop(runtime);
        runtime = open();
        runtime.publish_fresh_key_package().await.unwrap();
    }
    let initial = slot_lifecycle(&runtime);
    let closes_at = initial.current_not_after.unwrap();
    let rotate_at = initial.refresh_at.unwrap();

    // Ordinary rotation reaches only the declared outbox. Close and reopen
    // before withdrawal so the fallback cannot come from a runtime cache.
    wall.set(rotate_at.0);
    runtime.run_due_maintenance().await.unwrap();
    let rotated = slot_lifecycle(&runtime);
    assert_ne!(rotated.authored_event_id, initial.authored_event_id);
    assert_eq!(rotated.stable_slot_id, initial.stable_slot_id);
    let publications = publisher.publications.publications();
    assert_eq!(publications[0].endpoints, [fallback.clone()]);
    assert!(publications[1..].iter().all(|publication| publication.endpoints == [declared.clone()]));
    drop(runtime);

    let mut runtime = open();
    if expire_fallback {
        wall.set(closes_at.0);
    } else {
        wall.set(rotate_at.0 + DAY);
        assert!(wall.now() < closes_at);
        assert_eq!(runtime.sweep_expired_key_package_private_material().unwrap(), 1);
    }
    assert_eq!(runtime.withdraw_key_package_slot().await.unwrap(), if withdraw_fallback { 2 } else { 1 });
    let withdrawals = publisher.withdrawals();
    let withdrawal = withdrawals.first().unwrap();
    assert_eq!(withdrawals.len(), 1);
    assert_eq!(withdrawal.slot_id, initial.stable_slot_id);
    assert!(withdrawal.created_at >= initial.authored_event_created_at.unwrap());
    let expected = if withdraw_fallback { vec![declared, fallback] } else { vec![declared] };
    assert_eq!(withdrawal.endpoints, expected);
    assert!(slot_lifecycle(&runtime).fallback_withdrawal_targets.is_empty());
}
