// Withdrawing this device's KeyPackage slot at sign-out (mdk#2628 item 1.2):
// one request naming only this device's slot, recorded before it goes out and
// undone when no relay accepts it, then a republish once the device runs
// again. `foundation/key-packages.md`, "Stopping publication".

#[derive(Clone, Default)]
struct WithdrawingKeyPackages {
    publications: RecordingKeyPackages,
    withdrawals: Arc<Mutex<Vec<KeyPackageSlotWithdrawal>>>,
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
        self.publications
            .publish_prepared_key_package(publication, artifact)
            .await
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot withdrawal refused").unwrap();
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
    let before = slot_lifecycle(&runtime);

    publisher.refuse.store(true, Ordering::Relaxed);
    runtime.withdraw_key_package_slot().await.unwrap_err();
    assert_eq!(publisher.withdrawals().len(), 1);
    assert_eq!(slot_lifecycle(&runtime), before);

    // The slot is still this device's to keep fresh.
    wall.set(before.refresh_at.unwrap().0);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(publisher.publications.publications().len(), 2);
}

#[tokio::test]
async fn a_restart_while_withdrawing_the_slot_republishes_it() {
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp slot withdrawal unpublished").unwrap();
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let publisher = WithdrawingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    assert_eq!(runtime.withdraw_key_package_slot().await.unwrap(), 0);
    assert!(publisher.withdrawals().is_empty());
}
