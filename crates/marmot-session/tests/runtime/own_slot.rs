// The own-slot check's runtime half (mdk#2628 item 3.4): a publication in
// this device's slot that it did not make is replaced by a newer KeyPackage
// of its own, and one dated too far ahead to outrank is deleted by id (D63)
// without ever holding back the device's refreshes.
// `foundation/key-packages.md`, "A publication the device did not make".

#[derive(Clone, Default)]
struct DeletingKeyPackages {
    publications: RecordingKeyPackages,
    deletions: Arc<Mutex<Vec<KeyPackageEventDeletion>>>,
    /// Endpoints answer the deletion without accepting it.
    refuse: Arc<std::sync::atomic::AtomicBool>,
}

impl DeletingKeyPackages {
    fn deletions(&self) -> Vec<KeyPackageEventDeletion> {
        self.deletions.lock().unwrap().clone()
    }
}

#[async_trait]
impl KeyPackagePublisher for DeletingKeyPackages {
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
        Ok(KeyPackagePublishReceipt {
            accepted: withdrawal.endpoints.clone(),
            failed: Vec::new(),
        })
    }

    async fn delete_key_package_event(
        &self,
        deletion: &KeyPackageEventDeletion,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        self.deletions.lock().unwrap().push(deletion.clone());
        Ok(if self.refuse.load(Ordering::Relaxed) {
            KeyPackagePublishReceipt {
                accepted: Vec::new(),
                failed: deletion.endpoints.clone(),
            }
        } else {
            KeyPackagePublishReceipt {
                accepted: deletion.endpoints.clone(),
                failed: Vec::new(),
            }
        })
    }
}

fn foreign(byte: u8, created_at: u64) -> ForeignSlotPublication {
    ForeignSlotPublication {
        event_id: cgka_traits::MessageId::new(vec![byte; 32]),
        created_at: cgka_traits::Timestamp(created_at),
    }
}

#[tokio::test]
async fn a_foreign_slot_publication_is_replaced_by_a_newer_one() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp foreign slot publication").unwrap();
    let now = unix_now();
    let wall = Arc::new(TestWallClock::new(now));
    let publisher = DeletingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let published = slot_lifecycle(&runtime).authored_event_created_at.unwrap();
    assert!(!runtime.key_package_network_maintenance_due().unwrap());

    // Someone else's publication, newer than this device's: the next
    // publication is newer still.
    let outcome = runtime
        .replace_foreign_slot_publications(&[foreign(7, now + 100)])
        .await
        .unwrap();
    assert!(outcome.replacing);
    assert_eq!(outcome.beyond_skew, 0);
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    // Resending the outranked event would change nothing.
    assert!(runtime.key_package_republish_falls_back().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    let publications = publisher.publications.publications();
    assert_eq!(publications.len(), 2);
    assert_ne!(publications[0].key_package, publications[1].key_package);
    assert_eq!(publications[1].created_at, cgka_traits::Timestamp(now + 101));
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    assert!(!runtime.key_package_republish_falls_back().unwrap());

    // One older than this device's is still what some relay serves as
    // current, so this device publishes again, newer than its own.
    runtime
        .replace_foreign_slot_publications(&[foreign(8, published.0)])
        .await
        .unwrap();
    runtime.run_due_maintenance().await.unwrap();
    let publications = publisher.publications.publications();
    assert_eq!(publications.len(), 3);
    assert_eq!(publications[2].created_at, cgka_traits::Timestamp(now + 102));
    assert!(publisher.deletions().is_empty());
}

#[tokio::test]
async fn a_foreign_publication_too_far_ahead_is_deleted_by_id_and_never_blocks_refreshes() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp foreign slot future").unwrap();
    let now = unix_now();
    let wall = Arc::new(TestWallClock::new(now));
    let publisher = DeletingKeyPackages::default();
    let open = || {
        slot_runtime(
            current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
            publisher.clone(),
            &wall,
            0,
            &[KEY_ENDPOINT],
        )
    };
    let mut runtime = open();
    runtime.publish_fresh_key_package().await.unwrap();
    let published = slot_lifecycle(&runtime).authored_event_created_at.unwrap();
    let weekly = slot_lifecycle(&runtime).refresh_at;

    // A relay that accepts nothing leaves the slot as it was, and the
    // weekly refresh where it was.
    publisher.refuse.store(true, Ordering::Relaxed);
    let far = foreign(9, now + 10 * DAY);
    let outcome = runtime
        .replace_foreign_slot_publications(std::slice::from_ref(&far))
        .await
        .unwrap();
    assert_eq!(outcome.beyond_skew, 1);
    assert_eq!(outcome.deleted, 0);
    assert!(!outcome.replacing);
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    assert_eq!(slot_lifecycle(&runtime).refresh_at, weekly);

    // One request naming that event alone, at the current time.
    publisher.refuse.store(false, Ordering::Relaxed);
    let outcome = runtime
        .replace_foreign_slot_publications(std::slice::from_ref(&far))
        .await
        .unwrap();
    assert_eq!(outcome.deleted, 1);
    assert!(outcome.replacing);
    let deletions = publisher.deletions();
    assert_eq!(deletions.len(), 2);
    assert_eq!(deletions[1].account_id, runtime.session().self_id());
    assert_eq!(deletions[1].event_id, far.event_id);
    assert_eq!(deletions[1].created_at, cgka_traits::Timestamp(now));
    assert_eq!(
        deletions[1].endpoints,
        vec![TransportEndpoint(KEY_ENDPOINT.into())]
    );

    // The slot is filled again, even across a restart, just after this
    // device's own publication: the far one never sets the next
    // publication's time.
    drop(runtime);
    let mut runtime = open();
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    runtime.run_due_maintenance().await.unwrap();
    let publications = publisher.publications.publications();
    assert_eq!(publications.len(), 2);
    assert_eq!(
        publications[1].created_at,
        cgka_traits::Timestamp(published.0 + 1)
    );
    assert_ne!(
        slot_lifecycle(&runtime).phase,
        cgka_traits::MaintenancePhase::ClockSkewBlocked
    );
    assert!(!runtime.key_package_network_maintenance_due().unwrap());

    // The weekly refresh still runs.
    let refresh_at = slot_lifecycle(&runtime).refresh_at.unwrap();
    wall.set(refresh_at.0);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(publisher.publications.publications().len(), 3);
}

#[tokio::test]
async fn a_foreign_publication_this_device_can_no_longer_outrank_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp foreign slot clock back").unwrap();
    let now = unix_now();
    let wall = Arc::new(TestWallClock::new(now));
    let publisher = DeletingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.publish_fresh_key_package().await.unwrap();
    runtime
        .replace_foreign_slot_publications(&[foreign(7, now + 200)])
        .await
        .unwrap();
    assert!(runtime.key_package_network_maintenance_due().unwrap());

    // The clock went back before maintenance ran: the foreign publication is
    // now past what this device would sign. It is dropped, not a block.
    wall.set(now - 150);
    runtime.run_due_maintenance().await.unwrap();
    assert_ne!(
        slot_lifecycle(&runtime).phase,
        cgka_traits::MaintenancePhase::ClockSkewBlocked
    );
    let publications = publisher.publications.publications();
    assert_eq!(publications.len(), 2);
    assert_eq!(publications[1].created_at, cgka_traits::Timestamp(now + 1));
}

#[tokio::test]
async fn paused_or_withdrawn_slots_ignore_foreign_publications() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("kp foreign slot paused").unwrap();
    let now = unix_now();
    let wall = Arc::new(TestWallClock::new(now));
    let publisher = DeletingKeyPackages::default();
    let mut runtime = slot_runtime(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice"),
        publisher.clone(),
        &wall,
        0,
        &[KEY_ENDPOINT],
    );
    runtime.publish_fresh_key_package().await.unwrap();

    runtime.pause_maintenance();
    let found = [foreign(7, now + 100), foreign(9, now + 10 * DAY)];
    let outcome = runtime
        .replace_foreign_slot_publications(&found)
        .await
        .unwrap();
    assert_eq!(outcome, ForeignSlotOutcome::default());
    runtime.resume_maintenance();
    assert!(!runtime.key_package_network_maintenance_due().unwrap());

    runtime.withdraw_key_package_slot().await.unwrap();
    let outcome = runtime
        .replace_foreign_slot_publications(&found)
        .await
        .unwrap();
    assert_eq!(outcome, ForeignSlotOutcome::default());
    assert!(publisher.deletions().is_empty());
}
