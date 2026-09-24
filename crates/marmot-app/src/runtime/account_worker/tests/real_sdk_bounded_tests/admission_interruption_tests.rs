//! Account-worker admission and completion fences for returned bounded results.

use super::*;

#[tokio::test]
async fn receipt_release_during_returned_batch_preserves_replay_eligibility() {
    use cgka_traits::storage::MessageStorage;
    use cgka_traits::{EpochId, MessageId, MessageRecord, MessageState};
    use storage_sqlite::TransportReconciliationItem;
    use transport_nostr_adapter::NostrAcquisitionEnd;

    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let fixture = super::super::bounded_known_fixture().await;
    let storage = fixture.app.account_storage("bob").unwrap();
    let released_id = MessageId::new([0xD4; 32]);
    let released = MessageRecord {
        id: released_id.clone(),
        group_id: fixture.group.clone(),
        epoch: EpochId(0),
        state: MessageState::Processed,
        payload: Vec::new(),
        deferred_peel: None,
    };
    storage.put_message(&released).unwrap();
    let now = crate::unix_now_seconds();
    storage
        .record_transport_reconciliation_item(
            &fixture.route,
            &TransportReconciliationItem {
                event_id: released_id.as_slice().try_into().unwrap(),
                created_at: now,
            },
        )
        .unwrap();
    assert!(
        storage
            .retained_recovery_event(
                &fixture.route,
                &released_id.as_slice().try_into().unwrap(),
                None,
                now,
            )
            .unwrap()
    );
    let before = storage.recovery_revision_fence().unwrap();
    fixture
        .runtime
        .shared_services()
        .bounded_pause_before_admission
        .store(true, Ordering::SeqCst);
    *fixture.relay.acquisition_result.lock().unwrap() =
        Some(super::super::controlled_bounded_result(
            vec![fixture.historical.clone()],
            NostrAcquisitionEnd::RequestPolicySatisfied,
            Vec::new(),
            NostrAcquisitionEnd::Deadline,
        ));
    let shared = fixture.runtime.shared_services();
    let mut result_ready = Box::pin(shared.bounded_result_ready.notified());
    result_ready.as_mut().enable();
    super::super::advance_bounded_fixture_clock(&fixture).await;
    timeout(Duration::from_secs(5), result_ready.as_mut())
        .await
        .expect("worker owns a returned transport batch before admission");
    assert!(
        !storage
            .retained_recovery_event(
                &fixture.route,
                &fixture.event_id,
                None,
                fixture.historical.created_at,
            )
            .unwrap()
    );
    assert_eq!(storage.recovery_revision_fence().unwrap(), before);

    // The real SQLCipher release path retires both the raw row and advertised
    // retained inventory, then journals the obsolete receipt for worker sync.
    storage.release_message_for_replay(&released).unwrap();
    let after_release = storage.recovery_revision_fence().unwrap();
    assert!(after_release.inventory_revision > before.inventory_revision);
    assert!(
        !storage
            .retained_recovery_event(
                &fixture.route,
                &released_id.as_slice().try_into().unwrap(),
                None,
                now,
            )
            .unwrap()
    );
    let mut finished = Box::pin(shared.bounded_recovery_finished.notified());
    finished.as_mut().enable();
    shared
        .bounded_pause_before_admission
        .store(false, Ordering::SeqCst);
    timeout(Duration::from_secs(5), finished.as_mut())
        .await
        .expect("stale returned batch finishes without admission");
    assert!(
        !storage
            .retained_recovery_event(
                &fixture.route,
                &fixture.event_id,
                None,
                fixture.historical.created_at,
            )
            .unwrap()
    );
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|d| d.ticket.id == fixture.demand_id)
    );

    fixture.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn replacement_attempt_keeps_valid_admission_but_rejects_old_completion() {
    use transport_nostr_adapter::NostrAcquisitionEnd;

    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let fixture = super::super::bounded_known_fixture().await;
    let storage = fixture.app.account_storage("bob").unwrap();
    let shared = fixture.runtime.shared_services();
    shared
        .bounded_pause_before_admission
        .store(true, Ordering::SeqCst);
    *fixture.relay.acquisition_result.lock().unwrap() =
        Some(super::super::controlled_bounded_result(
            vec![fixture.historical.clone()],
            NostrAcquisitionEnd::RequestPolicySatisfied,
            Vec::new(),
            NostrAcquisitionEnd::Deadline,
        ));
    let mut ready = Box::pin(shared.bounded_result_ready.notified());
    ready.as_mut().enable();
    super::super::advance_bounded_fixture_clock(&fixture).await;
    timeout(Duration::from_secs(5), ready.as_mut())
        .await
        .expect("old attempt owns the returned valid ciphertext");
    let old_attempt = storage.recovery_retry_state().unwrap().attempt_serial;
    let fence = storage.recovery_revision_fence().unwrap();
    let original_scope = storage
        .recovery_scope_snapshots(fixture.demand_id)
        .unwrap()
        .remove(0);
    let now = crate::client::recovery::wall_now_ms().unwrap();
    let newer = storage
        .reserve_recovery_attempt(&fence, now, 15_000, true)
        .unwrap()
        .expect("fault injection reserves a newer attempt under the same obligation");
    assert!(newer.attempt_serial > old_attempt);
    assert_eq!(storage.recovery_revision_fence().unwrap(), fence);
    let new_token = storage
        .install_recovery_scope_plan(
            &fence,
            newer.attempt_serial,
            fixture.demand_id,
            &[original_scope.plan],
        )
        .unwrap()
        .expect("the newer attempt replaces the old frozen scope")
        .remove(0);
    assert!(new_token.revision > original_scope.token.revision);
    let mut finished = Box::pin(shared.bounded_recovery_finished.notified());
    finished.as_mut().enable();
    shared
        .bounded_pause_before_admission
        .store(false, Ordering::SeqCst);
    timeout(Duration::from_secs(5), finished.as_mut())
        .await
        .expect("old result reaches conditional completion after scope replacement");
    assert!(
        storage
            .retained_recovery_event(
                &fixture.route,
                &fixture.event_id,
                None,
                fixture.historical.created_at,
            )
            .unwrap(),
        "valid bytes may be admitted despite stale completion authority"
    );
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|d| d.ticket.id == fixture.demand_id)
    );
    fixture.runtime.shutdown_and_close().await.unwrap();
}
