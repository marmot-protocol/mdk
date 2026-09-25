//! Real SDK result rejection after receipt release changes the inventory fence.

use super::*;
use cgka_traits::storage::MessageStorage;
use cgka_traits::{EpochId, MessageId, MessageRecord, MessageState};
use storage_sqlite::TransportReconciliationItem;

#[tokio::test]
async fn real_sdk_returned_event_rejected_after_receipt_release() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let bootstrap = MockRelay::run().await.unwrap();
    let bootstrap_url = bootstrap.url().await.to_string();
    let (left_url, left) = counted_relay().await;
    let (right_url, right) = counted_relay().await;
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        bootstrap_url.clone(),
        crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let shared = runtime.shared_services();
    shared
        .bounded_group_recovery_enabled
        .store(true, Ordering::SeqCst);
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &bootstrap_url);
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package("bob").await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "exact fence",
            std::slice::from_ref(&bob.account_id_hex),
            AppCreateGroupOptions {
                relays: Some(vec![left_url, right_url]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            runtime.catch_up_accounts().await.unwrap();
            if app
                .group(&bob.label, &hex::encode(&group))
                .unwrap()
                .is_some()
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Bob joins before the history gap");

    runtime
        .sign_out(
            &alice.label,
            crate::SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    runtime
        .send_message(&bob.label, &group, b"exact result fence".to_vec())
        .await
        .unwrap();
    let historical = left.group_event();
    assert_eq!(right.group_event()["id"], historical["id"]);
    let event_id: [u8; 32] = hex::decode(historical["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let created_at = historical["created_at"].as_u64().unwrap();
    let route: [u8; 32] = hex::decode(
        app.group(&alice.label, &hex::encode(&group))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    let route = storage_sqlite::TransportReconciliationRoute::Group(route);
    let storage = app.account_storage(&alice.label).unwrap();
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );
    runtime.sign_in_account(&alice.label).await.unwrap();
    timeout(Duration::from_secs(45), runtime.catch_up_accounts())
        .await
        .expect("startup catch-up ends before the exact demand")
        .unwrap();
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .all(|d| d.cause != storage_sqlite::RecoveryCause::KnownEvent),
        "startup carries no prior exact-ID demand"
    );

    // The distinct synthetic receipt drives the real SQLCipher release
    // transaction. The target is a valid encrypted message from Bob.
    let released = MessageRecord {
        id: MessageId::new([0xD4; 32]),
        group_id: group.clone(),
        epoch: EpochId(0),
        state: MessageState::Processed,
        payload: Vec::new(),
        deferred_peel: None,
    };
    storage.put_message(&released).unwrap();
    storage
        .record_transport_reconciliation_item(
            &route,
            &TransportReconciliationItem {
                event_id: released.id.as_slice().try_into().unwrap(),
                created_at,
            },
        )
        .unwrap();
    assert!(
        storage
            .retained_recovery_event(
                &route,
                &released.id.as_slice().try_into().unwrap(),
                None,
                created_at,
            )
            .unwrap()
    );

    shared
        .bounded_pause_before_admission
        .store(true, Ordering::SeqCst);
    let mut first_result = Box::pin(shared.bounded_result_ready.notified());
    first_result.as_mut().enable();
    storage
        .request_recovery(
            storage_sqlite::RecoveryRequest::KnownEvent {
                group_id: group.as_slice(),
                event_id: &event_id,
            },
            crate::client::recovery::wall_now_ms().unwrap(),
        )
        .unwrap();
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    let commands = runtime
        .accounts()
        .worker_commands(&alice.label)
        .await
        .unwrap();
    let (respond, status) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: group.clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(5), status)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(10), first_result.as_mut()).await.unwrap_or_else(|_| {
        panic!(
            "first bounded result absent: exact_requests={}, retry_serial={}, demands={}, probes={}",
            left.counts().id_requests,
            storage.recovery_retry_state().unwrap().attempt_serial,
            storage.pending_recovery_demands().unwrap().len(),
            shared.bounded_preparation_probes.load(Ordering::SeqCst),
        )
    });
    let first_witness = shared
        .bounded_result_witness
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(first_witness.account_label, alice.label);
    assert_eq!(first_witness.event_id, event_id);
    assert_eq!(
        first_witness.attempt_serial,
        storage.recovery_retry_state().unwrap().attempt_serial
    );
    assert!(
        first_witness.matching_items > 0,
        "real SDK result contains the requested event"
    );
    assert_eq!(left.counts().id_requests, 1);
    assert_eq!(right.counts().id_requests, 1);
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );

    let demand_id = storage
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|d| d.known_event_id == Some(event_id))
        .unwrap()
        .ticket
        .id;
    let cursor_before = storage
        .load_account_projection_state(&alice.label, 0)
        .unwrap()
        .last_transport_timestamp;
    assert!(
        cursor_before.is_none_or(|cursor| cursor < created_at),
        "the sampled cursor must be below the missing event"
    );
    let scopes_before = storage.recovery_scope_snapshots(demand_id).unwrap();
    assert!(!scopes_before.is_empty());
    assert!(
        scopes_before
            .iter()
            .all(|scope| !scope.retained_known_event)
    );
    let before_release = storage.recovery_revision_fence().unwrap();
    storage.release_message_for_replay(&released).unwrap();
    assert!(
        storage
            .recovery_revision_fence()
            .unwrap()
            .inventory_revision
            > before_release.inventory_revision
    );
    let mut first_finished = Box::pin(shared.bounded_recovery_finished.notified());
    first_finished.as_mut().enable();
    shared
        .bounded_pause_before_admission
        .store(false, Ordering::SeqCst);
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::ZERO)
        .await;
    timeout(Duration::from_secs(10), first_finished.as_mut())
        .await
        .expect("stale returned result finishes without admission");
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|d| d.ticket.id == demand_id)
    );
    assert_eq!(
        storage
            .load_account_projection_state(&alice.label, 0)
            .unwrap()
            .last_transport_timestamp,
        cursor_before
    );
    let scopes_after = storage.recovery_scope_snapshots(demand_id).unwrap();
    assert_eq!(scopes_after.len(), scopes_before.len());
    for (before, after) in scopes_before.iter().zip(&scopes_after) {
        assert!(after.token == before.token);
        assert_eq!(after.attempt_serial, before.attempt_serial);
        assert_eq!(after.obligation_revision, before.obligation_revision);
        assert_eq!(after.loss_revision, before.loss_revision);
        assert_eq!(after.route_revision, before.route_revision);
        assert_eq!(after.inventory_revision, before.inventory_revision);
        assert_eq!(after.retained_known_event, before.retained_known_event);
        assert!(
            after
                .checkpoints
                .iter()
                .all(|checkpoint| !checkpoint.exhaustive && !checkpoint.admission_complete)
        );
    }
    runtime.shutdown_and_close().await.unwrap();
    bootstrap.shutdown();
}
