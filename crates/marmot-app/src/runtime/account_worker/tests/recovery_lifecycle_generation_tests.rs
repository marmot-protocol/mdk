//! A real SDK result may be durably admitted after owner attempt/scope replacement,
//! but only the current attempt may checkpoint or discharge its obligation.

use super::*;

#[tokio::test]
async fn real_sdk_result_after_attempt_replacement_retains_bytes_without_old_completion() {
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
            "attempt replacement",
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
    .expect("Bob joins before the historical event");

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
        .send_message(&bob.label, &group, b"attempt generation".to_vec())
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
    runtime.sign_in_account(&alice.label).await.unwrap();
    timeout(Duration::from_secs(45), runtime.catch_up_accounts())
        .await
        .expect("startup catch-up ends before the exact demand")
        .unwrap();
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap(),
        "ordinary history did not durably admit the target"
    );

    shared
        .bounded_pause_before_admission
        .store(true, Ordering::SeqCst);
    let mut result_ready = Box::pin(shared.bounded_result_ready.notified());
    result_ready.as_mut().enable();
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
    timeout(Duration::from_secs(10), result_ready.as_mut())
        .await
        .expect("the real SDK returned an exact-ID result before admission");
    let witness = shared
        .bounded_result_witness
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    let old_attempt = storage.recovery_retry_state().unwrap().attempt_serial;
    assert_eq!(witness.account_label, alice.label);
    assert_eq!(witness.attempt_serial, old_attempt);
    assert_eq!(witness.event_id, event_id);
    assert_eq!(
        witness.matching_items, 2,
        "both exact relays returned the ID"
    );
    assert_eq!(left.counts().id_requests, 1);
    assert_eq!(right.counts().id_requests, 1);
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap(),
        "the result witness precedes durable admission"
    );

    let demand_id = storage
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|demand| demand.known_event_id == Some(event_id))
        .unwrap()
        .ticket
        .id;
    let old_scope = storage
        .recovery_scope_snapshots(demand_id)
        .unwrap()
        .remove(0);
    assert_eq!(old_scope.attempt_serial, old_attempt);
    assert!(old_scope.checkpoints.is_empty());
    let expected_endpoints = old_scope.plan.required_endpoints.clone();
    assert_eq!(expected_endpoints.len(), 2);
    let cursor_before = storage
        .load_account_projection_state(&alice.label, 0)
        .unwrap()
        .last_transport_timestamp;
    assert!(cursor_before.is_none_or(|cursor| cursor < created_at));
    let fence = storage.recovery_revision_fence().unwrap();
    let newer = storage
        .reserve_recovery_attempt(
            &fence,
            crate::client::recovery::wall_now_ms().unwrap(),
            // The fixture advanced this worker's logical clock by 600 s.
            // Keep the injected replacement ineligible until after we inspect
            // the old job's completion, even on a slow debug-build runner.
            3_600_000,
            true,
        )
        .unwrap()
        .expect("a newer owner attempt is reserved under the same obligation");
    assert!(newer.attempt_serial > old_attempt);
    assert_eq!(storage.recovery_revision_fence().unwrap(), fence);
    let new_token = storage
        .install_recovery_scope_plan(&fence, newer.attempt_serial, demand_id, &[old_scope.plan])
        .unwrap()
        .expect("the newer attempt replaces the frozen scope")
        .remove(0);
    assert!(new_token.revision > old_scope.token.revision);
    let retry = storage.recovery_retry_state().unwrap();
    assert_eq!(retry.attempt_serial, newer.attempt_serial);
    assert!(
        retry
            .not_before_ms
            .saturating_sub(crate::client::recovery::wall_now_ms().unwrap())
            > 3_000_000,
        "the replacement stays beyond the worker's 600-second clock advance"
    );

    // Two endpoint copies leave one item pending after the first successful
    // bounded ingest. This hook gates that exact Job after its admitted count
    // advances, so later retention cannot be attributed to legacy/live ingress.
    shared
        .bounded_pause_after_first_admission
        .store(true, Ordering::SeqCst);
    let mut first_admitted = Box::pin(shared.bounded_prefix_admitted.notified());
    first_admitted.as_mut().enable();
    let mut finished = Box::pin(shared.bounded_recovery_finished.notified());
    finished.as_mut().enable();
    let mut errors = runtime.subscribe();
    shared
        .bounded_pause_before_admission
        .store(false, Ordering::SeqCst);
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::ZERO)
        .await;
    timeout(Duration::from_secs(10), first_admitted.as_mut())
        .await
        .expect("the exact resumed bounded job durably admits its first item");
    assert!(
        storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap(),
        "the first bounded admission retained the returned ID"
    );
    let after_first = storage.recovery_scope_snapshots(demand_id).unwrap();
    assert_eq!(after_first.len(), 1);
    assert!(after_first[0].token == new_token);
    assert_eq!(after_first[0].attempt_serial, newer.attempt_serial);
    assert_eq!(after_first[0].plan.required_endpoints, expected_endpoints);
    assert!(after_first[0].checkpoints.is_empty());
    assert!(
        futures::FutureExt::now_or_never(finished.as_mut()).is_none(),
        "the same bounded job still owns the second endpoint copy"
    );

    shared
        .bounded_pause_after_first_admission
        .store(false, Ordering::SeqCst);
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::ZERO)
        .await;
    timeout(Duration::from_secs(10), finished.as_mut())
        .await
        .expect("the old result reaches admission and conditional completion");
    assert!(
        storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap(),
        "valid returned bytes remain durably admitted"
    );
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|demand| demand.ticket.id == demand_id),
        "old completion cannot clear the new owner's demand"
    );
    let current_scopes = storage.recovery_scope_snapshots(demand_id).unwrap();
    assert_eq!(current_scopes.len(), 1);
    assert!(current_scopes[0].token == new_token);
    assert_eq!(current_scopes[0].attempt_serial, newer.attempt_serial);
    assert_eq!(
        current_scopes[0].plan.required_endpoints,
        expected_endpoints
    );
    assert!(current_scopes[0].checkpoints.is_empty());
    loop {
        match errors.try_recv() {
            Ok(MarmotAppEvent::AccountError(error))
                if error.account_label == alice.label
                    && (error
                        .message
                        .starts_with("bounded recovery admission failed")
                        || error
                            .message
                            .starts_with("bounded recovery checkpoint failed")) =>
            {
                panic!("old bounded job failed instead of reaching conditional completion")
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(error) => panic!("bounded completion error observation unavailable: {error:?}"),
        }
    }
    let cursor_after = storage
        .load_account_projection_state(&alice.label, 0)
        .unwrap()
        .last_transport_timestamp;
    assert!(
        cursor_after.is_none_or(|cursor| cursor <= created_at),
        "no persisted cursor may skip beyond the sole historical target"
    );
    runtime.shutdown_and_close().await.unwrap();
    bootstrap.shutdown();
}
