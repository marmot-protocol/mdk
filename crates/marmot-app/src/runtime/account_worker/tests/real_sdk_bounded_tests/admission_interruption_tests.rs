//! Prior durable progress and interrupted acquisition through the real SDK and account worker.

use super::*;

#[derive(Clone, Debug, Default)]
struct CapturedGroupWrites(Arc<Mutex<Vec<Value>>>);

impl nostr_relay_builder::prelude::WritePolicy for CapturedGroupWrites {
    fn admit_event<'a>(
        &'a self,
        event: &'a nostr_relay_builder::prelude::Event,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let value = serde_json::to_value(event).unwrap();
            if value["kind"] == 445 {
                self.0.lock().unwrap().push(value);
            }
            PolicyResult::Accept
        })
    }
}

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
async fn route_revision_after_result_before_admission_keeps_known_demand() {
    use transport_nostr_adapter::NostrAcquisitionEnd;

    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let fixture = super::super::bounded_known_fixture().await;
    let storage = fixture.app.account_storage("bob").unwrap();
    let before = storage.recovery_revision_fence().unwrap();
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
        .expect("the worker owns the exact result before the route changes");
    assert_eq!(storage.recovery_revision_fence().unwrap(), before);
    storage.observe_recovery_route_snapshot([0xA5; 32]).unwrap();
    assert!(storage.recovery_revision_fence().unwrap().route_revision > before.route_revision);
    let mut finished = Box::pin(shared.bounded_recovery_finished.notified());
    finished.as_mut().enable();
    shared
        .bounded_pause_before_admission
        .store(false, Ordering::SeqCst);
    timeout(Duration::from_secs(5), finished.as_mut())
        .await
        .expect("stale route result reaches the worker's completion boundary");
    assert!(
        !storage
            .retained_recovery_event(
                &fixture.route,
                &fixture.event_id,
                None,
                fixture.historical.created_at,
            )
            .unwrap(),
        "old route evidence cannot admit its returned ciphertext"
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
    assert!(
        storage.recovery_retry_state().unwrap().attempt_serial >= newer.attempt_serial,
        "the owner may reserve another attempt after the stale result finishes"
    );
    fixture.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn real_sdk_prior_valid_admission_survives_cancel_and_unretained_reopen() {
    use base64::Engine as _;
    use nostr_sdk::prelude::{
        Client as NostrSdkClient, EventBuilder, FinalizeEvent, Keys, Kind, Tag,
    };
    use transport_nostr_adapter::{NostrRelayClient, NostrSdkRelayClient};

    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = HeldExactQuery::default();
    let writes = CapturedGroupWrites::default();
    let relay = LocalRelay::new(
        RelayBuilder::default()
            .query_policy(gate.clone())
            .write_policy(writes.clone()),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let config = crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    let runtime = super::super::super::super::MarmotAppRuntime::new(app.clone());
    runtime
        .shared_services()
        .bounded_group_recovery_enabled
        .store(true, Ordering::SeqCst);
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&bob.label).await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "prior durable admission",
            std::slice::from_ref(&bob.account_id_hex),
            AppCreateGroupOptions {
                relays: Some(vec![url.clone()]),
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
    .expect("Bob joins before the historical encrypted send");
    assert!(
        runtime
            .sign_out(
                &alice.label,
                super::super::super::super::SignOutOptions {
                    delete_key_packages: false,
                },
            )
            .await
            .unwrap()
            .local_cleanup
            .completed
    );
    runtime
        .send_message(&bob.label, &group, b"valid retained prefix".to_vec())
        .await
        .unwrap();
    let first = writes
        .0
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("relay accepted Bob's valid MLS ciphertext");
    let first_id: [u8; 32] = hex::decode(first["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let first_time = first["created_at"].as_u64().unwrap();
    let route_hex = app
        .group(&alice.label, &hex::encode(&group))
        .unwrap()
        .unwrap()
        .nostr_routing
        .nostr_group_id_hex;
    let route = storage_sqlite::TransportReconciliationRoute::Group(
        hex::decode(&route_hex).unwrap().try_into().unwrap(),
    );
    let storage = app.account_storage(&alice.label).unwrap();
    assert!(
        !storage
            .retained_recovery_event(&route, &first_id, None, first_time)
            .unwrap()
    );
    storage
        .request_recovery(
            storage_sqlite::RecoveryRequest::KnownEvent {
                group_id: group.as_slice(),
                event_id: &first_id,
            },
            crate::client::recovery::wall_now_ms().unwrap(),
        )
        .unwrap();
    runtime.sign_in_account(&alice.label).await.unwrap();
    timeout(Duration::from_secs(45), runtime.catch_up_accounts())
        .await
        .expect("first account catch-up returns")
        .unwrap();
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    timeout(Duration::from_secs(15), async {
        loop {
            if storage
                .retained_recovery_event(&route, &first_id, None, first_time)
                .unwrap()
                && storage
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .all(|d| d.known_event_id != Some(first_id))
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("account recovery durably accounts for the valid historical prefix");
    let shared = runtime.shared_services();
    while futures::FutureExt::now_or_never(shared.bounded_result_ready.notified()).is_some() {}

    // The next eligible ID has transport-shaped bytes but is not published
    // until after reopening. This isolates cancellation from ordinary live
    // delivery; it does not prove same-attempt partial admission or SDK cache.
    let mut envelope = vec![0u8; 12];
    envelope.extend_from_slice(b"held-unretained-suffix");
    let signed = EventBuilder::new(
        Kind::MlsGroupMessage,
        base64::engine::general_purpose::STANDARD.encode(envelope),
    )
    .tags([Tag::custom("h", [route_hex])])
    .finalize(&Keys::generate())
    .unwrap();
    let second_id = signed.id.to_bytes();
    let second_time = signed.created_at.as_secs();
    *gate.event_id_hex.lock().unwrap() = signed.id.to_hex();
    gate.hold_exact.store(true, Ordering::SeqCst);
    gate.reject_broad.store(true, Ordering::SeqCst);
    let mut result_ready = Box::pin(shared.bounded_result_ready.notified());
    result_ready.as_mut().enable();
    let second_demand = storage
        .request_recovery(
            storage_sqlite::RecoveryRequest::KnownEvent {
                group_id: group.as_slice(),
                event_id: &second_id,
            },
            crate::client::recovery::wall_now_ms().unwrap(),
        )
        .unwrap();
    let (_, remaining, _) = runtime.recovery_retry_snapshot_for_test(&alice.label).await;
    runtime
        .advance_recovery_clock_for_test(&alice.label, remaining + Duration::from_secs(1))
        .await;
    timeout(Duration::from_secs(10), gate.entered.notified())
        .await
        .expect("second exact SDK REQ enters the held relay query");
    let entered_at = gate.entered_at.lock().unwrap().unwrap();
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|d| d.ticket.id == second_demand.id)
    );
    assert!(
        storage
            .retained_recovery_event(&route, &first_id, None, first_time)
            .unwrap()
    );
    assert!(
        !storage
            .retained_recovery_event(&route, &second_id, None, second_time)
            .unwrap()
    );
    assert!(futures::FutureExt::now_or_never(result_ready.as_mut()).is_none());
    let attempt = storage.recovery_retry_state().unwrap().attempt_serial;
    timeout(
        Duration::from_secs(4)
            .checked_sub(entered_at.elapsed())
            .expect("shutdown starts before the request deadline"),
        runtime.shutdown_and_close(),
    )
    .await
    .expect("shutdown cancels the live acquisition before its five-second deadline")
    .unwrap();
    assert!(futures::FutureExt::now_or_never(result_ready.as_mut()).is_none());
    gate.release.notify_waiters();
    drop(storage);
    drop(runtime);
    drop(app);

    let reopened_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config);
    let reopened_runtime = super::super::super::super::MarmotAppRuntime::new(reopened_app.clone());
    reopened_runtime
        .shared_services()
        .bounded_group_recovery_enabled
        .store(true, Ordering::SeqCst);
    timeout(
        Duration::from_secs(20),
        reopened_runtime.reconcile_accounts(),
    )
    .await
    .expect("actual SQLCipher account store reopens")
    .unwrap();
    let reopened = reopened_app.account_storage(&alice.label).unwrap();
    assert_eq!(
        reopened.recovery_retry_state().unwrap().attempt_serial,
        attempt
    );
    assert!(
        reopened
            .retained_recovery_event(&route, &first_id, None, first_time)
            .unwrap()
    );
    assert!(
        !reopened
            .retained_recovery_event(&route, &second_id, None, second_time)
            .unwrap()
    );
    assert!(
        reopened
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|d| d.ticket.id == second_demand.id)
    );
    let comparison_before = reopened.recovery_comparison().unwrap();
    reopened_runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    timeout(Duration::from_secs(20), async {
        loop {
            if reopened.recovery_comparison().unwrap().settled_revision
                > comparison_before.settled_revision
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("conforming startup comparison settles before the exact retry");
    let transport_event =
        transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&signed).unwrap();
    let publisher = NostrSdkRelayClient::new(NostrSdkClient::builder().build());
    publisher
        .publish_event(&[cgka_traits::TransportEndpoint(url)], &transport_event, 1)
        .await
        .unwrap();
    gate.hold_exact.store(false, Ordering::SeqCst);
    let requests_before_retry = gate.exact_queries.load(Ordering::SeqCst);
    reopened_runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    timeout(Duration::from_secs(12), async {
        loop {
            if gate.exact_queries.load(Ordering::SeqCst) > requests_before_retry
                && reopened
                    .retained_recovery_event(&route, &second_id, None, second_time)
                    .unwrap()
                && reopened
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .all(|d| d.ticket.id != second_demand.id)
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("fresh exact request reacquires and retains the suffix after reopen");
    reopened_runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
}
