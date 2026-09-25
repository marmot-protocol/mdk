//! Same-live-SDK ordinary sighting followed by owned exact-ID admission.

use super::*;
use cgka_traits::storage::MessageStorage;
use cgka_traits::{EpochId, MessageId, MessageState};

#[tokio::test]
async fn ordinary_sdk_seen_but_unretained_event_is_admitted_by_bounded_worker() {
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
    runtime.publish_key_package(&bob.label).await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "ordinary seen redelivery",
            std::slice::from_ref(&bob.account_id_hex),
            AppCreateGroupOptions {
                relays: Some(vec![left_url.clone(), right_url.clone()]),
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
    .expect("Bob joins before the target message");

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
    let route_hex = hex::encode(route);
    timeout(Duration::from_secs(10), async {
        loop {
            if left
                .live
                .lock()
                .unwrap()
                .iter()
                .any(|live| live.route == route_hex)
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("an ordinary group REQ is live");
    let storage = app.account_storage(&alice.label).unwrap();
    let stored_ids = || {
        storage
            .list_messages(&group, EpochId(0))
            .unwrap()
            .into_iter()
            .map(|message| hex::encode(message.id.as_slice()))
            .collect::<HashSet<_>>()
    };
    let before_target = stored_ids();

    // Send from a separate Bob client so the runtime plane cannot deliver a
    // local-publish echo to Alice. The controlled relays store the real MLS
    // ciphertext without replaying backlog on their ordinary subscriptions.
    runtime
        .accounts()
        .workers
        .lock()
        .await
        .remove(&bob.account_id_hex)
        .unwrap()
        .shutdown()
        .await;
    let mut bob_client = app.client(&bob.label).await.unwrap();
    bob_client
        .send(&group, b"ordinary seen then bounded redelivery")
        .await
        .unwrap();
    drop(bob_client);
    let historical = left.group_event();
    assert_eq!(right.group_event()["id"], historical["id"]);
    let event_id: [u8; 32] = hex::decode(historical["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let created_at = historical["created_at"].as_u64().unwrap();
    let recovery_route = storage_sqlite::TransportReconciliationRoute::Group(route);
    let message_id = MessageId::new(event_id);
    assert!(storage.get_message(&message_id).is_err());
    assert_eq!(stored_ids(), before_target);
    assert!(
        !storage
            .retained_recovery_event(&recovery_route, &event_id, None, created_at)
            .unwrap()
    );
    assert!(
        app.messages(&alice.label)
            .unwrap()
            .iter()
            .all(|m| m.plaintext != "ordinary seen then bounded redelivery")
    );

    *shared.ordinary_drop_once.lock().unwrap() = Some(crate::runtime::OrdinaryDeliveryDropTarget {
        account_label: alice.label.clone(),
        event_id,
    });
    let live = left
        .live
        .lock()
        .unwrap()
        .iter()
        .filter(|live| live.route == route_hex)
        .cloned()
        .collect::<Vec<_>>();
    for interest in &live {
        interest
            .sender
            .send(json!(["EVENT", interest.id, historical]))
            .unwrap();
        if timeout(
            Duration::from_secs(3),
            shared.ordinary_delivery_dropped.notified(),
        )
        .await
        .is_ok()
        {
            break;
        }
    }
    let ordinary = shared
        .ordinary_drop_witness
        .lock()
        .unwrap()
        .clone()
        .expect("one ordinary SDK EVENT reaches Alice's worker");
    assert_eq!(ordinary.account_label, alice.label);
    assert_eq!(ordinary.event_id, event_id);
    assert!(
        live.iter()
            .any(|interest| interest.id == ordinary.subscription_id)
    );
    assert!(
        !storage
            .retained_recovery_event(&recovery_route, &event_id, None, created_at)
            .unwrap()
    );
    assert!(storage.get_message(&message_id).is_err());
    assert_eq!(stored_ids(), before_target);
    assert!(
        storage
            .transport_reconciliation_inventory(&recovery_route, crate::unix_now_seconds())
            .unwrap()
            .items
            .iter()
            .all(|item| item.event_id != event_id)
    );
    assert!(
        app.messages(&alice.label)
            .unwrap()
            .iter()
            .all(|m| m.plaintext != "ordinary seen then bounded redelivery")
    );

    // The same Alice worker and SDK client remain live. The SDK's ordinary
    // first-sighting ID cache now knows the event, but its default database
    // retains no bytes; only the bounded exact-ID result can supply them.
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
        .expect("bounded SDK result arrives");
    let bounded = shared
        .bounded_result_witness
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(bounded.account_label, alice.label);
    assert_eq!(bounded.event_id, event_id);
    assert_eq!(
        bounded.attempt_serial,
        storage.recovery_retry_state().unwrap().attempt_serial
    );
    assert_eq!(bounded.matching_items, 2);
    assert_eq!(left.counts().id_requests, 1);
    assert_eq!(right.counts().id_requests, 1);
    assert!(
        !storage
            .retained_recovery_event(&recovery_route, &event_id, None, created_at)
            .unwrap()
    );
    assert!(storage.get_message(&message_id).is_err());
    assert_eq!(stored_ids(), before_target);
    assert!(
        storage
            .transport_reconciliation_inventory(&recovery_route, crate::unix_now_seconds())
            .unwrap()
            .items
            .iter()
            .all(|item| item.event_id != event_id)
    );
    assert!(
        app.messages(&alice.label)
            .unwrap()
            .iter()
            .all(|m| m.plaintext != "ordinary seen then bounded redelivery")
    );

    let mut admitted = Box::pin(shared.bounded_prefix_admitted.notified());
    admitted.as_mut().enable();
    let mut finished = Box::pin(shared.bounded_recovery_finished.notified());
    finished.as_mut().enable();
    shared
        .bounded_pause_before_admission
        .store(false, Ordering::SeqCst);
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::ZERO)
        .await;
    timeout(Duration::from_secs(10), admitted.as_mut())
        .await
        .expect("bounded worker admits a real SDK item");
    timeout(Duration::from_secs(10), finished.as_mut())
        .await
        .expect("bounded attempt finishes");
    assert!(
        storage
            .retained_recovery_event(&recovery_route, &event_id, None, created_at)
            .unwrap()
    );
    // Successful peel stores a canonical MLS content row, while the outer
    // Nostr wrapper is recorded separately in route inventory.
    let new_rows = storage
        .list_messages(&group, EpochId(0))
        .unwrap()
        .into_iter()
        .filter(|row| !before_target.contains(&hex::encode(row.id.as_slice())))
        .collect::<Vec<_>>();
    assert_eq!(new_rows.len(), 1);
    assert_eq!(new_rows[0].state, MessageState::Processed);
    assert!(
        storage
            .transport_reconciliation_inventory(&recovery_route, crate::unix_now_seconds())
            .unwrap()
            .items
            .iter()
            .any(|item| item.event_id == event_id)
    );
    let messages = app.messages(&alice.label).unwrap();
    let projected = messages
        .iter()
        .filter(|m| m.plaintext == "ordinary seen then bounded redelivery")
        .collect::<Vec<_>>();
    assert_eq!(projected.len(), 1);
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .all(|d| d.known_event_id != Some(event_id))
    );
    assert_eq!(left.counts().id_requests, 1);
    assert_eq!(right.counts().id_requests, 1);

    runtime.shutdown_and_close().await.unwrap();
    bootstrap.shutdown();
}
