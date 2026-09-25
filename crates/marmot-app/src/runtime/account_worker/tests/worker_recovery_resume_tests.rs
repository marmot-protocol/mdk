//! The owned comparison result stays outside account admission until the
//! serialized worker explicitly submits it. The off-worker scheduler is a
//! separate follow-up; this exercises its current inline consumer boundary.

use super::*;
use cgka_traits::{TransportEndpoint, TransportGroupSubscription};
use nostr_relay_builder::MockRelay;
use std::sync::Mutex;
use transport_nostr_adapter::NostrReconciliationProgress;

#[derive(Default)]
struct ComparisonCursor(Mutex<Option<[u8; 32]>>);

impl NostrReconciliationProgress for ComparisonCursor {
    fn load_cursor(&self) -> Result<Option<[u8; 32]>, cgka_traits::TransportAdapterError> {
        Ok(*self.0.lock().unwrap())
    }

    fn save_cursor(
        &self,
        cursor: Option<[u8; 32]>,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        *self.0.lock().unwrap() = cursor;
        Ok(())
    }
}

#[tokio::test]
async fn comparison_result_waits_for_worker_submission_before_durable_admission() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    let runtime = super::super::super::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&bob.label).await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "owned comparison result",
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
    .expect("peer joins before the missing message is published");
    runtime
        .accounts()
        .workers
        .lock()
        .await
        .remove(&alice.account_id_hex)
        .unwrap()
        .shutdown()
        .await;
    runtime
        .send_message(&bob.label, &group, b"comparison-owned body".to_vec())
        .await
        .unwrap();

    let mut client = app.client(&alice.label).await.unwrap();
    // Register ordinary route state and wait for its startup replay to finish
    // before dropping the queued delivery. Reconciliation must reacquire its
    // bytes despite the first SDK sighting.
    client.prepare_transport().await.unwrap();
    timeout(Duration::from_secs(10), async {
        while !client.adapter.account_subscription_eose().await.complete() {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("startup replay reaches EOSE before checking comparison ownership");
    while matches!(
        timeout(Duration::from_millis(100), client.receive_next_delivery()).await,
        Ok(Ok(_))
    ) {}
    let record = app
        .group(&alice.label, &hex::encode(&group))
        .unwrap()
        .unwrap();
    let route: [u8; 32] = hex::decode(record.nostr_routing.nostr_group_id_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let storage = app.account_storage(&alice.label).unwrap();
    let inventory = storage
        .transport_reconciliation_inventory(
            &storage_sqlite::TransportReconciliationRoute::Group(route),
            crate::unix_now_seconds(),
        )
        .unwrap();
    let local_items = inventory
        .items
        .iter()
        .map(|item| transport_nostr_adapter::NostrReconciliationItem {
            event_id: item.event_id,
            created_at: item.created_at,
        })
        .collect::<Vec<_>>();
    let subscription = TransportGroupSubscription {
        group_id: group.clone(),
        transport_group_id: route.to_vec(),
        endpoints: vec![TransportEndpoint(url)],
    };
    let (summary, mut events) = client
        .adapter
        .reconcile_group_history(
            subscription.clone(),
            &local_items,
            inventory.since,
            crate::unix_now_seconds(),
            &ComparisonCursor::default(),
        )
        .await
        .unwrap()
        .expect("SDK reconciliation backend is configured");
    assert_eq!(summary.relays_succeeded, 1);
    assert_eq!(summary.relays_failed, 0);
    assert!(
        !events.is_empty(),
        "the missing encrypted event is returned"
    );
    let event = events.remove(0);
    let event_id: [u8; 32] = hex::decode(&event.event.id).unwrap().try_into().unwrap();
    let route = storage_sqlite::TransportReconciliationRoute::Group(route);
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, crate::unix_now_seconds())
            .unwrap()
    );
    assert!(
        timeout(Duration::from_millis(100), client.receive_next_delivery())
            .await
            .is_err(),
        "an owned comparison result must not enter the ordinary delivery queue"
    );
    let (_, repeated) = client
        .adapter
        .reconcile_group_history(
            subscription.clone(),
            &local_items,
            inventory.since,
            crate::unix_now_seconds(),
            &ComparisonCursor::default(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        repeated
            .iter()
            .any(|candidate| candidate.event.id == hex::encode(event_id)),
        "a comparison result not admitted by the worker remains eligible"
    );
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, crate::unix_now_seconds())
            .unwrap()
    );

    assert_eq!(
        client.adapter.queue_reconciled_event(event).await.unwrap(),
        1
    );
    let delivery = timeout(Duration::from_secs(2), client.receive_next_delivery())
        .await
        .expect("explicit submission reaches the account")
        .unwrap();
    let crate::relay_plane::AccountDeliveryReceive::Delivery(delivery) = delivery else {
        panic!("expected the submitted event, not an overflow signal");
    };
    client.ingest_received_delivery(*delivery).await.unwrap();
    assert!(
        storage
            .retained_recovery_event(&route, &event_id, None, crate::unix_now_seconds())
            .unwrap()
    );
    assert!(
        timeout(Duration::from_millis(100), client.receive_next_delivery())
            .await
            .is_err(),
        "one worker submission must not queue duplicate copies"
    );
    drop(client);
    runtime.shutdown_and_close().await.unwrap();
}
