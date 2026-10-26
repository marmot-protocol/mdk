//! The owned comparison result stays outside account admission until the
//! serialized worker admits it through ordinary ingest, never through the
//! live delivery queue.

use super::*;
use cgka_traits::{TransportEndpoint, TransportGroupSubscription};
use nostr_relay_builder::MockRelay;
use std::sync::Mutex;
use transport_nostr_adapter::NostrReconciliationProgress;

const RECONCILIATION_CALLER_ALLOWANCE: std::time::Duration = std::time::Duration::from_secs(60);

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
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
    let body = "comparison-owned body";
    runtime
        .send_message(&bob.label, &group, body.as_bytes().to_vec())
        .await
        .unwrap();

    let mut client = app.client(&alice.label).await.unwrap();
    // Wait for wire acquisition, not MDK admission: native input deliberately
    // retains this ciphertext until the owner consumes it. Reconciliation must
    // still return bytes the SDK has seen but the account has not admitted.
    client.prepare_transport().await.unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            let observation = client.adapter.replay_admission().await;
            let acquired = observation.active()
                && observation.sources().next().is_some()
                && observation.sources().all(|source| source.admitted());
            drop(observation);
            if acquired {
                break;
            }
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
        .app_storage()
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
        retained_since: None,
    };
    assert!(
        app.messages(&alice.label)
            .unwrap()
            .iter()
            .all(|message| message.plaintext != body),
        "wire acquisition must not admit the missing plaintext"
    );
    let (summary, events) = client
        .adapter
        .reconcile_group_history(
            subscription.clone(),
            &local_items,
            inventory.since,
            crate::unix_now_seconds(),
            &ComparisonCursor::default(),
            tokio::time::Instant::now() + RECONCILIATION_CALLER_ALLOWANCE,
        )
        .await
        .unwrap()
        .expect("SDK reconciliation backend is configured");
    assert_eq!(summary.relays_succeeded, 1);
    assert_eq!(summary.relays_failed, 0);
    let returned = events
        .iter()
        .map(|event| event.event.id.clone())
        .collect::<std::collections::HashSet<_>>();
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
            tokio::time::Instant::now() + RECONCILIATION_CALLER_ALLOWANCE,
        )
        .await
        .unwrap()
        .unwrap();
    let repeated = repeated
        .into_iter()
        .map(|event| event.event.id)
        .collect::<std::collections::HashSet<_>>();
    assert!(
        returned.is_subset(&repeated),
        "a comparison result not admitted by the worker remains eligible"
    );
    assert!(
        app.messages(&alice.label)
            .unwrap()
            .iter()
            .all(|message| message.plaintext != body),
        "acquiring the same owned result twice must not admit its plaintext"
    );

    for event in events {
        for delivery in client.adapter.recovered_deliveries(event).await.unwrap() {
            client
                .admit_recovered_delivery(&delivery, crate::client::InventoryWrite::Immediate)
                .await
                .unwrap();
        }
    }
    assert!(
        app.messages(&alice.label)
            .unwrap()
            .iter()
            .any(|message| { message.plaintext == body && message.sender == bob.account_id_hex }),
        "only owner admission persists the genuine peer plaintext"
    );
    assert!(
        timeout(Duration::from_millis(100), client.receive_next_delivery())
            .await
            .is_err(),
        "worker admission never queues the event for live delivery"
    );
    drop(client);
    runtime.shutdown_and_close().await.unwrap();
}
