//! The owned comparison result stays outside account admission until the
//! serialized worker admits it through ordinary ingest, never through the
//! live delivery queue.

use super::*;
use async_trait::async_trait;
use cgka_traits::TransportEndpoint;
use nostr::prelude::EventId;
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::{Event, RelayUrl};
use tokio_util::sync::CancellationToken;
use transport_nostr_adapter::compare::{
    CompareEnd, ComparePolicy, CompareRequest, CompareSink, LocalItem, run_comparison,
};
use transport_nostr_adapter::sweep::{
    RelayCaps, SdkSweepRelay, SweepRange, SweepRoute, SweepSinkError,
};
use transport_nostr_adapter::{NostrRelayEvent, NostrSdkRelayClient};
use transport_nostr_peeler::NostrTransportEvent;

const COMPARISON_CALLER_ALLOWANCE: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Default)]
struct CollectedEvents(Vec<Event>);

#[async_trait]
impl CompareSink for CollectedEvents {
    async fn admit(
        &mut self,
        _window: SweepRange,
        _certified: bool,
        events: Vec<Event>,
        _fetched_bytes: u64,
    ) -> Result<(), SweepSinkError> {
        self.0.extend(events);
        Ok(())
    }
}

async fn run_group_comparison(
    sdk: &NostrSdkRelayClient,
    url: &str,
    route: [u8; 32],
    local: &[LocalItem],
    since: u64,
    until: u64,
) -> Vec<NostrRelayEvent> {
    let relay_url = RelayUrl::parse(url).unwrap();
    let relay = SdkSweepRelay::new(
        sdk,
        relay_url,
        RelayCaps {
            max_limit: Some(500),
            negentropy: true,
        },
        COMPARISON_CALLER_ALLOWANCE,
    );
    let mut sink = CollectedEvents::default();
    let report = run_comparison(
        CompareRequest {
            route: SweepRoute::Group {
                nostr_group_id: route,
            },
            range: SweepRange { since, until },
            local,
            deadline: Some(tokio::time::Instant::now() + COMPARISON_CALLER_ALLOWANCE),
            policy: ComparePolicy::new(256, 1024 * 1024),
        },
        &relay,
        &mut sink,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, CompareEnd::Finished);
    sink.0
        .into_iter()
        .map(|event| NostrRelayEvent {
            endpoint: TransportEndpoint(url.to_owned()),
            subscription_id: None,
            event: NostrTransportEvent::from_nostr_event(&event).unwrap(),
        })
        .collect()
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
        .unwrap()
        .operation
        .expect("eligible fixture members");
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
    // retains this ciphertext until the owner consumes it. Comparison must
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
    let mut local_items = inventory
        .items
        .iter()
        .map(|item| LocalItem {
            created_at: item.created_at,
            id: EventId::from_byte_array(item.event_id),
        })
        .collect::<Vec<_>>();
    local_items.sort();
    let alice_id = cgka_traits::MemberId::new(hex::decode(&alice.account_id_hex).unwrap());
    let sdk = app
        .relay_plane
        .account_history_relay_client(&alice_id)
        .await
        .expect("SDK account history client is configured");
    assert!(
        app.messages(&alice.label)
            .unwrap()
            .iter()
            .all(|message| message.plaintext != body),
        "wire acquisition must not admit the missing plaintext"
    );
    let events = run_group_comparison(
        &sdk,
        &url,
        route,
        &local_items,
        inventory.since,
        crate::unix_now_seconds(),
    )
    .await;
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
    let repeated = run_group_comparison(
        &sdk,
        &url,
        route,
        &local_items,
        inventory.since,
        crate::unix_now_seconds(),
    )
    .await
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
