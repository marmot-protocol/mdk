#![cfg(feature = "sdk")]

use cgka_traits::{GroupId, MemberId, TransportAdapterError, TransportEndpoint};
use futures::{SinkExt, StreamExt};
use nostr_memory::MemoryDatabase as SdkMemoryDatabase;
use nostr_relay_builder::prelude::{MemoryDatabase, MemoryDatabaseOptions, NostrDatabase};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{Client, EventBuilder, FinalizeEvent, Keys, Kind, Tag};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};
use transport_nostr_adapter::{
    NostrReconciliationItem, NostrReconciliationProgress, NostrSdkRelayClient, NostrSubscription,
    SubscriptionAttempt,
};

const ROUTE: [u8; 32] = [0xc3; 32];
const LARGE_EVENT_BYTES: usize = 40 * 1024;

#[derive(Default)]
struct Cursor(Mutex<Option<[u8; 32]>>);

impl NostrReconciliationProgress for Cursor {
    fn load_cursor(&self) -> Result<Option<[u8; 32]>, TransportAdapterError> {
        Ok(*self.0.lock().unwrap())
    }

    fn save_cursor(&self, cursor: Option<[u8; 32]>) -> Result<(), TransportAdapterError> {
        *self.0.lock().unwrap() = cursor;
        Ok(())
    }
}

#[derive(Default)]
struct WireCounts {
    sent_text: AtomicUsize,
    received_text: AtomicUsize,
    sent_event_json: AtomicUsize,
    sent_control_text: AtomicUsize,
    received_control_text: AtomicUsize,
    requests: AtomicUsize,
    comparisons: AtomicUsize,
    drop_requests: AtomicBool,
    suppress_events: AtomicBool,
    extra_event_copies: AtomicUsize,
}

impl WireCounts {
    fn total_text(&self) -> usize {
        self.sent_text.load(Ordering::SeqCst) + self.received_text.load(Ordering::SeqCst)
    }
}

async fn counted_proxy(backend: String) -> (String, Arc<WireCounts>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let counts = Arc::new(WireCounts::default());
    let accepted = counts.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let backend = backend.clone();
            let counts = accepted.clone();
            tokio::spawn(async move {
                let Ok(client) = accept_async(stream).await else {
                    return;
                };
                let Ok((upstream, _)) = connect_async(&backend).await else {
                    return;
                };
                let (mut client_write, mut client_read) = client.split();
                let (mut relay_write, mut relay_read) = upstream.split();
                let to_relay = async {
                    while let Some(Ok(message)) = client_read.next().await {
                        if let Message::Text(text) = &message {
                            counts.received_text.fetch_add(text.len(), Ordering::SeqCst);
                            counts
                                .received_control_text
                                .fetch_add(text.len(), Ordering::SeqCst);
                            if text.starts_with("[\"REQ\"") {
                                counts.requests.fetch_add(1, Ordering::SeqCst);
                                if counts.drop_requests.load(Ordering::SeqCst) {
                                    continue;
                                }
                            }
                            if text.starts_with("[\"NEG-OPEN\"") {
                                counts.comparisons.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        if relay_write.send(message).await.is_err() {
                            break;
                        }
                    }
                };
                let to_client = async {
                    while let Some(Ok(message)) = relay_read.next().await {
                        if let Message::Text(text) = &message {
                            counts.sent_text.fetch_add(text.len(), Ordering::SeqCst);
                            let mut event_frame = false;
                            if let Ok(frame) = serde_json::from_str::<Vec<Value>>(text)
                                && frame.first().and_then(Value::as_str) == Some("EVENT")
                                && let Some(event) = frame.get(2)
                            {
                                event_frame = true;
                                let payload_bytes = event.to_string().len();
                                counts
                                    .sent_event_json
                                    .fetch_add(payload_bytes, Ordering::SeqCst);
                                if counts.suppress_events.load(Ordering::SeqCst) {
                                    continue;
                                }
                                for _ in 0..counts.extra_event_copies.load(Ordering::SeqCst) {
                                    counts.sent_text.fetch_add(text.len(), Ordering::SeqCst);
                                    counts
                                        .sent_event_json
                                        .fetch_add(payload_bytes, Ordering::SeqCst);
                                    if client_write.send(message.clone()).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            if !event_frame {
                                counts
                                    .sent_control_text
                                    .fetch_add(text.len(), Ordering::SeqCst);
                            }
                        }
                        if client_write.send(message).await.is_err() {
                            break;
                        }
                    }
                };
                tokio::select! { _ = to_relay => {}, _ = to_client => {} }
            });
        }
    });
    (url, counts)
}

fn subscription(urls: &[String]) -> NostrSubscription {
    NostrSubscription::Group {
        account_id: MemberId::new(vec![0xa1; 32]),
        group_id: GroupId::new(vec![0xb2; 16]),
        transport_group_id: ROUTE.to_vec(),
        endpoints: urls.iter().cloned().map(TransportEndpoint).collect(),
        since: None,
        attempt: SubscriptionAttempt::INITIAL,
    }
}

#[tokio::test]
async fn large_retained_history_and_sparse_gap_use_finite_bounded_acquisition() {
    let keys = Keys::generate();
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(2_048),
    });
    let mut retained = Vec::new();
    let mut missing = Vec::new();
    for index in 0..1_108 {
        let content = if index >= 1_100 {
            format!("missing-{index}-{}", "x".repeat(LARGE_EVENT_BYTES))
        } else {
            format!("retained-{index}")
        };
        let event = EventBuilder::new(Kind::MlsGroupMessage, content)
            .tags([Tag::custom("h", [hex::encode(ROUTE)])])
            .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(
                1_700_000_000 + index as u64,
            ))
            .finalize(&keys)
            .unwrap();
        database
            .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
            .await
            .unwrap();
        let item = NostrReconciliationItem {
            event_id: event.id.to_bytes(),
            created_at: event.created_at.as_secs(),
        };
        if index >= 1_100 {
            missing.push(item)
        } else {
            retained.push(item)
        }
    }
    let left = LocalRelay::new(RelayBuilder::default().database(database.clone()));
    let right = LocalRelay::new(RelayBuilder::default().database(database));
    left.run().await.unwrap();
    right.run().await.unwrap();
    let (left_url, left_counts) = counted_proxy(left.url().await.to_string()).await;
    let (right_url, right_counts) = counted_proxy(right.url().await.to_string()).await;
    let urls = vec![left_url, right_url];
    let sdk = NostrSdkRelayClient::new(Client::builder().build());
    for url in &urls {
        sdk.client().add_relay(url.as_str()).await.unwrap();
    }
    sdk.client().connect().await;
    let cursor = Cursor::default();
    let route = subscription(&urls);
    let all_retained = retained.iter().chain(&missing).cloned().collect::<Vec<_>>();
    let (caught_up, events) = sdk
        .reconcile_subscription(route.clone(), &all_retained, 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert_eq!(caught_up.relays_succeeded, 2);
    assert_eq!(caught_up.relays_failed, 0);
    assert!(events.is_empty());
    assert_eq!(left_counts.requests.load(Ordering::SeqCst), 0);
    assert_eq!(right_counts.requests.load(Ordering::SeqCst), 0);
    assert_eq!(left_counts.sent_event_json.load(Ordering::SeqCst), 0);
    assert_eq!(right_counts.sent_event_json.load(Ordering::SeqCst), 0);
    let caught_up_bytes = left_counts.total_text() + right_counts.total_text();
    assert!(
        caught_up_bytes <= 160 * 1024,
        "zero-new-event comparison used {caught_up_bytes} text bytes"
    );
    assert_eq!(
        caught_up_bytes,
        left_counts.sent_control_text.load(Ordering::SeqCst)
            + right_counts.sent_control_text.load(Ordering::SeqCst)
            + left_counts.received_control_text.load(Ordering::SeqCst)
            + right_counts.received_control_text.load(Ordering::SeqCst),
        "zero-new-data traffic is all reconciliation/control text"
    );

    let mut admitted = retained;
    let wanted: HashSet<_> = missing.iter().map(|item| item.event_id).collect();
    let mut seen = HashSet::new();
    for _attempt in 0..4 {
        let before_left = left_counts.sent_event_json.load(Ordering::SeqCst);
        let before_right = right_counts.sent_event_json.load(Ordering::SeqCst);
        let (summary, events) = sdk
            .reconcile_subscription(route.clone(), &admitted, 0, u64::MAX, &cursor)
            .await
            .unwrap();
        assert_eq!(summary.relays_succeeded + summary.relays_failed, 2);
        assert!(
            !events.is_empty(),
            "a bounded partial pass must keep useful events"
        );
        if seen.is_empty() {
            assert_eq!(summary.relays_failed, 2, "byte exhaustion is incomplete");
            assert!(
                events.len() < missing.len(),
                "one pass may not retain the whole gap"
            );
        }
        assert!(left_counts.comparisons.load(Ordering::SeqCst) <= 5);
        assert!(right_counts.comparisons.load(Ordering::SeqCst) <= 5);
        assert!(left_counts.requests.load(Ordering::SeqCst) <= 4 * 16);
        assert!(right_counts.requests.load(Ordering::SeqCst) <= 4 * 16);
        let left_payload = left_counts.sent_event_json.load(Ordering::SeqCst) - before_left;
        let right_payload = right_counts.sent_event_json.load(Ordering::SeqCst) - before_right;
        assert!(
            left_payload <= 180 * 1024,
            "left sent {left_payload} prefilter EVENT bytes"
        );
        assert!(
            right_payload <= 180 * 1024,
            "right sent {right_payload} prefilter EVENT bytes"
        );
        for event in events {
            let id = hex::decode(event.event.id).unwrap().try_into().unwrap();
            assert!(wanted.contains(&id));
            if seen.insert(id) {
                admitted.push(
                    missing
                        .iter()
                        .find(|item| item.event_id == id)
                        .unwrap()
                        .clone(),
                );
            }
        }
        if seen.len() == wanted.len() {
            break;
        }
    }
    assert_eq!(
        seen, wanted,
        "all missing IDs resume under finite acquisition attempts"
    );
    let requests_before_settled = (
        left_counts.requests.load(Ordering::SeqCst),
        right_counts.requests.load(Ordering::SeqCst),
    );
    let (settled, events) = sdk
        .reconcile_subscription(route, &admitted, 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert_eq!(settled.relays_failed, 0);
    assert!(events.is_empty());
    assert_eq!(
        (
            left_counts.requests.load(Ordering::SeqCst),
            right_counts.requests.load(Ordering::SeqCst),
        ),
        requests_before_settled,
        "admitted history must not trigger another exact-ID REQ"
    );
    let control_bytes = [left_counts.as_ref(), right_counts.as_ref()]
        .iter()
        .map(|counts| {
            counts.sent_control_text.load(Ordering::SeqCst)
                + counts.received_control_text.load(Ordering::SeqCst)
        })
        .sum::<usize>();
    let prefilter_payload_bytes = left_counts.sent_event_json.load(Ordering::SeqCst)
        + right_counts.sent_event_json.load(Ordering::SeqCst);
    assert!(
        control_bytes <= 160 * 1024,
        "control text used {control_bytes} bytes"
    );
    eprintln!(
        "selective acquisition: caught_up_text={caught_up_bytes}, control_text={control_bytes}, prefilter_event_json={prefilter_payload_bytes}, requests=({}, {})",
        left_counts.requests.load(Ordering::SeqCst),
        right_counts.requests.load(Ordering::SeqCst),
    );
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

async fn one_missing_event_fixture() -> (
    LocalRelay,
    LocalRelay,
    NostrSdkRelayClient,
    NostrSubscription,
    Arc<WireCounts>,
    Arc<WireCounts>,
    String,
) {
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(8),
    });
    let event = EventBuilder::new(Kind::MlsGroupMessage, "missing encrypted event")
        .tags([Tag::custom("h", [hex::encode(ROUTE)])])
        .finalize(&Keys::generate())
        .unwrap();
    database
        .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
        .await
        .unwrap();
    let left = LocalRelay::new(RelayBuilder::default().database(database.clone()));
    let right = LocalRelay::new(RelayBuilder::default().database(database));
    left.run().await.unwrap();
    right.run().await.unwrap();
    let (left_url, left_counts) = counted_proxy(left.url().await.to_string()).await;
    let (right_url, right_counts) = counted_proxy(right.url().await.to_string()).await;
    let urls = vec![left_url, right_url];
    let sdk = NostrSdkRelayClient::new(Client::builder().build());
    for url in &urls {
        sdk.client().add_relay(url.as_str()).await.unwrap();
    }
    sdk.client().connect().await;
    let subscription = subscription(&urls);
    (
        left,
        right,
        sdk,
        subscription,
        left_counts,
        right_counts,
        event.id.to_hex(),
    )
}

async fn cached_fixture(
    sizes: &[usize],
    cached_sorted_indices: &[usize],
) -> (
    LocalRelay,
    LocalRelay,
    NostrSdkRelayClient,
    NostrSubscription,
    Arc<WireCounts>,
    Arc<WireCounts>,
    Vec<NostrReconciliationItem>,
) {
    let relay_database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(64),
    });
    let sdk_database = Arc::new(SdkMemoryDatabase::unbounded());
    let keys =
        Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e").unwrap();
    let mut events = sizes
        .iter()
        .enumerate()
        .map(|(index, size)| {
            EventBuilder::new(
                Kind::MlsGroupMessage,
                format!("{index}-{}", "x".repeat(*size)),
            )
            .tags([Tag::custom("h", [hex::encode(ROUTE)])])
            .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(
                1_700_001_000 + index as u64,
            ))
            .finalize(&keys)
            .unwrap()
        })
        .collect::<Vec<_>>();
    events.sort_unstable_by_key(|event| event.id);
    for (index, event) in events.iter().enumerate() {
        relay_database
            .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
            .await
            .unwrap();
        if cached_sorted_indices.contains(&index) {
            nostr_sdk::prelude::NostrDatabase::save_event(sdk_database.as_ref(), event)
                .await
                .unwrap();
        }
    }
    let items = events
        .iter()
        .map(|event| NostrReconciliationItem {
            event_id: event.id.to_bytes(),
            created_at: event.created_at.as_secs(),
        })
        .collect();
    let left = LocalRelay::new(RelayBuilder::default().database(relay_database.clone()));
    let right = LocalRelay::new(RelayBuilder::default().database(relay_database));
    left.run().await.unwrap();
    right.run().await.unwrap();
    let (left_url, left_counts) = counted_proxy(left.url().await.to_string()).await;
    let (right_url, right_counts) = counted_proxy(right.url().await.to_string()).await;
    let urls = vec![left_url, right_url];
    let sdk = NostrSdkRelayClient::new(Client::builder().database(sdk_database).build());
    for url in &urls {
        sdk.client().add_relay(url.as_str()).await.unwrap();
    }
    sdk.client().connect().await;
    let route = subscription(&urls);
    (left, right, sdk, route, left_counts, right_counts, items)
}

fn returned_json_bytes(events: &[transport_nostr_adapter::NostrRelayEvent]) -> usize {
    events
        .iter()
        .map(|event| {
            event
                .event
                .to_verified_nostr_event()
                .unwrap()
                .as_json()
                .len()
        })
        .sum()
}

#[tokio::test]
async fn warm_full_event_cache_resumes_under_combined_result_budget() {
    let (left, right, sdk, route, left_counts, right_counts, items) =
        cached_fixture(&[LARGE_EVENT_BYTES; 8], &(0..8).collect::<Vec<_>>()).await;
    let expected = items
        .iter()
        .map(|item| item.event_id)
        .collect::<HashSet<_>>();
    let mut admitted = Vec::new();
    let mut seen = HashSet::new();
    let cursor = Cursor::default();
    for _ in 0..4 {
        let (summary, events) = sdk
            .reconcile_subscription(route.clone(), &admitted, 0, u64::MAX, &cursor)
            .await
            .unwrap();
        assert!(returned_json_bytes(&events) <= 128 * 1024);
        assert!(events.len() <= 3);
        if seen.len() + events.len() < expected.len() {
            assert_eq!(summary.relays_failed, 2);
        }
        for event in events {
            let id = hex::decode(event.event.id).unwrap().try_into().unwrap();
            assert!(
                seen.insert(id),
                "cached ID should not return after admission"
            );
            admitted.push(
                items
                    .iter()
                    .find(|item| item.event_id == id)
                    .unwrap()
                    .clone(),
            );
        }
        if seen == expected {
            break;
        }
    }
    assert_eq!(seen, expected);
    assert_eq!(left_counts.requests.load(Ordering::SeqCst), 0);
    assert_eq!(right_counts.requests.load(Ordering::SeqCst), 0);
    assert_eq!(left_counts.sent_event_json.load(Ordering::SeqCst), 0);
    assert_eq!(right_counts.sent_event_json.load(Ordering::SeqCst), 0);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn cached_id_over_single_object_ceiling_keeps_smaller_id_reachable() {
    let (left, right, sdk, route, left_counts, right_counts, items) =
        cached_fixture(&[5 * 1024 * 1024 + 1024, 1024], &[0, 1]).await;
    let (summary, events) = sdk
        .reconcile_subscription(route, &[], 0, u64::MAX, &Cursor::default())
        .await
        .unwrap();
    let small = items
        .iter()
        .find(|item| {
            events
                .iter()
                .any(|event| event.event.id == hex::encode(item.event_id))
        })
        .expect("a later affordable cached candidate remains reachable");
    assert!(items.iter().any(|item| item.event_id != small.event_id));
    assert_eq!(events.len(), 1);
    assert!(returned_json_bytes(&events) < 128 * 1024);
    assert_eq!(summary.relays_failed, 2);
    assert_eq!(left_counts.requests.load(Ordering::SeqCst), 0);
    assert_eq!(right_counts.requests.load(Ordering::SeqCst), 0);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn one_large_network_event_is_recovered_within_single_object_ceiling() {
    let (left, right, sdk, route, left_counts, right_counts, items) =
        cached_fixture(&[160 * 1024], &[]).await;
    let (summary, events) = sdk
        .reconcile_subscription(route, &[], 0, u64::MAX, &Cursor::default())
        .await
        .unwrap();
    assert_eq!(summary.relays_failed, 0);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.id, hex::encode(items[0].event_id));
    assert!(returned_json_bytes(&events) > 128 * 1024);
    assert!(returned_json_bytes(&events) <= 5 * 1024 * 1024);
    assert!(left_counts.sent_event_json.load(Ordering::SeqCst) > 128 * 1024);
    assert!(right_counts.sent_event_json.load(Ordering::SeqCst) > 128 * 1024);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn warm_large_event_waits_for_empty_next_pass_after_smaller_event() {
    // With the fixed signing key, ID order puts index 1 before index 0.
    let (left, right, sdk, route, left_counts, right_counts, items) =
        cached_fixture(&[160 * 1024, 1024], &[0, 1]).await;
    assert_eq!(items[0].created_at, 1_700_001_001);
    assert_eq!(items[1].created_at, 1_700_001_000);
    let cursor = Cursor::default();
    let (first, small) = sdk
        .reconcile_subscription(route.clone(), &[], 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert_eq!(first.relays_failed, 2);
    assert_eq!(small.len(), 1);
    assert_eq!(small[0].event.id, hex::encode(items[0].event_id));
    assert!(returned_json_bytes(&small) < 128 * 1024);
    let (next, large) = sdk
        .reconcile_subscription(route, &items[..1], 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert_eq!(next.relays_failed, 0);
    assert_eq!(large.len(), 1);
    assert_eq!(large[0].event.id, hex::encode(items[1].event_id));
    assert!(returned_json_bytes(&large) > 128 * 1024);
    assert!(returned_json_bytes(&large) <= 5 * 1024 * 1024);
    assert_eq!(left_counts.requests.load(Ordering::SeqCst), 0);
    assert_eq!(right_counts.requests.load(Ordering::SeqCst), 0);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn large_network_id_retries_after_a_smaller_cached_prefix() {
    let (left, right, sdk, route, left_counts, right_counts, items) =
        cached_fixture(&[160 * 1024, 1024], &[0]).await;
    assert_eq!(items[0].created_at, 1_700_001_001);
    let cursor = Cursor::default();
    let (first, small) = sdk
        .reconcile_subscription(route.clone(), &[], 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert_eq!(first.relays_failed, 2);
    assert_eq!(small.len(), 1);
    assert_eq!(small[0].event.id, hex::encode(items[0].event_id));
    assert!(returned_json_bytes(&small) < 128 * 1024);
    let (next, large) = sdk
        .reconcile_subscription(route, &items[..1], 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert_eq!(next.relays_failed, 0);
    assert_eq!(large.len(), 1);
    assert_eq!(large[0].event.id, hex::encode(items[1].event_id));
    assert!(returned_json_bytes(&large) > 128 * 1024);
    assert!(returned_json_bytes(&large) <= 5 * 1024 * 1024);
    assert!(left_counts.requests.load(Ordering::SeqCst) >= 2);
    assert!(right_counts.requests.load(Ordering::SeqCst) >= 2);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn unadmitted_small_network_id_does_not_hide_deferred_large_id() {
    // The fixed fixture key puts the small ID first. Keep the caller's durable
    // inventory empty on every pass: returning A is not admission of A.
    let (left, right, sdk, route, _, _, items) = cached_fixture(&[160 * 1024, 1024], &[]).await;
    assert_eq!(items[0].created_at, 1_700_001_001);
    let cursor = Cursor::default();
    let (first_summary, first) = sdk
        .reconcile_subscription(route.clone(), &[], 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert_eq!(first_summary.relays_failed, 2);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].event.id, hex::encode(items[0].event_id));
    let (second_summary, second) = sdk
        .reconcile_subscription(route, &[], 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert_eq!(second.len(), 1, "the deferred ID must lead the next pass");
    assert_eq!(second[0].event.id, hex::encode(items[1].event_id));
    assert!(returned_json_bytes(&second) > 128 * 1024);
    assert_eq!(second_summary.relays_failed, 2, "A remains unadmitted");
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn duplicate_route_endpoint_preserves_cached_prefix_and_unique_obligations() {
    let (left, right, sdk, mut route, left_counts, right_counts, items) =
        cached_fixture(&[1024, 1024], &[0]).await;
    let NostrSubscription::Group { endpoints, .. } = &mut route else {
        panic!("group fixture");
    };
    endpoints.push(endpoints[0].clone());
    endpoints.push(TransportEndpoint(format!(
        "{}/",
        endpoints[0].as_str().trim_end_matches('/')
    )));
    let (summary, events) = sdk
        .reconcile_subscription(route, &[], 0, u64::MAX, &Cursor::default())
        .await
        .unwrap();
    assert_eq!(events.len(), 2, "cached prefix and network suffix survive");
    assert!(
        events
            .iter()
            .any(|event| event.event.id == hex::encode(items[0].event_id))
    );
    assert!(
        events
            .iter()
            .any(|event| event.event.id == hex::encode(items[1].event_id))
    );
    assert_eq!(summary.relays_failed, 0);
    assert_eq!(
        summary.relays_succeeded, 2,
        "two distinct relay obligations"
    );
    assert_eq!(left_counts.requests.load(Ordering::SeqCst), 1);
    assert_eq!(right_counts.requests.load(Ordering::SeqCst), 1);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn large_network_result_survives_one_withholding_endpoint() {
    let (left, right, sdk, route, left_counts, right_counts, items) =
        cached_fixture(&[160 * 1024], &[]).await;
    right_counts.suppress_events.store(true, Ordering::SeqCst);
    let (summary, events) = sdk
        .reconcile_subscription(route, &[], 0, u64::MAX, &Cursor::default())
        .await
        .unwrap();
    assert_eq!(summary.relays_succeeded, 1);
    assert_eq!(summary.relays_failed, 1);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.id, hex::encode(items[0].event_id));
    assert!(returned_json_bytes(&events) > 128 * 1024);
    assert!(left_counts.sent_event_json.load(Ordering::SeqCst) > 128 * 1024);
    assert!(right_counts.sent_event_json.load(Ordering::SeqCst) > 128 * 1024);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn mixed_cache_and_network_share_one_return_budget() {
    let (left, right, sdk, route, left_counts, right_counts, items) =
        cached_fixture(&[LARGE_EVENT_BYTES; 4], &[0]).await;
    let cursor = Cursor::default();
    let (summary, first) = sdk
        .reconcile_subscription(route.clone(), &[], 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert_eq!(summary.relays_failed, 2);
    assert_eq!(first.len(), 3);
    assert!(returned_json_bytes(&first) <= 128 * 1024);
    assert!(
        first
            .iter()
            .any(|event| event.event.id == hex::encode(items[0].event_id))
    );
    assert!(left_counts.requests.load(Ordering::SeqCst) >= 1);
    assert!(right_counts.requests.load(Ordering::SeqCst) >= 1);
    let admitted = first
        .iter()
        .map(|event| {
            let id: [u8; 32] = hex::decode(&event.event.id).unwrap().try_into().unwrap();
            items
                .iter()
                .find(|item| item.event_id == id)
                .unwrap()
                .clone()
        })
        .collect::<Vec<_>>();
    let (next, remaining) = sdk
        .reconcile_subscription(route, &admitted, 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert_eq!(next.relays_failed, 0);
    assert_eq!(remaining.len(), 1);
    assert!(
        !admitted
            .iter()
            .any(|item| remaining[0].event.id == hex::encode(item.event_id))
    );
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn duplicated_endpoint_item_limit_keeps_partial_event_and_incomplete_summary() {
    let (left, right, sdk, route, left_counts, right_counts, event_id) =
        one_missing_event_fixture().await;
    right_counts.extra_event_copies.store(20, Ordering::SeqCst);
    let (summary, events) = sdk
        .reconcile_subscription(route, &[], 0, u64::MAX, &Cursor::default())
        .await
        .unwrap();
    assert_eq!(summary.relays_succeeded, 1);
    assert_eq!(summary.relays_failed, 1);
    assert_eq!(events.len(), 1, "cross-relay copies stay one owned event");
    assert_eq!(events[0].event.id, event_id);
    assert!(left_counts.sent_event_json.load(Ordering::SeqCst) > 0);
    assert!(right_counts.sent_event_json.load(Ordering::SeqCst) > 0);
    assert!(right_counts.sent_event_json.load(Ordering::SeqCst) < 16 * 1024);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn silent_endpoint_deadline_keeps_healthy_partial_event_and_incomplete_summary() {
    let (left, right, sdk, route, left_counts, right_counts, event_id) =
        one_missing_event_fixture().await;
    right_counts.drop_requests.store(true, Ordering::SeqCst);
    let (summary, events) = sdk
        .reconcile_subscription(route, &[], 0, u64::MAX, &Cursor::default())
        .await
        .unwrap();
    assert_eq!(summary.relays_succeeded, 1);
    assert_eq!(summary.relays_failed, 1);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.id, event_id);
    assert!(left_counts.requests.load(Ordering::SeqCst) >= 1);
    assert!(right_counts.requests.load(Ordering::SeqCst) >= 1);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn silent_and_fast_withholding_endpoint_resume_two_ids_across_paced_passes() {
    for silent in [true, false] {
        let (left, right, sdk, route, left_counts, right_counts, items) =
            cached_fixture(&[1024, 1024], &[]).await;
        if silent {
            right_counts.drop_requests.store(true, Ordering::SeqCst);
        } else {
            right_counts.suppress_events.store(true, Ordering::SeqCst);
        }
        let cursor = Cursor::default();
        let mut admitted = Vec::new();
        let mut seen = HashSet::new();
        for pass in 0..if silent { 2 } else { 1 } {
            let (summary, events) = sdk
                .reconcile_subscription(route.clone(), &admitted, 0, u64::MAX, &cursor)
                .await
                .unwrap();
            if silent {
                // A silent relay can consume almost the entire deadline. If
                // the healthy endpoint finishes another exact request in the
                // remaining interval, both IDs can arrive this pass; otherwise
                // cursor rotation reaches the second ID on the next pass.
                assert!(summary.relays_failed >= 1);
                assert!(!events.is_empty());
                if seen.len() + events.len() < 2 {
                    assert_eq!(summary.relays_failed, 2);
                }
            } else {
                assert_eq!(summary.relays_succeeded, 1);
                assert_eq!(summary.relays_failed, 1);
                assert_eq!(
                    events.len(),
                    2,
                    "fast failure cannot block a healthy suffix"
                );
            }
            for event in events {
                let id: [u8; 32] = hex::decode(&event.event.id).unwrap().try_into().unwrap();
                assert!(seen.insert(id), "pass {pass} must reach a later ID");
                admitted.push(
                    items
                        .iter()
                        .find(|item| item.event_id == id)
                        .unwrap()
                        .clone(),
                );
            }
            if seen.len() == 2 {
                break;
            }
        }
        assert_eq!(seen.len(), 2, "both IDs remain reachable");
        assert!(left_counts.requests.load(Ordering::SeqCst) >= 2);
        assert!(right_counts.requests.load(Ordering::SeqCst) >= 2);
        sdk.client().shutdown().await;
        left.shutdown();
        right.shutdown();
    }
}

#[tokio::test]
async fn comparison_claim_without_exact_id_bytes_remains_incomplete() {
    let (left, right, sdk, route, left_counts, right_counts, event_id) =
        one_missing_event_fixture().await;
    right_counts.suppress_events.store(true, Ordering::SeqCst);
    let (summary, events) = sdk
        .reconcile_subscription(route, &[], 0, u64::MAX, &Cursor::default())
        .await
        .unwrap();
    assert_eq!(summary.relays_succeeded, 1);
    assert_eq!(summary.relays_failed, 1);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.id, event_id);
    assert!(left_counts.sent_event_json.load(Ordering::SeqCst) > 0);
    assert!(right_counts.sent_event_json.load(Ordering::SeqCst) > 0);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}
