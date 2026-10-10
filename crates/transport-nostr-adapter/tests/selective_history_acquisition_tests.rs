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
/// The adapter's ordinary per-pass, per-relay result budgets.
const PASS_BYTE_BUDGET: usize = 1024 * 1024;
const PASS_ITEM_BUDGET: usize = 256;
/// Three fit one pass's byte budget, so a gap of eight needs several passes.
const LARGE_EVENT_BYTES: usize = 320 * 1024;
/// Over the ordinary pass budget but under the 5-MiB single-object ceiling.
/// The odd 11 bytes keep the fixed fixture key's ID order, which puts a small
/// event before this one.
const OVER_PASS_EVENT_BYTES: usize = PASS_BYTE_BUDGET + 256 * 1024 + 11;

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
    /// Event IDs (hex) this relay claims but never sends.
    suppress_ids: Mutex<HashSet<String>>,
    /// Once set, NEG-OPEN frames after this many go unanswered.
    comparisons_answered: Mutex<Option<usize>>,
    extra_event_copies: AtomicUsize,
    /// Simulated round trip: each client frame reaches the relay this long
    /// after it was sent, in order, without delaying the frames behind it.
    latency_ms: AtomicUsize,
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
                // Stamp each client frame on arrival and release it once its
                // latency has passed, so concurrent requests overlap as they
                // would on a real link.
                let (delayed_tx, mut delayed_rx) = tokio::sync::mpsc::unbounded_channel();
                let stamp = async {
                    while let Some(Ok(message)) = client_read.next().await {
                        let latency = counts.latency_ms.load(Ordering::SeqCst) as u64;
                        let due =
                            tokio::time::Instant::now() + std::time::Duration::from_millis(latency);
                        if delayed_tx.send((due, message)).is_err() {
                            break;
                        }
                    }
                };
                let to_relay = async {
                    while let Some((due, message)) = delayed_rx.recv().await {
                        tokio::time::sleep_until(due).await;
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
                                let seen = counts.comparisons.fetch_add(1, Ordering::SeqCst);
                                if counts
                                    .comparisons_answered
                                    .lock()
                                    .unwrap()
                                    .is_some_and(|answered| seen >= answered)
                                {
                                    continue;
                                }
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
                                if counts.suppress_events.load(Ordering::SeqCst)
                                    || event.get("id").and_then(Value::as_str).is_some_and(|id| {
                                        counts.suppress_ids.lock().unwrap().contains(id)
                                    })
                                {
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
                tokio::select! { _ = stamp => {}, _ = to_relay => {}, _ = to_client => {} }
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
        .reconcile_subscription(route.clone(), &all_retained, SINCE, UNTIL, &cursor)
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
    // Oldest-first may return nothing on a pass that fetched only events
    // newer than one it left behind, so allow more passes than the gap needs.
    for attempt in 1..=12usize {
        let before_left = left_counts.sent_event_json.load(Ordering::SeqCst);
        let before_right = right_counts.sent_event_json.load(Ordering::SeqCst);
        let (summary, events) = sdk
            .reconcile_subscription(route.clone(), &admitted, SINCE, UNTIL, &cursor)
            .await
            .unwrap();
        assert_eq!(summary.relays_succeeded + summary.relays_failed, 2);
        if seen.is_empty() {
            assert_eq!(summary.relays_failed, 2, "byte exhaustion is incomplete");
            assert!(
                events.len() < missing.len(),
                "one pass may not retain the whole gap"
            );
        }
        // One comparison, at most six rounds of eight window probes, and one
        // round of delivery probes per pass.
        assert!(left_counts.comparisons.load(Ordering::SeqCst) <= 1 + attempt * 57);
        assert!(right_counts.comparisons.load(Ordering::SeqCst) <= 1 + attempt * 57);
        assert!(left_counts.requests.load(Ordering::SeqCst) <= attempt * 16);
        assert!(right_counts.requests.load(Ordering::SeqCst) <= attempt * 16);
        let left_payload = left_counts.sent_event_json.load(Ordering::SeqCst) - before_left;
        let right_payload = right_counts.sent_event_json.load(Ordering::SeqCst) - before_right;
        assert!(
            left_payload <= PASS_BYTE_BUDGET + LARGE_EVENT_BYTES + 64 * 1024,
            "left sent {left_payload} prefilter EVENT bytes"
        );
        assert!(
            right_payload <= PASS_BYTE_BUDGET + LARGE_EVENT_BYTES + 64 * 1024,
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
        .reconcile_subscription(route, &admitted, SINCE, UNTIL, &cursor)
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
    // Fetching this gap oldest-first adds dry-run comparisons over narrower
    // windows of the 1,100 retained events, about 200 KiB here.
    assert!(
        control_bytes <= 320 * 1024,
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

/// What recovering a large gap of ordinary-sized events costs over a link
/// with a realistic round trip: passes, wall time, requests and the largest
/// per-relay event payload one pass carried. Prints its measurement.
#[tokio::test]
async fn large_gap_of_small_events_recovers_in_few_passes() {
    const MISSING: usize = 512;
    let keys = Keys::generate();
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(4_096),
    });
    let mut retained = Vec::new();
    let mut missing = Vec::new();
    for index in 0..(100 + MISSING) {
        // About the size of an encrypted chat message.
        let content = format!("{index}-{}", "x".repeat(1_200));
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
        if index >= 100 {
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
    left_counts.latency_ms.store(40, Ordering::SeqCst);
    right_counts.latency_ms.store(40, Ordering::SeqCst);
    let urls = vec![left_url, right_url];
    let sdk = NostrSdkRelayClient::new(Client::builder().build());
    for url in &urls {
        sdk.client().add_relay(url.as_str()).await.unwrap();
    }
    sdk.client().connect().await;
    let cursor = Cursor::default();
    let route = subscription(&urls);
    let wanted: HashSet<_> = missing.iter().map(|item| item.event_id).collect();
    let mut admitted = retained;
    let mut seen = HashSet::new();
    let mut passes = 0usize;
    let mut largest_pass_payload = 0usize;
    let started = std::time::Instant::now();
    while seen.len() < wanted.len() && passes < 200 {
        passes += 1;
        let before = [
            left_counts.sent_event_json.load(Ordering::SeqCst),
            right_counts.sent_event_json.load(Ordering::SeqCst),
        ];
        let (_, events) = sdk
            .reconcile_subscription(route.clone(), &admitted, 0, u64::MAX, &cursor)
            .await
            .unwrap();
        largest_pass_payload = largest_pass_payload
            .max(left_counts.sent_event_json.load(Ordering::SeqCst) - before[0])
            .max(right_counts.sent_event_json.load(Ordering::SeqCst) - before[1]);
        for event in events {
            let id: [u8; 32] = hex::decode(event.event.id).unwrap().try_into().unwrap();
            if wanted.contains(&id) && seen.insert(id) {
                admitted.push(
                    missing
                        .iter()
                        .find(|item| item.event_id == id)
                        .unwrap()
                        .clone(),
                );
            }
        }
    }
    let elapsed = started.elapsed();
    let requests =
        left_counts.requests.load(Ordering::SeqCst) + right_counts.requests.load(Ordering::SeqCst);
    let payload = left_counts.sent_event_json.load(Ordering::SeqCst)
        + right_counts.sent_event_json.load(Ordering::SeqCst);
    eprintln!(
        "large gap: missing={MISSING} passes={passes} elapsed_ms={} requests={requests} \
         event_json_bytes={payload} largest_pass_payload_per_relay={largest_pass_payload}",
        elapsed.as_millis()
    );
    assert_eq!(seen, wanted, "every missing event is recovered");
    assert!(
        requests < MISSING,
        "batched recovery used {requests} requests for {MISSING} events"
    );
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

/// A route's comparison window as the app passes it: its 30-day inventory
/// floor up to now, with the gaps below near the recent end.
const SINCE: u64 = 1_700_000_000 - 30 * 24 * 60 * 60;
const UNTIL: u64 = 1_700_200_000;

/// Events at consecutive seconds from `start`, each about the size of an
/// encrypted chat message, stored in a fresh relay database.
async fn timed_events(
    keys: &Keys,
    start: u64,
    count: usize,
    label: &str,
    database: &MemoryDatabase,
) -> Vec<NostrReconciliationItem> {
    let mut items = Vec::new();
    for index in 0..count {
        let event = EventBuilder::new(
            Kind::MlsGroupMessage,
            format!("{label}-{index}-{}", "x".repeat(1_200)),
        )
        .tags([Tag::custom("h", [hex::encode(ROUTE)])])
        .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(
            start + index as u64,
        ))
        .finalize(keys)
        .unwrap();
        database
            .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
            .await
            .unwrap();
        items.push(NostrReconciliationItem {
            event_id: event.id.to_bytes(),
            created_at: event.created_at.as_secs(),
        });
    }
    items
}

fn relay_database() -> MemoryDatabase {
    MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(8_192),
    })
}

async fn sdk_on(urls: &[String]) -> NostrSdkRelayClient {
    let sdk = NostrSdkRelayClient::new(Client::builder().build());
    for url in urls {
        sdk.client().add_relay(url.as_str()).await.unwrap();
    }
    sdk.client().connect().await;
    sdk
}

/// Events signed by a fresh key until `accept` holds for the ID order, so a
/// test can rely on which ID a pass requests first.
fn events_with_id_order(
    specs: &[(usize, u64)],
    accept: impl Fn(&[nostr_sdk::prelude::Event]) -> bool,
) -> Vec<nostr_sdk::prelude::Event> {
    loop {
        let keys = Keys::generate();
        let events = specs
            .iter()
            .enumerate()
            .map(|(index, (size, created_at))| {
                EventBuilder::new(
                    Kind::MlsGroupMessage,
                    format!("{index}-{}", "x".repeat(*size)),
                )
                .tags([Tag::custom("h", [hex::encode(ROUTE)])])
                .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(*created_at))
                .finalize(&keys)
                .unwrap()
            })
            .collect::<Vec<_>>();
        if accept(&events) {
            return events;
        }
    }
}

/// Two relays that claim the same batch can each return a different event
/// within their own limits. What the pass returns is the union, and it must
/// still fit the pass allowance; the event that does not fit leads the next
/// pass.
#[tokio::test]
async fn complementary_relay_results_share_one_pass_allowance() {
    // A small event first in ID order, then two 600-KiB events in one batch.
    let events = events_with_id_order(
        &[
            (1_024, 1_700_000_000),
            (600 * 1024, 1_700_000_001),
            (600 * 1024, 1_700_000_002),
        ],
        |events| events[0].id < events[1].id && events[0].id < events[2].id,
    );
    let database = relay_database();
    for event in &events {
        database
            .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
            .await
            .unwrap();
    }
    let left = LocalRelay::new(RelayBuilder::default().database(database.clone()));
    let right = LocalRelay::new(RelayBuilder::default().database(database));
    left.run().await.unwrap();
    right.run().await.unwrap();
    let (left_url, left_counts) = counted_proxy(left.url().await.to_string()).await;
    let (right_url, right_counts) = counted_proxy(right.url().await.to_string()).await;
    // Both relays claim all three; each serves only one of the large ones.
    left_counts
        .suppress_ids
        .lock()
        .unwrap()
        .insert(events[2].id.to_hex());
    right_counts
        .suppress_ids
        .lock()
        .unwrap()
        .insert(events[1].id.to_hex());
    let urls = vec![left_url, right_url];
    let sdk = sdk_on(&urls).await;
    let route = subscription(&urls);
    let cursor = Cursor::default();
    let (_, first) = sdk
        .reconcile_subscription(route.clone(), &[], 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert!(
        returned_json_bytes(&first) <= PASS_BYTE_BUDGET,
        "one pass returned {} bytes",
        returned_json_bytes(&first)
    );
    assert_eq!(first.len(), 2, "the small event and one large event fit");
    let admitted = first
        .iter()
        .map(|event| NostrReconciliationItem {
            event_id: hex::decode(&event.event.id).unwrap().try_into().unwrap(),
            created_at: event.event.created_at,
        })
        .collect::<Vec<_>>();
    let (_, second) = sdk
        .reconcile_subscription(route, &admitted, 0, u64::MAX, &cursor)
        .await
        .unwrap();
    assert_eq!(second.len(), 1, "the deferred large event arrives next");
    assert!(
        first
            .iter()
            .all(|event| event.event.id != second[0].event.id)
    );
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

/// A large event a batch's byte limit cuts off, behind smaller batch-mates the
/// relay sends first, leads the next pass, where it fits as a one-ID request
/// under the single-object ceiling.
#[tokio::test]
async fn large_event_cut_from_a_batch_leads_the_next_pass() {
    // Thirty 80-KiB events, which the relay sends before the older large
    // one, and a 4.5-MiB event that falls in the first batch after the
    // pass's one-ID first request (about eleven IDs at this size) without
    // being that first request. Smaller events remain after the batch, so a
    // cursor left past the batch would not come back to the large one soon.
    let mut specs = (0..30)
        .map(|index| (80 * 1024, 1_700_000_100 + index))
        .collect::<Vec<_>>();
    specs.push((4 * 1024 * 1024 + 512 * 1024, 1_700_000_000));
    let events = events_with_id_order(&specs, |events| {
        let rank = events[..30]
            .iter()
            .filter(|small| small.id < events[30].id)
            .count();
        (1..=10).contains(&rank)
    });
    let large_id = events[30].id;
    let database = relay_database();
    for event in &events {
        database
            .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
            .await
            .unwrap();
    }
    let relay = LocalRelay::new(RelayBuilder::default().database(database));
    relay.run().await.unwrap();
    let (url, _) = counted_proxy(relay.url().await.to_string()).await;
    let sdk = sdk_on(std::slice::from_ref(&url)).await;
    let route = subscription(&[url]);
    let cursor = Cursor::default();
    let (_, first) = sdk
        .reconcile_subscription(route.clone(), &[], SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert!(
        first
            .iter()
            .all(|event| event.event.id != large_id.to_hex())
    );
    let admitted = first
        .iter()
        .map(|event| NostrReconciliationItem {
            event_id: hex::decode(&event.event.id).unwrap().try_into().unwrap(),
            created_at: event.event.created_at,
        })
        .collect::<Vec<_>>();
    let (_, second) = sdk
        .reconcile_subscription(route, &admitted, SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert!(
        second
            .iter()
            .any(|event| event.event.id == large_id.to_hex()),
        "the cut-off large event arrives on the next pass"
    );
    sdk.client().shutdown().await;
    relay.shutdown();
}

/// A gap larger than one pass arrives from its oldest end: no pass returns an
/// event newer than one still missing, so commits cannot carry a member's
/// epoch past older messages it has not fetched (#2086).
#[tokio::test]
async fn a_gap_larger_than_one_pass_arrives_oldest_first() {
    let keys = Keys::generate();
    let database = relay_database();
    let retained = timed_events(&keys, 1_700_000_000, 50, "retained", &database).await;
    let missing = timed_events(&keys, 1_700_100_000, 700, "missing", &database).await;
    let relay = LocalRelay::new(RelayBuilder::default().database(database));
    relay.run().await.unwrap();
    let (url, counts) = counted_proxy(relay.url().await.to_string()).await;
    counts.latency_ms.store(40, Ordering::SeqCst);
    let sdk = sdk_on(std::slice::from_ref(&url)).await;
    let route = subscription(&[url]);
    let cursor = Cursor::default();
    let mut admitted = retained;
    let mut pending = missing.clone();
    let mut passes = 0;
    let started = std::time::Instant::now();
    while !pending.is_empty() && passes < 20 {
        passes += 1;
        let (_, events) = sdk
            .reconcile_subscription(route.clone(), &admitted, SINCE, UNTIL, &cursor)
            .await
            .unwrap();
        assert!(!events.is_empty(), "pass {passes} made no progress");
        let newest_returned = events
            .iter()
            .map(|event| event.event.created_at)
            .max()
            .unwrap();
        let returned = events
            .iter()
            .map(|event| hex::decode(&event.event.id).unwrap())
            .collect::<HashSet<_>>();
        pending.retain(|item| {
            if returned.contains(item.event_id.as_slice()) {
                admitted.push(item.clone());
                false
            } else {
                true
            }
        });
        if let Some(oldest_missing) = pending.iter().map(|item| item.created_at).min() {
            assert!(
                newest_returned < oldest_missing,
                "pass {passes} returned an event newer than one still missing"
            );
        }
    }
    eprintln!(
        "oldest-first gap: missing={} passes={passes} elapsed_ms={} comparisons={} requests={}",
        missing.len(),
        started.elapsed().as_millis(),
        counts.comparisons.load(Ordering::SeqCst),
        counts.requests.load(Ordering::SeqCst),
    );
    assert!(pending.is_empty(), "every missing event arrives");
    sdk.client().shutdown().await;
    relay.shutdown();
}

/// Older history that appears after a backlog is under way, here from a relay
/// that joins the route, still arrives before newer history: the window
/// search looks below where the previous pass left off.
#[tokio::test]
async fn older_history_that_appears_later_still_arrives_first() {
    let keys = Keys::generate();
    let recent = relay_database();
    let older = relay_database();
    let newer_gap = timed_events(&keys, 1_700_100_000, 600, "newer", &recent).await;
    let older_gap = timed_events(&keys, 1_700_000_000, 400, "older", &older).await;
    let recent_relay = LocalRelay::new(RelayBuilder::default().database(recent));
    let older_relay = LocalRelay::new(RelayBuilder::default().database(older));
    recent_relay.run().await.unwrap();
    older_relay.run().await.unwrap();
    let (recent_url, _) = counted_proxy(recent_relay.url().await.to_string()).await;
    let (older_url, _) = counted_proxy(older_relay.url().await.to_string()).await;
    let sdk = sdk_on(&[recent_url.clone(), older_url.clone()]).await;
    let cursor = Cursor::default();
    let mut admitted = Vec::new();
    let admit = |admitted: &mut Vec<NostrReconciliationItem>,
                 events: Vec<transport_nostr_adapter::NostrRelayEvent>| {
        for event in events {
            let id: [u8; 32] = hex::decode(&event.event.id).unwrap().try_into().unwrap();
            if let Some(item) = newer_gap
                .iter()
                .chain(&older_gap)
                .find(|item| item.event_id == id)
            {
                admitted.push(item.clone());
            }
        }
    };
    // One pass against the recent relay alone leaves the route's search
    // seeded past the older history.
    let (_, events) = sdk
        .reconcile_subscription(
            subscription(std::slice::from_ref(&recent_url)),
            &admitted,
            SINCE,
            UNTIL,
            &cursor,
        )
        .await
        .unwrap();
    assert!(!events.is_empty());
    admit(&mut admitted, events);
    // The older relay joins: its whole gap is older than anything left.
    let route = subscription(&[recent_url, older_url]);
    let (_, events) = sdk
        .reconcile_subscription(route, &admitted, SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    let older_ids = older_gap
        .iter()
        .map(|item| item.event_id)
        .collect::<HashSet<_>>();
    assert!(!events.is_empty());
    assert!(
        events.iter().all(|event| {
            let id: [u8; 32] = hex::decode(&event.event.id).unwrap().try_into().unwrap();
            older_ids.contains(&id)
        }),
        "the newly appeared older history comes first"
    );
    sdk.client().shutdown().await;
    recent_relay.shutdown();
    older_relay.shutdown();
}

/// More old events the account never admits than a route keeps set aside
/// cannot stall it: past that limit the route falls back to ID-order
/// selection, which reaches the wanted history in turn.
#[tokio::test]
async fn more_never_admitted_history_than_can_be_set_aside_still_lets_the_gap_arrive() {
    let keys = Keys::generate();
    let database = relay_database();
    let junk = timed_events(&keys, 1_700_000_000, 1_100, "junk", &database).await;
    let wanted = timed_events(&keys, 1_700_100_000, 50, "wanted", &database).await;
    let relay = LocalRelay::new(RelayBuilder::default().database(database));
    relay.run().await.unwrap();
    let (url, _) = counted_proxy(relay.url().await.to_string()).await;
    let sdk = sdk_on(std::slice::from_ref(&url)).await;
    let route = subscription(&[url]);
    let cursor = Cursor::default();
    let junk_ids = junk
        .iter()
        .map(|item| item.event_id)
        .collect::<HashSet<_>>();
    let mut admitted = Vec::new();
    let mut pending = wanted
        .iter()
        .map(|item| item.event_id)
        .collect::<HashSet<_>>();
    for _ in 0..30 {
        if pending.is_empty() {
            break;
        }
        let (_, events) = sdk
            .reconcile_subscription(route.clone(), &admitted, SINCE, UNTIL, &cursor)
            .await
            .unwrap();
        for event in events {
            let id: [u8; 32] = hex::decode(&event.event.id).unwrap().try_into().unwrap();
            if !junk_ids.contains(&id) && pending.remove(&id) {
                admitted.push(
                    wanted
                        .iter()
                        .find(|item| item.event_id == id)
                        .unwrap()
                        .clone(),
                );
            }
        }
    }
    assert!(
        pending.is_empty(),
        "{} wanted events never arrived",
        pending.len()
    );
    sdk.client().shutdown().await;
    relay.shutdown();
}

/// A gap within one pass by count can exceed it by bytes. A pass the byte
/// budget cuts short still returns only events older than every one it left
/// behind.
#[tokio::test]
async fn a_gap_too_large_in_bytes_still_arrives_oldest_first() {
    let keys = Keys::generate();
    let database = relay_database();
    let mut missing = Vec::new();
    for index in 0..60u64 {
        let event = EventBuilder::new(
            Kind::MlsGroupMessage,
            format!("large-{index}-{}", "x".repeat(50 * 1024)),
        )
        .tags([Tag::custom("h", [hex::encode(ROUTE)])])
        .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(
            1_700_100_000 + index,
        ))
        .finalize(&keys)
        .unwrap();
        database
            .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
            .await
            .unwrap();
        missing.push(NostrReconciliationItem {
            event_id: event.id.to_bytes(),
            created_at: event.created_at.as_secs(),
        });
    }
    let relay = LocalRelay::new(RelayBuilder::default().database(database));
    relay.run().await.unwrap();
    let (url, _) = counted_proxy(relay.url().await.to_string()).await;
    let sdk = sdk_on(std::slice::from_ref(&url)).await;
    let route = subscription(&[url]);
    let cursor = Cursor::default();
    let mut admitted = Vec::new();
    let mut pending = missing.clone();
    let mut passes = 0;
    while !pending.is_empty() && passes < 30 {
        passes += 1;
        let (_, events) = sdk
            .reconcile_subscription(route.clone(), &admitted, SINCE, UNTIL, &cursor)
            .await
            .unwrap();
        let returned = events
            .iter()
            .map(|event| hex::decode(&event.event.id).unwrap())
            .collect::<HashSet<_>>();
        pending.retain(|item| {
            if returned.contains(item.event_id.as_slice()) {
                admitted.push(item.clone());
                false
            } else {
                true
            }
        });
        if let (Some(newest), Some(oldest_missing)) = (
            events.iter().map(|event| event.event.created_at).max(),
            pending.iter().map(|item| item.created_at).min(),
        ) {
            assert!(
                newest < oldest_missing,
                "pass {passes} returned an event newer than one still missing"
            );
        }
    }
    assert!(pending.is_empty(), "{} events never arrived", pending.len());
    sdk.client().shutdown().await;
    relay.shutdown();
}

/// A relay that answers the opening comparison but not the window probes may
/// hold older history the others lack. Its silence cannot make a window of
/// the others' history look like the oldest one: that pass fetches nothing
/// rather than newer history first, and the next still makes progress.
#[tokio::test]
async fn a_relay_that_misses_the_probes_cannot_make_newer_history_look_oldest() {
    let keys = Keys::generate();
    let older = relay_database();
    let newer = relay_database();
    let older_gap = timed_events(&keys, 1_700_000_000, 300, "older", &older).await;
    let newer_gap = timed_events(&keys, 1_700_100_000, 300, "newer", &newer).await;
    let older_relay = LocalRelay::new(RelayBuilder::default().database(older));
    let newer_relay = LocalRelay::new(RelayBuilder::default().database(newer));
    older_relay.run().await.unwrap();
    newer_relay.run().await.unwrap();
    let (older_url, older_counts) = counted_proxy(older_relay.url().await.to_string()).await;
    let (newer_url, _) = counted_proxy(newer_relay.url().await.to_string()).await;
    // The opening comparison is answered; every probe after it is not.
    *older_counts.comparisons_answered.lock().unwrap() = Some(1);
    let urls = vec![older_url, newer_url];
    let sdk = sdk_on(&urls).await;
    let route = subscription(&urls);
    let cursor = Cursor::default();
    let newer_ids = newer_gap
        .iter()
        .map(|item| hex::encode(item.event_id))
        .collect::<HashSet<_>>();
    let (_, first) = sdk
        .reconcile_subscription(route.clone(), &[], SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert!(
        first
            .iter()
            .all(|event| !newer_ids.contains(&event.event.id)),
        "newer history arrived while older history went unseen"
    );
    let (_, second) = sdk
        .reconcile_subscription(route, &[], SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert!(!second.is_empty(), "the next pass still makes progress");
    assert!(older_gap.len() + newer_gap.len() > 0);
    sdk.client().shutdown().await;
    older_relay.shutdown();
    newer_relay.shutdown();
}

/// Old events the account never admits (malformed, or refused every time)
/// cannot hold the oldest window: once fetched they yield to history not
/// tried yet, and the rest of the gap still arrives.
#[tokio::test]
async fn history_never_admitted_cannot_hold_the_oldest_window() {
    let keys = Keys::generate();
    let database = relay_database();
    let junk = timed_events(&keys, 1_700_000_000, 400, "junk", &database).await;
    let wanted = timed_events(&keys, 1_700_100_000, 400, "wanted", &database).await;
    let relay = LocalRelay::new(RelayBuilder::default().database(database));
    relay.run().await.unwrap();
    let (url, _) = counted_proxy(relay.url().await.to_string()).await;
    let sdk = sdk_on(std::slice::from_ref(&url)).await;
    let route = subscription(&[url]);
    let cursor = Cursor::default();
    let junk_ids = junk
        .iter()
        .map(|item| item.event_id)
        .collect::<HashSet<_>>();
    let mut admitted = Vec::new();
    let mut pending = wanted
        .iter()
        .map(|item| item.event_id)
        .collect::<HashSet<_>>();
    for _ in 0..12 {
        if pending.is_empty() {
            break;
        }
        let (_, events) = sdk
            .reconcile_subscription(route.clone(), &admitted, SINCE, UNTIL, &cursor)
            .await
            .unwrap();
        for event in events {
            let id: [u8; 32] = hex::decode(&event.event.id).unwrap().try_into().unwrap();
            // The junk is fetched but never admitted.
            if !junk_ids.contains(&id) && pending.remove(&id) {
                admitted.push(
                    wanted
                        .iter()
                        .find(|item| item.event_id == id)
                        .unwrap()
                        .clone(),
                );
            }
        }
    }
    assert!(
        pending.is_empty(),
        "{} wanted events never arrived",
        pending.len()
    );
    sdk.client().shutdown().await;
    relay.shutdown();
}

/// Old IDs a relay names but never serves cannot hold the oldest window
/// either: they yield once that relay answers without them, and another
/// relay still serves the gap.
#[tokio::test]
async fn ids_a_relay_never_serves_cannot_hold_the_oldest_window() {
    let keys = Keys::generate();
    let honest = relay_database();
    let lying = relay_database();
    // Only the lying relay names these, and it serves no events at all.
    timed_events(&keys, 1_700_000_000, 400, "phantom", &lying).await;
    let wanted = timed_events(&keys, 1_700_100_000, 400, "wanted", &honest).await;
    for item in &wanted {
        let event = honest
            .event_by_id(&nostr_relay_builder::prelude::EventId::from_byte_array(
                item.event_id,
            ))
            .await
            .unwrap()
            .unwrap();
        lying.save_event(&event).await.unwrap();
    }
    let honest_relay = LocalRelay::new(RelayBuilder::default().database(honest));
    let lying_relay = LocalRelay::new(RelayBuilder::default().database(lying));
    honest_relay.run().await.unwrap();
    lying_relay.run().await.unwrap();
    let (honest_url, _) = counted_proxy(honest_relay.url().await.to_string()).await;
    let (lying_url, lying_counts) = counted_proxy(lying_relay.url().await.to_string()).await;
    lying_counts.suppress_events.store(true, Ordering::SeqCst);
    let urls = vec![honest_url, lying_url];
    let sdk = sdk_on(&urls).await;
    let route = subscription(&urls);
    let cursor = Cursor::default();
    let mut admitted = Vec::new();
    let mut pending = wanted
        .iter()
        .map(|item| item.event_id)
        .collect::<HashSet<_>>();
    for _ in 0..12 {
        if pending.is_empty() {
            break;
        }
        let (_, events) = sdk
            .reconcile_subscription(route.clone(), &admitted, SINCE, UNTIL, &cursor)
            .await
            .unwrap();
        for event in events {
            let id: [u8; 32] = hex::decode(&event.event.id).unwrap().try_into().unwrap();
            if pending.remove(&id) {
                admitted.push(
                    wanted
                        .iter()
                        .find(|item| item.event_id == id)
                        .unwrap()
                        .clone(),
                );
            }
        }
    }
    assert!(
        pending.is_empty(),
        "{} wanted events never arrived",
        pending.len()
    );
    sdk.client().shutdown().await;
    honest_relay.shutdown();
    lying_relay.shutdown();
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
    // A pass returns only events older than every one it left behind, so one
    // that fetched newer events first may return none of them.
    for _ in 0..12 {
        let (summary, events) = sdk
            .reconcile_subscription(route.clone(), &admitted, SINCE, UNTIL, &cursor)
            .await
            .unwrap();
        assert!(returned_json_bytes(&events) <= PASS_BYTE_BUDGET);
        assert!(events.len() <= 3);
        if seen.len() + events.len() < expected.len() {
            assert_eq!(summary.relays_failed, 2);
        }
        if let Some(newest) = events.iter().map(|event| event.event.created_at).max() {
            assert!(items.iter().all(|item| {
                seen.contains(&item.event_id)
                    || events
                        .iter()
                        .any(|event| event.event.id == hex::encode(item.event_id))
                    || item.created_at > newest
            }));
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
    assert!(returned_json_bytes(&events) < PASS_BYTE_BUDGET);
    assert_eq!(summary.relays_failed, 2);
    assert_eq!(
        summary.incomplete_endpoints.len(),
        2,
        "a relay that answered with an unfetchable ID is incomplete, not failed"
    );
    assert_eq!(left_counts.requests.load(Ordering::SeqCst), 0);
    assert_eq!(right_counts.requests.load(Ordering::SeqCst), 0);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn one_large_network_event_is_recovered_within_single_object_ceiling() {
    let (left, right, sdk, route, left_counts, right_counts, items) =
        cached_fixture(&[OVER_PASS_EVENT_BYTES], &[]).await;
    let (summary, events) = sdk
        .reconcile_subscription(route, &[], 0, u64::MAX, &Cursor::default())
        .await
        .unwrap();
    assert_eq!(summary.relays_failed, 0);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.id, hex::encode(items[0].event_id));
    assert!(returned_json_bytes(&events) > PASS_BYTE_BUDGET);
    assert!(returned_json_bytes(&events) <= 5 * 1024 * 1024);
    assert!(left_counts.sent_event_json.load(Ordering::SeqCst) > PASS_BYTE_BUDGET);
    assert!(right_counts.sent_event_json.load(Ordering::SeqCst) > PASS_BYTE_BUDGET);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn warm_older_large_event_arrives_before_newer_small_event() {
    // With the fixed signing key, ID order puts the newer small event (index
    // 1) before the older large one (index 0).
    let (left, right, sdk, route, left_counts, right_counts, items) =
        cached_fixture(&[OVER_PASS_EVENT_BYTES, 1024], &[0, 1]).await;
    assert_eq!(items[0].created_at, 1_700_001_001);
    assert_eq!(items[1].created_at, 1_700_001_000);
    let cursor = Cursor::default();
    // The small event fits first, but the older large one did not: nothing
    // newer than it may be returned yet.
    let (first, held) = sdk
        .reconcile_subscription(route.clone(), &[], SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert_eq!(first.relays_failed, 2);
    assert!(held.is_empty());
    // The large event leads the next pass, alone in its allowance.
    let (_, large) = sdk
        .reconcile_subscription(route.clone(), &[], SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert_eq!(large.len(), 1);
    assert_eq!(large[0].event.id, hex::encode(items[1].event_id));
    assert!(returned_json_bytes(&large) > PASS_BYTE_BUDGET);
    assert!(returned_json_bytes(&large) <= 5 * 1024 * 1024);
    let (next, small) = sdk
        .reconcile_subscription(route, &items[1..], SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert_eq!(next.relays_failed, 0);
    assert_eq!(small.len(), 1);
    assert_eq!(small[0].event.id, hex::encode(items[0].event_id));
    assert_eq!(left_counts.requests.load(Ordering::SeqCst), 0);
    assert_eq!(right_counts.requests.load(Ordering::SeqCst), 0);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn older_large_network_event_arrives_before_newer_cached_small_event() {
    let (left, right, sdk, route, left_counts, right_counts, items) =
        cached_fixture(&[OVER_PASS_EVENT_BYTES, 1024], &[0]).await;
    assert_eq!(items[0].created_at, 1_700_001_001);
    let cursor = Cursor::default();
    // The cached newer small event is in hand, but the older large network
    // event did not fit after it: nothing newer than it is returned yet.
    let (first, held) = sdk
        .reconcile_subscription(route.clone(), &[], SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert_eq!(first.relays_failed, 2);
    assert!(held.is_empty());
    let (_, large) = sdk
        .reconcile_subscription(route.clone(), &[], SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert_eq!(
        large.len(),
        1,
        "the cut-off large event leads the next pass"
    );
    assert_eq!(large[0].event.id, hex::encode(items[1].event_id));
    assert!(returned_json_bytes(&large) > PASS_BYTE_BUDGET);
    assert!(returned_json_bytes(&large) <= 5 * 1024 * 1024);
    let (next, small) = sdk
        .reconcile_subscription(route, &items[1..], SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert_eq!(next.relays_failed, 0);
    assert_eq!(small.len(), 1);
    assert_eq!(small[0].event.id, hex::encode(items[0].event_id));
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
    let (left, right, sdk, route, _, _, items) =
        cached_fixture(&[OVER_PASS_EVENT_BYTES, 1024], &[]).await;
    assert_eq!(items[0].created_at, 1_700_001_001);
    let cursor = Cursor::default();
    // The small ID comes back first but is newer than the large one the
    // budget cut off, so it is held back.
    let (first_summary, first) = sdk
        .reconcile_subscription(route.clone(), &[], SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert_eq!(first_summary.relays_failed, 2);
    assert!(first.is_empty());
    let (second_summary, second) = sdk
        .reconcile_subscription(route, &[], SINCE, UNTIL, &cursor)
        .await
        .unwrap();
    assert_eq!(second.len(), 1, "the deferred ID must lead the next pass");
    assert_eq!(second[0].event.id, hex::encode(items[1].event_id));
    assert!(returned_json_bytes(&second) > PASS_BYTE_BUDGET);
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
        cached_fixture(&[OVER_PASS_EVENT_BYTES], &[]).await;
    right_counts.suppress_events.store(true, Ordering::SeqCst);
    let (summary, events) = sdk
        .reconcile_subscription(route, &[], 0, u64::MAX, &Cursor::default())
        .await
        .unwrap();
    assert_eq!(summary.relays_succeeded, 1);
    assert_eq!(summary.relays_failed, 1);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.id, hex::encode(items[0].event_id));
    assert!(returned_json_bytes(&events) > PASS_BYTE_BUDGET);
    assert!(left_counts.sent_event_json.load(Ordering::SeqCst) > PASS_BYTE_BUDGET);
    assert!(right_counts.sent_event_json.load(Ordering::SeqCst) > PASS_BYTE_BUDGET);
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
    assert!(returned_json_bytes(&first) <= PASS_BYTE_BUDGET);
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
    // More copies than one pass's item budget.
    right_counts
        .extra_event_copies
        .store(PASS_ITEM_BUDGET + 20, Ordering::SeqCst);
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
    assert!(right_counts.sent_event_json.load(Ordering::SeqCst) < (PASS_ITEM_BUDGET + 21) * 1024);
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
    assert!(
        summary.incomplete_endpoints.is_empty(),
        "a relay that timed out did not answer"
    );
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
                    assert!(
                        summary.incomplete_endpoints.is_empty(),
                        "a pass cut short by its deadline is a timeout, not an answer"
                    );
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
    assert_eq!(
        summary.incomplete_endpoints, summary.failed_endpoints,
        "a relay that answered without the claimed bytes is incomplete"
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.id, event_id);
    assert!(left_counts.sent_event_json.load(Ordering::SeqCst) > 0);
    assert!(right_counts.sent_event_json.load(Ordering::SeqCst) > 0);
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}

#[tokio::test]
async fn endpoint_with_nothing_missing_succeeds_while_a_silent_peer_fails() {
    // Only the left relay holds the missing event. Its exact-ID request goes
    // unanswered, which fails the left relay alone: the right relay claimed
    // nothing, is never asked, and its comparison still vouches for it.
    let holding = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(8),
    });
    let event = EventBuilder::new(Kind::MlsGroupMessage, "held by one relay")
        .tags([Tag::custom("h", [hex::encode(ROUTE)])])
        .finalize(&Keys::generate())
        .unwrap();
    holding
        .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
        .await
        .unwrap();
    let left = LocalRelay::new(RelayBuilder::default().database(holding));
    let right = LocalRelay::new(RelayBuilder::default().database(MemoryDatabase::with_opts(
        MemoryDatabaseOptions {
            events: true,
            max_events: Some(8),
        },
    )));
    left.run().await.unwrap();
    right.run().await.unwrap();
    let (left_url, left_counts) = counted_proxy(left.url().await.to_string()).await;
    let (right_url, right_counts) = counted_proxy(right.url().await.to_string()).await;
    left_counts.drop_requests.store(true, Ordering::SeqCst);
    let urls = vec![left_url.clone(), right_url];
    let sdk = NostrSdkRelayClient::new(Client::builder().build());
    for url in &urls {
        sdk.client().add_relay(url.as_str()).await.unwrap();
    }
    sdk.client().connect().await;
    let (summary, events) = sdk
        .reconcile_subscription(subscription(&urls), &[], 0, u64::MAX, &Cursor::default())
        .await
        .unwrap();
    assert!(events.is_empty());
    assert_eq!(summary.relays_succeeded, 1);
    assert_eq!(summary.relays_failed, 1);
    assert_eq!(summary.failed_endpoints.len(), 1);
    assert_eq!(
        summary.failed_endpoints[0].as_str().trim_end_matches('/'),
        left_url.trim_end_matches('/')
    );
    assert!(left_counts.requests.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        right_counts.requests.load(Ordering::SeqCst),
        0,
        "an endpoint that claimed nothing is never asked for it"
    );
    sdk.client().shutdown().await;
    left.shutdown();
    right.shutdown();
}
