//! Resource qualification at the relay text-frame boundary, SDK result, and worker credit.

use super::*;
use futures::{SinkExt, StreamExt};
use nostr_sdk::prelude::{Client as SdkClient, EventBuilder, FinalizeEvent, Keys, Kind};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use transport_nostr_adapter::{
    NostrAcquisitionCancellation, NostrAcquisitionEnd, NostrAcquisitionLimits,
    NostrAcquisitionRequest, NostrAcquisitionScope, NostrRelayClient, NostrSdkRelayClient,
};

#[derive(Clone, Copy, Default, Debug)]
struct TextBoundary {
    sent_text: usize,
    sent_event_json: usize,
    sent_events: usize,
    received_text: usize,
    received_requests: usize,
    received_closes: usize,
}

#[derive(Default)]
struct CountedRelay {
    counts: Mutex<TextBoundary>,
    request_seen: tokio::sync::Notify,
}

impl CountedRelay {
    fn snapshot(&self) -> TextBoundary {
        *self.counts.lock().unwrap()
    }
}

// The test owns text payload counts before any SDK filtering. WebSocket headers,
// TLS/TCP, parser allocation, and binary/control frames are outside this counter.
async fn counted_exact_relay(
    event: Option<Value>,
    copies: usize,
    send_eose: bool,
) -> (String, Arc<CountedRelay>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let counts = Arc::new(CountedRelay::default());
    let shared = counts.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let counts = shared.clone();
            let event = event.clone();
            tokio::spawn(async move {
                let Ok(socket) = accept_async(stream).await else {
                    return;
                };
                let (mut writer, mut reader) = socket.split();
                while let Some(Ok(message)) = reader.next().await {
                    let Message::Text(text) = message else {
                        continue;
                    };
                    let Ok(frame) = serde_json::from_str::<Vec<Value>>(&text) else {
                        continue;
                    };
                    {
                        let mut tally = counts.counts.lock().unwrap();
                        tally.received_text += text.len();
                        match frame.first().and_then(Value::as_str) {
                            Some("REQ") => tally.received_requests += 1,
                            Some("CLOSE") => tally.received_closes += 1,
                            _ => {}
                        }
                    }
                    if frame.first().and_then(Value::as_str) != Some("REQ") {
                        continue;
                    }
                    let Some(id) = frame.get(1).and_then(Value::as_str) else {
                        continue;
                    };
                    let ids = frame
                        .iter()
                        .skip(2)
                        .flat_map(|filter| filter["ids"].as_array().into_iter().flatten())
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>();
                    let exact = event
                        .as_ref()
                        .is_some_and(|event| ids.iter().any(|id| event["id"] == *id));
                    if exact {
                        counts.request_seen.notify_one();
                        let event = event.as_ref().unwrap();
                        for _ in 0..copies {
                            let frame = json!(["EVENT", id, event]);
                            let text = frame.to_string();
                            if writer
                                .send(Message::Text(text.clone().into()))
                                .await
                                .is_err()
                            {
                                return;
                            }
                            let mut tally = counts.counts.lock().unwrap();
                            tally.sent_text += text.len();
                            tally.sent_event_json += event.to_string().len();
                            tally.sent_events += 1;
                        }
                    }
                    if send_eose {
                        let text = json!(["EOSE", id]).to_string();
                        if writer
                            .send(Message::Text(text.clone().into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                        counts.counts.lock().unwrap().sent_text += text.len();
                    }
                }
            });
        }
    });
    (url, counts)
}

fn signed_event(payload_len: usize) -> (Value, [u8; 32]) {
    let event = EventBuilder::new(Kind::TextNote, "x".repeat(payload_len))
        .finalize(&Keys::generate())
        .unwrap();
    let id = event.id.to_bytes();
    (serde_json::to_value(event).unwrap(), id)
}

async fn acquire_exact(
    endpoints: &[String],
    id: [u8; 32],
    items: usize,
    bytes: usize,
    duration: Duration,
) -> transport_nostr_adapter::NostrAcquisitionResult {
    let sdk = NostrSdkRelayClient::new(SdkClient::builder().build());
    let request = NostrAcquisitionRequest {
        account_id: cgka_traits::MemberId::new(vec![7; 32]),
        scope: NostrAcquisitionScope::KnownEventIds(vec![id]),
        endpoints: endpoints
            .iter()
            .cloned()
            .map(cgka_traits::TransportEndpoint)
            .collect(),
        limits: NostrAcquisitionLimits {
            max_endpoints: 2,
            max_requested_event_ids: 1,
            max_received_items_per_endpoint: items,
            max_serialized_event_bytes_per_endpoint: bytes,
            max_duration: duration,
        },
    };
    timeout(
        duration + Duration::from_secs(2),
        sdk.acquire_history(request, NostrAcquisitionCancellation::new()),
    )
    .await
    .expect("bounded SDK call returns")
    .expect("valid exact request")
}

#[tokio::test]
async fn exact_no_data_has_an_absolute_text_budget_and_no_retained_input() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let (left_url, left) = counted_exact_relay(None, 0, true).await;
    let (right_url, right) = counted_exact_relay(None, 0, true).await;
    let result = acquire_exact(
        &[left_url, right_url],
        [0x42; 32],
        4,
        4096,
        Duration::from_secs(3),
    )
    .await;
    assert_eq!(result.endpoints.len(), 2);
    for endpoint in result.endpoints {
        assert_eq!(endpoint.end, NostrAcquisitionEnd::RequestPolicySatisfied);
        assert!(endpoint.events.is_empty());
        assert_eq!(endpoint.stats.received_items, 0);
        assert_eq!(endpoint.stats.retained_high_water_items, 0);
    }
    let left = left.snapshot();
    let right = right.snapshot();
    assert_eq!(left.sent_event_json + right.sent_event_json, 0);
    assert_eq!(left.sent_events + right.sent_events, 0);
    assert_eq!(left.received_requests + right.received_requests, 2);
    assert!(
        left.sent_text + right.sent_text + left.received_text + right.received_text <= 4096,
        "fixture ceiling for two exact requests, EOSEs and CLOSEs: left={left:?} right={right:?}"
    );
    println!(
        "resource no-data: client_text={} relay_text={} event_json=0",
        left.received_text + right.received_text,
        left.sent_text + right.sent_text
    );
}

#[tokio::test]
async fn one_missing_eose_returns_partial_input_and_incomplete_endpoint() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let (event, id) = signed_event(128);
    let event_bytes = event.to_string().len();
    let (left_url, left) = counted_exact_relay(Some(event), 1, true).await;
    let (right_url, right) = counted_exact_relay(None, 0, false).await;
    let result = acquire_exact(&[left_url, right_url], id, 4, 4096, Duration::from_secs(2)).await;
    assert_eq!(result.endpoints.len(), 2);
    assert_eq!(
        result.endpoints[0].end,
        NostrAcquisitionEnd::RequestPolicySatisfied
    );
    assert_eq!(result.endpoints[0].events.len(), 1);
    assert_eq!(
        result.endpoints[0].stats.retained_high_water_event_bytes,
        event_bytes
    );
    assert_eq!(result.endpoints[1].end, NostrAcquisitionEnd::Deadline);
    assert!(result.endpoints[1].events.is_empty());
    assert_eq!(left.snapshot().sent_events, 1);
    assert_eq!(right.snapshot().sent_events, 0);
    assert_eq!(right.snapshot().received_requests, 1);
    assert!(left.snapshot().sent_text + right.snapshot().sent_text < 4096);
    println!(
        "resource partial: client_text={} relay_text={} event_json={}",
        left.snapshot().received_text + right.snapshot().received_text,
        left.snapshot().sent_text + right.snapshot().sent_text,
        left.snapshot().sent_event_json
    );
}

#[tokio::test]
async fn duplicate_notifications_spend_item_budget_before_retention_deduplication() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let (event, id) = signed_event(128);
    let event_bytes = event.to_string().len();
    let (left_url, left) = counted_exact_relay(Some(event.clone()), 24, false).await;
    let (right_url, right) = counted_exact_relay(Some(event), 24, false).await;
    let result = acquire_exact(
        &[left_url, right_url],
        id,
        4,
        16 * 1024,
        Duration::from_secs(3),
    )
    .await;
    assert_eq!(result.endpoints.len(), 2);
    for endpoint in result.endpoints {
        assert_eq!(endpoint.end, NostrAcquisitionEnd::ItemLimitReached);
        assert_eq!(endpoint.events.len(), 1);
        assert_eq!(endpoint.stats.received_items, 5);
        assert_eq!(endpoint.stats.duplicates, 3);
        assert_eq!(endpoint.stats.retained_high_water_items, 1);
        assert_eq!(endpoint.stats.retained_high_water_event_bytes, event_bytes);
        assert_eq!(endpoint.stats.serialized_event_bytes, 5 * event_bytes);
    }
    let left = left.snapshot();
    let right = right.snapshot();
    assert_eq!(left.sent_events + right.sent_events, 48);
    assert_eq!(
        left.sent_event_json + right.sent_event_json,
        48 * event_bytes,
        "pre-dedup text includes both relay copies and events already queued after the SDK stopped"
    );
    println!(
        "resource duplicates: client_text={} relay_text={} relay_event_json={} sdk_received_items=10 sdk_retained_items=2",
        left.received_text + right.received_text,
        left.sent_text + right.sent_text,
        left.sent_event_json + right.sent_event_json,
    );
}

#[tokio::test]
async fn oversized_event_exhausts_byte_budget_without_retention() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let (event, id) = signed_event(4096);
    let event_bytes = event.to_string().len();
    let (left_url, left) = counted_exact_relay(Some(event.clone()), 1, true).await;
    let (right_url, right) = counted_exact_relay(Some(event), 1, true).await;
    let result = acquire_exact(&[left_url, right_url], id, 4, 1024, Duration::from_secs(3)).await;
    for endpoint in result.endpoints {
        assert_eq!(endpoint.end, NostrAcquisitionEnd::ByteLimitReached);
        assert!(endpoint.events.is_empty());
        assert_eq!(endpoint.stats.received_items, 1);
        assert_eq!(endpoint.stats.serialized_event_bytes, event_bytes);
        assert_eq!(endpoint.stats.retained_high_water_items, 0);
    }
    assert_eq!(
        left.snapshot().sent_event_json + right.snapshot().sent_event_json,
        2 * event_bytes
    );
    println!(
        "resource oversized: client_text={} relay_text={} relay_event_json={} sdk_retained_items=0",
        left.snapshot().received_text + right.snapshot().received_text,
        left.snapshot().sent_text + right.snapshot().sent_text,
        2 * event_bytes
    );
}

#[tokio::test]
async fn exhausted_execution_credits_preserve_demand_and_control_service() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let fixture = bounded_known_fixture().await;
    let storage = fixture.app.account_storage("bob").unwrap();
    let credits = bounded_recovery::hold_all_credits_for_test();
    assert_eq!(bounded_recovery::available_credits(), 0);
    let refusals = bounded_recovery::credit_refusals_for_test();
    advance_bounded_fixture_clock(&fixture).await;
    timeout(Duration::from_secs(8), async {
        loop {
            if bounded_recovery::credit_refusals_for_test() > refusals {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("known-event candidate passes route checks and reaches the exhausted credit gate");
    let commands = fixture
        .runtime
        .accounts()
        .worker_commands("bob")
        .await
        .unwrap();
    let (respond, response) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::QuarantinedGroups { respond })
        .unwrap();
    timeout(Duration::from_secs(8), response)
        .await
        .expect("committed snapshot control read remains serviceable")
        .unwrap()
        .unwrap();
    assert_eq!(fixture.relay.acquisition_calls.load(Ordering::SeqCst), 0);
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|d| d.ticket.id == fixture.demand_id)
    );
    drop(credits);
    fixture.runtime.shutdown().await;
    assert_eq!(
        bounded_recovery::available_credits(),
        bounded_recovery::MAX_CONCURRENT_JOBS
    );
}

#[tokio::test]
async fn partial_worker_result_admits_useful_input_and_releases_capacity() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let fixture = bounded_known_fixture().await;
    let storage = fixture.app.account_storage("bob").unwrap();
    *fixture.relay.acquisition_result.lock().unwrap() = Some(controlled_bounded_result(
        vec![fixture.historical.clone()],
        NostrAcquisitionEnd::RequestPolicySatisfied,
        Vec::new(),
        NostrAcquisitionEnd::Deadline,
    ));
    wake_bounded_fixture(&fixture).await;
    timeout(Duration::from_secs(10), async {
        loop {
            if storage
                .retained_recovery_event(
                    &fixture.route,
                    &fixture.event_id,
                    None,
                    fixture.historical.created_at,
                )
                .unwrap()
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("one useful event is retained despite the other endpoint's deadline");
    assert_eq!(fixture.relay.acquisition_calls.load(Ordering::SeqCst), 1);
    fixture.runtime.shutdown().await;
    assert_eq!(
        bounded_recovery::available_credits(),
        bounded_recovery::MAX_CONCURRENT_JOBS
    );
}
