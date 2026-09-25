//! Endpoint capability changes during the SDK's bounded comparison.
//! This observes complete WebSocket text payloads before SDK duplicate filtering.

use super::*;
use futures::{SinkExt, StreamExt};
use nostr_relay_builder::prelude::{MemoryDatabase, MemoryDatabaseOptions, NostrDatabase};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{Client as SdkClient, EventBuilder, FinalizeEvent, Keys, Kind, Tag};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};
use transport_nostr_adapter::{
    NostrReconciliationProgress, NostrSdkRelayClient, NostrSubscription, SubscriptionAttempt,
};

#[derive(Default)]
struct TextCounts {
    client_text: AtomicUsize,
    relay_text: AtomicUsize,
    neg_opens: AtomicUsize,
    requests: AtomicUsize,
    event_json: AtomicUsize,
}

struct SwitchingRelay {
    url: String,
    reject_negentropy: Arc<AtomicBool>,
    counts: Arc<TextCounts>,
}

async fn switching_relay(backend: String) -> SwitchingRelay {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let reject_negentropy = Arc::new(AtomicBool::new(true));
    let counts = Arc::new(TextCounts::default());
    let reject = reject_negentropy.clone();
    let tally = counts.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let reject = reject.clone();
            let tally = tally.clone();
            let backend = backend.clone();
            tokio::spawn(async move {
                let Ok(client) = accept_async(stream).await else {
                    return;
                };
                let Ok((upstream, _)) = connect_async(&backend).await else {
                    return;
                };
                let (mut client_write, mut client_read) = client.split();
                let (mut upstream_write, mut upstream_read) = upstream.split();
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
                let write = tokio::spawn(async move {
                    while let Some(message) = rx.recv().await {
                        if client_write.send(message).await.is_err() {
                            break;
                        }
                    }
                });
                let to_upstream = async {
                    while let Some(Ok(message)) = client_read.next().await {
                        if let Message::Text(ref text) = message {
                            tally.client_text.fetch_add(text.len(), Ordering::SeqCst);
                            if text.starts_with("[\"REQ\"") {
                                tally.requests.fetch_add(1, Ordering::SeqCst);
                            }
                            if text.starts_with("[\"NEG-OPEN\"") {
                                tally.neg_opens.fetch_add(1, Ordering::SeqCst);
                                if reject.load(Ordering::SeqCst) {
                                    let notice = json!(["NOTICE", "bad msg: unknown cmd NEG-OPEN"]);
                                    let text = notice.to_string();
                                    tally.relay_text.fetch_add(text.len(), Ordering::SeqCst);
                                    let _ = tx.send(Message::Text(text.into()));
                                    continue;
                                }
                            }
                        }
                        if upstream_write.send(message).await.is_err() {
                            break;
                        }
                    }
                };
                let to_client = async {
                    while let Some(Ok(message)) = upstream_read.next().await {
                        if let Message::Text(ref text) = message {
                            tally.relay_text.fetch_add(text.len(), Ordering::SeqCst);
                            if let Ok(frame) = serde_json::from_str::<Vec<Value>>(text)
                                && frame.first().and_then(Value::as_str) == Some("EVENT")
                                && let Some(event) = frame.get(2)
                            {
                                tally
                                    .event_json
                                    .fetch_add(event.to_string().len(), Ordering::SeqCst);
                            }
                        }
                        if tx.send(message).is_err() {
                            break;
                        }
                    }
                };
                tokio::select! { _ = to_upstream => {}, _ = to_client => {} }
                write.abort();
            });
        }
    });
    SwitchingRelay {
        url,
        reject_negentropy,
        counts,
    }
}

#[derive(Default)]
struct Cursor(std::sync::Mutex<Option<[u8; 32]>>);

impl NostrReconciliationProgress for Cursor {
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
async fn empty_endpoint_comparison_keeps_public_no_op_result() {
    let sdk = NostrSdkRelayClient::new(SdkClient::builder().build());
    let subscription = NostrSubscription::Group {
        account_id: cgka_traits::MemberId::new(vec![0xa1; 32]),
        group_id: GroupId::new(vec![0xb2; 16]),
        transport_group_id: vec![0xc3; 32],
        endpoints: Vec::new(),
        since: None,
        attempt: SubscriptionAttempt::INITIAL,
    };
    let (summary, events) = sdk
        .reconcile_subscription(subscription, &[], 0, u64::MAX, &Cursor::default())
        .await
        .expect("empty endpoint set remains a no-op");
    assert_eq!(summary, Default::default());
    assert!(events.is_empty());
}

#[tokio::test]
async fn unsupported_endpoint_is_reprobed_after_connection_generation_changes() {
    let _guard = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let left_database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(8),
    });
    let left_backend = LocalRelay::new(RelayBuilder::default().database(left_database.clone()));
    let right_backend = LocalRelay::new(RelayBuilder::default());
    left_backend.run().await.unwrap();
    right_backend.run().await.unwrap();
    let route = [0xc3; 32];
    let event = EventBuilder::new(Kind::MlsGroupMessage, "missing retained body")
        .tags([Tag::custom("h", [hex::encode(route)])])
        .finalize(&Keys::generate())
        .unwrap();
    left_database
        .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
        .await
        .unwrap();
    let left = switching_relay(left_backend.url().await.to_string()).await;
    let right = switching_relay(right_backend.url().await.to_string()).await;
    let sdk = NostrSdkRelayClient::new(SdkClient::builder().build());
    for url in [&left.url, &right.url] {
        sdk.client().add_relay(url.as_str()).await.unwrap();
    }
    sdk.client().connect().await;
    let subscription = NostrSubscription::Group {
        account_id: cgka_traits::MemberId::new(vec![0xa1; 32]),
        group_id: GroupId::new(vec![0xb2; 16]),
        transport_group_id: route.to_vec(),
        endpoints: vec![
            cgka_traits::TransportEndpoint(left.url.clone()),
            cgka_traits::TransportEndpoint(right.url.clone()),
        ],
        since: None,
        attempt: SubscriptionAttempt::INITIAL,
    };
    let progress = Cursor::default();
    for _ in 0..2 {
        let (summary, events) = sdk
            .reconcile_subscription(subscription.clone(), &[], 0, u64::MAX, &progress)
            .await
            .unwrap();
        assert_eq!(summary.relays_succeeded, 0);
        assert_eq!(summary.relays_failed, 2);
        assert!(events.is_empty());
    }
    assert_eq!(left.counts.neg_opens.load(Ordering::SeqCst), 2);
    assert_eq!(right.counts.neg_opens.load(Ordering::SeqCst), 2);
    assert_eq!(left.counts.event_json.load(Ordering::SeqCst), 0);
    assert_eq!(right.counts.event_json.load(Ordering::SeqCst), 0);
    assert_eq!(left.counts.requests.load(Ordering::SeqCst), 0);
    assert_eq!(right.counts.requests.load(Ordering::SeqCst), 0);
    let empty_text = [&left, &right]
        .iter()
        .map(|relay| {
            relay.counts.client_text.load(Ordering::SeqCst)
                + relay.counts.relay_text.load(Ordering::SeqCst)
        })
        .sum::<usize>();
    assert!(
        empty_text <= 16 * 1024,
        "two zero-new-event comparisons used {empty_text} WebSocket text bytes"
    );

    left.reject_negentropy.store(false, Ordering::SeqCst);
    let relay = sdk
        .client()
        .relay(left.url.as_str())
        .await
        .unwrap()
        .unwrap();
    let before = relay.stats().success();
    relay.disconnect();
    relay.connect();
    tokio::time::timeout(Duration::from_secs(5), async {
        while relay.stats().success() <= before {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("same URL establishes a new connection");

    let (summary, events) = sdk
        .reconcile_subscription(subscription, &[], 0, u64::MAX, &progress)
        .await
        .unwrap();
    assert_eq!(summary.relays_succeeded, 1);
    assert_eq!(
        summary.relays_failed, 1,
        "the other unsupported endpoint remains incomplete"
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.id, event.id.to_hex());
    assert_eq!(left.counts.neg_opens.load(Ordering::SeqCst), 3);
    assert_eq!(right.counts.neg_opens.load(Ordering::SeqCst), 3);
    assert!(left.counts.requests.load(Ordering::SeqCst) <= 1);
    assert!(right.counts.requests.load(Ordering::SeqCst) <= 1);
    assert!(left.counts.event_json.load(Ordering::SeqCst) > 0);
    eprintln!(
        "selective endpoint fixture: empty_text={empty_text}, client_text={}, relay_text={}, event_json={}, neg_opens={}",
        left.counts.client_text.load(Ordering::SeqCst)
            + right.counts.client_text.load(Ordering::SeqCst),
        left.counts.relay_text.load(Ordering::SeqCst)
            + right.counts.relay_text.load(Ordering::SeqCst),
        left.counts.event_json.load(Ordering::SeqCst)
            + right.counts.event_json.load(Ordering::SeqCst),
        left.counts.neg_opens.load(Ordering::SeqCst)
            + right.counts.neg_opens.load(Ordering::SeqCst)
    );
    sdk.client().shutdown().await;
    left_backend.shutdown();
    right_backend.shutdown();
}
