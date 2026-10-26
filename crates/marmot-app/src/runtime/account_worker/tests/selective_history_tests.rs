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

const RECONCILIATION_CALLER_ALLOWANCE: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Default)]
struct TextCounts {
    client_text: AtomicUsize,
    relay_text: AtomicUsize,
    neg_opens: AtomicUsize,
    requests: AtomicUsize,
    event_json: AtomicUsize,
    window_requests: AtomicUsize,
    group_events: std::sync::Mutex<Vec<nostr_sdk::prelude::Event>>,
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
                                if let Ok(frame) = serde_json::from_str::<Vec<Value>>(text)
                                    && frame
                                        .get(2)
                                        .and_then(|filter| filter.get("limit"))
                                        .and_then(Value::as_u64)
                                        == Some(256)
                                    && frame
                                        .get(2)
                                        .and_then(|filter| filter.get("kinds"))
                                        .and_then(Value::as_array)
                                        .is_some_and(|kinds| {
                                            kinds.iter().any(|kind| {
                                                kind.as_u64()
                                                    == Some(u64::from(
                                                        Kind::MlsGroupMessage.as_u16(),
                                                    ))
                                            })
                                        })
                                {
                                    tally.window_requests.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                            if text.starts_with("[\"EVENT\"")
                                && let Ok(frame) = serde_json::from_str::<Vec<Value>>(text)
                                && let Some(event) = frame.get(1)
                                && event.get("kind").and_then(Value::as_u64)
                                    == Some(u64::from(Kind::MlsGroupMessage.as_u16()))
                            {
                                tally
                                    .group_events
                                    .lock()
                                    .unwrap()
                                    .push(serde_json::from_value(event.clone()).unwrap());
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_commit_700_recovers() {
    use marmot_account::AccountHome;
    use nostr_relay_builder::prelude::{EventId as RelayEventId, Filter as RelayFilter};
    use nostr_sdk::prelude::Timestamp;

    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(8_192),
    });
    let backend = LocalRelay::new(RelayBuilder::default().database(database.clone()));
    backend.run().await.unwrap();
    let proxy = switching_relay(backend.url().await.to_string()).await;
    let url = proxy.url.clone();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let config = crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true);
    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config);
    crate::tests::remember_test_member_inbox(&app, &alice.account_id_hex, &url);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&alice.label).await.unwrap();
    let group = runtime
        .create_group_with_options(
            &bob.label,
            "paged recovery",
            std::slice::from_ref(&alice.account_id_hex),
            crate::AppCreateGroupOptions {
                relays: Some(vec![url.clone()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            runtime.catch_up_accounts().await.unwrap();
            if app
                .group(&alice.label, &hex::encode(&group))
                .unwrap()
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Alice joins the real MLS group");
    let old_text = "x".repeat(4_096);
    runtime
        .send_message(&bob.label, &group, old_text.clone().into_bytes())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            runtime.catch_up_accounts().await.unwrap();
            if app
                .messages(&alice.label)
                .unwrap()
                .iter()
                .any(|message| message.plaintext == old_text)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Alice durably receives the old MLS payload");
    let old = proxy
        .counts
        .group_events
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    let route_hex = app
        .group(&alice.label, &hex::encode(&group))
        .unwrap()
        .unwrap()
        .nostr_routing
        .nostr_group_id_hex;
    let mut route = [0; 32];
    hex::decode_to_slice(&route_hex, &mut route).unwrap();
    runtime
        .accounts()
        .deactivate_account(&alice.label)
        .await
        .unwrap();
    let start = proxy.counts.group_events.lock().unwrap().len();
    runtime
        .update_group_profile(&bob.label, &group, Some("late commit".into()), None)
        .await
        .unwrap();
    let expected = "new message after paged recovery";
    runtime
        .send_message(&bob.label, &group, expected.as_bytes().to_vec())
        .await
        .unwrap();
    let epoch = runtime
        .group_mls_state(&bob.label, &group)
        .await
        .unwrap()
        .epoch;
    let published = proxy.counts.group_events.lock().unwrap().split_off(start);

    // Retained outer copies carry an already-durable MLS payload. Their raw
    // bytes force a cut without adding unknown messages to the engine.
    let base = Timestamp::now().as_secs() - 1_600;
    let outer = Keys::generate();
    let protocol_store = app.account_storage(&alice.label).unwrap();
    let storage = protocol_store.app_storage();
    let mut retained_bytes = 0;
    for index in 0..1_024 {
        let retained = EventBuilder::new(old.kind, old.content.clone())
            .tags(old.tags.iter().cloned())
            .custom_created_at(Timestamp::from_secs(base - 20_000 + index))
            .finalize(&outer)
            .unwrap();
        let json = retained.as_json();
        retained_bytes += json.as_str().len();
        database
            .save_event(&serde_json::from_str(json.as_str()).unwrap())
            .await
            .unwrap();
        storage
            .record_reconciliation_items(std::iter::once((
                &storage_sqlite::TransportReconciliationRoute::Group(route),
                &storage_sqlite::TransportReconciliationItem {
                    event_id: retained.id.to_bytes(),
                    created_at: retained.created_at.as_secs(),
                },
            )))
            .unwrap();
    }
    assert!(
        retained_bytes > 4 * 1024 * 1024,
        "held history exceeds a production scan byte budget"
    );
    // Empty group AAD allows new outer timestamps around the genuine commit.
    // The commit is below the live floor and 700 newer wrappers, with no ties.
    let commit = &published[0];
    let late = EventBuilder::new(commit.kind, commit.content.clone())
        .tags(commit.tags.iter().cloned())
        .custom_created_at(Timestamp::from_secs(base))
        .finalize(&outer)
        .unwrap();
    database
        .save_event(&serde_json::from_str(late.as_json().as_str()).unwrap())
        .await
        .unwrap();
    database
        .delete(RelayFilter::new().id(RelayEventId::from_byte_array(commit.id.to_bytes())))
        .await
        .unwrap();
    let future = published.last().unwrap();
    for index in 0..700 {
        let event = EventBuilder::new(future.kind, future.content.clone())
            .tags(future.tags.iter().cloned())
            .custom_created_at(Timestamp::from_secs(base + 900 + index))
            .finalize(&outer)
            .unwrap();
        database
            .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
            .await
            .unwrap();
    }
    runtime
        .accounts()
        .sign_in_account(&alice.label)
        .await
        .unwrap();
    runtime.reconcile_accounts().await.unwrap();
    // Held-only cuts retain production backoff between scan attempts.
    let recovered = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            runtime.catch_up_accounts().await.unwrap();
            if app
                .messages(&alice.label)
                .unwrap()
                .iter()
                .any(|message| message.plaintext == expected)
                && runtime
                    .group_mls_state(&alice.label, &group)
                    .await
                    .unwrap()
                    .epoch
                    >= epoch
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "late commit recovery failed: local_epoch={}, target_epoch={epoch}, window_requests={}",
        runtime
            .group_mls_state(&alice.label, &group)
            .await
            .unwrap()
            .epoch,
        proxy.counts.window_requests.load(Ordering::SeqCst)
    );
    assert!(
        proxy.counts.window_requests.load(Ordering::SeqCst) > 1,
        "recovery must pass the newest page after NEG refusal"
    );
    runtime.shutdown_and_close().await.unwrap();
    backend.shutdown();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::disallowed_methods)]
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
        .reconcile_subscription(
            subscription,
            &[],
            0,
            u64::MAX,
            &Cursor::default(),
            tokio::time::Instant::now() + RECONCILIATION_CALLER_ALLOWANCE,
        )
        .await
        .expect("empty endpoint set remains a no-op");
    assert_eq!(summary, Default::default());
    assert!(events.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::disallowed_methods)]
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
            .reconcile_subscription(
                subscription.clone(),
                &[],
                0,
                u64::MAX,
                &progress,
                tokio::time::Instant::now() + RECONCILIATION_CALLER_ALLOWANCE,
            )
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
        .reconcile_subscription(
            subscription,
            &[],
            0,
            u64::MAX,
            &progress,
            tokio::time::Instant::now() + RECONCILIATION_CALLER_ALLOWANCE,
        )
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
