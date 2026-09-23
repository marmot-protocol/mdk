//! MDK-owned projection of SDK transport evidence. The current production
//! NostrRelayClient seam has no acquisition method; this belongs in the
//! eventual adapter extension, with admission and retry owned above it.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use cgka_traits::TransportEndpoint;
use nostr_sdk::NotificationUpdate;
use nostr_sdk::prelude::*;
use tokio::time::timeout;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestEnd {
    ExitPolicySatisfied,
    ExitCount,
    ItemLimit,
    ByteLimit,
    Cancelled,
    TimedOut,
    Disconnected,
    ReceiveLoss,
    ReceiverClosed,
    AuthenticationFailed,
    Rejected,
    SetupFailed,
}

struct BatchEvidence {
    endpoint: TransportEndpoint,
    events: BTreeSet<Event>,
    end: RequestEnd,
    received_items: usize,
    received_event_bytes: usize,
    duplicates: usize,
    high_water_items: usize,
    high_water_event_bytes: usize,
}

impl BatchEvidence {
    fn from_sdk(endpoint: &RelayUrl, result: RelayAcquisition) -> Self {
        let end = match result.end {
            AcquisitionEnd::Completed => RequestEnd::ExitPolicySatisfied,
            AcquisitionEnd::ExitLimitReached => RequestEnd::ExitCount,
            AcquisitionEnd::ItemBudgetExceeded => RequestEnd::ItemLimit,
            AcquisitionEnd::ByteBudgetExceeded => RequestEnd::ByteLimit,
            AcquisitionEnd::Cancelled => RequestEnd::Cancelled,
            AcquisitionEnd::TimedOut => RequestEnd::TimedOut,
            AcquisitionEnd::Disconnected => RequestEnd::Disconnected,
            AcquisitionEnd::ReceiveLoss(_) => RequestEnd::ReceiveLoss,
            AcquisitionEnd::ReceiverClosed => RequestEnd::ReceiverClosed,
            AcquisitionEnd::AuthenticationFailed => RequestEnd::AuthenticationFailed,
            AcquisitionEnd::Rejected(_) => RequestEnd::Rejected,
            AcquisitionEnd::Failed(_) => RequestEnd::SetupFailed,
        };
        Self {
            endpoint: TransportEndpoint(endpoint.to_string()),
            events: result.events,
            end,
            received_items: result.received_items,
            received_event_bytes: result.received_event_bytes,
            duplicates: result.duplicates,
            high_water_items: result.high_water_items,
            high_water_event_bytes: result.high_water_event_bytes,
        }
    }
}

fn limits(max_items: usize, max_event_bytes: usize) -> AcquisitionLimits {
    AcquisitionLimits::new(2, max_items, max_event_bytes, Duration::from_secs(3))
}

async fn connected(relay: &LocalRelay) -> (Client, RelayUrl) {
    let url = relay.url().await;
    let client = Client::default();
    client
        .add_relay(&url)
        .notification_channel_size(256)
        .await
        .unwrap();
    client
        .try_connect_relay(&url, Duration::from_secs(3))
        .await
        .unwrap();
    (client, url)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_batches_project_partial_per_relay_results_and_known_inventory_traffic() {
    let relay = LocalRelay::new();
    relay.run().await.unwrap();
    let keys = Keys::generate();
    let mut inventory = Vec::new();
    for index in 0..12 {
        let event = EventBuilder::new(Kind::TextNote, format!("inventory-{index}"))
            .finalize(&keys)
            .unwrap();
        relay.add_event(event.clone()).await.unwrap();
        inventory.push(event);
    }
    let (client, url) = connected(&relay).await;
    let connection = client.relay(&url).await.unwrap().unwrap();
    let before_received = connection.stats().bytes_received();
    let before_sent = connection.stats().bytes_sent();
    let unavailable = RelayUrl::parse("ws://127.0.0.1:1").unwrap();
    let report = client
        .acquire_events(
            ReqTarget::manual(vec![
                (
                    url.clone(),
                    vec![Filter::new().kind(Kind::TextNote).limit(12)],
                ),
                (
                    unavailable.clone(),
                    vec![Filter::new().kind(Kind::TextNote)],
                ),
            ]),
            limits(3, 64 * 1024),
        )
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    let mut per_relay = report.relays;
    let mut healthy = BatchEvidence::from_sdk(&url, per_relay.remove(&url).unwrap());
    assert_eq!(healthy.endpoint.as_str(), url.as_str());
    assert_eq!(healthy.end, RequestEnd::ItemLimit);
    assert_eq!(healthy.events.len(), 3);
    assert_eq!(healthy.received_items, 4);
    assert_eq!(healthy.high_water_items, 3);
    assert!(healthy.high_water_event_bytes <= 64 * 1024);
    // The other selected relay is absent from the pool, so its typed result
    // remains independent of the healthy relay's partial data.
    let missing = BatchEvidence::from_sdk(&unavailable, per_relay.remove(&unavailable).unwrap());
    assert_eq!(missing.end, RequestEnd::SetupFailed);
    assert!(missing.events.is_empty());
    let mut received_items = healthy.received_items;
    let mut serialized_event_bytes = healthy.received_event_bytes;
    let mut duplicates = healthy.duplicates;
    let mut requests = 1;
    for pair in inventory.chunks(2) {
        let ids = pair.iter().map(|event| event.id).collect::<Vec<_>>();
        let report = client
            .acquire_events(
                ReqTarget::single(&url, [Filter::new().ids(ids)]),
                limits(3, 64 * 1024),
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        let outcome = BatchEvidence::from_sdk(&url, report.relays.into_values().next().unwrap());
        assert_eq!(outcome.end, RequestEnd::ExitPolicySatisfied);
        received_items += outcome.received_items;
        serialized_event_bytes += outcome.received_event_bytes;
        duplicates += outcome.duplicates;
        healthy.events.extend(outcome.events);
        requests += 1;
    }
    assert_eq!(healthy.events.len(), 12);
    assert_eq!(requests, 7);
    let received_text_bytes = connection.stats().bytes_received() - before_received;
    let sent_text_bytes = connection.stats().bytes_sent() - before_sent;
    assert!(received_text_bytes >= serialized_event_bytes);
    eprintln!(
        "MDK known inventory: requests={requests} received_items={received_items} duplicate_items={duplicates} serialized_event_bytes={serialized_event_bytes} connection_text_received_bytes={received_text_bytes} connection_text_sent_bytes={sent_text_bytes} (not wire bytes)"
    );
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_event_byte_limit_and_cancellation_leave_live_interest_operating() {
    let relay = LocalRelay::new();
    relay.run().await.unwrap();
    let keys = Keys::generate();
    let large = EventBuilder::new(Kind::TextNote, "x".repeat(16 * 1024))
        .finalize(&keys)
        .unwrap();
    relay.add_event(large.clone()).await.unwrap();
    let (client, url) = connected(&relay).await;
    let report = client
        .acquire_events(
            ReqTarget::single(&url, [Filter::new().kind(Kind::TextNote)]),
            limits(10, 4 * 1024),
        )
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    let outcome = BatchEvidence::from_sdk(&url, report.relays.into_values().next().unwrap());
    assert_eq!(outcome.end, RequestEnd::ByteLimit);
    assert_eq!(outcome.received_items, 1);
    assert!(outcome.received_event_bytes > 4 * 1024);
    assert!(outcome.events.is_empty());
    assert_eq!(outcome.high_water_event_bytes, 0);

    let connection = client.relay(&url).await.unwrap().unwrap();
    let live_id = connection
        .subscribe(Filter::new().kind(Kind::Metadata))
        .await
        .unwrap();
    let mut notifications = connection.notifications_with_gaps();
    let handle = client
        .acquire_events(
            ReqTarget::single(&url, [Filter::new().kind(Kind::TextNote)]),
            limits(10, 64 * 1024)
                .policy(ReqExitPolicy::WaitDurationAfterEOSE(Duration::from_secs(2))),
        )
        .await
        .unwrap();
    let started = Instant::now();
    handle.cancel();
    let report = timeout(Duration::from_secs(1), handle.finish())
        .await
        .unwrap()
        .unwrap();
    let cancel_latency = started.elapsed();
    let outcome = BatchEvidence::from_sdk(&url, report.relays.into_values().next().unwrap());
    assert_eq!(outcome.end, RequestEnd::Cancelled);
    // Cancellation can win before the first EVENT is retained. The report
    // must describe the partial work that actually happened, including none.
    assert!(outcome.events.len() <= 1);
    assert!(outcome.events.iter().all(|event| event.id == large.id));
    let live_event = EventBuilder::new(Kind::Metadata, "live after history cancel")
        .finalize(&keys)
        .unwrap();
    relay.add_event(live_event.clone()).await.unwrap();
    timeout(Duration::from_secs(1), async {
        loop {
            if let NotificationUpdate::Notification(RelayNotification::Event {
                subscription_id,
                event,
            }) = notifications
                .next()
                .await
                .expect("live notification stream closed after cancellation")
                && subscription_id == live_id
                && event.id == live_event.id
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    eprintln!(
        "MDK cancel: partial_items={} retained_serialized_event_bytes={} cancel_latency={cancel_latency:?} live_delivery=true",
        outcome.events.len(),
        outcome.high_water_event_bytes
    );
    client.shutdown().await;
}
