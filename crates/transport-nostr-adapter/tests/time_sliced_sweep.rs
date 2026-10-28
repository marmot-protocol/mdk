#![cfg(feature = "sdk")]
// Test fixtures dial local relays directly.
#![allow(clippy::disallowed_methods)]

//! The time-sliced sweep over the wire: `SdkSweepRelay` against a local relay
//! behind the strfry-limits proxy (`support/limit_relay.rs`, 500 clamp, no
//! NIP-67 hints unless a test turns on wok's). Synthetic group events only; no
//! MLS.

#[path = "support/limit_relay.rs"]
mod limit_relay;

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use limit_relay::{LimitConfig, LimitRelay};
use nostr_relay_builder::prelude::{
    MemoryDatabase, MemoryDatabaseOptions, NostrDatabase, RateLimit,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{
    Client, Event, EventBuilder, FinalizeEvent, Keys, Kind, RelayUrl, Tag, Timestamp,
};
use tokio_util::sync::CancellationToken;
use transport_nostr_adapter::NostrSdkRelayClient;
use transport_nostr_adapter::sweep::{
    CoveredSlice, RelayCaps, SdkSweepRelay, SliceProof, SweepCursor, SweepCursorStore, SweepEnd,
    SweepPolicy, SweepRange, SweepRequest, SweepRoute, SweepSink, SweepSinkError, SweepStoreError,
    run_sweep,
};

const GROUP: [u8; 32] = [3; 32];
const OTHER_GROUP: [u8; 32] = [4; 32];
const T0: u64 = 1_700_000_000;
const DAY: u64 = 24 * 60 * 60;
/// strfry's NIP-11 document, as deployed.
const STRFRY_NIP11: &str = r#"{"name":"strfry","software":"git+https://github.com/hoytech/strfry.git",
    "supported_nips":[1,2,4,9,11,22,28,40,70,77],
    "limitation":{"max_message_length":131072,"max_subscriptions":200,"max_limit":500}}"#;

struct Fixture {
    _upstream: LocalRelay,
    database: MemoryDatabase,
    limit: LimitRelay,
    sdk: NostrSdkRelayClient,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_limits(LimitConfig::default()).await
    }

    async fn with_limits(config: LimitConfig) -> Self {
        Self::with_client(config, NostrSdkRelayClient::from_builder(Client::builder())).await
    }

    async fn with_client(config: LimitConfig, sdk: NostrSdkRelayClient) -> Self {
        let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
            events: true,
            max_events: Some(16_384),
        });
        let upstream = LocalRelay::new(
            RelayBuilder::default()
                .database(database.clone())
                .rate_limit(RateLimit {
                    notes_per_minute: 16_384,
                    ..RateLimit::default()
                })
                .default_filter_limit(100_000),
        );
        upstream.run().await.unwrap();
        let limit = LimitRelay::start(upstream.url().await.to_string(), config).await;
        sdk.client().add_relay(limit.url()).await.unwrap();
        sdk.client().connect().await;
        Self {
            _upstream: upstream,
            database,
            limit,
            sdk,
        }
    }

    async fn store(&self, events: &[Event]) {
        for event in events {
            self.database
                .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
                .await
                .unwrap();
        }
    }

    fn relay(&self) -> SdkSweepRelay {
        self.relay_with_caps(STRFRY_NIP11)
    }

    fn relay_with_caps(&self, nip11: &str) -> SdkSweepRelay {
        SdkSweepRelay::new(
            &self.sdk,
            RelayUrl::parse(&self.limit.url()).unwrap(),
            RelayCaps::from_nip11_json(nip11).unwrap(),
            Duration::from_secs(10),
        )
    }
}

fn group_event(keys: &Keys, group: [u8; 32], created_at: u64, n: usize) -> Event {
    EventBuilder::new(Kind::MlsGroupMessage, format!("payload-{n}"))
        .tags([Tag::custom("h", [hex::encode(group)])])
        .custom_created_at(Timestamp::from_secs(created_at))
        .finalize(keys)
        .unwrap()
}

#[derive(Default)]
struct MemoryStore(std::sync::Mutex<Option<SweepCursor>>);

#[async_trait]
impl SweepCursorStore for MemoryStore {
    async fn load(&self) -> Result<Option<SweepCursor>, SweepStoreError> {
        Ok(*self.0.lock().unwrap())
    }

    async fn save(&self, cursor: SweepCursor) -> Result<(), SweepStoreError> {
        *self.0.lock().unwrap() = Some(cursor);
        Ok(())
    }
}

#[derive(Default)]
struct Sink {
    slices: Vec<CoveredSlice>,
    events: Vec<Event>,
    /// Cancel once this many slices were admitted.
    cancel_after: Option<(usize, CancellationToken)>,
}

#[async_trait]
impl SweepSink for Sink {
    async fn admit(
        &mut self,
        slice: CoveredSlice,
        events: Vec<Event>,
    ) -> Result<(), SweepSinkError> {
        self.slices.push(slice);
        self.events.extend(events);
        if let Some((after, token)) = &self.cancel_after
            && self.slices.len() >= *after
        {
            token.cancel();
        }
        Ok(())
    }
}

fn request(range: SweepRange) -> SweepRequest {
    SweepRequest {
        route: SweepRoute::Group {
            nostr_group_id: GROUP,
        },
        range,
        deadline: None,
        policy: SweepPolicy {
            initial_delta: DAY,
            min_request_interval: Duration::from_millis(5),
            rate_limit_backoff: Duration::from_millis(50),
            ..SweepPolicy::default()
        },
    }
}

/// 1,500 events over a day, a 700-event second, and another group's noise.
fn backlog() -> (Vec<Event>, HashSet<nostr_sdk::prelude::EventId>, u64) {
    let keys = Keys::generate();
    let burst = T0 + 12 * 3_600 + 7;
    let mut events = (0..1_500)
        .map(|n| group_event(&keys, GROUP, T0 + (n as u64) * DAY / 1_500, n))
        .collect::<Vec<_>>();
    events.extend((0..700).map(|n| group_event(&keys, GROUP, burst, 2_000 + n)));
    let wanted = events.iter().map(|event| event.id).collect();
    events.extend((0..200).map(|n| group_event(&keys, OTHER_GROUP, T0 + (n as u64) * 400, n)));
    (events, wanted, burst)
}

fn range() -> SweepRange {
    SweepRange {
        since: T0,
        until: T0 + DAY - 1,
    }
}

fn assert_once_in_order(sink: &Sink, wanted: &HashSet<nostr_sdk::prelude::EventId>) {
    let ids = sink.events.iter().map(|event| event.id).collect::<Vec<_>>();
    assert_eq!(ids.len(), wanted.len(), "every event exactly once");
    assert_eq!(&ids.iter().copied().collect::<HashSet<_>>(), wanted);
    assert!(
        sink.events
            .windows(2)
            .all(|pair| pair[0].created_at <= pair[1].created_at)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sweep_pages_a_strfry_relay_and_resolves_a_saturated_second() {
    let fixture = Fixture::new().await;
    let (events, wanted, burst) = backlog();
    fixture.store(&events).await;
    let relay = fixture.relay();
    let store = MemoryStore::default();
    let mut sink = Sink::default();
    let report = run_sweep(
        request(range()),
        &relay,
        &mut sink,
        &store,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished, "{report:?}");
    assert_eq!(report.stats.saturated_seconds, 1);
    assert!(report.stats.halvings > 0);
    assert!(report.covered.iter().any(|slice| slice.since == burst
        && slice.until == burst
        && slice.proof == SliceProof::Negentropy
        && slice.events == 700));
    assert_once_in_order(&sink, &wanted);
    // The proxy clamped every slice REQ to strfry's 500.
    assert_eq!(fixture.limit.stats().max_req_limit_seen, 500);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sweep_resumes_over_the_wire_without_refetching() {
    let fixture = Fixture::new().await;
    let (events, wanted, _) = backlog();
    fixture.store(&events).await;
    let relay = fixture.relay();
    let store = MemoryStore::default();
    let mut sink = Sink::default();
    let mut attempts = 0;
    loop {
        attempts += 1;
        assert!(attempts < 50);
        let cancel = CancellationToken::new();
        sink.cancel_after = Some((sink.slices.len() + 2, cancel.clone()));
        let report = run_sweep(request(range()), &relay, &mut sink, &store, &cancel).await;
        if report.end == SweepEnd::Finished {
            break;
        }
        assert_eq!(report.end, SweepEnd::Cancelled);
    }
    assert!(attempts > 2);
    let mut next = T0;
    for slice in &sink.slices {
        assert_eq!(slice.since, next, "slices must not overlap or skip");
        next = slice.until + 1;
    }
    assert_once_in_order(&sink, &wanted);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limited_closed_is_waited_out() {
    let fixture = Fixture::new().await;
    let (events, wanted, _) = backlog();
    fixture.store(&events).await;
    fixture.limit.rate_limit_next_reqs(3);
    let relay = fixture.relay();
    let mut sink = Sink::default();
    let report = run_sweep(
        request(range()),
        &relay,
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished, "{report:?}");
    assert_eq!(report.stats.rate_limited_waits, 3);
    assert_once_in_order(&sink, &wanted);
}

/// wok's marmot preset: cap 5,000, default page 500. A saturated second over
/// the cap goes through NIP-77 and exact-id REQs, which must name their limit
/// or the default page shorts them; and a small byte budget splits id chunks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturated_second_over_a_default_page_and_byte_budget() {
    let fixture = Fixture::with_limits(LimitConfig {
        req_limit_clamp: Some(5_000),
        req_default_limit: Some(500),
        ..LimitConfig::default()
    })
    .await;
    let keys = Keys::generate();
    let burst = T0 + 3_600;
    let mut events = (0..300)
        .map(|n| group_event(&keys, GROUP, T0 + 1 + (n as u64) * 200, n))
        .collect::<Vec<_>>();
    events.extend((0..5_200).map(|n| group_event(&keys, GROUP, burst, 1_000 + n)));
    let wanted = events.iter().map(|event| event.id).collect();
    fixture.store(&events).await;
    let relay = SdkSweepRelay::new(
        &fixture.sdk,
        RelayUrl::parse(&fixture.limit.url()).unwrap(),
        RelayCaps::from_nip11_json(
            r#"{"supported_nips":[1,11,42,67,77],"limitation":{"max_limit":5000,"default_limit":500}}"#,
        )
        .unwrap(),
        Duration::from_secs(20),
    )
    // About 1,000 of these events: a 5,000-id chunk has to split.
    .with_reply_max_bytes(400 * 1_000);
    let mut sink = Sink::default();
    let report = run_sweep(
        request(range()),
        &relay,
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished, "{report:?}");
    assert_eq!(report.stats.saturated_seconds, 1);
    assert!(report.covered.iter().any(|slice| slice.since == burst
        && slice.proof == SliceProof::Negentropy
        && slice.events == 5_200));
    assert_once_in_order(&sink, &wanted);
}

/// A wok-like NIP-11 document with a 50-event cap.
const HINTED_NIP11: &str =
    r#"{"supported_nips":[1,11,42,67,77],"limitation":{"max_limit":50,"default_limit":50}}"#;

fn hinted_limits(eose_hints: bool) -> LimitConfig {
    LimitConfig {
        req_limit_clamp: Some(50),
        eose_hints,
        ..LimitConfig::default()
    }
}

/// Exactly the cap, spread over the day.
fn one_full_page() -> (Vec<Event>, HashSet<nostr_sdk::prelude::EventId>) {
    let keys = Keys::generate();
    let events = (0..50)
        .map(|n| group_event(&keys, GROUP, T0 + (n as u64) * 1_000, n))
        .collect::<Vec<_>>();
    let wanted = events.iter().map(|event| event.id).collect();
    (events, wanted)
}

/// A reply holding exactly the cap may hide more, so it is split and proven by
/// counts. wok's `finish` changes nothing: the sweep runs the same with it,
/// without it, and through a client built without the tap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finish_hint_changes_nothing() {
    let mut runs = Vec::new();
    for (relay_hints, tapped) in [(true, true), (false, true), (true, false)] {
        let sdk = if tapped {
            NostrSdkRelayClient::from_builder(Client::builder())
        } else {
            NostrSdkRelayClient::new(Client::builder().build())
        };
        let fixture = Fixture::with_client(hinted_limits(relay_hints), sdk).await;
        let (events, wanted) = one_full_page();
        fixture.store(&events).await;
        let mut sink = Sink::default();
        let report = run_sweep(
            request(range()),
            &fixture.relay_with_caps(HINTED_NIP11),
            &mut sink,
            &MemoryStore::default(),
            &CancellationToken::new(),
        )
        .await;
        let case = format!("relay hints {relay_hints}, tapped {tapped}");
        assert_eq!(report.end, SweepEnd::Finished, "{case}: {report:?}");
        assert_once_in_order(&sink, &wanted);
        assert!(report.stats.halvings > 0, "{case}");
        assert!(
            report
                .covered
                .iter()
                .all(|slice| matches!(slice.proof, SliceProof::BelowCap { cap: 50, .. })),
            "{case}: {:?}",
            report.covered
        );
        assert_eq!(
            fixture.limit.stats().finish_hints > 0,
            relay_hints,
            "{case}"
        );
        runs.push((case, report.stats.requests, report.covered));
    }
    let (_, requests, covered) = &runs[0];
    for (case, other_requests, other_covered) in &runs[1..] {
        assert_eq!(other_requests, requests, "{case}");
        assert_eq!(other_covered, covered, "{case}");
    }
}

/// A relay that clamps below the cap its NIP-11 document publishes: a count
/// would take its short reply as complete, but wok's `more` splits it until
/// every slice's reply is whole, and counts prove those.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn more_hint_splits_a_reply_below_the_published_cap() {
    let fixture = Fixture::with_limits(hinted_limits(true)).await;
    let keys = Keys::generate();
    let events = (0..120)
        .map(|n| group_event(&keys, GROUP, T0 + (n as u64) * 700, n))
        .collect::<Vec<_>>();
    let wanted = events.iter().map(|event| event.id).collect();
    fixture.store(&events).await;
    let mut sink = Sink::default();
    let report = run_sweep(
        request(range()),
        // Publishes 500; the relay clamps to 50.
        &fixture.relay_with_caps(STRFRY_NIP11),
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished, "{report:?}");
    assert!(report.stats.halvings > 0);
    assert!(fixture.limit.stats().more_hints > 0);
    assert!(
        report
            .covered
            .iter()
            .all(|slice| matches!(slice.proof, SliceProof::BelowCap { cap: 500, .. })),
        "{:?}",
        report.covered
    );
    assert_once_in_order(&sink, &wanted);
}
