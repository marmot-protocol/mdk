#![cfg(feature = "sdk")]
// Test fixtures dial local relays directly.
#![allow(clippy::disallowed_methods)]

//! The time-sliced sweep over the wire: `SdkSweepRelay` against a local relay
//! behind the strfry-limits proxy (`support/limit_relay.rs`, 500 clamp, no
//! NIP-67 hints unless a test turns on wok's). Synthetic group events only; no
//! MLS. Requests cut mid-reply (the proxy's stall) are covered for the
//! comparison's fetches too.

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
use transport_nostr_adapter::compare::{
    CompareEnd, ComparePolicy, CompareRequest, CompareSink, run_comparison,
};
use transport_nostr_adapter::sweep::{
    CoveredSlice, INTERRUPT_GRACE, RelayCaps, SdkSweepRelay, SliceProof, SliceQuery, SliceReply,
    SweepCursor, SweepCursorStore, SweepEnd, SweepPolicy, SweepRange, SweepRelay, SweepRequest,
    SweepRoute, SweepSink, SweepSinkError, SweepStoreError, run_sweep,
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

/// A reply the byte budget cuts short keeps no events, but the relay sent
/// them: the relay reports every byte it read, so a caller's byte budget sees
/// what the cut discarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cut_reply_still_reports_the_bytes_it_read() {
    let fixture = Fixture::new().await;
    let keys = Keys::generate();
    let events = (0..50)
        .map(|n| group_event(&keys, GROUP, T0 + n as u64, n))
        .collect::<Vec<_>>();
    fixture.store(&events).await;
    let one = events[0].as_json().len();
    let relay = fixture.relay().with_reply_max_bytes(4 * one);
    let query = SliceQuery {
        route: SweepRoute::Group {
            nostr_group_id: GROUP,
        },
        since: T0,
        until: T0 + DAY - 1,
        limit: Some(500),
    };

    let reply = relay.fetch_slice(query).await;
    assert!(
        matches!(&reply, SliceReply::Answered { events, more: true, .. } if events.is_empty()),
        "{reply:?}"
    );
    let read = relay.take_fetched_bytes();
    assert!(
        read > 4 * one as u64,
        "the over-budget event counts too: {read}"
    );
    assert_eq!(relay.take_fetched_bytes(), 0, "taking the count resets it");

    // A reply that fits reports what it kept.
    let relay = fixture.relay();
    let reply = relay.fetch_slice(query).await;
    let SliceReply::Answered { events: kept, .. } = reply else {
        panic!("{reply:?}");
    };
    assert_eq!(kept.len(), events.len());
    let kept_bytes: u64 = kept.iter().map(|event| event.as_json().len() as u64).sum();
    assert_eq!(relay.take_fetched_bytes(), kept_bytes);
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

/// Events whose JSON is all one length, so bytes read are a count of events.
fn uniform_events(count: usize, created_at: impl Fn(usize) -> u64) -> (Vec<Event>, u64) {
    let keys = Keys::generate();
    let events = (0..count)
        .map(|n| {
            EventBuilder::new(Kind::MlsGroupMessage, format!("payload-{n:06}"))
                .tags([Tag::custom("h", [hex::encode(GROUP)])])
                .custom_created_at(Timestamp::from_secs(created_at(n)))
                .finalize(&keys)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let one = events[0].as_json().len();
    assert!(events.iter().all(|event| event.as_json().len() == one));
    (events, one as u64)
}

/// A slice reply the deadline cuts mid-stream: the sweep interrupts the
/// request rather than dropping it, and the relay reports every event byte it
/// read before the cut.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slice_cut_mid_reply_reports_every_byte_it_read() {
    let fixture = Fixture::new().await;
    let (events, one) = uniform_events(200, |n| T0 + n as u64);
    fixture.store(&events).await;
    fixture.limit.stall_after_events(30);
    let relay = fixture.relay();
    let mut sweep = request(range());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    sweep.deadline = Some(deadline);
    let report = run_sweep(
        sweep,
        &relay,
        &mut Sink::default(),
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    let returned = tokio::time::Instant::now();
    assert_eq!(report.end, SweepEnd::DeadlineReached, "{report:?}");
    assert_eq!((report.stats.requests, report.stats.answers), (1, 0));
    assert!(report.covered.is_empty());
    let stats = fixture.limit.stats();
    assert_eq!(stats.events_before_stall, 30);
    assert!(stats.stalled_frames > 0, "the reply was cut mid-stream");
    assert_eq!(relay.take_fetched_bytes(), 30 * one);
    assert!(returned < deadline + INTERRUPT_GRACE);
}

/// A saturated second cut by cancellation (shutdown, or a pass preempting
/// it) after two of its id-fetch chunks completed and mid-way through the
/// third: every byte the slice and the chunks read is reported, and no
/// further chunk goes out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_cut_after_completed_chunks_reports_every_byte_it_read() {
    let fixture = Fixture::with_limits(LimitConfig {
        req_limit_clamp: Some(50),
        ..LimitConfig::default()
    })
    .await;
    let burst = T0 + 3_600;
    let (events, one) = uniform_events(300, |_| burst);
    fixture.store(&events).await;
    let relay =
        fixture.relay_with_caps(r#"{"supported_nips":[1,11,77],"limitation":{"max_limit":50}}"#);
    // The slice's 50, two whole chunks of 50, and 20 of the third.
    let read = 50 + 2 * 50 + 20;
    fixture.limit.stall_after_events(read);
    let cancel = CancellationToken::new();
    let cancelled_at = {
        let cancel = cancel.clone();
        let limit = &fixture.limit;
        async move {
            assert!(
                limit
                    .wait_for(Duration::from_secs(10), |stats| {
                        stats.events_before_stall == read && stats.stalled_frames > 0
                    })
                    .await,
                "the third chunk stalls"
            );
            // Let the client take in what the proxy sent.
            tokio::time::sleep(Duration::from_millis(300)).await;
            cancel.cancel();
            tokio::time::Instant::now()
        }
    };
    let second = SweepRange {
        since: burst,
        until: burst,
    };
    let (mut sink, store) = (Sink::default(), MemoryStore::default());
    let (report, cancelled_at) = tokio::join!(
        run_sweep(request(second), &relay, &mut sink, &store, &cancel),
        cancelled_at
    );
    let returned = tokio::time::Instant::now();
    assert_eq!(report.end, SweepEnd::Cancelled, "{report:?}");
    assert_eq!(report.stats.saturated_seconds, 1);
    assert!(report.covered.is_empty());
    assert_eq!(relay.take_fetched_bytes(), read as u64 * one);
    assert!(returned < cancelled_at + INTERRUPT_GRACE);
    // The slice and three chunks; the interrupted fetch asked for no fourth.
    let stats = fixture
        .limit
        .wait_quiet(Duration::from_millis(300), Duration::from_secs(5))
        .await;
    assert_eq!(stats.total_reqs, 4, "{}", stats.summary());
}

#[derive(Default)]
struct CompareBatches {
    events: usize,
    bytes: u64,
}

#[async_trait]
impl CompareSink for CompareBatches {
    async fn admit(
        &mut self,
        _window: SweepRange,
        _certified: bool,
        events: Vec<Event>,
        fetched_bytes: u64,
    ) -> Result<(), SweepSinkError> {
        self.events += events.len();
        self.bytes += fetched_bytes;
        Ok(())
    }
}

/// A comparison's fetch by id cut mid-reply reports what it read, as a
/// sweep's request does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_comparison_fetch_cut_mid_reply_reports_every_byte_it_read() {
    let fixture = Fixture::new().await;
    let (events, one) = uniform_events(200, |n| T0 + n as u64 * 60);
    fixture.store(&events).await;
    fixture.limit.stall_after_events(30);
    let relay = fixture.relay();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut sink = CompareBatches::default();
    let report = run_comparison(
        CompareRequest {
            route: SweepRoute::Group {
                nostr_group_id: GROUP,
            },
            range: range(),
            local: &[],
            deadline: Some(deadline),
            policy: ComparePolicy::new(2_048, 8 * 1024 * 1024),
        },
        &relay,
        &mut sink,
        &CancellationToken::new(),
    )
    .await;
    let returned = tokio::time::Instant::now();
    assert_eq!(report.end, CompareEnd::DeadlineReached, "{report:?}");
    assert!(report.certified.is_empty());
    assert_eq!(report.stats.missing, 200);
    assert_eq!(sink.events, 0);
    assert_eq!(fixture.limit.stats().events_before_stall, 30);
    assert_eq!(sink.bytes + report.unadmitted_bytes, 30 * one);
    assert!(returned < deadline + INTERRUPT_GRACE);
}
