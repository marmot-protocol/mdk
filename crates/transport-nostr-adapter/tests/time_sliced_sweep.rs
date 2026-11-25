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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::TransportEndpointRejectionCategory;
use limit_relay::{LimitConfig, LimitRelay, NegFault};
use nostr_relay_builder::prelude::{
    MemoryDatabase, MemoryDatabaseOptions, NostrDatabase, RateLimit,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::authenticator::SignerAuthenticator;
use nostr_sdk::prelude::{
    Client, ClientMessage, Event, EventBuilder, FinalizeEvent, Keys, Kind, RelayUrl,
    SubscriptionId, Tag, Timestamp,
};
use tokio_util::sync::CancellationToken;
use transport_nostr_adapter::NostrSdkRelayClient;
use transport_nostr_adapter::compare::{
    CompareEnd, ComparePolicy, CompareReply, CompareRequest, CompareSink, run_comparison,
};
use transport_nostr_adapter::sweep::{
    ClosedReason, CoveredSlice, INTERRUPT_GRACE, RelayCaps, SdkSweepRelay, SecondReply, SliceProof,
    SliceQuery, SliceReply, SweepCursor, SweepCursorStore, SweepEnd, SweepPolicy, SweepRange,
    SweepRelay, SweepRequest, SweepRoute, SweepSink, SweepSinkError, SweepStoreError,
    UnreachableKind, run_sweep,
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
        let sdk = NostrSdkRelayClient::from_builder(Client::builder());
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
    covered_through: Option<Arc<Mutex<Option<u64>>>>,
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
        if let Some(through) = &self.covered_through {
            *through.lock().unwrap() = Some(slice.until);
        }
        if let Some((after, token)) = &self.cancel_after
            && self.slices.len() >= *after
        {
            token.cancel();
        }
        Ok(())
    }
}

/// Observes the actual SDK request boundary without replacing its fetches.
struct UncoveredSdkRelay {
    relay: SdkSweepRelay,
    covered_through: Arc<Mutex<Option<u64>>>,
}

impl UncoveredSdkRelay {
    fn assert_uncovered(&self, since: u64) {
        if let Some(through) = *self.covered_through.lock().unwrap() {
            assert!(since > through, "SDK request refetched an admitted prefix");
        }
    }
}

#[async_trait]
impl SweepRelay for UncoveredSdkRelay {
    fn caps(&self) -> RelayCaps {
        SweepRelay::caps(&self.relay)
    }
    async fn fetch_slice(&self, query: SliceQuery) -> SliceReply {
        self.assert_uncovered(query.since);
        self.relay.fetch_slice(query).await
    }
    async fn fetch_second(&self, route: SweepRoute, second: u64, cap: Option<u32>) -> SecondReply {
        self.assert_uncovered(second);
        self.relay.fetch_second(route, second, cap).await
    }
    fn take_fetched_bytes(&self) -> u64 {
        SweepRelay::take_fetched_bytes(&self.relay)
    }
    fn interrupt(&self) -> bool {
        SweepRelay::interrupt(&self.relay)
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

/// Missing metadata leaves the relay's NIP-77 support unknown. A relay that
/// refuses the NEG-OPEN, or says it does not know the command, then cannot
/// prove the second, as one whose document omits NIP-77 cannot (mdk#3264);
/// that refuses neither the underlying history REQ nor advances its cursor.
/// Silence, a refusal after a reply, or withheld ids it listed leave the
/// second inconclusive: a later attempt may prove it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_without_relay_metadata_advances_only_after_reconciliation() {
    let fixture = Fixture::new().await;
    let event = group_event(&Keys::generate(), GROUP, T0, 0);
    fixture.store(std::slice::from_ref(&event)).await;
    let relay = SdkSweepRelay::from_optional_caps(
        &fixture.sdk,
        RelayUrl::parse(&fixture.limit.url()).unwrap(),
        None,
        Duration::from_secs(10),
    );
    let range = SweepRange {
        since: T0,
        until: T0,
    };
    let store = MemoryStore::default();
    let mut sink = Sink::default();
    let cancel = CancellationToken::new();

    // The same relay behind a document that omits NIP-77 stays sweep-only.
    let known = fixture.relay_with_caps("{}");
    let published = run_sweep(request(range), &known, &mut sink, &store, &cancel).await;
    assert_eq!(published.end, SweepEnd::SaturatedSecond { second: T0 });
    assert_eq!(fixture.limit.stats().neg_opens, 0);

    // A refused NEG-OPEN, or a NOTICE the SDK reads as "negentropy not
    // supported" (here strfry's `unknown cmd`), answers that the relay cannot
    // prove the second.
    for fault in [NegFault::ErrOnOpen, NegFault::UnknownCmdOnOpen] {
        fixture.limit.set_neg_fault(fault);
        let refused = run_sweep(request(range), &relay, &mut sink, &store, &cancel).await;
        assert_eq!(
            refused.end,
            SweepEnd::SaturatedSecond { second: T0 },
            "{fault:?}"
        );
        assert!(sink.slices.is_empty());
    }
    // A relay that may serve it after AUTH, that failed generically, that
    // never answered, or that refused only after reconciling began may still
    // prove it.
    for fault in [
        NegFault::ErrOnOpenWith("auth-required: injected"),
        NegFault::ErrOnOpenWith("error: injected"),
        NegFault::SilentOpen,
        NegFault::ErrAfterReply,
    ] {
        fixture.limit.set_neg_fault(fault);
        let retried = run_sweep(request(range), &relay, &mut sink, &store, &cancel).await;
        assert_eq!(
            retried.end,
            SweepEnd::InconclusiveSecond { second: T0 },
            "{fault:?}"
        );
        assert!(sink.slices.is_empty());
    }

    fixture.limit.set_neg_fault(NegFault::None);
    fixture.limit.withhold_id_fetch_events(1);
    let withheld = run_sweep(request(range), &relay, &mut sink, &store, &cancel).await;
    assert_eq!(withheld.end, SweepEnd::InconclusiveSecond { second: T0 });
    assert!(sink.slices.is_empty());

    fixture.limit.withhold_id_fetch_events(0);
    let proved = run_sweep(request(range), &relay, &mut sink, &store, &cancel).await;
    assert_eq!(proved.end, SweepEnd::Finished);
    assert_eq!(sink.slices.len(), 1);
    assert_eq!(sink.slices[0].proof, SliceProof::Negentropy);
    assert_eq!(sink.events, [event]);
}

/// A NIP-77 relay that answers a busy second inconclusively, by listing its
/// ids and then withholding one, by sending a NEG-MSG the client cannot
/// parse, or by repeating each event of an id fetch until a one-id reply
/// overruns its budget, has not shown the second unprovable: the sweep ends
/// on an inconclusive second, not a saturated one, and asking again under
/// the same caps proves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inconclusive_second_is_retried_not_saturated() {
    for fault in ["withheld id", "malformed NEG-MSG", "repeated id events"] {
        let fixture = Fixture::new().await;
        let (events, wanted, burst) = backlog();
        fixture.store(&events).await;
        match fault {
            "withheld id" => fixture.limit.withhold_id_fetch_events(1),
            "malformed NEG-MSG" => fixture.limit.set_neg_fault(NegFault::MalformedReply),
            _ => fixture.limit.repeat_id_fetch_events(3),
        }
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
        let stats = fixture.limit.stats();
        assert_eq!(
            (
                stats.withheld_id_events,
                stats.malformed_neg_replies > 0,
                stats.repeated_id_events > 0,
            ),
            match fault {
                "withheld id" => (1, false, false),
                "malformed NEG-MSG" => (0, true, false),
                _ => (0, false, true),
            },
            "{fault}"
        );
        assert_eq!(
            report.end,
            SweepEnd::InconclusiveSecond { second: burst },
            "{fault}: {report:?}"
        );
        assert_eq!(
            report.cursor.map(|cursor| cursor.next_since),
            Some(burst),
            "{fault}"
        );
        fixture.limit.set_neg_fault(NegFault::None);
        fixture.limit.repeat_id_fetch_events(1);
        let report = run_sweep(
            request(range()),
            &relay,
            &mut sink,
            &store,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(report.end, SweepEnd::Finished, "{fault}: {report:?}");
        assert_once_in_order(&sink, &wanted);
    }
}

/// A relay's full raw page can lose an event at SDK validation. Its 499
/// accepted events are not a below-cap certificate: every one of the 1,200
/// valid historical events must still be swept and admitted exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_filtered_full_page_still_owes_all_valid_history() {
    let fixture = Fixture::new().await;
    let keys = Keys::generate();
    let events = (0..1_200)
        .map(|n| group_event(&keys, GROUP, T0 + n as u64 * DAY / 1_200, n))
        .collect::<Vec<_>>();
    let wanted = events.iter().map(|event| event.id).collect::<HashSet<_>>();
    fixture.store(&events).await;
    let mut invalid = group_event(&keys, GROUP, T0 + DAY - 1, 1_200);
    invalid.sig = group_event(&keys, GROUP, T0 + DAY - 2, 1_201).sig;
    assert!(
        invalid.verify().is_err(),
        "the fixture must be filtered by SDK validation"
    );
    // The database fixture bypasses publish-time validation, as a relay may
    // return malformed historical data to an otherwise valid query.
    fixture.store(&[invalid]).await;
    let relay = fixture.relay();
    let reply = relay
        .fetch_slice(SliceQuery {
            route: SweepRoute::Group {
                nostr_group_id: GROUP,
            },
            since: T0,
            until: T0 + DAY - 1,
            limit: Some(500),
        })
        .await;
    match reply {
        SliceReply::Answered {
            events,
            received,
            more,
        } => {
            assert_eq!(received, 500, "raw page fullness survives validation");
            assert_eq!(events.len(), 499, "exactly one raw event was filtered");
            assert!(!more, "strfry supplies no more hint to rescue the proof");
        }
        other => panic!("expected a filtered full reply, got {other:?}"),
    }
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
    assert!(
        report.stats.halvings > 0,
        "a full page cannot certify the entire window"
    );
    assert_once_in_order(&sink, &wanted);
    assert_eq!(report.covered.first().unwrap().since, T0);
    assert_eq!(report.covered.last().unwrap().until, T0 + DAY - 1);
    for pair in report.covered.windows(2) {
        assert_eq!(
            pair[0].until + 1,
            pair[1].since,
            "coverage has no missing strip"
        );
    }
    let again = run_sweep(
        request(range()),
        &relay,
        &mut Sink::default(),
        &store,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(again.end, SweepEnd::Finished);
    assert_eq!(
        again.stats.requests, 0,
        "completed cursor never refetches the range"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sweep_resumes_over_the_wire_without_refetching() {
    let fixture = Fixture::new().await;
    let (events, wanted, _) = backlog();
    fixture.store(&events).await;
    let through = Arc::new(Mutex::new(None));
    let relay = UncoveredSdkRelay {
        relay: fixture.relay(),
        covered_through: through.clone(),
    };
    let store = MemoryStore::default();
    let mut sink = Sink {
        covered_through: Some(through),
        ..Sink::default()
    };
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

/// A relay that ends a slice with NIP-67 `auth` may hold events back until
/// the client authenticates (mdk#3689). A client that cannot authenticate
/// gets no retry, so the reply stands as an `auth-required:` refusal would,
/// never a covered slice: nothing is admitted and the cursor stays, so the
/// slice stays owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_auth_hint_leaves_the_slice_owed() {
    let fixture = Fixture::new().await;
    let keys = Keys::generate();
    // Far below the cap: without the hint, one reply would prove the day.
    let events = (0..10)
        .map(|n| group_event(&keys, GROUP, T0 + (n as u64) * 3_600, n))
        .collect::<Vec<_>>();
    fixture.store(&events).await;
    fixture.limit.auth_hint_next_eoses(1);
    let store = MemoryStore::default();
    let mut sink = Sink::default();
    let report = run_sweep(
        request(range()),
        &fixture.relay(),
        &mut sink,
        &store,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(
        report.end,
        SweepEnd::Refused(ClosedReason(Some(
            TransportEndpointRejectionCategory::AuthRequired
        ))),
        "{report:?}"
    );
    assert_eq!(fixture.limit.stats().auth_hints, 1);
    assert!(report.covered.is_empty(), "{:?}", report.covered);
    assert!(sink.slices.is_empty() && sink.events.is_empty());
    assert!(
        store
            .0
            .lock()
            .unwrap()
            .is_none_or(|cursor| cursor.next_since == T0),
        "the cursor stays at the slice"
    );
}

/// A relay that answers one REQ before NIP-42 finishes, ends it with
/// NIP-67 `auth` and the AUTH challenge, and once the client authenticates
/// answers each REQ with the newest `cap` of `events` its `since`/`until`
/// match: a cap it publishes nowhere. A REQ before authentication is
/// refused.
async fn auth_gated_clamping_relay(
    events: Vec<Event>,
    cap: usize,
) -> (RelayUrl, tokio::task::JoinHandle<()>) {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as Ws;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = RelayUrl::parse(&format!("ws://{}", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut reqs, mut authenticated) = (0, false);
        while let Some(Ok(message)) = socket.next().await {
            let Ws::Text(text) = message else {
                continue;
            };
            let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
            let replies = match (frame[0].as_str(), frame[1].as_str()) {
                (Some("REQ"), Some(id)) => {
                    reqs += 1;
                    let filter = &frame[2];
                    let since = filter["since"].as_u64().unwrap_or(0);
                    let until = filter["until"].as_u64().unwrap_or(u64::MAX);
                    let mut matched = events
                        .iter()
                        .filter(|event| (since..=until).contains(&event.created_at.as_secs()))
                        .collect::<Vec<_>>();
                    matched.sort_by_key(|event| std::cmp::Reverse(event.created_at));
                    if reqs == 1 {
                        // The oldest match only, as a relay hiding the rest
                        // until the client authenticates.
                        let mut frames = matched
                            .last()
                            .map(|event| serde_json::json!(["EVENT", id, event]))
                            .into_iter()
                            .collect::<Vec<_>>();
                        frames.push(serde_json::json!(["AUTH", "challenge"]));
                        frames.push(serde_json::json!(["EOSE", id, ["auth"]]));
                        frames
                    } else if !authenticated {
                        vec![serde_json::json!([
                            "CLOSED",
                            id,
                            "auth-required: too early"
                        ])]
                    } else {
                        let mut frames = matched
                            .into_iter()
                            .take(cap)
                            .map(|event| serde_json::json!(["EVENT", id, event]))
                            .collect::<Vec<_>>();
                        frames.push(serde_json::json!(["EOSE", id]));
                        frames
                    }
                }
                (Some("AUTH"), _) => {
                    authenticated = true;
                    vec![serde_json::json!(["OK", frame[1]["id"], true, ""])]
                }
                _ => Vec::new(),
            };
            for reply in replies {
                if socket
                    .send(Ws::Text(reply.to_string().into()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    });
    (url, server)
}

/// A slice retried after authentication carries two pages: the one the
/// relay answered while holding events back, and the authenticated one
/// (mdk#3689). Counting them as one would teach a relay with no published
/// cap one larger than it is, and the next clamped page would then pass as
/// complete. A retried reply proves nothing, so no slice is covered without
/// every event in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slice_retried_after_authentication_proves_nothing() {
    let keys = Keys::generate();
    let older = group_event(&keys, GROUP, T0 + 10, 0);
    let newer = group_event(&keys, GROUP, T0 + 20, 1);
    let (url, server) = auth_gated_clamping_relay(vec![older.clone(), newer.clone()], 1).await;
    let sdk = NostrSdkRelayClient::from_builder(
        Client::builder().authenticator(SignerAuthenticator::new(Keys::generate())),
    );
    sdk.client().add_relay(&url).await.unwrap();
    sdk.client().connect().await;
    let relay = SdkSweepRelay::new(
        &sdk,
        url,
        RelayCaps {
            max_limit: None,
            negentropy: false,
        },
        Duration::from_secs(5),
    );
    let mut sink = Sink::default();
    let report = run_sweep(
        request(SweepRange {
            since: T0,
            until: T0 + 99,
        }),
        &relay,
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    let admitted = sink
        .events
        .iter()
        .map(|event| event.id)
        .collect::<HashSet<_>>();
    for event in [&older, &newer] {
        let second = event.created_at.as_secs();
        if report
            .covered
            .iter()
            .any(|slice| (slice.since..=slice.until).contains(&second))
        {
            assert!(
                admitted.contains(&event.id),
                "second {second} covered without its event: {report:?}"
            );
        }
    }
    sdk.shutdown().await;
    server.abort();
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
/// counts. wok's `finish` changes nothing: the sweep runs the same with it and
/// without it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finish_hint_changes_nothing() {
    let mut runs = Vec::new();
    for relay_hints in [true, false] {
        let fixture = Fixture::with_limits(hinted_limits(relay_hints)).await;
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
        let case = format!("relay hints {relay_hints}");
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
    batches: Vec<(SweepRange, bool, Vec<Event>)>,
}

#[async_trait]
impl CompareSink for CompareBatches {
    async fn admit(
        &mut self,
        window: SweepRange,
        certified: bool,
        events: Vec<Event>,
        fetched_bytes: u64,
    ) -> Result<(), SweepSinkError> {
        self.events += events.len();
        self.bytes += fetched_bytes;
        self.batches.push((window, certified, events));
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

/// Comparison exact-id fetches have their own splitting implementation; the
/// saturated-second sweep case does not execute it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_comparison_splits_byte_cut_chunks_and_withholds_an_oversize_id() {
    for oversize in [false, true] {
        let fixture = Fixture::with_limits(LimitConfig {
            req_limit_clamp: Some(50),
            req_default_limit: Some(2),
            ..LimitConfig::default()
        })
        .await;
        let (mut events, one) = uniform_events(24, |_| T0);
        let mut expected = events.clone();
        expected.sort_by_key(|event| event.id);
        let extra_bytes = if oversize {
            let large = EventBuilder::new(Kind::MlsGroupMessage, "x".repeat(6 * one as usize))
                .tags([Tag::custom("h", [hex::encode(GROUP)])])
                .custom_created_at(Timestamp::from_secs(T0))
                .finalize(&Keys::generate())
                .unwrap();
            let bytes = large.as_json().len() as u64;
            events.push(large);
            bytes
        } else {
            0
        };
        fixture.store(&events).await;
        let relay = fixture
            .relay_with_caps(HINTED_NIP11)
            .with_reply_max_bytes(3 * one as usize);
        let window = SweepRange {
            since: T0,
            until: T0,
        };
        let mut sink = CompareBatches::default();
        let report = run_comparison(
            CompareRequest {
                route: SweepRoute::Group {
                    nostr_group_id: GROUP,
                },
                range: window,
                local: &[],
                deadline: None,
                policy: ComparePolicy {
                    pacing: SweepPolicy {
                        min_request_interval: Duration::ZERO,
                        ..SweepPolicy::default()
                    },
                    ..ComparePolicy::new(50, 8 * 1024 * 1024)
                },
            },
            &relay,
            &mut sink,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(
            report.end,
            if oversize {
                CompareEnd::Withheld
            } else {
                CompareEnd::Finished
            },
            "{report:?}"
        );
        assert_eq!(sink.batches.len(), 1);
        assert_eq!(sink.batches[0], (window, !oversize, expected));
        assert_eq!(report.certified.len(), usize::from(!oversize));
        assert_eq!(sink.events, 24);
        assert_eq!(report.unadmitted_bytes, 0);
        if oversize {
            assert!(
                sink.bytes >= 24 * one + extra_bytes,
                "even the over-budget singleton is metered"
            );
        } else {
            // A 24-id chunk splits 24 -> 12 -> 6 -> 3. Seven cut
            // attempts each read their fourth event; eight fitting leaves
            // read the 24 retained events. The relay default is only two.
            assert_eq!(sink.bytes, 52 * one);
        }
        assert_eq!(
            fixture.limit.stats().max_req_limit_seen,
            events.len() as u64
        );
        fixture.sdk.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_comparison_ends_neg_and_starts_no_acquisition() {
    let fixture = Fixture::new().await;
    fixture.limit.set_neg_fault(NegFault::SilentOpen);
    let relay = fixture.relay();
    let route = SweepRoute::Group {
        nostr_group_id: GROUP,
    };
    let compare =
        transport_nostr_adapter::compare::CompareRelay::compare(&relay, route, range(), &[], 50);
    let interrupt = async {
        assert!(
            fixture
                .limit
                .wait_for(Duration::from_secs(5), |stats| stats.neg_opens == 1)
                .await
        );
        assert!(SweepRelay::interrupt(&relay));
    };
    let (reply, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(compare, interrupt)
    })
    .await
    .expect("interrupted NEG must end before its original ten-second timeout");
    assert!(
        matches!(
            reply,
            CompareReply::Unreachable(UnreachableKind::Disconnected)
        ),
        "{reply:?}"
    );

    let reply = relay
        .fetch_slice(SliceQuery {
            route,
            since: T0,
            until: T0 + DAY - 1,
            limit: Some(50),
        })
        .await;
    assert!(
        matches!(
            reply,
            SliceReply::Unreachable(UnreachableKind::Disconnected)
        ),
        "{reply:?}"
    );
    // A FIFO marker is an outbound boundary only: no claim is made that it
    // proves the SDK processed inbound event bytes.
    let marker = format!(
        "{}{}",
        limit_relay::FLUSH_PREFIX,
        SubscriptionId::generate()
    );
    fixture
        .sdk
        .client()
        .relay(fixture.limit.url())
        .await
        .unwrap()
        .unwrap()
        .send_msg(ClientMessage::Close(std::borrow::Cow::Owned(
            SubscriptionId::new(&marker),
        )))
        .await
        .unwrap();
    assert!(
        fixture
            .limit
            .wait_for(Duration::from_secs(5), |stats| stats
                .flushes
                .contains(&marker))
            .await
    );
    assert_eq!(fixture.limit.stats().total_reqs, 0);
    assert_eq!(relay.take_fetched_bytes(), 0);
    fixture.sdk.shutdown().await;
}
