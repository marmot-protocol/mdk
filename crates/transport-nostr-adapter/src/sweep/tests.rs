//! The sweep against a model relay that answers as strfry or wok do: inclusive
//! `since`/`until`, newest first with same-second ties in local insertion
//! order, a per-filter cap, and (wok) NIP-67 `more` and a REQ token bucket.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nostr::prelude::{EventId, Keys, Kind as NostrKind, PublicKey, Signature, Tag};

use super::*;

const GROUP: [u8; 32] = [7; 32];
const OTHER_GROUP: [u8; 32] = [8; 32];
const T0: u64 = 1_700_000_000;
const DAY: u64 = 24 * 60 * 60;

fn route() -> SweepRoute {
    SweepRoute::Group {
        nostr_group_id: GROUP,
    }
}

struct EventFactory {
    pubkey: PublicKey,
    next: u64,
}

impl EventFactory {
    fn new() -> Self {
        Self {
            pubkey: Keys::generate().public_key(),
            next: 0,
        }
    }

    fn event(&mut self, group: [u8; 32], created_at: u64) -> Event {
        self.next += 1;
        // Ids deliberately not in insertion order, so id order cannot stand
        // in for the relay's same-second order.
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&self.next.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
        id[8..16].copy_from_slice(&self.next.to_be_bytes());
        Event::new(
            EventId::from_byte_array(id),
            self.pubkey,
            Timestamp::from_secs(created_at),
            NostrKind::from(GROUP_MESSAGE_KIND),
            [Tag::parse(["h", &hex::encode(group)]).expect("h tag")],
            "",
            Signature::from_byte_array([1; 64]),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    /// Cap 500, no hints; hidden events count toward the cap but are not sent.
    Strfry,
    /// Cap 5,000 (marmot preset), NIP-67 hints. Only `more` reaches the
    /// sweep: it never reads `finish`.
    Wok,
}

struct Stored {
    event: Event,
    /// Matches the filter but is not readable by this connection.
    hidden: bool,
}

struct Bucket {
    rate_per_sec: f64,
    burst: f64,
    tokens: f64,
    at: Instant,
}

#[derive(Default)]
struct Log {
    /// Every slice REQ, in order.
    queries: Vec<SliceQuery>,
    seconds: Vec<u64>,
}

struct ModelRelay {
    profile: Profile,
    caps: RelayCaps,
    /// The cap actually enforced; differs from `caps` for an unpublished cap.
    enforced_cap: usize,
    store: Vec<Stored>,
    latency: Duration,
    bucket: Option<Mutex<Bucket>>,
    /// Scripted answers that pre-empt the next requests.
    script: Mutex<VecDeque<SliceReply>>,
    log: Mutex<Log>,
    /// Cancel this token once this many slice REQs went out.
    cancel_after: Mutex<Option<(usize, CancellationToken)>>,
    /// The last second a linked sink admitted. Every request must start past
    /// it: a sweep never asks again for what it already covered.
    covered_through: Arc<Mutex<Option<u64>>>,
}

impl ModelRelay {
    fn new(profile: Profile, events: Vec<Event>) -> Self {
        let cap = match profile {
            Profile::Strfry => 500,
            Profile::Wok => 5_000,
        };
        Self {
            profile,
            caps: RelayCaps {
                max_limit: Some(cap),
                negentropy: true,
            },
            enforced_cap: cap as usize,
            store: events
                .into_iter()
                .map(|event| Stored {
                    event,
                    hidden: false,
                })
                .collect(),
            latency: Duration::from_millis(50),
            bucket: None,
            script: Mutex::new(VecDeque::new()),
            log: Mutex::new(Log::default()),
            cancel_after: Mutex::new(None),
            covered_through: Arc::new(Mutex::new(None)),
        }
    }

    /// A sink whose admissions this relay checks every later request against.
    fn sink(&self) -> RecordingSink {
        RecordingSink {
            covered_through: self.covered_through.clone(),
            ..RecordingSink::default()
        }
    }

    fn assert_uncovered(&self, since: u64) {
        if let Some(through) = *self.covered_through.lock().unwrap() {
            assert!(
                since > through,
                "request at {since} refetched seconds covered through {through}"
            );
        }
    }

    fn with_bucket(mut self, rate_per_sec: f64, burst: f64) -> Self {
        self.bucket = Some(Mutex::new(Bucket {
            rate_per_sec,
            burst,
            tokens: burst,
            at: Instant::now(),
        }));
        self
    }

    fn take_token(&self) -> bool {
        let Some(bucket) = &self.bucket else {
            return true;
        };
        let mut bucket = bucket.lock().unwrap();
        let now = Instant::now();
        let refill = now.duration_since(bucket.at).as_secs_f64() * bucket.rate_per_sec;
        bucket.tokens = (bucket.tokens + refill).min(bucket.burst);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn matching(&self, route: SweepRoute, since: u64, until: u64) -> Vec<&Stored> {
        let mut matching = self
            .store
            .iter()
            .filter(|stored| {
                let at = stored.event.created_at.as_secs();
                at >= since && at <= until && route.matches(&stored.event)
            })
            .collect::<Vec<_>>();
        // Newest first; within a second, newest insertion first.
        matching.reverse();
        matching.sort_by_key(|stored| std::cmp::Reverse(stored.event.created_at));
        matching
    }

    fn queries(&self) -> Vec<SliceQuery> {
        self.log.lock().unwrap().queries.clone()
    }
}

#[async_trait]
impl SweepRelay for ModelRelay {
    fn caps(&self) -> RelayCaps {
        self.caps
    }

    async fn fetch_slice(&self, query: SliceQuery) -> SliceReply {
        self.assert_uncovered(query.since);
        {
            let mut log = self.log.lock().unwrap();
            log.queries.push(query);
            if let Some((after, token)) = &*self.cancel_after.lock().unwrap()
                && log.queries.len() >= *after
            {
                token.cancel();
            }
        }
        tokio::time::sleep(self.latency).await;
        if let Some(reply) = self.script.lock().unwrap().pop_front() {
            return reply;
        }
        if !self.take_token() {
            return SliceReply::Closed(ClosedReason::from_message(
                "rate-limited: slow down there chief",
            ));
        }
        let matching = self.matching(query.route, query.since, query.until);
        let limit = query
            .limit
            .map_or(self.enforced_cap, |limit| limit as usize)
            .min(self.enforced_cap);
        let sent = matching.iter().take(limit).collect::<Vec<_>>();
        let cut = matching.len() > sent.len();
        let more = self.profile == Profile::Wok && cut;
        let events = sent
            .iter()
            .filter(|stored| !stored.hidden)
            .map(|stored| stored.event.clone())
            .collect::<Vec<_>>();
        SliceReply::Answered {
            received: events.len(),
            events,
            more,
        }
    }

    async fn fetch_second(&self, route: SweepRoute, second: u64, _cap: Option<u32>) -> SecondReply {
        self.assert_uncovered(second);
        self.log.lock().unwrap().seconds.push(second);
        tokio::time::sleep(self.latency).await;
        if !self.caps.negentropy {
            return SecondReply::Unproven;
        }
        SecondReply::Complete(
            self.matching(route, second, second)
                .into_iter()
                .filter(|stored| !stored.hidden)
                .map(|stored| stored.event.clone())
                .collect(),
        )
    }
}

#[derive(Default)]
struct MemoryStore {
    cursor: Mutex<Option<SweepCursor>>,
    saves: Mutex<u32>,
}

#[async_trait]
impl SweepCursorStore for MemoryStore {
    async fn load(&self) -> Result<Option<SweepCursor>, SweepStoreError> {
        Ok(*self.cursor.lock().unwrap())
    }

    async fn save(&self, cursor: SweepCursor) -> Result<(), SweepStoreError> {
        *self.saves.lock().unwrap() += 1;
        *self.cursor.lock().unwrap() = Some(cursor);
        Ok(())
    }
}

#[derive(Default)]
struct RecordingSink {
    slices: Vec<CoveredSlice>,
    events: Vec<Event>,
    covered_through: Arc<Mutex<Option<u64>>>,
}

#[async_trait]
impl SweepSink for RecordingSink {
    async fn admit(
        &mut self,
        slice: CoveredSlice,
        events: Vec<Event>,
    ) -> Result<(), SweepSinkError> {
        self.slices.push(slice);
        self.events.extend(events);
        *self.covered_through.lock().unwrap() = Some(slice.until);
        Ok(())
    }
}

fn request(range: SweepRange) -> SweepRequest {
    SweepRequest {
        route: route(),
        range,
        deadline: None,
        policy: SweepPolicy::default(),
    }
}

fn month() -> SweepRange {
    SweepRange {
        since: T0,
        until: T0 + 30 * DAY - 1,
    }
}

/// `count` events spread evenly over `range`, plus noise from another group.
fn spread(factory: &mut EventFactory, range: SweepRange, count: u64) -> Vec<Event> {
    let span = range.until - range.since + 1;
    let mut events = (0..count)
        .map(|n| factory.event(GROUP, range.since + n * span / count))
        .collect::<Vec<_>>();
    events.extend((0..50).map(|n| factory.event(OTHER_GROUP, range.since + n * DAY / 2)));
    events
}

/// Every event of `GROUP` in `range`, oldest first, exactly once.
fn assert_admitted_once_in_order(sink: &RecordingSink, store: &[Event], range: SweepRange) {
    let mut expected = store
        .iter()
        .filter(|event| {
            let at = event.created_at.as_secs();
            at >= range.since && at <= range.until && route().matches(event)
        })
        .map(|event| event.id)
        .collect::<Vec<_>>();
    let admitted = sink.events.iter().map(|event| event.id).collect::<Vec<_>>();
    assert_eq!(
        admitted.iter().collect::<HashSet<_>>().len(),
        admitted.len(),
        "an event was admitted twice"
    );
    assert!(
        sink.events
            .windows(2)
            .all(|pair| pair[0].created_at <= pair[1].created_at),
        "admission must be oldest first"
    );
    let mut sorted = admitted;
    sorted.sort();
    expected.sort();
    assert_eq!(sorted, expected);
}

/// Covered slices are contiguous, start at the range, and never overlap.
fn assert_contiguous(slices: &[CoveredSlice], range: SweepRange) {
    let mut next = range.since;
    for slice in slices {
        assert_eq!(slice.since, next, "covered slices must be contiguous");
        assert!(slice.until >= slice.since);
        next = slice.until + 1;
    }
    assert_eq!(next, range.until + 1, "covered slices must reach the end");
}

#[test]
fn caps_come_from_nip11() {
    let strfry = r#"{"name":"strfry","supported_nips":[1,2,4,9,11,22,28,40,70,77],
        "limitation":{"max_message_length":131072,"max_subscriptions":200,"max_limit":500}}"#;
    assert_eq!(
        RelayCaps::from_nip11_json(strfry).unwrap(),
        RelayCaps {
            max_limit: Some(500),
            negentropy: true
        }
    );
    let wok =
        r#"{"supported_nips":[1,11,42,67,77],"limitation":{"max_limit":5000,"default_limit":500}}"#;
    assert_eq!(
        RelayCaps::from_nip11_json(wok).unwrap().max_limit,
        Some(5_000)
    );
    // Missing, zero or mistyped caps are unknown, never a default.
    for document in [
        r#"{}"#,
        r#"{"limitation":{"max_limit":0}}"#,
        r#"{"limitation":{"max_limit":"500"}}"#,
        r#"{"supported_nips":"77"}"#,
    ] {
        assert_eq!(
            RelayCaps::from_nip11_json(document).unwrap(),
            RelayCaps::default()
        );
    }
}

#[test]
fn closed_reasons_keep_only_their_category() {
    assert_eq!(
        ClosedReason::from_message("rate-limited: too many historical queries waiting").0,
        Some(TransportEndpointRejectionCategory::RateLimited)
    );
    assert_eq!(
        ClosedReason::from_message("blocked: too many concurrent REQs").0,
        Some(TransportEndpointRejectionCategory::Blocked)
    );
    assert_eq!(ClosedReason::from_message("nope").0, None);
}

#[tokio::test(start_paused = true)]
async fn full_replies_halve_and_sparse_replies_grow() {
    let mut factory = EventFactory::new();
    let range = month();
    // A sparse first fortnight, then 4,000 events in two days, then sparse.
    let mut events = spread(
        &mut factory,
        SweepRange {
            since: T0,
            until: T0 + 14 * DAY - 1,
        },
        40,
    );
    events.extend((0..4_000u64).map(|n| factory.event(GROUP, T0 + 14 * DAY + n * 2 * DAY / 4_000)));
    events.extend((0..40u64).map(|n| factory.event(GROUP, T0 + 16 * DAY + n * 3 * 3_600)));
    let relay = ModelRelay::new(Profile::Strfry, events.clone());
    let store = MemoryStore::default();
    let mut sink = relay.sink();
    let report = run_sweep(
        request(range),
        &relay,
        &mut sink,
        &store,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished);
    assert_eq!(report.outcome(), SweepOutcomeKind::Advanced);
    assert!(report.stats.halvings > 0, "the dense stretch must halve Δ");
    assert!(report.stats.growths > 0, "the sparse tail must grow Δ back");
    assert!(sink.slices.iter().all(|slice| matches!(
        slice.proof,
        SliceProof::BelowCap { received, cap: 500 } if received < 500
    )));
    assert_contiguous(&report.covered, range);
    assert_eq!(sink.slices, report.covered);
    assert_admitted_once_in_order(&sink, &events, range);
    assert_eq!(report.cursor, None);
    // The stored cursor is past the range: the next call has nothing owed.
    let again = run_sweep(
        request(range),
        &relay,
        &mut relay.sink(),
        &store,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(again.outcome(), SweepOutcomeKind::NothingOwed);
    assert_eq!(again.stats.requests, 0);
}

/// The module's known limit, pinned so a change to it is deliberate: strfry
/// spends its cap on events it then withholds, so a short page over a
/// restricted-read kind is not proof. Kind 445 is readable by everyone.
#[tokio::test(start_paused = true)]
async fn withheld_events_defeat_the_count_proof() {
    let mut factory = EventFactory::new();
    let range = SweepRange {
        since: T0,
        until: T0 + DAY - 1,
    };
    let events = spread(&mut factory, range, 480);
    let mut relay = ModelRelay::new(Profile::Strfry, events.clone());
    // 40 newest-second unreadable events take cap room; 460 arrive.
    for _ in 0..40 {
        relay.store.push(Stored {
            event: factory.event(GROUP, range.until),
            hidden: true,
        });
    }
    let mut sink = relay.sink();
    let mut sweep = request(range);
    sweep.policy.initial_delta = DAY;
    let report = run_sweep(
        sweep,
        &relay,
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished);
    assert_eq!(report.stats.requests, 1);
    assert_eq!(
        sink.events.len(),
        460,
        "the 20 oldest readable events are missed"
    );
}

#[tokio::test(start_paused = true)]
async fn cancelled_sweep_resumes_at_its_cursor() {
    let mut factory = EventFactory::new();
    let range = month();
    let events = spread(&mut factory, range, 3_000);
    let relay = ModelRelay::new(Profile::Strfry, events.clone());
    let store = MemoryStore::default();
    let mut sink = relay.sink();
    let mut covered = Vec::new();
    let mut outcomes = Vec::new();
    for attempt in 0..100 {
        let cancel = CancellationToken::new();
        *relay.cancel_after.lock().unwrap() = Some((relay.queries().len() + 3, cancel.clone()));
        let report = run_sweep(request(range), &relay, &mut sink, &store, &cancel).await;
        outcomes.push(report.outcome());
        covered.extend(report.covered.iter().copied());
        if report.end == SweepEnd::Finished {
            assert!(attempt > 2, "the sweep must need several attempts");
            break;
        }
        assert_eq!(report.end, SweepEnd::Cancelled);
    }
    assert!(outcomes.contains(&SweepOutcomeKind::CancelledWithProgress));
    assert_contiguous(&covered, range);
    assert_admitted_once_in_order(&sink, &events, range);
}

#[tokio::test(start_paused = true)]
async fn cancellation_before_any_slice_is_not_progress() {
    let relay = ModelRelay::new(Profile::Strfry, Vec::new());
    let cancel = CancellationToken::new();
    *relay.cancel_after.lock().unwrap() = Some((1, cancel.clone()));
    let store = MemoryStore::default();
    let report = run_sweep(request(month()), &relay, &mut relay.sink(), &store, &cancel).await;
    assert_eq!(report.outcome(), SweepOutcomeKind::Cancelled);
    assert!(report.covered.is_empty());
    assert_eq!(*store.cursor.lock().unwrap(), None);
}

#[tokio::test(start_paused = true)]
async fn saturated_second_falls_back_to_negentropy() {
    let mut factory = EventFactory::new();
    let range = SweepRange {
        since: T0,
        until: T0 + DAY - 1,
    };
    let mut events = spread(&mut factory, range, 200);
    let burst = T0 + 3_600;
    events.extend((0..1_200).map(|_| factory.event(GROUP, burst)));
    let relay = ModelRelay::new(Profile::Strfry, events.clone());
    let mut sink = relay.sink();
    let report = run_sweep(
        request(range),
        &relay,
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished);
    assert_eq!(report.stats.saturated_seconds, 1);
    assert_eq!(relay.log.lock().unwrap().seconds, vec![burst]);
    let second = report
        .covered
        .iter()
        .find(|slice| slice.since == burst)
        .expect("the burst second is its own slice");
    assert_eq!(
        (second.until, second.proof, second.events),
        (burst, SliceProof::Negentropy, 1_200)
    );
    assert_contiguous(&report.covered, range);
    assert_admitted_once_in_order(&sink, &events, range);
}

#[tokio::test(start_paused = true)]
async fn saturated_second_without_negentropy_makes_no_progress_there() {
    let mut factory = EventFactory::new();
    let burst = T0 + 3_600;
    let events = (0..700)
        .map(|_| factory.event(GROUP, burst))
        .collect::<Vec<_>>();
    let mut relay = ModelRelay::new(Profile::Strfry, events);
    relay.caps.negentropy = false;
    let store = MemoryStore::default();
    let range = SweepRange {
        since: burst,
        until: burst + DAY,
    };
    let report = run_sweep(
        request(range),
        &relay,
        &mut relay.sink(),
        &store,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::SaturatedSecond { second: burst });
    assert_eq!(report.outcome(), SweepOutcomeKind::AnsweredNoProgress);
    assert_eq!(report.cursor.map(|cursor| cursor.next_since), Some(burst));
}

#[tokio::test(start_paused = true)]
async fn a_reply_at_the_cap_is_split_even_where_the_relay_hints() {
    let mut factory = EventFactory::new();
    let range = SweepRange {
        since: T0,
        until: T0 + DAY - 1,
    };
    // Exactly the cap. Wok would say `finish`, but only counting proves a
    // slice, so the sweep splits it.
    let events = spread(&mut factory, range, 5_000);
    let relay = ModelRelay::new(Profile::Wok, events.clone());
    let mut sink = relay.sink();
    let report = run_sweep(
        request(range),
        &relay,
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished);
    assert!(report.stats.halvings > 0);
    assert!(
        report
            .covered
            .iter()
            .all(|slice| matches!(slice.proof, SliceProof::BelowCap { .. }))
    );
    assert_admitted_once_in_order(&sink, &events, range);
}

#[tokio::test(start_paused = true)]
async fn a_wrong_more_costs_requests_never_history() {
    let mut factory = EventFactory::new();
    let range = SweepRange {
        since: T0,
        until: T0 + DAY - 1,
    };
    let events = spread(&mut factory, range, 100);
    let sweep = || {
        let mut sweep = request(range);
        sweep.policy.initial_delta = DAY;
        sweep
    };
    let honest = ModelRelay::new(Profile::Wok, events.clone());
    let baseline = run_sweep(
        sweep(),
        &honest,
        &mut honest.sink(),
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(baseline.stats.requests, 1);

    // The relay sends the whole slice but says `more`: the sweep drops the
    // reply, asks for both halves, and admits the same events once.
    let wrong = ModelRelay::new(Profile::Wok, events.clone());
    let all = wrong.matching(route(), range.since, range.until);
    let reply = SliceReply::Answered {
        received: all.len(),
        events: all.iter().map(|stored| stored.event.clone()).collect(),
        more: true,
    };
    wrong.script.lock().unwrap().push_back(reply);
    let mut sink = wrong.sink();
    let report = run_sweep(
        sweep(),
        &wrong,
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished);
    assert_eq!(report.stats.halvings, 1);
    assert_eq!(report.stats.requests, baseline.stats.requests + 2);
    assert_eq!(report.stats.events, baseline.stats.events);
    assert_contiguous(&report.covered, range);
    assert_admitted_once_in_order(&sink, &events, range);
}

#[tokio::test(start_paused = true)]
async fn wok_more_hint_splits_below_the_cap() {
    let range = SweepRange {
        since: T0,
        until: T0 + DAY - 1,
    };
    let relay = ModelRelay::new(Profile::Wok, Vec::new());
    // A cut the count cannot see (one filter asking for the cap makes this
    // unreachable on wok today): `more` still wins.
    relay
        .script
        .lock()
        .unwrap()
        .push_back(SliceReply::Answered {
            events: Vec::new(),
            received: 10,
            more: true,
        });
    let report = run_sweep(
        request(range),
        &relay,
        &mut relay.sink(),
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished);
    assert_eq!(report.stats.halvings, 1);
    assert_eq!(
        report.covered[0].until - report.covered[0].since + 1,
        DAY / 2
    );
}

#[tokio::test(start_paused = true)]
async fn unpublished_cap_is_learned_not_assumed() {
    let mut factory = EventFactory::new();
    let range = month();
    let events = spread(&mut factory, range, 2_000);
    let mut relay = ModelRelay::new(Profile::Strfry, events.clone());
    // No NIP-11 cap, and a silent clamp below the requested limit.
    relay.caps.max_limit = None;
    relay.enforced_cap = 300;
    let mut sink = relay.sink();
    let report = run_sweep(
        request(range),
        &relay,
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished);
    assert!(sink.slices.iter().all(|slice| match slice.proof {
        SliceProof::BelowObserved { received, observed } => received < observed,
        _ => false,
    }));
    assert_admitted_once_in_order(&sink, &events, range);
}

#[tokio::test(start_paused = true)]
async fn rate_limits_are_waited_out_never_empty_pages() {
    let mut factory = EventFactory::new();
    let range = month();
    let events = spread(&mut factory, range, 5_000);
    // A tight bucket and no pacing: the relay refuses often.
    let relay = ModelRelay::new(Profile::Wok, events.clone()).with_bucket(2.0, 3.0);
    let mut sweep = request(range);
    sweep.policy.min_request_interval = Duration::ZERO;
    sweep.policy.initial_delta = DAY;
    let mut sink = relay.sink();
    let report = run_sweep(
        sweep,
        &relay,
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished);
    assert!(report.stats.rate_limited_waits > 0);
    assert_contiguous(&report.covered, range);
    assert_admitted_once_in_order(&sink, &events, range);
}

#[tokio::test(start_paused = true)]
async fn persistent_rate_limit_is_a_refusal_without_progress() {
    let relay = ModelRelay::new(Profile::Wok, Vec::new());
    for _ in 0..20 {
        relay
            .script
            .lock()
            .unwrap()
            .push_back(SliceReply::Closed(ClosedReason::from_message(
                "rate-limited: slow down",
            )));
    }
    let store = MemoryStore::default();
    let report = run_sweep(
        request(month()),
        &relay,
        &mut relay.sink(),
        &store,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::RateLimited);
    assert_eq!(report.outcome(), SweepOutcomeKind::Refused);
    assert_eq!(report.stats.rate_limited_waits, 8);
    assert_eq!(*store.cursor.lock().unwrap(), None);
}

#[tokio::test(start_paused = true)]
async fn blocked_is_retried_then_refused() {
    let mut factory = EventFactory::new();
    let events = spread(&mut factory, month(), 100);
    // One transient `blocked:` (wok: too many concurrent REQs) is waited out.
    let relay = ModelRelay::new(Profile::Wok, events.clone());
    relay
        .script
        .lock()
        .unwrap()
        .push_back(SliceReply::Closed(ClosedReason::from_message(
            "blocked: too many concurrent REQs",
        )));
    let mut sink = relay.sink();
    let report = run_sweep(
        request(month()),
        &relay,
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::Finished);
    assert_eq!(report.stats.blocked_waits, 1);
    assert_admitted_once_in_order(&sink, &events, month());

    // A lasting one (query too broad) ends the call as refused.
    let relay = ModelRelay::new(Profile::Wok, Vec::new());
    for _ in 0..3 {
        relay
            .script
            .lock()
            .unwrap()
            .push_back(SliceReply::Closed(ClosedReason::from_message(
                "blocked: query too broad",
            )));
    }
    let report = run_sweep(
        request(month()),
        &relay,
        &mut relay.sink(),
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(
        report.end,
        SweepEnd::Refused(ClosedReason(Some(
            TransportEndpointRejectionCategory::Blocked
        )))
    );
    assert_eq!(report.outcome(), SweepOutcomeKind::Refused);
}

#[tokio::test(start_paused = true)]
async fn unreachable_relay_is_relay_health_not_an_empty_page() {
    let mut factory = EventFactory::new();
    let events = spread(&mut factory, month(), 3_000);
    let relay = ModelRelay::new(Profile::Strfry, events);
    relay
        .script
        .lock()
        .unwrap()
        .push_back(SliceReply::Unreachable(UnreachableKind::TimedOut));
    let store = MemoryStore::default();
    let report = run_sweep(
        request(month()),
        &relay,
        &mut relay.sink(),
        &store,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.outcome(), SweepOutcomeKind::RelayUnreachable);
    assert!(report.covered.is_empty());
    assert_eq!(*store.cursor.lock().unwrap(), None);

    // After progress, a drop still reports the progress first.
    let mut factory = EventFactory::new();
    let events = spread(&mut factory, month(), 100);
    let relay = ModelRelay::new(Profile::Strfry, events);
    let mut sweep = request(month());
    sweep.policy.initial_delta = DAY;
    relay.script.lock().unwrap().extend([
        SliceReply::Answered {
            events: Vec::new(),
            received: 0,
            more: false,
        },
        SliceReply::Unreachable(UnreachableKind::Disconnected),
    ]);
    let report = run_sweep(
        sweep,
        &relay,
        &mut relay.sink(),
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(
        report.end,
        SweepEnd::Unreachable(UnreachableKind::Disconnected)
    );
    assert_eq!(report.outcome(), SweepOutcomeKind::Advanced);
    assert_eq!(report.covered.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn deadline_is_a_pause() {
    let mut factory = EventFactory::new();
    let events = spread(&mut factory, month(), 5_000);
    let relay = ModelRelay::new(Profile::Strfry, events);
    let mut sweep = request(month());
    sweep.deadline = Some(Instant::now() + Duration::from_millis(600));
    let report = run_sweep(
        sweep,
        &relay,
        &mut relay.sink(),
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::DeadlineReached);
    assert_eq!(report.outcome(), SweepOutcomeKind::Advanced);

    // Cut before the first slice completes: answered, nothing new.
    let mut factory = EventFactory::new();
    let relay = ModelRelay::new(Profile::Strfry, spread(&mut factory, month(), 50_000));
    let mut sweep = request(month());
    sweep.deadline = Some(Instant::now() + Duration::from_millis(120));
    let report = run_sweep(
        sweep,
        &relay,
        &mut relay.sink(),
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::DeadlineReached);
    assert_eq!(report.outcome(), SweepOutcomeKind::AnsweredNoProgress);

    // Cut before the relay answered at all: nobody's fault, charge nothing.
    let relay = ModelRelay::new(Profile::Strfry, Vec::new());
    let mut sweep = request(month());
    sweep.deadline = Some(Instant::now() + Duration::from_millis(30));
    let report = run_sweep(
        sweep,
        &relay,
        &mut relay.sink(),
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::DeadlineReached);
    assert_eq!(report.outcome(), SweepOutcomeKind::Unanswered);

    // Likewise a deadline spent waiting out a rate limit.
    let relay = ModelRelay::new(Profile::Wok, Vec::new());
    relay
        .script
        .lock()
        .unwrap()
        .push_back(SliceReply::Closed(ClosedReason::from_message(
            "rate-limited: slow down",
        )));
    let mut sweep = request(month());
    sweep.deadline = Some(Instant::now() + Duration::from_millis(500));
    let report = run_sweep(
        sweep,
        &relay,
        &mut relay.sink(),
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::DeadlineReached);
    assert_eq!(report.stats.rate_limited_waits, 1);
    assert_eq!(report.outcome(), SweepOutcomeKind::Unanswered);
}

/// The issue's completion bar: a large group finishes over successive cut
/// attempts, and no attempt refetches what an earlier one covered.
#[tokio::test(start_paused = true)]
async fn large_groups_finish_over_cut_attempts_without_refetching() {
    let mut measurements = HashMap::new();
    for profile in [Profile::Strfry, Profile::Wok] {
        for count in [5_000u64, 50_000] {
            let mut factory = EventFactory::new();
            let range = month();
            let mut events = spread(&mut factory, range, count);
            // A saturated second for each relay's cap.
            let burst = T0 + 20 * DAY + 17;
            let burst_size = match profile {
                Profile::Strfry => 800,
                Profile::Wok => 6_000,
            };
            events.extend((0..burst_size).map(|_| factory.event(GROUP, burst)));
            let mut relay = ModelRelay::new(profile, events.clone());
            relay.latency = Duration::from_millis(200);
            let store = MemoryStore::default();
            let mut sink = relay.sink();
            let mut covered = Vec::new();
            let mut attempts = 0;
            loop {
                attempts += 1;
                assert!(attempts < 1_000, "the sweep must finish");
                let mut sweep = request(range);
                // The old capture's 10 s pass budget.
                sweep.deadline = Some(Instant::now() + Duration::from_secs(10));
                let report =
                    run_sweep(sweep, &relay, &mut sink, &store, &CancellationToken::new()).await;
                covered.extend(report.covered.iter().copied());
                match report.end {
                    SweepEnd::Finished => break,
                    SweepEnd::DeadlineReached => {
                        assert_eq!(report.outcome(), SweepOutcomeKind::Advanced);
                    }
                    other => panic!("unexpected end {other:?}"),
                }
            }
            assert_contiguous(&covered, range);
            assert_admitted_once_in_order(&sink, &events, range);
            let queries = relay.queries();
            measurements.insert(
                (format!("{profile:?}"), count),
                (attempts, queries.len(), covered.len()),
            );
        }
    }
    let mut rows = measurements.into_iter().collect::<Vec<_>>();
    rows.sort();
    for ((profile, count), (attempts, requests, slices)) in rows {
        eprintln!(
            "sweep measurement: {profile} {count} events (+ saturated second): \
             {attempts} attempts of 10 s, {requests} slice REQs, {slices} covered slices"
        );
    }
}

/// A relay whose every request reads until it is interrupted. It then ends
/// after `ends_after`, metering `read` bytes, or never does.
struct HangingRelay {
    /// What [`SweepRelay::interrupt`] answers.
    can_interrupt: bool,
    ends_after: Option<Duration>,
    read: u64,
    interrupted: CancellationToken,
    metered: std::sync::atomic::AtomicU64,
    ended: std::sync::atomic::AtomicU32,
}

impl HangingRelay {
    fn new(can_interrupt: bool, ends_after: Option<Duration>) -> Self {
        Self {
            can_interrupt,
            ends_after,
            read: 4_096,
            interrupted: CancellationToken::new(),
            metered: Default::default(),
            ended: Default::default(),
        }
    }

    async fn read_until_interrupted(&self) {
        self.interrupted.cancelled().await;
        match self.ends_after {
            Some(after) => tokio::time::sleep(after).await,
            None => std::future::pending().await,
        }
        self.metered
            .fetch_add(self.read, std::sync::atomic::Ordering::SeqCst);
        self.ended.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn ended(&self) -> u32 {
        self.ended.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl SweepRelay for HangingRelay {
    fn caps(&self) -> RelayCaps {
        RelayCaps {
            max_limit: Some(500),
            negentropy: true,
        }
    }

    async fn fetch_slice(&self, _query: SliceQuery) -> SliceReply {
        self.read_until_interrupted().await;
        // An empty answer would prove the slice: it must never be used.
        SliceReply::Answered {
            events: Vec::new(),
            received: 0,
            more: false,
        }
    }

    async fn fetch_second(
        &self,
        _route: SweepRoute,
        _second: u64,
        _cap: Option<u32>,
    ) -> SecondReply {
        self.read_until_interrupted().await;
        SecondReply::Complete(Vec::new())
    }

    fn take_fetched_bytes(&self) -> u64 {
        self.metered.swap(0, std::sync::atomic::Ordering::SeqCst)
    }

    fn interrupt(&self) -> bool {
        self.interrupted.cancel();
        self.can_interrupt
    }
}

/// A request the deadline cuts is interrupted and awaited, so its relay
/// meters what it read; its reply is never used.
#[tokio::test(start_paused = true)]
async fn a_cut_request_is_interrupted_and_reports_what_it_read() {
    let relay = HangingRelay::new(true, Some(Duration::from_millis(100)));
    let started = Instant::now();
    let mut sweep = request(month());
    sweep.deadline = Some(started + Duration::from_secs(2));
    let mut sink = RecordingSink::default();
    let report = run_sweep(
        sweep,
        &relay,
        &mut sink,
        &MemoryStore::default(),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, SweepEnd::DeadlineReached);
    assert_eq!(report.outcome(), SweepOutcomeKind::Unanswered);
    assert!(report.covered.is_empty() && sink.slices.is_empty());
    assert_eq!((report.stats.requests, report.stats.answers), (1, 0));
    assert_eq!(relay.ended(), 1, "the request ran to its end");
    assert_eq!(relay.take_fetched_bytes(), relay.read);
    assert_eq!(started.elapsed(), Duration::from_millis(2_100));

    // Cancellation (shutdown, a pass preemption) interrupts it the same way.
    let relay = HangingRelay::new(true, Some(Duration::from_millis(100)));
    let cancel = CancellationToken::new();
    let started = Instant::now();
    let cancelling = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            cancel.cancel();
        })
    };
    let report = run_sweep(
        request(month()),
        &relay,
        &mut RecordingSink::default(),
        &MemoryStore::default(),
        &cancel,
    )
    .await;
    cancelling.await.unwrap();
    assert_eq!(report.end, SweepEnd::Cancelled);
    assert!(report.covered.is_empty());
    assert_eq!(relay.take_fetched_bytes(), relay.read);
    assert_eq!(started.elapsed(), Duration::from_millis(2_100));
}

/// The grace bounds the wait for a relay that does not end its request, and
/// a relay that cannot interrupt has its request dropped at once.
#[tokio::test(start_paused = true)]
async fn a_cut_request_is_dropped_after_the_grace_or_at_once() {
    for (can_interrupt, wait) in [(true, INTERRUPT_GRACE), (false, Duration::ZERO)] {
        let relay = HangingRelay::new(can_interrupt, None);
        let started = Instant::now();
        let mut sweep = request(month());
        sweep.deadline = Some(started + Duration::from_secs(2));
        let report = run_sweep(
            sweep,
            &relay,
            &mut RecordingSink::default(),
            &MemoryStore::default(),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(report.end, SweepEnd::DeadlineReached);
        assert_eq!(relay.ended(), 0, "the request was dropped");
        assert_eq!(relay.take_fetched_bytes(), 0);
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(2) + wait,
            "can interrupt: {can_interrupt}"
        );
    }
}
