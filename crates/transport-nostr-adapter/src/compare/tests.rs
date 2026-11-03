//! The comparison against a model relay that answers NIP-77 as strfry does:
//! its set for a window is every matching event, newest first, as far as the
//! comparison's limit, and a fetch by id returns the named events it holds.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, PublicKey, Signature, Tag, Timestamp};

use super::*;

const GROUP: [u8; 32] = [7; 32];
const T0: u64 = 1_700_000_000;
const DAY: u64 = 24 * 60 * 60;
const GROUP_MESSAGE_KIND: u16 = 445;

fn route() -> SweepRoute {
    SweepRoute::Group {
        nostr_group_id: GROUP,
    }
}

fn day() -> SweepRange {
    SweepRange {
        since: T0,
        until: T0 + DAY - 1,
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

    fn event(&mut self, created_at: u64) -> Event {
        self.next += 1;
        // Ids not in time order, so id order cannot stand in for age.
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&self.next.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
        id[8..16].copy_from_slice(&self.next.to_be_bytes());
        Event::new(
            EventId::from_byte_array(id),
            self.pubkey,
            Timestamp::from_secs(created_at),
            Kind::from(GROUP_MESSAGE_KIND),
            [Tag::parse(["h", &hex::encode(GROUP)]).expect("h tag")],
            "",
            Signature::from_byte_array([1; 64]),
        )
    }

    /// `count` events spread evenly over `range`.
    fn spread(&mut self, range: SweepRange, count: u64) -> Vec<Event> {
        let span = range.until - range.since + 1;
        (0..count)
            .map(|index| self.event(range.since + index * span / count))
            .collect()
    }
}

#[derive(Default)]
struct ModelRelay {
    events: Vec<Event>,
    /// Ids it names in comparisons but never returns.
    withheld: HashSet<EventId>,
    /// Requests, by index, refused with `rate-limited:`.
    limited: BTreeSet<usize>,
    unsupported: bool,
    max_limit: Option<u32>,
    requests: AtomicUsize,
    /// Every id asked for, in order.
    fetched: Mutex<Vec<EventId>>,
    fetch_chunks: Mutex<Vec<Vec<EventId>>>,
    fetch_replies: Mutex<VecDeque<IdsReply>>,
    compare_replies: Mutex<VecDeque<CompareReply>>,
    comparisons: Mutex<Vec<(SweepRange, usize)>>,
    /// The largest relay set a comparison reported.
    largest_set: AtomicUsize,
    /// Every fetch by id reads `read_until_cut` bytes and waits to be
    /// interrupted before it answers.
    hold_fetches: bool,
    read_until_cut: u64,
    /// What [`CompareRelay::interrupt`] answers.
    interruptible: bool,
    interrupted: CancellationToken,
    metered: AtomicU64,
}

impl ModelRelay {
    fn holding(events: Vec<Event>) -> Self {
        Self {
            events,
            ..Self::default()
        }
    }

    fn arrive(&self) -> Option<ClosedReason> {
        let index = self.requests.fetch_add(1, Ordering::SeqCst);
        self.limited
            .contains(&index)
            .then(|| ClosedReason::from_message("rate-limited: slow down"))
    }

    fn fetched(&self) -> Vec<EventId> {
        self.fetched.lock().unwrap().clone()
    }

    fn in_window(&self, window: SweepRange) -> Vec<&Event> {
        let mut matching = self
            .events
            .iter()
            .filter(|event| {
                let at = event.created_at.as_secs();
                at >= window.since && at <= window.until
            })
            .collect::<Vec<_>>();
        matching.sort_by_key(|event| std::cmp::Reverse((event.created_at, event.id)));
        matching
    }
}

#[async_trait]
impl CompareRelay for ModelRelay {
    fn caps(&self) -> RelayCaps {
        RelayCaps {
            max_limit: self.max_limit,
            negentropy: !self.unsupported,
        }
    }

    async fn compare(
        &self,
        _route: SweepRoute,
        window: SweepRange,
        local: &[LocalItem],
        limit: usize,
    ) -> CompareReply {
        self.comparisons.lock().unwrap().push((window, limit));
        if let Some(reason) = self.arrive() {
            return CompareReply::Closed(reason);
        }
        if self.unsupported {
            return CompareReply::Unsupported;
        }
        if let Some(reply) = self.compare_replies.lock().unwrap().pop_front() {
            return reply;
        }
        let held = local.iter().map(|item| item.id).collect::<HashSet<_>>();
        let set = self
            .in_window(window)
            .into_iter()
            .take(limit)
            .collect::<Vec<_>>();
        self.largest_set.fetch_max(set.len(), Ordering::SeqCst);
        CompareReply::Compared {
            missing: set
                .iter()
                .map(|event| event.id)
                .filter(|id| !held.contains(id))
                .collect(),
            relay_set: set.len(),
        }
    }

    async fn fetch_ids(&self, _route: SweepRoute, window: SweepRange, ids: &[EventId]) -> IdsReply {
        self.fetch_chunks.lock().unwrap().push(ids.to_vec());
        if let Some(reason) = self.arrive() {
            return IdsReply::Closed(reason);
        }
        self.fetched.lock().unwrap().extend_from_slice(ids);
        if let Some(reply) = self.fetch_replies.lock().unwrap().pop_front() {
            return reply;
        }
        if self.hold_fetches {
            self.interrupted.cancelled().await;
            self.metered
                .fetch_add(self.read_until_cut, Ordering::SeqCst);
        }
        let asked = ids.iter().collect::<HashSet<_>>();
        IdsReply::Answered(
            self.in_window(window)
                .into_iter()
                .filter(|event| asked.contains(&event.id) && !self.withheld.contains(&event.id))
                .cloned()
                .collect(),
        )
    }

    fn take_fetched_bytes(&self) -> u64 {
        self.metered.swap(0, Ordering::SeqCst)
    }

    fn interrupt(&self) -> bool {
        self.interrupted.cancel();
        self.interruptible
    }
}

/// One admitted batch.
#[derive(Clone, Debug)]
struct Batch {
    window: SweepRange,
    certified: bool,
    events: Vec<Event>,
}

#[derive(Default)]
struct RecordingSink {
    batches: Vec<Batch>,
    bytes: u64,
}

#[async_trait]
impl CompareSink for RecordingSink {
    async fn admit(
        &mut self,
        window: SweepRange,
        certified: bool,
        events: Vec<Event>,
        fetched_bytes: u64,
    ) -> Result<(), SweepSinkError> {
        self.bytes += fetched_bytes;
        self.batches.push(Batch {
            window,
            certified,
            events,
        });
        Ok(())
    }
}

fn policy(max_events: usize) -> ComparePolicy {
    ComparePolicy {
        pacing: SweepPolicy {
            min_request_interval: Duration::ZERO,
            ..SweepPolicy::default()
        },
        ..ComparePolicy::new(max_events, 8 * 1024 * 1024)
    }
}

fn local(events: &[Event]) -> Vec<LocalItem> {
    let mut items = events
        .iter()
        .map(|event| LocalItem {
            created_at: event.created_at.as_secs(),
            id: event.id,
        })
        .collect::<Vec<_>>();
    items.sort();
    items
}

fn signed_spread(range: SweepRange, count: u64) -> Vec<Event> {
    let keys = Keys::generate();
    let span = range.until - range.since + 1;
    (0..count)
        .map(|n| {
            EventBuilder::new(Kind::MlsGroupMessage, format!("history-{n}"))
                .tags([Tag::custom("h", [hex::encode(GROUP)])])
                .custom_created_at(Timestamp::from_secs(range.since + n * span / count))
                .finalize(&keys).unwrap()
        })
        .collect()
}

async fn compare(
    relay: &ModelRelay,
    range: SweepRange,
    held: &[LocalItem],
    policy: ComparePolicy,
) -> (CompareReport, RecordingSink) {
    let mut sink = RecordingSink::default();
    let report = run_comparison(
        CompareRequest {
            route: route(),
            range,
            local: held,
            deadline: None,
            policy,
        },
        relay,
        &mut sink,
        &CancellationToken::new(),
    )
    .await;
    (report, sink)
}

fn assert_contiguous(windows: &[CertifiedWindow], since: u64) {
    let mut next = since;
    for window in windows {
        assert_eq!(window.since, next, "certified windows leave a gap");
        assert!(window.until >= window.since);
        next = window.until + 1;
    }
}

#[tokio::test(start_paused = true)]
async fn a_large_difference_is_certified_oldest_first_over_several_calls() {
    let mut factory = EventFactory::new();
    let held = factory.spread(day(), 1_000);
    let missing = factory.spread(day(), 5_000);
    let relay = ModelRelay::holding(held.iter().chain(&missing).cloned().collect());
    let mut local_set = local(&held);
    let mut since = day().since;
    let mut calls = 0;
    let mut staged = Vec::new();
    loop {
        calls += 1;
        assert!(calls < 20, "the difference never finished");
        let range = SweepRange {
            since,
            until: day().until,
        };
        let (report, sink) = compare(&relay, range, &local_set, policy(2_048)).await;
        assert_contiguous(&report.certified, since);
        let fetched = sink
            .batches
            .iter()
            .map(|batch| batch.events.len())
            .sum::<usize>();
        assert!(fetched <= 2_048, "one call fetched past its budget");
        for batch in &sink.batches {
            assert!(
                batch.events.windows(2).all(
                    |pair| (pair[0].created_at, pair[0].id) <= (pair[1].created_at, pair[1].id)
                ),
                "a batch is not oldest first"
            );
            staged.extend(batch.events.iter().cloned());
            local_set.extend(local(&batch.events));
        }
        local_set.sort();
        if let Some(last) = report.certified.last() {
            since = last.until + 1;
        }
        if report.end == CompareEnd::Finished {
            break;
        }
        assert_eq!(report.end, CompareEnd::BudgetSpent);
        assert!(
            !report.certified.is_empty(),
            "a call within its budget certified nothing"
        );
    }
    assert!(calls >= 3, "the difference fit in {calls} calls");
    let fetched = relay.fetched();
    let unique = fetched.iter().collect::<HashSet<_>>();
    assert_eq!(fetched.len(), unique.len(), "an id was fetched twice");
    let wanted = missing.iter().map(|event| event.id).collect::<HashSet<_>>();
    let got = staged.iter().map(|event| event.id).collect::<HashSet<_>>();
    assert_eq!(got, wanted, "the difference, all of it and nothing held");
}

#[tokio::test(start_paused = true)]
async fn a_window_whose_relay_set_fills_the_limit_halves() {
    let mut factory = EventFactory::new();
    let events = factory.spread(day(), 300);
    let relay = ModelRelay::holding(events.clone());
    let mut policy = policy(2_048);
    policy.set_limit = 100;

    let (report, sink) = compare(&relay, day(), &[], policy).await;

    assert_eq!(report.end, CompareEnd::Finished);
    assert!(report.stats.narrowings > 0);
    assert_contiguous(&report.certified, day().since);
    assert_eq!(report.certified.last().unwrap().until, day().until);
    assert!(sink.batches.iter().all(|batch| batch.certified));
    assert_eq!(
        sink.batches
            .iter()
            .map(|batch| batch.events.len())
            .sum::<usize>(),
        300
    );
}

#[tokio::test(start_paused = true)]
async fn a_held_range_certifies_without_fetching() {
    let mut factory = EventFactory::new();
    let events = factory.spread(day(), 400);
    let relay = ModelRelay::holding(events.clone());

    let (report, sink) = compare(&relay, day(), &local(&events), policy(2_048)).await;

    assert_eq!(report.end, CompareEnd::Finished);
    assert_eq!(report.stats.fetches, 0);
    assert_eq!(report.stats.missing, 0);
    assert!(!report.certified.is_empty());
    assert_contiguous(&report.certified, day().since);
    assert_eq!(report.certified.last().unwrap().until, day().until);
    assert_eq!(sink.batches.len(), report.certified.len());
    for (batch, window) in sink.batches.iter().zip(&report.certified) {
        assert_eq!((batch.window.since, batch.window.until), (window.since, window.until));
        assert_eq!(window.events, 0);
    }
    assert!(
        sink.batches
            .iter()
            .all(|batch| batch.certified && batch.events.is_empty())
    );
}

#[tokio::test(start_paused = true)]
async fn a_withheld_id_leaves_its_window_unproven() {
    let mut factory = EventFactory::new();
    let events = factory.spread(day(), 40);
    let mut relay = ModelRelay::holding(events.clone());
    relay.withheld.insert(events[25].id);
    // Small windows: a set over ten halves.
    let mut policy = policy(2_048);
    policy.set_limit = 10;

    let (report, sink) = compare(&relay, day(), &[], policy).await;

    assert_eq!(report.end, CompareEnd::Withheld);
    assert_contiguous(&report.certified, day().since);
    let proven_until = report.certified.last().unwrap().until;
    assert!(proven_until < events[25].created_at.as_secs());
    let last = sink.batches.last().unwrap();
    assert!(
        !last.certified,
        "the window holding the withheld id is certified"
    );
    assert!(last.window.since <= events[25].created_at.as_secs());
    assert!(
        last.events.iter().all(|event| event.id != events[25].id),
        "a withheld event was admitted"
    );
}

#[tokio::test(start_paused = true)]
async fn a_second_over_the_budget_is_taken_in_parts() {
    let mut factory = EventFactory::new();
    let second = T0 + 100;
    let events = (0..10).map(|_| factory.event(second)).collect::<Vec<_>>();
    let relay = ModelRelay::holding(events);
    let range = SweepRange {
        since: second,
        until: second,
    };
    let mut held = Vec::new();
    let mut ends = Vec::new();
    for _ in 0..5 {
        let (report, sink) = compare(&relay, range, &held, policy(4)).await;
        ends.push(report.end);
        for batch in &sink.batches {
            held.extend(local(&batch.events));
        }
        held.sort();
        if report.end == CompareEnd::Finished {
            break;
        }
        assert!(report.certified.is_empty());
    }
    assert_eq!(
        ends,
        [
            CompareEnd::BudgetSpent,
            CompareEnd::BudgetSpent,
            CompareEnd::Finished
        ]
    );
    assert_eq!(held.len(), 10);
    let fetched = relay.fetched();
    assert_eq!(fetched.len(), 10, "an id was fetched twice");
}

#[tokio::test(start_paused = true)]
async fn a_rate_limited_comparison_waits_then_answers() {
    let mut factory = EventFactory::new();
    let mut relay = ModelRelay::holding(factory.spread(day(), 20));
    relay.limited = [0, 1].into_iter().collect();

    let started = Instant::now();
    let (report, _sink) = compare(&relay, day(), &[], policy(2_048)).await;

    assert_eq!(report.end, CompareEnd::Finished);
    assert_eq!(report.stats.rate_limited_waits, 2);
    assert!(!report.rate_limited);
    assert_eq!(started.elapsed(), Duration::from_secs(3));
}

#[tokio::test(start_paused = true)]
async fn a_relay_that_keeps_rate_limiting_ends_rate_limited() {
    let mut factory = EventFactory::new();
    let mut relay = ModelRelay::holding(factory.spread(day(), 20));
    relay.limited = (0..100).collect();

    let (report, _sink) = compare(&relay, day(), &[], policy(2_048)).await;

    assert_eq!(report.end, CompareEnd::RateLimited);
    assert!(report.rate_limited);
    assert!(report.certified.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_relay_without_nip77_ends_unsupported() {
    let mut factory = EventFactory::new();
    let mut relay = ModelRelay::holding(factory.spread(day(), 20));
    relay.unsupported = true;

    let (report, sink) = compare(&relay, day(), &[], policy(2_048)).await;

    assert_eq!(report.end, CompareEnd::Unsupported);
    assert!(sink.batches.is_empty());
}

#[tokio::test(start_paused = true)]
async fn fetches_name_at_most_the_relay_cap() {
    let mut factory = EventFactory::new();
    let mut relay = ModelRelay::holding(factory.spread(day(), 120));
    relay.max_limit = Some(50);
    let mut wanted = relay.events.iter().map(|event| event.id).collect::<Vec<_>>();
    wanted.sort();

    let (report, _sink) = compare(&relay, day(), &[], policy(2_048)).await;

    assert_eq!(report.end, CompareEnd::Finished);
    assert_eq!(report.stats.fetches, 3);
    assert_eq!(relay.fetched().len(), 120);
    let chunks = relay.fetch_chunks.lock().unwrap();
    assert_eq!(chunks.iter().map(Vec::len).collect::<Vec<_>>(), [50, 50, 20]);
    assert_eq!(chunks.concat(), wanted);
}

#[tokio::test(start_paused = true)]
async fn the_deadline_pauses_the_call() {
    let mut factory = EventFactory::new();
    let relay = ModelRelay::holding(factory.spread(day(), 20));
    let mut sink = RecordingSink::default();
    let report = run_comparison(
        CompareRequest {
            route: route(),
            range: day(),
            local: &[],
            deadline: Some(Instant::now()),
            policy: policy(2_048),
        },
        &relay,
        &mut sink,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.end, CompareEnd::DeadlineReached);
    assert_eq!(report.stats.answers, 0);
}

/// A fetch the deadline cuts is interrupted and awaited, so the bytes it read
/// reach the report; a relay that cannot interrupt has it dropped, unmetered.
#[tokio::test(start_paused = true)]
async fn a_cut_fetch_reports_what_it_read() {
    for interruptible in [true, false] {
        let mut factory = EventFactory::new();
        let relay = ModelRelay {
            hold_fetches: true,
            read_until_cut: 4_096,
            interruptible,
            ..ModelRelay::holding(factory.spread(day(), 20))
        };
        let mut sink = RecordingSink::default();
        let started = Instant::now();
        let report = run_comparison(
            CompareRequest {
                route: route(),
                range: day(),
                local: &[],
                deadline: Some(started + Duration::from_secs(2)),
                policy: policy(2_048),
            },
            &relay,
            &mut sink,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(report.end, CompareEnd::DeadlineReached);
        assert!(report.certified.is_empty() && sink.batches.is_empty());
        assert_eq!(relay.fetched().len(), 20, "the cut fetch went out");
        let read = if interruptible { 4_096 } else { 0 };
        assert_eq!(
            report.unadmitted_bytes, read,
            "interruptible: {interruptible}"
        );
        assert_eq!(started.elapsed(), Duration::from_secs(2));
    }
}

#[tokio::test(start_paused = true)]
async fn a_stopped_fetch_preserves_its_uncertified_prefix() {
    for stop in ["bytes", "restricted", "disconnected", "rate_limited"] {
        let events = signed_spread(day(), 6);
        let mut by_id = events.clone();
        by_id.sort_by_key(|event| event.id);
        let first = by_id[..2].to_vec();
        let first_bytes: u64 = first.iter().map(|event| event.as_json().len() as u64).sum();
        let relay = ModelRelay::holding(events);
        relay.fetch_replies.lock().unwrap().push_back(IdsReply::Answered(first.clone()));
        let mut limits = policy(10);
        limits.ids_per_request = 2;
        let expected = match stop {
            "bytes" => {
                limits.max_bytes = first_bytes;
                CompareEnd::BudgetSpent
            }
            "restricted" => {
                let reason = ClosedReason(Some(TransportEndpointRejectionCategory::Restricted));
                relay.fetch_replies.lock().unwrap().push_back(IdsReply::Closed(reason));
                CompareEnd::Refused(reason)
            }
            "disconnected" => {
                relay.fetch_replies.lock().unwrap().push_back(IdsReply::Unreachable(UnreachableKind::Disconnected));
                CompareEnd::Unreachable(UnreachableKind::Disconnected)
            }
            "rate_limited" => {
                limits.pacing.max_rate_limit_waits = 1;
                for _ in 0..2 {
                    relay.fetch_replies.lock().unwrap().push_back(IdsReply::Closed(ClosedReason(Some(TransportEndpointRejectionCategory::RateLimited))));
                }
                CompareEnd::RateLimited
            }
            _ => unreachable!(),
        };

        let started = Instant::now();
        let (report, sink) = compare(&relay, day(), &[], limits).await;

        assert_eq!(report.end, expected, "{stop}");
        assert_eq!(report.rate_limited, stop == "rate_limited");
        assert!(report.certified.is_empty(), "{stop}");
        assert_eq!(sink.batches.len(), 1, "{stop}");
        let batch = &sink.batches[0];
        assert_eq!(batch.window, day());
        assert!(!batch.certified, "{stop}");
        let mut expected = first;
        expected.sort_by_key(|event| (event.created_at, event.id));
        assert_eq!(batch.events, expected, "{stop}");
        assert_eq!(report.stats.events, 2, "{stop}");
        assert_eq!(sink.bytes + report.unadmitted_bytes, first_bytes, "{stop}");
        let chunks = relay.fetch_chunks.lock().unwrap();
        assert_eq!(chunks.len(), match stop { "bytes" => 1, "rate_limited" => 3, _ => 2 }, "{stop}");
        if stop == "rate_limited" {
            assert_eq!(chunks[1], chunks[2], "retry the same unfinished ids");
            assert_eq!(report.stats.rate_limited_waits, 1);
            assert_eq!(started.elapsed(), Duration::from_secs(1));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn sink_failure_never_certifies_a_complete_or_partial_window() {
    struct RejectingSink(Vec<Batch>, u64);
    #[async_trait]
    impl CompareSink for RejectingSink {
        async fn admit(&mut self, window: SweepRange, certified: bool, events: Vec<Event>, bytes: u64) -> Result<(), SweepSinkError> {
            self.0.push(Batch { window, certified, events });
            self.1 += bytes;
            Err(SweepSinkError)
        }
    }

    for partial in [false, true] {
        let events = signed_spread(day(), 4);
        let mut by_id = events.clone();
        by_id.sort_by_key(|event| event.id);
        let relay = ModelRelay::holding(events);
        let mut limits = policy(10);
        limits.ids_per_request = 2;
        if partial {
            relay.fetch_replies.lock().unwrap().extend([
                IdsReply::Answered(by_id[..2].to_vec()),
                IdsReply::Unreachable(UnreachableKind::Disconnected),
            ]);
        }
        let mut sink = RejectingSink(Vec::new(), 0);
        let report = run_comparison(
            CompareRequest { route: route(), range: day(), local: &[], deadline: None, policy: limits },
            &relay, &mut sink, &CancellationToken::new(),
        ).await;

        assert_eq!(report.end, CompareEnd::SinkFailed, "partial: {partial}");
        assert!(report.certified.is_empty());
        assert_eq!(report.stats.events, 0);
        assert_eq!(sink.0.len(), 1);
        assert_eq!(sink.0[0].window, day());
        assert_eq!(sink.0[0].certified, !partial);
        let mut expected = if partial { by_id[..2].to_vec() } else { by_id };
        expected.sort_by_key(|event| (event.created_at, event.id));
        let expected_bytes: u64 = expected.iter().map(|event| event.as_json().len() as u64).sum();
        assert_eq!(sink.0[0].events, expected);
        assert_eq!(sink.1 + report.unadmitted_bytes, expected_bytes);
    }
}

#[tokio::test(start_paused = true)]
async fn set_limits_and_spent_budgets_leave_saturated_seconds_unproven() {
    let second = SweepRange { since: T0, until: T0 };
    for count in [4, 5] {
        let events = signed_spread(second, count);
        let relay = ModelRelay::holding(events);
        let mut limits = policy(10);
        limits.set_limit = 4;
        let (report, sink) = compare(&relay, second, &[], limits).await;
        assert_eq!(*relay.comparisons.lock().unwrap(), [(second, 5)]);
        if count == 4 {
            assert_eq!(report.end, CompareEnd::Finished);
            assert_eq!(report.certified, [CertifiedWindow { since: T0, until: T0, events: 4 }]);
            assert_eq!(sink.batches[0].events.len(), 4);
            assert!(sink.batches[0].certified);
        } else {
            assert_eq!(report.end, CompareEnd::SaturatedWindow { second: T0 });
            assert!(report.certified.is_empty() && sink.batches.is_empty());
            assert!(relay.fetched().is_empty());
        }
    }

    let first = signed_spread(second, 2);
    let later = signed_spread(SweepRange { since: T0 + 1, until: T0 + 1 }, 10);
    let relay = ModelRelay::holding(first.iter().chain(&later).cloned().collect());
    let (report, sink) = compare(&relay, SweepRange { since: T0, until: T0 + 1 }, &[], policy(4)).await;
    assert_eq!(report.end, CompareEnd::BudgetSpent);
    assert_eq!(report.certified, [CertifiedWindow { since: T0, until: T0, events: 2 }]);
    assert_eq!(sink.batches.len(), 1);
    assert!(sink.batches[0].certified);
    assert_eq!(relay.fetch_chunks.lock().unwrap().len(), 1);
    assert_eq!(relay.fetched().into_iter().collect::<HashSet<_>>(), first.iter().map(|event| event.id).collect());
}

#[tokio::test(start_paused = true)]
async fn only_requested_route_events_can_satisfy_a_difference() {
    let keys = Keys::generate();
    let event = |kind: u16, group: [u8; 32], at: u64, content: &str| {
        EventBuilder::new(Kind::from(kind), content)
            .tags([Tag::custom("h", [hex::encode(group)])])
            .custom_created_at(Timestamp::from_secs(at))
            .finalize(&keys).unwrap()
    };
    let mut ties = [event(445, GROUP, T0 + 1, "tie a"), event(445, GROUP, T0 + 1, "tie b")];
    ties.sort_by_key(|event| event.id);
    let good = [event(445, GROUP, T0, "first"), ties[0].clone(), ties[1].clone(), event(445, GROUP, T0 + DAY - 1, "last")];
    let foreign = [
        event(445, [8; 32], T0, "wrong group"),
        event(1, GROUP, T0, "wrong kind"),
        event(445, GROUP, T0 - 1, "before range"),
        event(445, GROUP, T0 + DAY, "after range"),
    ];
    let unsolicited = event(445, GROUP, T0 + 1, "not requested");
    // All distinct signed events can reach the SDK collector when optional
    // subscription-filter verification is disabled (its default). Its set
    // deduplicates identical events before this boundary.
    let inventory = good.iter().chain(&foreign).cloned().collect();
    let relay = ModelRelay::holding(inventory);
    relay.compare_replies.lock().unwrap().push_back(CompareReply::Compared {
        missing: good.iter().chain(&foreign).map(|event| event.id).collect(),
        relay_set: good.len() + foreign.len(),
    });
    let incoming = foreign.iter().cloned().chain([unsolicited]).chain(good.iter().rev().cloned()).collect::<Vec<_>>();
    let incoming_bytes: u64 = incoming.iter().map(|event| event.as_json().len() as u64).sum();
    relay.fetch_replies.lock().unwrap().push_back(IdsReply::Answered(incoming));
    let (report, sink) = compare(&relay, day(), &[], policy(20)).await;
    assert_eq!(report.end, CompareEnd::Withheld);
    assert!(report.certified.is_empty());
    assert_eq!(sink.batches.len(), 1);
    assert!(!sink.batches[0].certified);
    assert_eq!(sink.batches[0].events, good);
    assert_eq!(sink.bytes + report.unadmitted_bytes, incoming_bytes);
}
