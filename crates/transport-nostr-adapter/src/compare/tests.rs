//! The comparison against a model relay that answers NIP-77 as strfry does:
//! its set for a window is every matching event, newest first, as far as the
//! comparison's limit, and a fetch by id returns the named events it holds.

use std::collections::{BTreeSet, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use nostr::prelude::{Keys, Kind, PublicKey, Signature, Tag, Timestamp};

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
        if let Some(reason) = self.arrive() {
            return CompareReply::Closed(reason);
        }
        if self.unsupported {
            return CompareReply::Unsupported;
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
        if let Some(reason) = self.arrive() {
            return IdsReply::Closed(reason);
        }
        self.fetched.lock().unwrap().extend_from_slice(ids);
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
    assert_contiguous(&report.certified, day().since);
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

    let (report, _sink) = compare(&relay, day(), &[], policy(2_048)).await;

    assert_eq!(report.end, CompareEnd::Finished);
    assert_eq!(report.stats.rate_limited_waits, 2);
    assert!(!report.rate_limited);
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

    let (report, _sink) = compare(&relay, day(), &[], policy(2_048)).await;

    assert_eq!(report.end, CompareEnd::Finished);
    assert_eq!(report.stats.fetches, 3);
    assert_eq!(relay.fetched().len(), 120);
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
