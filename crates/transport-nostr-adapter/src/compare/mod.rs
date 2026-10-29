//! NIP-77 comparison of one route's range on one relay, oldest first (#2660
//! phase 4).
//!
//! One call compares one route's inclusive `created_at` range on one relay
//! with the caller's local set, a window at a time from the oldest end, and
//! fetches each window's difference by id:
//!
//! - A window's comparison names the ids the relay holds there that the local
//!   set lacks. A relay set that reaches the truncation limit
//!   ([`COMPARE_SET_LIMIT`]) may hide more, so it proves nothing and the
//!   window halves. A window starts with at most half that many local items.
//! - A difference larger than what the call may still fetch narrows the window
//!   before anything is fetched, so a window's whole difference is fetched in
//!   one go.
//! - Once every id a window named is fetched, its events go to the caller's
//!   [`CompareSink`] with the window certified: every event the relay holds in
//!   it is now held locally or among those events.
//! - When the call stops inside a window (its budget, its deadline, a relay
//!   that withholds an id it named, a refusal), what that window fetched still
//!   goes to the sink, uncertified. Ids carry no `created_at` until fetched, so
//!   the certified prefix ends below that window. The caller holds those events
//!   from then on, so the next call's comparison no longer names them: a large
//!   difference finishes over several calls, and nothing is fetched twice.
//!
//! The call schedules nothing and keeps no cursor. Its caller (the recovery
//! runner) passes the range still owed and what it holds there, and reads the
//! [`CompareReport`].

use std::collections::HashSet;

use async_trait::async_trait;
use cgka_traits::transport_adapter::TransportEndpointRejectionCategory;
use nostr::prelude::{Event, EventId};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::sweep::{
    ClosedReason, RelayCaps, SweepPolicy, SweepRange, SweepRoute, SweepSinkError, UnreachableKind,
};

#[cfg(test)]
mod tests;

/// The most items a relay's set for one window may hold and still prove it:
/// the storage inventory's ceiling, which relays apply too. A comparison asks
/// for one more, so a set that reaches the limit shows.
pub const COMPARE_SET_LIMIT: usize = 16_384;

/// Ids one fetch names when the relay publishes no NIP-11 cap.
pub const COMPARE_IDS_PER_REQUEST: usize = 500;

/// One event the caller already holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalItem {
    pub created_at: u64,
    pub id: EventId,
}

/// A relay's answer to one comparison.
#[derive(Debug)]
pub enum CompareReply {
    /// The relay compared its set for the window with the local one.
    Compared {
        /// Ids the relay holds that the local set lacks.
        missing: Vec<EventId>,
        /// Items in the relay's set, as far as the comparison's limit.
        relay_set: usize,
    },
    /// The relay refused the comparison (NEG-ERR, or its NEG cap).
    Closed(ClosedReason),
    /// The relay does not speak NIP-77, or broke its protocol.
    Unsupported,
    Unreachable(UnreachableKind),
}

/// A relay's answer to one fetch by id.
#[derive(Debug)]
pub enum IdsReply {
    /// The relay reached EOSE: every event it sent.
    Answered(Vec<Event>),
    Closed(ClosedReason),
    Unreachable(UnreachableKind),
}

/// One relay, as a comparison sees it. Implementations keep their connections
/// behind the dial-safety chokepoint (`RelaySafetyPolicy`).
#[async_trait]
pub trait CompareRelay: Send + Sync {
    fn caps(&self) -> RelayCaps;

    /// A dry-run NIP-77 comparison of `route`'s events in `window` with
    /// `local`, its filter limited to `limit`.
    async fn compare(
        &self,
        route: SweepRoute,
        window: SweepRange,
        local: &[LocalItem],
        limit: usize,
    ) -> CompareReply;

    /// One fetch of `ids` among `route`'s events in `window`, closed at its
    /// EOSE.
    async fn fetch_ids(&self, route: SweepRoute, window: SweepRange, ids: &[EventId]) -> IdsReply;

    /// Event JSON bytes the relay sent since the last call, as
    /// [`SweepRelay::take_fetched_bytes`](crate::sweep::SweepRelay) counts
    /// them. Zero for a relay that does not meter what it reads; the call then
    /// counts the events it gets.
    fn take_fetched_bytes(&self) -> u64 {
        0
    }
}

/// Receives each window's fetched events, oldest first (`created_at`, then
/// id). A process that dies before a window reaches its sink fetches that
/// window again, so the sink must tolerate a repeat.
#[async_trait]
pub trait CompareSink: Send {
    /// `certified`: every event the relay holds in `window` is held locally or
    /// among `events`. Otherwise the window stays unproven and `events` are
    /// only what it fetched there before the call stopped. `fetched_bytes`
    /// are the event bytes the relay sent since the last batch, whether a
    /// reply kept them or not.
    async fn admit(
        &mut self,
        window: SweepRange,
        certified: bool,
        events: Vec<Event>,
        fetched_bytes: u64,
    ) -> Result<(), SweepSinkError>;
}

/// Tunables.
#[derive(Clone, Copy, Debug)]
pub struct ComparePolicy {
    /// See [`COMPARE_SET_LIMIT`].
    pub set_limit: usize,
    /// Ids one fetch names when the relay publishes no cap; otherwise its cap.
    pub ids_per_request: usize,
    /// The most events one call fetches, and the event bytes after which it
    /// asks for no more.
    pub max_events: usize,
    pub max_bytes: u64,
    /// Request pacing and refusal waits, as a sweep applies them; its slicing
    /// fields are not read.
    pub pacing: SweepPolicy,
}

impl ComparePolicy {
    pub fn new(max_events: usize, max_bytes: u64) -> Self {
        Self {
            set_limit: COMPARE_SET_LIMIT,
            ids_per_request: COMPARE_IDS_PER_REQUEST,
            max_events,
            max_bytes,
            pacing: SweepPolicy::default(),
        }
    }
}

/// One call's work.
#[derive(Clone, Copy, Debug)]
pub struct CompareRequest<'a> {
    pub route: SweepRoute,
    pub range: SweepRange,
    /// What the caller holds of `route`, sorted by `created_at`. Items outside
    /// `range` are ignored.
    pub local: &'a [LocalItem],
    /// The call's time budget. Reaching it is a pause, not a failure.
    pub deadline: Option<Instant>,
    pub policy: ComparePolicy,
}

/// Why a call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareEnd {
    /// Every window of the range is certified.
    Finished,
    DeadlineReached,
    Cancelled,
    /// The call fetched as much as its policy allows.
    BudgetSpent,
    /// The relay named an id in a comparison and did not return it.
    Withheld,
    /// One second's relay set reached the truncation limit.
    SaturatedWindow {
        second: u64,
    },
    /// The relay kept refusing with `rate-limited:`.
    RateLimited,
    Refused(ClosedReason),
    /// The relay does not speak NIP-77.
    Unsupported,
    Unreachable(UnreachableKind),
    SinkFailed,
}

impl CompareEnd {
    pub fn label(self) -> &'static str {
        match self {
            Self::Finished => "finished",
            Self::DeadlineReached => "deadline",
            Self::Cancelled => "cancelled",
            Self::BudgetSpent => "budget_spent",
            Self::Withheld => "withheld",
            Self::SaturatedWindow { .. } => "saturated_window",
            Self::RateLimited => "rate_limited",
            Self::Refused(_) => "refused",
            Self::Unsupported => "unsupported",
            Self::Unreachable(_) => "unreachable",
            Self::SinkFailed => "sink_failed",
        }
    }
}

/// A window the call certified on its relay. With the caller's (route, relay)
/// it is one coverage-ledger row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertifiedWindow {
    pub since: u64,
    pub until: u64,
    /// Events fetched for it.
    pub events: u32,
}

/// Aggregate counts for one call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompareStats {
    pub requests: u32,
    pub comparisons: u32,
    pub narrowings: u32,
    pub fetches: u32,
    /// Answers the relay gave (comparisons and fetches).
    pub answers: u32,
    pub rate_limited_waits: u32,
    pub blocked_waits: u32,
    /// Ids the relay named that the local set lacked.
    pub missing: u64,
    /// Events fetched and handed to the sink.
    pub events: u64,
}

#[derive(Clone, Debug)]
pub struct CompareReport {
    /// Windows certified by this call, oldest first and contiguous from the
    /// range's start.
    pub certified: Vec<CertifiedWindow>,
    pub end: CompareEnd,
    /// The relay's last reply was a `rate-limited:` refusal.
    pub rate_limited: bool,
    /// Event bytes the relay sent that no batch handed to the sink carried.
    pub unadmitted_bytes: u64,
    pub stats: CompareStats,
}

/// Why a wait stopped early.
enum Interrupt {
    Cancelled,
    Deadline,
}

impl From<Interrupt> for CompareEnd {
    fn from(interrupt: Interrupt) -> Self {
        match interrupt {
            Interrupt::Cancelled => Self::Cancelled,
            Interrupt::Deadline => Self::DeadlineReached,
        }
    }
}

/// What to do after a refusal.
enum Refusal {
    Retry,
    Stop(CompareEnd),
}

struct Comparison<'a, R: ?Sized, K: ?Sized> {
    request: CompareRequest<'a>,
    relay: &'a R,
    sink: &'a mut K,
    cancel: &'a CancellationToken,
    caps: RelayCaps,
    certified: Vec<CertifiedWindow>,
    stats: CompareStats,
    last_request: Option<Instant>,
    rate_limited_in_a_row: u32,
    blocked_in_a_row: u32,
    events_left: usize,
    bytes_left: u64,
    /// Event bytes read since the last batch reached the sink.
    pending_bytes: u64,
}

/// Run one comparison call: certify what it can of `request.range` on
/// `relay`, from the range's start.
pub async fn run_comparison<R, K>(
    request: CompareRequest<'_>,
    relay: &R,
    sink: &mut K,
    cancel: &CancellationToken,
) -> CompareReport
where
    R: CompareRelay + ?Sized,
    K: CompareSink + ?Sized,
{
    let mut call = Comparison {
        request,
        relay,
        sink,
        cancel,
        caps: relay.caps(),
        certified: Vec::new(),
        stats: CompareStats::default(),
        last_request: None,
        rate_limited_in_a_row: 0,
        blocked_in_a_row: 0,
        events_left: request.policy.max_events,
        bytes_left: request.policy.max_bytes,
        pending_bytes: 0,
    };
    let end = call.run().await;
    // A fetch the deadline or a cancellation dropped never reported its bytes.
    call.read_bytes(0);
    let report = CompareReport {
        certified: call.certified,
        end,
        rate_limited: call.rate_limited_in_a_row > 0,
        unadmitted_bytes: call.pending_bytes,
        stats: call.stats,
    };
    tracing::debug!(
        target: "transport_nostr_adapter::compare",
        method = "run_comparison",
        end = end.label(),
        refusal = match end {
            CompareEnd::Refused(reason) => reason.label(),
            CompareEnd::Unreachable(kind) => kind.as_str(),
            _ => "none",
        },
        windows = report.certified.len(),
        range_seconds = request.range.until.saturating_sub(request.range.since),
        requests = report.stats.requests,
        comparisons = report.stats.comparisons,
        narrowings = report.stats.narrowings,
        fetches = report.stats.fetches,
        answers = report.stats.answers,
        rate_limited_waits = report.stats.rate_limited_waits,
        blocked_waits = report.stats.blocked_waits,
        missing = report.stats.missing,
        events = report.stats.events,
    );
    report
}

impl<'a, R, K> Comparison<'a, R, K>
where
    R: CompareRelay + ?Sized,
    K: CompareSink + ?Sized,
{
    async fn run(&mut self) -> CompareEnd {
        let range = self.request.range;
        let set_limit = self.request.policy.set_limit.max(1);
        let mut since = range.since;
        let mut width = range.until.saturating_sub(range.since).saturating_add(1);
        loop {
            if since > range.until {
                return CompareEnd::Finished;
            }
            if self.cancel.is_cancelled() {
                return CompareEnd::Cancelled;
            }
            if self.past_deadline() {
                return CompareEnd::DeadlineReached;
            }
            if self.events_left == 0 || self.bytes_left == 0 {
                return CompareEnd::BudgetSpent;
            }
            let window = SweepRange {
                since,
                until: self.window_until(since, width),
            };
            let local = self.local_in(window);
            let reply = match self
                .ask(
                    self.relay
                        .compare(self.request.route, window, local, set_limit + 1),
                )
                .await
            {
                Ok(reply) => reply,
                Err(interrupt) => return interrupt.into(),
            };
            self.stats.comparisons += 1;
            let (mut missing, relay_set) = match reply {
                CompareReply::Compared { missing, relay_set } => (missing, relay_set),
                CompareReply::Closed(reason) => match self.refused(reason).await {
                    Refusal::Retry => continue,
                    Refusal::Stop(end) => return end,
                },
                CompareReply::Unsupported => return CompareEnd::Unsupported,
                CompareReply::Unreachable(kind) => return CompareEnd::Unreachable(kind),
            };
            self.answered();
            let span = window.until - window.since + 1;
            if relay_set > set_limit {
                // The set may hide items: it proves nothing.
                if span == 1 {
                    return CompareEnd::SaturatedWindow {
                        second: window.since,
                    };
                }
                self.stats.narrowings += 1;
                width = span / 2;
                continue;
            }
            missing.sort_unstable();
            missing.dedup();
            if missing.len() > self.events_left {
                if span > 1 {
                    // Narrow to what the call can still fetch, at least by
                    // half: differences need not be spread evenly.
                    self.stats.narrowings += 1;
                    let fits = u128::from(span) * self.events_left as u128 / missing.len() as u128;
                    width = u64::try_from(fits).unwrap_or(u64::MAX).min(span / 2).max(1);
                    continue;
                }
                // One second holds more than the call may still fetch. Only a
                // call that has fetched nothing yet takes part of it; the next
                // call no longer names what it took.
                if self.events_left < self.request.policy.max_events {
                    return CompareEnd::BudgetSpent;
                }
                missing.truncate(self.events_left);
                self.stats.missing += missing.len() as u64;
                return self
                    .fetch(window, missing, false)
                    .await
                    .unwrap_or(CompareEnd::BudgetSpent);
            }
            self.stats.missing += missing.len() as u64;
            let found = missing.len();
            if let Some(end) = self.fetch(window, missing, true).await {
                return end;
            }
            let Some(next) = window.until.checked_add(1) else {
                return CompareEnd::Finished;
            };
            since = next;
            // Widen while the relay's sets and differences stay small.
            width = if found.saturating_mul(4) <= self.events_left
                && relay_set.saturating_mul(4) < set_limit
            {
                span.saturating_mul(2)
            } else {
                span
            };
        }
    }

    /// The window's last second: `width` from `since`, within the range, and
    /// holding at most half the set limit of local items.
    fn window_until(&self, since: u64, width: u64) -> u64 {
        let until = since
            .saturating_add(width.max(1) - 1)
            .min(self.request.range.until);
        let half = (self.request.policy.set_limit / 2).max(1);
        let local = self.request.local;
        let first = local.partition_point(|item| item.created_at < since);
        match local.get(first + half) {
            Some(item) if item.created_at <= until => item.created_at.saturating_sub(1).max(since),
            _ => until,
        }
    }

    fn local_in(&self, window: SweepRange) -> &'a [LocalItem] {
        let local = self.request.local;
        let first = local.partition_point(|item| item.created_at < window.since);
        let end = local.partition_point(|item| item.created_at <= window.until);
        &local[first..end.max(first)]
    }

    fn ids_per_request(&self) -> usize {
        self.caps
            .max_limit
            .map_or(self.request.policy.ids_per_request, |cap| cap as usize)
            .max(1)
    }

    /// Fetch `ids` from `window` and hand what came back to the sink: with the
    /// window certified when `certify` and every id came back. `None` when the
    /// window was certified; otherwise how the call ends.
    async fn fetch(
        &mut self,
        window: SweepRange,
        ids: Vec<EventId>,
        certify: bool,
    ) -> Option<CompareEnd> {
        let route = self.request.route;
        let per_request = self.ids_per_request();
        let mut events: Vec<Event> = Vec::with_capacity(ids.len());
        let mut start = 0;
        while start < ids.len() {
            let chunk = &ids[start..(start + per_request).min(ids.len())];
            let reply = match self.ask(self.relay.fetch_ids(route, window, chunk)).await {
                Ok(reply) => reply,
                Err(interrupt) => return Some(self.stop(window, events, interrupt.into()).await),
            };
            self.stats.fetches += 1;
            let got = match reply {
                IdsReply::Answered(got) => got,
                IdsReply::Closed(reason) => {
                    self.read_bytes(0);
                    match self.refused(reason).await {
                        Refusal::Retry => continue,
                        Refusal::Stop(end) => return Some(self.stop(window, events, end).await),
                    }
                }
                IdsReply::Unreachable(kind) => {
                    self.read_bytes(0);
                    let end = CompareEnd::Unreachable(kind);
                    return Some(self.stop(window, events, end).await);
                }
            };
            self.answered();
            self.read_bytes(event_bytes(&got));
            let asked = chunk.iter().copied().collect::<HashSet<_>>();
            let mut kept = got
                .into_iter()
                .filter(|event| {
                    let at = event.created_at.as_secs();
                    asked.contains(&event.id)
                        && at >= window.since
                        && at <= window.until
                        && route.matches(event)
                })
                .collect::<Vec<_>>();
            kept.sort_by_key(|event| event.id);
            kept.dedup_by_key(|event| event.id);
            let short = kept.len() < chunk.len();
            self.events_left = self.events_left.saturating_sub(kept.len());
            events.extend(kept);
            start += chunk.len();
            if short {
                return Some(self.stop(window, events, CompareEnd::Withheld).await);
            }
            if self.bytes_left == 0 && start < ids.len() {
                return Some(self.stop(window, events, CompareEnd::BudgetSpent).await);
            }
        }
        if !certify {
            return Some(self.stop(window, events, CompareEnd::BudgetSpent).await);
        }
        let count = u32::try_from(events.len()).unwrap_or(u32::MAX);
        if !self.admit(window, true, events).await {
            return Some(CompareEnd::SinkFailed);
        }
        self.certified.push(CertifiedWindow {
            since: window.since,
            until: window.until,
            events: count,
        });
        None
    }

    /// End the call inside `window`: what it fetched there still reaches the
    /// sink, uncertified.
    async fn stop(
        &mut self,
        window: SweepRange,
        events: Vec<Event>,
        end: CompareEnd,
    ) -> CompareEnd {
        if events.is_empty() || self.admit(window, false, events).await {
            end
        } else {
            CompareEnd::SinkFailed
        }
    }

    async fn admit(&mut self, window: SweepRange, certified: bool, mut events: Vec<Event>) -> bool {
        events.sort_by_key(|event| (event.created_at, event.id));
        let fetched = events.len() as u64;
        let bytes = std::mem::take(&mut self.pending_bytes);
        if self
            .sink
            .admit(window, certified, events, bytes)
            .await
            .is_err()
        {
            return false;
        }
        self.stats.events += fetched;
        true
    }

    /// Count what the relay read: its own meter, or `kept` when it keeps none.
    fn read_bytes(&mut self, kept: u64) {
        let bytes = self.relay.take_fetched_bytes().max(kept);
        self.pending_bytes = self.pending_bytes.saturating_add(bytes);
        self.bytes_left = self.bytes_left.saturating_sub(bytes);
    }

    async fn refused(&mut self, reason: ClosedReason) -> Refusal {
        let pacing = self.request.policy.pacing;
        match reason.0 {
            Some(TransportEndpointRejectionCategory::RateLimited) => {
                if self.rate_limited_in_a_row >= pacing.max_rate_limit_waits {
                    return Refusal::Stop(CompareEnd::RateLimited);
                }
                let wait = pacing
                    .rate_limit_backoff
                    .saturating_mul(1 << self.rate_limited_in_a_row.min(16))
                    .min(pacing.max_rate_limit_backoff);
                self.rate_limited_in_a_row += 1;
                self.stats.rate_limited_waits += 1;
                match self.wait_until(Instant::now() + wait).await {
                    Ok(()) => Refusal::Retry,
                    Err(interrupt) => Refusal::Stop(interrupt.into()),
                }
            }
            Some(TransportEndpointRejectionCategory::Blocked)
                if self.blocked_in_a_row < pacing.blocked_retries =>
            {
                self.blocked_in_a_row += 1;
                self.stats.blocked_waits += 1;
                let wait = pacing.rate_limit_backoff.min(pacing.max_rate_limit_backoff);
                match self.wait_until(Instant::now() + wait).await {
                    Ok(()) => Refusal::Retry,
                    Err(interrupt) => Refusal::Stop(interrupt.into()),
                }
            }
            _ => Refusal::Stop(CompareEnd::Refused(reason)),
        }
    }

    fn answered(&mut self) {
        self.stats.answers += 1;
        self.rate_limited_in_a_row = 0;
        self.blocked_in_a_row = 0;
    }

    /// Pace, then run one relay request under the call's cancellation and
    /// deadline. A request cut by either is dropped.
    async fn ask<T>(&mut self, request: impl Future<Output = T>) -> Result<T, Interrupt> {
        if let Some(last) = self.last_request {
            self.wait_until(last + self.request.policy.pacing.min_request_interval)
                .await?;
        }
        self.last_request = Some(Instant::now());
        self.stats.requests += 1;
        let deadline = self.request.deadline;
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(Interrupt::Cancelled),
            () = sleep_until_deadline(deadline) => Err(Interrupt::Deadline),
            reply = request => Ok(reply),
        }
    }

    async fn wait_until(&self, at: Instant) -> Result<(), Interrupt> {
        if self.request.deadline.is_some_and(|deadline| at >= deadline) {
            // The wait would outlast the call: pause now rather than later.
            return Err(Interrupt::Deadline);
        }
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(Interrupt::Cancelled),
            () = tokio::time::sleep_until(at) => Ok(()),
        }
    }

    fn past_deadline(&self) -> bool {
        self.request
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
}

fn event_bytes(events: &[Event]) -> u64 {
    events
        .iter()
        .map(|event| event.as_json().len() as u64)
        .fold(0u64, u64::saturating_add)
}

async fn sleep_until_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}
