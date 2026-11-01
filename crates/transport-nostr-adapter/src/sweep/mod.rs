//! Time-sliced, resumable, oldest-first history sweep (#2660 phase 3).
//!
//! One sweep walks one route on one relay through one inclusive `created_at`
//! range, forward in time. Each step asks for a slice `[cursor, cursor + Δ)`
//! with one filter per REQ, and the REQ closes after its EOSE:
//!
//! - A reply proven complete is a covered slice. Its events go to the caller's
//!   [`SweepSink`] oldest first, then the cursor advances through the caller's
//!   [`SweepCursorStore`]. Nothing is held across slices, and a later call
//!   resumes at the stored cursor, so no completed slice is fetched twice.
//! - A full reply halves Δ and asks again; a nearly empty one doubles Δ for
//!   the next slice.
//! - A full one-second slice cannot be paged: both strfry and wok order events
//!   of one second by local insertion, not id. That second goes to
//!   [`SweepRelay::fetch_second`] (NIP-77 ids, then an ids fetch).
//!
//! Completeness ([`SliceProof`]) comes from counting: a reply below the
//! relay's NIP-11 `limitation.max_limit` (strfry 500, wok's marmot preset
//! 5,000), counting every EVENT the relay sent, valid or not; or, when the
//! relay publishes no cap, a reply below the largest full reply seen from it.
//! A NIP-67 `more` hint always splits, but no hint proves a slice: nostr-sdk
//! drops hints, so the SDK relay reads them off the wire, and there a misread
//! `finish` would skip history where a misread `more` only costs requests.
//! Requested limits are lowered silently, so the cap is read, never assumed. Each slice REQ asks for
//! exactly the cap with one filter, so on wok a reply below it was never cut
//! (its 10,000 per-REQ total cannot bind first).
//!
//! Known limit: strfry counts events this connection may not read toward the
//! cap without sending them, so a short page proves completeness only while the
//! swept kind is readable by everyone. Kind 445 is; a restricted-read kind
//! would need another proof (NIP-77) before it could be swept this way.
//!
//! The sweep schedules nothing. Its caller (the recovery runner, phase 4)
//! decides which route, relay and range to sweep, and reads the call's
//! [`SweepReport`]: the covered slices for the coverage ledger and one
//! [`SweepOutcomeKind`] for backoff.

use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::transport_adapter::TransportEndpointRejectionCategory;
use nostr::message::MachineReadablePrefix;
use nostr::prelude::{Event, Filter, Kind, SingleLetterTag, Timestamp};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "sdk")]
pub(crate) mod hint_tap;
#[cfg(feature = "sdk")]
mod sdk;
#[cfg(test)]
mod tests;

#[cfg(feature = "sdk")]
pub(crate) use sdk::NegFailure;
#[cfg(feature = "sdk")]
pub use sdk::SdkSweepRelay;

/// Marmot group message kind.
const GROUP_MESSAGE_KIND: u16 = 445;

/// NIP-59 gift wrap kind: an account inbox's events.
const GIFT_WRAP_KIND: u16 = 1059;

/// What one sweep or comparison walks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SweepRoute {
    /// A group's kind-445 events, by their 32-byte Nostr routing id (`#h`).
    Group { nostr_group_id: [u8; 32] },
    /// An account inbox's gift wraps, by the recipient's 32-byte public key
    /// (`#p`). Compared only, never swept: many inbox relays restrict who may
    /// read kind 1059, so a short page proves nothing there (see the module's
    /// known limit).
    Inbox { pubkey: [u8; 32] },
}

impl SweepRoute {
    /// The one filter a slice REQ carries.
    pub fn slice_filter(&self, since: u64, until: u64, limit: Option<u32>) -> Filter {
        let filter = self.second_filter(since, until);
        match limit {
            Some(limit) => filter.limit(limit as usize),
            None => filter,
        }
    }

    fn second_filter(&self, since: u64, until: u64) -> Filter {
        let (kind, tag, value) = match self {
            Self::Group { nostr_group_id } => (GROUP_MESSAGE_KIND, 'h', nostr_group_id),
            Self::Inbox { pubkey } => (GIFT_WRAP_KIND, 'p', pubkey),
        };
        Filter::new()
            .kind(Kind::from(kind))
            .custom_tag(
                SingleLetterTag::from_char(tag).expect("a valid single-letter tag"),
                hex::encode(value),
            )
            .since(Timestamp::from_secs(since))
            .until(Timestamp::from_secs(until))
    }

    /// Whether an event a relay returned belongs to this route.
    pub(crate) fn matches(&self, event: &Event) -> bool {
        let (kind, tag, value) = match self {
            Self::Group { nostr_group_id } => (GROUP_MESSAGE_KIND, "h", nostr_group_id),
            Self::Inbox { pubkey } => (GIFT_WRAP_KIND, "p", pubkey),
        };
        event.kind == Kind::from(kind)
            && event.tags.iter().any(|candidate| {
                let parts = candidate.as_slice();
                parts.len() >= 2
                    && parts[0] == tag
                    && hex::decode(&parts[1]).ok().as_deref() == Some(value.as_slice())
            })
    }
}

/// An inclusive `created_at` range, as relays read `since` and `until`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SweepRange {
    pub since: u64,
    pub until: u64,
}

/// What a relay says about its own limits, from its NIP-11 document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayCaps {
    /// `limitation.max_limit`: the most events one filter returns.
    pub max_limit: Option<u32>,
    /// NIP-77 is in `supported_nips`.
    pub negentropy: bool,
}

impl RelayCaps {
    /// Read the caps from a NIP-11 relay information document. Missing or
    /// malformed fields read as unknown, never as a guess.
    pub fn from_nip11(document: &serde_json::Value) -> Self {
        let max_limit = document
            .get("limitation")
            .and_then(|limitation| limitation.get("max_limit"))
            .and_then(serde_json::Value::as_u64)
            .filter(|limit| *limit > 0)
            .map(|limit| u32::try_from(limit).unwrap_or(u32::MAX));
        let negentropy = document
            .get("supported_nips")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|nips| nips.iter().any(|nip| nip.as_u64() == Some(77)));
        Self {
            max_limit,
            negentropy,
        }
    }

    /// [`Self::from_nip11`] over the document's JSON text.
    pub fn from_nip11_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str::<serde_json::Value>(json).map(|document| Self::from_nip11(&document))
    }
}

/// One slice REQ: a route's events in `[since, until]`, at most `limit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SliceQuery {
    pub route: SweepRoute,
    pub since: u64,
    pub until: u64,
    pub limit: Option<u32>,
}

impl SliceQuery {
    pub fn filter(&self) -> Filter {
        self.route.slice_filter(self.since, self.until, self.limit)
    }
}

/// Why a relay could not be asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnreachableKind {
    /// The relay did not answer before the request's own deadline.
    TimedOut,
    /// The connection dropped or never came up.
    Disconnected,
}

impl UnreachableKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::TimedOut => "timed_out",
            Self::Disconnected => "disconnected",
        }
    }
}

/// A relay's `CLOSED` reason, reduced to its machine-readable category. The
/// reason's text is never kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosedReason(pub Option<TransportEndpointRejectionCategory>);

impl ClosedReason {
    pub fn from_message(message: &str) -> Self {
        use MachineReadablePrefix as Prefix;
        Self(MachineReadablePrefix::parse(message).and_then(|prefix| {
            Some(match prefix {
                Prefix::Duplicate => TransportEndpointRejectionCategory::Duplicate,
                Prefix::Pow => TransportEndpointRejectionCategory::Pow,
                Prefix::Blocked => TransportEndpointRejectionCategory::Blocked,
                Prefix::RateLimited => TransportEndpointRejectionCategory::RateLimited,
                Prefix::Invalid => TransportEndpointRejectionCategory::Invalid,
                Prefix::Error => TransportEndpointRejectionCategory::Error,
                Prefix::Unsupported => TransportEndpointRejectionCategory::Unsupported,
                Prefix::AuthRequired => TransportEndpointRejectionCategory::AuthRequired,
                Prefix::Restricted => TransportEndpointRejectionCategory::Restricted,
                Prefix::Custom(_) => return None,
            })
        }))
    }

    pub(crate) fn label(self) -> &'static str {
        self.0
            .map_or("unclassified", TransportEndpointRejectionCategory::as_str)
    }
}

/// A relay's answer to one slice REQ.
#[derive(Debug)]
pub enum SliceReply {
    /// The relay reached EOSE. `received` counts every EVENT it sent for the
    /// REQ, including ones that failed validation, since those still count
    /// toward the relay's cap. Events it withheld are invisible here (see the
    /// module's known limit).
    Answered {
        events: Vec<Event>,
        received: usize,
        /// The relay said a cut left matching events unsent: NIP-67 `more`,
        /// or a reply past the requested limit. It splits the slice.
        more: bool,
    },
    /// The relay sent `CLOSED` before EOSE.
    Closed(ClosedReason),
    /// The relay never answered.
    Unreachable(UnreachableKind),
}

/// A relay's answer for every event of one second.
#[derive(Debug)]
pub enum SecondReply {
    /// Every event the relay holds for the second: its NIP-77 id set, all
    /// fetched.
    Complete(Vec<Event>),
    /// The relay has no NIP-77, or the id fetch came back short.
    Unproven,
    Closed(ClosedReason),
    Unreachable(UnreachableKind),
}

/// One relay, as a sweep sees it. Implementations issue one filter per REQ,
/// close it after EOSE, and keep their connections behind the dial-safety
/// chokepoint (`RelaySafetyPolicy`).
#[async_trait]
pub trait SweepRelay: Send + Sync {
    fn caps(&self) -> RelayCaps;

    async fn fetch_slice(&self, query: SliceQuery) -> SliceReply;

    /// Every event of `route` at `second`, for a second holding more events
    /// than one reply can.
    async fn fetch_second(&self, route: SweepRoute, second: u64, cap: Option<u32>) -> SecondReply;

    /// Event JSON bytes the relay sent since the last call, whether a reply
    /// kept them or not: duplicates, a reply a budget cut short, the chunks
    /// of a second that failed and an interrupted request included. Zero for
    /// a relay that does not meter what it reads; a caller budgeting bytes
    /// then counts the events it gets.
    fn take_fetched_bytes(&self) -> u64 {
        0
    }

    /// End the request in flight early, and every later one at once, so it
    /// returns and meters what it read instead of being dropped. `true` when
    /// the relay can: a sweep cut by its deadline or cancellation then waits
    /// up to [`INTERRUPT_GRACE`] for the request before dropping it. The
    /// default, `false`, has the request dropped at once.
    fn interrupt(&self) -> bool {
        false
    }
}

/// How long a cut request whose relay can end it ([`SweepRelay::interrupt`])
/// has to return before it is dropped anyway.
pub const INTERRUPT_GRACE: Duration = Duration::from_secs(1);

/// How a covered slice was proven complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SliceProof {
    /// Fewer events than the relay's NIP-11 `max_limit`.
    BelowCap { received: u32, cap: u32 },
    /// The relay publishes no cap; fewer events than a full reply it sent.
    BelowObserved { received: u32, observed: u32 },
    /// One second, through its NIP-77 id set.
    Negentropy,
}

/// A slice this relay has proven complete for the sweep's route. With the
/// caller's (route, relay) it is one coverage-ledger row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoveredSlice {
    pub since: u64,
    pub until: u64,
    pub proof: SliceProof,
    /// Events handed to the sink for this slice.
    pub events: u32,
}

/// Where a sweep stands, kept by the caller between calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SweepCursor {
    /// The first second not yet covered.
    pub next_since: u64,
    /// The slice width to try next, in seconds.
    pub delta: u64,
    /// Largest full reply seen from a relay with no published cap.
    pub observed_cap: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepStoreError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepSinkError;

/// Durable cursor for one (route, relay, range). A sweep saves only after the
/// sink admitted the slice the cursor passes.
#[async_trait]
pub trait SweepCursorStore: Send + Sync {
    async fn load(&self) -> Result<Option<SweepCursor>, SweepStoreError>;
    async fn save(&self, cursor: SweepCursor) -> Result<(), SweepStoreError>;
}

/// Receives each covered slice's events, oldest first (`created_at`, then id),
/// before the cursor passes them. A process that dies between the two fetches
/// that one slice again, so admission must tolerate a repeat.
#[async_trait]
pub trait SweepSink: Send {
    async fn admit(
        &mut self,
        slice: CoveredSlice,
        events: Vec<Event>,
    ) -> Result<(), SweepSinkError>;
}

/// Tunables. The defaults suit strfry and wok as deployed.
#[derive(Clone, Copy, Debug)]
pub struct SweepPolicy {
    /// Δ for a sweep with no stored cursor.
    pub initial_delta: u64,
    pub max_delta: u64,
    /// A reply under `cap / grow_below` events doubles Δ.
    pub grow_below: u32,
    /// `limit` to request from a relay that publishes no cap.
    pub unknown_cap_limit: u32,
    /// Least time between two REQs. wok's marmot preset allows 50 REQ/s per
    /// connection, which the sweep shares with live subscriptions.
    pub min_request_interval: Duration,
    /// First wait after a `rate-limited:` CLOSED; doubles per repeat.
    pub rate_limit_backoff: Duration,
    pub max_rate_limit_backoff: Duration,
    /// Consecutive rate-limited answers before the call gives the relay up.
    pub max_rate_limit_waits: u32,
    /// Waited retries of a `blocked:` CLOSED before it counts as a refusal.
    /// wok blocks transient conditions too (too many concurrent REQs).
    pub blocked_retries: u32,
}

impl Default for SweepPolicy {
    fn default() -> Self {
        Self {
            initial_delta: 24 * 60 * 60,
            max_delta: 32 * 24 * 60 * 60,
            grow_below: 4,
            unknown_cap_limit: 500,
            min_request_interval: Duration::from_millis(100),
            rate_limit_backoff: Duration::from_secs(1),
            max_rate_limit_backoff: Duration::from_secs(30),
            max_rate_limit_waits: 8,
            blocked_retries: 2,
        }
    }
}

/// One call's work.
#[derive(Clone, Copy, Debug)]
pub struct SweepRequest {
    pub route: SweepRoute,
    pub range: SweepRange,
    /// The call's time budget. Reaching it is a pause, not a failure.
    pub deadline: Option<Instant>,
    pub policy: SweepPolicy,
}

/// Why a call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SweepEnd {
    /// The cursor passed the range's end.
    Finished,
    /// The call's deadline came first.
    DeadlineReached,
    Cancelled,
    /// A saturated second this relay could not prove.
    SaturatedSecond {
        second: u64,
    },
    /// The relay kept refusing with `rate-limited:`.
    RateLimited,
    Refused(ClosedReason),
    Unreachable(UnreachableKind),
    SinkFailed,
    StoreFailed,
}

impl SweepEnd {
    fn label(self) -> &'static str {
        match self {
            Self::Finished => "finished",
            Self::DeadlineReached => "deadline",
            Self::Cancelled => "cancelled",
            Self::SaturatedSecond { .. } => "saturated_second",
            Self::RateLimited => "rate_limited",
            Self::Refused(_) => "refused",
            Self::Unreachable(_) => "unreachable",
            Self::SinkFailed => "sink_failed",
            Self::StoreFailed => "store_failed",
        }
    }
}

/// The issue's outcome table, one meaning each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SweepOutcomeKind {
    /// The cursor advanced (a cut mid-sweep included): reset backoff.
    Advanced,
    /// Caller cancellation after the cursor advanced.
    CancelledWithProgress,
    /// The relay answered and nothing was covered: spends the route's
    /// no-progress budget.
    AnsweredNoProgress,
    /// Unreachable or timed out before answering: relay health, not the route.
    RelayUnreachable,
    /// Refused (rate limiting that never cleared included): try other relays.
    Refused,
    /// Cancelled before anything was covered.
    Cancelled,
    /// The call's deadline came before the relay answered anything: neither
    /// the route's nor the relay's fault, so charge nothing.
    Unanswered,
    /// The range was already covered.
    NothingOwed,
    /// Local admission or cursor storage failed.
    LocalFailure,
}

/// Aggregate counts for one call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepStats {
    pub requests: u32,
    pub halvings: u32,
    pub growths: u32,
    pub rate_limited_waits: u32,
    pub blocked_waits: u32,
    pub saturated_seconds: u32,
    /// Answers the relay gave (slice replies and saturated-second replies).
    pub answers: u32,
    pub events: u64,
}

#[derive(Clone, Debug)]
pub struct SweepReport {
    /// Slices covered by this call, oldest first and contiguous.
    pub covered: Vec<CoveredSlice>,
    pub end: SweepEnd,
    /// The cursor as the call left it; `None` once the range is covered.
    pub cursor: Option<SweepCursor>,
    pub stats: SweepStats,
}

impl SweepReport {
    pub fn outcome(&self) -> SweepOutcomeKind {
        let progressed = !self.covered.is_empty();
        match self.end {
            SweepEnd::SinkFailed | SweepEnd::StoreFailed => SweepOutcomeKind::LocalFailure,
            SweepEnd::Cancelled if progressed => SweepOutcomeKind::CancelledWithProgress,
            _ if progressed => SweepOutcomeKind::Advanced,
            SweepEnd::Finished => SweepOutcomeKind::NothingOwed,
            SweepEnd::Cancelled => SweepOutcomeKind::Cancelled,
            SweepEnd::Unreachable(_) => SweepOutcomeKind::RelayUnreachable,
            SweepEnd::Refused(_) | SweepEnd::RateLimited => SweepOutcomeKind::Refused,
            SweepEnd::DeadlineReached if self.stats.answers == 0 => SweepOutcomeKind::Unanswered,
            SweepEnd::DeadlineReached | SweepEnd::SaturatedSecond { .. } => {
                SweepOutcomeKind::AnsweredNoProgress
            }
        }
    }
}

/// Why a wait or a request stopped early.
pub(crate) enum Interrupt {
    Cancelled,
    Deadline,
}

/// Run one relay request under a call's cancellation and deadline. A request
/// either cuts is interrupted rather than dropped when its relay can end it
/// (`interrupt` returns `true`): it then has [`INTERRUPT_GRACE`] to return,
/// so the relay meters the reply it was reading, and is dropped after that,
/// which closes its REQ. A cut request's reply is never used.
pub(crate) async fn ask_until_cut<T>(
    request: impl Future<Output = T>,
    cancel: &CancellationToken,
    deadline: Option<Instant>,
    interrupt: impl FnOnce() -> bool,
) -> Result<T, Interrupt> {
    let mut request = std::pin::pin!(request);
    let cut = tokio::select! {
        biased;
        () = cancel.cancelled() => Interrupt::Cancelled,
        () = sleep_until_deadline(deadline) => Interrupt::Deadline,
        reply = &mut request => return Ok(reply),
    };
    if interrupt() {
        let _ = tokio::time::timeout(INTERRUPT_GRACE, request).await;
    }
    Err(cut)
}

impl From<Interrupt> for SweepEnd {
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
    Stop(SweepEnd),
}

struct Sweep<'a, R: ?Sized, K: ?Sized, C: ?Sized> {
    request: SweepRequest,
    relay: &'a R,
    sink: &'a mut K,
    store: &'a C,
    cancel: &'a CancellationToken,
    caps: RelayCaps,
    cursor: SweepCursor,
    covered: Vec<CoveredSlice>,
    stats: SweepStats,
    last_request: Option<Instant>,
    rate_limited_in_a_row: u32,
    blocked_in_a_row: u32,
}

/// Run one sweep call: cover what it can of `request.range` on `relay`,
/// starting at the stored cursor.
pub async fn run_sweep<R, K, C>(
    request: SweepRequest,
    relay: &R,
    sink: &mut K,
    store: &C,
    cancel: &CancellationToken,
) -> SweepReport
where
    R: SweepRelay + ?Sized,
    K: SweepSink + ?Sized,
    C: SweepCursorStore + ?Sized,
{
    let fresh = SweepCursor {
        next_since: request.range.since,
        delta: request.policy.initial_delta.max(1),
        observed_cap: None,
    };
    let (cursor, loaded) = match store.load().await {
        Ok(Some(mut cursor)) => {
            cursor.next_since = cursor.next_since.max(request.range.since);
            cursor.delta = cursor.delta.clamp(1, request.policy.max_delta.max(1));
            (cursor, true)
        }
        Ok(None) => (fresh, false),
        Err(SweepStoreError) => {
            return finish(
                request,
                Vec::new(),
                SweepEnd::StoreFailed,
                None,
                SweepStats::default(),
            );
        }
    };
    let mut sweep = Sweep {
        request,
        relay,
        sink,
        store,
        cancel,
        caps: relay.caps(),
        cursor,
        covered: Vec::new(),
        stats: SweepStats::default(),
        last_request: None,
        rate_limited_in_a_row: 0,
        blocked_in_a_row: 0,
    };
    let end = if loaded && sweep.cursor.next_since > request.range.until {
        SweepEnd::Finished
    } else {
        sweep.run().await
    };
    let cursor = (end != SweepEnd::Finished).then_some(sweep.cursor);
    finish(request, sweep.covered, end, cursor, sweep.stats)
}

fn finish(
    request: SweepRequest,
    covered: Vec<CoveredSlice>,
    end: SweepEnd,
    cursor: Option<SweepCursor>,
    stats: SweepStats,
) -> SweepReport {
    let report = SweepReport {
        covered,
        end,
        cursor,
        stats,
    };
    tracing::debug!(
        target: "transport_nostr_adapter::sweep",
        method = "run_sweep",
        end = end.label(),
        outcome = ?report.outcome(),
        refusal = match end {
            SweepEnd::Refused(reason) => reason.label(),
            SweepEnd::Unreachable(kind) => kind.as_str(),
            _ => "none",
        },
        slices = report.covered.len(),
        range_seconds = request.range.until.saturating_sub(request.range.since),
        requests = stats.requests,
        halvings = stats.halvings,
        growths = stats.growths,
        rate_limited_waits = stats.rate_limited_waits,
        blocked_waits = stats.blocked_waits,
        saturated_seconds = stats.saturated_seconds,
        answers = stats.answers,
        events = stats.events,
    );
    report
}

impl<R, K, C> Sweep<'_, R, K, C>
where
    R: SweepRelay + ?Sized,
    K: SweepSink + ?Sized,
    C: SweepCursorStore + ?Sized,
{
    async fn run(&mut self) -> SweepEnd {
        let range = self.request.range;
        loop {
            let since = self.cursor.next_since;
            if since > range.until {
                return SweepEnd::Finished;
            }
            if self.cancel.is_cancelled() {
                return SweepEnd::Cancelled;
            }
            if self.past_deadline() {
                return SweepEnd::DeadlineReached;
            }
            let until = since.saturating_add(self.cursor.delta - 1).min(range.until);
            let query = SliceQuery {
                route: self.request.route,
                since,
                until,
                limit: Some(self.request_limit()),
            };
            let reply = match self.ask(self.relay.fetch_slice(query)).await {
                Ok(reply) => reply,
                Err(interrupt) => return interrupt.into(),
            };
            let step = match reply {
                SliceReply::Closed(reason) => match self.refused(reason).await {
                    Refusal::Retry => continue,
                    Refusal::Stop(end) => return end,
                },
                SliceReply::Unreachable(kind) => return SweepEnd::Unreachable(kind),
                SliceReply::Answered {
                    events,
                    received,
                    more,
                } => {
                    self.answered();
                    self.slice_answered(since, until, events, received, more)
                        .await
                }
            };
            if let Some(end) = step {
                return end;
            }
        }
    }

    /// Handle one answered slice; `Some` ends the call.
    async fn slice_answered(
        &mut self,
        since: u64,
        until: u64,
        events: Vec<Event>,
        received: usize,
        more: bool,
    ) -> Option<SweepEnd> {
        let received = u32::try_from(received.max(events.len())).unwrap_or(u32::MAX);
        let proof = if more {
            None
        } else {
            self.count_proof(received)
        };
        let Some(proof) = proof else {
            if since == until {
                return self.saturated_second(since).await;
            }
            self.stats.halvings += 1;
            self.cursor.delta = (until - since).div_ceil(2).max(1);
            return self.save().await.err();
        };
        if self.grows(received) {
            let grown = self
                .cursor
                .delta
                .saturating_mul(2)
                .min(self.request.policy.max_delta.max(1));
            if grown > self.cursor.delta {
                self.stats.growths += 1;
                self.cursor.delta = grown;
            }
        }
        self.cover(since, until, proof, events).await
    }

    async fn saturated_second(&mut self, second: u64) -> Option<SweepEnd> {
        self.stats.saturated_seconds += 1;
        loop {
            let cap = self.caps.max_limit;
            let reply = match self
                .ask(self.relay.fetch_second(self.request.route, second, cap))
                .await
            {
                Ok(reply) => reply,
                Err(interrupt) => return Some(interrupt.into()),
            };
            return match reply {
                SecondReply::Complete(events) => {
                    self.answered();
                    self.cover(second, second, SliceProof::Negentropy, events)
                        .await
                }
                SecondReply::Unproven => {
                    self.answered();
                    Some(SweepEnd::SaturatedSecond { second })
                }
                SecondReply::Closed(reason) => match self.refused(reason).await {
                    Refusal::Retry => continue,
                    Refusal::Stop(end) => Some(end),
                },
                SecondReply::Unreachable(kind) => Some(SweepEnd::Unreachable(kind)),
            };
        }
    }

    /// Admit a proven slice, then move the cursor past it.
    async fn cover(
        &mut self,
        since: u64,
        until: u64,
        proof: SliceProof,
        events: Vec<Event>,
    ) -> Option<SweepEnd> {
        let route = self.request.route;
        let mut events = events
            .into_iter()
            .filter(|event| {
                let at = event.created_at.as_secs();
                at >= since && at <= until && route.matches(event)
            })
            .collect::<Vec<_>>();
        events.sort_by_key(|event| (event.created_at, event.id));
        events.dedup_by_key(|event| event.id);
        let slice = CoveredSlice {
            since,
            until,
            proof,
            events: u32::try_from(events.len()).unwrap_or(u32::MAX),
        };
        let admitted = events.len() as u64;
        if self.sink.admit(slice, events).await.is_err() {
            return Some(SweepEnd::SinkFailed);
        }
        self.stats.events += admitted;
        self.cursor.next_since = until.saturating_add(1);
        self.covered.push(slice);
        if let Err(end) = self.save().await {
            return Some(end);
        }
        if until >= self.request.range.until {
            return Some(SweepEnd::Finished);
        }
        None
    }

    fn count_proof(&mut self, received: u32) -> Option<SliceProof> {
        if let Some(cap) = self.caps.max_limit {
            return (received < cap).then_some(SliceProof::BelowCap { received, cap });
        }
        if received == 0 {
            return Some(SliceProof::BelowObserved {
                received,
                observed: 0,
            });
        }
        match self.cursor.observed_cap {
            Some(observed) if received < observed => {
                Some(SliceProof::BelowObserved { received, observed })
            }
            // A relay with no published cap may have clamped this reply. It
            // proves only that the cap is at least this large.
            _ => {
                self.cursor.observed_cap = Some(
                    self.cursor
                        .observed_cap
                        .map_or(received, |observed| observed.max(received)),
                );
                None
            }
        }
    }

    fn grows(&self, received: u32) -> bool {
        let cap = self
            .caps
            .max_limit
            .or(self.cursor.observed_cap)
            .unwrap_or(0);
        u64::from(received) * u64::from(self.request.policy.grow_below.max(1)) < u64::from(cap)
            || received == 0
    }

    fn request_limit(&self) -> u32 {
        self.caps
            .max_limit
            .unwrap_or(self.request.policy.unknown_cap_limit)
    }

    async fn refused(&mut self, reason: ClosedReason) -> Refusal {
        let policy = self.request.policy;
        match reason.0 {
            Some(TransportEndpointRejectionCategory::RateLimited) => {
                if self.rate_limited_in_a_row >= policy.max_rate_limit_waits {
                    return Refusal::Stop(SweepEnd::RateLimited);
                }
                let wait = policy
                    .rate_limit_backoff
                    .saturating_mul(1 << self.rate_limited_in_a_row.min(16))
                    .min(policy.max_rate_limit_backoff);
                self.rate_limited_in_a_row += 1;
                self.stats.rate_limited_waits += 1;
                match self.wait_until(Instant::now() + wait).await {
                    Ok(()) => Refusal::Retry,
                    Err(interrupt) => Refusal::Stop(interrupt.into()),
                }
            }
            Some(TransportEndpointRejectionCategory::Blocked)
                if self.blocked_in_a_row < policy.blocked_retries =>
            {
                self.blocked_in_a_row += 1;
                self.stats.blocked_waits += 1;
                let wait = policy.rate_limit_backoff.min(policy.max_rate_limit_backoff);
                match self.wait_until(Instant::now() + wait).await {
                    Ok(()) => Refusal::Retry,
                    Err(interrupt) => Refusal::Stop(interrupt.into()),
                }
            }
            _ => Refusal::Stop(SweepEnd::Refused(reason)),
        }
    }

    fn answered(&mut self) {
        self.stats.answers += 1;
        self.rate_limited_in_a_row = 0;
        self.blocked_in_a_row = 0;
    }

    /// Pace, then run one relay request under the call's cancellation and
    /// deadline ([`ask_until_cut`]).
    async fn ask<T>(&mut self, request: impl Future<Output = T>) -> Result<T, Interrupt> {
        if let Some(last) = self.last_request {
            self.wait_until(last + self.request.policy.min_request_interval)
                .await?;
        }
        self.last_request = Some(Instant::now());
        self.stats.requests += 1;
        let relay = self.relay;
        ask_until_cut(request, self.cancel, self.request.deadline, || {
            relay.interrupt()
        })
        .await
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

    async fn save(&mut self) -> Result<(), SweepEnd> {
        self.store
            .save(self.cursor)
            .await
            .map_err(|SweepStoreError| SweepEnd::StoreFailed)
    }
}

async fn sleep_until_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}
