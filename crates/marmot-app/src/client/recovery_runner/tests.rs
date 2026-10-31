//! The runner over real account storage, against a model relay and a fake
//! live-tail source (or, in one test, an account's real live tails). The host
//! runs worker turns inline and reads the tails once at the start of each debt
//! turn, as the account worker will. Its engine marks every staged event it
//! is handed as seen, unless a test says it keeps no trace of it.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cgka_traits::transport::{
    Timestamp as TransportTime, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::{
    MemberId, MessageId, TransportDelivery, TransportDeliveryPlane, TransportDeliverySource,
};
use nostr::prelude::{Event, EventId, Keys, Kind, PublicKey, Signature, Tag, Timestamp};
use storage_sqlite::{
    RecoveryCoverageProof, RecoveryCoverageRange, RecoveryCoverageSlice, RecoveryRelayCaps,
    RecoveryStagedSlice, RecoveryUnit, RecoveryUnitBreak, RecoveryUnitOutcome, RecoveryUnitState,
    SqlCipherKey, SqliteAccountStorage, SqliteAppStorage, StoredAccountState,
    TransportReconciliationRoute,
};
use tokio::sync::Notify;
use tokio::time::Instant;
use transport_nostr_adapter::compare::{CompareRelay, CompareReply, IdsReply, LocalItem};
use transport_nostr_adapter::sweep::{
    ClosedReason, INTERRUPT_GRACE, RelayCaps, SecondReply, SliceQuery, SliceReply, SweepEnd,
    SweepPolicy, SweepRange, SweepRelay, SweepRoute, UnreachableKind,
};

use super::admission::{Drained, LiveFence, Stalled, live_fences};
use super::policy::{
    RUNNER_BACKOFF_BASE_SECS, RUNNER_QUANTUM, RUNNER_RECHECK_INTERVAL_SECS, RUNNER_REQUEST_TIMEOUT,
    RUNNER_UNREACHABLE_RETRY_SECS,
};
use super::quantum::{SinkStop, classify};
use super::select::{Survey, survey};
use super::*;
use crate::client::AppClient;
use crate::runtime::account_worker::recovery_credits::{
    self, RecoveryCreditPool, available_credits, hold_all_credits_for_test,
};

mod comparison;
mod inbox;

const RELAY: &str = "wss://a.example";
const OTHER_RELAY: &str = "wss://b.example";
const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;
const GROUP_MESSAGE_KIND: u16 = 445;
const GIFT_WRAP_KIND: u16 = 1059;
/// The account's public key: its inbox's `#p`, and the recipient of the
/// deliveries the host routes.
const INBOX_KEY: [u8; 32] = [0xAA; 32];

type Route = TransportReconciliationRoute;
type Outcome = RecoveryUnitOutcome;
/// What an engine took from staging, in order: `(created_at, event id)`.
type AdmittedLog = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;

fn group(byte: u8) -> Route {
    Route::Group([byte; 32])
}

fn range(since: u64, until: u64) -> RecoveryCoverageRange {
    RecoveryCoverageRange {
        since_seconds: since,
        until_seconds: until,
    }
}

fn unit_key(route: &Route, relay: &str) -> UnitKey {
    UnitKey {
        route: route.clone(),
        relay: relay.to_owned(),
    }
}

fn required(route: &Route, relays: &[&str]) -> RunnerRoute {
    RunnerRoute {
        route: route.clone(),
        group_id: None,
        required: relays.iter().map(|relay| (*relay).to_owned()).collect(),
        best_effort: Vec::new(),
        unrecoverable: false,
        window: false,
        goal_until: None,
    }
}

fn caps(max_limit: u32, negentropy: bool) -> RelayCaps {
    RelayCaps {
        max_limit: Some(max_limit),
        negentropy,
    }
}

/// No pause between requests, so multi-slice sweeps finish quickly.
fn test_policy() -> RecoveryRunnerPolicy {
    RecoveryRunnerPolicy {
        sweep: SweepPolicy {
            min_request_interval: Duration::ZERO,
            ..SweepPolicy::default()
        },
        ..RecoveryRunnerPolicy::default()
    }
}

/// One account's encrypted database.
struct Account {
    _dir: tempfile::TempDir,
    _storage: SqliteAccountStorage,
    app: SqliteAppStorage,
    /// What its engine took from staging, in order: `(created_at, event id)`.
    admitted: AdmittedLog,
}

const ACCOUNT_DB: &str = "account.db";

fn account_key() -> SqlCipherKey {
    // A raw key skips SQLCipher's passphrase derivation, which dominates a
    // test's run time in debug builds.
    SqlCipherKey::raw([7; 32])
}

fn account() -> Account {
    let dir = tempfile::tempdir().unwrap();
    let storage =
        SqliteAccountStorage::open_encrypted(dir.path().join(ACCOUNT_DB), &account_key()).unwrap();
    let app = storage.app_storage();
    Account {
        _dir: dir,
        _storage: storage,
        app,
        admitted: Arc::default(),
    }
}

impl Account {
    /// A second connection to the database, only to inject write faults.
    fn fault_connection(&self) -> rusqlite::Connection {
        let connection = rusqlite::Connection::open(self._dir.path().join(ACCOUNT_DB)).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &connection,
            &account_key(),
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        connection
    }

    fn goal(&self, route: &Route, since: u64) {
        self.app
            .widen_recovery_coverage_goals(std::slice::from_ref(route), since)
            .unwrap();
    }

    /// A live REQ's EOSE proved `[since, until]` on `relay`.
    fn live_boundary(&self, route: &Route, relay: &str, since: u64, until: u64) {
        self.app
            .record_recovery_coverage(
                &[RecoveryCoverageSlice {
                    route,
                    relay,
                    since_seconds: since,
                    until_seconds: until,
                    proof: RecoveryCoverageProof::LiveBoundary,
                }],
                until,
            )
            .unwrap();
    }

    /// The unit's last re-check pass finished at `at`, so none falls due for
    /// six hours: for tests about debt alone. An idle runner still wakes for
    /// it then.
    fn rechecked(&self, route: &Route, relay: &str, at: u64) {
        let revision = self
            .app
            .recovery_unit(route, relay)
            .unwrap()
            .map_or(0, |unit| unit.recheck.revision);
        assert!(
            self.app
                .record_recovery_recheck(route, relay, revision, 0, true, at)
                .unwrap()
        );
    }

    fn debt(&self, route: &Route, relay: &str, until: u64) -> Vec<RecoveryCoverageRange> {
        self.app.recovery_unit_debt(route, relay, until).unwrap()
    }

    fn unit(&self, route: &Route, relay: &str) -> RecoveryUnit {
        self.app
            .recovery_unit(route, relay)
            .unwrap()
            .expect("the runner touched the unit")
    }

    /// Every range a unit keeps fenced: `(route, relay, range)`.
    fn fences(&self) -> Vec<(Route, String, RecoveryCoverageRange)> {
        self.app
            .recovery_unit_fences()
            .unwrap()
            .into_iter()
            .map(|fence| (fence.route, fence.relay, fence.range))
            .collect()
    }

    /// What the engine took from staging, in order.
    fn admitted(&self) -> Vec<(u64, Vec<u8>)> {
        self.admitted.lock().unwrap().clone()
    }

    /// How many distinct events the engine took from staging.
    fn admitted_events(&self) -> u64 {
        let admitted = self.admitted();
        admitted
            .iter()
            .map(|(_, event_id)| event_id)
            .collect::<BTreeSet<_>>()
            .len() as u64
    }

    /// Events still staged, from `relay` on `route`'s group alone.
    fn staged_from(&self, routes: &[Route], relay: &str) -> u64 {
        self.app
            .staged_recovery_usage(routes, Some(relay))
            .unwrap()
            .events
    }

    /// `relay` already swept `[since, until]` and staged `events`.
    fn swept(&self, route: &Route, relay: &str, events: &[Event], since: u64, until: u64) {
        let deliveries = events.iter().map(delivery).collect::<Vec<_>>();
        self.app
            .stage_recovery_slice(
                &RecoveryStagedSlice {
                    route,
                    relay,
                    events: &deliveries,
                    fetched_bytes: 0,
                    covered: &[range(since, until)],
                    proof: RecoveryCoverageProof::SweepSlice,
                    mark: self.app.recovery_coverage_mark().unwrap(),
                },
                until.saturating_add(1),
            )
            .unwrap();
    }

    /// The last second the ledger covers on `relay`.
    fn covered_through(&self, route: &Route, relay: &str) -> u64 {
        self.app
            .recovery_coverage_ranges(route, relay)
            .unwrap()
            .iter()
            .map(|proved| proved.range.until_seconds)
            .max()
            .expect("something is covered")
    }
}

/// Unix seconds: real time at creation, plus Tokio time since (paused or
/// not), plus whatever the test advanced by hand.
#[derive(Clone)]
struct Clock {
    base: u64,
    start: Instant,
    offset: Arc<AtomicU64>,
}

impl Clock {
    fn new() -> Self {
        Self {
            base: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            start: Instant::now(),
            offset: Arc::new(AtomicU64::new(0)),
        }
    }

    fn now(&self) -> u64 {
        self.base + self.offset.load(Ordering::SeqCst) + self.start.elapsed().as_secs()
    }

    fn advance(&self, seconds: u64) {
        self.offset.fetch_add(seconds, Ordering::SeqCst);
    }

    /// Advance to `at`, if it is still ahead.
    fn advance_to(&self, at: u64) {
        self.advance(at.saturating_sub(self.now()));
    }
}

static PUBKEY: LazyLock<PublicKey> = LazyLock::new(|| Keys::generate().public_key());

fn event(group: [u8; 32], created_at: u64) -> Event {
    tagged(GROUP_MESSAGE_KIND, "h", group, created_at)
}

/// A gift wrap to `recipient`.
fn wrap(recipient: [u8; 32], created_at: u64) -> Event {
    tagged(GIFT_WRAP_KIND, "p", recipient, created_at)
}

fn tagged(kind: u16, tag: &str, value: [u8; 32], created_at: u64) -> Event {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let next = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&next.to_be_bytes());
    Event::new(
        EventId::from_byte_array(id),
        *PUBKEY,
        Timestamp::from_secs(created_at),
        Kind::from(kind),
        [Tag::parse([tag, hex::encode(value).as_str()]).unwrap()],
        "",
        Signature::from_byte_array([1; 64]),
    )
}

/// The value of the event's first `tag` tag.
fn tag_value(event: &Event, tag: &str) -> Option<Vec<u8>> {
    event.tags.iter().find_map(|candidate| {
        let parts = candidate.as_slice();
        (parts.len() >= 2 && parts[0] == tag)
            .then(|| hex::decode(&parts[1]).ok())
            .flatten()
    })
}

/// Whether the event belongs to `route`, as a relay filters it.
fn on_route(route: SweepRoute, event: &Event) -> bool {
    let (kind, tag, value) = match route {
        SweepRoute::Group { nostr_group_id } => (GROUP_MESSAGE_KIND, "h", nostr_group_id),
        SweepRoute::Inbox { pubkey } => (GIFT_WRAP_KIND, "p", pubkey),
    };
    event.kind == Kind::from(kind) && tag_value(event, tag).as_deref() == Some(value.as_slice())
}

/// The ledger route a wire route names.
fn ledger_route(route: SweepRoute) -> Route {
    match route {
        SweepRoute::Group { nostr_group_id } => Route::Group(nostr_group_id),
        SweepRoute::Inbox { .. } => Route::Inbox,
    }
}

/// One event every `step` seconds in `[since, until)`.
fn every(group: [u8; 32], since: u64, until: u64, step: u64) -> Vec<Event> {
    (since..until)
        .step_by(usize::try_from(step).unwrap())
        .map(|at| event(group, at))
        .collect()
}

fn group_tag(event: &Event) -> Option<Vec<u8>> {
    tag_value(event, "h")
}

fn delivery(event: &Event) -> TransportDelivery {
    let at = TransportTime(event.created_at.as_secs());
    let account_id = MemberId::new(INBOX_KEY.to_vec());
    let (envelope, plane) = match group_tag(event) {
        Some(transport_group_id) => (
            TransportEnvelope::GroupMessage { transport_group_id },
            TransportDeliveryPlane::Group,
        ),
        None => (
            TransportEnvelope::Welcome {
                recipient: account_id.clone(),
            },
            TransportDeliveryPlane::AccountInbox,
        ),
    };
    TransportDelivery {
        account_id,
        group_id_hint: None,
        message: TransportMessage {
            id: MessageId::new(event.id.to_bytes().to_vec()),
            payload: event.id.to_bytes().to_vec(),
            timestamp: at,
            causal_deps: Vec::new(),
            source: TransportSource("nostr".to_owned()),
            envelope,
        },
        received_at: at,
        source: TransportDeliverySource {
            transport: TransportSource("nostr".to_owned()),
            plane,
            endpoint: None,
            subscription_id: Some("recovery".to_owned()),
            wire: None,
        },
    }
}

/// Live tails as the relay plane would report them: where each standing tail
/// starts.
#[derive(Default)]
struct TailSource {
    standing: Mutex<BTreeMap<UnitKey, u64>>,
}

impl TailSource {
    fn stand(&self, route: &Route, relay: &str, from: u64) {
        self.standing
            .lock()
            .unwrap()
            .insert(unit_key(route, relay), from);
    }

    /// The tail's generation broke: nothing tells the runner.
    fn lapse(&self, route: &Route, relay: &str) {
        self.standing
            .lock()
            .unwrap()
            .remove(&unit_key(route, relay));
    }

    /// One read, as `live_tails` takes it: a snapshot for one turn.
    fn read(&self) -> Tails {
        Tails(self.standing.lock().unwrap().clone())
    }
}

struct Tails(BTreeMap<UnitKey, u64>);

impl LiveTailRead for Tails {
    fn owed_until(&self, route: &Route, relay: &str, now: u64) -> u64 {
        self.0
            .get(&unit_key(route, relay))
            .map_or(now, |from| from.saturating_sub(1).min(now))
    }
}

/// Holds requests from one index on until it opens.
struct Gate {
    hold_from: AtomicUsize,
    waiting: AtomicUsize,
    opened: Notify,
}

/// Counts one held request while it waits, dropped or not.
struct Held<'a>(&'a AtomicUsize);

impl<'a> Held<'a> {
    fn new(waiting: &'a AtomicUsize) -> Self {
        waiting.fetch_add(1, Ordering::SeqCst);
        Self(waiting)
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Gate {
    fn new() -> Self {
        Self {
            hold_from: AtomicUsize::new(usize::MAX),
            waiting: AtomicUsize::new(0),
            opened: Notify::new(),
        }
    }

    fn hold_from(&self, index: usize) {
        self.hold_from.store(index, Ordering::SeqCst);
    }

    fn open(&self) {
        self.hold_from.store(usize::MAX, Ordering::SeqCst);
        self.opened.notify_waiters();
    }

    fn waiting(&self) -> usize {
        self.waiting.load(Ordering::SeqCst)
    }

    async fn pass(&self, index: usize) {
        let mut held = None;
        loop {
            let opened = self.opened.notified();
            tokio::pin!(opened);
            opened.as_mut().enable();
            if index < self.hold_from.load(Ordering::SeqCst) {
                return;
            }
            held.get_or_insert_with(|| Held::new(&self.waiting));
            opened.await;
        }
    }
}

/// Requests in flight across relays, and the most seen at once.
#[derive(Default)]
struct InFlight {
    now: AtomicUsize,
    max: AtomicUsize,
}

struct Flight<'a>(&'a InFlight);

impl InFlight {
    fn enter(&self) -> Flight<'_> {
        let now = self.now.fetch_add(1, Ordering::SeqCst) + 1;
        self.max.fetch_max(now, Ordering::SeqCst);
        Flight(self)
    }

    fn now(&self) -> usize {
        self.now.load(Ordering::SeqCst)
    }

    fn max(&self) -> usize {
        self.max.load(Ordering::SeqCst)
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.0.now.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A relay that answers as strfry does: inclusive `since`/`until`, newest
/// first, at most its cap per REQ, every event of a second through NIP-77
/// when it has it.
struct ModelRelay {
    url: &'static str,
    /// What its NIP-11 document says; `None` when it cannot be read.
    published: Option<RelayCaps>,
    cap: usize,
    negentropy: bool,
    events: Vec<Event>,
    reachable: AtomicBool,
    /// Requests, by index, that get `rate-limited:` back.
    limited: Range<usize>,
    /// Event bytes each request reads before it waits out the gate, as a
    /// second's completed chunks are read before a later one is held.
    read_before_reply: u64,
    /// What `interrupt` answers. An interrupted request ends at once and
    /// reports `read_until_cut` more bytes: what it read before the cut.
    interruptible: bool,
    read_until_cut: u64,
    /// Bytes read that `take_fetched_bytes` has not reported yet.
    unreported: AtomicU64,
    latency: Duration,
    requests: AtomicUsize,
    queries: Mutex<Vec<SliceQuery>>,
    seconds: Mutex<Vec<u64>>,
    gate: Gate,
    in_flight: Arc<InFlight>,
    /// When set, every request is checked against the ledger: one that starts
    /// inside a range this relay already proved is a refetch.
    ledger: Option<SqliteAppStorage>,
    refetches: Mutex<Vec<u64>>,
    /// Every NIP-77 comparison's window, in order.
    comparisons: Mutex<Vec<SweepRange>>,
    /// Every id fetched by id, in order.
    fetched_ids: Mutex<Vec<EventId>>,
    /// It refuses every read of an inbox's gift wraps, as a relay that
    /// restricts kind 1059 to authenticated recipients does.
    refusing_inbox: bool,
}

impl ModelRelay {
    fn new(url: &'static str, caps: RelayCaps) -> Self {
        Self {
            url,
            published: Some(caps),
            cap: caps.max_limit.map_or(500, |cap| cap as usize),
            negentropy: caps.negentropy,
            events: Vec::new(),
            reachable: AtomicBool::new(true),
            limited: 0..0,
            read_before_reply: 0,
            interruptible: false,
            read_until_cut: 0,
            unreported: AtomicU64::new(0),
            latency: Duration::ZERO,
            requests: AtomicUsize::new(0),
            queries: Mutex::new(Vec::new()),
            seconds: Mutex::new(Vec::new()),
            gate: Gate::new(),
            in_flight: Arc::default(),
            ledger: None,
            refetches: Mutex::new(Vec::new()),
            comparisons: Mutex::new(Vec::new()),
            fetched_ids: Mutex::new(Vec::new()),
            refusing_inbox: false,
        }
    }

    fn refusing_inbox(mut self) -> Self {
        self.refusing_inbox = true;
        self
    }

    fn with_events(mut self, events: Vec<Event>) -> Self {
        self.events = events;
        self
    }

    fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    fn unreachable(self) -> Self {
        self.reachable.store(false, Ordering::SeqCst);
        self
    }

    fn rate_limiting(self) -> Self {
        self.rate_limiting_requests(0..usize::MAX)
    }

    fn rate_limiting_requests(mut self, requests: Range<usize>) -> Self {
        self.limited = requests;
        self
    }

    fn reading_before_reply(mut self, bytes: u64) -> Self {
        self.read_before_reply = bytes;
        self
    }

    fn interruptible(mut self, read_until_cut: u64) -> Self {
        self.interruptible = true;
        self.read_until_cut = read_until_cut;
        self
    }

    fn checking(mut self, account: &Account) -> Self {
        self.ledger = Some(account.app.clone());
        self
    }

    fn sharing(mut self, in_flight: &Arc<InFlight>) -> Self {
        self.in_flight = in_flight.clone();
        self
    }

    fn build(self) -> Arc<Self> {
        Arc::new(self)
    }

    fn set_reachable(&self, reachable: bool) {
        self.reachable.store(reachable, Ordering::SeqCst);
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    fn queries(&self) -> Vec<SliceQuery> {
        self.queries.lock().unwrap().clone()
    }

    fn seconds(&self) -> Vec<u64> {
        self.seconds.lock().unwrap().clone()
    }

    fn refetches(&self) -> Vec<u64> {
        self.refetches.lock().unwrap().clone()
    }

    fn comparisons(&self) -> Vec<SweepRange> {
        self.comparisons.lock().unwrap().clone()
    }

    fn fetched_ids(&self) -> Vec<EventId> {
        self.fetched_ids.lock().unwrap().clone()
    }

    fn matching(&self, route: SweepRoute, since: u64, until: u64) -> Vec<Event> {
        let mut matching = self
            .events
            .iter()
            .filter(|event| {
                let at = event.created_at.as_secs();
                at >= since && at <= until && on_route(route, event)
            })
            .cloned()
            .collect::<Vec<_>>();
        matching.sort_by_key(|event| std::cmp::Reverse(event.created_at));
        matching
    }

    fn check_uncovered(&self, route: SweepRoute, since: u64) {
        let Some(app) = &self.ledger else {
            return;
        };
        let proved = app
            .recovery_coverage_ranges(&ledger_route(route), self.url)
            .unwrap();
        if proved.iter().any(|proved| {
            proved.range.since_seconds <= since && since <= proved.range.until_seconds
        }) {
            self.refetches.lock().unwrap().push(since);
        }
    }

    /// Wait out the gate and the latency, unless `cut` interrupts the wait.
    /// What the relay says instead of an answer, if anything.
    async fn arrive(&self, cut: &CancellationToken) -> Option<ClosedOrUnreachable> {
        let index = self.requests.fetch_add(1, Ordering::SeqCst);
        self.unreported
            .fetch_add(self.read_before_reply, Ordering::SeqCst);
        let wait = async {
            self.gate.pass(index).await;
            if !self.latency.is_zero() {
                tokio::time::sleep(self.latency).await;
            }
        };
        tokio::select! {
            () = wait => {}
            () = cut.cancelled(), if self.interruptible => {
                self.unreported
                    .fetch_add(self.read_until_cut, Ordering::SeqCst);
                return Some(ClosedOrUnreachable::Unreachable);
            }
        }
        if !self.reachable.load(Ordering::SeqCst) {
            Some(ClosedOrUnreachable::Unreachable)
        } else if self.limited.contains(&index) {
            Some(ClosedOrUnreachable::RateLimited)
        } else {
            None
        }
    }

    async fn fetch_slice(&self, query: SliceQuery, cut: &CancellationToken) -> SliceReply {
        let _flight = self.in_flight.enter();
        self.check_uncovered(query.route, query.since);
        self.queries.lock().unwrap().push(query);
        match self.arrive(cut).await {
            Some(ClosedOrUnreachable::Unreachable) => {
                return SliceReply::Unreachable(UnreachableKind::TimedOut);
            }
            Some(ClosedOrUnreachable::RateLimited) => return SliceReply::Closed(rate_limited()),
            None => {}
        }
        let matching = self.matching(query.route, query.since, query.until);
        let limit = query
            .limit
            .map_or(usize::MAX, |limit| limit as usize)
            .min(self.cap);
        let received = matching.len().min(limit);
        SliceReply::Answered {
            events: matching.into_iter().take(limit).collect(),
            received,
            more: false,
        }
    }

    async fn fetch_second(
        &self,
        route: SweepRoute,
        second: u64,
        cut: &CancellationToken,
    ) -> SecondReply {
        let _flight = self.in_flight.enter();
        self.seconds.lock().unwrap().push(second);
        match self.arrive(cut).await {
            Some(ClosedOrUnreachable::Unreachable) => {
                return SecondReply::Unreachable(UnreachableKind::TimedOut);
            }
            Some(ClosedOrUnreachable::RateLimited) => return SecondReply::Closed(rate_limited()),
            None => {}
        }
        if self.negentropy {
            SecondReply::Complete(self.matching(route, second, second))
        } else {
            SecondReply::Unproven
        }
    }

    /// A NIP-77 comparison as strfry answers it: its set for the window is
    /// every matching event, newest first, as far as the limit.
    async fn compare(
        &self,
        route: SweepRoute,
        window: SweepRange,
        local: &[LocalItem],
        limit: usize,
        cut: &CancellationToken,
    ) -> CompareReply {
        let _flight = self.in_flight.enter();
        self.comparisons.lock().unwrap().push(window);
        match self.arrive(cut).await {
            Some(ClosedOrUnreachable::Unreachable) => {
                return CompareReply::Unreachable(UnreachableKind::TimedOut);
            }
            Some(ClosedOrUnreachable::RateLimited) => return CompareReply::Closed(rate_limited()),
            None => {}
        }
        if !self.negentropy {
            return CompareReply::Unsupported;
        }
        if self.refusing_inbox && matches!(route, SweepRoute::Inbox { .. }) {
            return CompareReply::Closed(restricted());
        }
        let held = local.iter().map(|item| item.id).collect::<BTreeSet<_>>();
        let set = self
            .matching(route, window.since, window.until)
            .into_iter()
            .take(limit)
            .collect::<Vec<_>>();
        CompareReply::Compared {
            relay_set: set.len(),
            missing: set
                .iter()
                .map(|event| event.id)
                .filter(|id| !held.contains(id))
                .collect(),
        }
    }

    async fn fetch_ids(
        &self,
        route: SweepRoute,
        window: SweepRange,
        ids: &[EventId],
        cut: &CancellationToken,
    ) -> IdsReply {
        let _flight = self.in_flight.enter();
        self.fetched_ids.lock().unwrap().extend_from_slice(ids);
        match self.arrive(cut).await {
            Some(ClosedOrUnreachable::Unreachable) => {
                return IdsReply::Unreachable(UnreachableKind::TimedOut);
            }
            Some(ClosedOrUnreachable::RateLimited) => return IdsReply::Closed(rate_limited()),
            None => {}
        }
        let asked = ids.iter().collect::<BTreeSet<_>>();
        IdsReply::Answered(
            self.matching(route, window.since, window.until)
                .into_iter()
                .filter(|event| asked.contains(&event.id))
                .collect(),
        )
    }
}

enum ClosedOrUnreachable {
    RateLimited,
    Unreachable,
}

fn rate_limited() -> ClosedReason {
    ClosedReason::from_message("rate-limited: slow down")
}

fn restricted() -> ClosedReason {
    ClosedReason::from_message("restricted: gift wraps are for their recipient")
}

/// The sweep's view of a model relay, with the caps the runner planned.
struct Swept {
    relay: Arc<ModelRelay>,
    caps: RelayCaps,
    /// Interrupts this quantum's requests.
    cut: CancellationToken,
}

#[async_trait]
impl SweepRelay for Swept {
    fn caps(&self) -> RelayCaps {
        self.caps
    }

    async fn fetch_slice(&self, query: SliceQuery) -> SliceReply {
        self.relay.fetch_slice(query, &self.cut).await
    }

    async fn fetch_second(&self, route: SweepRoute, second: u64, _cap: Option<u32>) -> SecondReply {
        self.relay.fetch_second(route, second, &self.cut).await
    }

    fn take_fetched_bytes(&self) -> u64 {
        self.relay.unreported.swap(0, Ordering::SeqCst)
    }

    fn interrupt(&self) -> bool {
        self.cut.cancel();
        self.relay.interruptible
    }
}

/// The comparison's view of a model relay.
struct Compared {
    relay: Arc<ModelRelay>,
    caps: RelayCaps,
    /// Interrupts this quantum's requests.
    cut: CancellationToken,
}

#[async_trait]
impl CompareRelay for Compared {
    fn caps(&self) -> RelayCaps {
        self.caps
    }

    async fn compare(
        &self,
        route: SweepRoute,
        window: SweepRange,
        local: &[LocalItem],
        limit: usize,
    ) -> CompareReply {
        self.relay
            .compare(route, window, local, limit, &self.cut)
            .await
    }

    async fn fetch_ids(&self, route: SweepRoute, window: SweepRange, ids: &[EventId]) -> IdsReply {
        self.relay.fetch_ids(route, window, ids, &self.cut).await
    }

    fn take_fetched_bytes(&self) -> u64 {
        self.relay.unreported.swap(0, Ordering::SeqCst)
    }

    fn interrupt(&self) -> bool {
        self.cut.cancel();
        self.relay.interruptible
    }
}

struct TestHost {
    app: SqliteAppStorage,
    clock: Clock,
    routes: Mutex<Vec<RunnerRoute>>,
    tails: TailSource,
    /// The live REQs' counts each debt turn reads.
    counts: Mutex<Vec<LiveCount>>,
    admitted: AdmittedLog,
    /// Events the engine keeps no trace of.
    no_trace: Mutex<BTreeSet<Vec<u8>>>,
    /// Events no installed subscription routes yet.
    unrouted: Mutex<BTreeSet<Vec<u8>>>,
    /// Events whose ingest fails locally.
    failing_ingests: Mutex<BTreeSet<Vec<u8>>>,
    /// How many seconds of the host's clock each ingest and each debt turn
    /// takes.
    ingest_seconds: AtomicU64,
    debt_turn_seconds: AtomicU64,
    /// A laggard every admission is checked against: each admitted event's
    /// second, with the first second the laggard owed then.
    laggard: Mutex<Option<UnitKey>>,
    behind: Mutex<Vec<(u64, Option<u64>)>>,
    /// When set, debt turns read this client's real live tails instead.
    client: Option<Arc<AppClient>>,
    relays: BTreeMap<&'static str, Arc<ModelRelay>>,
    debt_turns: AtomicUsize,
    /// How long a NIP-11 read takes.
    caps_latency: Mutex<Duration>,
    /// Every NIP-11 read is unknown, as a relay that serves no document.
    caps_unknown: AtomicBool,
    /// Worker turns still to fail, against `closed`.
    failing_turns: AtomicUsize,
    closed: OnceLock<Account>,
    /// The relay pool's connection generations, by relay.
    connections: watch::Sender<BTreeMap<String, u64>>,
    /// Audit rows the runner's worker turns recorded.
    audited: Mutex<Vec<AuditEventKind>>,
    /// What the last survey found catching up.
    catching_up: Mutex<Option<BTreeSet<UnitKey>>>,
}

impl TestHost {
    fn new(
        account: &Account,
        clock: &Clock,
        routes: Vec<RunnerRoute>,
        relays: &[&Arc<ModelRelay>],
    ) -> Arc<Self> {
        Self::reading(
            account.app.clone(),
            None,
            &account.admitted,
            clock,
            routes,
            relays,
        )
    }

    /// A host over `client`'s account whose debt turns read its live tails.
    fn on_client(
        app: SqliteAppStorage,
        client: AppClient,
        clock: &Clock,
        routes: Vec<RunnerRoute>,
        relays: &[&Arc<ModelRelay>],
    ) -> Arc<Self> {
        Self::reading(
            app,
            Some(Arc::new(client)),
            &Arc::default(),
            clock,
            routes,
            relays,
        )
    }

    fn reading(
        app: SqliteAppStorage,
        client: Option<Arc<AppClient>>,
        admitted: &AdmittedLog,
        clock: &Clock,
        routes: Vec<RunnerRoute>,
        relays: &[&Arc<ModelRelay>],
    ) -> Arc<Self> {
        Arc::new(Self {
            app,
            clock: clock.clone(),
            routes: Mutex::new(routes),
            tails: TailSource::default(),
            counts: Mutex::default(),
            admitted: admitted.clone(),
            no_trace: Mutex::default(),
            unrouted: Mutex::default(),
            failing_ingests: Mutex::default(),
            ingest_seconds: AtomicU64::new(0),
            debt_turn_seconds: AtomicU64::new(0),
            laggard: Mutex::default(),
            behind: Mutex::default(),
            client,
            relays: relays
                .iter()
                .map(|relay| (relay.url, Arc::clone(relay)))
                .collect(),
            debt_turns: AtomicUsize::new(0),
            caps_latency: Mutex::new(Duration::ZERO),
            caps_unknown: AtomicBool::new(false),
            failing_turns: AtomicUsize::new(0),
            closed: OnceLock::new(),
            connections: watch::channel(BTreeMap::new()).0,
            audited: Mutex::default(),
            catching_up: Mutex::default(),
        })
    }

    fn debt_turns(&self) -> usize {
        self.debt_turns.load(Ordering::SeqCst)
    }

    fn set_counts(&self, counts: Vec<LiveCount>) {
        *self.counts.lock().unwrap() = counts;
    }

    /// Each fenced group's release point, as one debt turn reads it.
    async fn fences(&self) -> Vec<(Vec<Route>, u64)> {
        self.debt_turn(|turn| live_fences(turn).unwrap())
            .await
            .unwrap()
            .into_iter()
            .map(
                |LiveFence {
                     routes,
                     release_before,
                 }| (routes, release_before),
            )
            .collect()
    }

    async fn survey(&self, policy: RecoveryRunnerPolicy) -> Survey {
        self.debt_turn(move |turn| survey(turn, &policy, &Stalled::default()).unwrap())
            .await
            .unwrap()
    }

    /// The pool's `relay` connects again (or for the first time).
    fn connect(&self, relay: &str) {
        self.connections.send_modify(|open| {
            *open.entry(relay.to_owned()).or_default() += 1;
        });
    }

    /// The next `turns` worker turns (not debt turns) run on a closed
    /// database, so every storage call in them fails.
    fn fail_next_turns(&self, turns: usize) {
        self.closed.get_or_init(|| {
            let closed = account();
            closed._storage.close().unwrap();
            closed
        });
        self.failing_turns.store(turns, Ordering::SeqCst);
    }
}

#[async_trait]
impl RunnerHost for TestHost {
    async fn turn<T, F>(&self, turn: F) -> Option<T>
    where
        F: FnOnce(&WorkerTurn<'_>) -> T + Send + 'static,
        T: Send + 'static,
    {
        let failing = self
            .failing_turns
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |turns| {
                turns.checked_sub(1)
            })
            .is_ok();
        let app = if failing {
            &self.closed.get().expect("a closed database").app
        } else {
            &self.app
        };
        let audit = |kind| self.audited.lock().unwrap().push(kind);
        Some(turn(&WorkerTurn {
            app,
            now: self.clock.now(),
            audit: &audit,
        }))
    }

    async fn debt_turn<T, F>(&self, turn: F) -> Option<T>
    where
        F: FnOnce(&DebtTurn<'_>) -> T + Send + 'static,
        T: Send + 'static,
    {
        let now = self.clock.now();
        let tails: Box<dyn LiveTailRead> = match &self.client {
            Some(client) => client.recovery_runner_live_tails(&self.app, now).await,
            None => Box::new(self.tails.read()),
        };
        let routes = self.routes.lock().unwrap().clone();
        let counts = self.counts.lock().unwrap().clone();
        let answer = turn(&DebtTurn {
            app: &self.app,
            routes: &routes,
            now,
            tails: &*tails,
            live_counts: &counts,
            inbox: INBOX_KEY,
        });
        self.debt_turns.fetch_add(1, Ordering::SeqCst);
        self.clock
            .advance(self.debt_turn_seconds.load(Ordering::SeqCst));
        Some(answer)
    }

    async fn relay_caps(&self, relay: &str) -> Option<RelayCaps> {
        let latency = *self.caps_latency.lock().unwrap();
        if !latency.is_zero() {
            tokio::time::sleep(latency).await;
        }
        if self.caps_unknown.load(Ordering::SeqCst) {
            return None;
        }
        self.relays.get(relay).and_then(|relay| relay.published)
    }

    fn sweep_relay(
        &self,
        relay: &str,
        caps: RelayCaps,
        _request_timeout: Duration,
    ) -> Option<Box<dyn SweepRelay>> {
        let relay = self.relays.get(relay)?.clone();
        Some(Box::new(Swept {
            relay,
            caps,
            cut: CancellationToken::new(),
        }))
    }

    fn compare_relay(
        &self,
        relay: &str,
        caps: RelayCaps,
        _request_timeout: Duration,
    ) -> Option<Box<dyn CompareRelay>> {
        let relay = self.relays.get(relay)?.clone();
        Some(Box::new(Compared {
            relay,
            caps,
            cut: CancellationToken::new(),
        }))
    }

    async fn deliveries(&self, _relay: &str, event: Event) -> Option<Vec<TransportDelivery>> {
        let unrouted = self
            .unrouted
            .lock()
            .unwrap()
            .contains(event.id.as_bytes().as_slice());
        (!unrouted).then(|| vec![delivery(&event)])
    }

    async fn admit_staged(
        &self,
        delivery: TransportDelivery,
    ) -> Option<Result<Admitted, &'static str>> {
        self.clock
            .advance(self.ingest_seconds.load(Ordering::SeqCst));
        let at = delivery.message.timestamp.0;
        let event_id = delivery.message.id.as_slice().to_vec();
        if self.no_trace.lock().unwrap().contains(&event_id) {
            return Some(Ok(Admitted::NoTrace));
        }
        if self.failing_ingests.lock().unwrap().contains(&event_id) {
            return Some(Err("storage"));
        }
        if let Some(laggard) = self.laggard.lock().unwrap().as_ref() {
            let now = self.clock.now();
            let owed_until = self
                .tails
                .read()
                .owed_until(&laggard.route, &laggard.relay, now);
            let owed = self
                .app
                .recovery_unit_debt(&laggard.route, &laggard.relay, owed_until)
                .unwrap()
                .first()
                .map(|range| range.since_seconds);
            self.behind.lock().unwrap().push((at, owed));
        }
        self.app
            .save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
                &StoredAccountState {
                    label: "runner".to_owned(),
                    seen_events: vec![hex::encode(&event_id)],
                    ..StoredAccountState::default()
                },
                100_000,
                0,
                &[],
                &[],
            )
            .unwrap();
        self.admitted.lock().unwrap().push((at, event_id));
        Some(Ok(Admitted::Kept))
    }

    fn now_seconds(&self) -> u64 {
        self.clock.now()
    }

    fn relay_connections(&self) -> Option<watch::Receiver<BTreeMap<String, u64>>> {
        Some(self.connections.subscribe())
    }

    fn surveyed(&self, catching_up: BTreeSet<UnitKey>) {
        *self.catching_up.lock().unwrap() = Some(catching_up);
    }
}

fn runner(
    host: &Arc<TestHost>,
    policy: RecoveryRunnerPolicy,
) -> (RecoveryRunner<TestHost>, RecoveryRunnerHandle) {
    RecoveryRunner::new(
        host.clone(),
        policy,
        recovery_credits::private_recovery_credit_pool_for_test(),
    )
}

fn runner_sharing(
    host: &Arc<TestHost>,
    credits: &Arc<RecoveryCreditPool>,
) -> (RecoveryRunner<TestHost>, RecoveryRunnerHandle) {
    RecoveryRunner::new(host.clone(), test_policy(), credits.clone())
}

fn ran(step: Step) -> QuantumSummary {
    match step {
        Step::Ran(summary) => summary,
        Step::Raced => panic!("expected a quantum; the unit raced"),
        Step::Idle { .. } => panic!("expected a quantum; the runner was idle"),
        Step::Stopped => panic!("expected a quantum; the runner stopped"),
    }
}

fn idle(step: Step) -> Option<u64> {
    match step {
        Step::Idle { next_due } => next_due,
        Step::Ran(_) => panic!("expected the runner to be idle; it ran a quantum"),
        Step::Raced => panic!("expected the runner to be idle; the unit raced"),
        Step::Stopped => panic!("expected the runner to be idle; it stopped"),
    }
}

/// Step until the runner is idle, at most `steps` times.
async fn run_until_idle(runner: &mut RecoveryRunner<TestHost>, steps: usize) -> Vec<Outcome> {
    let mut outcomes = Vec::new();
    for _ in 0..steps {
        match runner.step().await {
            Step::Ran(summary) => outcomes.push(summary.outcome),
            Step::Raced => {}
            Step::Idle { .. } => return outcomes,
            Step::Stopped => panic!("the runner stopped"),
        }
    }
    panic!("the runner was still busy after {steps} steps");
}

async fn wait_until(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

const WAIT: Duration = Duration::from_secs(10);

/// An hour of history whose oldest second holds three events, over a cap of
/// two on a relay without NIP-77: every sweep stalls on that second.
fn stalling_relay(group: [u8; 32], floor: u64) -> ModelRelay {
    ModelRelay::new(RELAY, caps(2, false))
        .with_events((0..3).map(|_| event(group, floor)).collect())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_never_charges_an_idle_connected_account_for_its_own_tail() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .with_events(every([1; 32], t0 - DAY, t0, 10 * 60))
        .checking(&account)
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    // The live REQ opened an hour ago: its EOSE proved the day before, and its
    // tail has stood since.
    let opened = t0 - HOUR;
    account.goal(&route, t0 - DAY);
    account.live_boundary(&route, RELAY, t0 - DAY, opened - 1);
    host.tails.stand(&route, RELAY, opened);
    let (mut runner, _handle) = runner(&host, test_policy());

    for _ in 0..3 {
        assert_eq!(idle(runner.step().await), None);
        clock.advance(10 * 60);
    }

    assert_eq!(
        host.debt_turns(),
        6,
        "each step read the tails again, to admit and to survey"
    );
    assert!(relay.queries().is_empty());
    assert!(account.app.recovery_unit(&route, RELAY).unwrap().is_none());
    assert_eq!(
        account
            .app
            .recovery_account_usage(clock.now())
            .unwrap()
            .attempts,
        0
    );
    // The ledger alone owes the tail's seconds; only the tail spares them.
    assert_eq!(
        account
            .debt(&route, RELAY, clock.now())
            .first()
            .map(|range| range.since_seconds),
        Some(opened)
    );
}

/// The test above against the account's real live tails: while its live
/// REQs stand nothing is owed, and once the relay client reports another
/// connection the tails lapse and their seconds are owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_never_charges_an_idle_connected_account_for_its_real_tail() {
    use crate::client::recovery_coverage::scenario_tests::{Fixture, fixture, relay, routes};
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let Fixture {
        _dir,
        _pump,
        relay: scripted,
        client,
        storage,
        ..
    } = fixture().await;
    let app = storage.app_storage();
    let url: &'static str = Box::leak(relay().into_boxed_str());
    let groups = routes(&client)
        .into_iter()
        .filter(|route| matches!(route, Route::Group(_)))
        .collect::<Vec<_>>();
    assert!(!groups.is_empty());
    let clock = Clock::new();
    app.widen_recovery_coverage_goals(&groups, clock.now() - DAY)
        .unwrap();
    let model = ModelRelay::new(url, caps(500, true)).build();
    let host = TestHost::on_client(
        app.clone(),
        client,
        &clock,
        groups.iter().map(|route| required(route, &[url])).collect(),
        &[&model],
    );
    let (mut runner, _handle) = runner(&host, test_policy());

    for _ in 0..2 {
        assert_eq!(idle(runner.step().await), None);
        clock.advance(HOUR);
    }
    assert!(model.queries().is_empty());
    assert_eq!(app.recovery_account_usage(clock.now()).unwrap().attempts, 0);

    scripted.connection_attempt.fetch_add(1, Ordering::SeqCst);
    assert_eq!(ran(runner.step().await).outcome, Outcome::Advanced);
    let first = model.queries()[0];
    assert!(
        first.since >= before,
        "only the tail's seconds are owed; the live boundary proved the rest"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_owes_a_broken_generation_tail_until_a_reconnect_or_a_proof() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .with_events(every([1; 32], t0 - DAY, t0, 10 * 60))
        .checking(&account)
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    let opened = t0 - HOUR;
    account.goal(&route, t0 - DAY);
    account.rechecked(&route, RELAY, t0);
    account.live_boundary(&route, RELAY, t0 - DAY, opened - 1);
    host.tails.stand(&route, RELAY, opened);
    let (mut runner, handle) = runner(&host, test_policy());
    assert_eq!(idle(runner.step().await), None);

    // The generation breaks, with no event: the next read owes its seconds,
    // and a fetch proves them.
    host.tails.lapse(&route, RELAY);
    let at = clock.now();
    assert_eq!(ran(runner.step().await).outcome, Outcome::Advanced);
    assert_eq!(relay.queries()[0].since, opened);
    assert!(account.debt(&route, RELAY, at).is_empty());
    let proved = account.covered_through(&route, RELAY);

    // The next generation's tail stands from there, so nothing is owed.
    host.tails.stand(&route, RELAY, proved + 1);
    assert_eq!(
        idle(runner.step().await),
        Some(t0 + RUNNER_RECHECK_INTERVAL_SECS)
    );

    // It breaks too, and the relay reconnects half an hour later. The new
    // tail starts at the reconnect's EOSE, so only the downtime is owed.
    host.tails.lapse(&route, RELAY);
    clock.advance(30 * 60);
    let reconnected = clock.now();
    host.tails.stand(&route, RELAY, reconnected);
    let turns = host.debt_turns();
    let swept = relay.queries().len();
    handle.relay_reconnected(RELAY);
    assert_eq!(ran(runner.step().await).outcome, Outcome::Advanced);
    assert!(
        host.debt_turns() > turns,
        "the reconnect's step read the tails"
    );
    let downtime = relay.queries().split_off(swept);
    assert_eq!(downtime[0].since, proved + 1);
    assert_eq!(
        downtime.iter().map(|query| query.until).max(),
        Some(reconnected - 1)
    );
    assert_eq!(
        idle(runner.step().await),
        Some(t0 + RUNNER_RECHECK_INTERVAL_SECS)
    );
    assert!(relay.refetches().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_begins_on_tails_read_after_its_credit_wait() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    // The live REQ's generation broke an hour ago: everything since is owed.
    let opened = t0 - HOUR;
    account.goal(&route, t0 - DAY);
    account.live_boundary(&route, RELAY, t0 - DAY, opened - 1);
    let credits = recovery_credits::private_recovery_credit_pool_for_test();
    let held = hold_all_credits_for_test(&credits);
    let (mut runner, _handle) = runner_sharing(&host, &credits);
    let stepping = tokio::spawn(async move { matches!(runner.step().await, Step::Raced) });

    wait_until("the survey", WAIT, || host.debt_turns() == 2).await;
    // While it waits for a credit, the relay reconnects and its new tail
    // stands over the whole debt.
    host.tails.stand(&route, RELAY, opened);
    drop(held);

    assert!(stepping.await.unwrap(), "begin found nothing owed");
    assert_eq!(host.debt_turns(), 3);
    assert!(relay.queries().is_empty());
    assert!(account.app.recovery_unit(&route, RELAY).unwrap().is_none());
    assert_eq!(available_credits(&credits), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_cancelled_or_crashed_mid_sweep_requests_no_slice_twice() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - 6 * DAY;
    // Six days at an event an hour, over a cap of twenty: many slices.
    let events = every([1; 32], floor, t0, HOUR);
    let total = events.len() as u64;
    let relay = ModelRelay::new(RELAY, caps(20, true))
        .with_events(events)
        .checking(&account)
        .build();
    account.goal(&route, floor);
    account.rechecked(&route, RELAY, t0);
    let credits = recovery_credits::private_recovery_credit_pool_for_test();
    let host = || {
        let host = TestHost::new(
            &account,
            &clock,
            vec![required(&route, &[RELAY])],
            &[&relay],
        );
        host.tails.stand(&route, RELAY, t0);
        host
    };

    // Cancelled: the fourth request waits until the runner shuts down.
    relay.gate.hold_from(3);
    let (mut first, handle) = runner_sharing(&host(), &credits);
    let stepping = tokio::spawn(async move { ran(first.step().await).outcome });
    wait_until("the fourth request", WAIT, || relay.gate.waiting() == 1).await;
    handle.shutdown();
    assert_eq!(stepping.await.unwrap(), Outcome::Advanced);

    // Crashed: a new runner's task is dropped while a request waits.
    relay.gate.hold_from(relay.requests() + 2);
    let (second, _handle) = runner_sharing(&host(), &credits);
    let task = second.spawn();
    wait_until("a held request", WAIT, || relay.gate.waiting() == 1).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    relay.gate.open();

    // A third runner resumes from the ledger's cursor and finishes.
    let (mut third, _handle) = runner_sharing(&host(), &credits);
    let outcomes = run_until_idle(&mut third, 20).await;
    assert!(outcomes.iter().all(|outcome| *outcome == Outcome::Advanced));

    assert!(account.debt(&route, RELAY, t0 - 1).is_empty());
    assert_eq!(
        relay.refetches(),
        Vec::<u64>::new(),
        "a proven slice was fetched again"
    );
    assert_eq!(account.app.staged_recovery_total().unwrap().events, 0);
    assert_eq!(account.admitted_events(), total, "every event was admitted");
    assert_eq!(available_credits(&credits), 2);
}

/// A runner aborted mid-quantum leaves its attempt open, and its owner's
/// refund settles it as unanswered: the charge goes back, the unit keeps its
/// retry state and the relay gets no verdict. A runner whose quantum settles
/// leaves nothing open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_refunds_the_attempt_an_aborted_quantum_left_open() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - DAY;
    let relay = ModelRelay::new(RELAY, caps(20, true))
        .with_events(every([1; 32], floor, t0, HOUR))
        .checking(&account)
        .build();
    account.goal(&route, floor);
    account.rechecked(&route, RELAY, t0);
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    host.tails.stand(&route, RELAY, t0);
    let attempts = || {
        account
            .app
            .recovery_account_usage(clock.now())
            .unwrap()
            .attempts
    };

    relay.gate.hold_from(0);
    let (aborted, _handle) = runner(&host, test_policy());
    let open = aborted.open_attempts();
    let task = aborted.spawn();
    wait_until("a held request", WAIT, || relay.gate.waiting() == 1).await;
    assert_eq!(attempts(), 1, "the quantum began");
    assert!(!open.is_empty());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    open.refund(&account.app, &test_policy().unit, clock.now());
    assert!(open.is_empty());
    assert_eq!(attempts(), 0, "the refund gave the charge back");
    let unit = account.app.recovery_unit(&route, RELAY).unwrap().unwrap();
    assert_eq!(
        (
            unit.no_progress,
            unit.backoff_step,
            unit.next_attempt_at_seconds
        ),
        (0, 0, 0),
        "the unit keeps its retry state"
    );
    let health = account.app.recovery_relay_health(RELAY).unwrap().unwrap();
    assert_eq!(
        (health.unreachable_streak, health.cooldown),
        (0, None),
        "the relay gets no verdict"
    );

    relay.gate.open();
    let (mut settled, _handle) = runner(&host, test_policy());
    let open = settled.open_attempts();
    let outcomes = run_until_idle(&mut settled, 20).await;
    assert!(!outcomes.is_empty());
    assert!(open.is_empty(), "every quantum settled");
}

// A paused clock (Tokio allows one only on the current-thread runtime) makes
// each request take exactly its latency, so every quantum is cut at a known
// point.
#[tokio::test(start_paused = true)]
async fn recovery_runner_serves_held_groups_first_then_small_debts_and_every_group_each_round() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (large, small, held) = (group(1), group(2), group(3));
    // An event an hour everywhere: sixty days for the large group, an hour
    // for the small one and two for the held one.
    let mut events = every([1; 32], t0 - 60 * DAY, t0, HOUR);
    events.extend(every([2; 32], t0 - HOUR, t0, HOUR));
    events.extend(every([3; 32], t0 - 2 * HOUR, t0, HOUR));
    let relay = ModelRelay::new(RELAY, caps(100, true))
        .with_events(events)
        .with_latency(Duration::from_secs(1))
        .build();
    // A best-effort relay owes the small group too; its class comes last.
    let other = ModelRelay::new(OTHER_RELAY, caps(100, true)).build();
    account.goal(&large, t0 - 60 * DAY);
    account.goal(&small, t0 - HOUR);
    account.goal(&held, t0 - 2 * HOUR);
    let mut routes = [&large, &small, &held]
        .map(|route| required(route, &[RELAY]))
        .to_vec();
    routes[1].best_effort = vec![OTHER_RELAY.to_owned()];
    let host = TestHost::new(&account, &clock, routes, &[&relay, &other]);
    // The held group's tail stands, so its first quantum ends its debt. No
    // other tail stands: the large and small groups owe their newest seconds
    // again after every quantum, so the small debt never runs out.
    host.tails.stand(&held, RELAY, t0);
    let (mut runner, handle) = runner(&host, test_policy());
    handle.set_hints(PriorityHints {
        held: BTreeSet::from([held.clone()]),
        window: BTreeSet::new(),
    });

    let name = |route: &Route| match route {
        route if *route == large => "large",
        route if *route == small => "small",
        _ => "held",
    };
    let mut served = Vec::new();
    for _ in 0..6 {
        let summary = ran(runner.step().await);
        assert_eq!(summary.outcome, Outcome::Advanced);
        assert_eq!(summary.key.relay, RELAY);
        served.push(name(&summary.key.route));
    }

    // The held group goes first although it owes more than the small one.
    // Then each round serves the small debt first and the large one next,
    // while the best-effort relay waits for the class above it to clear.
    assert_eq!(
        served,
        ["held", "small", "large", "small", "large", "small"]
    );
    assert!(
        !account.debt(&large, RELAY, t0).is_empty(),
        "the large group still owes after two rounds"
    );
}

#[tokio::test(start_paused = true)]
async fn recovery_runner_serves_an_open_conversation_before_smaller_debts() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (open, closed) = (group(1), group(2));
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    account.goal(&open, t0 - DAY);
    account.goal(&closed, t0 - HOUR);
    let routes = vec![
        RunnerRoute {
            window: true,
            ..required(&open, &[RELAY])
        },
        required(&closed, &[RELAY]),
    ];
    let host = TestHost::new(&account, &clock, routes, &[&relay]);
    for route in [&open, &closed] {
        host.tails.stand(route, RELAY, t0);
    }
    let (mut runner, _handle) = runner(&host, test_policy());

    // Without the window the hour would go first, as the smaller debt.
    assert_eq!(ran(runner.step().await).key.route, open);
    assert_eq!(ran(runner.step().await).key.route, closed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_accounts_share_two_credits() {
    let clock = Clock::new();
    let t0 = clock.now();
    let credits = recovery_credits::private_recovery_credit_pool_for_test();
    let in_flight = Arc::new(InFlight::default());
    let mut accounts = Vec::new();
    for byte in 1..=3 {
        let account = account();
        let route = group(byte);
        account.goal(&route, t0 - DAY);
        let relay = ModelRelay::new(RELAY, caps(500, true))
            .with_events(every([byte; 32], t0 - DAY, t0, HOUR))
            .sharing(&in_flight)
            .build();
        relay.gate.hold_from(0);
        let host = TestHost::new(
            &account,
            &clock,
            vec![required(&route, &[RELAY])],
            &[&relay],
        );
        host.tails.stand(&route, RELAY, t0);
        let (runner, handle) = runner_sharing(&host, &credits);
        let task = runner.spawn();
        accounts.push((account, route, relay, handle, task));
    }

    wait_until("two quanta in flight", WAIT, || in_flight.now() == 2).await;
    // The third account waits for a credit, not for its relay.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(in_flight.now(), 2);
    assert_eq!(available_credits(&credits), 0);
    for (_, _, relay, _, _) in &accounts {
        relay.gate.open();
    }
    for (account, route, _, _, _) in &accounts {
        wait_until("every account caught up", WAIT, || {
            account.debt(route, RELAY, t0 - 1).is_empty()
        })
        .await;
    }

    assert_eq!(in_flight.max(), 2);
    for (_, _, _, handle, task) in accounts {
        handle.shutdown();
        task.await.unwrap();
    }
    assert_eq!(available_credits(&credits), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_live_traffic_never_resets_backoff() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let relay = stalling_relay([1; 32], floor).build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());

    assert_eq!(ran(runner.step().await).outcome, Outcome::NoProgress);
    let unit = account.unit(&route, RELAY);
    assert_eq!((unit.no_progress, unit.backoff_step), (1, 1));
    let retry = unit.next_attempt_at_seconds;

    // Live traffic proves the rest of the hour on the same relay.
    account.live_boundary(&route, RELAY, floor + 1, t0 - 1);
    assert_eq!(idle(runner.step().await), Some(retry));
    let unit = account.unit(&route, RELAY);
    assert_eq!(
        (
            unit.no_progress,
            unit.backoff_step,
            unit.next_attempt_at_seconds
        ),
        (1, 1, retry)
    );

    clock.advance_to(retry);
    assert_eq!(ran(runner.step().await).outcome, Outcome::NoProgress);
    let unit = account.unit(&route, RELAY);
    assert_eq!((unit.no_progress, unit.backoff_step), (2, 2));

    // Live traffic proves the stalled second itself while the next quantum's
    // request waits. That is not the quantum's progress.
    clock.advance_to(unit.next_attempt_at_seconds);
    relay.gate.hold_from(relay.requests());
    let stepping = tokio::spawn(async move { ran(runner.step().await).outcome });
    wait_until("the held request", WAIT, || relay.gate.waiting() == 1).await;
    account.live_boundary(&route, RELAY, floor, floor);
    relay.gate.open();
    assert_eq!(stepping.await.unwrap(), Outcome::NoProgress);
    let unit = account.unit(&route, RELAY);
    assert_eq!((unit.no_progress, unit.backoff_step), (3, 3));
    assert!(account.debt(&route, RELAY, t0 - 1).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_breaks_a_unit_after_six_answers_without_progress() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let relay = stalling_relay([1; 32], floor).build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());

    for answer in 1..=5 {
        assert_eq!(ran(runner.step().await).outcome, Outcome::NoProgress);
        let unit = account.unit(&route, RELAY);
        assert_eq!(
            (unit.state, unit.no_progress),
            (RecoveryUnitState::Active, answer)
        );
        assert_eq!(
            idle(runner.step().await),
            Some(unit.next_attempt_at_seconds)
        );
        clock.advance_to(unit.next_attempt_at_seconds);
    }
    assert_eq!(ran(runner.step().await).outcome, Outcome::NoProgress);

    let unit = account.unit(&route, RELAY);
    assert_eq!(
        unit.state,
        RecoveryUnitState::Broken(RecoveryUnitBreak::NoProgress)
    );
    let requests = relay.requests();
    clock.advance(DAY);
    assert_eq!(
        idle(runner.step().await),
        None,
        "a broken unit waits for evidence, not for time"
    );
    assert_eq!(relay.requests(), requests);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_rearms_nothing_on_an_unknown_caps_read() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let relay = stalling_relay([1; 32], floor).build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, handle) = runner(&host, test_policy());
    let broken = RecoveryUnitState::Broken(RecoveryUnitBreak::NoProgress);
    let state = || {
        let unit = account.app.recovery_unit(&route, RELAY).unwrap();
        unit.map(|unit| unit.state)
    };
    while state() != Some(broken) {
        match runner.step().await {
            Step::Ran(summary) => assert_eq!(summary.outcome, Outcome::NoProgress),
            Step::Idle { next_due } => clock.advance_to(next_due.unwrap()),
            Step::Raced | Step::Stopped => panic!("the unit runs until it breaks"),
        }
    }
    let requests = relay.requests();

    // The relay reconnects without a document: no evidence its caps changed.
    host.caps_unknown.store(true, Ordering::SeqCst);
    handle.relay_reconnected(RELAY);
    assert_eq!(idle(runner.step().await), None);
    assert_eq!(account.unit(&route, RELAY).state, broken);
    // Nor is reading the caps it was planned with.
    host.caps_unknown.store(false, Ordering::SeqCst);
    handle.relay_reconnected(RELAY);
    assert_eq!(idle(runner.step().await), None);
    assert_eq!(account.unit(&route, RELAY).state, broken);
    assert_eq!(relay.requests(), requests, "a broken unit fetches nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_cools_a_relay_after_three_unreachable_answers() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (first, second) = (group(1), group(2));
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .unreachable()
        .build();
    let routes = vec![required(&first, &[RELAY]), required(&second, &[RELAY])];
    let host = TestHost::new(&account, &clock, routes, &[&relay]);
    for route in [&first, &second] {
        account.goal(route, t0 - HOUR);
        host.tails.stand(route, RELAY, t0);
    }
    let (mut runner, handle) = runner(&host, test_policy());

    let served = [ran(runner.step().await), ran(runner.step().await)];
    assert!(
        served
            .iter()
            .all(|summary| summary.outcome == Outcome::Unreachable)
    );
    let retries = [&first, &second].map(|route| account.unit(route, RELAY).next_attempt_at_seconds);
    assert_eq!(idle(runner.step().await), retries.iter().min().copied());
    let health = account.app.recovery_relay_health(RELAY).unwrap().unwrap();
    assert_eq!((health.unreachable_streak, health.cooldown), (2, None));

    clock.advance_to(retries[0].max(retries[1]));
    assert_eq!(ran(runner.step().await).outcome, Outcome::Unreachable);
    let health = account.app.recovery_relay_health(RELAY).unwrap().unwrap();
    let (_, until) = health.cooldown.expect("the third answer cools the relay");
    assert_eq!(idle(runner.step().await), Some(until));

    // A reconnect ends the cooldown at once.
    relay.set_reachable(true);
    handle.relay_reconnected(RELAY);
    assert_eq!(ran(runner.step().await).outcome, Outcome::Advanced);
    let health = account.app.recovery_relay_health(RELAY).unwrap().unwrap();
    assert_eq!((health.unreachable_streak, health.cooldown), (0, None));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_pauses_the_account_at_its_hourly_cap() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let groups = [group(1), group(2), group(3)];
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    let routes = groups
        .iter()
        .map(|route| required(route, &[RELAY]))
        .collect();
    let host = TestHost::new(&account, &clock, routes, &[&relay]);
    for route in &groups {
        account.goal(route, t0 - HOUR);
        host.tails.stand(route, RELAY, t0);
    }
    let mut policy = test_policy();
    policy.unit.max_attempts_per_hour = 2;
    let (mut runner, _handle) = runner(&host, policy);

    let served = [ran(runner.step().await), ran(runner.step().await)];
    assert!(
        served
            .iter()
            .all(|summary| summary.outcome == Outcome::Advanced)
    );
    let requests = relay.requests();
    let until = account
        .app
        .recovery_account_paused_until(&policy.unit, clock.now())
        .unwrap()
        .expect("two attempts reach the cap");
    assert_eq!(idle(runner.step().await), Some(until));
    assert_eq!(runner.reported_pause, Some(until));
    assert_eq!(relay.requests(), requests);
    // Once per pause: the next step while paused records nothing more.
    assert_eq!(idle(runner.step().await), Some(until));
    let audited = std::mem::take(&mut *host.audited.lock().unwrap());
    let [
        AuditEventKind::RecoveryRunnerPaused {
            cap,
            attempts,
            paused_for_secs,
            pauses,
            ..
        },
    ] = audited.as_slice()
    else {
        panic!("one pause row");
    };
    assert_eq!(
        (*cap, *attempts, *paused_for_secs),
        (RecoveryRunnerCap::Attempts, 2, until - clock.now())
    );
    assert!(*pauses >= 1 && recovery_runner_counts().account_pauses >= *pauses);
    let waiting = groups
        .iter()
        .find(|route| served.iter().all(|summary| summary.key.route != **route))
        .unwrap();
    assert!(account.app.recovery_unit(waiting, RELAY).unwrap().is_none());

    clock.advance_to(until);
    let summary = ran(runner.step().await);
    assert_eq!(
        (&summary.key.route, summary.outcome),
        (waiting, Outcome::Advanced)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_catches_up_a_cap_only_relay_by_count_proofs() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - 3 * DAY;
    let events = every([1; 32], floor, t0, 20 * 60);
    let total = events.len() as u64;
    let relay = ModelRelay::new(RELAY, caps(50, false))
        .with_events(events)
        .checking(&account)
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());

    let outcomes = run_until_idle(&mut runner, 10).await;

    assert!(!outcomes.is_empty());
    assert!(outcomes.iter().all(|outcome| *outcome == Outcome::Advanced));
    assert!(account.debt(&route, RELAY, t0 - 1).is_empty());
    assert!(relay.seconds().is_empty(), "no second needed its id set");
    assert!(
        account
            .app
            .recovery_coverage_ranges(&route, RELAY)
            .unwrap()
            .iter()
            .all(|proved| proved.proof == RecoveryCoverageProof::SweepSlice)
    );
    assert_eq!(account.app.staged_recovery_total().unwrap().events, 0);
    assert_eq!(account.admitted_events(), total, "every event was admitted");
    let unit = account.unit(&route, RELAY);
    assert_eq!(
        (unit.state, unit.no_progress),
        (RecoveryUnitState::Active, 0)
    );
    let health = account.app.recovery_relay_health(RELAY).unwrap().unwrap();
    assert_eq!(
        health.caps,
        Some(RecoveryRelayCaps {
            max_limit: Some(50),
            negentropy: false,
        })
    );
    assert!(relay.refetches().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_tries_a_best_effort_relay_once_per_new_debt() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    let other = ModelRelay::new(OTHER_RELAY, caps(500, true))
        .unreachable()
        .build();
    let routes = vec![RunnerRoute {
        best_effort: vec![OTHER_RELAY.to_owned()],
        ..required(&route, &[RELAY])
    }];
    let host = TestHost::new(&account, &clock, routes, &[&relay, &other]);
    account.goal(&route, t0 - HOUR);
    account.rechecked(&route, RELAY, t0);
    host.tails.stand(&route, RELAY, t0);
    host.tails.stand(&route, OTHER_RELAY, t0);
    let (mut runner, handle) = runner(&host, test_policy());

    let first = ran(runner.step().await);
    assert_eq!(
        (first.key.relay.as_str(), first.best_effort, first.outcome),
        (RELAY, false, Outcome::Advanced)
    );
    let second = ran(runner.step().await);
    assert_eq!(
        (
            second.key.relay.as_str(),
            second.best_effort,
            second.outcome
        ),
        (OTHER_RELAY, true, Outcome::Unreachable)
    );
    assert_eq!(
        idle(runner.step().await),
        Some(t0 + RUNNER_RECHECK_INTERVAL_SECS),
        "one attempt per debt"
    );
    assert!(
        account
            .app
            .recovery_unit(&route, OTHER_RELAY)
            .unwrap()
            .is_none()
    );
    let health = account.app.recovery_relay_health(OTHER_RELAY).unwrap();
    assert!(
        health.is_none_or(|health| health.unreachable_streak == 0 && health.cooldown.is_none())
    );
    assert_eq!(
        account
            .app
            .recovery_account_usage(clock.now())
            .unwrap()
            .attempts,
        1
    );

    // A reconnect is new evidence: one more attempt.
    handle.relay_reconnected(OTHER_RELAY);
    let third = ran(runner.step().await);
    assert_eq!(
        (third.key.relay.as_str(), third.outcome),
        (OTHER_RELAY, Outcome::Unreachable)
    );
    assert_eq!(
        idle(runner.step().await),
        Some(t0 + RUNNER_RECHECK_INTERVAL_SECS)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_explicit_pass_serves_each_due_unit_once() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let groups = [group(1), group(2), group(3)];
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    let other = ModelRelay::new(OTHER_RELAY, caps(500, true)).build();
    let mut routes: Vec<RunnerRoute> = groups
        .iter()
        .map(|route| required(route, &[RELAY]))
        .collect();
    routes[1].best_effort = vec![OTHER_RELAY.to_owned()];
    let host = TestHost::new(&account, &clock, routes, &[&relay, &other]);
    // No tails stand, so a unit owes its newest seconds again right after its
    // quantum. The pass still serves it once, a held group's included, and
    // reaches the classes below it.
    for route in &groups {
        account.goal(route, t0 - HOUR);
        account.rechecked(route, RELAY, t0);
    }
    let (mut runner, handle) = runner(&host, test_policy());
    handle.set_hints(PriorityHints {
        held: BTreeSet::from([groups[0].clone()]),
        window: BTreeSet::new(),
    });

    let report = runner.run_pass(Duration::from_secs(30)).await;
    assert_eq!(
        report,
        PassReport {
            quanta: 4,
            advanced: 4
        }
    );

    clock.advance(60);
    let report = runner.run_pass(Duration::from_secs(30)).await;
    assert_eq!(
        report,
        PassReport {
            quanta: 4,
            advanced: 4
        }
    );
}

// A paused clock (Tokio allows one only on the current-thread runtime) lets
// the rate-limit waits and the caps reads pass without the test waiting.
#[tokio::test(start_paused = true)]
async fn recovery_runner_cools_a_relay_that_only_says_rate_limited() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .rate_limiting()
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, t0 - HOUR);
    host.tails.stand(&route, RELAY, t0);
    // The starting values: the waits double until one would outlast the
    // quantum, which then ends without an answer.
    let (mut runner, _handle) = runner(&host, RecoveryRunnerPolicy::default());

    let summary = ran(runner.step().await);
    assert_eq!(summary.outcome, Outcome::RateLimited);
    assert!(
        relay.requests() > 1,
        "it waited the limit out in the quantum"
    );
    let health = account.app.recovery_relay_health(RELAY).unwrap().unwrap();
    let (_, until) = health.cooldown.expect("the relay cools down");
    assert_eq!(idle(runner.step().await), Some(until));
    assert_eq!(
        account
            .app
            .recovery_account_usage(clock.now())
            .unwrap()
            .attempts,
        1
    );
}

/// One route on a relay that stalls on its oldest second (every reply is
/// full, so none proves a slice) and rate limits the requests in `limited`,
/// stepped once at the starting values.
async fn step_against_rate_limits(
    limited: Range<usize>,
    hold_from: Option<usize>,
) -> (Account, Arc<ModelRelay>, QuantumSummary) {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let relay = stalling_relay([1; 32], floor)
        .rate_limiting_requests(limited)
        .build();
    if let Some(index) = hold_from {
        relay.gate.hold_from(index);
    }
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, RecoveryRunnerPolicy::default());
    let summary = ran(runner.step().await);
    (account, relay, summary)
}

#[tokio::test(start_paused = true)]
async fn recovery_runner_cools_a_relay_rate_limited_after_an_answer() {
    // The first reply answers; every later one is rate limited until the
    // quantum runs out.
    let (account, relay, summary) = step_against_rate_limits(1..usize::MAX, None).await;

    assert_eq!(summary.outcome, Outcome::RateLimited);
    assert!(relay.requests() > 2);
    let health = account.app.recovery_relay_health(RELAY).unwrap().unwrap();
    assert!(health.cooldown.is_some(), "the relay cools down");
    assert_eq!(account.unit(&group(1), RELAY).no_progress, 0);
}

#[tokio::test(start_paused = true)]
async fn recovery_runner_settles_an_answer_after_a_rate_limit_as_answered() {
    // The first request is rate limited, the second answers, and the third
    // is still in flight when the quantum runs out.
    let (account, relay, summary) = step_against_rate_limits(0..1, Some(2)).await;

    assert_eq!(summary.outcome, Outcome::NoProgress);
    assert_eq!(relay.gate.waiting(), 0, "the cut request was dropped");
    let health = account.app.recovery_relay_health(RELAY).unwrap().unwrap();
    assert!(
        health.cooldown.is_none(),
        "an answer cleared the rate limit"
    );
    assert_eq!(account.unit(&group(1), RELAY).no_progress, 1);
}

#[tokio::test(start_paused = true)]
async fn recovery_runner_reads_a_pass_cut_during_a_rate_limit_as_preempted() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .rate_limiting_requests(0..1)
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, t0 - HOUR);
    host.tails.stand(&route, RELAY, t0);
    let policy = RecoveryRunnerPolicy::default();
    let (mut runner, _handle) = runner(&host, policy);

    // The pass ends inside the first rate-limit wait: a preemption, not the
    // relay's verdict, so nothing is charged and nothing cools.
    let budget = policy.sweep.rate_limit_backoff / 2;
    assert_eq!(
        runner.run_pass(budget).await,
        PassReport {
            quanta: 1,
            advanced: 0
        }
    );
    assert_eq!(relay.requests(), 1);
    let unit = account.unit(&route, RELAY);
    assert_eq!((unit.no_progress, unit.backoff_step), (0, 0));
    let health = account.app.recovery_relay_health(RELAY).unwrap();
    assert!(health.is_none_or(|health| health.cooldown.is_none()));
    assert_eq!(
        account
            .app
            .recovery_account_usage(clock.now())
            .unwrap()
            .attempts,
        0
    );

    // A full quantum waits the limit out.
    assert_eq!(ran(runner.step().await).outcome, Outcome::Advanced);
}

#[tokio::test(start_paused = true)]
async fn recovery_runner_retries_a_failed_reconnect_before_the_cooldown_ends() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, t0 - HOUR);
    host.tails.stand(&route, RELAY, t0);
    let mut policy = test_policy();
    policy.unit.cooldown_base_seconds = HOUR;
    for _ in 0..policy.unit.cooldown_after_unreachable {
        account
            .app
            .settle_recovery_unit(&route, RELAY, Outcome::Unreachable, &policy.unit, t0)
            .unwrap();
    }
    let cooling = || {
        account
            .app
            .recovery_relay_health(RELAY)
            .unwrap()
            .unwrap()
            .cooldown
            .is_some()
    };
    assert!(cooling());
    let (runner, handle) = runner(&host, policy);
    let task = runner.spawn();
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(relay.requests(), 0, "every unit is cooling");

    // The reconnect's write fails once. The task retries it on the local
    // backoff, not at the end of the hour-long cooldown it should end.
    host.fail_next_turns(1);
    let started = Instant::now();
    handle.relay_reconnected(RELAY);
    wait_until("the reconnect", Duration::from_secs(5 * 60), || !cooling()).await;
    wait_until("the sweep", WAIT, || relay.requests() > 0).await;
    assert!(started.elapsed() < Duration::from_secs(60));

    handle.shutdown();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn recovery_runner_hears_the_pools_reconnects() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, t0 - HOUR);
    host.tails.stand(&route, RELAY, t0);
    let mut policy = test_policy();
    policy.unit.cooldown_base_seconds = HOUR;
    for _ in 0..policy.unit.cooldown_after_unreachable {
        account
            .app
            .settle_recovery_unit(&route, RELAY, Outcome::Unreachable, &policy.unit, t0)
            .unwrap();
    }
    let cooling = || {
        account
            .app
            .recovery_relay_health(RELAY)
            .unwrap()
            .unwrap()
            .cooldown
            .is_some()
    };
    // The pool publishes the relay's URL as it parsed it, with a slash.
    let published = format!("{RELAY}/");
    // A connection made before the runner first looks ends nothing.
    host.connect(&published);
    let (runner, handle) = runner(&host, policy);
    let task = runner.spawn();
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(cooling());
    assert_eq!(relay.requests(), 0, "every unit is cooling");

    // The pool connects it again: the idle task wakes, ends the cooldown,
    // and the survey that follows reads the tails.
    let turns = host.debt_turns();
    host.connect(&published);
    wait_until("the reconnect", WAIT, || !cooling()).await;
    wait_until("the sweep", WAIT, || relay.requests() > 0).await;
    assert!(host.debt_turns() > turns);

    handle.shutdown();
    task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_counts_a_best_effort_attempt_only_when_it_reached_the_relay() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (route, unrelated) = (group(1), group(2));
    let floor = t0 - HOUR;
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    let other = ModelRelay::new(OTHER_RELAY, caps(500, true))
        .with_events(every([1; 32], floor, t0, 60))
        .build();
    let routes = vec![RunnerRoute {
        best_effort: vec![OTHER_RELAY.to_owned()],
        ..required(&route, &[RELAY])
    }];
    let host = TestHost::new(&account, &clock, routes, &[&relay, &other]);
    account.goal(&route, floor);
    account.rechecked(&route, RELAY, t0);
    host.tails.stand(&route, RELAY, t0);
    host.tails.stand(&route, OTHER_RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());
    assert_eq!(ran(runner.step().await).key.relay, RELAY);

    // Its staging write fails: a local failure, not the one attempt. It runs
    // again once the local hold ends.
    host.fail_next_turns(1);
    let failed = ran(runner.step().await);
    assert_eq!(
        (failed.key.relay.as_str(), failed.outcome),
        (OTHER_RELAY, Outcome::LocalFailure)
    );
    assert!(idle(runner.step().await).is_some(), "held, not done");
    clock.advance(RecoveryRunnerPolicy::default().local_failure_backoff_seconds(1));
    other.set_reachable(false);
    let tried = ran(runner.step().await);
    assert_eq!(
        (tried.key.relay.as_str(), tried.outcome),
        (OTHER_RELAY, Outcome::Unreachable)
    );
    assert_eq!(
        idle(runner.step().await),
        Some(t0 + RUNNER_RECHECK_INTERVAL_SECS),
        "one attempt per debt"
    );

    // A loss on another route moves the account's un-cover mark but changes
    // nothing this relay owes.
    account.goal(&unrelated, floor);
    account.live_boundary(&unrelated, RELAY, floor, t0);
    let mark = account.app.recovery_coverage_mark().unwrap();
    account
        .app
        .uncover_recovery_coverage(std::slice::from_ref(&unrelated), floor)
        .unwrap();
    assert_ne!(account.app.recovery_coverage_mark().unwrap(), mark);
    assert_eq!(
        idle(runner.step().await),
        Some(t0 + RUNNER_RECHECK_INTERVAL_SECS)
    );

    // Debt before its first owed second is new evidence. The required relay
    // owes it too, and its class goes first.
    other.set_reachable(true);
    account.goal(&route, floor - HOUR);
    assert_eq!(ran(runner.step().await).key.relay, RELAY);
    let renewed = ran(runner.step().await);
    assert_eq!(renewed.key.relay, OTHER_RELAY);
}

#[test]
fn recovery_runner_sizes_a_route_last_seen_empty_by_its_span() {
    let (quiet, busy) = (group(1), group(2));
    let candidate = |route: &Route, owed_seconds: u64| select::Candidate {
        key: unit_key(route, RELAY),
        best_effort: false,
        owed_seconds,
        position: 0,
        last_served_at: None,
        due_at: 0,
        blocked: false,
        recheck: false,
    };
    let mut memory = select::Memory::default();
    let policy = test_policy();
    // The quiet route's last quantum proved an hour with no events.
    let report = quantum::QuantumReport {
        end: SweepEnd::Finished,
        requests: 1,
        answers: 1,
        rate_limited: false,
        unstaged_bytes: 0,
        newly_covered_seconds: HOUR,
        proved_seconds: HOUR,
        proved_events: 0,
        delta: HOUR,
        observed_cap: None,
        stop: None,
    };
    memory.settled(
        &candidate(&quiet, HOUR),
        Some(&report),
        Outcome::Advanced,
        0,
        &policy,
    );

    // A month of quiet owes more than a minute of the busy route, which has
    // no rate yet.
    let survey = select::Survey {
        candidates: vec![candidate(&quiet, 30 * DAY), candidate(&busy, 60)],
        rechecks: Vec::new(),
        paused_until: None,
        fenced: BTreeSet::new(),
        window: BTreeSet::new(),
        catching_up: BTreeSet::new(),
    };
    let select::Pick::Unit(first) =
        select::pick(survey, &mut memory, &PriorityHints::default(), 0, true)
    else {
        panic!("a unit is due");
    };
    assert_eq!(first.key.route, busy);
}

#[tokio::test(start_paused = true)]
async fn recovery_runner_bounds_caps_reads_by_the_pass_and_shutdown() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, t0 - HOUR);
    host.tails.stand(&route, RELAY, t0);
    *host.caps_latency.lock().unwrap() = Duration::from_secs(HOUR);
    let credits = recovery_credits::private_recovery_credit_pool_for_test();
    let budget = Duration::from_secs(5);

    // A pass ends at its deadline inside the quantum's caps read, with its
    // credit released and nothing charged.
    let (mut runner, handle) = runner_sharing(&host, &credits);
    let started = Instant::now();
    assert_eq!(runner.run_pass(budget).await, PassReport::default());
    assert!(started.elapsed() < 2 * budget);
    assert_eq!(available_credits(&credits), 2);
    assert_eq!(relay.requests(), 0);
    assert!(account.app.recovery_unit(&route, RELAY).unwrap().is_none());

    // Likewise inside a reconnect's caps read, which waits for the next step.
    handle.relay_reconnected(RELAY);
    let started = Instant::now();
    assert_eq!(runner.run_pass(budget).await, PassReport::default());
    assert!(started.elapsed() < 2 * budget);
    assert!(runner.reconnected().contains(RELAY));

    // A shutdown ends either read.
    let stop = |handle: RecoveryRunnerHandle| {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            handle.shutdown();
        })
    };
    let stopping = stop(handle);
    assert!(matches!(runner.step().await, Step::Stopped));
    stopping.await.unwrap();
    assert!(runner.reconnected().contains(RELAY));
    let (mut runner, handle) = runner_sharing(&host, &credits);
    let stopping = stop(handle);
    assert!(matches!(runner.step().await, Step::Stopped));
    stopping.await.unwrap();
    assert_eq!(available_credits(&credits), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_charges_returned_bytes_to_required_units_alone() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    // The required relay stalls on its oldest second, so every reply it sends
    // is discarded and no slice is staged.
    let relay = stalling_relay([1; 32], floor).build();
    // The best-effort relay proves the whole hour.
    let other = ModelRelay::new(OTHER_RELAY, caps(500, true))
        .with_events(every([1; 32], floor + 1, t0, 60))
        .build();
    let routes = vec![RunnerRoute {
        best_effort: vec![OTHER_RELAY.to_owned()],
        ..required(&route, &[RELAY])
    }];
    let host = TestHost::new(&account, &clock, routes, &[&relay, &other]);
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, t0);
    host.tails.stand(&route, OTHER_RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());
    let usage = || account.app.recovery_account_usage(clock.now()).unwrap();

    let first = ran(runner.step().await);
    assert_eq!(
        (first.key.relay.as_str(), first.outcome),
        (RELAY, Outcome::NoProgress)
    );
    assert_eq!(account.app.staged_recovery_total().unwrap().events, 0);
    let charged = usage().event_bytes;
    assert!(charged > 0, "discarded replies are charged");

    let second = ran(runner.step().await);
    assert_eq!(
        (second.key.relay.as_str(), second.outcome),
        (OTHER_RELAY, Outcome::Advanced)
    );
    assert!(account.app.staged_recovery_total().unwrap().events > 0);
    assert_eq!(usage().event_bytes, charged, "best effort is never charged");
    assert_eq!(usage().attempts, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_leaves_a_slice_owed_while_its_events_route_nowhere() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let events = every([1; 32], floor, t0, 10 * 60);
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .with_events(events.clone())
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, t0);
    // The account was just given the relay: its installed subscriptions do
    // not route the group there yet.
    host.unrouted
        .lock()
        .unwrap()
        .extend(events.iter().map(|event| event.id.to_bytes().to_vec()));
    let (mut runner, _handle) = runner(&host, test_policy());
    let usage = || account.app.recovery_account_usage(clock.now()).unwrap();

    // A local failure: the relay is not blamed, and the unit waits out a
    // local hold rather than fetching the same slice again at once.
    assert_eq!(ran(runner.step().await).outcome, Outcome::LocalFailure);
    assert_eq!(account.app.staged_recovery_total().unwrap().events, 0);
    assert!(
        !account.debt(&route, RELAY, t0 - 1).is_empty(),
        "nothing it fetched covers the hour"
    );
    assert!(usage().event_bytes > 0, "its bytes are charged");
    let due = idle(runner.step().await).expect("the unit is retried");

    // Once the subscriptions catch up, the retry stages and covers it.
    host.unrouted.lock().unwrap().clear();
    clock.advance_to(due);
    assert_eq!(ran(runner.step().await).outcome, Outcome::Advanced);
    assert_eq!(
        account.app.staged_recovery_total().unwrap().events,
        events.len() as u64
    );
    assert!(account.debt(&route, RELAY, t0 - 1).is_empty());
}

#[tokio::test(start_paused = true)]
async fn recovery_runner_charges_what_a_dropped_request_already_read() {
    const READ: u64 = 4096;
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    // The first request reads, then outlasts the quantum: an id fetch whose
    // earlier chunks completed and whose next one never comes back.
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .reading_before_reply(READ)
        .build();
    relay.gate.hold_from(0);
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, t0 - HOUR);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());

    assert_eq!(ran(runner.step().await).outcome, Outcome::Unanswered);
    assert_eq!(relay.gate.waiting(), 0, "the deadline dropped the request");
    assert_eq!(
        account
            .app
            .recovery_account_usage(clock.now())
            .unwrap()
            .event_bytes,
        READ
    );
}

// The paused clock (Tokio allows one only on the current-thread runtime)
// runs the quantum out without the test waiting in real time.
#[tokio::test(start_paused = true)]
async fn recovery_runner_charges_the_reply_a_cut_request_was_reading() {
    const READ: u64 = 4096;
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    // The first request is still reading when the quantum runs out; its
    // relay ends it when interrupted and reports what it read.
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .interruptible(READ)
        .build();
    relay.gate.hold_from(0);
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, t0 - HOUR);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());

    let started = Instant::now();
    assert_eq!(ran(runner.step().await).outcome, Outcome::Unanswered);
    assert!(
        started.elapsed() < RUNNER_QUANTUM + INTERRUPT_GRACE,
        "the interrupted request ended within the grace"
    );
    assert_eq!(relay.gate.waiting(), 0);
    assert_eq!(
        account
            .app
            .recovery_account_usage(clock.now())
            .unwrap()
            .event_bytes,
        READ
    );
}

// The paused clock (Tokio allows one only on the current-thread runtime)
// keeps the quantum's deadline away while the stop waits for the request.
#[tokio::test(start_paused = true)]
async fn recovery_runner_charges_the_reply_a_stopped_request_was_reading() {
    const READ: u64 = 4096;
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    // The first request is still reading when the runner is stopped, as an
    // explicit caller's cancel stops it; its relay ends it when interrupted
    // and reports what it read.
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .interruptible(READ)
        .build();
    relay.gate.hold_from(0);
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, t0 - HOUR);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, handle) = runner(&host, test_policy());

    let stop = async {
        // Busy, so the paused clock never runs the quantum out first.
        while relay.gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        handle.shutdown();
    };
    let (step, ()) = tokio::join!(runner.step(), stop);
    assert_eq!(ran(step).outcome, Outcome::Unanswered);
    assert_eq!(relay.gate.waiting(), 0, "the stop ended the request");
    assert_eq!(
        account
            .app
            .recovery_account_usage(clock.now())
            .unwrap()
            .event_bytes,
        READ
    );
}

// The paused clock (Tokio allows one only on the current-thread runtime)
// waits out the rate limit and the quantum without the test doing so.
#[tokio::test(start_paused = true)]
async fn recovery_runner_reads_a_cut_retry_after_a_rate_limit_as_rate_limited() {
    const READ: u64 = 4096;
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    // The first request is rate limited; the retry is still reading when the
    // quantum runs out. Its interrupted end is no answer: the rate limit
    // never cleared.
    let relay = stalling_relay([1; 32], floor)
        .rate_limiting_requests(0..1)
        .interruptible(READ)
        .build();
    relay.gate.hold_from(1);
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, RecoveryRunnerPolicy::default());

    assert_eq!(ran(runner.step().await).outcome, Outcome::RateLimited);
    assert_eq!(relay.requests(), 2);
    let health = account.app.recovery_relay_health(RELAY).unwrap().unwrap();
    assert!(health.cooldown.is_some(), "the relay cools down");
    assert_eq!(
        account
            .app
            .recovery_account_usage(clock.now())
            .unwrap()
            .event_bytes,
        READ
    );
}

// A paused clock (Tokio allows one only on the current-thread runtime) lets
// the task's retry timer fire without the test waiting in real time.
#[tokio::test(start_paused = true)]
async fn recovery_runner_task_wakes_on_a_bump_and_at_its_retry_time() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let relay = stalling_relay([1; 32], floor).build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, floor);
    let (runner, handle) = runner(&host, test_policy());
    let task = runner.spawn();

    tokio::time::sleep(Duration::from_secs(HOUR)).await;
    assert_eq!(relay.requests(), 0, "nothing is owed, so the task sleeps");

    // The generation breaks, and whoever sees it bumps the runner.
    host.tails.lapse(&route, RELAY);
    handle.bump();
    let backoff = |step: u32| {
        account
            .app
            .recovery_unit(&route, RELAY)
            .unwrap()
            .is_some_and(|unit| unit.backoff_step == step)
    };
    wait_until("the bumped quantum", WAIT, || backoff(1)).await;
    let first = account.unit(&route, RELAY).last_served_at_seconds.unwrap();

    // It answered without progress; the task wakes at the retry time alone.
    wait_until("the retry", Duration::from_secs(5 * 60), || backoff(2)).await;
    let second = account.unit(&route, RELAY).last_served_at_seconds.unwrap();
    assert!(second >= first + RUNNER_BACKOFF_BASE_SECS);

    handle.shutdown();
    task.await.unwrap();
}

// The account's own wake sender (the routing's) wakes a runner built on it,
// and the spawned task answers a pass until it stops. Paused as above.
#[tokio::test(start_paused = true)]
async fn recovery_runner_task_wakes_on_its_accounts_sender_and_answers_passes() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let relay = stalling_relay([1; 32], floor).build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, floor);
    let wake = tokio::sync::watch::channel(0).0;
    let (runner, handle) = RecoveryRunner::waking_on(
        host.clone(),
        test_policy(),
        recovery_credits::private_recovery_credit_pool_for_test(),
        wake.clone(),
    );
    let task = runner.spawn();

    tokio::time::sleep(Duration::from_secs(HOUR)).await;
    assert_eq!(relay.requests(), 0, "nothing is owed, so the task sleeps");
    host.tails.lapse(&route, RELAY);
    wake.send_modify(|bumps| *bumps += 1);
    wait_until("the woken quantum", WAIT, || {
        account
            .app
            .recovery_unit(&route, RELAY)
            .unwrap()
            .is_some_and(|unit| unit.last_served_at_seconds.is_some())
    })
    .await;

    assert!(handle.run_pass(WAIT).await.is_some());
    handle.shutdown();
    task.await.unwrap();
    assert!(
        handle.run_pass(WAIT).await.is_none(),
        "a stopped runner runs no pass"
    );
}

#[test]
fn recovery_runner_classifies_every_sweep_end() {
    use SweepEnd as End;
    let refused = ClosedReason(None);
    let timed_out = End::Unreachable(UnreachableKind::TimedOut);
    let disconnected = End::Unreachable(UnreachableKind::Disconnected);
    let local = Some(SinkStop::Local);
    let stale = Some(SinkStop::StaleMark);
    let gone = Some(SinkStop::WorkerGone);
    let unrouted = Some(SinkStop::Unrouted);
    // (end, answered, last reply rate limited, newly covered, sink stop, still
    // owed)
    let cases = [
        (
            (End::Finished, true, false, 0, None, true),
            Outcome::NoProgress,
        ),
        (
            (End::Finished, true, false, 0, None, false),
            Outcome::NothingOwed,
        ),
        (
            (End::Finished, true, false, 9, None, false),
            Outcome::Advanced,
        ),
        (
            (End::DeadlineReached, false, false, 0, None, true),
            Outcome::Unanswered,
        ),
        (
            (End::DeadlineReached, false, true, 0, None, true),
            Outcome::RateLimited,
        ),
        // Answers before the rate limit do not clear it.
        (
            (End::DeadlineReached, true, true, 0, None, true),
            Outcome::RateLimited,
        ),
        (
            (End::DeadlineReached, true, false, 0, None, true),
            Outcome::NoProgress,
        ),
        (
            (End::DeadlineReached, true, false, 9, None, true),
            Outcome::Advanced,
        ),
        (
            (End::DeadlineReached, true, true, 9, None, true),
            Outcome::Advanced,
        ),
        (
            (End::Cancelled, false, false, 0, None, true),
            Outcome::Unanswered,
        ),
        (
            (End::Cancelled, true, false, 0, None, true),
            Outcome::Unanswered,
        ),
        (
            (End::Cancelled, true, false, 9, None, true),
            Outcome::Advanced,
        ),
        (
            (
                End::SaturatedSecond { second: 7 },
                true,
                false,
                0,
                None,
                true,
            ),
            Outcome::NoProgress,
        ),
        (
            (End::RateLimited, true, true, 0, None, true),
            Outcome::RateLimited,
        ),
        // Progress outranks a relay's later verdict; the next quantum
        // without progress applies it.
        (
            (End::RateLimited, true, true, 9, None, true),
            Outcome::Advanced,
        ),
        (
            (End::Refused(refused), true, false, 0, None, true),
            Outcome::Refused,
        ),
        (
            (timed_out, false, false, 0, None, true),
            Outcome::Unreachable,
        ),
        (
            (disconnected, false, false, 0, None, true),
            Outcome::Unreachable,
        ),
        (
            (End::SinkFailed, true, false, 0, local, true),
            Outcome::LocalFailure,
        ),
        // A local failure outranks progress.
        (
            (End::SinkFailed, true, false, 9, local, true),
            Outcome::LocalFailure,
        ),
        (
            (End::SinkFailed, true, false, 0, stale, true),
            Outcome::Unanswered,
        ),
        (
            (End::SinkFailed, true, false, 9, stale, true),
            Outcome::Advanced,
        ),
        (
            (End::SinkFailed, true, false, 0, gone, true),
            Outcome::Unanswered,
        ),
        // An event no installed subscription routes yet is local too.
        (
            (End::SinkFailed, true, false, 0, unrouted, true),
            Outcome::LocalFailure,
        ),
        (
            (End::SinkFailed, true, false, 9, unrouted, true),
            Outcome::LocalFailure,
        ),
        (
            (End::StoreFailed, true, false, 0, None, true),
            Outcome::LocalFailure,
        ),
        (
            (End::StoreFailed, true, false, 9, None, true),
            Outcome::LocalFailure,
        ),
    ];
    for ((end, answered, rate_limited, newly, stop, still_owed), expected) in cases {
        assert_eq!(
            classify(end, answered, rate_limited, newly, stop, still_owed),
            expected,
            "{end:?}, answered {answered}, rate limited {rate_limited}, newly {newly}, \
             stop {stop:?}, owed {still_owed}"
        );
    }
}

#[test]
fn recovery_runner_policy_holds_the_starting_values() {
    let policy = RecoveryRunnerPolicy::default();
    assert!(
        RUNNER_QUANTUM > RUNNER_REQUEST_TIMEOUT,
        "a cut before any answer is a preemption, never a slow relay"
    );
    assert_eq!(
        (policy.quantum, policy.request_timeout),
        (RUNNER_QUANTUM, RUNNER_REQUEST_TIMEOUT)
    );
    assert_eq!(
        (
            policy.unit.backoff_base_seconds,
            policy.unit.backoff_cap_seconds,
            policy.unit.break_after_no_progress
        ),
        (30, HOUR, 6)
    );
    assert_eq!(
        (
            policy.unit.cooldown_after_unreachable,
            policy.unit.cooldown_base_seconds,
            policy.unit.cooldown_cap_seconds
        ),
        (3, 60, HOUR)
    );
    assert_eq!(
        (
            policy.unit.max_attempts_per_hour,
            policy.unit.max_event_bytes_per_hour
        ),
        (720, 256 * 1024 * 1024)
    );
    assert_eq!(
        (
            policy.staging.group_events,
            policy.staging.group_bytes,
            policy.staging.account_bytes
        ),
        (2_048, 8 * 1024 * 1024, 64 * 1024 * 1024)
    );
    assert_eq!(policy.admission_per_turn, 4);
    assert_eq!(policy.fences_per_unit, 8);
    let holds = (1..=8)
        .map(|failures| policy.local_failure_backoff_seconds(failures))
        .collect::<Vec<_>>();
    assert_eq!(holds, [1, 2, 4, 8, 16, 32, 60, 60]);
}

fn ids(events: &[Event]) -> Vec<Vec<u8>> {
    events
        .iter()
        .map(|event| event.id.to_bytes().to_vec())
        .collect()
}

/// For a paused clock: a five-minute slice holds five of these events, and a
/// 4 s request fits twice in a 10 s quantum, so each quantum proves ten
/// minutes. Without NIP-77, so it sweeps where the account holds events.
fn slow_relay(url: &'static str, events: Vec<Event>) -> ModelRelay {
    ModelRelay::new(url, caps(10, false))
        .with_events(events)
        .with_latency(Duration::from_secs(4))
}

fn five_minute_slices() -> RecoveryRunnerPolicy {
    let mut policy = test_policy();
    policy.sweep.initial_delta = 5 * 60;
    policy
}

fn blocked(survey: Survey) -> BTreeMap<String, bool> {
    survey
        .candidates
        .into_iter()
        .map(|candidate| (candidate.key.relay, candidate.blocked))
        .collect()
}

// A paused clock, as above.
#[tokio::test(start_paused = true)]
async fn recovery_runner_admits_nothing_newer_ahead_of_a_laggards_older_commit() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    // An event a minute for an hour, which A swept before. B holds a commit
    // half a minute past minute 25 that A never had.
    let events = every([1; 32], floor, t0, 60);
    let commit = event([1; 32], floor + 25 * 60 + 30);
    let mut held_by_b = events.clone();
    held_by_b.push(commit.clone());
    let a = ModelRelay::new(RELAY, caps(500, true)).build();
    let b = slow_relay(OTHER_RELAY, held_by_b).build();
    account.goal(&route, floor);
    account.swept(&route, RELAY, &events, floor, t0 - 1);
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY, OTHER_RELAY])],
        &[&a, &b],
    );
    host.tails.stand(&route, RELAY, t0);
    host.tails.stand(&route, OTHER_RELAY, t0);
    *host.laggard.lock().unwrap() = Some(unit_key(&route, OTHER_RELAY));
    let (mut runner, _handle) = runner(&host, five_minute_slices());

    // B's first quantum proves ten minutes. A's hour waited for it.
    let first = ran(runner.step().await);
    assert_eq!(
        (first.key.relay.as_str(), first.outcome),
        (OTHER_RELAY, Outcome::Advanced)
    );
    assert!(account.admitted().is_empty());
    let reached = account.covered_through(&route, OTHER_RELAY);
    assert!(reached < commit.created_at.as_secs());

    // The next step admits A's events below B's position, and none newer.
    ran(runner.step().await);
    let early = account.admitted();
    assert!(!early.is_empty());
    assert!(early.iter().all(|(at, _)| *at <= reached));

    run_until_idle(&mut runner, 20).await;
    let behind = host.behind.lock().unwrap().clone();
    assert!(
        behind
            .iter()
            .all(|(at, owed)| owed.is_none_or(|owed| *at < owed)),
        "an event went in ahead of history B still owed"
    );
    assert!(behind.iter().any(|(_, owed)| owed.is_some()));
    let mut all = events
        .iter()
        .chain([&commit])
        .map(|event| (event.created_at.as_secs(), event.id.to_bytes().to_vec()))
        .collect::<Vec<_>>();
    all.sort();
    assert_eq!(account.admitted(), all, "oldest first, the commit in place");
    assert_eq!(account.app.staged_recovery_total().unwrap().events, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_fences_live_frames_below_a_non_empty_count_alone() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (fenced, quiet) = (group(1), group(2));
    let floor = t0 - HOUR;
    // One live REQ per relay, from `since`, requested at `requested`. A's sent
    // nothing; B's oldest event came at `oldest`, which proves what follows.
    let since = t0 - 30 * 60;
    let oldest = t0 - 25 * 60;
    let requested = t0 - 20 * 60;
    let a = ModelRelay::new(RELAY, caps(500, true)).build();
    let b = ModelRelay::new(OTHER_RELAY, caps(500, true)).build();
    for route in [&fenced, &quiet] {
        account.goal(route, floor);
    }
    account.live_boundary(&fenced, RELAY, floor, since - 1);
    account.live_boundary(&fenced, OTHER_RELAY, floor, since - 1);
    account.live_boundary(&fenced, OTHER_RELAY, oldest + 1, requested - 1);
    // The quiet group's earlier REQ proved five minutes more, so it owes less.
    account.live_boundary(&quiet, RELAY, floor, since + 5 * 60 - 1);
    let host = TestHost::new(
        &account,
        &clock,
        vec![
            required(&fenced, &[RELAY, OTHER_RELAY]),
            required(&quiet, &[RELAY]),
        ],
        &[&a, &b],
    );
    for (route, relay) in [(&fenced, RELAY), (&fenced, OTHER_RELAY), (&quiet, RELAY)] {
        host.tails.stand(route, relay, requested);
    }
    host.set_counts(vec![
        LiveCount {
            routes: vec![fenced.clone(), quiet.clone()],
            relay: RELAY.to_owned(),
            since,
            oldest_seen: None,
        },
        LiveCount {
            routes: vec![fenced.clone()],
            relay: OTHER_RELAY.to_owned(),
            since,
            oldest_seen: Some(oldest),
        },
    ]);

    // The empty count's range is owed in both groups and holds nothing. B's
    // capture holds the fenced group's frames from `since` on.
    assert_eq!(
        account.debt(&quiet, RELAY, requested - 1),
        vec![range(since + 5 * 60, requested - 1)]
    );
    assert_eq!(
        account.debt(&fenced, RELAY, requested - 1),
        vec![range(since, requested - 1)]
    );
    assert_eq!(host.fences().await, vec![(vec![fenced.clone()], since)]);
    assert_eq!(
        host.survey(test_policy()).await.fenced,
        BTreeSet::from([fenced.clone()])
    );

    // An admission turn keeps B's capture, so a restart, which forgets the
    // counts, still holds the frames.
    let (mut runner, _handle) = runner(&host, test_policy());
    assert!(matches!(
        runner.admit(None).await,
        Ok(Drained { due: None, .. })
    ));
    assert_eq!(
        account.fences(),
        vec![(fenced.clone(), OTHER_RELAY.to_owned(), range(since, oldest))]
    );
    host.set_counts(Vec::new());
    assert_eq!(host.fences().await, vec![(vec![fenced.clone()], since)]);

    // The held group goes first, although the quiet one owes less.
    let first = ran(runner.step().await);
    assert_eq!(
        (&first.key.route, first.key.relay.as_str()),
        (&fenced, RELAY)
    );

    // B cannot be reached: it leaves the frontier and stops fencing, but
    // keeps its capture.
    b.set_reachable(false);
    let second = ran(runner.step().await);
    assert_eq!(
        (&second.key.route, second.key.relay.as_str(), second.outcome),
        (&fenced, OTHER_RELAY, Outcome::Unreachable)
    );
    assert!(host.fences().await.is_empty());
    assert_eq!(account.fences().len(), 1);

    // Back, it sweeps the capture, and the fence is gone for good.
    b.set_reachable(true);
    clock.advance(RUNNER_UNREACHABLE_RETRY_SECS);
    run_until_idle(&mut runner, 10).await;
    assert!(account.debt(&fenced, OTHER_RELAY, requested - 1).is_empty());
    assert!(account.debt(&quiet, RELAY, requested - 1).is_empty());
    assert!(account.fences().is_empty());
    assert!(host.fences().await.is_empty());
}

/// Two generations of one relay's live REQ, each with a non-empty count, and
/// between their captures history the relay owes that no count left
/// unproven. Times are minutes before now.
struct TwoCaptures {
    account: Account,
    route: Route,
    host: Arc<TestHost>,
    first: RecoveryCoverageRange,
    /// The owed history between the captures starts here.
    between: u64,
    second: RecoveryCoverageRange,
}

impl TwoCaptures {
    fn new(clock: &Clock) -> Self {
        let account = account();
        let t0 = clock.now();
        let route = group(1);
        let at = |minutes: u64| t0 - minutes * 60;
        let first = range(at(50), at(45));
        let second = range(at(30), at(25));
        let between = at(40);
        let b = ModelRelay::new(OTHER_RELAY, caps(500, true)).build();
        account.goal(&route, t0 - HOUR);
        account.live_boundary(&route, OTHER_RELAY, t0 - HOUR, first.since_seconds - 1);
        // Each generation's boundary proves from after its oldest event to its
        // request; the second REQ's `since` is past the first's request.
        account.live_boundary(&route, OTHER_RELAY, first.until_seconds + 1, between - 1);
        account.live_boundary(&route, OTHER_RELAY, second.until_seconds + 1, at(20) - 1);
        let host = TestHost::new(
            &account,
            clock,
            vec![required(&route, &[OTHER_RELAY])],
            &[&b],
        );
        host.tails.stand(&route, OTHER_RELAY, at(20));
        Self {
            account,
            route,
            host,
            first,
            between,
            second,
        }
    }

    fn count(&self, capture: RecoveryCoverageRange) -> LiveCount {
        LiveCount {
            routes: vec![self.route.clone()],
            relay: OTHER_RELAY.to_owned(),
            since: capture.since_seconds,
            oldest_seen: Some(capture.until_seconds),
        }
    }

    /// Admit with each generation's count in turn, then restart, which
    /// forgets the counts.
    async fn admit_both_then_restart(&self, runner: &mut RecoveryRunner<TestHost>) {
        for capture in [self.first, self.second] {
            self.host.set_counts(vec![self.count(capture)]);
            assert!(matches!(
                runner.admit(None).await,
                Ok(Drained { due: None, .. })
            ));
        }
        self.host.set_counts(Vec::new());
    }

    fn kept(
        &self,
        ranges: &[RecoveryCoverageRange],
    ) -> Vec<(Route, String, RecoveryCoverageRange)> {
        ranges
            .iter()
            .map(|range| (self.route.clone(), OTHER_RELAY.to_owned(), *range))
            .collect()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_keeps_every_owed_capture_across_a_restart() {
    let clock = Clock::new();
    let case = TwoCaptures::new(&clock);
    let (mut runner, _handle) = runner(&case.host, test_policy());
    case.admit_both_then_restart(&mut runner).await;
    assert_eq!(case.account.fences(), case.kept(&[case.first, case.second]));
    let held = |release_before| vec![(vec![case.route.clone()], release_before)];
    assert_eq!(case.host.fences().await, held(case.first.since_seconds));

    // The older capture is swept; the newer one still holds the frames from
    // its own start, not from the owed history between them.
    let (since, until) = (case.first.since_seconds, case.first.until_seconds);
    case.account
        .swept(&case.route, OTHER_RELAY, &[], since, until);
    assert_eq!(
        case.account
            .debt(&case.route, OTHER_RELAY, case.second.until_seconds)
            .first()
            .map(|owed| owed.since_seconds),
        Some(case.between)
    );
    assert_eq!(case.host.fences().await, held(case.second.since_seconds));
    assert!(matches!(
        runner.admit(None).await,
        Ok(Drained { due: None, .. })
    ));
    assert_eq!(case.account.fences(), case.kept(&[case.second]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_joins_the_newest_captures_past_its_bound() {
    let clock = Clock::new();
    let case = TwoCaptures::new(&clock);
    let policy = RecoveryRunnerPolicy {
        fences_per_unit: 1,
        ..test_policy()
    };
    let (mut runner, _handle) = runner(&case.host, policy);
    case.admit_both_then_restart(&mut runner).await;
    let joined = range(case.first.since_seconds, case.second.until_seconds);
    assert_eq!(case.account.fences(), case.kept(&[joined]));

    // Joined, it fences more, never less: the owed history between the
    // captures holds the frames too once the older capture is swept.
    let (since, until) = (case.first.since_seconds, case.first.until_seconds);
    case.account
        .swept(&case.route, OTHER_RELAY, &[], since, until);
    assert_eq!(
        case.host.fences().await,
        vec![(vec![case.route.clone()], case.between)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_never_fences_an_idle_connected_account_for_its_own_tail() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .checking(&account)
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    // As for the idle account above: the live REQ opened an hour ago, its
    // EOSE proved the day before, and its tail has stood since. The stored
    // events it sent lie inside that tail; another REQ sent nothing.
    let opened = t0 - HOUR;
    account.goal(&route, t0 - DAY);
    account.live_boundary(&route, RELAY, t0 - DAY, opened - 1);
    host.tails.stand(&route, RELAY, opened);
    let count = |oldest_seen| LiveCount {
        routes: vec![route.clone()],
        relay: RELAY.to_owned(),
        since: opened,
        oldest_seen,
    };
    host.set_counts(vec![count(Some(opened + 5 * 60)), count(None)]);
    let (mut runner, _handle) = runner(&host, test_policy());

    for _ in 0..3 {
        assert_eq!(idle(runner.step().await), None);
        assert!(host.fences().await.is_empty());
        assert!(host.survey(test_policy()).await.fenced.is_empty());
        clock.advance(10 * 60);
    }

    assert!(relay.queries().is_empty());
    assert!(
        account.app.recovery_unit(&route, RELAY).unwrap().is_none(),
        "no unit was touched, and none keeps a fence"
    );
}

// A paused clock, as above.
#[tokio::test(start_paused = true)]
async fn recovery_runner_holds_a_full_relay_back_until_the_laggard_advances_or_leaves() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let events = every([1; 32], floor, t0, 60);
    let a = slow_relay(RELAY, events.clone()).build();
    let b = slow_relay(OTHER_RELAY, events).build();
    account.goal(&route, floor);
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY, OTHER_RELAY])],
        &[&a, &b],
    );
    host.tails.stand(&route, RELAY, t0);
    host.tails.stand(&route, OTHER_RELAY, t0);
    // Five staged events fill one relay's share of the group.
    let mut policy = five_minute_slices();
    policy.staging.group_events = 5;
    let (mut runner, _handle) = runner(&host, policy);
    let routes = [route.clone()];
    let only = |relay: &str, held: bool| {
        BTreeMap::from([
            (RELAY.to_owned(), relay == RELAY && held),
            (OTHER_RELAY.to_owned(), relay == OTHER_RELAY && held),
        ])
    };

    // A goes first and stages ten events past B, which owes from the floor.
    let first = ran(runner.step().await);
    assert_eq!(
        (first.key.relay.as_str(), first.outcome),
        (RELAY, Outcome::Advanced)
    );
    assert_eq!(account.staged_from(&routes, RELAY), 10);
    assert_eq!(blocked(host.survey(policy).await), only(RELAY, true));

    // So the runner serves B rather than wait on A. Once B reaches A's
    // position, both hold the frontier and A is eligible again.
    let second = ran(runner.step().await);
    assert_eq!(
        (second.key.relay.as_str(), second.outcome),
        (OTHER_RELAY, Outcome::Advanced)
    );
    assert_eq!(blocked(host.survey(policy).await), only(RELAY, false));

    // The next step admits A's events and runs A ahead again.
    let third = ran(runner.step().await);
    assert_eq!(third.key.relay, RELAY);
    assert_eq!(account.admitted_events(), 10);
    assert_eq!(account.staged_from(&routes, RELAY), 10);
    assert_eq!(blocked(host.survey(policy).await), only(RELAY, true));

    // B cannot be reached: it leaves the frontier, so A holds it, full or
    // not, and runs.
    b.set_reachable(false);
    let fourth = ran(runner.step().await);
    assert_eq!(
        (fourth.key.relay.as_str(), fourth.outcome),
        (OTHER_RELAY, Outcome::Unreachable)
    );
    assert_eq!(blocked(host.survey(policy).await), only(RELAY, false));
    let fifth = ran(runner.step().await);
    assert_eq!(fifth.key.relay, RELAY);
    // What A staged past B went in as late input.
    assert_eq!(account.admitted_events(), 20);
}

/// As above, a laggard leaves the frontier once its last quantum made no
/// progress or was refused, and while its relay cools down; the full relay
/// ahead of it is then eligible.
#[tokio::test(start_paused = true)]
async fn recovery_runner_stops_waiting_on_a_laggard_without_progress_refused_or_cooling_down() {
    for outcome in [Outcome::NoProgress, Outcome::Refused, Outcome::RateLimited] {
        let account = account();
        let clock = Clock::new();
        let t0 = clock.now();
        let route = group(1);
        let floor = t0 - HOUR;
        let events = every([1; 32], floor, t0, 60);
        let a = slow_relay(RELAY, events.clone()).build();
        let b = slow_relay(OTHER_RELAY, events).build();
        account.goal(&route, floor);
        let host = TestHost::new(
            &account,
            &clock,
            vec![required(&route, &[RELAY, OTHER_RELAY])],
            &[&a, &b],
        );
        host.tails.stand(&route, RELAY, t0);
        host.tails.stand(&route, OTHER_RELAY, t0);
        let mut policy = five_minute_slices();
        policy.staging.group_events = 5;
        let (mut runner, _handle) = runner(&host, policy);

        // A goes first, stages past B and waits on it.
        assert_eq!(ran(runner.step().await).key.relay, RELAY);
        assert_eq!(blocked(host.survey(policy).await).get(RELAY), Some(&true));

        account
            .app
            .settle_recovery_unit(&route, OTHER_RELAY, outcome, &policy.unit, clock.now())
            .unwrap();
        assert_eq!(
            blocked(host.survey(policy).await).get(RELAY),
            Some(&false),
            "B still holds the frontier after {outcome:?}"
        );
        if outcome == Outcome::Refused {
            // A loss above A's coverage earns B's park a probe, so B owes
            // from the floor again; broken, it still stays off the frontier.
            let reached = account.covered_through(&route, RELAY);
            account
                .app
                .uncover_recovery_coverage(std::slice::from_ref(&route), reached + 1)
                .unwrap();
            assert!(account.unit(&route, OTHER_RELAY).probe);
            assert_eq!(
                account.debt(&route, OTHER_RELAY, t0 - 1)[0].since_seconds,
                floor
            );
            assert_eq!(
                blocked(host.survey(policy).await).get(RELAY),
                Some(&false),
                "a probing broken unit holds the frontier"
            );
        }
    }
}

/// A route of the MLS group with id `[9; 16]`.
fn shared(route: &Route, relays: &[&str]) -> RunnerRoute {
    RunnerRoute {
        group_id: Some(vec![9; 16]),
        ..required(route, relays)
    }
}

// A paused clock, as above.
#[tokio::test(start_paused = true)]
async fn recovery_runner_shares_one_frontier_across_a_groups_routes() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (current, retained) = (group(1), group(2));
    let floor = t0 - HOUR;
    let half = t0 - 30 * 60;
    // An event every two minutes on each route. A swept the retained route's
    // hour and the first half of the current one's; B, which the retained
    // route alone requires, owes its hour.
    let current_events = every([1; 32], floor, t0, 120);
    let retained_events = every([2; 32], floor, t0, 120);
    let first_half = current_events
        .iter()
        .filter(|event| event.created_at.as_secs() < half)
        .cloned()
        .collect::<Vec<_>>();
    let a = ModelRelay::new(RELAY, caps(500, true))
        .with_events(
            current_events
                .iter()
                .chain(&retained_events)
                .cloned()
                .collect(),
        )
        .build();
    let b = slow_relay(OTHER_RELAY, retained_events.clone()).build();
    for route in [&current, &retained] {
        account.goal(route, floor);
    }
    account.swept(&retained, RELAY, &retained_events, floor, t0 - 1);
    account.swept(&current, RELAY, &first_half, floor, half - 1);
    let host = TestHost::new(
        &account,
        &clock,
        vec![
            shared(&current, &[RELAY]),
            shared(&retained, &[RELAY, OTHER_RELAY]),
        ],
        &[&a, &b],
    );
    for (route, relay) in [
        (&current, RELAY),
        (&retained, RELAY),
        (&retained, OTHER_RELAY),
    ] {
        host.tails.stand(route, relay, t0);
    }
    *host.laggard.lock().unwrap() = Some(unit_key(&retained, OTHER_RELAY));
    // A holds 15 events on the current route and 30 on the retained one:
    // each under the group's share, together over it.
    let mut policy = five_minute_slices();
    policy.staging.group_events = 40;
    assert_eq!(
        account.staged_from(std::slice::from_ref(&current), RELAY),
        15
    );
    assert_eq!(
        account.staged_from(std::slice::from_ref(&retained), RELAY),
        30
    );
    assert_eq!(
        blocked(host.survey(policy).await),
        BTreeMap::from([(RELAY.to_owned(), true), (OTHER_RELAY.to_owned(), false)])
    );

    // B's frontier on the retained route holds back what A staged on the
    // current one too.
    let (mut runner, _handle) = runner(&host, policy);
    let first = ran(runner.step().await);
    assert_eq!(
        (&first.key.route, first.key.relay.as_str()),
        (&retained, OTHER_RELAY)
    );
    assert!(account.admitted().is_empty());

    run_until_idle(&mut runner, 30).await;
    let behind = host.behind.lock().unwrap().clone();
    assert!(
        behind
            .iter()
            .all(|(at, owed)| owed.is_none_or(|owed| *at < owed)),
        "an event went in ahead of history B still owed"
    );
    assert!(behind.iter().any(|(_, owed)| owed.is_some()));
    assert_eq!(account.admitted_events(), 60);
    assert_eq!(account.app.staged_recovery_total().unwrap().events, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_gives_back_what_an_unlisted_route_staged() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (gone, listed) = (group(1), group(2));
    let floor = t0 - HOUR;
    let events = every([1; 32], floor, t0, 10 * 60);
    let a = ModelRelay::new(RELAY, caps(500, true)).build();
    let b = ModelRelay::new(OTHER_RELAY, caps(500, true)).build();
    for route in [&gone, &listed] {
        account.goal(route, floor);
    }
    // A staged an hour on a route the runner no longer lists, and is ahead
    // of B on the one it does.
    account.swept(&gone, RELAY, &events, floor, t0 - 1);
    account.swept(&listed, RELAY, &[], floor, t0 - 30 * 60);
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&listed, &[RELAY, OTHER_RELAY])],
        &[&a, &b],
    );
    for relay in [RELAY, OTHER_RELAY] {
        host.tails.stand(&listed, relay, t0);
    }
    let mut policy = test_policy();
    policy.staging.account_bytes = 1;
    assert_eq!(account.staged_from(std::slice::from_ref(&gone), RELAY), 6);
    assert_eq!(
        blocked(host.survey(policy).await).get(RELAY),
        Some(&true),
        "the unlisted route's rows fill the account"
    );

    // Admission gives them back, owed again on their route, so they hold
    // nothing.
    let (mut runner, _handle) = runner(&host, policy);
    assert!(matches!(
        runner.admit(None).await,
        Ok(Drained { due: None, .. })
    ));
    assert!(account.admitted().is_empty());
    assert_eq!(account.app.staged_recovery_total().unwrap().events, 0);
    assert!(!account.debt(&gone, RELAY, t0 - 1).is_empty());
    assert_eq!(blocked(host.survey(policy).await).get(RELAY), Some(&false));
}

/// A group whose copy froze after a sweep staged its history ingests none of
/// it: admission gives it back, owed again, so it holds no bound either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_gives_back_what_a_suspended_group_staged() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (frozen, other) = (group(1), group(2));
    let floor = t0 - HOUR;
    let events = every([1; 32], floor, t0, 10 * 60);
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    for route in [&frozen, &other] {
        account.goal(route, floor);
    }
    account.swept(&frozen, RELAY, &events, floor, t0 - 1);
    let host = TestHost::new(
        &account,
        &clock,
        vec![
            RunnerRoute {
                unrecoverable: true,
                ..required(&frozen, &[RELAY])
            },
            required(&other, &[RELAY]),
        ],
        &[&relay],
    );
    for route in [&frozen, &other] {
        host.tails.stand(route, RELAY, t0);
    }
    let mut policy = test_policy();
    policy.staging.account_bytes = 1;
    assert_eq!(account.staged_from(std::slice::from_ref(&frozen), RELAY), 6);

    let (mut runner, _handle) = runner(&host, policy);
    assert!(matches!(
        runner.admit(None).await,
        Ok(Drained { due: None, .. })
    ));
    assert!(
        account.admitted().is_empty(),
        "nothing enters the frozen copy"
    );
    assert_eq!(account.app.staged_recovery_total().unwrap().events, 0);
    assert!(!account.debt(&frozen, RELAY, t0 - 1).is_empty());
    assert_eq!(
        blocked(host.survey(policy).await).get(RELAY),
        Some(&false),
        "the other group is not held back by the frozen one's rows"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_holds_a_group_behind_an_event_the_engine_kept_no_trace_of() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (stuck, other) = (group(1), group(2));
    let floor = t0 - HOUR;
    // Both groups' hours were swept and staged already.
    let stuck_events = every([1; 32], floor, t0, 10 * 60);
    let other_events = every([2; 32], floor, t0, 10 * 60);
    for (route, events) in [(&stuck, &stuck_events), (&other, &other_events)] {
        account.goal(route, floor);
        account.swept(route, RELAY, events, floor, t0 - 1);
    }
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&stuck, &[RELAY]), required(&other, &[RELAY])],
        &[&relay],
    );
    host.tails.stand(&stuck, RELAY, t0);
    host.tails.stand(&other, RELAY, t0);
    // For now the engine refuses the stuck group's third event.
    host.no_trace
        .lock()
        .unwrap()
        .insert(stuck_events[2].id.to_bytes().to_vec());
    let (mut runner, _handle) = runner(&host, test_policy());
    let admitted = || {
        account
            .admitted()
            .into_iter()
            .map(|(_, event_id)| event_id)
            .collect::<Vec<_>>()
    };

    // The other group goes in whole, the stuck one up to the refused event.
    // That event stays staged, and its group waits behind it.
    let due = idle(runner.step().await).expect("the stuck group is retried");
    let s = ids(&stuck_events);
    let o = ids(&other_events);
    let mut first = vec![s[0].clone(), o[0].clone(), s[1].clone(), o[1].clone()];
    first.extend_from_slice(&o[2..]);
    assert_eq!(admitted(), first);
    assert_eq!(account.staged_from(std::slice::from_ref(&stuck), RELAY), 4);

    // Once the engine takes it, the rest of its group follows in order.
    host.no_trace.lock().unwrap().clear();
    clock.advance_to(due);
    assert_eq!(idle(runner.step().await), None);
    first.extend_from_slice(&s[2..]);
    assert_eq!(admitted(), first);
    assert_eq!(account.app.staged_recovery_total().unwrap().events, 0);
}

// A paused clock, as above.
#[tokio::test(start_paused = true)]
async fn recovery_runner_fetches_nothing_for_a_group_held_behind_an_untraced_event() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let events = every([1; 32], floor, t0, 60);
    let relay = slow_relay(RELAY, events.clone()).build();
    account.goal(&route, floor);
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    host.tails.stand(&route, RELAY, t0);
    // For now the engine refuses the group's second event.
    host.no_trace
        .lock()
        .unwrap()
        .insert(events[1].id.to_bytes().to_vec());
    let (mut runner, _handle) = runner(&host, five_minute_slices());
    let routes = [route.clone()];

    let first = ran(runner.step().await);
    assert_eq!(first.outcome, Outcome::Advanced);
    let staged = account.staged_from(&routes, RELAY);
    let reached = account.covered_through(&route, RELAY);

    // The next step admits the first event and holds the group behind the
    // second. Nothing more is fetched for it while it cannot drain, though
    // its relay holds the frontier and owes the rest of the hour: not at the
    // hold's end, when admission retries first, and not when admission's own
    // turns outlast the hold, which then still stands for the step's survey.
    let queries = relay.queries().len();
    let due = idle(runner.step().await).expect("the held group is retried");
    clock.advance_to(due - 1);
    assert_eq!(idle(runner.step().await), Some(due));
    host.debt_turn_seconds.store(5, Ordering::SeqCst);
    for _ in 0..3 {
        let due = idle(runner.step().await).expect("the held group is retried");
        clock.advance_to(due);
    }
    host.debt_turn_seconds.store(0, Ordering::SeqCst);
    assert_eq!(relay.queries().len(), queries);
    assert_eq!(account.admitted_events(), 1);
    assert_eq!(account.staged_from(&routes, RELAY), staged - 1);
    assert_eq!(account.covered_through(&route, RELAY), reached);

    // Once the engine takes it, the group drains and the sweep goes on.
    host.no_trace.lock().unwrap().clear();
    let resumed = ran(runner.step().await);
    assert_eq!(
        (resumed.key.relay.as_str(), resumed.outcome),
        (RELAY, Outcome::Advanced)
    );
    assert_eq!(account.admitted_events(), staged);
    assert!(account.covered_through(&route, RELAY) > reached);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_fetches_nothing_while_admission_waits_after_a_local_failure() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (failing, other) = (group(1), group(2));
    let floor = t0 - HOUR;
    let mid = t0 - HOUR / 2;
    // The failing group's hour was swept and staged already. The other group
    // owes its newer half hour, and its older one is due a re-check.
    let failing_events = every([1; 32], floor, t0, 10 * 60);
    account.goal(&failing, floor);
    account.swept(&failing, RELAY, &failing_events, floor, t0 - 1);
    account.goal(&other, floor);
    account.live_boundary(&other, RELAY, floor, mid);
    account
        .app
        .record_recovery_relay_caps(
            RELAY,
            Some(RecoveryRelayCaps {
                max_limit: Some(500),
                negentropy: true,
            }),
            t0,
        )
        .unwrap();
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .with_events(every([2; 32], floor, t0, 10 * 60))
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&failing, &[RELAY]), required(&other, &[RELAY])],
        &[&relay],
    );
    host.tails.stand(&failing, RELAY, t0);
    host.tails.stand(&other, RELAY, t0);
    // For now the failing group's first event fails to go in, after longer
    // than the first wait it arms.
    host.failing_ingests
        .lock()
        .unwrap()
        .insert(failing_events[0].id.to_bytes().to_vec());
    host.ingest_seconds.store(5, Ordering::SeqCst);
    let (mut runner, _handle) = runner(&host, test_policy());

    // Admission waits after the failure, and nothing is fetched for any group
    // meanwhile: not the other group's debt, nor its re-check.
    let due = idle(runner.step().await).expect("admission is retried");
    assert!(due > clock.now(), "the wait was born expired");
    assert!(account.admitted().is_empty());
    assert!(relay.queries().is_empty());
    assert!(relay.comparisons().is_empty());
    assert_eq!(
        account.debt(&other, RELAY, t0 - 1),
        [range(mid + 1, t0 - 1)]
    );

    // Once the wait ends and the ingest goes through, the other group's debt
    // runs.
    host.failing_ingests.lock().unwrap().clear();
    clock.advance_to(due);
    let resumed = ran(runner.step().await);
    assert_eq!((&resumed.key.route, resumed.recheck), (&other, false));
    assert_eq!(account.admitted_events(), failing_events.len() as u64);
}

/// An Unrecoverable group's route is suspended: no sweep, re-check or
/// comparison runs for it, nothing is charged, broken or parked, and its debt
/// stays owed. Once the copy is repaired the route is served again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_suspends_an_unrecoverable_groups_route() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .with_events(every([1; 32], floor, t0, 60))
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![RunnerRoute {
            unrecoverable: true,
            ..required(&route, &[RELAY])
        }],
        &[&relay],
    );
    // No re-check has run, so one would be due at once.
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());
    let owed = account.debt(&route, RELAY, t0 - 1);
    assert!(!owed.is_empty());

    assert_eq!(
        idle(runner.step().await),
        None,
        "a suspended route waits for its repair, not for time"
    );
    clock.advance(DAY);
    assert_eq!(idle(runner.step().await), None);
    assert_eq!(
        runner.run_pass(Duration::from_secs(30)).await,
        PassReport::default()
    );
    // A unit picked before its group froze does not begin.
    let key = unit_key(&route, RELAY);
    let policy = test_policy();
    assert!(
        host.debt_turn(move |turn| {
            select::begin(turn, &key, false, Some(caps(500, true)), true, &policy).unwrap()
        })
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(relay.requests(), 0);
    assert!(relay.comparisons().is_empty());
    assert!(
        account.app.recovery_unit(&route, RELAY).unwrap().is_none(),
        "never charged, broken or parked"
    );
    assert_eq!(account.debt(&route, RELAY, t0 - 1), owed);

    host.routes.lock().unwrap()[0].unrecoverable = false;
    assert_eq!(ran(runner.step().await).outcome, Outcome::Advanced);
}

/// A retained prior route owes history only through its goal's end: the sweep
/// stops there, and once that is covered the route owes nothing more, though
/// no live tail stands after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_owes_a_retained_route_nothing_past_its_goal() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let ceiling = t0 - HOUR / 2;
    let relay = ModelRelay::new(RELAY, caps(500, false))
        .with_events(every([1; 32], floor, t0, 60))
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![RunnerRoute {
            goal_until: Some(ceiling),
            ..required(&route, &[RELAY])
        }],
        &[&relay],
    );
    account.goal(&route, floor);
    account.rechecked(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());

    let outcomes = run_until_idle(&mut runner, 10).await;
    assert!(!outcomes.is_empty());
    assert!(outcomes.iter().all(|outcome| *outcome == Outcome::Advanced));
    assert_eq!(account.covered_through(&route, RELAY), ceiling);
    assert!(relay.queries().iter().all(|query| query.until <= ceiling));
    assert_eq!(account.debt(&route, RELAY, ceiling), []);

    let requests = relay.requests();
    clock.advance(60);
    assert!(matches!(runner.step().await, Step::Idle { .. }));
    assert_eq!(relay.requests(), requests);
}

/// An explicit repair's verdict leaves a suspended group's route out, as its
/// notices do: the runner serves none of its debt, so the repair still ends
/// with the other routes' windows covered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_repair_leaves_a_suspended_groups_route_out_of_its_verdict() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (served, frozen) = (group(1), group(2));
    let floor = t0 - HOUR;
    let relay = ModelRelay::new(RELAY, caps(500, false))
        .with_events(every([1; 32], floor, t0, 60))
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![
            required(&served, &[RELAY]),
            RunnerRoute {
                unrecoverable: true,
                ..required(&frozen, &[RELAY])
            },
        ],
        &[&relay],
    );
    for route in [&served, &frozen] {
        account.goal(route, floor);
        host.tails.stand(route, RELAY, t0);
    }
    let (mut runner, _handle) = runner(&host, test_policy());

    let end = runner
        .repair(&super::PassBound::within(Duration::from_secs(60)))
        .await;
    assert!(matches!(end, super::RepairEnd::Covered));
    assert!(!account.debt(&frozen, RELAY, t0 - 1).is_empty());
}

/// An explicit repair judges a retained route's window only through its
/// goal's end, where the runner stops serving it, so the repair ends with
/// it covered though no live tail stands after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_repair_judges_a_retained_route_through_its_goal() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let ceiling = t0 - HOUR / 2;
    let relay = ModelRelay::new(RELAY, caps(500, false))
        .with_events(every([1; 32], floor, t0, 60))
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![RunnerRoute {
            goal_until: Some(ceiling),
            ..required(&route, &[RELAY])
        }],
        &[&relay],
    );
    account.goal(&route, floor);
    let (mut runner, _handle) = runner(&host, test_policy());

    let end = runner
        .repair(&super::PassBound::within(Duration::from_secs(60)))
        .await;
    assert!(matches!(end, super::RepairEnd::Covered));
    assert_eq!(account.covered_through(&route, RELAY), ceiling);
}
