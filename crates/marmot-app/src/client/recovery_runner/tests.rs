//! The runner over real account storage, against a model relay and a fake
//! live-tail source. The host runs worker turns inline and reads the tails
//! once at the start of each debt turn, as the account worker will.

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
    RecoveryUnit, RecoveryUnitBreak, RecoveryUnitOutcome, RecoveryUnitState, SqlCipherKey,
    SqliteAccountStorage, SqliteAppStorage, TransportReconciliationRoute,
};
use tokio::sync::Notify;
use tokio::time::Instant;
use transport_nostr_adapter::sweep::{
    ClosedReason, RelayCaps, SecondReply, SliceQuery, SliceReply, SweepEnd, SweepPolicy,
    SweepRelay, SweepRoute, UnreachableKind,
};

use super::policy::{RUNNER_BACKOFF_BASE_SECS, RUNNER_QUANTUM, RUNNER_REQUEST_TIMEOUT};
use super::quantum::{SinkStop, classify};
use super::tails::OwedThroughNow;
use super::*;
use crate::runtime::account_worker::recovery_credits::{
    self, RecoveryCreditPool, available_credits, hold_all_credits_for_test,
};

const RELAY: &str = "wss://a.example";
const OTHER_RELAY: &str = "wss://b.example";
const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;
const GROUP_MESSAGE_KIND: u16 = 445;

type Route = TransportReconciliationRoute;
type Outcome = RecoveryUnitOutcome;

fn group(byte: u8) -> Route {
    Route::Group([byte; 32])
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
        required: relays.iter().map(|relay| (*relay).to_owned()).collect(),
        best_effort: Vec::new(),
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
}

fn account() -> Account {
    let dir = tempfile::tempdir().unwrap();
    // A raw key skips SQLCipher's passphrase derivation, which dominates a
    // test's run time in debug builds.
    let key = SqlCipherKey::raw([7; 32]);
    let storage =
        SqliteAccountStorage::open_encrypted(dir.path().join("account.db"), &key).unwrap();
    let app = storage.app_storage();
    Account {
        _dir: dir,
        _storage: storage,
        app,
    }
}

impl Account {
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

    fn debt(&self, route: &Route, relay: &str, until: u64) -> Vec<RecoveryCoverageRange> {
        self.app.recovery_unit_debt(route, relay, until).unwrap()
    }

    fn unit(&self, route: &Route, relay: &str) -> RecoveryUnit {
        self.app
            .recovery_unit(route, relay)
            .unwrap()
            .expect("the runner touched the unit")
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
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let next = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&next.to_be_bytes());
    Event::new(
        EventId::from_byte_array(id),
        *PUBKEY,
        Timestamp::from_secs(created_at),
        Kind::from(GROUP_MESSAGE_KIND),
        [Tag::parse(["h", hex::encode(group).as_str()]).unwrap()],
        "",
        Signature::from_byte_array([1; 64]),
    )
}

/// One event every `step` seconds in `[since, until)`.
fn every(group: [u8; 32], since: u64, until: u64, step: u64) -> Vec<Event> {
    (since..until)
        .step_by(usize::try_from(step).unwrap())
        .map(|at| event(group, at))
        .collect()
}

fn group_tag(event: &Event) -> Option<Vec<u8>> {
    event.tags.iter().find_map(|tag| {
        let parts = tag.as_slice();
        (parts.len() >= 2 && parts[0] == "h")
            .then(|| hex::decode(&parts[1]).ok())
            .flatten()
    })
}

fn delivery(event: &Event) -> TransportDelivery {
    let at = TransportTime(event.created_at.as_secs());
    TransportDelivery {
        account_id: MemberId::new(vec![0xAA; 32]),
        group_id_hint: None,
        message: TransportMessage {
            id: MessageId::new(event.id.to_bytes().to_vec()),
            payload: event.id.to_bytes().to_vec(),
            timestamp: at,
            causal_deps: Vec::new(),
            source: TransportSource("nostr".to_owned()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_tag(event).expect("a group event"),
            },
        },
        received_at: at,
        source: TransportDeliverySource {
            transport: TransportSource("nostr".to_owned()),
            plane: TransportDeliveryPlane::Group,
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
            latency: Duration::ZERO,
            requests: AtomicUsize::new(0),
            queries: Mutex::new(Vec::new()),
            seconds: Mutex::new(Vec::new()),
            gate: Gate::new(),
            in_flight: Arc::default(),
            ledger: None,
            refetches: Mutex::new(Vec::new()),
        }
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

    fn matching(&self, route: SweepRoute, since: u64, until: u64) -> Vec<Event> {
        let SweepRoute::Group { nostr_group_id } = route;
        let mut matching = self
            .events
            .iter()
            .filter(|event| {
                let at = event.created_at.as_secs();
                at >= since
                    && at <= until
                    && group_tag(event).as_deref() == Some(nostr_group_id.as_slice())
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
        let SweepRoute::Group { nostr_group_id } = route;
        let proved = app
            .recovery_coverage_ranges(&Route::Group(nostr_group_id), self.url)
            .unwrap();
        if proved.iter().any(|proved| {
            proved.range.since_seconds <= since && since <= proved.range.until_seconds
        }) {
            self.refetches.lock().unwrap().push(since);
        }
    }

    /// Wait out the gate and the latency. What the relay says instead of an
    /// answer, if anything.
    async fn arrive(&self) -> Option<ClosedOrUnreachable> {
        let index = self.requests.fetch_add(1, Ordering::SeqCst);
        self.gate.pass(index).await;
        if !self.latency.is_zero() {
            tokio::time::sleep(self.latency).await;
        }
        if !self.reachable.load(Ordering::SeqCst) {
            Some(ClosedOrUnreachable::Unreachable)
        } else if self.limited.contains(&index) {
            Some(ClosedOrUnreachable::RateLimited)
        } else {
            None
        }
    }

    async fn fetch_slice(&self, query: SliceQuery) -> SliceReply {
        let _flight = self.in_flight.enter();
        self.check_uncovered(query.route, query.since);
        self.queries.lock().unwrap().push(query);
        match self.arrive().await {
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

    async fn fetch_second(&self, route: SweepRoute, second: u64) -> SecondReply {
        let _flight = self.in_flight.enter();
        self.seconds.lock().unwrap().push(second);
        match self.arrive().await {
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
}

enum ClosedOrUnreachable {
    RateLimited,
    Unreachable,
}

fn rate_limited() -> ClosedReason {
    ClosedReason::from_message("rate-limited: slow down")
}

/// The sweep's view of a model relay, with the caps the runner planned.
struct Swept {
    relay: Arc<ModelRelay>,
    caps: RelayCaps,
}

#[async_trait]
impl SweepRelay for Swept {
    fn caps(&self) -> RelayCaps {
        self.caps
    }

    async fn fetch_slice(&self, query: SliceQuery) -> SliceReply {
        self.relay.fetch_slice(query).await
    }

    async fn fetch_second(&self, route: SweepRoute, second: u64, _cap: Option<u32>) -> SecondReply {
        self.relay.fetch_second(route, second).await
    }
}

struct TestHost {
    app: SqliteAppStorage,
    clock: Clock,
    routes: Mutex<Vec<RunnerRoute>>,
    tails: TailSource,
    relays: BTreeMap<&'static str, Arc<ModelRelay>>,
    debt_turns: AtomicUsize,
    /// How long a NIP-11 read takes.
    caps_latency: Mutex<Duration>,
    /// Worker turns still to fail, against `closed`.
    failing_turns: AtomicUsize,
    closed: OnceLock<Account>,
}

impl TestHost {
    fn new(
        account: &Account,
        clock: &Clock,
        routes: Vec<RunnerRoute>,
        relays: &[&Arc<ModelRelay>],
    ) -> Arc<Self> {
        Arc::new(Self {
            app: account.app.clone(),
            clock: clock.clone(),
            routes: Mutex::new(routes),
            tails: TailSource::default(),
            relays: relays
                .iter()
                .map(|relay| (relay.url, Arc::clone(relay)))
                .collect(),
            debt_turns: AtomicUsize::new(0),
            caps_latency: Mutex::new(Duration::ZERO),
            failing_turns: AtomicUsize::new(0),
            closed: OnceLock::new(),
        })
    }

    fn debt_turns(&self) -> usize {
        self.debt_turns.load(Ordering::SeqCst)
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
        Some(turn(&WorkerTurn {
            app,
            now: self.clock.now(),
        }))
    }

    async fn debt_turn<T, F>(&self, turn: F) -> Option<T>
    where
        F: FnOnce(&DebtTurn<'_>) -> T + Send + 'static,
        T: Send + 'static,
    {
        let tails = self.tails.read();
        let routes = self.routes.lock().unwrap().clone();
        let answer = turn(&DebtTurn {
            app: &self.app,
            routes: &routes,
            now: self.clock.now(),
            tails: &tails,
        });
        self.debt_turns.fetch_add(1, Ordering::SeqCst);
        Some(answer)
    }

    async fn relay_caps(&self, relay: &str) -> Option<RelayCaps> {
        let latency = *self.caps_latency.lock().unwrap();
        if !latency.is_zero() {
            tokio::time::sleep(latency).await;
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
        Some(Box::new(Swept { relay, caps }))
    }

    async fn deliveries(&self, _relay: &str, event: Event) -> Vec<TransportDelivery> {
        vec![delivery(&event)]
    }

    fn now_seconds(&self) -> u64 {
        self.clock.now()
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

    assert_eq!(host.debt_turns(), 3, "each step read the tails again");
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
    assert_eq!(idle(runner.step().await), None);

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
    assert_eq!(idle(runner.step().await), None);
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

    wait_until("the survey", WAIT, || host.debt_turns() == 1).await;
    // While it waits for a credit, the relay reconnects and its new tail
    // stands over the whole debt.
    host.tails.stand(&route, RELAY, opened);
    drop(held);

    assert!(stepping.await.unwrap(), "begin found nothing owed");
    assert_eq!(host.debt_turns(), 2);
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
    assert_eq!(account.app.staged_recovery_total().unwrap().events, total);
    assert_eq!(available_credits(&credits), 2);
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
    assert_eq!(account.app.staged_recovery_total().unwrap().events, total);
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
    assert_eq!(idle(runner.step().await), None, "one attempt per debt");
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
    assert_eq!(idle(runner.step().await), None);
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
    assert_eq!(idle(runner.step().await), None, "one attempt per debt");

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
    assert_eq!(idle(runner.step().await), None);

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
        paused_until: None,
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

#[test]
fn recovery_runner_classifies_every_sweep_end() {
    use SweepEnd as End;
    let refused = ClosedReason(None);
    let timed_out = End::Unreachable(UnreachableKind::TimedOut);
    let disconnected = End::Unreachable(UnreachableKind::Disconnected);
    let local = Some(SinkStop::Local);
    let stale = Some(SinkStop::StaleMark);
    let gone = Some(SinkStop::WorkerGone);
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
fn recovery_runner_stub_tails_owe_through_now() {
    let tails = OwedThroughNow;
    assert_eq!(tails.owed_until(&group(1), RELAY, 1_000), 1_000);
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
    let holds = (1..=8)
        .map(|failures| policy.local_failure_backoff_seconds(failures))
        .collect::<Vec<_>>();
    assert_eq!(holds, [1, 2, 4, 8, 16, 32, 60, 60]);
}
