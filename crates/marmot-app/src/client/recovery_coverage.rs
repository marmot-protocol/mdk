//! The coverage ledger recorder, in shadow mode (mdk#2660 phase 2).
//!
//! Fills storage's coverage ledger from facts the stack already produces:
//! live REQ boundaries the adapter admitted, comparison certificates at
//! settlement, epoch gaps and startup history goals. Storage itself un-covers
//! the ledger inside each loss import's and receipt release's transaction,
//! and a certificate loses whatever was un-covered after its grant was
//! selected. Then the recorder
//! compares the ledger with every pending obligation and reports agreement as
//! aggregate counts. Nothing here schedules, retries or fences recovery, and
//! every write is best effort: a failure is logged and the recovery step it
//! follows goes on. No route, relay, group or obligation identity is logged.
use std::collections::{BTreeMap, HashMap, HashSet};

use storage_sqlite::{
    RecoveryCause, RecoveryCoverageMark, RecoveryCoverageProof, RecoveryCoverageSlice,
    RecoveryLossCause, RecoveryLossImport, RecoveryLossReach, RecoveryPredicate,
    RecoveryRevisionFence, RecoveryScopeOutcome, SqliteAppStorage, StoredRecoveryScope,
    TRANSPORT_RECONCILIATION_RETENTION_SECS, TransportReconciliationRoute,
};
use transport_nostr::MarmotRelayPlaneAccountAdapter;
use transport_nostr_adapter::{ReplayAdmissionStatus, ReplayLiveCount, ReplaySourceGeneration};

use super::AppClient;
use super::recovery::AttemptGrant;
use super::sync::RouteComparison;
use crate::AppError;
use crate::notifications::unix_now_seconds;

const TARGET: &str = "marmot_app::recovery_coverage";

/// How the ledger and the obligations compare, in aggregate. Each compared
/// scope is counted once; known-event, maintenance-boundary and unresolved
/// scopes are not comparable, nor is a loss obligation's scope on a route its
/// loss never reached inside the scope's window, nor a scope whose proof
/// hangs on where acknowledged loss reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CoverageShadowReport {
    pub(crate) scopes_compared: u64,
    /// The scope is still owed, and the ledger agrees.
    pub(crate) agree_owed: u64,
    /// The obligation holds the scope's proof, and so does the ledger.
    pub(crate) agree_covered: u64,
    /// The obligation still owes a scope the ledger has proved complete.
    pub(crate) ledger_ahead: u64,
    /// The obligation holds a scope's proof the ledger does not have.
    pub(crate) ledger_behind: u64,
    pub(crate) not_comparable: u64,
    /// Current routes with ledger debt and no pending scope on that route.
    pub(crate) unowed_debt_routes: u64,
}

impl CoverageShadowReport {
    pub(crate) fn disagreements(&self) -> u64 {
        self.ledger_ahead + self.ledger_behind + self.unowed_debt_routes
    }
}

/// One live REQ's generation on one relay: the request, the relay as the
/// ledger spells it, and the adapter's generation. Account-private.
type GenerationKey = (String, String, ReplaySourceGeneration);

/// Where each healthy, open live REQ's provisional coverage starts, by route
/// and relay (as the ledger spells it), as of the recorder's last look at the
/// adapter. While such a REQ stays open its relay sends it everything it
/// stores from that second on, so those seconds are not owed while it lasts.
/// The ledger never holds them: nothing proves when an open REQ stopped
/// delivering, so once its generation ends or breaks they are owed until a
/// later EOSE or a fetch proves them. A tail never covers a second released
/// for replay, which its REQ will not deliver again.
///
/// Debt that drives work (a unit's debt, its derived cursor, the capture
/// fence) is the ledger's debt through [`LiveTails::owed_until`], read from
/// [`AppClient::live_tails`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LiveTails(BTreeMap<(TransportReconciliationRoute, String), u64>);

impl LiveTails {
    /// The last second the ledger must prove on `relay` for `route` at
    /// `now`: the second before a live tail starts there, else `now`.
    pub(crate) fn owed_until(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
        now: u64,
    ) -> u64 {
        self.0
            .get(&(route.clone(), relay.to_owned()))
            .map_or(now, |since| since.saturating_sub(1).min(now))
    }

    fn start(&mut self, route: &TransportReconciliationRoute, relay: &str, since: u64) {
        self.0
            .entry((route.clone(), relay.to_owned()))
            .and_modify(|held| *held = (*held).min(since))
            .or_insert(since);
    }
}

/// What the live-boundary recorder keeps between observations.
///
/// A live REQ's count proves to the ledger only what its relay had stored
/// when it ran the query: from [`live_boundary_since`] through the second
/// before the count's `requested_at`, a stamp taken before the REQ went out.
/// Past that the REQ vouches only provisionally, while it lasts
/// ([`LiveTails`]).
///
/// A generation that loss may have reached proves nothing again. The
/// recorder reads the un-cover generation before each observation of the
/// adapter, so a generation that one observation did not see began after that
/// observation's mark, and every loss imported since that mark (all of it
/// account-wide until loss carries routes) is checked against every
/// generation seen now. The first mark is read when the client opens; the
/// shared adapter may still report generations an earlier session of the
/// account saw begin, and loss imported before that mark could have reached
/// them, so none of those is trusted.
pub(crate) struct LiveCoverage {
    mark: Option<RecoveryCoverageMark>,
    /// Generations loss may have reached, while the adapter still reports
    /// them.
    broken: HashSet<GenerationKey>,
    /// Generations whose count is settled: written, or unable to prove
    /// anything. A count is written once.
    settled: HashSet<GenerationKey>,
    tails: LiveTails,
}

impl LiveCoverage {
    /// `mark` is the un-cover generation read as the client opens, before it
    /// observes `adapter`; `None` makes the first observation trust no
    /// generation.
    pub(crate) async fn open(
        mark: Option<RecoveryCoverageMark>,
        adapter: &MarmotRelayPlaneAccountAdapter,
    ) -> Self {
        let (_, _, inherited) = observe_live_counts(&adapter.replay_admission().await);
        Self {
            mark,
            broken: inherited.into_keys().collect(),
            settled: HashSet::new(),
            tails: LiveTails::default(),
        }
    }

    #[cfg(test)]
    fn opened_at(mark: Option<RecoveryCoverageMark>) -> Self {
        Self {
            mark,
            broken: HashSet::new(),
            settled: HashSet::new(),
            tails: LiveTails::default(),
        }
    }

    /// Break every generation in `present` whose routes `lost` touches; with
    /// no route list (account-wide loss, or a log that no longer reaches the
    /// mark), every one.
    fn break_reached(
        &mut self,
        present: &HashMap<GenerationKey, Vec<TransportReconciliationRoute>>,
        lost: Option<&[TransportReconciliationRoute]>,
    ) {
        for (key, routes) in present {
            if lost.is_none_or(|lost| lost.iter().any(|route| routes.contains(route))) {
                self.broken.insert(key.clone());
            }
        }
    }

    /// The counts `facts` settle now, each with the range it proves on every
    /// route its filter carries, if any: from [`live_boundary_since`]
    /// through the second before its `requested_at`. Generations loss may
    /// have reached prove nothing.
    fn durable<'a>(
        &self,
        facts: &'a [LiveCountFact],
    ) -> Vec<(&'a LiveCountFact, Option<(u64, u64)>)> {
        facts
            .iter()
            .filter(|fact| {
                fact.placed && !self.settled.contains(&fact.key) && !self.broken.contains(&fact.key)
            })
            .map(|fact| {
                let range = live_boundary_since(fact.since, &fact.count)
                    .map(|since| (since, fact.count.requested_at.saturating_sub(1)))
                    .filter(|(since, until)| since <= until);
                (fact, range)
            })
            .collect()
    }

    /// Where each healthy, open generation's tail starts on each route its
    /// filter carries: at its count's `live_from` (its `requested_at`, or its
    /// EOSE for a REQ the relay pool sent again), unless the relay sent no
    /// stored event older than that, so it may have cut what it stored
    /// after; then just past the oldest it sent. `released` moves a start on
    /// a route past the seconds released for replay there, or drops it.
    fn tails(
        &self,
        facts: &[LiveCountFact],
        mut released: impl FnMut(&TransportReconciliationRoute, u64) -> Option<u64>,
    ) -> LiveTails {
        let mut tails = LiveTails::default();
        for fact in facts
            .iter()
            .filter(|fact| !fact.ended && fact.placed && !self.broken.contains(&fact.key))
        {
            let count = &fact.count;
            let since = match count.oldest {
                Some(oldest) if count.events > 0 && oldest >= count.live_from => {
                    oldest.saturating_add(1)
                }
                _ => count.live_from,
            };
            for route in &fact.routes {
                if let Some(since) = released(route, since) {
                    tails.start(route, &fact.key.1, since);
                }
            }
        }
        tails
    }
}

/// One generation's count, copied out of the adapter's guard.
struct LiveCountFact {
    key: GenerationKey,
    routes: Vec<TransportReconciliationRoute>,
    since: u64,
    count: ReplayLiveCount,
    /// The relay closed the REQ or its connection dropped, or the relay
    /// client no longer reports the connection its serial started on.
    ended: bool,
    /// The request's input reached durable placement.
    placed: bool,
}

/// The first second a live REQ's count proves on one relay: the second after
/// the oldest event the client saw before EOSE, and never before the REQ's
/// `since`. A relay that cut its reply sent the newest events it stored, so
/// everything newer than the oldest one it sent reached the client; the
/// count says nothing about how many it sent, because the SDK drops some
/// frames (an expired event, one its database deleted) without a word, so
/// even a short reply may have been cut. An empty count proves nothing.
fn live_boundary_since(since: u64, count: &ReplayLiveCount) -> Option<u64> {
    count
        .oldest
        .filter(|_| count.events > 0)
        .map(|oldest| oldest.saturating_add(1).max(since))
}

/// The adapter's live-REQ generations, copied out of its guard: whether its
/// input is placed (the cursor seal's own guard), the counts that can prove,
/// and every generation it reports with the routes its filter carries.
fn observe_live_counts(
    observation: &ReplayAdmissionStatus<'_>,
) -> (
    bool,
    Vec<LiveCountFact>,
    HashMap<GenerationKey, Vec<TransportReconciliationRoute>>,
) {
    let input_placed = !observation.pending && !observation.spill_pending;
    let mut facts = Vec::new();
    let mut present = HashMap::new();
    for source in observation.sources() {
        let routes = source
            .group_routes()
            .map(|id| TransportReconciliationRoute::Group(*id))
            .collect::<Vec<_>>();
        let routes = if routes.is_empty() {
            vec![TransportReconciliationRoute::Inbox]
        } else {
            routes
        };
        let placed = source.placed();
        for endpoint in source.endpoints() {
            let relay = transport_nostr::canonical_relay(endpoint.endpoint().as_str());
            let mut fact = |generation, count, ended| {
                let key = (source.id().to_owned(), relay.clone(), generation);
                present.insert(key.clone(), routes.clone());
                if let Some(count) = count {
                    facts.push(LiveCountFact {
                        key,
                        routes: routes.clone(),
                        since: source.since(),
                        count,
                        ended,
                        placed,
                    });
                }
            };
            // A count whose REQ the relay client no longer reports streaming
            // has ended, whatever the adapter has heard: it is written, with
            // no tail.
            fact(
                endpoint.generation(),
                endpoint.live_count().filter(|_| endpoint.admitted()),
                !endpoint.streaming(),
            );
            if let Some(ended) = endpoint.ended_count() {
                fact(ended.generation, Some(ended.count), true);
            }
        }
    }
    (input_placed, facts, present)
}

/// A route the account currently subscribes, with the relays that certify it.
struct CurrentRoute {
    route: TransportReconciliationRoute,
    group_id: Option<Vec<u8>>,
    required: Vec<String>,
}

/// The ledger keys relays by one spelling: the adapter and the scope plans
/// spell the same relay differently.
fn relays(endpoints: &[String]) -> Vec<String> {
    let mut relays = endpoints
        .iter()
        .map(|endpoint| transport_nostr::canonical_relay(endpoint))
        .collect::<Vec<_>>();
    relays.sort();
    relays.dedup();
    relays
}

fn retention_floor(now: u64) -> u64 {
    now.saturating_sub(TRANSPORT_RECONCILIATION_RETENTION_SECS)
}

fn log_failure(method: &'static str, error: &AppError) {
    tracing::warn!(target: TARGET, method = method, error_kind = error.privacy_safe_kind(),
        "coverage ledger write skipped");
}

/// Where each cause's unresolved loss may have lost events, as of one
/// report. Account-private.
struct LossReach {
    queue: RecoveryLossReach,
    notification: RecoveryLossReach,
}

impl LossReach {
    fn read(app: &SqliteAppStorage, label: &str) -> Result<Self, AppError> {
        Ok(Self {
            queue: app.recovery_loss_reach(label, RecoveryLossCause::Queue)?,
            notification: app
                .recovery_loss_reach(label, RecoveryLossCause::NotificationConsumer)?,
        })
    }

    /// The loss a loss demand owes, or `None` for any other demand.
    fn owed_by(&self, cause: RecoveryCause) -> Option<&RecoveryLossReach> {
        match cause {
            RecoveryCause::QueueLoss => Some(&self.queue),
            RecoveryCause::NotificationLoss => Some(&self.notification),
            _ => None,
        }
    }
}

/// Whether the obligation counts the scope proved, as completion would once
/// loss invalidates by route: its own predicate over checkpoints captured at
/// the account's current route and inventory revisions and the obligation's
/// current revision. A checkpoint from before newer loss proves nothing only
/// when `newer_loss_reaches`: loss imported after the checkpoint's loss
/// revision may have lost an event on the scope's route inside its window.
/// Retiring that loss later proves nothing, so it still voids.
fn obligation_holds(
    scope: &StoredRecoveryScope,
    predicate: RecoveryPredicate,
    fence: &RecoveryRevisionFence,
    obligation_revision: u64,
    newer_loss_reaches: bool,
) -> bool {
    let current = (scope.loss_revision == fence.loss_revision || !newer_loss_reaches)
        && scope.route_revision == fence.route_revision
        && scope.inventory_revision == fence.inventory_revision
        && scope.obligation_revision == obligation_revision;
    let plan = &scope.plan;
    current
        && match predicate {
            RecoveryPredicate::ReplayAdmission => {
                scope.replay_admitted && !plan.admitted_endpoints.is_empty()
            }
            _ => {
                !plan.required_endpoints.is_empty()
                    && plan.required_endpoints.iter().all(|required| {
                        plan.admitted_endpoints.contains(required)
                            && scope.checkpoints.iter().any(|checkpoint| {
                                &checkpoint.endpoint == required
                                    && checkpoint.outcome == RecoveryScopeOutcome::Covered
                                    && checkpoint.exhaustive
                                    && checkpoint.admission_complete
                            })
                    })
            }
        }
}

fn scope_route(scope: &StoredRecoveryScope) -> Option<TransportReconciliationRoute> {
    match (scope.plan.route_kind, scope.plan.transport_group_id) {
        (0, _) => Some(TransportReconciliationRoute::Inbox),
        (1, Some(id)) => Some(TransportReconciliationRoute::Group(id)),
        _ => None,
    }
}

impl AppClient {
    fn current_coverage_routes(&self) -> Vec<CurrentRoute> {
        let routing = self.routing.snapshot();
        let operated = &self.app.config.deployment.recovery_operated_relays;
        let required = |endpoints: &[cgka_traits::TransportEndpoint]| {
            let admitted = self.adapter.recovery_admitted_endpoints(endpoints);
            relays(&transport_nostr::recovery_required_endpoints(
                &admitted, operated,
            ))
        };
        let mut routes = vec![CurrentRoute {
            route: TransportReconciliationRoute::Inbox,
            group_id: None,
            required: required(&routing.local_inbox_endpoints),
        }];
        let mut seen = HashSet::new();
        for entry in &routing.group_routes {
            let Ok(id) = <[u8; 32]>::try_from(entry.transport_group_id.as_slice()) else {
                continue;
            };
            if seen.insert(id) {
                routes.push(CurrentRoute {
                    route: TransportReconciliationRoute::Group(id),
                    group_id: Some(entry.group_id.as_slice().to_vec()),
                    required: required(&entry.endpoints),
                });
            }
        }
        routes
    }

    fn coverage_storage(&self) -> Result<storage_sqlite::SqliteAccountStorage, AppError> {
        self.app.account_storage(&self.state.label)
    }

    /// Storage un-covered the loss in the import's own transaction: only the
    /// routes a routed generation named, each from its own bound, with their
    /// goals; and every ledger route from the floor of a generation that named
    /// none. For that, a current route the ledger does not hold yet still owes
    /// from the floor, so its goal widens here; if this write
    /// is lost, the pending loss scopes widen it at the next comparison. Every
    /// account-wide import is new evidence, even with nothing counted or no
    /// demand changed: a notification lag charges no delivery count.
    pub(crate) fn record_coverage_loss(&self, imports: &[RecoveryLossImport]) {
        // Routed loss widened its own routes' goals in the import.
        let floors = imports
            .iter()
            .filter(|import| import.every_route)
            .map(|import| import.goal_floor.unwrap_or(0))
            .collect::<Vec<_>>();
        let Some(floor) = floors.into_iter().min() else {
            return;
        };
        let routes = self
            .current_coverage_routes()
            .into_iter()
            .map(|current| current.route)
            .collect::<Vec<_>>();
        if let Err(error) = self.coverage_storage().and_then(|storage| {
            Ok(storage
                .app_storage()
                .widen_recovery_coverage_goals(&routes, floor)?)
        }) {
            log_failure("record_coverage_loss", &error);
        }
    }

    /// Where a current route's standing goal starts: the retention floor,
    /// or for a group route whose copy has a Welcome time, that time less the
    /// clock-skew allowance when it is later. The Welcome time is only a hint
    /// (`Group::local_copy_welcome_created_at`): it starts goals and never
    /// retires, un-covers or drops debt, so loss, released receipts and
    /// explicit repair keep their own floors, and a goal already lower stays.
    /// A Welcome time after `now` (the joining clock ran fast) is ignored, even
    /// one inside the allowance, or the goal would start minutes ago and never
    /// owe the window.
    fn standing_floor(&self, current: &CurrentRoute, now: u64) -> u64 {
        let welcome = current.group_id.as_ref().and_then(|group| {
            self.runtime
                .group_record(&cgka_traits::GroupId::new(group.clone()))
                .ok()?
                .local_copy_welcome_created_at
        });
        welcome
            .filter(|welcome| welcome.0 <= now)
            .map_or(0, |welcome| crate::history_floor(welcome.0).0)
            .max(retention_floor(now))
    }

    /// Widen each current route's goal to its standing floor.
    fn widen_standing_goals(
        &self,
        app: &SqliteAppStorage,
        routes: &[&CurrentRoute],
        now: u64,
    ) -> Result<(), AppError> {
        let mut by_floor = std::collections::BTreeMap::<u64, Vec<_>>::new();
        for current in routes {
            by_floor
                .entry(self.standing_floor(current, now))
                .or_default()
                .push(current.route.clone());
        }
        for (floor, routes) in by_floor {
            app.widen_recovery_coverage_goals(&routes, floor)?;
        }
        Ok(())
    }

    /// Startup incremental history wants every current route from its
    /// standing floor, and explicit repair every route's whole retained
    /// window. Nothing below the window is owed.
    pub(crate) fn record_coverage_request(&self, cause: RecoveryCause) {
        let now = unix_now_seconds();
        let current = self.current_coverage_routes();
        let result = self.coverage_storage().and_then(|storage| {
            let app = storage.app_storage();
            match cause {
                RecoveryCause::IncrementalHistory => {
                    self.widen_standing_goals(&app, &current.iter().collect::<Vec<_>>(), now)
                }
                RecoveryCause::ExplicitHistory => {
                    let routes = current
                        .into_iter()
                        .map(|current| current.route)
                        .collect::<Vec<_>>();
                    Ok(app.widen_recovery_coverage_goals(&routes, retention_floor(now))?)
                }
                _ => Ok(()),
            }
        });
        if let Err(error) = result {
            log_failure("record_coverage_request", &error);
        }
    }

    /// Record what live REQs prove, as live boundaries on each relay that
    /// admitted its REQ's whole original window and counted its stored events
    /// before EOSE: from [`live_boundary_since`] through the second before the
    /// REQ went out, once per generation. Then find each healthy generation's
    /// provisional tail
    /// ([`LiveTails`]). Healthy means the cursor seal's guards: input placed,
    /// no loss or spill hand-off pending. Loss may have dropped what a
    /// generation delivered, so a generation it may have reached proves
    /// nothing again (see [`LiveCoverage`]). Storage keeps released seconds
    /// out of every live boundary.
    pub(crate) async fn record_native_coverage(&self, app: &SqliteAppStorage) {
        self.record_native_coverage_at(app, unix_now_seconds())
            .await;
    }

    pub(crate) async fn record_native_coverage_at(&self, app: &SqliteAppStorage, now: u64) {
        let mut live = self.live_coverage.lock().await;
        live.tails = LiveTails::default();
        // Before the adapter: whatever this observation sees for the first
        // time began after this mark.
        let mark = match app.recovery_coverage_mark() {
            Ok(mark) => mark,
            Err(error) => return log_failure("record_native_coverage", &error.into()),
        };
        let lost = match live.mark {
            Some(previous) => match app.recovery_coverage_lost_since(previous) {
                Ok(lost) => lost,
                Err(error) => return log_failure("record_native_coverage", &error.into()),
            },
            None => None,
        };
        let (input_placed, facts, present) = {
            let observation = self.adapter.replay_admission().await;
            observe_live_counts(&observation)
        };
        live.broken.retain(|key| present.contains_key(key));
        live.settled.retain(|key| present.contains_key(key));
        live.break_reached(&present, lost.as_deref());
        live.mark = Some(mark);
        if !input_placed || self.delivery_loss_blocks_cursor() {
            return;
        }
        let durable = live.durable(&facts);
        let slices = durable
            .iter()
            .filter_map(|(fact, range)| range.map(|range| (fact, range)))
            .flat_map(|(fact, (since, until))| {
                fact.routes.iter().map(move |route| RecoveryCoverageSlice {
                    route,
                    relay: &fact.key.1,
                    since_seconds: since,
                    until_seconds: until,
                    proof: RecoveryCoverageProof::LiveBoundary,
                })
            })
            .collect::<Vec<_>>();
        match app.record_recovery_coverage_since(&slices, now, mark) {
            Ok(true) => {
                let settled = durable
                    .iter()
                    .map(|(fact, _)| fact.key.clone())
                    .collect::<Vec<_>>();
                live.settled.extend(settled);
            }
            Ok(false) => {
                return tracing::debug!(target: TARGET, method = "record_native_coverage",
                    slices = slices.len(), "un-cover log no longer reaches the observation's mark");
            }
            Err(error) => return log_failure("record_native_coverage", &error.into()),
        }
        // Loss imported while the adapter was read may have reached a
        // generation this observation saw: the write left its seconds out,
        // and it gets no tail either.
        match app.recovery_coverage_lost_since(mark) {
            Ok(lost) => live.break_reached(&present, lost.as_deref()),
            Err(error) => return log_failure("record_native_coverage", &error.into()),
        }
        // The adapter may also have ended a generation while the ledger was
        // written (a `CLOSED` or reconnect it processed meanwhile): a tail
        // stands only on a generation it still reports streaming, with the
        // count this observation saw.
        let (input_placed, streaming, _) = {
            let observation = self.adapter.replay_admission().await;
            observe_live_counts(&observation)
        };
        if !input_placed || self.delivery_loss_blocks_cursor() {
            return;
        }
        let facts = facts
            .into_iter()
            .filter(|fact| {
                streaming
                    .iter()
                    .any(|now| now.key == fact.key && now.count == fact.count && !now.ended)
            })
            .collect::<Vec<_>>();
        live.tails = live.tails(&facts, |route, since| {
            match app.recovery_coverage_newest_released(route, since) {
                Ok(newest) => Some(newest.map_or(since, |second| second.saturating_add(1))),
                Err(error) => {
                    log_failure("record_native_coverage", &error.into());
                    None
                }
            }
        });
    }

    /// The live tails now: observes the adapter as
    /// [`Self::record_native_coverage_at`] does, then returns what it found.
    pub(crate) async fn live_tails(&self, app: &SqliteAppStorage, now: u64) -> LiveTails {
        self.record_native_coverage_at(app, now).await;
        self.live_coverage.lock().await.tails.clone()
    }

    /// A certified comparison covers its frozen window on each relay that
    /// certifies the route, less whatever was un-covered after the grant was
    /// selected: a loss or released receipt since then may lie inside the
    /// window, and its debt must stay.
    pub(super) fn record_comparison_coverage(
        &self,
        app: &SqliteAppStorage,
        grant: &AttemptGrant,
        certified: &[&TransportReconciliationRoute],
        now: u64,
    ) {
        let required = grant
            .inventory
            .iter()
            .map(|window| relays(&window.required))
            .collect::<Vec<_>>();
        let mut slices = Vec::new();
        for route in certified {
            for (window, required) in grant
                .inventory
                .iter()
                .zip(&required)
                .filter(|(window, _)| &window.route == *route && window.since <= window.until)
            {
                for relay in required {
                    slices.push(RecoveryCoverageSlice {
                        route: &window.route,
                        relay,
                        since_seconds: window.since,
                        until_seconds: window.until,
                        proof: RecoveryCoverageProof::Comparison,
                    });
                }
            }
        }
        let Some(mark) = grant.coverage_mark else {
            tracing::debug!(target: TARGET, method = "record_comparison_coverage",
                routes = certified.len(), "pass has no coverage mark; certificates not recorded");
            return;
        };
        match app.record_recovery_coverage_since(&slices, now, mark) {
            Ok(true) => {}
            Ok(false) => tracing::debug!(target: TARGET, method = "record_comparison_coverage",
                routes = certified.len(), "un-cover log no longer reaches the pass's start"),
            Err(error) => log_failure("record_comparison_coverage", &error.into()),
        }
    }

    /// The settlement seam: record what the pass proved, keep goals for
    /// pending epoch gaps, prune the retention window, then compare.
    pub(crate) async fn observe_recovery_coverage(
        &self,
        app: &SqliteAppStorage,
        grant: &AttemptGrant,
        compared: &[RouteComparison],
    ) {
        let now = unix_now_seconds();
        let certified = compared
            .iter()
            .filter(|comparison| comparison.certified)
            .map(|comparison| &comparison.route)
            .collect::<Vec<_>>();
        self.record_comparison_coverage(app, grant, &certified, now);
        match self.coverage_shadow_report(app).await {
            Ok(report) if report.disagreements() > 0 => {
                tracing::info!(target: TARGET, method = "observe_recovery_coverage",
                    scopes_compared = report.scopes_compared, agree_owed = report.agree_owed,
                    agree_covered = report.agree_covered, ledger_ahead = report.ledger_ahead,
                    ledger_behind = report.ledger_behind, not_comparable = report.not_comparable,
                    unowed_debt_routes = report.unowed_debt_routes,
                    "coverage ledger disagrees with recovery obligations");
            }
            Ok(report) => {
                tracing::debug!(target: TARGET, method = "observe_recovery_coverage",
                    scopes_compared = report.scopes_compared, agree_owed = report.agree_owed,
                    agree_covered = report.agree_covered, not_comparable = report.not_comparable,
                    "coverage ledger agrees with recovery obligations");
            }
            Err(error) => log_failure("observe_recovery_coverage", &error),
        }
    }

    /// Bring the ledger up to date with the live boundaries, the goals of
    /// pending epoch gaps and loss, and the retention window, then compare it
    /// with every pending obligation. Writes only to the ledger.
    pub(crate) async fn coverage_shadow_report(
        &self,
        app: &SqliteAppStorage,
    ) -> Result<CoverageShadowReport, AppError> {
        let now = unix_now_seconds();
        self.record_native_coverage_at(app, now).await;
        let floor = retention_floor(now);
        let current = self.current_coverage_routes();
        let demands = app.pending_recovery_demands()?;
        // An epoch gap needs its group's routes from their standing floors.
        let gap_routes = current
            .iter()
            .filter(|route| {
                route.group_id.as_ref().is_some_and(|group| {
                    demands.iter().any(|demand| {
                        demand.cause == RecoveryCause::EpochGap
                            && demand.group_id.as_ref() == Some(group)
                    })
                })
            })
            .collect::<Vec<_>>();
        self.widen_standing_goals(app, &gap_routes, now)?;
        // Loss is imported on this worker, so every loss read below was
        // imported at or before the fence's loss revision, or not yet.
        let fence = app.recovery_revision_fence()?;
        let reach = LossReach::read(app, &self.state.label)?;
        // Pending loss owes each scope's route from where it reached that
        // route: this restores a goal the import's best-effort widening lost.
        // A goal back below the floor parks nothing the prune already settled.
        let mut demand_scopes = Vec::with_capacity(demands.len());
        for demand in &demands {
            let scopes = app.recovery_scope_snapshots(demand.ticket.id)?;
            if let Some(owed) = reach.owed_by(demand.cause) {
                for route in scopes.iter().filter_map(scope_route) {
                    if let Some(floor) = owed.floor(&route) {
                        app.widen_recovery_coverage_goals(std::slice::from_ref(&route), floor)?;
                    }
                }
            }
            demand_scopes.push(scopes);
        }
        // What a current route still owes below the floor is parked, not
        // dropped.
        let certifying = current
            .iter()
            .map(|current| (current.route.clone(), current.required.clone()))
            .collect::<Vec<_>>();
        app.prune_recovery_coverage(floor, &certifying)?;
        // Tails as of now, not as of the writes above.
        let tails = self.live_tails(app, now).await;

        // What each stale loss revision has not seen, read once per revision.
        let mut newer_loss = BTreeMap::new();
        let mut report = CoverageShadowReport::default();
        let mut owed_routes = HashSet::new();
        let mut inbox_owed = false;
        for (demand, scopes) in demands.iter().zip(demand_scopes) {
            if scopes.is_empty() {
                // Not frozen yet: the demand owes its group's routes, or every
                // route, but has no window to compare.
                report.not_comparable += 1;
                for current in &current {
                    if demand.group_id.is_none() || current.group_id == demand.group_id {
                        match &current.route {
                            TransportReconciliationRoute::Inbox => inbox_owed = true,
                            TransportReconciliationRoute::Group(id) => {
                                owed_routes.insert(*id);
                            }
                        }
                    }
                }
            }
            for scope in scopes {
                let route = scope_route(&scope);
                match &route {
                    Some(TransportReconciliationRoute::Inbox) => inbox_owed = true,
                    Some(TransportReconciliationRoute::Group(id)) => {
                        owed_routes.insert(*id);
                    }
                    None => {}
                }
                let comparable = matches!(
                    demand.predicate,
                    RecoveryPredicate::AllEndpoints | RecoveryPredicate::ReplayAdmission
                ) && scope.plan.known_event_id.is_none()
                    && !scope.plan.required_endpoints.is_empty();
                let Some(route) = route.filter(|_| comparable) else {
                    report.not_comparable += 1;
                    continue;
                };
                // A loss obligation owes every route, but owes the ledger
                // only those its loss reached inside the scope's window.
                if reach
                    .owed_by(demand.cause)
                    .is_some_and(|owed| !owed.reaches(&route, scope.plan.until_seconds))
                {
                    report.not_comparable += 1;
                    continue;
                }
                // Whether loss newer than the scope's checkpoints reached it;
                // unknown once an acknowledgment deleted that loss's evidence.
                let newer_loss_reaches = if scope.loss_revision == fence.loss_revision {
                    Some(false)
                } else {
                    let newer = match newer_loss.entry(scope.loss_revision) {
                        std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                        std::collections::btree_map::Entry::Vacant(entry) => entry.insert(
                            app.recovery_loss_reach_after(&self.state.label, scope.loss_revision)?,
                        ),
                    };
                    newer
                        .as_ref()
                        .map(|newer| newer.reaches(&route, scope.plan.until_seconds))
                };
                let holds = obligation_holds(
                    &scope,
                    demand.predicate,
                    &fence,
                    demand.ticket.revision,
                    newer_loss_reaches.unwrap_or(false),
                );
                if holds && newer_loss_reaches.is_none() {
                    report.not_comparable += 1;
                    continue;
                }
                // The ledger keeps nothing below the retained window: an
                // older or unknown floor owes everything still retained.
                let since = scope.plan.since_seconds.unwrap_or(floor).max(floor);
                report.scopes_compared += 1;
                let mut ledger = true;
                for relay in relays(&scope.plan.required_endpoints) {
                    // A live tail vouches for the rest while it lasts, as
                    // replay admission does for the obligation.
                    let until = scope
                        .plan
                        .until_seconds
                        .min(tails.owed_until(&route, &relay, now));
                    if !app.recovery_coverage_covers(
                        &route,
                        std::slice::from_ref(&relay),
                        since,
                        until,
                    )? {
                        ledger = false;
                        break;
                    }
                }
                match (holds, ledger) {
                    (false, false) => report.agree_owed += 1,
                    (true, true) => report.agree_covered += 1,
                    (false, true) => report.ledger_ahead += 1,
                    (true, false) => report.ledger_behind += 1,
                }
            }
        }
        for route in &current {
            let owed = match &route.route {
                TransportReconciliationRoute::Inbox => inbox_owed,
                TransportReconciliationRoute::Group(id) => owed_routes.contains(id),
            };
            if owed {
                continue;
            }
            for relay in &route.required {
                let until = tails.owed_until(&route.route, relay, now);
                if !app
                    .recovery_coverage_debt(&route.route, std::slice::from_ref(relay), until)?
                    .is_empty()
                {
                    report.unowed_debt_routes += 1;
                    break;
                }
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
#[path = "recovery_coverage/scenario_tests.rs"]
pub(in crate::client) mod scenario_tests;

#[cfg(test)]
#[path = "recovery_coverage/live_boundary_tests.rs"]
mod live_boundary_tests;
