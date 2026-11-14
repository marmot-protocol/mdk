//! Coverage recording and the runner-owned debt handoff (mdk#2660).
//!
//! Fills storage's coverage ledger from facts the stack already produces:
//! live REQ boundaries the adapter admitted, epoch gaps and standing goals.
//! Storage itself un-covers the ledger inside each loss import's and receipt
//! release's transaction. Legacy observation writes are best effort: a failure is
//! logged and the recovery step it follows goes on. Runner-owned conversion,
//! loss import and newly armed epoch gaps are authoritative and fallible.
//! The runner schedules their debt; this module also wires its bounded live
//! fences. No route, relay, group or obligation identity is logged.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use cgka_traits::storage::{GroupStorage, StorageError, StorageProvider, StorageResult};
use storage_sqlite::{
    RecoveryCause, RecoveryCopy, RecoveryCoverageMark, RecoveryCoverageProof,
    RecoveryCoverageSlice, RecoveryRejoin, SqliteAppStorage,
    TRANSPORT_RECONCILIATION_RETENTION_SECS, TransportReconciliationRoute,
};
use transport_nostr::MarmotRelayPlaneAccountAdapter;
use transport_nostr_adapter::{
    ReplayAdmissionStatus, ReplayFence, ReplayFencePlan, ReplayFenceTicket, ReplayLiveCount,
    ReplaySourceGeneration,
};

use super::recovery_runner::{self, LiveCount, LiveFence};
use crate::AppError;
use crate::client::AppClient;
use crate::notifications::unix_now_seconds;

const TARGET: &str = "marmot_app::recovery_coverage";

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
    /// The routes on which each generation's count is settled: written, or
    /// unable to prove anything. A count is written once on each route.
    settled: HashMap<GenerationKey, BTreeSet<TransportReconciliationRoute>>,
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
        let (_, _, inherited) = observe_live_counts(&adapter.replay_admission().await, true);
        Self {
            mark,
            broken: inherited.into_keys().collect(),
            settled: HashMap::new(),
            tails: LiveTails::default(),
        }
    }

    #[cfg(test)]
    fn opened_at(mark: Option<RecoveryCoverageMark>) -> Self {
        Self {
            mark,
            broken: HashSet::new(),
            settled: HashMap::new(),
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

    /// The counts `facts` settle now, each with the range it proves, if any,
    /// and the routes its filter carries that it settles on: from
    /// [`live_boundary_since`] through the second before its `requested_at`.
    /// Generations loss may have reached prove nothing, and a route whose
    /// group's live frames a fence holds waits until they are released.
    fn durable<'a>(&self, facts: &'a [LiveCountFact]) -> Vec<Settling<'a>> {
        facts
            .iter()
            .filter(|fact| fact.placed && !self.broken.contains(&fact.key))
            .filter_map(|fact| {
                let routes = fact
                    .routes
                    .iter()
                    .filter(|route| {
                        !fact.held.contains(route)
                            && !self
                                .settled
                                .get(&fact.key)
                                .is_some_and(|settled| settled.contains(route))
                    })
                    .collect::<Vec<_>>();
                if routes.is_empty() {
                    return None;
                }
                let range = live_boundary_since(fact.since, &fact.count)
                    .map(|since| (since, fact.count.requested_at.saturating_sub(1)))
                    .filter(|(since, until)| since <= until);
                Some((fact, range, routes))
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

/// A count [`LiveCoverage::durable`] settles now: the range it proves, if
/// any, and the routes it settles on.
type Settling<'a> = (
    &'a LiveCountFact,
    Option<(u64, u64)>,
    Vec<&'a TransportReconciliationRoute>,
);

/// One generation's count, copied out of the adapter's guard.
struct LiveCountFact {
    key: GenerationKey,
    routes: Vec<TransportReconciliationRoute>,
    since: u64,
    count: ReplayLiveCount,
    /// The relay closed the REQ or its connection dropped, or the relay
    /// client no longer reports the connection its serial started on.
    ended: bool,
    /// The request's input reached durable placement, apart from live
    /// frames a fence holds.
    placed: bool,
    /// The routes whose group's live frames a fence holds: nothing on them
    /// is placed above the hold yet.
    held: Vec<TransportReconciliationRoute>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl LiveCountFact {
    /// The count as the runner's fence reads it. Only a non-empty count
    /// leaves capture debt below its oldest event. A full admitted reply
    /// leaves that debt too; admission is not proof that the original query
    /// was complete.
    fn live_count(&self) -> LiveCount {
        LiveCount {
            routes: self.routes.clone(),
            relay: self.key.1.clone(),
            since: self.since,
            oldest_seen: self.count.oldest.filter(|_| self.count.events > 0),
        }
    }
}

/// What the runner's fence reads from one look at the adapter (mdk#2660
/// phase 4). Not `Debug`: it carries routes and relays.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct LiveCountRead {
    /// The look's place in the adapter's fence order: a plan built from these
    /// counts carries it, so it answers only the counts this look saw.
    pub(crate) ticket: ReplayFenceTicket,
    /// Each admitted count, current or ended.
    pub(crate) counts: Vec<LiveCount>,
    /// The routes whose group's live frames the adapter holds now, waiting
    /// for the runner's answer or behind its fence: served first.
    pub(crate) held: BTreeSet<TransportReconciliationRoute>,
}

/// The adapter's plan for `fences`, as of `ticket`. A fence holds only group
/// frames, so inbox routes are left out.
#[cfg_attr(not(test), allow(dead_code))]
fn fence_plan(ticket: ReplayFenceTicket, fences: &[LiveFence]) -> ReplayFencePlan {
    ReplayFencePlan {
        ticket,
        fences: fences
            .iter()
            .flat_map(|fence| {
                fence.routes.iter().filter_map(|route| match route {
                    TransportReconciliationRoute::Group(route) => Some(ReplayFence {
                        route: *route,
                        release_before: fence.release_before,
                    }),
                    TransportReconciliationRoute::Inbox => None,
                })
            })
            .collect(),
    }
}

/// Runner-owned debt and live-fence handoffs.
#[cfg_attr(not(test), allow(dead_code))]
impl AppClient {
    /// A newly armed gap contradicts earlier coverage of this group's retained
    /// history. Commit its legacy diagnostic obligation and runnable ledger
    /// debt together, once per obligation revision, before waking the owner.
    pub(crate) fn arm_epoch_gap_recovery(
        &self,
        intents: &[storage_sqlite::StoredEpochBackfillIntent],
    ) -> Result<(), AppError> {
        if intents.is_empty() {
            return self
                .app
                .arm_epoch_backfill_intents(&self.state.label, intents);
        }
        let storage = self.coverage_storage()?;
        let current = self.current_coverage_routes();
        let now = unix_now_seconds();
        let floor = retention_floor(now);
        let changed = storage.with_transaction(|storage| -> Result<bool, AppError> {
            let app = storage.app_storage();
            let before = app.pending_recovery_demands()?;
            app.arm_epoch_backfill_intents(intents)?;
            let mut changed = false;
            for demand in app.pending_recovery_demands()?.iter().filter(|demand| {
                demand.cause == RecoveryCause::EpochGap
                    && !before.iter().any(|prior| prior.ticket == demand.ticket)
            }) {
                let routes = current
                    .iter()
                    .filter(|route| route.group_id == demand.group_id)
                    .collect::<Vec<_>>();
                if routes.is_empty() {
                    return Err(
                        StorageError::Backend("epoch gap routes are not installed".into()).into(),
                    );
                }
                let floors = routes
                    .into_iter()
                    .map(|route| {
                        // The Welcome time is only a goal hint, never evidence for
                        // invalidation. Preserve the actual durable goal, bounded
                        // by retention; a route with no goal owes the whole window.
                        let since = app
                            .recovery_coverage_goal(&route.route)?
                            .unwrap_or(floor)
                            .max(floor);
                        Ok((route.route.clone(), since))
                    })
                    .collect::<Result<Vec<_>, AppError>>()?;
                app.begin_recovery_epoch_gap_retry(demand.ticket, &floors, now)?;
                changed = true;
            }
            Ok(changed)
        })?;
        if changed {
            self.routing.wake_recovery_runner();
        }
        Ok(())
    }

    /// The adapter's admitted live counts for the runner's fence, read now
    /// with the fence ticket and the held routes from the same look. The
    /// runner's host reads this with each debt turn's tails (from 5g).
    pub(crate) async fn recovery_runner_live_counts(&self) -> LiveCountRead {
        let observation = self.adapter.replay_admission().await;
        let (_, facts, _) = observe_live_counts(&observation, self.app.vouches_for_relay_replies());
        LiveCountRead {
            ticket: observation.fence_ticket(),
            counts: facts.iter().map(LiveCountFact::live_count).collect(),
            held: observation
                .fenced_routes()
                .map(|route| TransportReconciliationRoute::Group(*route))
                .collect(),
        }
    }

    /// Have the adapter hold each counted group's live frames until the
    /// runner answers with [`Self::fence_live_frames`]. Backlog holds follow
    /// durable admission progress, independently of request deadlines. No
    /// call undoes it.
    pub(crate) async fn enable_live_fences(&self) {
        self.adapter.enable_replay_fencing().await;
    }

    /// Release each fenced group's held live frames below its fence, and the
    /// rest of every group the counts read at `ticket` held that `fences`
    /// leaves out.
    pub(crate) async fn fence_live_frames(&self, ticket: ReplayFenceTicket, fences: &[LiveFence]) {
        self.adapter.fence_replay(&fence_plan(ticket, fences)).await;
    }
}

/// The first second a live REQ's count proves on one relay: the second after
/// the oldest event the client saw before EOSE, and never before the REQ's
/// `since`. A relay that cut its reply sent the newest events it stored, so
/// everything newer than the oldest one it sent reached the client; the
/// count says nothing about how many it sent, because the SDK drops some
/// frames (an expired event, one its database deleted) without a word, so
/// even a short reply may have been cut. An empty count proves nothing,
/// unless the wire showed the relay sent no EVENT frame at all
/// ([`ReplayLiveCount::sent_nothing`]): a relay that sent nothing cut
/// nothing, so the count proves its whole window from `since`.
fn live_boundary_since(since: u64, count: &ReplayLiveCount) -> Option<u64> {
    if count.events == 0 {
        return count.sent_nothing.then_some(since);
    }
    count
        .oldest
        .map(|oldest| oldest.saturating_add(1).max(since))
}

/// The adapter's live-REQ generations, copied out of its guard: whether its
/// input is placed (the cursor seal's own guard), the counts that can prove,
/// and every generation it reports with the routes its filter carries.
fn observe_live_counts(
    observation: &ReplayAdmissionStatus<'_>,
    vouched: bool,
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
        let placed = source.placed_apart_from_fences();
        let held = source
            .fenced_routes()
            .map(|id| TransportReconciliationRoute::Group(*id))
            .collect::<Vec<_>>();
        for endpoint in source.endpoints() {
            let relay = transport_nostr::canonical_relay(endpoint.endpoint().as_str());
            let mut fact = |generation, count: Option<ReplayLiveCount>, ended| {
                let key = (source.id().to_owned(), relay.clone(), generation);
                present.insert(key.clone(), routes.clone());
                if let Some(count) = count {
                    facts.push(LiveCountFact {
                        key,
                        routes: routes.clone(),
                        since: source.since(),
                        count: ReplayLiveCount {
                            sent_nothing: count.sent_nothing && vouched,
                            ..count
                        },
                        ended,
                        placed,
                        held: held.clone(),
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

/// A route the account currently subscribes, with the relays that certify it
/// and its other admitted relays.
struct CurrentRoute {
    route: TransportReconciliationRoute,
    group_id: Option<Vec<u8>>,
    required: Vec<String>,
    best_effort: Vec<String>,
    /// A retained prior route's goal end ([`crate::retained_route_goal_until`]).
    goal_until: Option<u64>,
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

/// How far the retention floor moves before the recovery runner's debt turns
/// prune the ledger again: history that leaves the window ages out within
/// about this long, and no turn but the first in this span pays for a prune.
const RUNNER_RETENTION_PRUNE_STEP_SECS: u64 = 60 * 60;

impl AppClient {
    /// Age the ledger out of the retention window, as grant settlement's
    /// shadow report did before the runner owned debt (mdk#2660 5g): what a
    /// current route still owes below the floor joins its parked remainder,
    /// coverage, released seconds and capture debt below it go, and goals
    /// rise to it. A capture the relays never answered then fences nothing
    /// older than the window. The process's first debt turn prunes, then one
    /// each time the floor has moved [`RUNNER_RETENTION_PRUNE_STEP_SECS`].
    ///
    /// The floor is the one as of the runner's previous debt turn, or of the
    /// open before its first ([`AppClient::runner_prune_clock`]); a turn
    /// whose prune failed does not count. A goal seeded since then at its own
    /// retention floor (by the open, a replay or an epoch gap) keeps the
    /// seconds that have slid out of the window since: no relay was asked for
    /// them yet, so they are not unproven history, and the debt turn sweeps
    /// them with the rest of the goal instead of this prune parking them
    /// (mdk#3040).
    pub(crate) fn prune_runner_retention(
        &mut self,
        app: &SqliteAppStorage,
        now: u64,
    ) -> cgka_traits::storage::StorageResult<()> {
        let floor = retention_floor(self.history_recovery.state.runner_prune_clock.min(now));
        if self
            .history_recovery
            .state
            .runner_pruned_floor
            .is_some_and(|pruned| floor < pruned.saturating_add(RUNNER_RETENTION_PRUNE_STEP_SECS))
        {
            self.history_recovery.state.runner_prune_clock = now;
            return Ok(());
        }
        let current = self.current_coverage_routes();
        let certifying = current
            .iter()
            .map(|current| (current.route.clone(), current.required.clone()))
            .collect::<Vec<_>>();
        // Audit-only reads: a failed one loses the remainder rows, never the
        // prune.
        let before = self
            .audit_v5_enabled()
            .then(|| app.recovery_coverage_remainders().ok())
            .flatten();
        app.prune_recovery_coverage(floor, &certifying)?;
        self.history_recovery.state.runner_pruned_floor = Some(floor);
        self.history_recovery.state.runner_prune_clock = now;
        if let Some(before) = before
            && let Ok(after) = app.recovery_coverage_remainders()
        {
            recovery_runner::audit::remainders_changed(
                &|group: Option<&[u8]>, kind| self.record_runner_audit(group, kind),
                |route| {
                    current
                        .iter()
                        .find(|current| current.route == *route)
                        .and_then(|current| current.group_id.clone())
                },
                &before,
                &after,
            );
        }
        Ok(())
    }
}

fn log_failure(method: &'static str, error: &AppError) {
    tracing::warn!(target: TARGET, method = method, error_kind = error.privacy_safe_kind(),
        "coverage ledger write skipped");
}

impl AppClient {
    /// Convert before any runner work or REQ, then charge later loss directly
    /// to the ledger. All route floors are validated before the first write.
    /// The caller is the shared loss-import seam, never the router callback.
    pub(crate) fn synchronize_runner_loss(&self, app: &SqliteAppStorage) -> Result<bool, AppError> {
        let now = unix_now_seconds();
        let routes = self
            .current_coverage_routes()
            .iter()
            .map(|current| {
                Ok(storage_sqlite::RecoveryConversionRoute {
                    route: current.route.clone(),
                    required_relays: current.required.clone(),
                    standing_floor_seconds: self.standing_floor(current, now)?,
                })
            })
            .collect::<StorageResult<Vec<_>>>()?;
        let input = storage_sqlite::RecoveryConversionInput {
            routes: &routes,
            canonical_relay: &transport_nostr::canonical_relay,
            retention_floor_seconds: retention_floor(now),
            now_seconds: now,
        };
        app.convert_recovery_obligations(&input)?;
        if let Some(report) = app.recovery_conversion_report()? {
            // Aggregate evidence that precedes the first runner quantum.
            // Conversion never records history coverage or recovery success.
            tracing::debug!(target: "marmot_app::recovery_runner", method = "conversion",
                shadow_ranges = report.shadow_ranges,
                shadow_remainders = report.shadow_remainders,
                units_broken = report.units_broken,
                epoch_gaps_reopened = report.epoch_gaps_reopened,
                "recovery conversion complete");
            for (cause, counts) in report.obligations {
                tracing::debug!(target: "marmot_app::recovery_runner", method = "conversion",
                    cause = ?cause, pending = counts.pending, parked = counts.parked,
                    dismissed = counts.dismissed, settled = counts.settled,
                    "recovery obligations converted");
            }
            app.acknowledge_recovery_conversion_report()?;
        }
        Ok(app.import_recovery_loss_to_ledger(&self.state.label, &input)?)
    }

    /// Account-local ownership is installed before even staging native input.
    /// The adapter rejects a late first switch; repeat setup is idempotent.
    pub(crate) async fn prepare_runner_ownership(&mut self) -> Result<(), AppError> {
        let prepared = self.prepare_runner_ownership_once().await;
        // Owed until a preparation succeeds: only then may the worker start
        // a runner it lacks, whatever else the refresh still owes.
        self.history_recovery.state.runner_preparation_owed = prepared.is_err();
        prepared
    }

    async fn prepare_runner_ownership_once(&mut self) -> Result<(), AppError> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_runner_preparation) {
            return Err(AppError::Storage(cgka_traits::storage::StorageError::Busy(
                "injected runner preparation failure".to_owned(),
            )));
        }
        let app = self.app.account_storage(&self.state.label)?.app_storage();
        self.synchronize_recovery_loss(&app)?;
        self.enable_live_fences().await;
        Ok(())
    }

    fn current_coverage_routes(&self) -> Vec<CurrentRoute> {
        let routing = self.routing.snapshot();
        let operated = &self.app.config.deployment.recovery_operated_relays;
        let current =
            |route, group_id, endpoints: &[cgka_traits::TransportEndpoint], goal_until| {
                let admitted = self.adapter.recovery_admitted_endpoints(endpoints);
                let required = relays(&transport_nostr::recovery_required_endpoints(
                    &admitted, operated,
                ));
                let best_effort = relays(&admitted)
                    .into_iter()
                    .filter(|relay| !required.contains(relay))
                    .collect();
                CurrentRoute {
                    route,
                    group_id,
                    required,
                    best_effort,
                    goal_until,
                }
            };
        let mut routes = vec![current(
            TransportReconciliationRoute::Inbox,
            None,
            &routing.local_inbox_endpoints,
            None,
        )];
        let mut seen = HashSet::new();
        for entry in &routing.group_routes {
            let Ok(id) = <[u8; 32]>::try_from(entry.transport_group_id.as_slice()) else {
                continue;
            };
            if seen.insert(id) {
                routes.push(current(
                    TransportReconciliationRoute::Group(id),
                    Some(entry.group_id.as_slice().to_vec()),
                    &entry.endpoints,
                    entry.retained_since.map(crate::retained_route_goal_until),
                ));
            }
        }
        routes
    }

    /// The account's current routes as its recovery runner reads them, once
    /// per debt turn (mdk#2660 phase 4).
    pub(crate) fn recovery_runner_routes(&self) -> Vec<super::recovery_runner::RunnerRoute> {
        let windows = self.open_conversation_groups();
        self.current_coverage_routes()
            .into_iter()
            .map(|current| super::recovery_runner::RunnerRoute {
                unrecoverable: current
                    .group_id
                    .as_deref()
                    .is_some_and(|group_id| self.group_unrecoverable(group_id)),
                window: current
                    .group_id
                    .as_ref()
                    .is_some_and(|group_id| windows.contains(group_id)),
                route: current.route,
                group_id: current.group_id,
                required: current.required,
                best_effort: current.best_effort,
                goal_until: current.goal_until,
            })
            .collect()
    }

    /// Settle what routing replacements changed since the recovery runner's
    /// last debt turn (mdk#2660 section 3), giving every current route its
    /// standing goal before the turn reads debt. A (route, relay) a replacement
    /// dropped is retired as gone once this turn confirms it: the routes still
    /// do not carry it, and its group is terminal or still has a route
    /// installed (the inbox: still has a relay). A group left with none may
    /// only be waiting to hydrate, so its drop is forgotten. A relay the
    /// routes carry again owes its whole goal. It runs at the start of a debt
    /// turn, between the owner's commands, so a command that drops a route and
    /// restores it settles nothing. A failed write keeps the changes for the
    /// next turn and returns the error to the runner's local-failure backoff;
    /// no debt read may treat failed preparation as nothing owed.
    pub(crate) fn settle_recovery_route_changes(
        &self,
        app: &SqliteAppStorage,
        now: u64,
    ) -> cgka_traits::storage::StorageResult<()> {
        let Some(changes) = self.routing.take_route_changes() else {
            return Ok(());
        };
        if changes.dropped.is_empty() && !changes.changed {
            return Ok(());
        }
        let routing = self.routing.snapshot();
        let carried =
            crate::ledger_route_pairs(&routing.group_routes, &routing.local_inbox_endpoints);
        let mut gone: BTreeMap<&TransportReconciliationRoute, Vec<String>> = BTreeMap::new();
        for (group, route, relay) in &changes.dropped {
            if carried.contains(&(route.clone(), relay.clone())) {
                continue;
            }
            let confirmed = match group {
                Some(group) => {
                    let group = cgka_traits::GroupId::new(group.clone());
                    crate::client::group_is_terminal(&self.runtime, &group)
                        || routing
                            .group_routes
                            .iter()
                            .any(|route| route.group_id == group)
                }
                None => !routing.local_inbox_endpoints.is_empty(),
            };
            if confirmed {
                gone.entry(route).or_default().push(relay.clone());
            }
        }
        let settled = (|| {
            let current = self.current_coverage_routes();
            // This turn reads the new debt immediately. Do not wake its own
            // runner, especially if a later write keeps the changes pending.
            for (floor, routes) in self.standing_goals(&current.iter().collect::<Vec<_>>(), now)? {
                app.widen_recovery_coverage_goals(
                    &routes,
                    floor,
                    storage_sqlite::CopyFloorReason::Clamp,
                )?;
            }
            let audit = |group: Option<&[u8]>, kind| self.record_runner_audit(group, kind);
            for (route, relays) in &gone {
                let ended = !carried.iter().any(|(carried, _)| carried == *route);
                let retired =
                    app.retire_gone_recovery_units(route, (!ended).then_some(relays), now)?;
                if retired > 0 {
                    let group = changes
                        .dropped
                        .iter()
                        .find(|(_, dropped, _)| dropped == *route)
                        .and_then(|(group, _, _)| group.as_deref());
                    audit(
                        group,
                        recovery_runner::audit::route_change(
                            route,
                            marmot_forensics::RecoveryRunnerChange::RetiredGone,
                            Some(retired),
                        ),
                    );
                }
            }
            let reopened = app.reopen_returned_recovery_units(|route, relay| {
                carried.contains(&(route.clone(), relay.to_owned()))
            })?;
            recovery_runner::audit::rearmed(
                &audit,
                marmot_forensics::RecoveryRunnerChange::Reopened,
                None,
                reopened,
            );
            Ok::<_, cgka_traits::storage::StorageError>(())
        })();
        if settled.is_err() {
            self.routing.restore_route_changes(changes);
        }
        settled
    }

    /// Settle each routed group's new local copy before the debt turn reads
    /// debt (mdk#2660 row 11). A replacement Welcome (the copy's install epoch
    /// moved and its join epoch was reset) is a rejoin: on every relay of
    /// every route of the group, what was owed or parked below the copy's
    /// standing floor retires as before this copy, never as coverage, and the
    /// group gets one notice. The Welcome time alone never retires anything;
    /// it only bounds what a rejoin retires. Any other copy, and an unknown one
    /// (a record migration 0153 could not decode), settles silently. A suspended
    /// copy settles nothing until it recovers or is replaced, and an ended
    /// group nothing at all. Each copy settles once: storage records it in the
    /// same transaction, so a restart raises no second notice. A relay that
    /// joins a rejoined copy's route later, or returns to it, retires below
    /// the rejoin's floor once at the first turn that carries it. A changed copy
    /// marks [`AppClient::recovery_copy_settled`], so the account worker
    /// announces the notice it raised or cleared. A failed write
    /// returns the error to the runner's local-failure backoff and the next
    /// turn tries again.
    pub(crate) fn settle_recovery_rejoins(
        &mut self,
        app: &SqliteAppStorage,
        now: u64,
    ) -> StorageResult<()> {
        let current = self.current_coverage_routes();
        let mut groups = BTreeMap::<&[u8], Vec<&CurrentRoute>>::new();
        for route in &current {
            if let Some(group_id) = &route.group_id {
                groups.entry(group_id).or_default().push(route);
            }
        }
        // The cache only saves reads. A group with no current route (deleted,
        // or no longer routed) drops its entry and rereads its durable copy if
        // it comes back.
        self.history_recovery
            .state
            .settled_recovery_copies
            .retain(|group_id, _| groups.contains_key(group_id.as_slice()));
        for (group_id, routes) in groups {
            let carried = routes
                .iter()
                .map(|current| {
                    let mut relays = current.required.clone();
                    relays.extend(current.best_effort.iter().cloned());
                    (current.route.clone(), relays)
                })
                .collect::<Vec<_>>();
            let group = match self
                .engine_storage
                .get_group(&cgka_traits::GroupId::new(group_id.to_vec()))
            {
                Ok(group) => group,
                Err(StorageError::NotFound) => continue,
                Err(error) => return Err(error),
            };
            let install = group.local_copy_install_epoch.0;
            if group.is_terminal()
                || self
                    .history_recovery
                    .state
                    .settled_recovery_copies
                    .get(group_id)
                    .is_some_and(|settled| settled.0 == install && settled.1 == carried)
            {
                continue;
            }
            match app.recovery_copy(group_id)? {
                Some(RecoveryCopy::Settled(settled)) if settled == install => {
                    let relays = app.retire_before_recovery_copy(group_id, &carried)?;
                    if relays > 0 {
                        tracing::info!(target: TARGET, method = "settle_recovery_rejoins",
                            relays,
                            "rejoined group's history before its copy retired on a later relay");
                    }
                }
                Some(RecoveryCopy::Unknown) => app.record_recovery_copy(group_id, install)?,
                _ if group.unrecoverable => continue,
                _ if group.join_epoch.0 == 0 && install > 0 => {
                    let floor = self.standing_floor(routes[0], now)?;
                    if app.settle_recovery_rejoin(&RecoveryRejoin {
                        group_id,
                        install_epoch: install,
                        routes: &carried,
                        floor_seconds: floor,
                        now_seconds: now,
                    })? {
                        self.history_recovery.state.recovery_copy_settled = true;
                        tracing::info!(target: TARGET, method = "settle_recovery_rejoins",
                            routes = carried.len(),
                            "rejoined group's history before its new copy retired");
                    }
                }
                _ => {
                    app.record_recovery_copy(group_id, install)?;
                    self.history_recovery.state.recovery_copy_settled = true;
                }
            }
            self.history_recovery
                .state
                .settled_recovery_copies
                .insert(group_id.to_vec(), (install, carried));
        }
        Ok(())
    }

    /// Whether the ledger proves `group_id`'s history up to `now` on every
    /// relay that certifies it (mdk#2628 item 3.6b-2): the group has a current
    /// route, and on each of its routes nothing is staged, the route has a
    /// goal and at least one required relay, and each required relay covers
    /// that goal through its owed second, as the recovery runner reads it.
    /// Parked, dismissed and route-gone spans stay owed, so a route whose
    /// recovery gave up is never proved; what a rejoin retired as before this
    /// copy is not this copy's to prove (mdk#2660 row 11).
    pub(crate) async fn group_history_proved(
        &self,
        group_id: &[u8],
        now: u64,
    ) -> Result<bool, AppError> {
        let routes = self
            .current_coverage_routes()
            .into_iter()
            .filter(|current| current.group_id.as_deref() == Some(group_id))
            .collect::<Vec<_>>();
        if routes.is_empty() {
            return Ok(false);
        }
        let app = self.coverage_storage()?.app_storage();
        let staged = app.staged_recovery_routes()?;
        let tails = self.recovery_runner_live_tails(&app, now).await;
        for current in &routes {
            if current.required.is_empty()
                || staged.contains(&current.route)
                || app.recovery_coverage_goal(&current.route)?.is_none()
            {
                return Ok(false);
            }
            let checked_until = current.goal_until.map_or(now, |until| until.min(now));
            for relay in &current.required {
                let until = checked_until.min(tails.owed_until(&current.route, relay, now));
                if !app
                    .recovery_copy_debt(&current.route, relay, until)?
                    .is_empty()
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// The last second of `group_id`'s history that a parked remainder on one
    /// of its current routes still owes: debt the retention floor overtook,
    /// which [`Self::group_history_proved`] does not read, since it lasts
    /// until a rejoin or the route's end clears it.
    pub(crate) fn group_parked_until(&self, group_id: &[u8]) -> Result<Option<u64>, AppError> {
        let routes = self
            .current_coverage_routes()
            .into_iter()
            .filter(|current| current.group_id.as_deref() == Some(group_id))
            .map(|current| current.route)
            .collect::<Vec<_>>();
        Ok(self
            .coverage_storage()?
            .app_storage()
            .recovery_coverage_remainders()?
            .into_iter()
            .filter(|remainder| routes.contains(&remainder.route))
            .map(|remainder| remainder.range.until_seconds)
            .max())
    }

    /// Whether the group's local copy is Unrecoverable, which suspends its
    /// recovery (mdk#2660 section 6). A group whose record cannot be read is
    /// not suspended.
    pub(crate) fn group_unrecoverable(&self, group_id: &[u8]) -> bool {
        self.runtime
            .group_record(&cgka_traits::GroupId::new(group_id.to_vec()))
            .is_ok_and(|group| group.unrecoverable)
    }

    fn coverage_storage(&self) -> Result<storage_sqlite::SqliteAccountStorage, AppError> {
        self.app.account_storage(&self.state.label)
    }

    /// Widen `routes`' goals to `floor` and wake the recovery runner to read
    /// its ledger again. Only the runner's own routing-change settlement
    /// widens directly without a wake: that turn immediately reads the debt.
    fn widen_coverage_goals(
        &self,
        app: &SqliteAppStorage,
        routes: &[TransportReconciliationRoute],
        floor: u64,
    ) -> cgka_traits::storage::StorageResult<()> {
        app.widen_recovery_coverage_goals(routes, floor, storage_sqlite::CopyFloorReason::Clamp)?;
        self.wake_recovery_runner();
        Ok(())
    }

    /// Where a current route's standing goal starts: the retention floor,
    /// or for a group route whose copy has a Welcome time, that time less the
    /// clock-skew allowance when it is later. The Welcome time is only a hint
    /// (`Group::local_copy_welcome_created_at`): it starts goals and never
    /// retires, un-covers or drops debt by itself, so loss, released receipts
    /// and explicit repair keep their own floors, and a goal already lower
    /// stays. Only a rejoin retires below this floor
    /// ([`Self::settle_recovery_rejoins`]).
    /// A Welcome time after `now` (the joining clock ran fast) is ignored, even
    /// one inside the allowance, or the goal would start minutes ago and never
    /// owe the window.
    fn standing_floor(&self, current: &CurrentRoute, now: u64) -> StorageResult<u64> {
        let welcome = match &current.group_id {
            Some(group) => match self
                .engine_storage
                .get_group(&cgka_traits::GroupId::new(group.clone()))
            {
                Ok(group) => group.local_copy_welcome_created_at,
                Err(StorageError::NotFound) => None,
                Err(error) => return Err(error),
            },
            None => None,
        };
        Ok(welcome
            .filter(|welcome| welcome.0 <= now)
            .map_or(0, |welcome| crate::history_floor(welcome.0).0)
            .max(retention_floor(now)))
    }

    /// Group standing goals by floor so one write can widen each set.
    fn standing_goals(
        &self,
        routes: &[&CurrentRoute],
        now: u64,
    ) -> StorageResult<BTreeMap<u64, Vec<TransportReconciliationRoute>>> {
        let mut by_floor = std::collections::BTreeMap::<u64, Vec<_>>::new();
        for current in routes {
            by_floor
                .entry(self.standing_floor(current, now)?)
                .or_default()
                .push(current.route.clone());
        }
        Ok(by_floor)
    }

    /// Widen each current route's goal to its standing floor and wake the
    /// runner. Its own routing-change turn uses the same grouping without a
    /// wake: that turn already reads what it widened.
    fn widen_standing_goals(
        &self,
        app: &SqliteAppStorage,
        routes: &[&CurrentRoute],
        now: u64,
    ) -> Result<(), AppError> {
        for (floor, routes) in self.standing_goals(routes, now)? {
            self.widen_coverage_goals(app, &routes, floor)?;
        }
        Ok(())
    }

    /// Every open owes each current route's retained window, even with a
    /// transport cursor. Durable coverage leaves only its unproven restart
    /// gap as debt. Widen the ledger directly: an IncrementalHistory request
    /// would also give the old comparison owner work in the hybrid. The
    /// runner's first routing-change turn retries a failed best-effort write.
    /// The runner's first prune takes its floor from the same clock reading,
    /// so what slides out of the window before it stays owed for the sweep
    /// rather than parked.
    pub(crate) fn record_open_coverage_goals(&mut self) {
        let now = unix_now_seconds();
        self.history_recovery.state.runner_prune_clock = now;
        let current = self.current_coverage_routes();
        let result = self.coverage_storage().and_then(|storage| {
            self.widen_standing_goals(
                &storage.app_storage(),
                &current.iter().collect::<Vec<_>>(),
                now,
            )
        });
        if let Err(error) = result {
            log_failure("record_open_coverage_goals", &error);
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
        let mut live = self.history_recovery.state.live_coverage.lock().await;
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
            observe_live_counts(&observation, self.app.vouches_for_relay_replies())
        };
        live.broken.retain(|key| present.contains_key(key));
        live.settled.retain(|key, _| present.contains_key(key));
        live.break_reached(&present, lost.as_deref());
        live.mark = Some(mark);
        if !input_placed || self.delivery_loss_blocks_cursor() {
            return;
        }
        let durable = live.durable(&facts);
        let slices = durable
            .iter()
            .filter_map(|(fact, range, routes)| range.map(|range| (fact, range, routes)))
            .flat_map(|(fact, (since, until), routes)| {
                routes.iter().map(move |route| RecoveryCoverageSlice {
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
                for (fact, _, routes) in &durable {
                    live.settled
                        .entry(fact.key.clone())
                        .or_default()
                        .extend(routes.iter().map(|route| (*route).clone()));
                }
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
            observe_live_counts(&observation, self.app.vouches_for_relay_replies())
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
        self.history_recovery
            .state
            .live_coverage
            .lock()
            .await
            .tails
            .clone()
    }
}

#[cfg(test)]
#[path = "recovery_coverage/scenario_tests.rs"]
pub(in crate::client) mod scenario_tests;

#[cfg(test)]
#[path = "recovery_coverage/live_boundary_tests.rs"]
mod live_boundary_tests;
