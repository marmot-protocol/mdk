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
use std::collections::HashSet;

use storage_sqlite::{
    RecoveryCause, RecoveryCoverageProof, RecoveryCoverageSlice, RecoveryDemandTransition,
    RecoveryLossImport, RecoveryPredicate, RecoveryRevisionFence, RecoveryScopeOutcome,
    SqliteAppStorage, StoredRecoveryScope, TRANSPORT_RECONCILIATION_RETENTION_SECS,
    TransportReconciliationRoute,
};

use super::AppClient;
use super::recovery::AttemptGrant;
use super::sync::RouteComparison;
use crate::AppError;
use crate::notifications::unix_now_seconds;

const TARGET: &str = "marmot_app::recovery_coverage";

/// How the ledger and the obligations compare, in aggregate. Each compared
/// scope is counted once; known-event, maintenance-boundary and unresolved
/// scopes are not comparable.
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

/// Whether the obligation counts the scope proved, as completion would: its
/// own predicate over checkpoints captured at the account's current loss,
/// route and inventory revisions and the obligation's current revision. A
/// certificate from before newer loss proves nothing any more.
fn obligation_holds(
    scope: &StoredRecoveryScope,
    predicate: RecoveryPredicate,
    fence: &RecoveryRevisionFence,
    obligation_revision: u64,
) -> bool {
    let current = scope.loss_revision == fence.loss_revision
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
    /// import that changed demand is new evidence, even with nothing counted:
    /// a notification lag charges no delivery count.
    pub(crate) fn record_coverage_loss(&self, imports: &[RecoveryLossImport]) {
        // Routed loss widened its own routes' goals in the import.
        let floors = imports
            .iter()
            .filter(|import| {
                import.every_route && import.transition != RecoveryDemandTransition::Unchanged
            })
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

    /// Startup incremental history and explicit repair want every current
    /// route's retained window. Explicit history is unbounded below; pruning
    /// raises it to the window.
    pub(crate) fn record_coverage_request(&self, cause: RecoveryCause) {
        let since = match cause {
            RecoveryCause::IncrementalHistory => retention_floor(unix_now_seconds()),
            RecoveryCause::ExplicitHistory => 0,
            _ => return,
        };
        let routes = self
            .current_coverage_routes()
            .into_iter()
            .map(|current| current.route)
            .collect::<Vec<_>>();
        if let Err(error) = self.coverage_storage().and_then(|storage| {
            Ok(storage
                .app_storage()
                .widen_recovery_coverage_goals(&routes, since)?)
        }) {
            log_failure("record_coverage_request", &error);
        }
    }

    /// Every endpoint that admitted its live REQ's complete original window in
    /// the current wire epoch covers that window up to now. The adapter resets
    /// that fact on a new wire generation, so a reconnect proves nothing until
    /// its own boundary is admitted again. Like the cursor seal, nothing is
    /// recorded while loss is pending: queue loss drops deliveries after the
    /// adapter placed them, without a new generation.
    pub(crate) async fn record_native_coverage(&self, app: &SqliteAppStorage) {
        let loss_pending = app.pending_recovery_demands().map(|demands| {
            demands.iter().any(|demand| {
                matches!(
                    demand.cause,
                    RecoveryCause::QueueLoss | RecoveryCause::NotificationLoss
                )
            })
        });
        match loss_pending {
            Ok(false) => {}
            Ok(true) => return,
            Err(error) => return log_failure("record_native_coverage", &error.into()),
        }
        let now = unix_now_seconds();
        let mut facts: Vec<(TransportReconciliationRoute, String, u64)> = Vec::new();
        {
            let observation = self.adapter.replay_admission().await;
            for source in observation.sources() {
                if !source.placed() {
                    continue;
                }
                let routes = source
                    .group_routes()
                    .map(|id| TransportReconciliationRoute::Group(*id))
                    .collect::<Vec<_>>();
                let routes = if routes.is_empty() {
                    vec![TransportReconciliationRoute::Inbox]
                } else {
                    routes
                };
                for endpoint in source.endpoints().filter(|endpoint| endpoint.admitted()) {
                    for route in &routes {
                        facts.push((
                            route.clone(),
                            transport_nostr::canonical_relay(endpoint.endpoint().as_str()),
                            source.since().min(now),
                        ));
                    }
                }
            }
        }
        let slices = facts
            .iter()
            .map(|(route, relay, since)| RecoveryCoverageSlice {
                route,
                relay,
                since_seconds: *since,
                until_seconds: now,
                proof: RecoveryCoverageProof::LiveBoundary,
            })
            .collect::<Vec<_>>();
        if let Err(error) = app.record_recovery_coverage(&slices, now) {
            log_failure("record_native_coverage", &error.into());
        }
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
        self.record_native_coverage(app).await;
        let now = unix_now_seconds();
        let floor = retention_floor(now);
        let current = self.current_coverage_routes();
        let demands = app.pending_recovery_demands()?;
        // An epoch gap needs its group's routes' retained window.
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
            .map(|route| route.route.clone())
            .collect::<Vec<_>>();
        app.widen_recovery_coverage_goals(&gap_routes, floor)?;
        // Pending loss owes each scope's window: this restores a goal the
        // import's best-effort widening lost.
        let mut demand_scopes = Vec::with_capacity(demands.len());
        for demand in &demands {
            let scopes = app.recovery_scope_snapshots(demand.ticket.id)?;
            if matches!(
                demand.cause,
                RecoveryCause::QueueLoss | RecoveryCause::NotificationLoss
            ) {
                for scope in &scopes {
                    if let Some(route) = scope_route(scope) {
                        app.widen_recovery_coverage_goals(
                            std::slice::from_ref(&route),
                            scope.plan.since_seconds.unwrap_or(0),
                        )?;
                    }
                }
            }
            demand_scopes.push(scopes);
        }
        app.prune_recovery_coverage(floor)?;
        let fence = app.recovery_revision_fence()?;

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
                report.scopes_compared += 1;
                // The ledger keeps nothing below the retained window: an
                // older or unknown floor owes everything still retained.
                let since = scope.plan.since_seconds.unwrap_or(floor).max(floor);
                let until = scope.plan.until_seconds.min(now);
                let ledger = app.recovery_coverage_covers(
                    &route,
                    &relays(&scope.plan.required_endpoints),
                    since,
                    until,
                )?;
                let holds =
                    obligation_holds(&scope, demand.predicate, &fence, demand.ticket.revision);
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
            if !owed
                && !app
                    .recovery_coverage_debt(&route.route, &route.required, now)?
                    .is_empty()
            {
                report.unowed_debt_routes += 1;
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
#[path = "recovery_coverage/scenario_tests.rs"]
mod scenario_tests;
