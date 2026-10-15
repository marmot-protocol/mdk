//! Immutable comparison I/O for a worker-owned recovery grant. The task has no
//! account storage, engine, session, or event-queue authority. The worker
//! admits what it fetched a few events per turn, never through the live queue.

use super::*;
use std::collections::VecDeque;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use storage_sqlite::RecoveryComparisonOutcome as Outcome;
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;
use transport_nostr_adapter::{NostrReconciliationProgress, SubscriptionAttempt};

/// Owned events one worker turn admits before commands and live input run.
pub(crate) const MAX_COMPARISON_ADMISSION_PER_TURN: usize = 4;

/// Newest events a window fetch takes from each relay that failed to compare
/// an epoch-gap route (mdk#2256). A commit first accepted long after it was
/// wrapped keeps its wrap-time `created_at` and sits below every live `since`,
/// so a relay that cannot compare leaves it unreachable. The missing commit
/// precedes the undecryptable traffic that armed the gap, so it is among the
/// route's newest events unless the group sent more than this many since.
const EPOCH_GAP_WINDOW_MAX_EVENTS_PER_RELAY: usize = 256;
/// Serialized event bytes a window fetch takes from each relay.
const EPOCH_GAP_WINDOW_MAX_BYTES_PER_RELAY: usize = 4 * 1024 * 1024;
/// Longest a window fetch may run, inside what remains of the pass deadline.
const EPOCH_GAP_WINDOW_MAX_DURATION: Duration = Duration::from_secs(3);

/// What the worker keeps while a comparison runs off the worker: the live
/// subscription attempt admission must still own, and the job's execution
/// bracket (loss attempt and audit rows). The bracket is boxed so worker enums
/// that park a pass stay small.
pub(crate) struct ComparisonExecution {
    attempt: Option<SubscriptionAttempt>,
    execution: Box<RecoveryExecutionState>,
}

/// A finished network pass the worker is admitting.
#[derive(Default)]
pub(crate) struct ComparisonAdmission {
    routes: Vec<AdmissionRoute>,
    pending: VecDeque<(
        usize,
        PendingSource,
        transport_nostr_adapter::NostrRelayEvent,
    )>,
    summary: SyncSummary,
    /// The grant changed mid-admission. The admitted prefix stays durable,
    /// but the pass certifies nothing.
    invalid: bool,
}

/// Where an owned event came from. Only comparison events bear on the
/// route's certificate and replay cursor; a window fetch certifies nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingSource {
    Comparison,
    Window,
}

struct AdmissionRoute {
    route: TransportReconciliationRoute,
    initial_cursor: Option<[u8; 32]>,
    cursor: Option<[u8; 32]>,
    outcome: Outcome,
    /// Every endpoint finished an untruncated comparison.
    certified: bool,
    /// Every required relay answered, whatever admission later did.
    answered: bool,
    reached_endpoints: Vec<String>,
    /// Every event this route fetched was durably admitted.
    admitted: bool,
    /// Events durably admitted: progress, even without a certificate.
    fetched: usize,
    /// What the relays returned, for the attempt's audit row only.
    acquisition: super::super::audit_recovery::RouteAcquisition,
}

fn comparison_failure(error: AppError) -> ClassifiedSyncFailure {
    ClassifiedSyncFailure::at_stage(SyncSummary::default(), error, SyncFailureStage::Unknown)
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct TestComparisonActivityWitness {
    pub(crate) attempt_serial: Arc<AtomicU64>,
    pub(crate) active_jobs: Arc<AtomicUsize>,
    pub(crate) active_requests: Arc<AtomicUsize>,
    pub(crate) target_event_id: Arc<Mutex<Option<String>>>,
    pub(crate) returned_events: Arc<AtomicUsize>,
    pub(crate) matching_events: Arc<AtomicUsize>,
}

#[cfg(test)]
struct ActiveCounter(Arc<AtomicUsize>);

#[cfg(test)]
impl ActiveCounter {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

#[cfg(test)]
impl Drop for ActiveCounter {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct MemoryProgress {
    cursor: Mutex<Option<[u8; 32]>>,
}

impl NostrReconciliationProgress for MemoryProgress {
    fn load_cursor(&self) -> Result<Option<[u8; 32]>, cgka_traits::TransportAdapterError> {
        Ok(*self.cursor.lock().expect("comparison progress mutex"))
    }

    fn save_cursor(
        &self,
        cursor: Option<[u8; 32]>,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        *self.cursor.lock().expect("comparison progress mutex") = cursor;
        Ok(())
    }
}

struct FrozenRoute {
    inventory: super::super::recovery::FrozenRecoveryInventory,
    initial_cursor: Option<[u8; 32]>,
    /// An epoch-gap group route: a relay that fails its comparison is asked
    /// for the route's newest events instead.
    window: Option<[u8; 32]>,
}

pub(crate) enum ComparisonRouteWorkResult {
    Skipped,
    TimedOut,
    Returned(OwnedComparisonResult),
}

pub(crate) struct ComparisonRouteResult {
    route: TransportReconciliationRoute,
    initial_cursor: Option<[u8; 32]>,
    cursor: Option<[u8; 32]>,
    result: ComparisonRouteWorkResult,
    /// What a window fetch returned from relays that failed the comparison.
    window: Vec<transport_nostr_adapter::NostrRelayEvent>,
}

impl ComparisonRouteWorkResult {
    /// The relays among `endpoints` a window fetch may stand in for: all of
    /// them when the comparison did not return, else every failed relay that
    /// did not answer its comparison. A relay that answered but left claimed
    /// IDs for a later pass is fetching that backlog oldest first, and while
    /// any compared relay still owes older history (or the pass could not
    /// order what it was missing), a newest page would skip the unfetched
    /// middle (#2086), so none is fetched. A route the deadline skipped has
    /// no time left to fetch anything.
    fn uncompared_endpoints(
        &self,
        endpoints: &[cgka_traits::TransportEndpoint],
    ) -> Vec<cgka_traits::TransportEndpoint> {
        use crate::relay_plane::same_relay;
        match self {
            Self::Skipped => Vec::new(),
            Self::TimedOut | Self::Returned(Err(_) | Ok(None)) => endpoints.to_vec(),
            Self::Returned(Ok(Some((summary, _)))) => {
                if summary.order_unproven || summary.received_items < summary.remote_items {
                    return Vec::new();
                }
                let unattributed = summary.failed_endpoints.len() < summary.relays_failed;
                let named =
                    |set: &[cgka_traits::TransportEndpoint],
                     endpoint: &cgka_traits::TransportEndpoint| {
                        set.iter()
                            .any(|named| same_relay(endpoint.as_str(), named.as_str()))
                    };
                endpoints
                    .iter()
                    .filter(|endpoint| unattributed || named(&summary.failed_endpoints, endpoint))
                    .filter(|endpoint| !named(&summary.incomplete_endpoints, endpoint))
                    .cloned()
                    .collect()
            }
        }
    }
}

pub(crate) struct ComparisonNetworkResult {
    routes: Vec<ComparisonRouteResult>,
}

impl ComparisonNetworkResult {
    /// What each route's relays returned, for a pass discarded before any
    /// admission exists: counts only, nothing admitted or certified. A route
    /// counts as answered only when its comparison ran and every failed relay
    /// still answered.
    fn unsettled_routes(
        &self,
    ) -> impl Iterator<Item = (bool, super::super::audit_recovery::RouteAcquisition)> + '_ {
        self.routes.iter().map(|route| match &route.result {
            ComparisonRouteWorkResult::Returned(Ok(Some((summary, events)))) => {
                let mut acquisition =
                    super::super::audit_recovery::RouteAcquisition::from_summary(summary);
                acquisition.retrieved = events.len();
                (
                    summary.failed_endpoints.len() == summary.incomplete_endpoints.len(),
                    acquisition,
                )
            }
            _ => (false, Default::default()),
        })
    }
}

#[cfg(test)]
impl ComparisonNetworkResult {
    pub(crate) fn outcome_kinds_for_test(&self) -> Vec<&'static str> {
        self.routes
            .iter()
            .map(|route| match &route.result {
                ComparisonRouteWorkResult::Skipped => "route_skipped",
                ComparisonRouteWorkResult::TimedOut => "route_timed_out",
                ComparisonRouteWorkResult::Returned(Ok(None)) => "route_unsupported",
                ComparisonRouteWorkResult::Returned(Err(_)) => "route_error",
                ComparisonRouteWorkResult::Returned(Ok(Some((summary, events)))) => {
                    if summary.relays_failed > 0 {
                        "route_relay_failed"
                    } else if events.is_empty() {
                        "route_no_events"
                    } else {
                        "route_events"
                    }
                }
            })
            .collect()
    }
}

/// Dropping the worker's handle cancels I/O and drops all unadmitted events.
pub(crate) struct ComparisonNetworkJob {
    handle: JoinHandle<(OwnedSemaphorePermit, ComparisonNetworkResult)>,
}

impl Drop for ComparisonNetworkJob {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Ask the relays that failed an epoch-gap route's comparison for the route's
/// newest events, inside the comparison window and what remains of the pass.
async fn fetch_epoch_gap_window(
    adapter: &crate::relay_plane::MarmotRelayPlaneAccountAdapter,
    transport_group_id: [u8; 32],
    endpoints: Vec<cgka_traits::TransportEndpoint>,
    since: u64,
    until: u64,
    deadline: tokio::time::Instant,
) -> Vec<transport_nostr_adapter::NostrRelayEvent> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if endpoints.is_empty() || remaining.is_zero() {
        return Vec::new();
    }
    let relays = endpoints.len();
    let fetch = adapter.acquire_group_window(
        transport_group_id,
        endpoints,
        since,
        until,
        transport_nostr_adapter::NostrAcquisitionLimits {
            max_endpoints: relays,
            max_requested_event_ids: 1,
            max_received_items_per_endpoint: EPOCH_GAP_WINDOW_MAX_EVENTS_PER_RELAY,
            max_serialized_event_bytes_per_endpoint: EPOCH_GAP_WINDOW_MAX_BYTES_PER_RELAY,
            max_duration: remaining.min(EPOCH_GAP_WINDOW_MAX_DURATION),
        },
    );
    let (events, timed_out) = match tokio::time::timeout_at(deadline, fetch).await {
        Ok(events) => (events, false),
        Err(_) => (Vec::new(), true),
    };
    tracing::info!(
        target: "marmot_app::client::sync::comparison_job",
        method = "fetch_epoch_gap_window",
        relays,
        events = events.len(),
        timed_out,
        "fetched an epoch-gap route's newest window from relays that failed to compare it"
    );
    events
}

impl ComparisonNetworkJob {
    /// Cancel the request and wait until its future has dropped the shared credit.
    pub(crate) async fn abort_and_wait(mut self) {
        self.handle.abort();
        let _ = (&mut self.handle).await;
    }

    /// The deadline of an automatic pass: one account-wide quantum.
    pub(crate) fn automatic_deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + TRANSPORT_RECONCILIATION_QUANTUM
    }

    /// Start the grant's comparison off the worker. A route the pass has not
    /// reached by `deadline` is skipped and keeps its debt.
    pub(crate) fn start(
        client: &AppClient,
        grant: &AttemptGrant,
        credit: OwnedSemaphorePermit,
        deadline: tokio::time::Instant,
        #[cfg(test)] witness: Option<TestComparisonActivityWitness>,
    ) -> Result<Self, AppError> {
        let storage = client.app.account_storage(&client.state.label)?;
        let epoch_gap_routes = grant
            .plan()
            .into_iter()
            .flatten()
            .filter(|obligation| obligation.cause == storage_sqlite::RecoveryCause::EpochGap)
            .flat_map(|obligation| &obligation.scopes)
            .filter_map(|scope| scope.goal.transport_group_id)
            .collect::<HashSet<[u8; 32]>>();
        let routes = grant
            .inventory
            .iter()
            .map(|inventory| {
                Ok(FrozenRoute {
                    inventory: inventory.clone(),
                    initial_cursor: storage
                        .transport_reconciliation_replay_cursor(&inventory.route)?,
                    window: match inventory.route {
                        TransportReconciliationRoute::Group(id)
                            if epoch_gap_routes.contains(&id) =>
                        {
                            Some(id)
                        }
                        _ => None,
                    },
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let adapter = client.adapter.clone();
        #[cfg(test)]
        let attempt_serial = grant.reservation.attempt_serial;
        #[cfg(test)]
        let (scripted, scripted_delay, scripted_cursor) = (
            client.test_comparison_results.clone(),
            client.test_comparison_delay,
            client.test_comparison_saved_cursor,
        );
        let handle = tokio::spawn(async move {
            #[cfg(test)]
            let _job_active = witness.as_ref().map(|witness| {
                witness
                    .attempt_serial
                    .store(attempt_serial, Ordering::SeqCst);
                ActiveCounter::new(witness.active_jobs.clone())
            });
            let mut results = Vec::with_capacity(routes.len());
            for frozen in routes {
                let FrozenRoute {
                    inventory,
                    initial_cursor,
                    window,
                } = frozen;
                if tokio::time::Instant::now() >= deadline {
                    results.push(ComparisonRouteResult {
                        route: inventory.route,
                        initial_cursor,
                        cursor: initial_cursor,
                        result: ComparisonRouteWorkResult::Skipped,
                        window: Vec::new(),
                    });
                    continue;
                }
                let endpoints = inventory.work.endpoints().to_vec();
                let (since, until) = (inventory.since, inventory.until);
                let progress = Arc::new(MemoryProgress {
                    cursor: Mutex::new(initial_cursor),
                });
                let run = async {
                    #[cfg(test)]
                    let _request_active = witness
                        .as_ref()
                        .map(|witness| ActiveCounter::new(witness.active_requests.clone()));
                    #[cfg(test)]
                    if let Some(scripted) = &scripted {
                        let (delay, timed) = match scripted.timed_answer(&inventory.route) {
                            Some((delay, answer)) => (delay, Some(answer)),
                            None => (None, None),
                        };
                        if let Some(cursor) = scripted_cursor {
                            progress.save_cursor(Some(cursor))?;
                        }
                        if let Some(delay) = delay.or(scripted_delay) {
                            tokio::time::sleep(delay).await;
                        }
                        return timed.unwrap_or_else(|| scripted.answer(&inventory.route));
                    }
                    match inventory.work {
                        TransportReconciliationWork::Inbox(endpoints) => {
                            adapter
                                .reconcile_inbox_history(
                                    endpoints,
                                    &inventory.items,
                                    inventory.since,
                                    inventory.until,
                                    progress.as_ref(),
                                )
                                .await
                        }
                        TransportReconciliationWork::Group(group) => {
                            adapter
                                .reconcile_group_history(
                                    group,
                                    &inventory.items,
                                    inventory.since,
                                    inventory.until,
                                    progress.as_ref(),
                                )
                                .await
                        }
                    }
                };
                let result = match tokio::time::timeout_at(deadline, run).await {
                    Ok(value) => ComparisonRouteWorkResult::Returned(value),
                    Err(_) => ComparisonRouteWorkResult::TimedOut,
                };
                #[cfg(test)]
                if let Some(witness) = &witness
                    && let ComparisonRouteWorkResult::Returned(Ok(Some((_, events)))) = &result
                {
                    witness
                        .returned_events
                        .fetch_add(events.len(), Ordering::SeqCst);
                    if let Some(target) = witness.target_event_id.lock().unwrap().as_ref() {
                        witness.matching_events.fetch_add(
                            events
                                .iter()
                                .filter(|event| event.event.id.eq_ignore_ascii_case(target))
                                .count(),
                            Ordering::SeqCst,
                        );
                    }
                }
                let window = match window {
                    Some(transport_group_id) => {
                        fetch_epoch_gap_window(
                            &adapter,
                            transport_group_id,
                            result.uncompared_endpoints(&endpoints),
                            since,
                            until,
                            deadline,
                        )
                        .await
                    }
                    None => Vec::new(),
                };
                let cursor = *progress.cursor.lock().expect("comparison progress mutex");
                results.push(ComparisonRouteResult {
                    route: inventory.route,
                    initial_cursor,
                    cursor,
                    result,
                    window,
                });
            }
            (credit, ComparisonNetworkResult { routes: results })
        });
        Ok(Self { handle })
    }

    pub(crate) async fn wait(
        &mut self,
    ) -> Result<(OwnedSemaphorePermit, ComparisonNetworkResult), tokio::task::JoinError> {
        (&mut self.handle).await
    }
}

impl ComparisonAdmission {
    /// What each accepted route's relays returned, for a pass that ends
    /// before settlement.
    fn unsettled_routes(
        &self,
    ) -> impl Iterator<Item = (bool, super::super::audit_recovery::RouteAcquisition)> + '_ {
        self.routes.iter().map(|route| {
            (
                route.answered && route.outcome != Outcome::Unsupported,
                route.acquisition.clone(),
            )
        })
    }
}

impl AppClient {
    /// Whether recovery has any work a grant could select, asked without
    /// spending a reservation: a direct caller asks before it waits for a
    /// credit, and the worker asks when none is free.
    pub(crate) fn recovery_pending(&self) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        Ok(!self.pending_recovery_arm_writes.is_empty()
            || !self.pending_recovery_capacity_writes.is_empty()
            || !storage.pending_recovery_demands()?.is_empty()
            || storage.recovery_comparison()?.pending())
    }

    /// Open the job's execution bracket and install the grant's maintenance
    /// subscriptions. A pass never touches the live subscriptions: it reuses
    /// the live tail, so it re-downloads no history the account already holds.
    pub(crate) async fn begin_comparison_grant(
        &mut self,
        grant: &AttemptGrant,
    ) -> Result<ComparisonExecution, AppError> {
        let mut execution = self
            .begin_recovery_execution(grant)
            .map_err(|failure| failure.source)?;
        // A maintenance boundary is its own REQ's end of stored events. It is
        // installed here, under this grant's scope tokens, and observed later.
        // Installing it is the job's only activation.
        if let Err(error) = self.install_granted_post_join_subscriptions(grant).await {
            let failure = ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                error,
                SyncFailureStage::GroupSubscriptionSync,
            );
            return match self.finish_recovery_execution(grant, execution, Err(failure)) {
                Ok(_) => unreachable!("a failed installation cannot complete"),
                Err(failure) => Err(failure.source),
            };
        }
        execution.activation = marmot_forensics::EpochBackfillActivationOutcome::Succeeded;
        Ok(ComparisonExecution {
            attempt: self.adapter.account_subscription_attempt().await,
            execution: Box::new(execution),
        })
    }

    /// The grant still owns its frozen debt, its comparison slot and the live
    /// subscription attempt it started under.
    async fn comparison_grant_stable(
        &mut self,
        grant: &AttemptGrant,
        execution: &ComparisonExecution,
        compare_inventory: bool,
    ) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        self.synchronize_recovery_loss(&storage)?;
        drop(self.transport_receipts()?);
        self.observe_recovery_route_policy()?;
        let current = storage.recovery_revision_fence()?;
        let slot_stable = match grant.comparison_revision {
            Some(revision) => {
                let slot = storage.recovery_comparison()?;
                slot.pending()
                    && slot.revision == revision
                    && slot.attempt_serial == grant.reservation.attempt_serial
                    && slot.frozen_revision == slot.revision
            }
            None => true,
        };
        Ok(current.loss_revision == grant.fence.loss_revision
            && current.route_revision == grant.fence.route_revision
            && (!compare_inventory || current.inventory_revision == grant.fence.inventory_revision)
            && grant
                .fence
                .obligations
                .iter()
                .all(|selected| current.obligations.contains(selected))
            && slot_stable
            && self.adapter.account_subscription_attempt().await == execution.attempt)
    }

    /// Take ownership of a finished network pass. `None` means the grant
    /// changed while it ran, so none of its bytes may be admitted.
    pub(crate) async fn accept_comparison_network(
        &mut self,
        grant: &AttemptGrant,
        execution: &mut ComparisonExecution,
        network: ComparisonNetworkResult,
    ) -> Result<Option<ComparisonAdmission>, AppError> {
        let stable = self.comparison_grant_stable(grant, execution, true).await;
        if !matches!(stable, Ok(true)) {
            // The result is discarded unadmitted; its finish row still says
            // what the relays returned.
            execution
                .execution
                .tally
                .observe_unsettled_routes(network.unsettled_routes());
            return stable.map(|_| None);
        }
        let mut admission = ComparisonAdmission::default();
        for (index, route) in network.routes.into_iter().enumerate() {
            let inventory = grant
                .inventory
                .iter()
                .find(|inventory| inventory.route == route.route);
            // A route the cutoff timed out, or whose request failed, lost the
            // events it collected with its future, though the adapter may
            // already have saved a cursor past them. It admitted nothing, so
            // its replay cursor must not move.
            let admitted = !matches!(
                route.result,
                ComparisonRouteWorkResult::TimedOut | ComparisonRouteWorkResult::Returned(Err(_))
            );
            let mut acquisition = super::super::audit_recovery::RouteAcquisition::default();
            let mut reached_endpoints = Vec::new();
            let (outcome, certified, answered, events) = match route.result {
                ComparisonRouteWorkResult::Skipped => {
                    (Outcome::ServicedPartial, false, false, Vec::new())
                }
                ComparisonRouteWorkResult::TimedOut
                | ComparisonRouteWorkResult::Returned(Err(_)) => {
                    (Outcome::TransientFailure, false, false, Vec::new())
                }
                ComparisonRouteWorkResult::Returned(Ok(None)) => {
                    (Outcome::Unsupported, false, true, Vec::new())
                }
                ComparisonRouteWorkResult::Returned(Ok(Some((summary, events)))) => {
                    acquisition =
                        super::super::audit_recovery::RouteAcquisition::from_summary(&summary);
                    acquisition.retrieved = events.len();
                    if let Some(inventory) = inventory {
                        use crate::relay_plane::same_relay;
                        let endpoints = inventory.work.endpoints();
                        let unattributed = summary.failed_endpoints.len() < summary.relays_failed
                            || summary.failed_endpoints.iter().any(|failed| {
                                !endpoints
                                    .iter()
                                    .any(|endpoint| same_relay(endpoint.as_str(), failed.as_str()))
                            });
                        if !unattributed {
                            reached_endpoints.extend(endpoints.iter().filter_map(|endpoint| {
                                let failed = summary
                                    .failed_endpoints
                                    .iter()
                                    .any(|failed| same_relay(endpoint.as_str(), failed.as_str()));
                                let incomplete = summary
                                    .incomplete_endpoints
                                    .iter()
                                    .any(|relay| same_relay(endpoint.as_str(), relay.as_str()));
                                (!failed || incomplete).then(|| endpoint.as_str().to_owned())
                            }));
                        }
                    }
                    let (outcome, certified, answered) = inventory
                        .map_or((Outcome::TransientFailure, false, false), |inventory| {
                            inventory.judge(&summary)
                        });
                    (outcome, certified, answered, events)
                }
            };
            // The late commit is the oldest event a window recovers, and a
            // relay that compared can return a newer commit from the same
            // epoch. Queue the route's comparison and window events together,
            // oldest first, so no newer commit converges before the late one
            // is buffered. An event both returned is admitted once, as a
            // comparison event.
            let compared = events
                .iter()
                .map(|event| event.event.id.clone())
                .collect::<HashSet<_>>();
            let mut batch = events
                .into_iter()
                .map(|event| (PendingSource::Comparison, event))
                .chain(
                    route
                        .window
                        .into_iter()
                        .filter(|event| !compared.contains(&event.event.id))
                        .map(|event| (PendingSource::Window, event)),
                )
                .collect::<Vec<_>>();
            batch.sort_by(|(a_source, a), (b_source, b)| {
                (
                    a.event.created_at,
                    &a.event.id,
                    *a_source == PendingSource::Window,
                )
                    .cmp(&(
                        b.event.created_at,
                        &b.event.id,
                        *b_source == PendingSource::Window,
                    ))
            });
            batch.dedup_by(|(_, later), (_, kept)| later.event.id == kept.event.id);
            admission.pending.extend(
                batch
                    .into_iter()
                    .map(|(source, event)| (index, source, event)),
            );
            admission.routes.push(AdmissionRoute {
                route: route.route,
                initial_cursor: route.initial_cursor,
                cursor: route.cursor,
                outcome,
                certified,
                answered,
                reached_endpoints,
                admitted,
                fetched: 0,
                acquisition,
            });
        }
        Ok(Some(admission))
    }

    /// Admit at most a few owned events through the ordinary ingest path, then
    /// return so the worker serves commands and live input before the next
    /// turn. Returns true once nothing remains to admit.
    pub(crate) async fn admit_comparison_turn(
        &mut self,
        grant: &AttemptGrant,
        execution: &mut ComparisonExecution,
        admission: &mut ComparisonAdmission,
    ) -> Result<bool, AppError> {
        if admission.pending.is_empty() {
            return Ok(true);
        }
        if !self
            .comparison_grant_stable(grant, execution, false)
            .await?
        {
            admission.invalid = true;
            admission.pending.clear();
            return Ok(true);
        }
        // An event the account already holds costs a receipt lookup, not an
        // ingest, so it does not spend one of the turn's slots. A newest
        // window starts with held history; the late commit behind it then
        // lands in this turn rather than after live input (mdk#2256).
        let mut spent = 0;
        while spent < MAX_COMPARISON_ADMISSION_PER_TURN {
            let Some((index, source, event)) = admission.pending.pop_front() else {
                break;
            };
            let mut held_only = true;
            // A window event is delivered like any other, but it bears on
            // neither the route's certificate nor its replay cursor: the
            // comparison never claimed it.
            let mut route =
                (source == PendingSource::Comparison).then(|| &mut admission.routes[index]);
            // An event that no longer routes to this account, or that cannot be
            // read as a transport message, was not admitted. It withholds the
            // route's certificate without failing the rest of the batch.
            let deliveries = match self.adapter.recovered_deliveries(event).await {
                Ok(deliveries) => deliveries,
                Err(
                    cgka_traits::TransportAdapterError::InvalidInboundEncoding
                    | cgka_traits::TransportAdapterError::InvalidInboundSignature,
                ) => Vec::new(),
                Err(error) => return Err(error.into()),
            };
            if let Some(route) = route.as_deref_mut() {
                route.admitted &= !deliveries.is_empty();
                if deliveries.is_empty() {
                    route.acquisition.rejected = route.acquisition.rejected.saturating_add(1);
                }
            }
            held_only &= !deliveries.is_empty();
            for delivery in deliveries {
                let (summary, settled) = self.admit_recovered_delivery(delivery).await?;
                admission.summary.merge(summary);
                let counts = &mut execution.execution.counts;
                match settled {
                    super::RecoveredDelivery::AlreadyHeld => {
                        counts.skipped = counts.skipped.saturating_add(1);
                    }
                    super::RecoveredDelivery::Ingested {
                        unpersisted,
                        refused_group,
                    } => {
                        held_only = false;
                        counts.deliveries = counts.deliveries.saturating_add(1);
                        if unpersisted {
                            counts.unpersisted = counts.unpersisted.saturating_add(1);
                        }
                        if let Some(route) = route.as_deref_mut() {
                            if unpersisted {
                                route.admitted = false;
                            } else {
                                route.fetched = route.fetched.saturating_add(1);
                            }
                        }
                        if let Some(group) = refused_group {
                            counts.refused = counts.refused.saturating_add(1);
                            counts.refused_groups.insert(group);
                        }
                    }
                }
            }
            if !held_only {
                spent += 1;
            }
        }
        Ok(admission.pending.is_empty())
    }

    /// Run one selected grant through the job and wait for it: the path of an
    /// explicit caller or a directly owned client, which has no worker loop to
    /// interleave. The comparison still runs in its own task under `credit`,
    /// and admission takes the same bounded turns. An explicit repair's
    /// `control` ends the network pass at its network deadline, and the
    /// routes that finished are admitted inside the admission reserve.
    /// Cancellation discards a pass in flight; cancellation or the whole
    /// budget stops admission at a turn boundary, keeping the admitted prefix
    /// and certifying nothing.
    pub(crate) async fn run_recovery_job(
        &mut self,
        grant: AttemptGrant,
        credit: OwnedSemaphorePermit,
        control: Option<&FullHistoryRepairControl<'_>>,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let execution = self.begin_comparison_grant(&grant).await?;
        let deadline = control.map_or_else(
            ComparisonNetworkJob::automatic_deadline,
            FullHistoryRepairControl::network_deadline,
        );
        let mut network = match ComparisonNetworkJob::start(
            self,
            &grant,
            credit,
            deadline,
            #[cfg(test)]
            None,
        ) {
            Ok(network) => network,
            Err(error) => {
                let _ = self.abandon_comparison_grant(grant, execution);
                return Err(error);
            }
        };
        let completed = loop {
            tokio::select! {
                completed = network.wait() => break completed.ok(),
                () = tokio::time::sleep(RECOVERY_JOB_CANCEL_POLL),
                    if control.is_some() =>
                {
                    // Only cancellation discards the pass. The network
                    // deadline ends it inside the task, which returns the
                    // routes that finished for admission.
                    if control.is_some_and(FullHistoryRepairControl::cancelled) {
                        network.abort_and_wait().await;
                        break None;
                    }
                }
            }
        };
        let Some((credit, result)) = completed else {
            return self.abandon_comparison_grant(grant, execution);
        };
        // Under a repair's control the only network deadline is its cutoff,
        // so a skipped or timed-out route is one that cutoff cut short.
        self.recovery_job_network_cut = control.is_some()
            && result.routes.iter().any(|route| {
                matches!(
                    route.result,
                    ComparisonRouteWorkResult::Skipped | ComparisonRouteWorkResult::TimedOut
                )
            });
        // The job counts against the process pool until admission and its
        // checkpoint finish, not only while the network request runs.
        let settled = self
            .admit_comparison_until(grant, execution, result, control)
            .await;
        drop(credit);
        settled
    }

    /// Run one selected grant through the job with a private credit.
    #[cfg(test)]
    pub(crate) async fn run_recovery_grant_for_test(
        &mut self,
        grant: AttemptGrant,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let credit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .expect("a private test credit");
        self.run_recovery_job(grant, credit, None).await
    }

    /// Admit a finished pass in bounded turns, yielding between them, then
    /// settle it. Startup uses this while its mutations are still deferred;
    /// the steady-state worker runs one turn per loop instead.
    pub(crate) async fn admit_comparison_inline(
        &mut self,
        grant: AttemptGrant,
        execution: ComparisonExecution,
        network: ComparisonNetworkResult,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        self.admit_comparison_until(grant, execution, network, None)
            .await
    }

    async fn admit_comparison_until(
        &mut self,
        grant: AttemptGrant,
        mut execution: ComparisonExecution,
        network: ComparisonNetworkResult,
        control: Option<&FullHistoryRepairControl<'_>>,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let mut admission = match self
            .accept_comparison_network(&grant, &mut execution, network)
            .await
        {
            Ok(admission) => admission,
            Err(error) => return Err(self.fail_comparison_grant(grant, execution, None, error)),
        };
        if let Some(admission) = admission.as_mut() {
            loop {
                // Cancellation, or the whole budget spent past the admission
                // reserve, stops at a turn boundary. The admitted prefix stays
                // durable; the pass certifies nothing, so the debt waits for a
                // later grant.
                if let Some(reason) = control.and_then(FullHistoryRepairControl::stopped) {
                    self.recovery_job_admission_expired |=
                        reason == crate::FullHistoryRepairIncompleteReason::Deadline;
                    execution.execution.interruption = Some(
                        if reason == crate::FullHistoryRepairIncompleteReason::Deadline {
                            marmot_forensics::RecoveryPassOutcome::Deadline
                        } else {
                            marmot_forensics::RecoveryPassOutcome::Cancelled
                        },
                    );
                    admission.invalid = true;
                    admission.pending.clear();
                    break;
                }
                match self
                    .admit_comparison_turn(&grant, &mut execution, admission)
                    .await
                {
                    Ok(true) => break,
                    Ok(false) => tokio::task::yield_now().await,
                    Err(error) => {
                        return Err(self.fail_comparison_grant(
                            grant,
                            execution,
                            Some(admission),
                            error,
                        ));
                    }
                }
            }
        }
        self.finish_comparison_grant(grant, execution, admission)
            .await
    }

    /// Settle the execution bracket after admission: checkpoints, loss
    /// acknowledgment and audit rows.
    pub(crate) async fn finish_comparison_grant(
        &mut self,
        grant: AttemptGrant,
        execution: ComparisonExecution,
        admission: Option<ComparisonAdmission>,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let mut execution = *execution.execution;
        let selected = grant.fence.obligations.clone();
        let comparison_selected = grant.comparison_revision.is_some();
        let settled = match admission {
            // The grant changed before admission; nothing was admitted.
            None => {
                execution.interruption = Some(marmot_forensics::RecoveryPassOutcome::Superseded);
                Ok(None)
            }
            // A change during admission keeps the durable prefix but certifies
            // nothing; the debt waits for a later grant.
            Some(admission) if admission.invalid => {
                // A repair stopped at a turn boundary already named why.
                execution.interruption = execution
                    .interruption
                    .or(Some(marmot_forensics::RecoveryPassOutcome::Superseded));
                // Settlement is skipped, but the finish row still reports
                // what the relays returned and the admitted prefix.
                execution
                    .tally
                    .observe_unsettled_routes(admission.unsettled_routes());
                Ok(Some(admission.summary))
            }
            Some(admission) => self
                .checkpoint_comparison_admission(&grant, &mut execution, admission)
                .await
                .map(Some),
        };
        let deferred = matches!(settled, Ok(None));
        let summary = self
            .finish_recovery_execution(&grant, execution, settled.map(Option::unwrap_or_default))
            .map_err(|failure| {
                self.pending_failed_sync_summary
                    .merge(failure.partial_summary);
                failure.source
            })?;
        if deferred {
            return Ok(EpochBackfillRunOutcome::Deferred);
        }
        let storage = self.app.account_storage(&self.state.label)?;
        let complete = !comparison_selected
            && selected.iter().all(|(id, revision)| {
                storage
                    .recovery_obligation_is_satisfied(*id, *revision)
                    .unwrap_or(false)
            });
        Ok(if complete {
            EpochBackfillRunOutcome::Completed(summary)
        } else {
            EpochBackfillRunOutcome::Incomplete(summary)
        })
    }

    /// The network task ended without a result. Settle the bracket like an
    /// attempt that admitted nothing; the durable debt waits for a later grant.
    pub(crate) fn abandon_comparison_grant(
        &mut self,
        grant: AttemptGrant,
        execution: ComparisonExecution,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let mut execution = *execution.execution;
        execution.interruption = Some(marmot_forensics::RecoveryPassOutcome::Cancelled);
        self.finish_recovery_execution(&grant, execution, Ok(SyncSummary::default()))
            .map_err(|failure| failure.source)?;
        Ok(EpochBackfillRunOutcome::Deferred)
    }

    /// Admission failed. Settle the bracket as a failed attempt; the durable
    /// prefix stays and the debt waits for a later grant.
    pub(crate) fn fail_comparison_grant(
        &mut self,
        grant: AttemptGrant,
        execution: ComparisonExecution,
        admission: Option<&mut ComparisonAdmission>,
        error: AppError,
    ) -> AppError {
        let mut execution = *execution.execution;
        let mut failure = comparison_failure(error);
        if let Some(admission) = admission {
            execution
                .tally
                .observe_unsettled_routes(admission.unsettled_routes());
            failure.partial_summary = std::mem::take(&mut admission.summary);
        }
        match self.finish_recovery_execution(&grant, execution, Err(failure)) {
            Ok(_) => unreachable!("a failed recovery cannot complete"),
            Err(failure) => {
                self.pending_failed_sync_summary
                    .merge(failure.partial_summary);
                failure.source
            }
        }
    }

    async fn checkpoint_comparison_admission(
        &mut self,
        grant: &AttemptGrant,
        execution: &mut RecoveryExecutionState,
        admission: ComparisonAdmission,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        let mut summary = admission.summary;
        let mut failure = |error| {
            ClassifiedSyncFailure::at_stage(
                std::mem::take(&mut summary),
                error,
                SyncFailureStage::Unknown,
            )
        };
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(&mut failure)?;
        let mut outcomes = Vec::with_capacity(admission.routes.len());
        for route in admission.routes {
            // A route whose batch was not fully admitted keeps its old cursor,
            // so the next pass fetches the unadmitted suffix again.
            if route.admitted && route.cursor != route.initial_cursor {
                storage
                    .advance_transport_reconciliation_replay_cursor(&route.route, route.cursor)
                    .map_err(|error| failure(error.into()))?;
            }
            outcomes.push(super::RouteComparison {
                route: route.route,
                outcome: if route.admitted {
                    route.outcome
                } else {
                    Outcome::TransientFailure
                },
                certified: route.certified && route.admitted,
                fetched: route.fetched,
                // Incomplete admission withholds the certificate and retries
                // the route, but the relays still answered.
                answered: route.answered,
                reached_endpoints: route.reached_endpoints,
                acquisition: route.acquisition,
            });
        }
        self.settle_recovery_grant(
            grant,
            &mut execution.counts,
            &mut execution.tally,
            outcomes,
            summary,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{
        ScriptedEosePump, ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
        scripted_eose_pump,
    };
    use cgka_traits::GroupStorage;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
    use std::sync::Arc;

    fn candidate_for_route(route: [u8; 32]) -> transport_nostr_adapter::NostrRelayEvent {
        let signed = EventBuilder::new(Kind::MlsGroupMessage, "queue boundary")
            .tags([Tag::custom("h", [hex::encode(route)])])
            .finalize(&Keys::generate())
            .unwrap();
        transport_nostr_adapter::NostrRelayEvent {
            endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
            subscription_id: None,
            event: transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&signed).unwrap(),
        }
    }

    fn candidate() -> transport_nostr_adapter::NostrRelayEvent {
        candidate_for_route([7; 32])
    }

    /// A signed event of a kind no transport message can carry.
    fn unreadable_for_route(route: [u8; 32]) -> transport_nostr_adapter::NostrRelayEvent {
        let signed = EventBuilder::new(Kind::TextNote, "not a transport message")
            .tags([Tag::custom("h", [hex::encode(route)])])
            .finalize(&Keys::generate())
            .unwrap();
        transport_nostr_adapter::NostrRelayEvent {
            endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
            subscription_id: None,
            event: transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&signed).unwrap(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abort_request_keeps_credit_until_network_future_is_dropped() {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let credit = capacity.clone().try_acquire_owned().unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let waiting = entered.notified();
        tokio::pin!(waiting);
        waiting.as_mut().enable();
        let handle = tokio::spawn({
            let entered = entered.clone();
            async move {
                entered.notify_one();
                std::future::pending::<()>().await;
                (credit, ComparisonNetworkResult { routes: Vec::new() })
            }
        });
        let job = ComparisonNetworkJob { handle };
        waiting.await;
        drop(job);
        // abort() has only requested cancellation. The task still owns the
        // permit until Tokio drops its future on the next scheduler turn.
        assert_eq!(capacity.available_permits(), 0);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while capacity.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled task releases its own permit");
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abort_and_wait_reaps_network_future_before_returning() {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let credit = capacity.clone().try_acquire_owned().unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let waiting = entered.notified();
        tokio::pin!(waiting);
        waiting.as_mut().enable();
        let handle = tokio::spawn({
            let entered = entered.clone();
            async move {
                entered.notify_one();
                std::future::pending::<()>().await;
                (credit, ComparisonNetworkResult { routes: Vec::new() })
            }
        });
        let job = ComparisonNetworkJob { handle };
        waiting.await;
        assert_eq!(capacity.available_permits(), 0);
        job.abort_and_wait().await;
        assert_eq!(capacity.available_permits(), 1);
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        _pump: ScriptedEosePump,
        relay: Arc<ScriptedPushRelayClient>,
        client: AppClient,
        storage: storage_sqlite::SqliteAccountStorage,
        group_id: GroupId,
    }

    async fn fixture() -> Fixture {
        fixture_with_group_relays(None).await
    }

    async fn fixture_with_group_relays(relays: Option<Vec<String>>) -> Fixture {
        fixture_with_group_relays_and_comparison(relays, true).await
    }

    async fn fixture_with_group_relays_and_comparison(
        relays: Option<Vec<String>>,
        comparison: bool,
    ) -> Fixture {
        fixture_with_options(relays, comparison, false).await
    }

    /// The default fixture, recording audit v5 from before the account opens.
    async fn audited_fixture() -> Fixture {
        fixture_with_options(None, true, true).await
    }

    async fn fixture_with_options(
        relays: Option<Vec<String>>,
        comparison: bool,
        audited: bool,
    ) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        if audited {
            app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
                .unwrap();
        }
        let pump = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_id = client
            .create_group_with_options(
                "comparison offload",
                &[],
                crate::AppCreateGroupOptions {
                    relays,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        if comparison {
            client.request_bounded_comparison().unwrap();
        }
        let storage = app.account_storage("alice").unwrap();
        Fixture {
            _dir: dir,
            _pump: pump,
            relay,
            client,
            storage,
            group_id,
        }
    }

    async fn arm_test_epoch_gap(fixture: &mut Fixture) {
        // Settle the create-group history demand through the original
        // executor, leaving its NeedsDeepRepair debt ineligible as in the
        // online worker fixture. The next selection then belongs to one gap.
        let baseline = fixture
            .client
            .authorize_account_recovery(
                None,
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .unwrap()
            .unwrap();
        fixture
            .client
            .run_recovery_grant_for_test(baseline)
            .await
            .unwrap();
        let epoch = fixture
            .client
            .group_mls_state(&fixture.group_id)
            .unwrap()
            .epoch;
        fixture
            .storage
            .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(fixture.group_id.as_slice()),
                stalled_epoch: epoch,
            }])
            .unwrap();
    }

    #[tokio::test]
    async fn pending_recovery_waits_for_a_credit_without_spending_a_reservation() {
        let relays = (0..5)
            .map(|index| format!("wss://relay-{index}.example"))
            .collect();
        // Five relays on one route no longer change how the gap is served.
        for relays in [None, Some(relays)] {
            let mut fixture = fixture_with_group_relays_and_comparison(relays, false).await;
            arm_test_epoch_gap(&mut fixture).await;
            let serial = fixture
                .storage
                .recovery_retry_state()
                .unwrap()
                .attempt_serial;
            assert!(fixture.client.recovery_pending().unwrap());
            assert_eq!(
                fixture
                    .storage
                    .recovery_retry_state()
                    .unwrap()
                    .attempt_serial,
                serial,
                "the preflight spends no reservation"
            );
        }
    }

    fn network_result(
        route: TransportReconciliationRoute,
        cursor: Option<[u8; 32]>,
    ) -> ComparisonNetworkResult {
        ComparisonNetworkResult {
            routes: vec![ComparisonRouteResult {
                route,
                initial_cursor: None,
                window: Vec::new(),
                cursor,
                result: ComparisonRouteWorkResult::Returned(Ok(Some((
                    transport_nostr_adapter::NostrReconciliationSummary {
                        relays_succeeded: 1,
                        ..Default::default()
                    },
                    Vec::new(),
                )))),
            }],
        }
    }

    #[tokio::test]
    async fn a_route_with_more_than_four_relays_is_compared_by_the_job() {
        let relays = (0..5)
            .map(|index| format!("wss://relay-{index}.example"))
            .collect();
        let mut fixture = fixture_with_group_relays(Some(relays)).await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant
            .inventory
            .iter()
            .find(|route| match &route.work {
                TransportReconciliationWork::Group(group) => group.endpoints.len() == 5,
                TransportReconciliationWork::Inbox(_) => false,
            })
            .expect("every relay of the wide route is compared")
            .route
            .clone();
        let serial = grant.reservation.attempt_serial;
        let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        let result = fixture
            .client
            .admit_comparison_inline(
                grant,
                execution,
                network_result(route.clone(), Some([8; 32])),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32])
        );
        assert_eq!(
            fixture
                .storage
                .recovery_retry_state()
                .unwrap()
                .attempt_serial,
            serial,
            "the selected grant is settled without a second authorization"
        );
    }

    #[tokio::test]
    async fn comparison_stale_result_preserves_cursor_and_debt() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        let activated_subscription = fixture.client.adapter.account_subscription_attempt().await;
        let new_goals = fixture
            .client
            .comparison_route_goals(unix_now_seconds())
            .unwrap();
        fixture
            .storage
            .join_recovery_comparison(
                &[9; 16],
                crate::client::recovery::wall_now_ms().unwrap(),
                &new_goals,
            )
            .unwrap();
        let result = fixture
            .client
            .admit_comparison_inline(grant, attempt, network_result(route.clone(), Some([8; 32])))
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None
        );
        assert!(fixture.storage.recovery_comparison().unwrap().pending());
        fixture
            .client
            .finish_deferred_comparison_sync()
            .await
            .unwrap();
        assert_eq!(
            fixture.client.adapter.account_subscription_attempt().await,
            activated_subscription,
            "a stale startup comparison drains its live activation without rebuilding subscriptions"
        );
    }

    #[tokio::test]
    async fn comparison_inventory_change_rejects_owned_result() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant
            .inventory
            .iter()
            .find_map(|item| match item.route {
                TransportReconciliationRoute::Group(id) => Some(id),
                TransportReconciliationRoute::Inbox => None,
            })
            .unwrap();
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        let before = fixture
            .storage
            .recovery_revision_fence()
            .unwrap()
            .inventory_revision;
        fixture
            .storage
            .record_transport_reconciliation_item(
                &TransportReconciliationRoute::Group(route),
                &TransportReconciliationItem {
                    event_id: [5; 32],
                    created_at: unix_now_seconds(),
                },
            )
            .unwrap();
        fixture
            .storage
            .delete_transport_group_route(&route)
            .unwrap();
        assert!(
            fixture
                .storage
                .recovery_revision_fence()
                .unwrap()
                .inventory_revision
                > before
        );
        let result = fixture
            .client
            .admit_comparison_inline(
                grant,
                attempt,
                network_result(TransportReconciliationRoute::Inbox, Some([8; 32])),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&TransportReconciliationRoute::Inbox)
                .unwrap(),
            None
        );
        assert!(fixture.storage.recovery_comparison().unwrap().pending());
    }

    #[tokio::test]
    async fn comparison_subscription_change_rejects_owned_result() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        fixture.client.adapter.require_fresh_activation().await;
        fixture
            .client
            .runtime
            .activate_transport(None)
            .await
            .unwrap();
        assert_ne!(
            fixture.client.adapter.account_subscription_attempt().await,
            attempt.attempt
        );
        let result = fixture
            .client
            .admit_comparison_inline(grant, attempt, network_result(route.clone(), Some([8; 32])))
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None
        );
        assert!(fixture.storage.recovery_comparison().unwrap().pending());
    }

    #[tokio::test]
    async fn comparison_worker_join_persists_advisory_cursor_before_settlement() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        let result = fixture
            .client
            .admit_comparison_inline(grant, attempt, network_result(route.clone(), Some([8; 32])))
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32])
        );
    }

    async fn group_route_grant(
        fixture: &mut Fixture,
    ) -> (
        AttemptGrant,
        ComparisonExecution,
        TransportReconciliationRoute,
        [u8; 32],
    ) {
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let (route, group_route) = grant
            .inventory
            .iter()
            .find_map(|item| match item.route {
                TransportReconciliationRoute::Group(id) => Some((item.route.clone(), id)),
                TransportReconciliationRoute::Inbox => None,
            })
            .expect("fixture has a selected group route");
        let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        (grant, execution, route, group_route)
    }

    fn fetched(
        route: TransportReconciliationRoute,
        events: Vec<transport_nostr_adapter::NostrRelayEvent>,
    ) -> ComparisonNetworkResult {
        let mut network = network_result(route, Some([8; 32]));
        network.routes[0].result = ComparisonRouteWorkResult::Returned(Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            events,
        ))));
        network
    }

    #[tokio::test]
    async fn an_unreadable_event_withholds_the_route_without_failing_the_batch() {
        let mut fixture = fixture().await;
        let (grant, execution, route, group_route) = group_route_grant(&mut fixture).await;
        let result = fixture
            .client
            .admit_comparison_inline(
                grant,
                execution,
                fetched(
                    route.clone(),
                    vec![
                        unreadable_for_route(group_route),
                        candidate_for_route(group_route),
                    ],
                ),
            )
            .await;
        assert!(
            matches!(result, Ok(EpochBackfillRunOutcome::Incomplete(_))),
            "one unreadable event must not fail the whole pass"
        );
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None,
            "a route with an unadmitted event keeps its pre-pass cursor"
        );
    }

    #[tokio::test]
    async fn comparison_admits_owned_events_directly_without_the_delivery_queue() {
        let mut fixture = fixture().await;
        let (grant, execution, route, group_route) = group_route_grant(&mut fixture).await;
        let result = fixture
            .client
            .admit_comparison_inline(
                grant,
                execution,
                fetched(route.clone(), vec![candidate_for_route(group_route)]),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32]),
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                fixture.client.adapter.receive_account_delivery()
            )
            .await
            .is_err(),
            "nothing passed through the live delivery queue"
        );
    }

    #[tokio::test]
    async fn comparison_admission_runs_in_bounded_turns() {
        let mut fixture = fixture().await;
        let (grant, mut execution, route, group_route) = group_route_grant(&mut fixture).await;
        let events = (0..MAX_COMPARISON_ADMISSION_PER_TURN + 1)
            .map(|_| candidate_for_route(group_route))
            .collect();
        let mut admission = fixture
            .client
            .accept_comparison_network(&grant, &mut execution, fetched(route, events))
            .await
            .unwrap()
            .expect("an unchanged grant owns its result");
        assert!(
            !fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap(),
            "one turn admits at most its bound, then yields"
        );
        assert_eq!(admission.pending.len(), 1);
        assert!(
            fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap()
        );
        fixture
            .client
            .finish_comparison_grant(grant, execution, Some(admission))
            .await
            .unwrap();
    }

    /// A newest window starts with history the device already holds. Those
    /// events must not spend the turn's admission slots, or the late commit
    /// behind them waits a turn while live input runs (mdk#2256).
    #[tokio::test]
    async fn already_held_events_do_not_spend_a_turns_admission_slots() {
        let mut fixture = fixture().await;
        let (grant, mut execution, route, group_route) = group_route_grant(&mut fixture).await;
        let held = (0..MAX_COMPARISON_ADMISSION_PER_TURN)
            .map(|_| candidate_for_route(group_route))
            .collect::<Vec<_>>();
        let mut admission = fixture
            .client
            .accept_comparison_network(&grant, &mut execution, fetched(route, held.clone()))
            .await
            .unwrap()
            .expect("an unchanged grant owns its result");
        assert!(
            fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap()
        );
        let late = candidate_for_route(group_route);
        admission.pending.extend(
            held.into_iter()
                .chain([late.clone()])
                .map(|event| (0, PendingSource::Window, event)),
        );
        assert!(
            fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap(),
            "held events pass without spending the turn"
        );
        assert!(
            fixture
                .client
                .transport_receipts()
                .unwrap()
                .contains(&late.event.id)
        );
        fixture
            .client
            .finish_comparison_grant(grant, execution, Some(admission))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn comparison_change_between_turns_keeps_the_prefix_and_certifies_nothing() {
        let mut fixture = fixture().await;
        let (grant, mut execution, route, group_route) = group_route_grant(&mut fixture).await;
        let events = (0..MAX_COMPARISON_ADMISSION_PER_TURN + 1)
            .map(|_| candidate_for_route(group_route))
            .collect();
        let mut admission = fixture
            .client
            .accept_comparison_network(&grant, &mut execution, fetched(route.clone(), events))
            .await
            .unwrap()
            .unwrap();
        fixture
            .client
            .admit_comparison_turn(&grant, &mut execution, &mut admission)
            .await
            .unwrap();
        // A newer join revises the comparison slot this grant froze.
        let goals = fixture
            .client
            .comparison_route_goals(unix_now_seconds())
            .unwrap();
        fixture
            .storage
            .join_recovery_comparison(
                &[9; 16],
                crate::client::recovery::wall_now_ms().unwrap(),
                &goals,
            )
            .unwrap();
        assert!(
            fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap()
        );
        assert!(admission.invalid);
        let result = fixture
            .client
            .finish_comparison_grant(grant, execution, Some(admission))
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None,
            "an invalidated pass records no cursor progress"
        );
        assert!(fixture.storage.recovery_comparison().unwrap().pending());
    }

    #[tokio::test]
    async fn comparison_unadmitted_event_keeps_prepass_cursor() {
        let mut fixture = fixture().await;
        let (grant, execution, route, _) = group_route_grant(&mut fixture).await;
        // This event routes to no route of the account, so it is not admitted.
        let result = fixture
            .client
            .admit_comparison_inline(grant, execution, fetched(route.clone(), vec![candidate()]))
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None,
        );
        // The relays answered; only admission fell short. That withholds the
        // certificate but is a quiet comparison, not an outage, so the slot is
        // serviced and the debt itself carries the retry.
        assert!(!fixture.storage.recovery_comparison().unwrap().pending());
        let history = fixture
            .storage
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|demand| demand.cause == storage_sqlite::RecoveryCause::IncrementalHistory)
            .expect("the comparison debt stays pending")
            .ticket
            .id;
        let TransportReconciliationRoute::Group(group_route) = route else {
            panic!("the fixture compares a group route");
        };
        let scope = fixture
            .storage
            .recovery_scope_snapshots(history)
            .unwrap()
            .into_iter()
            .find(|scope| scope.plan.transport_group_id == Some(group_route))
            .expect("the group route has a scope");
        assert_eq!(scope.quiet_passes, 1);
    }

    #[tokio::test]
    async fn comparison_partial_pass_rotates_cursor_and_keeps_retry_debt() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        let mut network = network_result(route.clone(), Some([8; 32]));
        network.routes[0].result = ComparisonRouteWorkResult::Returned(Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_failed: 1,
                ..Default::default()
            },
            Vec::new(),
        ))));
        fixture
            .client
            .admit_comparison_inline(grant, attempt, network)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32])
        );
        let slot = fixture.storage.recovery_comparison().unwrap();
        assert!(slot.pending());
        assert!(!slot.plan.unwrap().retry_routes.is_empty());
    }

    /// The comparison answer for every route: the group route's relay failed,
    /// or every relay answered.
    fn group_route_comparison(group_relay_failed: bool) -> ScriptedComparisons {
        ScriptedComparisons::by_route(move |route| {
            let failed =
                group_relay_failed && matches!(route, TransportReconciliationRoute::Group(_));
            Ok(Some((
                transport_nostr_adapter::NostrReconciliationSummary {
                    relays_succeeded: usize::from(!failed),
                    relays_failed: usize::from(failed),
                    failed_endpoints: if failed {
                        vec![cgka_traits::TransportEndpoint("wss://relay.example".into())]
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                },
                Vec::new(),
            )))
        })
    }

    /// Script the relay's answer to a window fetch: `event`, then EOSE.
    fn script_window(fixture: &Fixture, event: &transport_nostr_adapter::NostrRelayEvent) {
        script_window_ending(
            fixture,
            event,
            transport_nostr_adapter::NostrAcquisitionEnd::RequestPolicySatisfied,
        );
    }

    /// Script the relay's answer to a window fetch: `event`, then `end`.
    fn script_window_ending(
        fixture: &Fixture,
        event: &transport_nostr_adapter::NostrRelayEvent,
        end: transport_nostr_adapter::NostrAcquisitionEnd,
    ) {
        *fixture.relay.acquisition_result.lock().unwrap() =
            Some(transport_nostr_adapter::NostrAcquisitionResult {
                endpoints: vec![transport_nostr_adapter::NostrAcquisitionEndpoint {
                    endpoint: event.endpoint.clone(),
                    session_generation: None,
                    events: vec![event.event.clone()],
                    end,
                    stats: Default::default(),
                }],
            });
    }

    /// Arm a gap for the fixture's group, with no earlier pass pacing it.
    fn arm_unpaced_epoch_gap(fixture: &Fixture) {
        let epoch = fixture
            .client
            .group_mls_state(&fixture.group_id)
            .unwrap()
            .epoch;
        fixture
            .storage
            .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(fixture.group_id.as_slice()),
                stalled_epoch: epoch,
            }])
            .unwrap();
    }

    fn epoch_gap_grant(fixture: &mut Fixture) -> (AttemptGrant, [u8; 32]) {
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let group_route = grant
            .inventory
            .iter()
            .find_map(|item| match item.route {
                TransportReconciliationRoute::Group(id) => Some(id),
                TransportReconciliationRoute::Inbox => None,
            })
            .expect("the gap selects its group route");
        (grant, group_route)
    }

    /// mdk#2256: a commit first accepted long after it was wrapped keeps its
    /// wrap-time `created_at`, so it sits below every live `since` and only
    /// history recovery can find it. When a relay fails the epoch-gap route's
    /// comparison, the job fetches that relay's newest events for the route
    /// and admits them, without certifying the route.
    #[tokio::test]
    async fn an_epoch_gap_route_a_relay_failed_to_compare_fetches_its_newest_window() {
        let mut fixture = fixture_with_group_relays_and_comparison(None, false).await;
        arm_unpaced_epoch_gap(&fixture);
        let (grant, group_route) = epoch_gap_grant(&mut fixture);
        let late = candidate_for_route(group_route);
        script_window(&fixture, &late);
        fixture.client.test_comparison_results = Some(group_route_comparison(true));

        let outcome = fixture
            .client
            .run_recovery_grant_for_test(grant)
            .await
            .unwrap();

        assert_eq!(
            fixture
                .relay
                .acquisition_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the failed relay is asked for the route's newest window"
        );
        assert!(
            fixture
                .client
                .transport_receipts()
                .unwrap()
                .contains(&late.event.id),
            "the late event is admitted"
        );
        assert!(
            matches!(outcome, EpochBackfillRunOutcome::Incomplete(_)),
            "a window fetch certifies nothing"
        );
    }

    /// The late commit is the oldest event in a gap, and relays answer the
    /// window newest first. Admission must not converge a newer commit from
    /// the same page before the late one is buffered, so the window is queued
    /// oldest first.
    #[tokio::test]
    async fn a_window_is_admitted_oldest_first() {
        let mut fixture = fixture().await;
        let (grant, mut execution, route, group_route) = group_route_grant(&mut fixture).await;
        let at = |created_at: u64| {
            let signed = EventBuilder::new(Kind::MlsGroupMessage, "window")
                .tags([Tag::custom("h", [hex::encode(group_route)])])
                .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(created_at))
                .finalize(&Keys::generate())
                .unwrap();
            transport_nostr_adapter::NostrRelayEvent {
                endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                subscription_id: None,
                event: transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&signed)
                    .unwrap(),
            }
        };
        // A relay that compared returned a newer commit than the late one
        // the window recovered from a relay that could not compare.
        let mut network = fetched(route, vec![at(25)]);
        network.routes[0].window = vec![at(30), at(10), at(20)];
        let admission = fixture
            .client
            .accept_comparison_network(&grant, &mut execution, network)
            .await
            .unwrap()
            .expect("an unchanged grant owns its result");
        assert_eq!(
            admission
                .pending
                .iter()
                .map(|(_, source, event)| (event.event.created_at, *source))
                .collect::<Vec<_>>(),
            vec![
                (10, PendingSource::Window),
                (20, PendingSource::Window),
                (25, PendingSource::Comparison),
                (30, PendingSource::Window),
            ]
        );
    }

    fn endpoint(name: &str) -> cgka_traits::TransportEndpoint {
        cgka_traits::TransportEndpoint(format!("wss://{name}.example"))
    }

    fn compared(
        summary: transport_nostr_adapter::NostrReconciliationSummary,
    ) -> ComparisonRouteWorkResult {
        ComparisonRouteWorkResult::Returned(Ok(Some((summary, Vec::new()))))
    }

    /// A relay that answered its comparison but left claimed IDs for a later
    /// pass is not a relay the window should replace: the comparison is
    /// fetching that backlog oldest first, and a newest page would skip its
    /// unfetched middle (#2086).
    #[test]
    fn a_relay_that_answered_its_comparison_is_not_window_fetched() {
        let relays = [endpoint("silent"), endpoint("partial")];
        let result = compared(transport_nostr_adapter::NostrReconciliationSummary {
            relays_failed: 2,
            failed_endpoints: relays.to_vec(),
            incomplete_endpoints: vec![endpoint("partial")],
            ..Default::default()
        });
        assert_eq!(
            result.uncompared_endpoints(&relays),
            vec![endpoint("silent")]
        );
    }

    /// While a compared relay still owes older history, the pass keeps its
    /// oldest-first boundary: no window fetch jumps past what it has not
    /// fetched yet.
    #[test]
    fn a_known_unfetched_backlog_holds_the_window_fetch() {
        let relays = [endpoint("healthy"), endpoint("silent")];
        for summary in [
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                relays_failed: 1,
                failed_endpoints: vec![endpoint("silent")],
                remote_items: 600,
                received_items: 256,
                ..Default::default()
            },
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_failed: 1,
                failed_endpoints: vec![endpoint("silent")],
                order_unproven: true,
                ..Default::default()
            },
        ] {
            assert!(compared(summary).uncompared_endpoints(&relays).is_empty());
        }
        let caught_up = compared(transport_nostr_adapter::NostrReconciliationSummary {
            relays_succeeded: 1,
            relays_failed: 1,
            failed_endpoints: vec![endpoint("silent")],
            remote_items: 7,
            received_items: 7,
            ..Default::default()
        });
        assert_eq!(
            caught_up.uncompared_endpoints(&relays),
            vec![endpoint("silent")]
        );
    }

    /// Relays send the newest page newest first, so a page the byte budget
    /// or the deadline cut holds only the newer events and leaves the late
    /// commit behind. Only a page the relay itself ended is admitted.
    #[tokio::test]
    async fn a_window_page_the_relay_did_not_finish_is_not_admitted() {
        for end in [
            transport_nostr_adapter::NostrAcquisitionEnd::ByteLimitReached,
            transport_nostr_adapter::NostrAcquisitionEnd::Deadline,
            transport_nostr_adapter::NostrAcquisitionEnd::ItemLimitReached,
        ] {
            let mut fixture = fixture_with_group_relays_and_comparison(None, false).await;
            arm_unpaced_epoch_gap(&fixture);
            let (grant, group_route) = epoch_gap_grant(&mut fixture);
            let newer = candidate_for_route(group_route);
            script_window_ending(&fixture, &newer, end);
            fixture.client.test_comparison_results = Some(group_route_comparison(true));

            fixture
                .client
                .run_recovery_grant_for_test(grant)
                .await
                .unwrap();

            assert_eq!(
                fixture
                    .relay
                    .acquisition_calls
                    .load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert!(
                !fixture
                    .client
                    .transport_receipts()
                    .unwrap()
                    .contains(&newer.event.id),
                "a page cut short ({end:?}) admits nothing"
            );
        }
    }

    #[tokio::test]
    async fn an_epoch_gap_route_every_relay_compared_fetches_no_window() {
        let mut fixture = fixture_with_group_relays_and_comparison(None, false).await;
        arm_unpaced_epoch_gap(&fixture);
        let (grant, group_route) = epoch_gap_grant(&mut fixture);
        script_window(&fixture, &candidate_for_route(group_route));
        fixture.client.test_comparison_results = Some(group_route_comparison(false));

        fixture
            .client
            .run_recovery_grant_for_test(grant)
            .await
            .unwrap();

        assert_eq!(
            fixture
                .relay
                .acquisition_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn a_history_route_a_relay_failed_to_compare_fetches_no_window() {
        let mut fixture = fixture().await;
        let (grant, group_route) = epoch_gap_grant(&mut fixture);
        assert!(
            grant
                .plan()
                .unwrap()
                .iter()
                .all(|obligation| { obligation.cause != storage_sqlite::RecoveryCause::EpochGap }),
            "the fixture owes history, not an epoch gap"
        );
        script_window(&fixture, &candidate_for_route(group_route));
        fixture.client.test_comparison_results = Some(group_route_comparison(true));

        fixture
            .client
            .run_recovery_grant_for_test(grant)
            .await
            .unwrap();

        assert_eq!(
            fixture
                .relay
                .acquisition_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn comparison_pass_records_acquisition_counts_and_verdicts() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let (grant, execution, route, group_route) = group_route_grant(&mut fixture).await;
        let serial = grant.reservation.attempt_serial;
        let obligations = grant.fence.obligations.len();
        fixture
            .client
            .admit_comparison_inline(
                grant,
                execution,
                fetched(
                    route,
                    vec![
                        unreadable_for_route(group_route),
                        candidate_for_route(group_route),
                    ],
                ),
            )
            .await
            .unwrap();
        let app = fixture.client.app.clone();
        let started = recorded_v5_rows(&app, "recovery_attempt_started");
        assert_eq!(started.len(), 1);
        let started = &started[0]["event"];
        assert_eq!(started["attempt_serial"], serial);
        assert_eq!(started["scope"], "history");
        assert_eq!(
            started["route_cap"],
            TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS
        );
        assert_eq!(
            started["admission_per_turn"],
            MAX_COMPARISON_ADMISSION_PER_TURN
        );
        assert_eq!(
            started["quantum_ms"],
            TRANSPORT_RECONCILIATION_QUANTUM.as_millis() as u64
        );

        let finished = recorded_v5_rows(&app, "recovery_attempt_finished");
        assert_eq!(finished.len(), 1);
        let finished = &finished[0]["event"];
        assert_eq!(finished["attempt_serial"], serial);
        assert_eq!(finished["obligation_count"], obligations);
        assert_eq!(finished["events_retrieved"], 2, "both handed-over events");
        assert_eq!(finished["events_rejected"], 1, "the unreadable one");
        assert_eq!(finished["routes_compared"], 1);
        // An unadmitted event withholds the route's certificate.
        assert_eq!(finished["routes_certified"], 0);
        assert_eq!(finished["routes_uncertified"], 1);
        assert!(finished.get("error_kind").is_none());

        let reassessed = recorded_v5_rows(&app, "recovery_obligation_reassessed");
        assert_eq!(reassessed.len(), obligations);
        for row in &reassessed {
            assert_eq!(row["event"]["attempt_serial"], serial);
            assert_eq!(
                row["event"]["record_context"]["operation_ref"],
                finished["record_context"]["operation_ref"]
            );
            assert!(
                row["event"]["scopes_certified"].as_u64() <= row["event"]["scopes_total"].as_u64()
            );
        }
    }

    #[tokio::test]
    async fn a_grant_changed_before_admission_records_a_superseded_pass() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        fixture.client.adapter.require_fresh_activation().await;
        fixture
            .client
            .runtime
            .activate_transport(None)
            .await
            .unwrap();
        let result = fixture
            .client
            .admit_comparison_inline(
                grant,
                attempt,
                fetched(route, vec![candidate(), candidate()]),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        let app = fixture.client.app.clone();
        let finished = recorded_v5_rows(&app, "recovery_attempt_finished");
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0]["event"]["outcome"], "superseded");
        // The relays answered before the grant was found changed: the row
        // reports that, although nothing was admitted or certified.
        assert_eq!(finished[0]["event"]["routes_compared"], 1);
        assert_eq!(finished[0]["event"]["events_retrieved"], 2);
        assert_eq!(finished[0]["event"]["events_retained"], 0);
        assert_eq!(finished[0]["event"]["routes_certified"], 0);
        assert!(
            recorded_v5_rows(&app, "recovery_obligation_reassessed").is_empty(),
            "a pass that settled nothing records no verdicts"
        );
    }

    #[tokio::test]
    async fn an_abandoned_network_pass_records_a_cancelled_pass() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let (grant, execution, _, _) = group_route_grant(&mut fixture).await;
        let result = fixture
            .client
            .abandon_comparison_grant(grant, execution)
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        let app = fixture.client.app.clone();
        let finished = recorded_v5_rows(&app, "recovery_attempt_finished");
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0]["event"]["outcome"], "cancelled");
        assert_eq!(finished[0]["event"]["routes_compared"], 0);
    }

    #[tokio::test]
    async fn a_repair_stopped_by_its_deadline_reports_what_it_fetched_and_retained() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let (grant, execution, route, group_route) = group_route_grant(&mut fixture).await;
        let serial = grant.reservation.attempt_serial;
        let events = (0..MAX_COMPARISON_ADMISSION_PER_TURN + 1)
            .map(|_| candidate_for_route(group_route))
            .collect();
        // The first turn runs inside the budget; the repair's budget is spent
        // before the second, which stops admission at that boundary.
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let cancelled = || {
            if checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                std::thread::sleep(Duration::from_millis(400));
            }
            false
        };
        let control = FullHistoryRepairControl {
            started: Instant::now(),
            timeout: Duration::from_millis(300),
            cancelled: &cancelled,
        };
        fixture
            .client
            .admit_comparison_until(grant, execution, fetched(route, events), Some(&control))
            .await
            .unwrap();
        let app = fixture.client.app.clone();
        let finished = recorded_v5_rows(&app, "recovery_attempt_finished");
        assert_eq!(finished.len(), 1);
        let finished = &finished[0]["event"];
        assert_eq!(finished["attempt_serial"], serial);
        assert_eq!(finished["outcome"], "deadline");
        assert_eq!(
            finished["events_retrieved"],
            MAX_COMPARISON_ADMISSION_PER_TURN + 1,
            "the relays' answer is reported although settlement was skipped"
        );
        assert!(
            finished["events_retained"].as_u64().unwrap() >= 1,
            "the first turn's durable prefix is reported: {finished}"
        );
        assert_eq!(finished["routes_compared"], 1);
        assert_eq!(finished["routes_certified"], 0);
        assert!(
            recorded_v5_rows(&app, "recovery_obligation_reassessed").is_empty(),
            "an unsettled pass writes no verdicts"
        );
    }

    #[tokio::test]
    async fn a_pass_whose_routes_timed_out_is_unserved_not_quiet() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let routes = grant
            .inventory
            .iter()
            .map(|inventory| ComparisonRouteResult {
                route: inventory.route.clone(),
                initial_cursor: None,
                window: Vec::new(),
                cursor: None,
                result: ComparisonRouteWorkResult::TimedOut,
            })
            .collect();
        let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        fixture
            .client
            .admit_comparison_inline(grant, execution, ComparisonNetworkResult { routes })
            .await
            .unwrap();
        let app = fixture.client.app.clone();
        let finished = recorded_v5_rows(&app, "recovery_attempt_finished");
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0]["event"]["outcome"], "unserved");
        assert_eq!(finished[0]["event"]["routes_certified"], 0);
        assert_eq!(finished[0]["event"]["events_retrieved"], 0);
    }

    #[tokio::test]
    async fn deadline_cuts_keep_retrying() {
        let mut fixture = fixture().await;
        for pass in 0..14 {
            let grant = fixture
                .client
                .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
                .unwrap()
                .expect("deadline-cut debt remains selectable");
            let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
            let network = if pass % 2 == 0 {
                let credit = Arc::new(tokio::sync::Semaphore::new(1))
                    .acquire_owned()
                    .await
                    .unwrap();
                let mut job = ComparisonNetworkJob::start(
                    &fixture.client,
                    &grant,
                    credit,
                    tokio::time::Instant::now(),
                    None,
                )
                .unwrap();
                let (_credit, network) = job.wait().await.unwrap();
                network
            } else {
                ComparisonNetworkResult {
                    routes: grant
                        .inventory
                        .iter()
                        .map(|inventory| ComparisonRouteResult {
                            route: inventory.route.clone(),
                            initial_cursor: None,
                            window: Vec::new(),
                            cursor: None,
                            result: ComparisonRouteWorkResult::TimedOut,
                        })
                        .collect(),
                }
            };
            fixture
                .client
                .admit_comparison_inline(grant, execution, network)
                .await
                .unwrap();
            assert!(
                fixture
                    .storage
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .all(|demand| {
                        demand.eligibility == storage_sqlite::RecoveryEligibility::Retry
                    })
            );
            fixture
                .client
                .recovery_owner
                .test_advance_to_retry(&fixture.storage);
        }
    }

    #[tokio::test]
    async fn a_comparison_only_pass_without_a_backend_is_unserved_not_quiet() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = fixture_with_options(None, false, true).await;
        // Settle the create-group history demand, as the epoch-gap fixture
        // does, so the next grant owns only the comparison slot.
        let baseline = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        fixture
            .client
            .run_recovery_grant_for_test(baseline)
            .await
            .unwrap();
        fixture.client.request_bounded_comparison().unwrap();
        fixture
            .client
            .recovery_owner
            .test_advance_to_retry(&fixture.storage);
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .expect("the comparison slot is selected");
        assert!(
            grant.fence.obligations.is_empty(),
            "a comparison-only grant"
        );
        assert!(grant.comparison_revision.is_some());
        let serial = grant.reservation.attempt_serial;
        let routes = grant
            .inventory
            .iter()
            .map(|inventory| ComparisonRouteResult {
                route: inventory.route.clone(),
                initial_cursor: None,
                window: Vec::new(),
                cursor: None,
                // No comparison backend: no relay comparison ran.
                result: ComparisonRouteWorkResult::Returned(Ok(None)),
            })
            .collect();
        let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        fixture
            .client
            .admit_comparison_inline(grant, execution, ComparisonNetworkResult { routes })
            .await
            .unwrap();
        let finished = recorded_v5_rows(&fixture.client.app.clone(), "recovery_attempt_finished")
            .into_iter()
            .find(|row| row["event"]["attempt_serial"] == serial)
            .expect("the comparison-only pass finished");
        assert_eq!(finished["event"]["obligation_count"], 0);
        assert_eq!(finished["event"]["outcome"], "unserved");
        assert_eq!(finished["event"]["routes_certified"], 0);
    }

    #[tokio::test]
    async fn an_obligation_compared_without_a_backend_is_unserved_and_spends_no_budget() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let serial = grant.reservation.attempt_serial;
        let routes = grant
            .inventory
            .iter()
            .map(|inventory| ComparisonRouteResult {
                route: inventory.route.clone(),
                initial_cursor: None,
                window: Vec::new(),
                cursor: None,
                // No comparison backend: no relay comparison ran.
                result: ComparisonRouteWorkResult::Returned(Ok(None)),
            })
            .collect();
        let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        fixture
            .client
            .admit_comparison_inline(grant, execution, ComparisonNetworkResult { routes })
            .await
            .unwrap();
        let app = fixture.client.app.clone();
        let incremental = recorded_v5_rows(&app, "recovery_obligation_reassessed")
            .into_iter()
            .find(|row| {
                row["event"]["attempt_serial"] == serial
                    && row["event"]["cause"] == "incremental_history"
            })
            .expect("the startup history obligation is reassessed");
        // Storage waits for a capability change, and a pass no relay
        // answered spends none of the parking budget.
        assert_eq!(incremental["event"]["verdict"], "waiting_capability");
        assert_eq!(incremental["event"]["progress"], "unserved");
        assert_eq!(
            incremental["event"]["quiet_passes"], 0,
            "no quiet pass was counted for an uncompared scope"
        );
        let finished = recorded_v5_rows(&app, "recovery_attempt_finished")
            .into_iter()
            .find(|row| row["event"]["attempt_serial"] == serial)
            .unwrap();
        assert_eq!(finished["event"]["outcome"], "unserved");
    }
    /// A real admission repairs retained projection work before a later grant
    /// failure. Both the worker and inline checkpoint must deliver that prefix.
    #[tokio::test]
    async fn failed_comparison_retains_repaired_admission_prefix() {
        for checkpoint in [false, true] {
            let mut fixture = fixture().await;
            let app = fixture.client.app.clone();
            let connection =
                super::super::runtime_group_subscription_refresh_tests::projection_fault_connection(
                    &app,
                );
            connection.execute_batch("CREATE TRIGGER fail_repaired_activity BEFORE INSERT ON app_events WHEN NEW.kind = 1210 BEGIN SELECT RAISE(FAIL, 'injected activity'); END;").unwrap();
            let effects = marmot_account::AccountDeviceEffects {
                events: vec![cgka_traits::engine::GroupEvent::GroupStateChanged {
                    group_id: fixture.group_id.clone(),
                    epoch: cgka_traits::EpochId(1),
                    actor: Some(fixture.client.runtime.session().self_id()),
                    change: cgka_traits::engine::GroupStateChange::GroupRenamed {
                        name: "admitted repair".into(),
                        previous_name: None,
                    },
                    origin_commit_id: None,
                }],
                ..Default::default()
            };
            assert!(
                fixture
                    .client
                    .observe_drained_session_events(&effects)
                    .await
                    .is_err()
            );
            connection
                .execute_batch("DROP TRIGGER fail_repaired_activity")
                .unwrap();
            let (grant, mut execution, route, group_route) = group_route_grant(&mut fixture).await;
            let candidates = (0..MAX_COMPARISON_ADMISSION_PER_TURN + 1)
                .map(|_| candidate_for_route(group_route))
                .collect();
            let mut admission = fixture
                .client
                .accept_comparison_network(&grant, &mut execution, fetched(route, candidates))
                .await
                .unwrap()
                .unwrap();
            assert!(
                !fixture
                    .client
                    .admit_comparison_turn(&grant, &mut execution, &mut admission)
                    .await
                    .unwrap()
            );
            assert_eq!(admission.summary.projection_updates.len(), 1);
            if checkpoint {
                fixture
                    .client
                    .admit_comparison_turn(&grant, &mut execution, &mut admission)
                    .await
                    .unwrap();
                // Unreadable candidates may withhold route admission. The
                // admitted cursor is the checkpoint whose write we fail here.
                admission.routes[0].admitted = true;
                connection.execute_batch("CREATE TRIGGER fail_repair_cursor BEFORE UPDATE OF replay_after ON transport_reconciliation_route_state BEGIN SELECT RAISE(FAIL, 'injected cursor'); END;").unwrap();
                assert!(
                    fixture
                        .client
                        .finish_comparison_grant(grant, execution, Some(admission))
                        .await
                        .is_err()
                );
            } else {
                fixture.client.released_backfill_reload_pending = true;
                fixture.client.fail_next_released_backfill_reload = true;
                let error = fixture
                    .client
                    .admit_comparison_turn(&grant, &mut execution, &mut admission)
                    .await
                    .unwrap_err();
                fixture
                    .client
                    .fail_comparison_grant(grant, execution, Some(&mut admission), error);
                assert!(admission.summary.projection_updates.is_empty());
            }
            assert_eq!(
                std::mem::take(&mut fixture.client.pending_failed_sync_summary)
                    .projection_updates
                    .len(),
                1
            );
            assert!(
                std::mem::take(&mut fixture.client.pending_failed_sync_summary)
                    .projection_updates
                    .is_empty()
            );
        }
    }
}
