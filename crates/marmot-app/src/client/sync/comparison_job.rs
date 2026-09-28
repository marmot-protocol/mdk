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

/// The bounded off-worker shape. A larger route retains the existing inline
/// executor with its complete endpoint set.
pub(crate) const MAX_COMPARISON_ENDPOINTS_PER_ROUTE: usize = 4;

/// Owned events one worker turn admits before commands and live input run.
pub(crate) const MAX_COMPARISON_ADMISSION_PER_TURN: usize = 4;

/// What the worker keeps while a comparison runs off the worker: the live
/// subscription attempt admission must still own, and the inline executor's
/// execution bracket (loss attempt and audit rows). The bracket is boxed so
/// worker enums that park a pass stay small.
pub(crate) struct ComparisonExecution {
    attempt: Option<SubscriptionAttempt>,
    execution: Box<RecoveryExecutionState>,
}

/// A finished network pass the worker is admitting.
#[derive(Default)]
pub(crate) struct ComparisonAdmission {
    routes: Vec<AdmissionRoute>,
    pending: VecDeque<(usize, transport_nostr_adapter::NostrRelayEvent)>,
    summary: SyncSummary,
    /// The grant changed mid-admission. The admitted prefix stays durable,
    /// but the pass certifies nothing.
    invalid: bool,
}

struct AdmissionRoute {
    route: TransportReconciliationRoute,
    initial_cursor: Option<[u8; 32]>,
    cursor: Option<[u8; 32]>,
    outcome: Outcome,
    /// Every endpoint finished an untruncated comparison.
    certified: bool,
    /// Every event this route fetched was durably admitted.
    admitted: bool,
    /// Events durably admitted: progress, even without a certificate.
    fetched: usize,
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
}

pub(crate) struct ComparisonNetworkResult {
    routes: Vec<ComparisonRouteResult>,
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

impl ComparisonNetworkJob {
    /// Cancel the request and wait until its future has dropped the shared credit.
    pub(crate) async fn abort_and_wait(mut self) {
        self.handle.abort();
        let _ = (&mut self.handle).await;
    }

    pub(crate) fn start(
        client: &AppClient,
        grant: &AttemptGrant,
        credit: OwnedSemaphorePermit,
        #[cfg(test)] witness: Option<TestComparisonActivityWitness>,
    ) -> Result<Self, AppError> {
        let storage = client.app.account_storage(&client.state.label)?;
        let routes = grant
            .inventory
            .iter()
            .map(|inventory| {
                Ok(FrozenRoute {
                    inventory: inventory.clone(),
                    initial_cursor: storage
                        .transport_reconciliation_replay_cursor(&inventory.route)?,
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let adapter = client.adapter.clone();
        #[cfg(test)]
        let attempt_serial = grant.reservation.attempt_serial;
        let handle = tokio::spawn(async move {
            #[cfg(test)]
            let _job_active = witness.as_ref().map(|witness| {
                witness
                    .attempt_serial
                    .store(attempt_serial, Ordering::SeqCst);
                ActiveCounter::new(witness.active_jobs.clone())
            });
            let deadline = tokio::time::Instant::now() + TRANSPORT_RECONCILIATION_QUANTUM;
            let mut results = Vec::with_capacity(routes.len());
            for frozen in routes {
                let FrozenRoute {
                    inventory,
                    initial_cursor,
                } = frozen;
                if tokio::time::Instant::now() >= deadline {
                    results.push(ComparisonRouteResult {
                        route: inventory.route,
                        initial_cursor,
                        cursor: initial_cursor,
                        result: ComparisonRouteWorkResult::Skipped,
                    });
                    continue;
                }
                let progress = Arc::new(MemoryProgress {
                    cursor: Mutex::new(initial_cursor),
                });
                let run = async {
                    #[cfg(test)]
                    let _request_active = witness
                        .as_ref()
                        .map(|witness| ActiveCounter::new(witness.active_requests.clone()));
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
                let cursor = *progress.cursor.lock().expect("comparison progress mutex");
                results.push(ComparisonRouteResult {
                    route: inventory.route,
                    initial_cursor,
                    cursor,
                    result,
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

impl AppClient {
    /// An advisory preflight used only when the shared credit pool is empty:
    /// every pending cause is one the off-worker job serves, so the owner
    /// waits for a credit instead of running it inline. The frozen grant is
    /// checked again after authorization when a credit exists.
    pub(crate) fn comparison_only_waiting_for_credit(&self) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let demands = storage.pending_recovery_demands()?;
        if demands.is_empty() && !storage.recovery_comparison()?.pending() {
            return Ok(false);
        }
        let routes = self.routing.snapshot();
        Ok(demands.iter().all(|demand| offloaded_cause(demand.cause))
            && routes.local_inbox_endpoints.len() <= MAX_COMPARISON_ENDPOINTS_PER_ROUTE
            && routes
                .group_routes
                .iter()
                .all(|route| route.endpoints.len() <= MAX_COMPARISON_ENDPOINTS_PER_ROUTE))
    }

    /// Every automatic grant runs its network wait off the worker, except
    /// maintenance boundaries, explicit repair and known-event demand, which
    /// keep their own executors. Per-pass route and endpoint caps still apply.
    /// The frozen grant is the authority; an earlier pending-demand probe
    /// never decides this.
    pub(crate) fn comparison_offload_eligible(
        &self,
        grant: &AttemptGrant,
    ) -> Result<bool, AppError> {
        let Some(plan) = grant.plan() else {
            return Ok(false);
        };
        let within_cap = |required: usize, admitted: usize| {
            required <= MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                && admitted <= MAX_COMPARISON_ENDPOINTS_PER_ROUTE
        };
        Ok(plan.iter().all(|obligation| {
            offloaded_cause(obligation.cause)
                && obligation.scopes.iter().all(|scope| {
                    within_cap(
                        scope.goal.required_endpoints.len(),
                        scope.goal.admitted_endpoints.len(),
                    )
                })
        }) && grant.inventory.len() <= TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS
            && grant.inventory.iter().all(|route| match &route.work {
                TransportReconciliationWork::Inbox(endpoints) => {
                    endpoints.len() <= MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                }
                TransportReconciliationWork::Group(group) => {
                    group.endpoints.len() <= MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                }
            })
            && grant.comparison_plan.as_ref().is_none_or(|plan| {
                plan.routes.len() <= TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS
                    && plan.routes.iter().all(|route| {
                        within_cap(
                            route.required_endpoints.len(),
                            route.admitted_endpoints.len(),
                        )
                    })
            }))
    }

    /// Open the inline executor's execution bracket for an off-worker pass. A
    /// steady-state pass never touches live subscriptions: it reuses the live
    /// tail, so it re-downloads no history the account already holds.
    pub(crate) async fn begin_comparison_grant(
        &mut self,
        grant: &AttemptGrant,
    ) -> Result<ComparisonExecution, AppError> {
        let mut execution = self
            .begin_recovery_execution(grant)
            .map_err(|failure| failure.source)?;
        execution.activation = marmot_forensics::EpochBackfillActivationOutcome::Succeeded;
        Ok(ComparisonExecution {
            attempt: self.adapter.account_subscription_attempt().await,
            execution: Box::new(execution),
        })
    }

    /// Startup's grant carries the session's first live subscriptions, floored
    /// at the cursor, so it activates before its network wait.
    pub(crate) async fn activate_startup_comparison_grant(
        &mut self,
        grant: &AttemptGrant,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<ComparisonExecution, AppError> {
        let mut execution = self
            .begin_recovery_execution(grant)
            .map_err(|failure| failure.source)?;
        let attempt = match self
            .activate_recovery_grant_inner(grant, telemetry, &mut execution.activation)
            .await
        {
            Ok(()) => self
                .adapter
                .account_subscription_attempt()
                .await
                .ok_or_else(|| {
                    comparison_failure(
                        cgka_traits::TransportAdapterError::Subscription(
                            "activated comparison subscription disappeared".into(),
                        )
                        .into(),
                    )
                }),
            Err(failure) => Err(failure),
        };
        match attempt {
            Ok(attempt) => Ok(ComparisonExecution {
                attempt: Some(attempt),
                execution: Box::new(execution),
            }),
            Err(failure) => {
                match self.finish_recovery_execution(grant, execution, Err(failure), false) {
                    Ok(_) => unreachable!("a failed activation cannot complete"),
                    Err(failure) => Err(failure.source),
                }
            }
        }
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
        storage.synchronize_account_delivery_loss(&self.state.label)?;
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
        execution: &ComparisonExecution,
        network: ComparisonNetworkResult,
    ) -> Result<Option<ComparisonAdmission>, AppError> {
        if !self.comparison_grant_stable(grant, execution, true).await? {
            return Ok(None);
        }
        let mut admission = ComparisonAdmission::default();
        for (index, route) in network.routes.into_iter().enumerate() {
            let inventory = grant
                .inventory
                .iter()
                .find(|inventory| inventory.route == route.route);
            let (outcome, certified, events) = match route.result {
                ComparisonRouteWorkResult::Skipped => (Outcome::ServicedPartial, false, Vec::new()),
                ComparisonRouteWorkResult::TimedOut
                | ComparisonRouteWorkResult::Returned(Err(_)) => {
                    (Outcome::TransientFailure, false, Vec::new())
                }
                ComparisonRouteWorkResult::Returned(Ok(None)) => {
                    (Outcome::Unsupported, false, Vec::new())
                }
                ComparisonRouteWorkResult::Returned(Ok(Some((summary, events)))) => {
                    let (outcome, certified) = inventory
                        .map_or((Outcome::TransientFailure, false), |inventory| {
                            inventory.judge(&summary)
                        });
                    (outcome, certified, events)
                }
            };
            admission
                .pending
                .extend(events.into_iter().map(|event| (index, event)));
            admission.routes.push(AdmissionRoute {
                route: route.route,
                initial_cursor: route.initial_cursor,
                cursor: route.cursor,
                outcome,
                certified,
                admitted: true,
                fetched: 0,
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
        for _ in 0..MAX_COMPARISON_ADMISSION_PER_TURN {
            let Some((index, event)) = admission.pending.pop_front() else {
                break;
            };
            let route = &mut admission.routes[index];
            let deliveries = self.adapter.recovered_deliveries(event).await?;
            // An event that no longer routes to this account was not admitted.
            route.admitted &= !deliveries.is_empty();
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
                        counts.deliveries = counts.deliveries.saturating_add(1);
                        if unpersisted {
                            counts.unpersisted = counts.unpersisted.saturating_add(1);
                            route.admitted = false;
                        } else {
                            route.fetched = route.fetched.saturating_add(1);
                        }
                        if let Some(group) = refused_group {
                            counts.refused = counts.refused.saturating_add(1);
                            counts.refused_groups.insert(group);
                        }
                    }
                }
            }
        }
        Ok(admission.pending.is_empty())
    }

    /// Admit a finished pass in bounded turns, yielding between them, then
    /// settle it. Startup uses this while its mutations are still deferred;
    /// the steady-state worker runs one turn per loop instead.
    pub(crate) async fn admit_comparison_inline(
        &mut self,
        grant: AttemptGrant,
        mut execution: ComparisonExecution,
        network: ComparisonNetworkResult,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let mut admission = match self
            .accept_comparison_network(&grant, &execution, network)
            .await
        {
            Ok(admission) => admission,
            Err(error) => return Err(self.fail_comparison_grant(grant, execution, error)),
        };
        if let Some(admission) = admission.as_mut() {
            loop {
                match self
                    .admit_comparison_turn(&grant, &mut execution, admission)
                    .await
                {
                    Ok(true) => break,
                    Ok(false) => tokio::task::yield_now().await,
                    Err(error) => return Err(self.fail_comparison_grant(grant, execution, error)),
                }
            }
        }
        self.finish_comparison_grant(grant, execution, admission)
            .await
    }

    /// Settle the execution bracket after admission: checkpoints, loss
    /// acknowledgment and audit rows, as the inline executor does.
    pub(crate) async fn finish_comparison_grant(
        &mut self,
        grant: AttemptGrant,
        execution: ComparisonExecution,
        admission: Option<ComparisonAdmission>,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let mut execution = *execution.execution;
        let settled = match admission {
            // The grant changed before admission; nothing was admitted.
            None => Ok(None),
            // A change during admission keeps the durable prefix but certifies
            // nothing; the debt waits for a later grant.
            Some(admission) if admission.invalid => Ok(Some(admission.summary)),
            Some(admission) => self
                .checkpoint_comparison_admission(&grant, &mut execution, admission)
                .await
                .map(Some),
        };
        let deferred = matches!(settled, Ok(None));
        let summary = self
            .finish_recovery_execution(
                &grant,
                execution,
                settled.map(Option::unwrap_or_default),
                false,
            )
            .map_err(|failure| {
                self.pending_failed_sync_summary
                    .merge(failure.partial_summary);
                failure.source
            })?;
        Ok(if deferred {
            EpochBackfillRunOutcome::Deferred
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
        self.finish_recovery_execution(
            &grant,
            *execution.execution,
            Ok(SyncSummary::default()),
            false,
        )
        .map_err(|failure| failure.source)?;
        Ok(EpochBackfillRunOutcome::Deferred)
    }

    /// Admission failed. Settle the bracket as a failed attempt; the durable
    /// prefix stays and the debt waits for a later grant.
    pub(crate) fn fail_comparison_grant(
        &mut self,
        grant: AttemptGrant,
        execution: ComparisonExecution,
        error: AppError,
    ) -> AppError {
        match self.finish_recovery_execution(
            &grant,
            *execution.execution,
            Err(comparison_failure(error)),
            false,
        ) {
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
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(comparison_failure)?;
        let mut outcomes = Vec::with_capacity(admission.routes.len());
        for route in admission.routes {
            // A route whose batch was not fully admitted keeps its old cursor,
            // so the next pass fetches the unadmitted suffix again.
            if route.admitted && route.cursor != route.initial_cursor {
                storage
                    .advance_transport_reconciliation_replay_cursor(&route.route, route.cursor)
                    .map_err(|error| comparison_failure(error.into()))?;
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
            });
        }
        self.finish_recovery_grant_after_drain(
            grant,
            &mut execution.counts,
            &mut execution.drain_verdict,
            outcomes,
            admission.summary,
            DrainVerdict::Complete,
        )
        .await
    }
}

/// Every automatic cause except maintenance boundaries, explicit repair and
/// known-event demand, which keep their own executors.
fn offloaded_cause(cause: storage_sqlite::RecoveryCause) -> bool {
    !matches!(
        cause,
        storage_sqlite::RecoveryCause::Maintenance
            | storage_sqlite::RecoveryCause::ExplicitHistory
            | storage_sqlite::RecoveryCause::KnownEvent
    )
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
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let pump = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
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
            .execute_pending_epoch_backfill_grant(baseline)
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
    async fn zero_credit_defers_an_offloadable_epoch_gap_but_not_an_over_cap_route() {
        let mut eligible = fixture_with_group_relays_and_comparison(None, false).await;
        arm_test_epoch_gap(&mut eligible).await;
        let serial = eligible
            .storage
            .recovery_retry_state()
            .unwrap()
            .attempt_serial;
        assert!(
            eligible
                .client
                .comparison_only_waiting_for_credit()
                .unwrap()
        );
        assert_eq!(
            eligible
                .storage
                .recovery_retry_state()
                .unwrap()
                .attempt_serial,
            serial,
            "the preflight spends no reservation"
        );

        let relays = (0..5)
            .map(|index| format!("wss://relay-{index}.example"))
            .collect();
        let mut over_cap = fixture_with_group_relays_and_comparison(Some(relays), false).await;
        arm_test_epoch_gap(&mut over_cap).await;
        assert!(
            !over_cap
                .client
                .comparison_only_waiting_for_credit()
                .unwrap()
        );
    }

    fn network_result(
        route: TransportReconciliationRoute,
        cursor: Option<[u8; 32]>,
    ) -> ComparisonNetworkResult {
        ComparisonNetworkResult {
            routes: vec![ComparisonRouteResult {
                route,
                initial_cursor: None,
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
    async fn comparison_more_than_four_endpoints_keeps_inline_grant() {
        let relays = (0..5)
            .map(|index| format!("wss://relay-{index}.example"))
            .collect();
        let mut fixture = fixture_with_group_relays(Some(relays)).await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        assert!(grant.inventory.iter().any(|route| match &route.work {
            TransportReconciliationWork::Group(group) => group.endpoints.len() == 5,
            TransportReconciliationWork::Inbox(_) => false,
        }));
        assert!(!fixture.client.comparison_offload_eligible(&grant).unwrap());
        let serial = grant.reservation.attempt_serial;
        fixture
            .client
            .execute_pending_epoch_backfill_grant(grant)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .storage
                .recovery_retry_state()
                .unwrap()
                .attempt_serial,
            serial,
            "inline fallback executes the selected grant without a second authorization"
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
        assert!(fixture.client.comparison_offload_eligible(&grant).unwrap());
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
        assert!(fixture.client.comparison_offload_eligible(&grant).unwrap());
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
            .accept_comparison_network(&grant, &execution, fetched(route, events))
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

    #[tokio::test]
    async fn comparison_change_between_turns_keeps_the_prefix_and_certifies_nothing() {
        let mut fixture = fixture().await;
        let (grant, mut execution, route, group_route) = group_route_grant(&mut fixture).await;
        let events = (0..MAX_COMPARISON_ADMISSION_PER_TURN + 1)
            .map(|_| candidate_for_route(group_route))
            .collect();
        let mut admission = fixture
            .client
            .accept_comparison_network(&grant, &execution, fetched(route.clone(), events))
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
        assert!(fixture.storage.recovery_comparison().unwrap().pending());
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
}
