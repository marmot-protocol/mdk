//! Immutable comparison I/O for a worker-owned recovery grant. The task has no
//! account storage, engine, session, or event-queue authority.

use super::*;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;
use transport_nostr_adapter::{NostrReconciliationProgress, SubscriptionAttempt};

/// The bounded off-worker shape. A larger route retains the existing inline
/// executor with its complete endpoint set.
pub(crate) const MAX_COMPARISON_ENDPOINTS_PER_ROUTE: usize = 4;

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct TestComparisonActivityWitness {
    pub(crate) attempt_serial: Arc<AtomicU64>,
    pub(crate) active_jobs: Arc<AtomicUsize>,
    pub(crate) active_requests: Arc<AtomicUsize>,
    pub(crate) target_event_id: Arc<Mutex<Option<String>>>,
    pub(crate) returned_events: Arc<AtomicUsize>,
    pub(crate) matching_events: Arc<AtomicUsize>,
    pub(crate) matching_queued_deliveries: Arc<AtomicUsize>,
    pub(crate) panic_after_queue_submission: Arc<std::sync::atomic::AtomicBool>,
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

pub(crate) struct RouteSubmission {
    route: TransportReconciliationRoute,
    initial_cursor: Option<[u8; 32]>,
    cursor: Option<[u8; 32]>,
    cursor_safe: bool,
    outcome: storage_sqlite::RecoveryComparisonOutcome,
    #[cfg(test)]
    attempted: usize,
    #[cfg(test)]
    delivered: usize,
}

#[cfg(test)]
impl RouteSubmission {
    pub(crate) fn delivery_counts_for_test(&self) -> (usize, usize) {
        (self.attempted, self.delivered)
    }
}

/// The queue producer owns no account engine or storage. The worker can drain
/// the same adapter queue while this bounded producer waits for capacity.
pub(crate) struct EpochGapQueueJob {
    credit: Option<Arc<OwnedSemaphorePermit>>,
    handle: JoinHandle<Vec<RouteSubmission>>,
}

impl Drop for EpochGapQueueJob {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl EpochGapQueueJob {
    pub(crate) fn start(
        client: &AppClient,
        network: ComparisonNetworkResult,
        credit: OwnedSemaphorePermit,
        #[cfg(test)] witness: Option<TestComparisonActivityWitness>,
    ) -> Self {
        let adapter = client.adapter.clone();
        let credit = Arc::new(credit);
        let task_credit = credit.clone();
        let handle = tokio::spawn(async move {
            let _credit = task_credit;
            let deadline = tokio::time::Instant::now() + TRANSPORT_RECONCILIATION_QUANTUM;
            let mut submitted = Vec::with_capacity(network.routes.len());
            for route in network.routes {
                submitted.push(
                    submit_reconciliation_route(
                        &adapter,
                        route,
                        deadline,
                        #[cfg(test)]
                        witness.as_ref(),
                    )
                    .await,
                );
            }
            #[cfg(test)]
            if witness
                .as_ref()
                .is_some_and(|witness| witness.panic_after_queue_submission.load(Ordering::SeqCst))
            {
                panic!("injected online recovery queue panic after submission");
            }
            submitted
        });
        Self {
            credit: Some(credit),
            handle,
        }
    }

    pub(crate) async fn wait(&mut self) -> Result<Vec<RouteSubmission>, tokio::task::JoinError> {
        (&mut self.handle).await
    }

    pub(crate) async fn abort_and_wait(mut self) -> Arc<OwnedSemaphorePermit> {
        self.handle.abort();
        let _ = (&mut self.handle).await;
        self.credit.take().expect("queue job owns credit")
    }

    pub(crate) fn into_credit(mut self) -> Arc<OwnedSemaphorePermit> {
        self.credit.take().expect("queue job owns credit")
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
    /// Capacity preflight before the owner spends a retry reservation. This is
    /// deliberately narrower than the post-selection grant check below.
    pub(crate) fn epoch_gap_only_waiting_for_credit(&self) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let fence = storage.recovery_eligible_revision_fence(false)?;
        if fence.obligations.len() != 1
            || storage.recovery_comparison()?.pending()
            || self.delivery_loss_blocks_cursor()
            || !storage
                .recovery_loss_snapshot(
                    &self.state.label,
                    storage_sqlite::RecoveryLossCause::Queue,
                )?
                .is_empty()
            || !storage
                .recovery_loss_snapshot(
                    &self.state.label,
                    storage_sqlite::RecoveryLossCause::NotificationConsumer,
                )?
                .is_empty()
        {
            return Ok(false);
        }
        // A zero-credit preflight may defer a grant only when its visible
        // routing shape fits the off-worker cap. Otherwise preserve the
        // inline executor even while another account holds both credits.
        let routes = self.routing.snapshot();
        let visible_routes =
            routes.group_routes.len() + usize::from(!routes.local_inbox_endpoints.is_empty());
        if visible_routes == 0
            || visible_routes > TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS
            || routes.local_inbox_endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
            || routes
                .group_routes
                .iter()
                .any(|route| route.endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE)
        {
            return Ok(false);
        }
        let selected = fence.obligations[0];
        if storage
            .recovery_scope_snapshots(selected.0)?
            .iter()
            .any(|scope| {
                scope.plan.required_endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                    || scope.plan.admitted_endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
            })
        {
            return Ok(false);
        }
        Ok(storage.pending_recovery_demands()?.iter().any(|demand| {
            demand.ticket.id == selected.0
                && demand.ticket.revision == selected.1
                && demand.cause == storage_sqlite::RecoveryCause::EpochGap
        }))
    }

    /// The one steady-state expansion of immutable comparison I/O. The
    /// comparison slot remains ineligible and its completion path is unused.
    pub(crate) fn epoch_gap_offload_eligible(
        &self,
        grant: &AttemptGrant,
    ) -> Result<bool, AppError> {
        let Some(plan) = grant.plan() else {
            return Ok(false);
        };
        if grant.seam != marmot_forensics::EpochBackfillExecutionSeam::Receive
            || grant.comparison_revision.is_some()
            || plan.len() != 1
            || plan[0].cause != storage_sqlite::RecoveryCause::EpochGap
            || grant.fence.obligations.len() != 1
            || grant.fence.obligations[0].0 != plan[0].id
            || self.delivery_loss_blocks_cursor()
            || grant.inventory.is_empty()
            || grant.inventory.len() > TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS
            || plan[0].scopes.iter().any(|scope| {
                scope.goal.admitted_endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                    || scope.goal.required_endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
            })
            || grant.inventory.iter().any(|route| match &route.work {
                TransportReconciliationWork::Inbox(endpoints) => {
                    endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                }
                TransportReconciliationWork::Group(group) => {
                    group.endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                }
            })
        {
            return Ok(false);
        }
        let storage = self.app.account_storage(&self.state.label)?;
        Ok(storage.pending_recovery_demands()?.iter().any(|demand| {
            demand.ticket.id == grant.fence.obligations[0].0
                && demand.ticket.revision == grant.fence.obligations[0].1
                && demand.cause == storage_sqlite::RecoveryCause::EpochGap
        }))
    }

    /// An advisory preflight used only when the shared credit pool is empty.
    /// Independent debt still reaches the legacy executor. The actual frozen
    /// grant is checked again after authorization when a credit exists.
    pub(crate) fn comparison_only_waiting_for_credit(&self) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        if !storage.recovery_comparison()?.pending()
            || storage
                .pending_recovery_demands()?
                .iter()
                .any(|demand| demand.cause != storage_sqlite::RecoveryCause::IncrementalHistory)
            || !storage
                .recovery_loss_snapshot(
                    &self.state.label,
                    storage_sqlite::RecoveryLossCause::Queue,
                )?
                .is_empty()
            || !storage
                .recovery_loss_snapshot(
                    &self.state.label,
                    storage_sqlite::RecoveryLossCause::NotificationConsumer,
                )?
                .is_empty()
        {
            return Ok(false);
        }
        let routes = self.routing.snapshot();
        Ok(
            routes.local_inbox_endpoints.len() <= MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                && routes
                    .group_routes
                    .iter()
                    .all(|route| route.endpoints.len() <= MAX_COMPARISON_ENDPOINTS_PER_ROUTE),
        )
    }

    /// The sole eligible automatic selection is the comparison and, when
    /// present, its own IncrementalHistory obligation. The frozen grant is the
    /// authority; an earlier pending-demand probe never decides this.
    pub(crate) fn comparison_offload_eligible(
        &self,
        grant: &AttemptGrant,
    ) -> Result<bool, AppError> {
        if grant.comparison_revision.is_none()
            || grant.inventory.len() > TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS
            || grant.comparison_plan.as_ref().is_none_or(|plan| {
                plan.routes.len() > TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS
                    || plan.routes.iter().any(|route| {
                        route.admitted_endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                            || route.required_endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                    })
            })
            || grant.inventory.iter().any(|route| match &route.work {
                TransportReconciliationWork::Inbox(endpoints) => {
                    endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                }
                TransportReconciliationWork::Group(group) => {
                    group.endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                }
            })
        {
            return Ok(false);
        }
        let Some(plan) = grant.plan() else {
            return Ok(false);
        };
        if plan.len() > 1
            || plan.iter().any(|item| {
                item.cause != storage_sqlite::RecoveryCause::IncrementalHistory
                    || item.scopes.iter().any(|scope| {
                        scope.goal.admitted_endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                            || scope.goal.required_endpoints.len()
                                > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                    })
            })
        {
            return Ok(false);
        }
        let selected = plan.iter().map(|item| item.id).collect::<Vec<_>>();
        if selected.len() != grant.fence.obligations.len()
            || !selected.iter().all(|id| {
                grant
                    .fence
                    .obligations
                    .iter()
                    .any(|(candidate, _)| candidate == id)
            })
        {
            return Ok(false);
        }
        let storage = self.app.account_storage(&self.state.label)?;
        let pending = storage.pending_recovery_demands()?;
        Ok(grant.fence.obligations.iter().all(|(id, revision)| {
            pending.iter().any(|demand| {
                demand.ticket.id == *id
                    && demand.ticket.revision == *revision
                    && demand.cause == storage_sqlite::RecoveryCause::IncrementalHistory
            })
        }))
    }

    pub(crate) async fn activate_comparison_grant(
        &mut self,
        grant: &AttemptGrant,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<SubscriptionAttempt, AppError> {
        let mut activation = EpochBackfillActivationOutcome::Failed;
        self.activate_recovery_grant_inner(grant, telemetry, &mut activation)
            .await
            .map_err(|failure| failure.source)?;
        self.adapter
            .account_subscription_attempt()
            .await
            .ok_or_else(|| {
                cgka_traits::TransportAdapterError::Subscription(
                    "activated comparison subscription disappeared".into(),
                )
                .into()
            })
    }

    pub(crate) async fn finish_comparison_grant(
        &mut self,
        grant: AttemptGrant,
        attempt: SubscriptionAttempt,
        network: ComparisonNetworkResult,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        storage.synchronize_account_delivery_loss(&self.state.label)?;
        drop(self.transport_receipts()?);
        self.observe_recovery_route_policy()?;
        let current = storage.recovery_revision_fence()?;
        let slot = storage.recovery_comparison()?;
        let stable = current.loss_revision == grant.fence.loss_revision
            && current.route_revision == grant.fence.route_revision
            && current.inventory_revision == grant.fence.inventory_revision
            && grant
                .fence
                .obligations
                .iter()
                .all(|selected| current.obligations.contains(selected))
            && slot.pending()
            && Some(slot.revision) == grant.comparison_revision
            && slot.attempt_serial == grant.reservation.attempt_serial
            && slot.frozen_revision == slot.revision
            && self.adapter.account_subscription_attempt().await == Some(attempt);
        if !stable {
            // The network task never wrote to SQLCipher or the delivery queue.
            // A changed grant or activation discards every proposed byte and
            // leaves durable comparison and coverage debt for the next owner.
            return Ok(EpochBackfillRunOutcome::Deferred);
        }
        // Acquisition may have consumed its entire quantum before the worker
        // joins. Give delivery of the already owned batch a separate bounded
        // admission window.
        let admission_deadline = tokio::time::Instant::now() + TRANSPORT_RECONCILIATION_QUANTUM;
        let mut outcomes = Vec::with_capacity(network.routes.len());
        for route in network.routes {
            outcomes.push(
                self.admit_comparison_route(&storage, route, admission_deadline)
                    .await?,
            );
        }
        let mut counts = DrainCounts::default();
        let mut verdict = None;
        let summary = self
            .complete_recovery_grant_inner(&grant, None, &mut counts, &mut verdict, outcomes)
            .await
            .map_err(|failure| {
                self.pending_failed_sync_summary
                    .merge(failure.partial_summary);
                failure.source
            })?;
        Ok(EpochBackfillRunOutcome::Incomplete(summary))
    }

    async fn admit_comparison_route(
        &self,
        storage: &storage_sqlite::SqliteAccountStorage,
        route: ComparisonRouteResult,
        admission_deadline: tokio::time::Instant,
    ) -> Result<
        (
            TransportReconciliationRoute,
            storage_sqlite::RecoveryComparisonOutcome,
        ),
        AppError,
    > {
        let submission = submit_reconciliation_route(
            &self.adapter,
            route,
            admission_deadline,
            #[cfg(test)]
            None,
        )
        .await;
        self.persist_reconciliation_submission(storage, submission)
    }

    pub(crate) fn persist_reconciliation_submission(
        &self,
        storage: &storage_sqlite::SqliteAccountStorage,
        submission: RouteSubmission,
    ) -> Result<
        (
            TransportReconciliationRoute,
            storage_sqlite::RecoveryComparisonOutcome,
        ),
        AppError,
    > {
        // A failed or timed-out queue step leaves an unqueued suffix whose
        // IDs cannot be mapped back to individual cursor positions.
        if submission.cursor_safe && submission.cursor != submission.initial_cursor {
            storage.advance_transport_reconciliation_replay_cursor(
                &submission.route,
                submission.cursor,
            )?;
        }
        Ok((submission.route, submission.outcome))
    }
}

async fn submit_reconciliation_route(
    adapter: &crate::relay_plane::MarmotRelayPlaneAccountAdapter,
    route: ComparisonRouteResult,
    admission_deadline: tokio::time::Instant,
    #[cfg(test)] witness: Option<&TestComparisonActivityWitness>,
) -> RouteSubmission {
    let mut cursor_safe = true;
    #[cfg(test)]
    let mut attempted = 0usize;
    #[cfg(test)]
    let mut delivered = 0usize;
    let outcome = match route.result {
        ComparisonRouteWorkResult::Skipped => {
            storage_sqlite::RecoveryComparisonOutcome::ServicedPartial
        }
        ComparisonRouteWorkResult::TimedOut => {
            storage_sqlite::RecoveryComparisonOutcome::TransientFailure
        }
        ComparisonRouteWorkResult::Returned(Ok(None)) => {
            storage_sqlite::RecoveryComparisonOutcome::Unsupported
        }
        ComparisonRouteWorkResult::Returned(Err(_)) => {
            storage_sqlite::RecoveryComparisonOutcome::TransientFailure
        }
        ComparisonRouteWorkResult::Returned(Ok(Some((summary, events)))) => {
            let mut submitted = true;
            for event in events {
                #[cfg(test)]
                {
                    attempted += 1;
                }
                #[cfg(test)]
                let matches_target = witness.is_some_and(|witness| {
                    witness
                        .target_event_id
                        .lock()
                        .unwrap()
                        .as_ref()
                        .is_some_and(|target| event.event.id.eq_ignore_ascii_case(target))
                });
                let queue = async {
                    #[cfg(test)]
                    if let Ok(Some(action)) = TEST_COMPARISON_QUEUE_ACTIONS
                        .try_with(|actions| actions.borrow_mut().pop_front())
                    {
                        match action {
                            TestComparisonQueueAction::Fail => {
                                return Err(cgka_traits::TransportAdapterError::Subscription(
                                    "injected comparison queue failure".into(),
                                ));
                            }
                            TestComparisonQueueAction::Block => {
                                std::future::pending::<()>().await;
                            }
                        }
                    }
                    adapter.queue_reconciled_event(event).await
                };
                match tokio::time::timeout_at(admission_deadline, queue).await {
                    Ok(Ok(route_count)) => {
                        #[cfg(test)]
                        {
                            delivered += route_count;
                        }
                        #[cfg(test)]
                        if matches_target && let Some(witness) = witness {
                            witness
                                .matching_queued_deliveries
                                .fetch_add(route_count, Ordering::SeqCst);
                        }
                        #[cfg(not(test))]
                        let _ = route_count;
                    }
                    _ => {
                        submitted = false;
                        break;
                    }
                }
            }
            if !submitted || summary.relays_failed > 0 {
                cursor_safe = submitted;
                storage_sqlite::RecoveryComparisonOutcome::TransientFailure
            } else {
                storage_sqlite::RecoveryComparisonOutcome::ServicedUnknown
            }
        }
    };
    RouteSubmission {
        route: route.route,
        initial_cursor: route.initial_cursor,
        cursor: route.cursor,
        cursor_safe,
        outcome,
        #[cfg(test)]
        attempted,
        #[cfg(test)]
        delivered,
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
    use std::cell::RefCell;
    use std::future::Future as _;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

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
    async fn epoch_gap_zero_credit_preflight_preserves_inline_fallback() {
        let mut eligible = fixture_with_group_relays_and_comparison(None, false).await;
        arm_test_epoch_gap(&mut eligible).await;
        let serial = eligible
            .storage
            .recovery_retry_state()
            .unwrap()
            .attempt_serial;
        assert!(eligible.client.epoch_gap_only_waiting_for_credit().unwrap());
        assert_eq!(
            eligible
                .storage
                .recovery_retry_state()
                .unwrap()
                .attempt_serial,
            serial
        );
        eligible
            .client
            .recovery_owner
            .test_advance_clock(Duration::from_secs(300));
        let maintenance = eligible
            .client
            .authorize_account_recovery(
                None,
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .unwrap()
            .unwrap();
        assert!(
            !eligible
                .client
                .epoch_gap_offload_eligible(&maintenance)
                .unwrap()
        );

        let relays = (0..5)
            .map(|index| format!("wss://relay-{index}.example"))
            .collect();
        let mut over_cap = fixture_with_group_relays_and_comparison(Some(relays), false).await;
        arm_test_epoch_gap(&mut over_cap).await;
        assert!(!over_cap.client.epoch_gap_only_waiting_for_credit().unwrap());
        over_cap
            .client
            .recovery_owner
            .test_advance_clock(Duration::from_secs(300));
        let grant = over_cap
            .client
            .authorize_account_recovery(None, marmot_forensics::EpochBackfillExecutionSeam::Receive)
            .unwrap()
            .unwrap();
        assert!(!over_cap.client.epoch_gap_offload_eligible(&grant).unwrap());
        let serial = grant.reservation.attempt_serial;
        over_cap
            .client
            .execute_pending_epoch_backfill_grant(grant)
            .await
            .unwrap();
        assert_eq!(
            over_cap
                .storage
                .recovery_retry_state()
                .unwrap()
                .attempt_serial,
            serial
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
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant, None)
            .await
            .unwrap();
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
            .finish_comparison_grant(grant, attempt, network_result(route.clone(), Some([8; 32])))
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
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant, None)
            .await
            .unwrap();
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
            .finish_comparison_grant(
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
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant, None)
            .await
            .unwrap();
        fixture.client.adapter.require_fresh_activation().await;
        fixture
            .client
            .runtime
            .activate_transport(None)
            .await
            .unwrap();
        assert_ne!(
            fixture.client.adapter.account_subscription_attempt().await,
            Some(attempt)
        );
        let result = fixture
            .client
            .finish_comparison_grant(grant, attempt, network_result(route.clone(), Some([8; 32])))
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
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant, None)
            .await
            .unwrap();
        let result = fixture
            .client
            .finish_comparison_grant(grant, attempt, network_result(route.clone(), Some([8; 32])))
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

    #[tokio::test(flavor = "current_thread")]
    async fn comparison_join_admits_owned_event_after_real_delivery_backpressure() {
        let mut fixture = fixture().await;
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
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant, None)
            .await
            .unwrap();
        let event = candidate_for_route(group_route);
        // Saturate the shared transport queue with another account's route.
        // Its account queue can hold this prefix; Alice's queue stays empty
        // until the comparison result is admitted and owner-drained.
        crate::AccountHome::open(fixture._dir.path())
            .create_account("bob")
            .unwrap();
        let mut bob = client_on_app_relay_plane(&fixture.client.app, "bob").await;
        let bob_group = bob.create_group("backpressure source", &[]).await.unwrap();
        let bob_record = fixture
            .client
            .app
            .group("bob", &hex::encode(bob_group))
            .unwrap()
            .unwrap();
        let bob_route: [u8; 32] = hex::decode(bob_record.nostr_routing.nostr_group_id_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let bob_event = candidate_for_route(bob_route);
        let adapter = bob.adapter.clone();
        let mut context = Context::from_waker(Waker::noop());
        tokio::task::unconstrained(async {
            for _ in 0..1024 {
                assert_eq!(
                    adapter
                        .queue_reconciled_event(bob_event.clone())
                        .await
                        .unwrap(),
                    1
                );
            }
            // Keep Tokio's cooperative yield from running the router during
            // the fill. The next real adapter send must pend on its buffer.
            let mut blocked = Box::pin(adapter.queue_reconciled_event(bob_event.clone()));
            assert!(matches!(blocked.as_mut().poll(&mut context), Poll::Pending));
        })
        .await;

        let mut network = network_result(route.clone(), Some([8; 32]));
        network.routes[0].result = ComparisonRouteWorkResult::Returned(Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            vec![event],
        ))));
        let mut finish = Box::pin(
            fixture
                .client
                .finish_comparison_grant(grant, attempt, network),
        );
        assert!(matches!(finish.as_mut().poll(&mut context), Poll::Pending));
        let result = tokio::time::timeout(Duration::from_secs(15), finish)
            .await
            .expect("the owner drains after its real queue send pends")
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32]),
        );
        assert!(fixture.client.adapter.pending_delivery_overflow().is_none());
        assert!(bob.adapter.pending_delivery_overflow().is_none());
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                fixture.client.adapter.receive_account_delivery()
            )
            .await
            .is_err(),
            "owner continuation drained Alice's admitted event"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn comparison_join_timeout_keeps_cursor_and_retry_debt_after_real_queue_block() {
        let mut fixture = fixture().await;
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
        fixture
            .client
            .activate_comparison_grant(&grant, None)
            .await
            .unwrap();
        let event = candidate_for_route(group_route);
        let adapter = fixture.client.adapter.clone();
        let router_pause = fixture.client.app.relay_plane.pause_router_for_test().await;
        let mut context = Context::from_waker(Waker::noop());
        tokio::task::unconstrained(async {
            for _ in 0..1024 {
                assert_eq!(
                    adapter.queue_reconciled_event(event.clone()).await.unwrap(),
                    1
                );
            }
            let mut blocked = Box::pin(adapter.queue_reconciled_event(event.clone()));
            assert!(matches!(blocked.as_mut().poll(&mut context), Poll::Pending));
        })
        .await;
        let mut network = network_result(route.clone(), Some([8; 32]));
        network.routes[0].result = ComparisonRouteWorkResult::Returned(Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            vec![event],
        ))));
        let route_result = network.routes.remove(0);
        let admission = fixture.client.admit_comparison_route(
            &fixture.storage,
            route_result,
            tokio::time::Instant::now() - Duration::from_millis(1),
        );
        // The elapsed admission deadline meets the same genuinely pending
        // production send while the test holds only the router task. Tokio's
        // real timeout fires before that task is restarted.
        let (route_key, outcome) = tokio::time::timeout(Duration::from_secs(1), admission)
            .await
            .expect("elapsed admission timeout fires on the real queue send")
            .unwrap();
        assert!(matches!(
            outcome,
            storage_sqlite::RecoveryComparisonOutcome::TransientFailure
        ));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None
        );
        drop(router_pause);
        let mut counts = DrainCounts::default();
        let mut verdict = None;
        tokio::time::timeout(
            Duration::from_secs(15),
            fixture.client.complete_recovery_grant_inner(
                &grant,
                None,
                &mut counts,
                &mut verdict,
                vec![(route_key, outcome)],
            ),
        )
        .await
        .expect("owner drains and checkpoints after timed-out admission")
        .unwrap();
        let slot = fixture.storage.recovery_comparison().unwrap();
        assert!(slot.pending());
        assert!(!slot.plan.unwrap().retry_routes.is_empty());
        assert!(fixture.client.adapter.pending_delivery_overflow().is_none());
    }

    #[tokio::test]
    async fn comparison_failed_queue_keeps_prepass_cursor_for_unqueued_suffix() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant, None)
            .await
            .unwrap();
        let mut network = network_result(route.clone(), Some([8; 32]));
        network.routes[0].result = ComparisonRouteWorkResult::Returned(Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            vec![candidate()],
        ))));
        let result = TEST_COMPARISON_QUEUE_ACTIONS
            .scope(
                RefCell::new([TestComparisonQueueAction::Fail].into()),
                async {
                    fixture
                        .client
                        .finish_comparison_grant(grant, attempt, network)
                        .await
                },
            )
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
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant, None)
            .await
            .unwrap();
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
            .finish_comparison_grant(grant, attempt, network)
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
