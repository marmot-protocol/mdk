//! Account recovery authorization. Network work remains on the account worker;
//! this module only decides whether one immutable grant may spend retry cost.
use cgka_traits::MaintenanceStorage;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use super::AppClient;
use crate::{AppError, RecoveryExecutorMode, unix_now_seconds};

use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};
use storage_sqlite::{
    RecoveryRetryState, RecoveryRevisionFence, RecoveryScopePlan, RecoveryScopeToken,
    SqliteAccountStorage,
};

/// Tests inject the result of a finite synthetic endpoint inventory. This seam
/// exercises admission/checkpoint/acknowledgment, not the production backend's
/// ability to prove exhaustiveness. That backend continues to return Unknown.
#[cfg(test)]
pub(crate) type TestRecoveryEvidence =
    fn(&RecoveryScopePlan) -> Vec<storage_sqlite::RecoveryEndpointCheckpoint>;

#[cfg(test)]
pub(crate) fn empty_finite_history(
    scope: &RecoveryScopePlan,
) -> Vec<storage_sqlite::RecoveryEndpointCheckpoint> {
    scope
        .admitted_endpoints
        .iter()
        .map(|endpoint| storage_sqlite::RecoveryEndpointCheckpoint {
            endpoint: endpoint.clone(),
            outcome: storage_sqlite::RecoveryScopeOutcome::Covered,
            exhaustive: true,
            admission_complete: true,
            first_boundary: false,
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryReadiness {
    #[cfg(test)]
    Ready,
    Unknown,
    Waiting,
}

/// One caller operation may override automatic pacing once. Continuing or
/// cancelling its acquisition never replenishes this permit.
#[derive(Default)]
pub(crate) struct ExplicitRecoveryPermit {
    spent: bool,
    full_history_requested: bool,
}

impl ExplicitRecoveryPermit {
    pub(super) fn full_history() -> Self {
        Self {
            full_history_requested: true,
            ..Self::default()
        }
    }
}

/// Owned by the serialized caller future. Synchronous drop cleanup runs at its
/// cancellation boundary; it never dispatches work or deletes unfinished debt.
/// Reopen repeats cleanup if storage closed before this guard could persist it.
pub(super) struct RecoveryCallerGuard {
    storage: SqliteAccountStorage,
    ticket: Option<storage_sqlite::RecoveryDemandTicket>,
}

impl RecoveryCallerGuard {
    pub(super) fn new(
        storage: SqliteAccountStorage,
        ticket: storage_sqlite::RecoveryDemandTicket,
    ) -> Self {
        Self {
            storage,
            ticket: Some(ticket),
        }
    }

    pub(super) fn detach(&mut self) -> StorageResult<()> {
        if let Some(ticket) = self.ticket {
            self.storage.detach_recovery_waiter(ticket)?;
            self.ticket = None;
        }
        Ok(())
    }
}

impl Drop for RecoveryCallerGuard {
    fn drop(&mut self) {
        if self.detach().is_err() {
            tracing::warn!(target: "marmot_app::recovery", method = "detach_recovery_caller",
                "caller cleanup remains pending until account reopen");
        }
    }
}

/// Cancellation of a granted executor must release its transient plane lease.
/// The account worker's sole active grant prevents overlap with another attempt.
/// Durable loss and its cursor guard remain armed.
pub(super) struct RecoveryLossAttemptGuard {
    adapter: crate::relay_plane::MarmotRelayPlaneAccountAdapter,
    armed: bool,
}
impl RecoveryLossAttemptGuard {
    pub(super) fn new(adapter: crate::relay_plane::MarmotRelayPlaneAccountAdapter) -> Self {
        Self {
            adapter,
            armed: true,
        }
    }
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for RecoveryLossAttemptGuard {
    fn drop(&mut self) {
        if self.armed {
            self.adapter.fail_delivery_overflow_recovery();
        }
    }
}

/// An acquisition observation changes eligibility, never the completion predicate.
/// Unknown history gets one bounded investigation per qualified demand revision;
/// missing epoch/event input remains useful to retry unless incapability is known.
pub(super) fn eligibility_after_observation(
    cause: storage_sqlite::RecoveryCause,
    outcome: storage_sqlite::RecoveryScopeOutcome,
    investigation_ended: bool,
    admission_refused: bool,
) -> storage_sqlite::RecoveryEligibility {
    use storage_sqlite::{
        RecoveryCause as Cause, RecoveryEligibility as Eligibility, RecoveryScopeOutcome as Outcome,
    };
    if admission_refused {
        return Eligibility::WaitingCapacity;
    }
    match outcome {
        Outcome::Unsupported | Outcome::Excluded => Eligibility::WaitingCapability,
        Outcome::Unknown | Outcome::BudgetExhausted
            if investigation_ended
                && matches!(
                    cause,
                    Cause::QueueLoss
                        | Cause::NotificationLoss
                        | Cause::ExplicitHistory
                        | Cause::IncrementalHistory
                ) =>
        {
            Eligibility::NeedsDeepRepair
        }
        _ => Eligibility::Retry,
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RecoveryRetryPolicy {
    pub(crate) base: Duration,
    pub(crate) cap: Duration,
}

impl RecoveryRetryPolicy {
    fn delay_ms(self, ordinal: u64) -> StorageResult<u64> {
        if self.base.is_zero() || self.base > self.cap {
            return Err(StorageError::Serialization(
                "invalid recovery retry policy".into(),
            ));
        }
        let factor = 1_u32
            .checked_shl(ordinal.min(31) as u32)
            .unwrap_or(u32::MAX);
        duration_ms(self.base.saturating_mul(factor).min(self.cap))
    }
}

/// Created only after the durable reservation commits. Owned by one executor
/// future, including its drain continuations. Dropping that future releases the
/// transient lease without asynchronous writes or deleting durable demand.
pub(crate) struct AttemptGrant {
    pub(crate) reservation: RecoveryRetryState,
    pub(crate) fence: RecoveryRevisionFence,
    pub(crate) seam: marmot_forensics::EpochBackfillExecutionSeam,
    plan: Vec<GrantedObligation>,
    pub(super) comparison_revision: Option<u64>,
    pub(super) comparison_plan: Option<storage_sqlite::RecoveryComparisonPlan>,
    pub(super) rotation_claim: Option<storage_sqlite::TransportReconciliationRoute>,
    pub(super) inventory: Vec<FrozenRecoveryInventory>,
    loss: Vec<GrantedLoss>,
    _live: Arc<()>,
    admission: Option<Arc<RecoveryAdmissionSnapshot>>,
}

/// Admission scope survives exactly as long as its grant. The owner holds only
/// a weak reference, so cancellation/quiescence cannot retain a finished plan.
struct RecoveryAdmissionSnapshot {
    scopes: Vec<RecoveryScopePlan>,
    attempt: u64,
    fence: RecoveryRevisionFence,
    comparison_revision: Option<u64>,
}

#[derive(Clone)]
struct GrantedLoss {
    id: [u8; 16],
    watermarks: storage_sqlite::RecoveryLossSnapshot,
}

/// Private input snapshot; identities are deliberately not Debug-printable.
pub(super) struct FrozenRecoveryInventory {
    pub(super) work: super::sync::TransportReconciliationWork,
    pub(super) route: storage_sqlite::TransportReconciliationRoute,
    pub(super) since: u64,
    pub(super) until: u64,
    pub(super) items: Vec<transport_nostr_adapter::NostrReconciliationItem>,
}

#[derive(Clone)]
pub(crate) struct GrantedScope {
    pub(crate) goal: RecoveryScopePlan,
    pub(crate) token: RecoveryScopeToken,
}

pub(crate) struct GrantedObligation {
    pub(crate) id: [u8; 16],
    pub(crate) scopes: Vec<GrantedScope>,
    pub(crate) cause: storage_sqlite::RecoveryCause,
    pub(crate) group_id: Option<cgka_traits::GroupId>,
}

impl AttemptGrant {
    /// Executors only receive grants whose entire selected plan was durably
    /// frozen. A reservation alone is never sufficient authority for I/O.
    pub(crate) fn plan(&self) -> Option<&[GrantedObligation]> {
        self.admission.as_ref().map(|_| self.plan.as_slice())
    }
}

#[derive(Clone)]
pub(crate) struct MaintenanceRecoveryObservation {
    pub(crate) fence: RecoveryRevisionFence,
    pub(crate) attempt_serial: u64,
    pub(crate) id: [u8; 16],
    pub(crate) scopes: Vec<GrantedScope>,
}

pub(crate) struct AccountRecoveryOwner {
    pub(crate) maintenance_observations:
        std::collections::HashMap<cgka_traits::GroupId, MaintenanceRecoveryObservation>,
    wall_anchor_ms: u64,
    monotonic_anchor: Instant,
    active: Weak<()>,
    active_admission: Weak<RecoveryAdmissionSnapshot>,
    last_unavailable_epoch_observation: Option<[u8; 32]>,
    policy: RecoveryRetryPolicy,
    mode: RecoveryExecutorMode,
    // At most the two loss causes. These are captured CAS inputs, never an
    // authority for completion: storage rechecks every predicate at acknowledgment.
    // Reopen discards them and restores all durable unacknowledged loss.
    pending_loss_acknowledgments: Vec<(RecoveryRevisionFence, GrantedLoss)>,
}

/// Use the same precision as persisted retry deadlines. Truncating to seconds
/// can make an ordinary reopen look like a backward wall-clock correction.
pub(crate) fn wall_now_ms() -> StorageResult<u64> {
    duration_ms(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default(),
    )
}

fn duration_ms(value: Duration) -> StorageResult<u64> {
    u64::try_from(value.as_millis()).map_err(|_| {
        StorageError::Serialization("recovery duration outside supported range".into())
    })
}

impl AccountRecoveryOwner {
    pub(crate) fn open(
        storage: &SqliteAccountStorage,
        wall_now_ms: u64,
        monotonic_now: Instant,
        policy: RecoveryRetryPolicy,
    ) -> StorageResult<Self> {
        policy.delay_ms(0)?;
        storage.restore_unacknowledged_recovery_loss()?;
        storage.restore_recovery_waiters()?;
        storage.reclaim_completed_recovery_events()?;
        storage.restore_recovery_retry(wall_now_ms, duration_ms(policy.cap)?)?;
        Ok(Self {
            maintenance_observations: std::collections::HashMap::new(),
            wall_anchor_ms: wall_now_ms,
            monotonic_anchor: monotonic_now,
            active: Weak::new(),
            active_admission: Weak::new(),
            last_unavailable_epoch_observation: None,
            policy,
            mode: RecoveryExecutorMode::Normal,
            pending_loss_acknowledgments: Vec::new(),
        })
    }

    /// Wall clock is sampled only on open. Later wall-clock corrections cannot
    /// repeatedly reopen the authorization gate within this process.
    #[cfg(any(test, feature = "test-policy-overrides"))]
    pub(crate) fn test_retry_remaining(&self, storage: &SqliteAccountStorage) -> Duration {
        Duration::from_millis(
            storage
                .recovery_retry_state()
                .unwrap()
                .not_before_ms
                .saturating_sub(self.logical_now_ms(Instant::now()).unwrap()),
        )
    }

    #[cfg(test)]
    pub(crate) fn test_advance_to_retry(&mut self, storage: &SqliteAccountStorage) {
        // Move the injected monotonic clock, never mutate durable retry state.
        self.wall_anchor_ms += self.test_retry_remaining(storage).as_millis() as u64;
    }

    #[cfg(any(test, feature = "test-policy-overrides"))]
    pub(crate) fn test_advance_clock(&mut self, elapsed: Duration) {
        self.wall_anchor_ms += elapsed.as_millis() as u64;
    }

    pub(super) fn logical_now_ms(&self, now: Instant) -> StorageResult<u64> {
        let elapsed = now
            .checked_duration_since(self.monotonic_anchor)
            .ok_or_else(|| {
                StorageError::Serialization("recovery monotonic clock moved backward".into())
            })?;
        self.wall_anchor_ms
            .checked_add(duration_ms(elapsed)?)
            .ok_or_else(|| {
                StorageError::Serialization("recovery clock outside supported range".into())
            })
    }

    pub(crate) fn select_authorized_attempt(
        &mut self,
        storage: &SqliteAccountStorage,
        readiness: RecoveryReadiness,
        now: Instant,
        explicit: Option<&mut ExplicitRecoveryPermit>,
    ) -> StorageResult<Option<AttemptGrant>> {
        if self.active.upgrade().is_some() {
            return Ok(None);
        }
        storage.reclaim_completed_recovery_events()?;
        if readiness == RecoveryReadiness::Waiting {
            return Ok(None);
        }
        let now_ms = self.logical_now_ms(now)?;
        storage.release_due_recovery_capacity_probes(now_ms, duration_ms(self.policy.base)?)?;
        let immediate = explicit.as_ref().is_some_and(|permit| !permit.spent);
        let mut fence = storage.recovery_eligible_revision_fence(immediate)?;
        let comparison = storage.recovery_comparison()?;
        let mut comparison_revision = (comparison.pending()
            && !explicit
                .as_ref()
                .is_some_and(|permit| permit.full_history_requested)
            && (immediate
                || comparison
                    .blocked_route_revision
                    .is_none_or(|r| r != fence.route_revision)))
        .then_some(comparison.revision);
        // An installed maintenance subscription is awaiting evidence, not
        // another acquisition. Observations are bound to its original scope
        // token and live session; reconnect cannot manufacture a new proof.
        fence.obligations.retain(|selected| {
            !self.maintenance_observations.values().any(|observation| {
                observation.fence.route_revision == fence.route_revision
                    && observation.fence.loss_revision == fence.loss_revision
                    && observation.fence.obligations.contains(selected)
                    && observation.id == selected.0
            })
        });
        let reserved = storage.with_transaction(|storage| {
            let prior = storage.recovery_retry_state()?;
            if (fence.obligations.is_empty() && comparison_revision.is_none())
                || (!immediate && now_ms < prior.not_before_ms)
            {
                return Ok::<_, StorageError>(None);
            }
            if self.mode == RecoveryExecutorMode::Normal {
                let maintenance = self
                    .maintenance_observations
                    .values()
                    .map(|observation| observation.id)
                    .collect::<Vec<_>>();
                storage.rearm_recovery_maintenance_for_activation(&maintenance)?;
                fence = storage.recovery_eligible_revision_fence(immediate)?;
            } else {
                // One predicate owns this grant. Restore other physical sessions
                // without re-completing their predicates or restarting grace.
                // Oldest installed attempt first prevents a retrying predicate
                // from starving the remaining durable obligations across reopen.
                let demands = storage.pending_recovery_demands()?;
                // Displaced unqualified boundaries need a new selected grant;
                // their prior waiting state cannot strand them after we discard
                // the old session observation. Completed grace stays completed.
                let displaced = self
                    .maintenance_observations
                    .values()
                    .filter(|observation| demands.iter().any(|d| d.ticket.id == observation.id))
                    .map(|observation| observation.id)
                    .collect::<Vec<_>>();
                storage.rearm_recovery_maintenance_for_activation(&displaced)?;
                let mut ordered = fence
                    .obligations
                    .iter()
                    .map(|(id, revision)| {
                        let caller = immediate
                            && demands
                                .iter()
                                .any(|d| d.ticket.id == *id && d.caller_waiting);
                        let last = storage
                            .recovery_scope_snapshots(*id)?
                            .iter()
                            .map(|scope| scope.attempt_serial)
                            .max()
                            .unwrap_or(0);
                        Ok((!caller, last, *id, *revision))
                    })
                    .collect::<StorageResult<Vec<_>>>()?;
                ordered.sort();
                if comparison_revision.is_some() {
                    let choose_comparison = ordered.first().is_none_or(|(not_caller, last, ..)| {
                        *not_caller && comparison.attempt_serial <= *last
                    });
                    if choose_comparison {
                        ordered.clear();
                    } else {
                        comparison_revision = None;
                    }
                }
                fence.obligations = ordered
                    .into_iter()
                    .take(1)
                    .map(|(_, _, id, revision)| (id, revision))
                    .collect();
            }
            let reservation = storage.reserve_recovery_work(
                &fence,
                comparison_revision,
                now_ms,
                self.policy.delay_ms(prior.ordinal)?,
                immediate,
            )?;
            Ok(reservation)
        })?;
        let Some(reservation) = reserved else {
            return Ok(None);
        };
        let live = Arc::new(());
        self.active = Arc::downgrade(&live);
        self.active_admission = Weak::new();
        Ok(Some(AttemptGrant {
            reservation,
            fence,
            seam: marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            plan: Vec::new(),
            comparison_revision,
            comparison_plan: None,
            rotation_claim: None,
            inventory: Vec::new(),
            loss: Vec::new(),
            _live: live,
            admission: None,
        }))
    }

    /// Resolve hydrated route goals before calling this method. The private
    /// grant owns both scope tokens and immutable bounds through every drain
    /// continuation; no executor may replace that plan or authorize a follow-up.
    pub(crate) fn freeze_plan(
        &mut self,
        storage: &SqliteAccountStorage,
        mut grant: AttemptGrant,
        goals: Vec<([u8; 16], Vec<RecoveryScopePlan>)>,
        explicit: Option<&mut ExplicitRecoveryPermit>,
    ) -> StorageResult<Option<AttemptGrant>> {
        if !grant.plan.is_empty() || goals.len() != grant.fence.obligations.len() {
            return Err(StorageError::Serialization(
                "invalid recovery grant plan".into(),
            ));
        }
        let result =
            storage.with_transaction(|storage| -> Result<Vec<GrantedObligation>, FreezeError> {
                let mut frozen = Vec::new();
                let demands = storage.pending_recovery_demands()?;
                for ((id, scopes), (selected, _)) in goals.into_iter().zip(&grant.fence.obligations)
                {
                    if id != *selected {
                        return Err(StorageError::Serialization(
                            "invalid recovery grant selection".into(),
                        )
                        .into());
                    }
                    let Some(tokens) = storage.install_recovery_scope_plan(
                        &grant.fence,
                        grant.reservation.attempt_serial,
                        id,
                        &scopes,
                    )?
                    else {
                        return Err(FreezeError::Stale);
                    };
                    let demand = demands
                        .iter()
                        .find(|demand| demand.ticket.id == id)
                        .ok_or_else(|| {
                            StorageError::Serialization(
                                "selected recovery demand disappeared".into(),
                            )
                        })?;
                    frozen.push(GrantedObligation {
                        id,
                        cause: demand.cause,
                        group_id: demand.group_id.clone().map(cgka_traits::GroupId::new),
                        scopes: scopes
                            .into_iter()
                            .zip(tokens)
                            .map(|(goal, token)| GrantedScope { goal, token })
                            .collect(),
                    });
                }
                match (grant.comparison_revision, &grant.comparison_plan) {
                    (Some(revision), Some(plan)) if plan.fence == grant.fence => {
                        if !storage.install_recovery_comparison_plan(
                            revision,
                            grant.reservation.attempt_serial,
                            plan,
                        )? {
                            return Err(FreezeError::Stale);
                        }
                    }
                    (None, None) => {}
                    _ => {
                        return Err(
                            StorageError::Serialization("missing comparison plan".into()).into(),
                        );
                    }
                }
                if let Some(route) = &grant.rotation_claim {
                    storage.advance_transport_reconciliation_route_cursor(route)?;
                }
                Ok(frozen)
            });
        grant.plan = match result {
            Ok(plan) => plan,
            Err(FreezeError::Stale) => return Ok(None),
            Err(FreezeError::Storage(error)) => return Err(error),
        };
        let admission = Arc::new(RecoveryAdmissionSnapshot {
            scopes: grant
                .plan
                .iter()
                .flat_map(|obligation| &obligation.scopes)
                .map(|scope| scope.goal.clone())
                .chain(
                    grant
                        .comparison_plan
                        .iter()
                        .flat_map(|plan| plan.routes.iter().cloned()),
                )
                .collect(),
            attempt: grant.reservation.attempt_serial,
            fence: grant.fence.clone(),
            comparison_revision: grant.comparison_revision,
        });
        self.active_admission = Arc::downgrade(&admission);
        grant.admission = Some(admission);
        // Reservation is durable retry cost, not permission to disturb an
        // installed session. Commit transient effects only after plan freeze.
        self.maintenance_observations.clear();
        if let Some(permit) = explicit {
            permit.spent = true;
        }
        Ok(Some(grant))
    }

    /// Ingest calls this only for a newly retained, non-rejected object after
    /// the engine persistence and release-journal synchronization. Duplicates,
    /// live traffic outside frozen bounds and unrelated routes cannot reset cost.
    pub(crate) fn observe_scoped_admission(
        &self,
        storage: &SqliteAccountStorage,
        route: &storage_sqlite::TransportReconciliationRoute,
        created_at: u64,
        now: Instant,
    ) -> StorageResult<bool> {
        let Some(admission) = self.active_admission.upgrade() else {
            return Ok(false);
        };
        if !admission.scopes.iter().any(|scope| {
            created_at <= scope.until_seconds
                && scope.since_seconds.is_none_or(|since| created_at >= since)
                && match route {
                    storage_sqlite::TransportReconciliationRoute::Inbox => scope.route_kind == 0,
                    storage_sqlite::TransportReconciliationRoute::Group(id) => {
                        scope.route_kind == 1 && scope.transport_group_id.as_ref() == Some(id)
                    }
                }
        }) {
            return Ok(false);
        }
        if let Some(revision) = admission.comparison_revision {
            return storage.checkpoint_recovery_comparison_progress(
                revision,
                admission.attempt,
                &admission.fence,
                self.logical_now_ms(now)?,
                duration_ms(self.policy.base)?,
            );
        }
        storage.checkpoint_recovery_progress(
            &admission.fence,
            admission.attempt,
            self.logical_now_ms(now)?,
            duration_ms(self.policy.base)?,
        )
    }

    #[cfg(test)]
    pub(crate) fn observe_durable_admission(
        &self,
        storage: &SqliteAccountStorage,
        grant: &AttemptGrant,
        now: Instant,
    ) -> StorageResult<bool> {
        storage.checkpoint_recovery_progress(
            &grant.fence,
            grant.reservation.attempt_serial,
            self.logical_now_ms(now)?,
            duration_ms(self.policy.base)?,
        )
    }

    /// Same-schema rollback changes the delegated executor, never the ledger
    /// or retry authority. An active plan retains its immutable mode.
    pub(crate) fn select_executor_mode(&mut self, mode: RecoveryExecutorMode) -> bool {
        if self.active.upgrade().is_some() {
            return false;
        }
        self.mode = mode;
        true
    }
}

enum FreezeError {
    Stale,
    Storage(StorageError),
}

impl From<StorageError> for FreezeError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl AppClient {
    pub(super) fn comparison_route_goals(
        &self,
        until: u64,
    ) -> Result<Vec<RecoveryScopePlan>, AppError> {
        let routing = self.routing.snapshot();
        let mut goals = Vec::new();
        let mut push = |group_id: Option<Vec<u8>>,
                        transport_group_id: Option<[u8; 32]>,
                        endpoints: &[cgka_traits::TransportEndpoint]| {
            let mut required = endpoints
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect::<Vec<_>>();
            required.sort();
            required.dedup();
            goals.push(RecoveryScopePlan {
                scope_id: goals.len() as u64,
                route_kind: u8::from(group_id.is_some()),
                route_role: 0,
                group_id,
                transport_group_id,
                // This is the inventory window, distinct from the newer live
                // subscription cutoff. Compaction can raise the actual floor.
                since_seconds: Some(
                    until.saturating_sub(storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS),
                ),
                until_seconds: until,
                known_event_id: None,
                inventory_floor: None,
                required_endpoints: required,
                admitted_endpoints: self.adapter.recovery_admitted_endpoints(endpoints),
            });
        };
        push(None, None, &routing.local_inbox_endpoints);
        let mut routes = routing.group_routes.iter().collect::<Vec<_>>();
        routes.sort_by(|a, b| {
            a.group_id
                .as_slice()
                .cmp(b.group_id.as_slice())
                .then(a.transport_group_id.cmp(&b.transport_group_id))
        });
        for route in routes {
            let id = route
                .transport_group_id
                .as_slice()
                .try_into()
                .map_err(|_| StorageError::Serialization("invalid comparison route".into()))?;
            push(
                Some(route.group_id.as_slice().to_vec()),
                Some(id),
                &route.endpoints,
            );
        }
        Ok(goals)
    }

    pub(super) fn request_bounded_comparison(&mut self) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        storage.synchronize_account_delivery_loss(&self.state.label)?;
        drop(self.transport_receipts()?);
        self.observe_recovery_route_policy()?;
        let now = wall_now_ms()?;
        let goals = self.comparison_route_goals(now / 1000)?;
        storage.observe_recovery_comparison_capability(
            self.adapter.recovery_comparison_capability_key(),
        )?;
        storage.join_recovery_comparison(&rand::random(), now, &goals)?;
        Ok(())
    }

    pub(super) async fn install_granted_post_join_subscriptions(
        &mut self,
        grant: &AttemptGrant,
    ) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let demands = storage.pending_recovery_demands()?;
        for obligation in grant
            .plan()
            .ok_or_else(|| StorageError::Serialization("unfrozen recovery grant".into()))?
        {
            let Some(demand) = demands.iter().find(|demand| {
                demand.ticket.id == obligation.id
                    && demand.cause == storage_sqlite::RecoveryCause::Maintenance
            }) else {
                continue;
            };
            let Some(group) = demand.group_id.as_ref() else {
                continue;
            };
            let group_id = cgka_traits::GroupId::new(group.clone());
            if self
                .post_join_maintenance_subscriptions
                .contains_key(&group_id)
            {
                continue;
            }
            let Some(scope) = obligation
                .scopes
                .iter()
                .find(|scope| scope.goal.route_kind == 1)
            else {
                continue;
            };
            let Some(route_id) = scope.goal.transport_group_id else {
                continue;
            };
            let route = cgka_traits::TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: route_id.to_vec(),
                endpoints: scope
                    .goal
                    .admitted_endpoints
                    .iter()
                    .cloned()
                    .map(cgka_traits::TransportEndpoint)
                    .collect(),
            };
            if route.endpoints.is_empty() {
                continue;
            }
            let subscription = self
                .adapter
                .install_group_maintenance_subscription(
                    route.clone(),
                    grant.reservation.attempt_serial,
                )
                .await?;
            if let Err(error) = self
                .runtime
                .mark_post_join_subscription_installed(&group_id)
            {
                let _ = self
                    .adapter
                    .remove_group_maintenance_subscription(&subscription)
                    .await;
                return Err(error.into());
            }
            self.post_join_maintenance_subscriptions
                .insert(group_id.clone(), (subscription, route));
            self.recovery_owner.maintenance_observations.insert(
                group_id,
                MaintenanceRecoveryObservation {
                    fence: grant.fence.clone(),
                    attempt_serial: grant.reservation.attempt_serial,
                    id: obligation.id,
                    scopes: obligation.scopes.clone(),
                },
            );
        }
        Ok(())
    }

    pub(super) async fn observe_post_join_recovery_boundary(
        &mut self,
        group_id: &cgka_traits::GroupId,
    ) -> Result<bool, AppError> {
        let Some(observation) = self
            .recovery_owner
            .maintenance_observations
            .get(group_id)
            .cloned()
        else {
            return Ok(false);
        };
        let Some((subscription, _)) = self.post_join_maintenance_subscriptions.get(group_id) else {
            return Ok(false);
        };
        let mut checkpoints = Vec::new();
        for scope in &observation.scopes {
            let mut endpoints = Vec::new();
            for endpoint in &scope.goal.admitted_endpoints {
                if self
                    .adapter
                    .group_maintenance_endpoint_eose(
                        subscription,
                        &cgka_traits::TransportEndpoint(endpoint.clone()),
                    )
                    .await
                    == Some(true)
                {
                    endpoints.push(storage_sqlite::RecoveryEndpointCheckpoint {
                        endpoint: endpoint.clone(),
                        outcome: storage_sqlite::RecoveryScopeOutcome::Partial,
                        exhaustive: false,
                        admission_complete: false,
                        first_boundary: true,
                    });
                }
            }
            checkpoints.push(storage_sqlite::RecoveryScopeCheckpoint {
                token: scope.token.clone(),
                endpoints,
                retained_known_event: false,
            });
        }
        let storage = self.app.account_storage(&self.state.label)?;
        storage.synchronize_account_delivery_loss(&self.state.label)?;
        self.observe_recovery_route_policy()?;
        let domain_updates = self.runtime.post_join_eose_updates(group_id)?;
        storage.with_transaction(|storage| {
            let qualified = storage.checkpoint_recovery_obligation(
                &observation.fence,
                observation.attempt_serial,
                observation.id,
                &checkpoints,
                storage_sqlite::RecoveryEligibility::Retry,
            )?;
            if qualified {
                for obligation in &domain_updates {
                    storage.put_maintenance_obligation(obligation)?;
                }
            }
            Ok(qualified)
        })
    }

    pub(crate) fn observe_recovery_route_policy(&self) -> Result<(), AppError> {
        use sha2::{Digest, Sha256};
        let routing = self.routing.snapshot();
        let mut inbox = routing
            .local_inbox_endpoints
            .iter()
            .map(|endpoint| &endpoint.0)
            .collect::<Vec<_>>();
        inbox.sort();
        inbox.dedup();
        let mut groups = routing
            .group_routes
            .iter()
            .map(|route| {
                let mut endpoints = route
                    .endpoints
                    .iter()
                    .map(|endpoint| &endpoint.0)
                    .collect::<Vec<_>>();
                endpoints.sort();
                endpoints.dedup();
                (
                    route.group_id.as_slice(),
                    route.transport_group_id.as_slice(),
                    endpoints,
                )
            })
            .collect::<Vec<_>>();
        groups.sort();
        groups.dedup();
        let canonical = serde_json::to_vec(&("history-route-policy-v1", inbox, groups))
            .map_err(|_| StorageError::Serialization("invalid recovery route snapshot".into()))?;
        self.app
            .account_storage(&self.state.label)?
            .observe_recovery_route_snapshot(Sha256::digest(canonical).into())?;
        Ok(())
    }

    pub(super) fn observe_qualified_local_stagnation(
        &mut self,
        group: &cgka_traits::GroupId,
    ) -> Result<(), AppError> {
        let Some(stall) = self.epoch_stall.wedge_evidence(group) else {
            return Ok(());
        };
        let record = self.runtime.group_record(group)?;
        if record.is_terminal() || record.epoch.0 != stall.stalled_epoch {
            return Ok(());
        }
        drop(self.transport_receipts()?);
        self.observe_recovery_route_policy()?;
        let storage = self.app.account_storage(&self.state.label)?;
        let observation = storage.next_recovery_engine_observation()?;
        let threshold = self.epoch_stall.fruitless_completion_threshold();
        let sample = storage.sample_qualified_recovery_stall(
            group.as_slice(),
            record.epoch.0,
            observation,
            self.recovery_owner.logical_now_ms(Instant::now())?,
            self.epoch_stall.qualified_observation_interval_ms(),
            threshold,
        )?;
        if let Some(sample) = sample {
            let count = sample.evidence.fruitless_completions;
            self.restore_persisted_epoch_stall_evidence(vec![sample.evidence]);
            if sample.warning_changed {
                self.mark_recovery_status_changed(group);
            }
            if sample.escalated {
                self.report_epoch_stall_escalation(
                    group,
                    record.epoch.0,
                    count,
                    threshold,
                    "observe_qualified_local_stagnation",
                );
            }
        }
        Ok(())
    }

    pub(super) fn abandon_loss_completion(&mut self) -> Result<(), AppError> {
        self.recovery_owner.pending_loss_acknowledgments.clear();
        self.app
            .account_storage(&self.state.label)?
            .restore_unacknowledged_recovery_loss()?;
        Ok(())
    }

    /// The completion handoff is ordered: durable qualification, exact live
    /// plane acknowledgment, then guarded evidence reclamation. Failure after
    /// the plane acknowledgment restores the local guard and durable demand.
    /// Reopen performs the same conservative rearm from unreclaimed evidence.
    pub(super) fn finish_qualified_recovery_loss(
        &mut self,
        grant: &AttemptGrant,
        attempt: crate::relay_plane::AccountDeliveryOverflow,
    ) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        if grant.loss.is_empty() {
            return Ok(false);
        }
        for loss in &grant.loss {
            let Some((_, revision)) = grant
                .fence
                .obligations
                .iter()
                .find(|(id, _)| *id == loss.id)
            else {
                return Ok(false);
            };
            if loss.watermarks.is_empty()
                || !storage.recovery_obligation_is_satisfied(loss.id, *revision)?
            {
                return Ok(false);
            }
        }
        for loss in &grant.loss {
            self.recovery_owner
                .pending_loss_acknowledgments
                .retain(|(_, prior)| prior.id != loss.id);
            self.recovery_owner.pending_loss_acknowledgments.push((
                {
                    let mut fence = grant.fence.clone();
                    fence.obligations.retain(|(id, _)| *id == loss.id);
                    fence
                },
                loss.clone(),
            ));
        }
        // Do not clear a shared plane guard while another loss obligation was
        // omitted from this grant (for example one waiting for a capability).
        if storage.pending_recovery_demands()?.iter().any(|demand| {
            matches!(
                demand.cause,
                storage_sqlite::RecoveryCause::QueueLoss
                    | storage_sqlite::RecoveryCause::NotificationLoss
            )
        }) {
            return Ok(false);
        }
        let Some(elapsed) = self.adapter.finish_delivery_overflow_recovery(attempt) else {
            self.recovery_owner.pending_loss_acknowledgments.clear();
            storage.restore_unacknowledged_recovery_loss()?;
            return Ok(false);
        };
        let reclaimed = storage.with_transaction(|_| {
            for (fence, loss) in &self.recovery_owner.pending_loss_acknowledgments {
                if !storage.acknowledge_recovery_loss_snapshot(fence, loss.id, &loss.watermarks)? {
                    // Roll back any preceding cause's deletion as well.
                    return Err(StorageError::NotFound);
                }
            }
            Ok(())
        });
        if let Err(error) = reclaimed {
            self.adapter
                .restore_delivery_overflow_guard(attempt.marker_token);
            self.recovery_owner.pending_loss_acknowledgments.clear();
            storage.restore_unacknowledged_recovery_loss()?;
            return if matches!(error, StorageError::NotFound) {
                Ok(false)
            } else {
                Err(error.into())
            };
        }
        self.recovery_owner.pending_loss_acknowledgments.clear();
        self.delivery_overflow_recovery_pending = false;
        self.delivery_overflow_recovery_marker_token = None;
        self.adapter
            .record_delivery_overflow_recovery_success(elapsed);
        Ok(true)
    }

    /// Preserve epoch-sensitive deferral diagnostics without restoring a second
    /// dispatcher or retaining another pending-group vector. The digest is
    /// private process state; no identity or digest is emitted in telemetry.
    fn record_unavailable_epoch_observation(
        &mut self,
        storage: &SqliteAccountStorage,
    ) -> Result<(), AppError> {
        use sha2::{Digest, Sha256};
        let retry = storage.recovery_retry_state()?;
        let mut digest = Sha256::new();
        digest.update(b"mdk-recovery-unavailable-epoch-v1");
        digest.update(retry.ordinal.to_be_bytes());
        let mut unavailable = false;
        for demand in storage
            .pending_recovery_demands()?
            .into_iter()
            .filter(|d| d.cause == storage_sqlite::RecoveryCause::EpochGap)
        {
            let observed = demand.group_id.as_ref().and_then(|id| {
                self.runtime
                    .group_record(&cgka_traits::GroupId::new(id.clone()))
                    .ok()
                    .map(|record| record.epoch.0)
            });
            unavailable |= observed.is_none();
            digest.update(demand.ticket.id);
            digest.update(demand.ticket.revision.to_be_bytes());
            for epoch in [demand.stalled_epoch, observed] {
                digest.update([u8::from(epoch.is_some())]);
                digest.update(epoch.unwrap_or(0).to_be_bytes());
            }
        }
        let snapshot = unavailable.then(|| <[u8; 32]>::from(digest.finalize()));
        if snapshot != self.recovery_owner.last_unavailable_epoch_observation {
            self.recovery_owner.last_unavailable_epoch_observation = snapshot;
            if unavailable {
                self.record_epoch_stall_backfill_deferred(
                    marmot_forensics::EpochBackfillDeferredReason::GroupEpochUnavailable,
                    retry.ordinal.saturating_sub(1),
                    &marmot_forensics::AuditEventContext {
                        operation_id: Some(format!("recovery-{}", retry.attempt_serial)),
                        ..Default::default()
                    },
                );
            }
        }
        Ok(())
    }

    /// Worker-only boundary: import loss and synchronize the existing receipt
    /// consumer before selecting a revision-fenced immutable history plan.
    pub(crate) fn authorize_account_recovery(
        &mut self,
        mut explicit: Option<&mut ExplicitRecoveryPermit>,
        seam: marmot_forensics::EpochBackfillExecutionSeam,
    ) -> Result<Option<AttemptGrant>, AppError> {
        // Wake collection retains the loaded live floor and leaves recovery
        // debt/pacing to an Advance runtime. Only the separate full-history
        // repair API explicitly opts into broad recovery in this posture.
        if self.app.cursor_persistence() == crate::CursorPersistence::Frozen
            && !explicit
                .as_ref()
                .is_some_and(|permit| permit.full_history_requested)
        {
            return Ok(None);
        }
        let storage = self.app.account_storage(&self.state.label)?;
        storage.synchronize_account_delivery_loss(&self.state.label)?;
        // Failed detector persistence is retried before any selection. These
        // observations carry demand only; SQL remains the retry authority.
        let arms = self
            .pending_recovery_arm_writes
            .iter()
            .map(|(group, epoch)| storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(group.as_slice()),
                stalled_epoch: *epoch,
            })
            .collect::<Vec<_>>();
        self.app
            .arm_epoch_backfill_intents(&self.state.label, &arms)?;
        self.pending_recovery_arm_writes.clear();
        for (group, epoch) in &self.pending_recovery_capacity_writes {
            storage.record_recovery_capacity_pressure(
                group.as_slice(),
                *epoch,
                self.recovery_owner.logical_now_ms(Instant::now())?,
            )?;
        }
        self.pending_recovery_capacity_writes.clear();
        drop(self.transport_receipts()?);
        self.observe_recovery_route_policy()?;
        let routing = self.routing.snapshot();
        let admitted = !self
            .adapter
            .recovery_admitted_endpoints(&routing.local_inbox_endpoints)
            .is_empty()
            || routing.group_routes.iter().any(|route| {
                !self
                    .adapter
                    .recovery_admitted_endpoints(&route.endpoints)
                    .is_empty()
            });
        let readiness = if admitted {
            RecoveryReadiness::Unknown
        } else {
            RecoveryReadiness::Waiting
        };
        let selected = self.recovery_owner.select_authorized_attempt(
            &storage,
            readiness,
            Instant::now(),
            explicit.as_deref_mut(),
        )?;
        self.record_unavailable_epoch_observation(&storage)?;
        let Some(mut grant) = selected else {
            return Ok(None);
        };
        grant.seam = seam;
        let demands = storage.pending_recovery_demands()?;
        let now = unix_now_seconds();
        let incremental_since = self
            .relay_plane
            .subscription_rebuild_since(self.checkpointed_transport_timestamp)
            .map(|timestamp| timestamp.0);
        let mut goals = Vec::new();
        let mut independent_broad_acquisition = false;
        for (id, revision) in &grant.fence.obligations {
            let demand = demands
                .iter()
                .find(|demand| demand.ticket.id == *id)
                .ok_or_else(|| {
                    StorageError::Serialization("selected recovery demand disappeared".into())
                })?;
            let stored = storage.recovery_scope_snapshots(*id)?;
            if !matches!(
                demand.cause,
                storage_sqlite::RecoveryCause::IncrementalHistory
                    | storage_sqlite::RecoveryCause::Maintenance
            ) {
                // Startup comparison alone cannot reissue an old broad goal.
                // Independently new loss/missing-input/route evidence, or a
                // live explicit caller, still owns its supported wider pass.
                independent_broad_acquisition |= explicit.is_some()
                    || stored.is_empty()
                    || stored.iter().any(|scope| {
                        scope.obligation_revision != *revision
                            || scope.route_revision != grant.fence.route_revision
                            || scope.loss_revision != grant.fence.loss_revision
                    });
            }
            let since = if demand.cause == storage_sqlite::RecoveryCause::IncrementalHistory {
                incremental_since
            } else {
                None
            };
            // Policy-only changes preserve time bounds. A new qualified demand
            // revision may extend the window, including a fresh loss at the same
            // engine epoch; updated_at changes for demand, not route observation.
            let goal_until = stored
                .iter()
                .map(|scope| scope.plan.until_seconds)
                .max()
                .map(|until| until.max(demand.requested_at_ms / 1000))
                .unwrap_or(now);
            // Reuse the frozen historical goal. Route-policy expansion is handled
            // by an explicit revision change before installing a successor plan.
            let scopes = if !stored.is_empty()
                && stored.iter().all(|scope| {
                    scope.obligation_revision == *revision
                        && scope.route_revision == grant.fence.route_revision
                }) {
                stored.into_iter().map(|scope| scope.plan).collect()
            } else {
                let mut scopes = Vec::new();
                if demand.group_id.is_none() {
                    let mut endpoints = routing
                        .local_inbox_endpoints
                        .iter()
                        .map(|endpoint| endpoint.0.clone())
                        .collect::<Vec<_>>();
                    endpoints.sort();
                    endpoints.dedup();
                    scopes.push(RecoveryScopePlan {
                        scope_id: 0,
                        route_kind: 0,
                        route_role: 0,
                        group_id: None,
                        transport_group_id: None,
                        since_seconds: since,
                        until_seconds: goal_until,
                        known_event_id: demand.known_event_id,
                        inventory_floor: None,
                        required_endpoints: endpoints,
                        admitted_endpoints: self
                            .adapter
                            .recovery_admitted_endpoints(&routing.local_inbox_endpoints),
                    });
                }
                let mut routes = routing
                    .group_routes
                    .iter()
                    .filter(|route| {
                        demand
                            .group_id
                            .as_deref()
                            .is_none_or(|group| group == route.group_id.as_slice())
                    })
                    .collect::<Vec<_>>();
                routes.sort_by(|left, right| {
                    left.group_id
                        .as_slice()
                        .cmp(right.group_id.as_slice())
                        .then(left.transport_group_id.cmp(&right.transport_group_id))
                });
                if demand.cause == storage_sqlite::RecoveryCause::Maintenance {
                    routes.truncate(1);
                }
                for route in routes {
                    let transport_group_id = route
                        .transport_group_id
                        .as_slice()
                        .try_into()
                        .map_err(|_| {
                            StorageError::Serialization("invalid recovery transport route".into())
                        })?;
                    let mut endpoints = route
                        .endpoints
                        .iter()
                        .map(|endpoint| endpoint.0.clone())
                        .collect::<Vec<_>>();
                    endpoints.sort();
                    endpoints.dedup();
                    scopes.push(RecoveryScopePlan {
                        scope_id: scopes.len() as u64,
                        route_kind: 1,
                        route_role: 0,
                        group_id: Some(route.group_id.as_slice().to_vec()),
                        transport_group_id: Some(transport_group_id),
                        since_seconds: since,
                        until_seconds: goal_until,
                        known_event_id: demand.known_event_id,
                        inventory_floor: None,
                        required_endpoints: endpoints,
                        admitted_endpoints: self
                            .adapter
                            .recovery_admitted_endpoints(&route.endpoints),
                    });
                }
                if scopes.is_empty() {
                    scopes.push(RecoveryScopePlan {
                        scope_id: 0,
                        route_kind: 2,
                        route_role: 0,
                        group_id: demand.group_id.clone(),
                        transport_group_id: None,
                        since_seconds: since,
                        until_seconds: goal_until,
                        known_event_id: demand.known_event_id,
                        inventory_floor: None,
                        required_endpoints: Vec::new(),
                        admitted_endpoints: Vec::new(),
                    });
                }
                if !stored.is_empty() {
                    let mut next_id = stored
                        .iter()
                        .map(|scope| scope.plan.scope_id)
                        .max()
                        .unwrap_or(0)
                        .saturating_add(1);
                    for scope in &mut scopes {
                        if let Some(old) = stored.iter().find(|old| {
                            old.plan.route_kind == scope.route_kind
                                && old.plan.group_id == scope.group_id
                                && old.plan.transport_group_id == scope.transport_group_id
                        }) {
                            scope.scope_id = old.plan.scope_id;
                            scope.since_seconds = old.plan.since_seconds;
                            scope.until_seconds = goal_until;
                            scope.inventory_floor = old.plan.inventory_floor;
                            scope
                                .required_endpoints
                                .extend(old.plan.required_endpoints.iter().cloned());
                            scope.required_endpoints.sort();
                            scope.required_endpoints.dedup();
                        } else {
                            scope.scope_id = next_id;
                            next_id = next_id.saturating_add(1);
                        }
                    }
                    for old in stored {
                        if !scopes
                            .iter()
                            .any(|scope| scope.scope_id == old.plan.scope_id)
                        {
                            scopes.push(old.plan);
                        }
                    }
                    scopes.sort_by_key(|scope| scope.scope_id);
                }
                scopes
            };
            goals.push((*id, scopes));
        }
        let mut loss = Vec::new();
        for obligation in demands.iter().filter(|demand| {
            grant
                .fence
                .obligations
                .iter()
                .any(|(id, _)| *id == demand.ticket.id)
        }) {
            let cause = match obligation.cause {
                storage_sqlite::RecoveryCause::QueueLoss => {
                    Some(storage_sqlite::RecoveryLossCause::Queue)
                }
                storage_sqlite::RecoveryCause::NotificationLoss => {
                    Some(storage_sqlite::RecoveryLossCause::NotificationConsumer)
                }
                _ => None,
            };
            if let Some(cause) = cause {
                loss.push(GrantedLoss {
                    id: obligation.ticket.id,
                    watermarks: storage.recovery_loss_snapshot(&self.state.label, cause)?,
                });
            }
        }
        let comparison = storage.recovery_comparison()?;
        let mut comparison_goals = if grant.comparison_revision.is_some() {
            self.comparison_route_goals(comparison.requested_until_seconds)?
        } else {
            Vec::new()
        };
        if let Some(prior) = comparison
            .plan
            .filter(|plan| plan.fence.route_revision == grant.fence.route_revision)
            && !prior.retry_routes.is_empty()
            && !comparison_goals.is_empty()
        {
            let retrying = comparison_goals
                .iter()
                .filter(|goal| {
                    prior.routes.iter().any(|old| {
                        prior.retry_routes.contains(&old.scope_id)
                            && old.route_kind == goal.route_kind
                            && old.transport_group_id == goal.transport_group_id
                            && old.group_id == goal.group_id
                    })
                })
                .cloned()
                .collect::<Vec<_>>();
            if !retrying.is_empty() {
                comparison_goals = retrying;
            }
        }
        let (inventory, rotation_claim) = if grant.comparison_revision.is_some() {
            self.freeze_recovery_inventory(&mut [([0; 16], comparison_goals.clone())])?
        } else {
            self.freeze_recovery_inventory(&mut goals)?
        };
        grant.rotation_claim = rotation_claim;
        if grant.comparison_revision.is_some() {
            let mut routes = Vec::new();
            for item in &inventory {
                if let Some(goal) = comparison_goals.iter().find(|goal| match item.route {
                    storage_sqlite::TransportReconciliationRoute::Inbox => goal.route_kind == 0,
                    storage_sqlite::TransportReconciliationRoute::Group(id) => {
                        goal.transport_group_id == Some(id)
                    }
                }) {
                    let mut goal = goal.clone();
                    goal.since_seconds = Some(item.since);
                    goal.until_seconds = item.until;
                    goal.inventory_floor = Some(item.since);
                    routes.push(goal);
                }
            }
            routes.sort_by_key(|r| r.scope_id);
            grant.comparison_plan = Some(storage_sqlite::RecoveryComparisonPlan {
                fence: grant.fence.clone(),
                live_since_seconds: if independent_broad_acquisition {
                    goals
                        .iter()
                        .filter(|(id, _)| {
                            demands.iter().any(|d| {
                                d.ticket.id == *id
                                    && d.cause != storage_sqlite::RecoveryCause::Maintenance
                            })
                        })
                        .flat_map(|(_, scopes)| scopes)
                        .map(|scope| scope.since_seconds)
                        .collect::<Option<Vec<_>>>()
                        .and_then(|bounds| bounds.into_iter().min())
                } else {
                    self.subscription_rebuild_since()?.map(|t| t.0)
                },
                routes,
                retry_routes: Vec::new(),
            });
        }
        let Some(mut grant) = self
            .recovery_owner
            .freeze_plan(&storage, grant, goals, explicit)?
        else {
            return Err(
                StorageError::Backend("recovery plan changed before activation".into()).into(),
            );
        };

        grant.inventory = inventory;
        grant.loss = loss;
        Ok(Some(grant))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-checked handoff shape only. The #1947 executor will submit the
    /// owned events to the worker and return endpoint evidence to this owner.
    #[test]
    fn owned_acquisition_result_can_travel_with_an_existing_grant() {
        use transport_nostr_adapter::{
            NostrAcquisitionEnd, NostrAcquisitionEndpoint, NostrAcquisitionResult,
            NostrAcquisitionStats,
        };

        fn stage_for_worker(
            grant: AttemptGrant,
            result: NostrAcquisitionResult,
        ) -> (
            AttemptGrant,
            Vec<transport_nostr_peeler::NostrTransportEvent>,
            Vec<NostrAcquisitionEndpoint>,
        ) {
            let mut endpoints = result.endpoints;
            let events = endpoints
                .iter_mut()
                .flat_map(|endpoint| std::mem::take(&mut endpoint.events))
                .collect();
            (grant, events, endpoints)
        }

        let (storage, mut owner, now) = fixture();
        let grant = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
            .unwrap()
            .unwrap();
        let attempt = grant.reservation.attempt_serial;
        let result = NostrAcquisitionResult {
            endpoints: vec![NostrAcquisitionEndpoint {
                endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                session_generation: Some(12),
                events: vec![transport_nostr_peeler::NostrTransportEvent {
                    id: "03".repeat(32),
                    pubkey: "04".repeat(32),
                    created_at: 1,
                    kind: 445,
                    tags: Vec::new(),
                    content: "owned bytes".into(),
                    sig: None,
                }],
                end: NostrAcquisitionEnd::ByteLimitReached,
                stats: NostrAcquisitionStats::default(),
            }],
        };
        let (grant, worker_input, endpoints) = stage_for_worker(grant, result);
        assert_eq!(grant.reservation.attempt_serial, attempt);
        assert_eq!(worker_input.len(), 1);
        assert_eq!(endpoints[0].end, NostrAcquisitionEnd::ByteLimitReached);
    }

    fn fixture() -> (SqliteAccountStorage, AccountRecoveryOwner, Instant) {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        storage.ensure_account_projection("alice").unwrap();
        storage
            .mark_account_delivery_recovery("alice", 1, 1)
            .unwrap();
        let now = Instant::now();
        let owner = AccountRecoveryOwner::open(&storage, 1_000_000, now, policy()).unwrap();
        (storage, owner, now)
    }

    fn policy() -> RecoveryRetryPolicy {
        RecoveryRetryPolicy {
            base: Duration::from_secs(15),
            cap: Duration::from_secs(300),
        }
    }

    #[test]
    fn owner_retry_policy_caps_extreme_ordinals_and_validates_bounds() {
        assert_eq!(policy().delay_ms(u64::MAX).unwrap(), 300_000);
        let oversized = RecoveryRetryPolicy {
            base: Duration::from_secs(600),
            cap: Duration::from_secs(600),
        };
        assert_eq!(oversized.delay_ms(0).unwrap(), 600_000);
        assert_eq!(oversized.delay_ms(u64::MAX).unwrap(), 600_000);
        assert!(
            RecoveryRetryPolicy {
                base: Duration::ZERO,
                ..policy()
            }
            .delay_ms(0)
            .is_err()
        );
        assert!(
            RecoveryRetryPolicy {
                base: Duration::from_secs(301),
                ..policy()
            }
            .delay_ms(0)
            .is_err()
        );
    }

    #[test]
    fn automatic_attempts_share_one_durable_exponential_schedule() {
        let (storage, mut owner, now) = fixture();
        for (index, seconds) in [0, 15, 45, 105, 225, 465, 765].into_iter().enumerate() {
            let due = now + Duration::from_secs(seconds);
            if seconds > 0 {
                assert!(
                    owner
                        .select_authorized_attempt(
                            &storage,
                            RecoveryReadiness::Ready,
                            due - Duration::from_millis(1),
                            None
                        )
                        .unwrap()
                        .is_none()
                );
            }
            let grant = owner
                .select_authorized_attempt(&storage, RecoveryReadiness::Ready, due, None)
                .unwrap()
                .unwrap();
            assert_eq!(grant.reservation.ordinal, index as u64 + 1);
            assert_eq!(grant.fence.obligations.len(), 1);
            assert!(
                owner
                    .select_authorized_attempt(&storage, RecoveryReadiness::Ready, due, None)
                    .unwrap()
                    .is_none()
            );
            drop(grant);
            storage
                .mark_account_delivery_recovery("alice", 1, 1)
                .unwrap();
            assert!(
                owner
                    .select_authorized_attempt(&storage, RecoveryReadiness::Unknown, due, None)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn cancellation_releases_only_the_transient_grant_and_explicit_override_is_once() {
        let (storage, mut owner, now) = fixture();
        let grant = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
            .unwrap()
            .unwrap();
        let mut caller = ExplicitRecoveryPermit::default();
        assert!(
            owner
                .select_authorized_attempt(
                    &storage,
                    RecoveryReadiness::Ready,
                    now,
                    Some(&mut caller)
                )
                .unwrap()
                .is_none()
        );
        assert!(!caller.spent);
        drop(grant);
        let explicit = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, Some(&mut caller))
            .unwrap()
            .unwrap();
        assert!(!caller.spent, "selection alone cannot consume the override");
        let goals = explicit
            .fence
            .obligations
            .iter()
            .map(|(id, _)| {
                (
                    *id,
                    vec![RecoveryScopePlan {
                        scope_id: 0,
                        route_kind: 0,
                        route_role: 0,
                        group_id: None,
                        transport_group_id: None,
                        since_seconds: None,
                        until_seconds: 10,
                        known_event_id: None,
                        inventory_floor: None,
                        required_endpoints: vec!["relay".into()],
                        admitted_endpoints: vec!["relay".into()],
                    }],
                )
            })
            .collect();
        let explicit = owner
            .freeze_plan(&storage, explicit, goals, Some(&mut caller))
            .unwrap()
            .unwrap();
        assert!(caller.spent);
        assert_eq!(explicit.reservation.attempt_serial, 2);
        drop(explicit);
        assert!(
            owner
                .select_authorized_attempt(
                    &storage,
                    RecoveryReadiness::Ready,
                    now,
                    Some(&mut caller)
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            storage.recovery_revision_fence().unwrap().obligations.len(),
            1
        );
    }

    #[test]
    fn readiness_wait_and_mode_handoff_preserve_pending_state_and_retry_cost() {
        let (storage, mut owner, now) = fixture();
        let before = storage.recovery_revision_fence().unwrap();
        assert!(
            owner
                .select_authorized_attempt(&storage, RecoveryReadiness::Waiting, now, None)
                .unwrap()
                .is_none()
        );
        assert_eq!(storage.recovery_retry_state().unwrap().attempt_serial, 0);
        let grant = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Unknown, now, None)
            .unwrap()
            .unwrap();
        assert_eq!(owner.mode, RecoveryExecutorMode::Normal);
        assert!(!owner.select_executor_mode(RecoveryExecutorMode::Conservative));
        drop(grant);
        assert!(owner.select_executor_mode(RecoveryExecutorMode::Conservative));
        assert!(
            owner
                .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
                .unwrap()
                .is_none()
        );
        let grant = owner
            .select_authorized_attempt(
                &storage,
                RecoveryReadiness::Ready,
                now + Duration::from_secs(15),
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(owner.mode, RecoveryExecutorMode::Conservative);
        drop(grant);
        assert!(owner.select_executor_mode(RecoveryExecutorMode::Normal));
        assert_eq!(storage.recovery_revision_fence().unwrap(), before);
        assert_eq!(storage.recovery_retry_state().unwrap().attempt_serial, 2);
    }

    #[test]
    fn conservative_grants_do_not_coalesce_or_buy_an_extra_retry() {
        let (storage, mut owner, now) = fixture();
        storage
            .request_recovery(
                storage_sqlite::RecoveryRequest::IncrementalHistory,
                1_000_000,
            )
            .unwrap();
        let before = storage.recovery_revision_fence().unwrap();
        let normal = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
            .unwrap()
            .unwrap();
        assert_eq!(normal.fence.obligations.len(), 2);
        assert!(!owner.select_executor_mode(RecoveryExecutorMode::Conservative));
        drop(normal); // cancellation before activation preserves both obligations
        let retry = storage.recovery_retry_state().unwrap();
        drop(owner);
        let mut owner = AccountRecoveryOwner::open(&storage, 1_000_000, now, policy()).unwrap();
        assert!(owner.select_executor_mode(RecoveryExecutorMode::Conservative));
        assert_eq!(storage.recovery_retry_state().unwrap(), retry);
        assert!(
            owner
                .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
                .unwrap()
                .is_none()
        );
        let single = owner
            .select_authorized_attempt(
                &storage,
                RecoveryReadiness::Ready,
                now + Duration::from_secs(15),
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(single.fence.obligations.len(), 1);
        assert_eq!(owner.mode, RecoveryExecutorMode::Conservative);
        drop(single);
        assert!(owner.select_executor_mode(RecoveryExecutorMode::Normal));
        assert!(
            owner
                .select_authorized_attempt(
                    &storage,
                    RecoveryReadiness::Ready,
                    now + Duration::from_secs(44),
                    None
                )
                .unwrap()
                .is_none()
        );
        let combined = owner
            .select_authorized_attempt(
                &storage,
                RecoveryReadiness::Ready,
                now + Duration::from_secs(45),
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(combined.fence.obligations.len(), 2);
        assert_eq!(storage.recovery_revision_fence().unwrap(), before);
    }

    #[tokio::test]
    async fn rejected_plan_preserves_observations_and_unspent_override() {
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
        let mut client = crate::tests::client_on_app_relay_plane(&app, "alice").await;
        let group = client.create_group("maintenance", &[]).await.unwrap();
        let storage = app.account_storage("alice").unwrap();
        let now = Instant::now();
        let mut owner = AccountRecoveryOwner::open(&storage, 1_000_000, now, policy()).unwrap();
        let ticket = storage
            .request_recovery(
                storage_sqlite::RecoveryRequest::MaintenanceBoundary {
                    job_id: &[1],
                    group_id: group.as_slice(),
                },
                1_000_000,
            )
            .unwrap();
        let grant = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
            .unwrap()
            .unwrap();
        let goal = RecoveryScopePlan {
            scope_id: 0,
            route_kind: 1,
            route_role: 0,
            group_id: Some(group.as_slice().to_vec()),
            transport_group_id: Some([9; 32]),
            since_seconds: None,
            until_seconds: 10,
            known_event_id: None,
            inventory_floor: None,
            required_endpoints: vec!["relay".into()],
            admitted_endpoints: vec!["relay".into()],
        };
        let goals = grant
            .fence
            .obligations
            .iter()
            .map(|(id, _)| (*id, vec![goal.clone()]))
            .collect();
        let grant = owner
            .freeze_plan(&storage, grant, goals, None)
            .unwrap()
            .unwrap();
        let maintenance = grant
            .plan()
            .unwrap()
            .iter()
            .find(|o| o.id == ticket.id)
            .unwrap();
        assert!(
            !storage
                .checkpoint_recovery_obligation(
                    &grant.fence,
                    grant.reservation.attempt_serial,
                    ticket.id,
                    &[storage_sqlite::RecoveryScopeCheckpoint {
                        token: maintenance.scopes[0].token.clone(),
                        endpoints: vec![],
                        retained_known_event: false
                    }],
                    storage_sqlite::RecoveryEligibility::WaitingCapability
                )
                .unwrap()
        );
        owner.maintenance_observations.insert(
            group.clone(),
            MaintenanceRecoveryObservation {
                fence: grant.fence.clone(),
                attempt_serial: grant.reservation.attempt_serial,
                id: ticket.id,
                scopes: maintenance.scopes.clone(),
            },
        );
        drop(grant);
        let old = owner.maintenance_observations[&group].clone();
        let mut permit = ExplicitRecoveryPermit::default();
        let rejected = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, Some(&mut permit))
            .unwrap()
            .unwrap();
        let goals = rejected
            .fence
            .obligations
            .iter()
            .map(|(id, _)| (*id, vec![goal.clone()]))
            .collect();
        // This approved off-worker writer can race selection. Its unimported
        // loss must reject freeze without pretending there was no work due.
        storage
            .mark_account_delivery_recovery("alice", 777, 1)
            .unwrap();
        assert!(
            owner
                .freeze_plan(&storage, rejected, goals, Some(&mut permit))
                .unwrap()
                .is_none()
        );
        assert!(
            !permit.spent,
            "a rejected plan must not consume the caller override"
        );
        assert_eq!(
            owner.maintenance_observations[&group].attempt_serial,
            old.attempt_serial
        );
        assert!(owner.active.upgrade().is_none());
        let reserved = storage.recovery_retry_state().unwrap();
        assert_eq!(
            reserved.attempt_serial, 2,
            "failed preparation still retains retry cost"
        );
        storage.synchronize_account_delivery_loss("alice").unwrap();
        assert!(
            !storage
                .checkpoint_recovery_obligation(
                    &old.fence,
                    old.attempt_serial,
                    old.id,
                    &[storage_sqlite::RecoveryScopeCheckpoint {
                        token: old.scopes[0].token.clone(),
                        endpoints: vec![storage_sqlite::RecoveryEndpointCheckpoint {
                            endpoint: "relay".into(),
                            outcome: storage_sqlite::RecoveryScopeOutcome::Partial,
                            exhaustive: false,
                            admission_complete: false,
                            first_boundary: true,
                        }],
                        retained_known_event: false,
                    }],
                    storage_sqlite::RecoveryEligibility::Retry
                )
                .unwrap()
        );
        let successor = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, Some(&mut permit))
            .unwrap()
            .unwrap();
        assert!(
            successor
                .fence
                .obligations
                .iter()
                .any(|(id, _)| *id == old.id)
        );
        let goals = successor
            .fence
            .obligations
            .iter()
            .map(|(id, _)| (*id, vec![goal.clone()]))
            .collect();
        let successor = owner
            .freeze_plan(&storage, successor, goals, Some(&mut permit))
            .unwrap()
            .unwrap();
        // The successful freeze consumes one override and releases observations
        // only when a successor can actually be dispatched.
        assert!(owner.maintenance_observations.is_empty());
        assert!(permit.spent);
        drop(successor);
        assert!(
            owner
                .select_authorized_attempt(
                    &storage,
                    RecoveryReadiness::Ready,
                    now,
                    Some(&mut permit)
                )
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn conservative_activation_keeps_displaced_unqualified_maintenance_selectable() {
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
        let mut client = crate::tests::client_on_app_relay_plane(&app, "alice").await;
        let group = client.create_group("maintenance", &[]).await.unwrap();
        let storage = app.account_storage("alice").unwrap();
        let now = Instant::now();
        let mut owner = AccountRecoveryOwner::open(&storage, 1_000_000, now, policy()).unwrap();
        let ticket = storage
            .request_recovery(
                storage_sqlite::RecoveryRequest::MaintenanceBoundary {
                    job_id: &[1],
                    group_id: group.as_slice(),
                },
                1_000_000,
            )
            .unwrap();
        let grant = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
            .unwrap()
            .unwrap();
        let goal = RecoveryScopePlan {
            scope_id: 0,
            route_kind: 1,
            route_role: 0,
            group_id: Some(group.as_slice().to_vec()),
            transport_group_id: Some([9; 32]),
            since_seconds: None,
            until_seconds: 10,
            known_event_id: None,
            inventory_floor: None,
            required_endpoints: vec!["relay".into()],
            admitted_endpoints: vec!["relay".into()],
        };
        let goals = grant
            .fence
            .obligations
            .iter()
            .map(|(id, _)| (*id, vec![goal.clone()]))
            .collect();
        let grant = owner
            .freeze_plan(&storage, grant, goals, None)
            .unwrap()
            .unwrap();
        let maintenance = grant
            .plan()
            .unwrap()
            .iter()
            .find(|o| o.id == ticket.id)
            .unwrap();
        assert!(
            !storage
                .checkpoint_recovery_obligation(
                    &grant.fence,
                    grant.reservation.attempt_serial,
                    ticket.id,
                    &[storage_sqlite::RecoveryScopeCheckpoint {
                        token: maintenance.scopes[0].token.clone(),
                        endpoints: vec![],
                        retained_known_event: false
                    }],
                    storage_sqlite::RecoveryEligibility::WaitingCapability
                )
                .unwrap()
        );
        owner.maintenance_observations.insert(
            group,
            MaintenanceRecoveryObservation {
                fence: grant.fence.clone(),
                attempt_serial: grant.reservation.attempt_serial,
                id: ticket.id,
                scopes: maintenance.scopes.clone(),
            },
        );
        drop(grant);
        owner.select_executor_mode(RecoveryExecutorMode::Conservative);
        let other = owner
            .select_authorized_attempt(
                &storage,
                RecoveryReadiness::Ready,
                now + Duration::from_secs(15),
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(other.fence.obligations.len(), 1);
        assert_ne!(other.fence.obligations[0].0, ticket.id);
        let pending = storage.pending_recovery_demands().unwrap();
        let maintenance = pending.iter().find(|d| d.ticket.id == ticket.id).unwrap();
        assert_eq!(
            maintenance.eligibility,
            storage_sqlite::RecoveryEligibility::Retry
        );
        assert!(maintenance.ticket.revision > ticket.revision);
        assert!(
            storage
                .recovery_eligible_revision_fence(false)
                .unwrap()
                .obligations
                .iter()
                .any(|(id, _)| *id == ticket.id)
        );
    }

    #[test]
    fn conservative_handoff_retains_partial_proof_and_completes_independently() {
        use storage_sqlite::{
            RecoveryEligibility, RecoveryEndpointCheckpoint, RecoveryRequest,
            RecoveryScopeCheckpoint, RecoveryScopeOutcome,
        };
        let storage = SqliteAccountStorage::in_memory().unwrap();
        storage.ensure_account_projection("alice").unwrap();
        storage
            .request_recovery(RecoveryRequest::IncrementalHistory, 1_000_000)
            .unwrap();
        storage
            .request_recovery(
                RecoveryRequest::ExplicitHistory {
                    operation_id: &[8; 16],
                },
                1_000_000,
            )
            .unwrap();
        let now = Instant::now();
        let mut owner = AccountRecoveryOwner::open(&storage, 1_000_000, now, policy()).unwrap();
        let goal = RecoveryScopePlan {
            scope_id: 0,
            route_kind: 0,
            route_role: 0,
            group_id: None,
            transport_group_id: None,
            since_seconds: Some(1),
            until_seconds: 10,
            known_event_id: None,
            inventory_floor: Some(1),
            required_endpoints: vec!["a".into(), "b".into()],
            admitted_endpoints: vec!["a".into(), "b".into()],
        };
        let proof = |endpoint: &str| RecoveryEndpointCheckpoint {
            endpoint: endpoint.into(),
            outcome: RecoveryScopeOutcome::Covered,
            exhaustive: true,
            admission_complete: true,
            first_boundary: true,
        };
        let grant = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
            .unwrap()
            .unwrap();
        let goals = grant
            .fence
            .obligations
            .iter()
            .map(|(id, _)| (*id, vec![goal.clone()]))
            .collect();
        let grant = owner
            .freeze_plan(&storage, grant, goals, None)
            .unwrap()
            .unwrap();
        assert_eq!(grant.plan().unwrap().len(), 2);
        for obligation in grant.plan().unwrap() {
            assert!(
                !storage
                    .checkpoint_recovery_obligation(
                        &grant.fence,
                        grant.reservation.attempt_serial,
                        obligation.id,
                        &[RecoveryScopeCheckpoint {
                            token: obligation.scopes[0].token.clone(),
                            endpoints: vec![proof("a")],
                            retained_known_event: false
                        }],
                        RecoveryEligibility::Retry
                    )
                    .unwrap()
            );
        }
        drop(grant);
        let retry = storage.recovery_retry_state().unwrap();
        drop(owner);
        let mut owner = AccountRecoveryOwner::open(&storage, 1_000_000, now, policy()).unwrap();
        owner.select_executor_mode(RecoveryExecutorMode::Conservative);
        assert_eq!(storage.recovery_retry_state().unwrap(), retry);
        let first = owner
            .select_authorized_attempt(
                &storage,
                RecoveryReadiness::Ready,
                now + Duration::from_secs(15),
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(first.fence.obligations.len(), 1);
        let id = first.fence.obligations[0].0;
        let first = owner
            .freeze_plan(&storage, first, vec![(id, vec![goal.clone()])], None)
            .unwrap()
            .unwrap();
        assert_eq!(
            storage.recovery_scope_snapshots(id).unwrap()[0]
                .checkpoints
                .len(),
            1
        );
        assert!(
            storage
                .checkpoint_recovery_obligation(
                    &first.fence,
                    first.reservation.attempt_serial,
                    id,
                    &[RecoveryScopeCheckpoint {
                        token: first.plan().unwrap()[0].scopes[0].token.clone(),
                        endpoints: vec![proof("b")],
                        retained_known_event: false
                    }],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
        drop(first);
        let pending = storage.pending_recovery_demands().unwrap();
        assert_eq!(pending.len(), 1);
        assert_ne!(pending[0].ticket.id, id);
        assert_eq!(
            storage
                .recovery_scope_snapshots(pending[0].ticket.id)
                .unwrap()[0]
                .checkpoints
                .len(),
            1
        );
        assert!(
            owner
                .select_authorized_attempt(
                    &storage,
                    RecoveryReadiness::Ready,
                    now + Duration::from_secs(44),
                    None
                )
                .unwrap()
                .is_none()
        );
        let second = owner
            .select_authorized_attempt(
                &storage,
                RecoveryReadiness::Ready,
                now + Duration::from_secs(45),
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            second.fence.obligations,
            vec![(pending[0].ticket.id, pending[0].ticket.revision)]
        );
        drop(second);
        owner.select_executor_mode(RecoveryExecutorMode::Normal);
        assert_eq!(storage.pending_recovery_demands().unwrap().len(), 1);
        assert_eq!(storage.recovery_retry_state().unwrap().attempt_serial, 3);
    }

    #[test]
    fn reopened_owner_observes_reservation_and_uses_monotonic_time_thereafter() {
        let (storage, mut owner, now) = fixture();
        drop(
            owner
                .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
                .unwrap(),
        );
        let reopened_at = now + Duration::from_secs(2);
        let mut reopened =
            AccountRecoveryOwner::open(&storage, 900_000, reopened_at, policy()).unwrap();
        assert_eq!(
            storage.recovery_retry_state().unwrap().not_before_ms,
            915_000
        );
        assert!(
            reopened
                .select_authorized_attempt(
                    &storage,
                    RecoveryReadiness::Ready,
                    reopened_at + Duration::from_secs(14),
                    None
                )
                .unwrap()
                .is_none()
        );
        assert!(
            reopened
                .select_authorized_attempt(
                    &storage,
                    RecoveryReadiness::Ready,
                    reopened_at + Duration::from_secs(15),
                    None
                )
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn only_new_durable_admission_resets_pacing_with_a_minimum_activation_delay() {
        let (storage, mut owner, now) = fixture();
        drop(
            owner
                .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
                .unwrap(),
        );
        let grant = owner
            .select_authorized_attempt(
                &storage,
                RecoveryReadiness::Ready,
                now + Duration::from_secs(15),
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(grant.reservation.not_before_ms, 1_045_000);
        assert!(
            owner
                .observe_durable_admission(&storage, &grant, now + Duration::from_secs(17))
                .unwrap()
        );
        assert!(
            !owner
                .observe_durable_admission(&storage, &grant, now + Duration::from_secs(25))
                .unwrap()
        );
        assert_eq!(
            storage.recovery_retry_state().unwrap().not_before_ms,
            1_032_000
        );
        drop(grant);
        assert!(
            owner
                .select_authorized_attempt(
                    &storage,
                    RecoveryReadiness::Ready,
                    now + Duration::from_secs(31),
                    None
                )
                .unwrap()
                .is_none()
        );
        assert!(
            owner
                .select_authorized_attempt(
                    &storage,
                    RecoveryReadiness::Ready,
                    now + Duration::from_secs(32),
                    None
                )
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn scoped_progress_rejects_unrelated_windows_and_invalidated_attempts() {
        let (storage, mut owner, now) = fixture();
        drop(
            owner
                .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
                .unwrap()
                .unwrap(),
        );
        let later = now + Duration::from_secs(15);
        let grant = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, later, None)
            .unwrap()
            .unwrap();
        let id = grant.fence.obligations[0].0;
        let scope = RecoveryScopePlan {
            scope_id: 0,
            route_kind: 0,
            route_role: 0,
            group_id: None,
            transport_group_id: None,
            since_seconds: Some(5),
            until_seconds: 10,
            known_event_id: None,
            inventory_floor: None,
            required_endpoints: vec!["relay".into()],
            admitted_endpoints: vec!["relay".into()],
        };
        let grant = owner
            .freeze_plan(&storage, grant, vec![(id, vec![scope])], None)
            .unwrap()
            .unwrap();
        let inbox = storage_sqlite::TransportReconciliationRoute::Inbox;
        assert!(
            !owner
                .observe_scoped_admission(&storage, &inbox, 4, later)
                .unwrap()
        );
        assert!(
            !owner
                .observe_scoped_admission(&storage, &inbox, 11, later)
                .unwrap()
        );
        assert!(
            !owner
                .observe_scoped_admission(
                    &storage,
                    &storage_sqlite::TransportReconciliationRoute::Group([9; 32]),
                    7,
                    later
                )
                .unwrap()
        );
        storage
            .record_account_delivery_loss("alice", 33, 1, 1)
            .unwrap();
        assert!(
            !owner
                .observe_scoped_admission(&storage, &inbox, 7, later)
                .unwrap()
        );
        drop(grant);
        assert!(
            !owner
                .observe_scoped_admission(&storage, &inbox, 7, later)
                .unwrap()
        );
        assert_eq!(storage.recovery_retry_state().unwrap().ordinal, 2);
    }

    #[test]
    fn executor_grant_contains_frozen_goals_and_checkpoint_tokens() {
        let (storage, mut owner, now) = fixture();
        let grant = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
            .unwrap()
            .unwrap();
        assert!(grant.plan().is_none());
        let id = grant.fence.obligations[0].0;
        let goal = RecoveryScopePlan {
            scope_id: 0,
            route_kind: 0,
            route_role: 0,
            group_id: None,
            transport_group_id: None,
            since_seconds: None,
            until_seconds: 10,
            known_event_id: None,
            inventory_floor: Some(5),
            required_endpoints: vec!["relay".into()],
            admitted_endpoints: vec!["relay".into()],
        };
        let grant = owner
            .freeze_plan(&storage, grant, vec![(id, vec![goal])], None)
            .unwrap()
            .unwrap();
        let plan = grant.plan().unwrap();
        assert_eq!(plan[0].id, id);
        assert_eq!(plan[0].scopes[0].goal.until_seconds, 10);
        assert_eq!(plan[0].scopes[0].token.scope_id, 0);
        let restored = storage.recovery_scope_snapshots(id).unwrap();
        assert_eq!(restored[0].plan.until_seconds, 10);
        assert!(restored[0].token == plan[0].scopes[0].token);
        let admission = owner.active_admission.clone();
        assert!(admission.upgrade().is_some());
        drop(grant);
        assert!(
            admission.upgrade().is_none(),
            "the last grant owns the frozen admission snapshot"
        );
        assert_eq!(storage.pending_recovery_demands().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn completed_known_event_metadata_waits_for_grant_release_then_is_reclaimed() {
        use storage_sqlite::{RecoveryEligibility, RecoveryRequest, RecoveryScopeCheckpoint};
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
        let mut client = crate::tests::client_on_app_relay_plane(&app, "alice").await;
        let group = client.create_group("retirement", &[]).await.unwrap();
        let storage = app.account_storage("alice").unwrap();
        let complete = storage
            .request_recovery(
                RecoveryRequest::KnownEvent {
                    group_id: group.as_slice(),
                    event_id: &[1; 32],
                },
                1,
            )
            .unwrap();
        let pending = storage
            .request_recovery(
                RecoveryRequest::KnownEvent {
                    group_id: group.as_slice(),
                    event_id: &[2; 32],
                },
                1,
            )
            .unwrap();
        let grant = client
            .authorize_account_recovery(
                None,
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .unwrap()
            .unwrap();
        let obligation = grant
            .plan()
            .unwrap()
            .iter()
            .find(|o| o.id == complete.id)
            .unwrap();
        // Supply the admission fact for this metadata-lifetime test. Runtime
        // retained-copy validation is exercised separately by ingress tests.
        let checkpoints = obligation
            .scopes
            .iter()
            .map(|scope| RecoveryScopeCheckpoint {
                token: scope.token.clone(),
                retained_known_event: true,
                endpoints: vec![],
            })
            .collect::<Vec<_>>();
        assert!(
            storage
                .checkpoint_recovery_obligation(
                    &grant.fence,
                    grant.reservation.attempt_serial,
                    complete.id,
                    &checkpoints,
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
        let retry = storage.recovery_retry_state().unwrap();
        assert!(
            client
                .authorize_account_recovery(
                    None,
                    marmot_forensics::EpochBackfillExecutionSeam::Receive
                )
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .recovery_obligation_is_satisfied(complete.id, complete.revision)
                .unwrap(),
            "a live grant can still need its completion verdict"
        );
        let stale_fence = grant.fence.clone();
        drop(grant);
        assert!(
            client
                .authorize_account_recovery(
                    None,
                    marmot_forensics::EpochBackfillExecutionSeam::Receive
                )
                .unwrap()
                .is_none(),
            "reclamation cannot bypass cooldown"
        );
        assert!(
            storage
                .recovery_scope_snapshots(complete.id)
                .unwrap()
                .is_empty(),
            "completed known-event scopes must not accumulate after their last grant drops"
        );
        assert!(
            !storage
                .recovery_obligation_is_satisfied(complete.id, complete.revision)
                .unwrap()
        );
        assert!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|d| d.ticket.id == pending.id)
        );
        assert_eq!(storage.recovery_retry_state().unwrap(), retry);
        assert!(
            !storage
                .checkpoint_recovery_obligation(
                    &stale_fence,
                    retry.attempt_serial,
                    complete.id,
                    &checkpoints,
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
    }

    #[tokio::test]
    async fn post_join_boundary_completes_only_its_predicate_and_keeps_grace_fixed() {
        verify_post_join_boundary_and_grace(RecoveryExecutorMode::Normal).await;
        verify_post_join_boundary_and_grace(RecoveryExecutorMode::Conservative).await;
    }

    async fn verify_maintenance_activation_floor(incremental: bool) {
        use crate::tests::{
            ScriptedPushRelayClient, bounded_epoch_backfill_config, client_on_app_relay_plane,
            every_subscription, scripted_eose_pump,
        };
        use cgka_traits::storage::MaintenanceStorage;
        let directory = tempfile::tempdir().unwrap();
        crate::AccountHome::open(directory.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = crate::MarmotApp::with_relay_and_config(
            directory.path(),
            "wss://relay.example",
            bounded_epoch_backfill_config().with_dev_epoch_backfill_retry_backoff_ms(15_000),
        )
        .with_test_relay_client(relay.clone());
        app.relay_plane = crate::MarmotRelayPlane::new_with_loopback(
            Some(Duration::from_secs(120)),
            relay.clone(),
            true,
        );
        let _pump = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group = client
            .create_group("maintenance predicate", &[])
            .await
            .unwrap();
        let storage = app.account_storage("alice").unwrap();
        let job = cgka_traits::MaintenanceObligation {
            id: cgka_traits::MessageId::new(vec![55; 32]),
            group_id: group.clone(),
            trigger: cgka_traits::MaintenanceTrigger::PostJoin,
            phase: cgka_traits::MaintenancePhase::CatchUp,
            created_at: cgka_traits::Timestamp(unix_now_seconds()),
            operational_target_at: None,
            overdue: false,
            eose_deadline_at: None,
            grace_until: None,
            quiet_since: None,
            own_leaf_baseline_hash: None,
            sampled_jitter_ms: 0,
            not_before: None,
            attempt_count: 0,
            semantic_rearm_count: 0,
            last_failure_code: None,
        };
        storage.put_maintenance_obligation(&job).unwrap();
        let cursor = unix_now_seconds().saturating_sub(300);
        client.checkpointed_transport_timestamp = Some(cursor);
        client.state.last_transport_timestamp = Some(cursor);
        app.save_state(&client.state).unwrap();
        let expected = client.subscription_rebuild_since().unwrap();
        // Park the initial no-cursor investigation through its honest outcome.
        let initial = client
            .authorize_account_recovery(
                None,
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .unwrap()
            .unwrap();
        client
            .execute_recovery_grant(initial, None, None)
            .await
            .unwrap();
        if incremental {
            storage
                .request_recovery(
                    storage_sqlite::RecoveryRequest::IncrementalHistory,
                    unix_now_seconds() * 1000,
                )
                .unwrap();
        }
        storage
            .request_recovery(
                storage_sqlite::RecoveryRequest::MaintenanceBoundary {
                    job_id: &serde_json::to_vec(&(job.id.as_slice(), job.semantic_rearm_count))
                        .unwrap(),
                    group_id: group.as_slice(),
                },
                unix_now_seconds() * 1000,
            )
            .unwrap();
        let before = relay.accepted_subscriptions().len();
        // Advance the injected owner clock to the real retry deadline. An
        // explicit override would deliberately reopen parked history as well.
        client.recovery_owner.wall_anchor_ms =
            storage.recovery_retry_state().unwrap().not_before_ms;
        client.recovery_owner.monotonic_anchor = Instant::now();
        let mut permit = incremental.then(ExplicitRecoveryPermit::default);
        let grant = client
            .authorize_account_recovery(
                permit.as_mut(),
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .unwrap()
            .unwrap();
        assert_eq!(grant.plan().unwrap().len(), if incremental { 2 } else { 1 });
        client
            .execute_recovery_grant(grant, None, None)
            .await
            .unwrap();
        let subscriptions = relay.accepted_subscriptions();
        let mut inbox = 0;
        let mut groups = 0;
        let mut maintenance = 0;
        for subscription in &subscriptions[before..] {
            match subscription {
                transport_nostr_adapter::NostrSubscription::AccountInbox { since, .. } => {
                    inbox += 1;
                    assert_eq!(
                        *since,
                        expected.map(|floor| cgka_traits::transport::Timestamp(
                            floor.0.saturating_sub(
                                transport_nostr_adapter::NIP59_TIMESTAMP_TWEAK_SECS
                            )
                        )),
                        "maintenance must preserve the live inbox floor and NIP-59 overlap"
                    );
                }
                transport_nostr_adapter::NostrSubscription::Group { since, .. } => {
                    groups += 1;
                    assert_eq!(
                        *since, expected,
                        "maintenance must preserve the live group floor"
                    );
                }
                transport_nostr_adapter::NostrSubscription::GroupMaintenance { .. } => {
                    maintenance += 1
                }
            }
        }
        assert!(inbox > 0 && groups > 0 && maintenance == 1);
        let (subscription, route) = &client.post_join_maintenance_subscriptions[&group];
        for endpoint in &route.endpoints {
            app.relay_plane
                .handle_relay_eose_for_test(endpoint.clone(), subscription.clone())
                .await;
        }
        client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();
        assert_eq!(
            storage
                .maintenance_obligation(&job.id)
                .unwrap()
                .unwrap()
                .phase,
            cgka_traits::MaintenancePhase::Grace
        );
        let pending = storage.pending_recovery_demands().unwrap();
        assert!(
            pending
                .iter()
                .all(|d| d.cause != storage_sqlite::RecoveryCause::Maintenance)
        );
        // EOSE satisfies only the maintenance boundary, never exhaustive history.
        assert!(
            pending
                .iter()
                .any(|d| d.cause == storage_sqlite::RecoveryCause::IncrementalHistory)
        );
    }

    #[tokio::test]
    async fn frozen_wake_preserves_recovery_debt_and_cost_until_explicit_full_repair() {
        use crate::tests::{
            ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
            scripted_eose_pump,
        };
        let directory = tempfile::tempdir().unwrap();
        crate::AccountHome::open(directory.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = crate::MarmotApp::with_relay_and_config(
            directory.path(),
            "wss://relay.example",
            crate::MarmotAppConfig::default()
                .with_cursor_persistence(crate::CursorPersistence::Frozen),
        )
        .with_test_relay_client(relay.clone());
        let _pump = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let storage = app.account_storage("alice").unwrap();
        storage
            .mark_account_delivery_recovery("alice", 42, 1)
            .unwrap();
        storage.synchronize_account_delivery_loss("alice").unwrap();
        let debt = storage.recovery_revision_fence().unwrap();
        let retry = storage.recovery_retry_state().unwrap();
        let mut caller = ExplicitRecoveryPermit::default();
        assert!(
            client
                .authorize_account_recovery(
                    Some(&mut caller),
                    marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp
                )
                .unwrap()
                .is_none()
        );
        assert!(!caller.spent);
        client.sync().await.unwrap();
        assert_eq!(storage.recovery_revision_fence().unwrap(), debt);
        assert_eq!(storage.recovery_retry_state().unwrap(), retry);
        // The distinct supported repair API still authorizes one attempt, but
        // this backend cannot certify it or release unresolved loss.
        assert!(client.repair_full_history().await.is_err());
        assert_eq!(
            storage.recovery_retry_state().unwrap().attempt_serial,
            retry.attempt_serial + 1
        );
        assert!(
            storage
                .account_delivery_recovery("alice")
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn maintenance_activation_preserves_incremental_and_live_tail_floors() {
        verify_maintenance_activation_floor(true).await;
        verify_maintenance_activation_floor(false).await;
    }

    async fn verify_post_join_boundary_and_grace(mode: RecoveryExecutorMode) {
        use crate::tests::{
            ScriptedPushRelayClient, bounded_epoch_backfill_config, client_on_app_relay_plane,
            every_subscription, scripted_eose_pump,
        };
        use cgka_traits::storage::MaintenanceStorage;
        let directory = tempfile::tempdir().unwrap();
        crate::AccountHome::open(directory.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = crate::MarmotApp::with_relay_and_config(
            directory.path(),
            "wss://relay.example",
            bounded_epoch_backfill_config().with_dev_epoch_backfill_retry_backoff_ms(15_000),
        )
        .with_test_relay_client(relay.clone());
        let _pump = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group = client
            .create_group("maintenance predicate", &[])
            .await
            .unwrap();
        let storage = app.account_storage("alice").unwrap();
        let job = cgka_traits::MaintenanceObligation {
            id: cgka_traits::MessageId::new(vec![55; 32]),
            group_id: group.clone(),
            trigger: cgka_traits::MaintenanceTrigger::PostJoin,
            phase: cgka_traits::MaintenancePhase::CatchUp,
            created_at: cgka_traits::Timestamp(unix_now_seconds()),
            operational_target_at: None,
            overdue: false,
            eose_deadline_at: None,
            grace_until: None,
            quiet_since: None,
            own_leaf_baseline_hash: None,
            sampled_jitter_ms: 0,
            not_before: None,
            attempt_count: 0,
            semantic_rearm_count: 0,
            last_failure_code: None,
        };
        storage.put_maintenance_obligation(&job).unwrap();
        storage
            .request_recovery(
                storage_sqlite::RecoveryRequest::ExplicitHistory {
                    operation_id: &[7; 16],
                },
                unix_now_seconds() * 1000,
            )
            .unwrap();
        client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();
        assert_eq!(client.post_join_maintenance_subscriptions.len(), 1);
        client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();
        let advanced = storage.maintenance_obligation(&job.id).unwrap().unwrap();
        assert_eq!(advanced.phase, cgka_traits::MaintenancePhase::Grace);
        assert!(advanced.grace_until.is_some());
        assert!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.cause == storage_sqlite::RecoveryCause::ExplicitHistory)
        );
        assert!(
            !storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.cause == storage_sqlite::RecoveryCause::Maintenance)
        );
        let attempts = storage.recovery_retry_state().unwrap().attempt_serial;
        client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();
        assert_eq!(
            storage
                .maintenance_obligation(&job.id)
                .unwrap()
                .unwrap()
                .grace_until,
            advanced.grace_until
        );
        assert_eq!(
            storage.recovery_retry_state().unwrap().attempt_serial,
            attempts
        );
        // Another due recovery activation replaces physical sessions. Its one
        // grant restores maintenance too; the grace deadline cannot restart.
        let old_id = client.post_join_maintenance_subscriptions[&group].0.clone();
        assert!(client.recovery_owner.select_executor_mode(mode));
        let mut permit = ExplicitRecoveryPermit::default();
        let grant = client
            .authorize_account_recovery(
                Some(&mut permit),
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .unwrap()
            .unwrap();
        if mode == RecoveryExecutorMode::Conservative {
            assert_eq!(grant.fence.obligations.len(), 1);
        }
        client
            .execute_recovery_grant(grant, None, None)
            .await
            .unwrap();
        let new_id = client.post_join_maintenance_subscriptions[&group].0.clone();
        assert_ne!(old_id, new_id);
        client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();
        assert_eq!(
            storage
                .maintenance_obligation(&job.id)
                .unwrap()
                .unwrap()
                .grace_until,
            advanced.grace_until
        );
        assert_eq!(
            storage.recovery_retry_state().unwrap().attempt_serial,
            attempts + 1
        );

        // Losing the physical session through Grace creates one paced restore,
        // reusing the bounded domain identity and keeping its existing timer.
        client
            .adapter
            .remove_group_maintenance_subscription(&new_id)
            .await
            .unwrap();
        let retry = storage.recovery_retry_state().unwrap();
        client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();
        assert!(
            !client
                .post_join_maintenance_subscriptions
                .contains_key(&group),
            "physical session loss cannot bypass the shared retry deadline"
        );
        assert_eq!(storage.recovery_retry_state().unwrap(), retry);
        assert_eq!(
            storage
                .maintenance_obligation(&job.id)
                .unwrap()
                .unwrap()
                .grace_until,
            advanced.grace_until
        );
        client.recovery_owner.test_advance_to_retry(&storage);
        client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();
        assert_ne!(client.post_join_maintenance_subscriptions[&group].0, new_id);
        assert_eq!(
            storage
                .maintenance_obligation(&job.id)
                .unwrap()
                .unwrap()
                .grace_until,
            advanced.grace_until
        );
    }
    #[test]
    fn outcome_policy_distinguishes_unknown_input_from_proven_incapability() {
        use storage_sqlite::{
            RecoveryCause as C, RecoveryEligibility as E, RecoveryScopeOutcome as O,
        };
        assert_eq!(
            eligibility_after_observation(C::EpochGap, O::Unknown, true, false),
            E::Retry
        );
        assert_eq!(
            eligibility_after_observation(C::KnownEvent, O::BudgetExhausted, true, false),
            E::Retry
        );
        assert_eq!(
            eligibility_after_observation(C::EpochGap, O::Unsupported, true, false),
            E::WaitingCapability
        );
        assert_eq!(
            eligibility_after_observation(C::QueueLoss, O::Unknown, false, false),
            E::Retry
        );
        assert_eq!(
            eligibility_after_observation(C::NotificationLoss, O::BudgetExhausted, true, false),
            E::NeedsDeepRepair
        );
        assert_eq!(
            eligibility_after_observation(C::QueueLoss, O::Unavailable, true, false),
            E::Retry
        );
        assert_eq!(
            eligibility_after_observation(C::QueueLoss, O::Unknown, true, true),
            E::WaitingCapacity
        );
        assert_eq!(
            eligibility_after_observation(C::Maintenance, O::Unknown, true, false),
            E::Retry
        );
    }

    #[tokio::test]
    async fn unknown_history_is_bounded_while_epoch_input_remains_retryable() {
        use crate::tests::{
            ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
            scripted_eose_pump,
        };
        use storage_sqlite::{RecoveryCause, RecoveryEligibility};
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let _pump = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group = client.create_group("retry policy", &[]).await.unwrap();
        let epoch = client.group_mls_state(&group).unwrap().epoch;
        let storage = app.account_storage("alice").unwrap();
        storage
            .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(group.as_slice()),
                stalled_epoch: epoch,
            }])
            .unwrap();
        storage
            .mark_account_delivery_recovery("alice", 42, 1)
            .unwrap();
        client.delivery_overflow_recovery_pending = true;
        client.delivery_overflow_recovery_marker_token = Some(42);
        let grant = client
            .authorize_account_recovery(
                None,
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .unwrap()
            .unwrap();
        client
            .execute_recovery_grant(grant, None, None)
            .await
            .unwrap();
        let pending = storage.pending_recovery_demands().unwrap();
        assert_eq!(
            pending
                .iter()
                .find(|d| d.cause == RecoveryCause::EpochGap)
                .unwrap()
                .eligibility,
            RecoveryEligibility::Retry,
            "EOSE without a coverage certificate does not prove missing-epoch acquisition unsupported"
        );
        assert_eq!(
            pending
                .iter()
                .find(|d| d.cause == RecoveryCause::QueueLoss)
                .unwrap()
                .eligibility,
            RecoveryEligibility::NeedsDeepRepair
        );
        assert!(client.delivery_overflow_recovery_pending);
        let attempts = storage.recovery_retry_state().unwrap().attempt_serial;
        for _ in 0..3 {
            client
                .recovery_owner
                .test_advance_clock(Duration::from_secs(300));
            let grant = client
                .authorize_account_recovery(
                    None,
                    marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                )
                .unwrap()
                .unwrap();
            assert!(
                grant
                    .plan()
                    .unwrap()
                    .iter()
                    .all(|o| o.cause == RecoveryCause::EpochGap),
                "expired cooldown cannot rearm unknown account-history debt"
            );
            client
                .execute_recovery_grant(grant, None, None)
                .await
                .unwrap();
        }
        let retry = storage.recovery_retry_state().unwrap();
        assert_eq!(retry.attempt_serial, attempts + 3);
        let now = Instant::now();
        let wall = client.recovery_owner.logical_now_ms(now).unwrap();
        client.recovery_owner = AccountRecoveryOwner::open(&storage, wall, now, policy()).unwrap();
        assert_eq!(storage.recovery_retry_state().unwrap(), retry);
        storage
            .mark_account_delivery_recovery("alice", 42, 1)
            .unwrap();
        assert_eq!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .find(|d| d.cause == RecoveryCause::QueueLoss)
                .unwrap()
                .eligibility,
            RecoveryEligibility::NeedsDeepRepair
        );
        storage
            .mark_account_delivery_recovery("alice", 42, 2)
            .unwrap();
        assert_eq!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .find(|d| d.cause == RecoveryCause::QueueLoss)
                .unwrap()
                .eligibility,
            RecoveryEligibility::Ready
        );
        assert!(
            client
                .authorize_account_recovery(
                    None,
                    marmot_forensics::EpochBackfillExecutionSeam::Maintenance
                )
                .unwrap()
                .is_none(),
            "new loss does not forgive the account retry reservation"
        );
        client.recovery_owner.test_advance_to_retry(&storage);
        let grant = client
            .authorize_account_recovery(
                None,
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .unwrap()
            .unwrap();
        assert!(
            grant
                .plan()
                .unwrap()
                .iter()
                .any(|o| o.cause == RecoveryCause::QueueLoss)
        );
    }

    // Synthetic exhaustive backend evidence, independent of EOSE. Production
    // legacy reconciliation cannot manufacture these endpoint certificates.
    fn qualify_test_obligation(
        storage: &SqliteAccountStorage,
        grant: &AttemptGrant,
        obligation: &GrantedObligation,
    ) {
        let checkpoints = obligation
            .scopes
            .iter()
            .map(|scope| storage_sqlite::RecoveryScopeCheckpoint {
                token: scope.token.clone(),
                retained_known_event: false,
                endpoints: scope
                    .goal
                    .required_endpoints
                    .iter()
                    .map(|endpoint| storage_sqlite::RecoveryEndpointCheckpoint {
                        endpoint: endpoint.clone(),
                        outcome: storage_sqlite::RecoveryScopeOutcome::Covered,
                        exhaustive: true,
                        admission_complete: true,
                        first_boundary: false,
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        assert!(
            storage
                .checkpoint_recovery_obligation(
                    &grant.fence,
                    grant.reservation.attempt_serial,
                    obligation.id,
                    &checkpoints,
                    storage_sqlite::RecoveryEligibility::Retry
                )
                .unwrap()
        );
    }

    #[tokio::test]
    async fn conservative_loss_causes_acknowledge_together_after_separate_grants() {
        verify_conservative_loss_handoff(false).await;
        verify_conservative_loss_handoff(true).await;
    }

    async fn verify_conservative_loss_handoff(reopen: bool) {
        use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
        use storage_sqlite::{RecoveryCause, RecoveryLossCause};
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let storage = app.account_storage("alice").unwrap();
        storage
            .record_account_recovery_loss("alice", RecoveryLossCause::Queue, 55, 1, 1)
            .unwrap();
        storage
            .record_account_recovery_loss(
                "alice",
                RecoveryLossCause::NotificationConsumer,
                56,
                0,
                1,
            )
            .unwrap();
        client.delivery_overflow_recovery_pending = true;
        client.delivery_overflow_recovery_marker_token = Some(55);
        let grant = client
            .authorize_account_recovery(
                None,
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .unwrap()
            .unwrap();
        for obligation in grant
            .plan()
            .unwrap()
            .iter()
            .filter(|o| o.cause == RecoveryCause::IncrementalHistory)
        {
            qualify_test_obligation(&storage, &grant, obligation);
        }
        drop(grant);
        client
            .recovery_owner
            .select_executor_mode(RecoveryExecutorMode::Conservative);
        let mut first_completed = None;
        for index in 0..2 {
            client.recovery_owner.test_advance_to_retry(&storage);
            let grant = client
                .authorize_account_recovery(
                    None,
                    marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                )
                .unwrap()
                .unwrap();
            assert_eq!(grant.plan().unwrap().len(), 1);
            let selected = grant.fence.obligations[0];
            if let Some(first) = first_completed {
                assert_ne!(selected.0, first);
            }
            qualify_test_obligation(&storage, &grant, &grant.plan().unwrap()[0]);
            let attempt = client.adapter.start_delivery_overflow_recovery(55);
            assert_eq!(
                client
                    .finish_qualified_recovery_loss(&grant, attempt)
                    .unwrap(),
                index == 1
            );
            if index == 0 {
                assert!(
                    storage
                        .recovery_obligation_is_satisfied(selected.0, selected.1)
                        .unwrap(),
                    "a separately qualified cause must survive while its sibling remains pending"
                );
                assert!(
                    (client.delivery_overflow_recovery_pending
                        || client.adapter.delivery_loss_blocks_cursor())
                );
                assert_eq!(
                    storage
                        .recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
                        .unwrap()
                        .len(),
                    1
                );
                assert_eq!(
                    storage
                        .recovery_loss_watermarks("alice", RecoveryLossCause::NotificationConsumer)
                        .unwrap()
                        .len(),
                    1
                );
                first_completed = Some(selected.0);
                client.adapter.fail_delivery_overflow_recovery();
            }
            drop(grant);
            if index == 0 && reopen {
                let retry = storage.recovery_retry_state().unwrap();
                let now = Instant::now();
                let wall = client.recovery_owner.logical_now_ms(now).unwrap();
                client.recovery_owner =
                    AccountRecoveryOwner::open(&storage, wall, now, policy()).unwrap();
                assert_eq!(storage.recovery_retry_state().unwrap(), retry);
                assert_eq!(
                    storage
                        .pending_recovery_demands()
                        .unwrap()
                        .iter()
                        .filter(|d| matches!(
                            d.cause,
                            RecoveryCause::QueueLoss | RecoveryCause::NotificationLoss
                        ))
                        .count(),
                    2
                );
                assert!(
                    client
                        .recovery_owner
                        .pending_loss_acknowledgments
                        .is_empty()
                );
                assert!(
                    client
                        .authorize_account_recovery(
                            None,
                            marmot_forensics::EpochBackfillExecutionSeam::Maintenance
                        )
                        .unwrap()
                        .is_none()
                );
                client.recovery_owner.test_advance_to_retry(&storage);
                let grant = client
                    .authorize_account_recovery(
                        None,
                        marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(client.recovery_owner.mode, RecoveryExecutorMode::Normal);
                assert_eq!(grant.loss.len(), 2);
                for obligation in grant.plan().unwrap() {
                    qualify_test_obligation(&storage, &grant, obligation);
                }
                let attempt = client.adapter.start_delivery_overflow_recovery(55);
                assert!(
                    client
                        .finish_qualified_recovery_loss(&grant, attempt)
                        .unwrap()
                );
                break;
            }
        }
        assert!(
            !(client.delivery_overflow_recovery_pending
                || client.adapter.delivery_loss_blocks_cursor())
        );
        assert!(
            storage
                .recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
                .unwrap()
                .is_empty()
        );
        assert!(
            storage
                .recovery_loss_watermarks("alice", RecoveryLossCause::NotificationConsumer)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn qualified_loss_completion_rolls_back_all_causes_after_plane_ack_failure() {
        use crate::tests::{
            ScriptedPushRelayClient, bounded_epoch_backfill_config, client_on_app_relay_plane,
        };
        use storage_sqlite::{
            RecoveryEligibility, RecoveryEndpointCheckpoint, RecoveryLossCause,
            RecoveryScopeCheckpoint, RecoveryScopeOutcome,
        };
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = crate::MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example",
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let storage = app.account_storage("alice").unwrap();
        storage
            .record_account_recovery_loss("alice", RecoveryLossCause::Queue, 55, 3, 1)
            .unwrap();
        storage
            .record_account_recovery_loss(
                "alice",
                RecoveryLossCause::NotificationConsumer,
                55,
                1,
                1,
            )
            .unwrap();
        client.delivery_overflow_recovery_pending = true;
        client.delivery_overflow_recovery_marker_token = Some(55);
        let mut permit = ExplicitRecoveryPermit::default();
        let grant = client
            .authorize_account_recovery(
                Some(&mut permit),
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .unwrap()
            .unwrap();
        assert_eq!(grant.loss.len(), 2);
        let attempt = client.adapter.start_delivery_overflow_recovery(55);
        assert!(
            !client
                .finish_qualified_recovery_loss(&grant, attempt)
                .unwrap(),
            "reservation and EOSE-free empty drain are not coverage"
        );
        // A synthetic exhaustive, empty endpoint fixture supplies qualified
        // coverage. The production SDK adapter never fabricates this evidence.
        for obligation in grant.plan().unwrap() {
            let checkpoints = obligation
                .scopes
                .iter()
                .map(|scope| RecoveryScopeCheckpoint {
                    token: scope.token.clone(),
                    retained_known_event: false,
                    endpoints: scope
                        .goal
                        .required_endpoints
                        .iter()
                        .map(|endpoint| RecoveryEndpointCheckpoint {
                            endpoint: endpoint.clone(),
                            outcome: RecoveryScopeOutcome::Covered,
                            exhaustive: true,
                            admission_complete: true,
                            first_boundary: false,
                        })
                        .collect(),
                })
                .collect::<Vec<_>>();
            assert!(
                storage
                    .checkpoint_recovery_obligation(
                        &grant.fence,
                        grant.reservation.attempt_serial,
                        obligation.id,
                        &checkpoints,
                        RecoveryEligibility::Retry
                    )
                    .unwrap()
            );
        }
        let path = app.account_storage_path("alice");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let key = app
            .sqlcipher_key("alice", &keys, &path, crate::SqlcipherDatabaseKind::Session)
            .unwrap();
        let connection = rusqlite::Connection::open(path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &connection,
            &key,
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        connection.execute_batch("CREATE TRIGGER fail_loss_reclaim BEFORE DELETE ON account_delivery_loss_evidence WHEN OLD.cause=1 BEGIN SELECT RAISE(FAIL, 'injected reclaim failure'); END;").unwrap();
        assert!(
            client
                .finish_qualified_recovery_loss(&grant, attempt)
                .is_err()
        );
        assert!(
            client.adapter.pending_delivery_overflow().is_some(),
            "plane guard restored after SQL failure"
        );
        assert!(client.delivery_overflow_recovery_pending);
        for cause in [
            RecoveryLossCause::Queue,
            RecoveryLossCause::NotificationConsumer,
        ] {
            assert_eq!(
                storage
                    .recovery_loss_watermarks("alice", cause)
                    .unwrap()
                    .len(),
                1,
                "both cause deletions roll back together"
            );
        }
        assert_eq!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .filter(|demand| matches!(
                    demand.cause,
                    storage_sqlite::RecoveryCause::QueueLoss
                        | storage_sqlite::RecoveryCause::NotificationLoss
                ))
                .count(),
            2
        );
        connection
            .execute_batch("DROP TRIGGER fail_loss_reclaim")
            .unwrap();
        drop(grant);
        let mut permit = ExplicitRecoveryPermit::default();
        let grant = client
            .authorize_account_recovery(
                Some(&mut permit),
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .unwrap()
            .unwrap();
        let attempt = client.adapter.start_delivery_overflow_recovery(55);
        for obligation in grant.plan().unwrap() {
            let checkpoints = obligation
                .scopes
                .iter()
                .map(|scope| RecoveryScopeCheckpoint {
                    token: scope.token.clone(),
                    retained_known_event: false,
                    endpoints: scope
                        .goal
                        .required_endpoints
                        .iter()
                        .map(|endpoint| RecoveryEndpointCheckpoint {
                            endpoint: endpoint.clone(),
                            outcome: RecoveryScopeOutcome::Covered,
                            exhaustive: true,
                            admission_complete: true,
                            first_boundary: false,
                        })
                        .collect(),
                })
                .collect::<Vec<_>>();
            assert!(
                storage
                    .checkpoint_recovery_obligation(
                        &grant.fence,
                        grant.reservation.attempt_serial,
                        obligation.id,
                        &checkpoints,
                        RecoveryEligibility::Retry
                    )
                    .unwrap()
            );
        }
        assert!(
            client
                .finish_qualified_recovery_loss(&grant, attempt)
                .unwrap()
        );
        assert!(!client.delivery_overflow_recovery_pending);
        assert!(client.adapter.pending_delivery_overflow().is_none());
        for cause in [
            RecoveryLossCause::Queue,
            RecoveryLossCause::NotificationConsumer,
        ] {
            assert!(
                storage
                    .recovery_loss_watermarks("alice", cause)
                    .unwrap()
                    .is_empty()
            );
        }
        assert_eq!(storage.restore_unacknowledged_recovery_loss().unwrap(), 0);
    }

    #[tokio::test]
    async fn recovery_inventory_is_frozen_before_io_and_excludes_future_items() {
        use crate::tests::{
            ScriptedPushRelayClient, bounded_epoch_backfill_config, client_on_app_relay_plane,
        };
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = crate::MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example",
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let storage = app.account_storage("alice").unwrap();
        let route = storage_sqlite::TransportReconciliationRoute::Inbox;
        let now = unix_now_seconds();
        let item = |id, created_at| storage_sqlite::TransportReconciliationItem {
            event_id: [id; 32],
            created_at,
        };
        storage
            .record_transport_reconciliation_item(&route, &item(1, now))
            .unwrap();
        storage
            .record_transport_reconciliation_item(&route, &item(2, now + 1000))
            .unwrap();
        storage
            .request_recovery(
                storage_sqlite::RecoveryRequest::IncrementalHistory,
                now * 1000,
            )
            .unwrap();
        let mut permit = ExplicitRecoveryPermit::default();
        let grant = client
            .authorize_account_recovery(
                Some(&mut permit),
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .unwrap()
            .unwrap();
        let frozen = grant
            .inventory
            .iter()
            .find(|snapshot| snapshot.route == route)
            .unwrap();
        assert_eq!(frozen.items.len(), 1);
        assert_eq!(frozen.items[0].event_id, [1; 32]);
        storage
            .record_transport_reconciliation_item(&route, &item(3, now))
            .unwrap();
        assert_eq!(
            frozen.items.len(),
            1,
            "a later admission cannot change an in-flight comparison snapshot"
        );
        assert!(frozen.until <= now + 1);
    }

    fn comparison_goal() -> RecoveryScopePlan {
        RecoveryScopePlan {
            scope_id: 0,
            route_kind: 0,
            route_role: 0,
            group_id: None,
            transport_group_id: None,
            since_seconds: Some(10),
            until_seconds: 100,
            known_event_id: None,
            inventory_floor: Some(10),
            required_endpoints: vec!["wss://relay.example".into()],
            admitted_endpoints: vec!["wss://relay.example".into()],
        }
    }

    fn freeze_comparison(
        owner: &mut AccountRecoveryOwner,
        storage: &SqliteAccountStorage,
        mut grant: AttemptGrant,
    ) -> AttemptGrant {
        grant.comparison_plan =
            grant
                .comparison_revision
                .map(|_| storage_sqlite::RecoveryComparisonPlan {
                    fence: grant.fence.clone(),
                    live_since_seconds: Some(90),
                    routes: vec![comparison_goal()],
                    retry_routes: vec![],
                });
        let goals = grant
            .fence
            .obligations
            .iter()
            .map(|(id, _)| (*id, vec![comparison_goal()]))
            .collect();
        owner
            .freeze_plan(storage, grant, goals, None)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn comparison_only_grant_preserves_cooldown_cancellation_and_scoped_admission() {
        for mode in [
            RecoveryExecutorMode::Normal,
            RecoveryExecutorMode::Conservative,
        ] {
            let storage = SqliteAccountStorage::in_memory().unwrap();
            let now = Instant::now();
            let mut owner = AccountRecoveryOwner::open(&storage, 1_000_000, now, policy()).unwrap();
            owner.select_executor_mode(mode);
            storage
                .join_recovery_comparison(&[1; 16], 1_000_000, &[comparison_goal()])
                .unwrap();
            let first = owner
                .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
                .unwrap()
                .unwrap();
            assert!(first.fence.obligations.is_empty());
            let first = freeze_comparison(&mut owner, &storage, first);
            assert_eq!(
                first.comparison_plan.as_ref().unwrap().live_since_seconds,
                Some(90)
            );
            assert!(first.plan().unwrap().is_empty());
            drop(first); // Cancelled after freeze; the pending slot and cost survive.
            let before = storage.recovery_retry_state().unwrap();
            storage
                .join_recovery_comparison(&[2; 16], 1_001_000, &[comparison_goal()])
                .unwrap();
            let mut owner = AccountRecoveryOwner::open(&storage, 1_001_000, now, policy()).unwrap();
            owner.select_executor_mode(mode);
            assert!(
                owner
                    .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(storage.recovery_retry_state().unwrap(), before);
            let due = now + Duration::from_secs(14);
            let next = owner
                .select_authorized_attempt(&storage, RecoveryReadiness::Ready, due, None)
                .unwrap()
                .unwrap();
            let next = freeze_comparison(&mut owner, &storage, next);
            let route = storage_sqlite::TransportReconciliationRoute::Inbox;
            assert!(
                !owner
                    .observe_scoped_admission(&storage, &route, 9, due)
                    .unwrap()
            );
            assert!(
                !owner
                    .observe_scoped_admission(&storage, &route, 101, due)
                    .unwrap()
            );
            assert!(
                owner
                    .observe_scoped_admission(&storage, &route, 50, due)
                    .unwrap()
            );
            assert_eq!(storage.recovery_retry_state().unwrap().ordinal, 1);
            assert!(
                !owner
                    .observe_scoped_admission(&storage, &route, 50, due)
                    .unwrap()
            );
            drop(next);
            assert!(
                !owner
                    .observe_scoped_admission(&storage, &route, 50, due)
                    .unwrap()
            );
            assert!(storage.recovery_comparison().unwrap().pending());
            assert_eq!(
                storage.pending_recovery_demands().unwrap()[0].eligibility,
                storage_sqlite::RecoveryEligibility::NeedsDeepRepair
            );
        }
    }

    #[test]
    fn comparison_and_coverage_share_one_cost_and_conservative_fairness() {
        for mode in [
            RecoveryExecutorMode::Normal,
            RecoveryExecutorMode::Conservative,
        ] {
            let (storage, mut owner, now) = fixture();
            owner.select_executor_mode(mode);
            storage
                .join_recovery_comparison(&[1; 16], 1_000_000, &[comparison_goal()])
                .unwrap();
            let first = owner
                .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
                .unwrap()
                .unwrap();
            assert!(first.comparison_revision.is_some());
            assert_eq!(
                first.fence.obligations.len(),
                usize::from(mode == RecoveryExecutorMode::Normal)
            );
            let first = freeze_comparison(&mut owner, &storage, first);
            drop(first);
            assert_eq!(storage.recovery_retry_state().unwrap().attempt_serial, 1);
            assert!(
                owner
                    .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, None)
                    .unwrap()
                    .is_none()
            );
            let next = owner
                .select_authorized_attempt(
                    &storage,
                    RecoveryReadiness::Ready,
                    now + Duration::from_secs(15),
                    None,
                )
                .unwrap()
                .unwrap();
            assert_eq!(next.fence.obligations.len(), 1);
            if mode == RecoveryExecutorMode::Conservative {
                assert!(next.comparison_revision.is_none());
            }
            assert_eq!(storage.recovery_retry_state().unwrap().attempt_serial, 2);
            drop(next);
            assert!(
                storage
                    .account_delivery_recovery("alice")
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[test]
    fn comparison_rejected_freeze_rolls_back_coverage_and_preserves_permit() {
        let (storage, mut owner, now) = fixture();
        storage
            .join_recovery_comparison(&[1; 16], 1_000_000, &[comparison_goal()])
            .unwrap();
        let mut permit = ExplicitRecoveryPermit::default();
        let mut grant = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, Some(&mut permit))
            .unwrap()
            .unwrap();
        let id = grant.fence.obligations[0].0;
        let before = storage.recovery_scope_snapshots(id).unwrap().len();
        grant.comparison_plan = Some(storage_sqlite::RecoveryComparisonPlan {
            fence: grant.fence.clone(),
            live_since_seconds: Some(90),
            routes: vec![comparison_goal()],
            retry_routes: vec![],
        });
        // A newer startup/caller joins after selection, invalidating the old slot revision.
        storage
            .join_recovery_comparison(&[2; 16], 1_001_000, &[comparison_goal()])
            .unwrap();
        let goals = grant
            .fence
            .obligations
            .iter()
            .map(|(id, _)| (*id, vec![comparison_goal()]))
            .collect();
        assert!(
            owner
                .freeze_plan(&storage, grant, goals, Some(&mut permit))
                .unwrap()
                .is_none()
        );
        assert!(!permit.spent);
        assert_eq!(storage.recovery_scope_snapshots(id).unwrap().len(), before);
        assert_eq!(storage.recovery_retry_state().unwrap().attempt_serial, 1);
        assert!(storage.recovery_comparison().unwrap().pending());
    }

    #[tokio::test]
    async fn comparison_runtime_retries_failed_route_without_reissuing_successful_sibling() {
        use crate::tests::{
            ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
            scripted_eose_pump,
        };
        for mode in [
            RecoveryExecutorMode::Normal,
            RecoveryExecutorMode::Conservative,
        ] {
            let dir = tempfile::tempdir().unwrap();
            crate::AccountHome::open(dir.path())
                .create_account("alice")
                .unwrap();
            let relay = Arc::new(ScriptedPushRelayClient::default());
            let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
                .with_test_relay_client(relay.clone());
            let _pump =
                scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
            let mut client = client_on_app_relay_plane(&app, "alice").await;
            client.recovery_owner.select_executor_mode(mode);
            client.create_group("comparison routes", &[]).await.unwrap();
            client.request_bounded_comparison().unwrap();
            let storage = app.account_storage("alice").unwrap();
            let grant = client
                .authorize_account_recovery(
                    None,
                    marmot_forensics::EpochBackfillExecutionSeam::Startup,
                )
                .unwrap()
                .unwrap();
            assert_eq!(grant.inventory.len(), 2);
            client.test_comparison_results = Some(
                grant
                    .inventory
                    .iter()
                    .map(|inventory| {
                        Ok(Some(transport_nostr_adapter::NostrReconciliationSummary {
                            relays_succeeded: 1,
                            // Even one failed endpoint keeps the entire group route
                            // retryable when the backend has only aggregate results.
                            relays_failed: usize::from(matches!(
                                inventory.route,
                                storage_sqlite::TransportReconciliationRoute::Group(_)
                            )),
                            ..Default::default()
                        }))
                    })
                    .collect(),
            );
            client
                .execute_recovery_grant(grant, None, None)
                .await
                .unwrap();
            assert!(client.test_comparison_results.as_ref().unwrap().is_empty());
            let pending = storage.recovery_comparison().unwrap();
            assert!(pending.pending());
            let plan = pending.plan.unwrap();
            assert_eq!(plan.retry_routes.len(), 1);
            assert_eq!(
                plan.routes
                    .iter()
                    .find(|r| r.scope_id == plan.retry_routes[0])
                    .unwrap()
                    .route_kind,
                1
            );
            let cost = storage.recovery_retry_state().unwrap();
            assert!(
                client
                    .authorize_account_recovery(
                        None,
                        marmot_forensics::EpochBackfillExecutionSeam::Maintenance
                    )
                    .unwrap()
                    .is_none()
            );
            assert_eq!(storage.recovery_retry_state().unwrap(), cost);
            client.recovery_owner.test_advance_to_retry(&storage);
            let retry = client
                .authorize_account_recovery(
                    None,
                    marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                )
                .unwrap()
                .unwrap();
            assert_eq!(
                retry.inventory.len(),
                1,
                "successful inbox must not consume another route attempt"
            );
            assert!(matches!(
                retry.inventory[0].route,
                storage_sqlite::TransportReconciliationRoute::Group(_)
            ));
            client.test_comparison_results = Some(
                [Ok(Some(
                    transport_nostr_adapter::NostrReconciliationSummary {
                        relays_succeeded: 1,
                        ..Default::default()
                    },
                ))]
                .into(),
            );
            client
                .execute_recovery_grant(retry, None, None)
                .await
                .unwrap();
            assert!(!storage.recovery_comparison().unwrap().pending());
            assert!(
                storage
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .any(
                        |d| d.cause == storage_sqlite::RecoveryCause::IncrementalHistory
                            && d.eligibility
                                == storage_sqlite::RecoveryEligibility::NeedsDeepRepair
                    )
            );
            let revision = storage.recovery_comparison().unwrap().revision;
            let cost = storage.recovery_retry_state().unwrap();
            for _ in 0..3 {
                client
                    .recovery_owner
                    .test_advance_clock(Duration::from_secs(300));
                client
                    .sync_automatically_with_partial_progress()
                    .await
                    .unwrap();
                client.prepare_transport().await.unwrap();
                client
                    .run_pending_epoch_backfill(
                        marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                    )
                    .await
                    .unwrap();
            }
            assert_eq!(
                storage.recovery_comparison().unwrap().revision,
                revision,
                "ticks, reconnect preparation and polling cannot create a request"
            );
            assert_eq!(storage.recovery_retry_state().unwrap(), cost);
        }
    }

    #[tokio::test]
    async fn cancelled_comparison_executor_keeps_intent_cost_and_parked_coverage() {
        use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        client.request_bounded_comparison().unwrap();
        let storage = app.account_storage("alice").unwrap();
        let grant = client
            .authorize_account_recovery(None, marmot_forensics::EpochBackfillExecutionSeam::Startup)
            .unwrap()
            .unwrap();
        let cost = storage.recovery_retry_state().unwrap();
        let revision = grant.comparison_revision.unwrap();
        relay.block_next_subscribe();
        let mut execution = Box::pin(client.execute_recovery_grant(grant, None, None));
        tokio::select! {
            _ = relay.wait_for_blocked_subscribe() => {},
            result = &mut execution => panic!("executor completed before cancellation: {}", result.is_ok()),
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("activation did not reach cancellation boundary"),
        }
        drop(execution);
        assert!(client.recovery_owner.active.upgrade().is_none());
        let slot = storage.recovery_comparison().unwrap();
        assert!(slot.pending());
        assert_eq!(slot.revision, revision);
        assert_eq!(storage.recovery_retry_state().unwrap(), cost);
        assert!(
            client
                .authorize_account_recovery(
                    None,
                    marmot_forensics::EpochBackfillExecutionSeam::Maintenance
                )
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .all(|d| d.eligibility == storage_sqlite::RecoveryEligibility::NeedsDeepRepair)
        );
    }

    #[tokio::test]
    async fn absent_comparison_backend_stays_parked_across_new_startup_requests() {
        use crate::tests::{
            ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
            scripted_eose_pump,
        };
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let _pump = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        client.request_bounded_comparison().unwrap();
        let storage = app.account_storage("alice").unwrap();
        let grant = client
            .authorize_account_recovery(None, marmot_forensics::EpochBackfillExecutionSeam::Startup)
            .unwrap()
            .unwrap();
        client
            .execute_recovery_grant(grant, None, None)
            .await
            .unwrap();
        assert!(
            storage
                .recovery_comparison()
                .unwrap()
                .blocked_route_revision
                .is_some()
        );
        let cost = storage.recovery_retry_state().unwrap();
        for _ in 0..3 {
            client
                .recovery_owner
                .test_advance_clock(Duration::from_secs(300));
            client.request_bounded_comparison().unwrap();
            assert!(
                client
                    .authorize_account_recovery(
                        None,
                        marmot_forensics::EpochBackfillExecutionSeam::Startup
                    )
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(storage.recovery_retry_state().unwrap(), cost);
        assert!(storage.recovery_comparison().unwrap().pending());
    }

    #[tokio::test]
    async fn comparison_quantum_keeps_interrupted_route_retryable_and_unattempted_coverage_pending()
    {
        use crate::tests::{
            ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
            scripted_eose_pump,
        };
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let _pump = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        client.create_group("comparison budget", &[]).await.unwrap();
        client.request_bounded_comparison().unwrap();
        let storage = app.account_storage("alice").unwrap();
        let grant = client
            .authorize_account_recovery(None, marmot_forensics::EpochBackfillExecutionSeam::Startup)
            .unwrap()
            .unwrap();
        assert_eq!(grant.inventory.len(), 2);
        let first = grant.inventory[0].route.clone();
        client.test_comparison_results =
            Some([Ok(Some(Default::default())), Ok(Some(Default::default()))].into());
        client.test_comparison_delay = Some(Duration::from_secs(60));
        tokio::time::timeout(
            Duration::from_secs(15),
            client.execute_recovery_grant(grant, None, None),
        )
        .await
        .unwrap()
        .unwrap();
        let slot = storage.recovery_comparison().unwrap();
        assert!(slot.pending());
        let plan = slot.plan.unwrap();
        assert_eq!(plan.retry_routes.len(), 1);
        let retry = plan
            .routes
            .iter()
            .find(|r| r.scope_id == plan.retry_routes[0])
            .unwrap();
        assert!(match first {
            storage_sqlite::TransportReconciliationRoute::Inbox => retry.route_kind == 0,
            storage_sqlite::TransportReconciliationRoute::Group(id) =>
                retry.transport_group_id == Some(id),
        });
        assert_eq!(
            client.test_comparison_results.as_ref().unwrap().len(),
            2,
            "the second route was never started"
        );
        let debt = storage
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|d| d.cause == storage_sqlite::RecoveryCause::IncrementalHistory)
            .unwrap();
        assert_eq!(
            storage
                .recovery_scope_snapshots(debt.ticket.id)
                .unwrap()
                .len(),
            2,
            "unattempted route coverage cannot disappear"
        );
        assert_eq!(
            debt.eligibility,
            storage_sqlite::RecoveryEligibility::NeedsDeepRepair
        );
    }

    #[test]
    fn explicit_full_history_keeps_its_range_when_comparison_is_pending() {
        let (storage, mut owner, now) = fixture();
        storage
            .join_recovery_comparison(&[1; 16], 1_000_000, &[comparison_goal()])
            .unwrap();
        let mut permit = ExplicitRecoveryPermit::full_history();
        let grant = owner
            .select_authorized_attempt(&storage, RecoveryReadiness::Ready, now, Some(&mut permit))
            .unwrap()
            .unwrap();
        assert!(
            grant.comparison_revision.is_none(),
            "bounded startup intent cannot narrow an explicit full repair"
        );
        assert!(!grant.fence.obligations.is_empty());
        assert!(storage.recovery_comparison().unwrap().pending());
    }
}
