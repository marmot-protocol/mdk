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
    pub(crate) mode: RecoveryExecutorMode,
    pub(crate) seam: marmot_forensics::EpochBackfillExecutionSeam,
    plan: Vec<GrantedObligation>,
    pub(super) inventory: Vec<FrozenRecoveryInventory>,
    loss: Vec<GrantedLoss>,
    _live: Arc<()>,
}

struct GrantedLoss {
    id: [u8; 16],
    watermarks: Vec<storage_sqlite::RecoveryLossWatermark>,
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
        (!self.plan.is_empty()).then_some(self.plan.as_slice())
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
    active_scopes: Vec<RecoveryScopePlan>,
    active_attempt: u64,
    active_fence: Option<RecoveryRevisionFence>,
    policy: RecoveryRetryPolicy,
    mode: RecoveryExecutorMode,
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
        storage.restore_recovery_retry(wall_now_ms, duration_ms(policy.cap)?)?;
        Ok(Self {
            maintenance_observations: std::collections::HashMap::new(),
            wall_anchor_ms: wall_now_ms,
            monotonic_anchor: monotonic_now,
            active: Weak::new(),
            active_scopes: Vec::new(),
            active_attempt: 0,
            active_fence: None,
            policy,
            mode: RecoveryExecutorMode::Normal,
        })
    }

    /// Wall clock is sampled only on open. Later wall-clock corrections cannot
    /// repeatedly reopen the authorization gate within this process.
    #[cfg(test)]
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

    #[cfg(test)]
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
        if self.active.upgrade().is_some() || readiness == RecoveryReadiness::Waiting {
            return Ok(None);
        }
        let now_ms = self.logical_now_ms(now)?;
        storage.release_due_recovery_capacity_probes(now_ms, duration_ms(self.policy.base)?)?;
        let immediate = explicit.as_ref().is_some_and(|permit| !permit.spent);
        let mut fence = storage.recovery_eligible_revision_fence(immediate)?;
        // An installed maintenance subscription is awaiting evidence, not
        // another acquisition. Observations are bound to its original scope
        // token and live session; reconnect cannot manufacture a new proof.
        fence.obligations.retain(|(id, _)| {
            !self
                .maintenance_observations
                .values()
                .any(|observation| observation.id == *id)
        });
        let reserved = storage.with_transaction(|storage| {
            let prior = storage.recovery_retry_state()?;
            if fence.obligations.is_empty() || (!immediate && now_ms < prior.not_before_ms) {
                return Ok::<_, StorageError>(None);
            }
            let maintenance = self
                .maintenance_observations
                .values()
                .map(|observation| observation.id)
                .collect::<Vec<_>>();
            storage.rearm_recovery_maintenance_for_activation(&maintenance)?;
            fence = storage.recovery_eligible_revision_fence(immediate)?;
            let reservation = storage.reserve_recovery_attempt(
                &fence,
                now_ms,
                self.policy.delay_ms(prior.ordinal)?,
                immediate,
            )?;
            Ok(reservation)
        })?;
        let Some(reservation) = reserved else {
            return Ok(None);
        };
        self.maintenance_observations.clear();
        if let Some(permit) = explicit {
            permit.spent = true;
        }
        let live = Arc::new(());
        self.active = Arc::downgrade(&live);
        self.active_scopes.clear();
        self.active_attempt = reservation.attempt_serial;
        self.active_fence = Some(fence.clone());
        Ok(Some(AttemptGrant {
            reservation,
            fence,
            mode: self.mode,
            seam: marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            plan: Vec::new(),
            inventory: Vec::new(),
            loss: Vec::new(),
            _live: live,
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
    ) -> StorageResult<Option<AttemptGrant>> {
        if !grant.plan.is_empty() || goals.len() != grant.fence.obligations.len() {
            return Err(StorageError::Serialization(
                "invalid recovery grant plan".into(),
            ));
        }
        let demands = storage.pending_recovery_demands()?;
        for ((id, scopes), (selected, _)) in goals.into_iter().zip(&grant.fence.obligations) {
            if id != *selected {
                return Err(StorageError::Serialization(
                    "invalid recovery grant selection".into(),
                ));
            }
            let Some(tokens) = storage.install_recovery_scope_plan(
                &grant.fence,
                grant.reservation.attempt_serial,
                id,
                &scopes,
            )?
            else {
                return Ok(None);
            };
            let demand = demands
                .iter()
                .find(|demand| demand.ticket.id == id)
                .ok_or_else(|| {
                    StorageError::Serialization("selected recovery demand disappeared".into())
                })?;
            grant.plan.push(GrantedObligation {
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
        self.active_scopes = grant
            .plan
            .iter()
            .flat_map(|obligation| &obligation.scopes)
            .map(|scope| scope.goal.clone())
            .collect();
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
        if self.active.upgrade().is_none()
            || !self.active_scopes.iter().any(|scope| {
                created_at <= scope.until_seconds
                    && scope.since_seconds.is_none_or(|since| created_at >= since)
                    && match route {
                        storage_sqlite::TransportReconciliationRoute::Inbox => {
                            scope.route_kind == 0
                        }
                        storage_sqlite::TransportReconciliationRoute::Group(id) => {
                            scope.route_kind == 1 && scope.transport_group_id.as_ref() == Some(id)
                        }
                    }
            })
        {
            return Ok(false);
        }
        let attempt = self.active_attempt;
        let Some(fence) = self.active_fence.as_ref() else {
            return Ok(false);
        };
        storage.checkpoint_recovery_progress(
            fence,
            attempt,
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

impl AppClient {
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
            storage.restore_unacknowledged_recovery_loss()?;
            return Ok(false);
        }
        for loss in &grant.loss {
            let Some((_, revision)) = grant
                .fence
                .obligations
                .iter()
                .find(|(id, _)| *id == loss.id)
            else {
                storage.restore_unacknowledged_recovery_loss()?;
                return Ok(false);
            };
            if loss.watermarks.is_empty()
                || !storage.recovery_obligation_is_satisfied(loss.id, *revision)?
            {
                storage.restore_unacknowledged_recovery_loss()?;
                return Ok(false);
            }
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
            storage.restore_unacknowledged_recovery_loss()?;
            return Ok(false);
        }
        let Some(elapsed) = self.adapter.finish_delivery_overflow_recovery(attempt) else {
            storage.restore_unacknowledged_recovery_loss()?;
            return Ok(false);
        };
        let reclaimed = storage.with_transaction(|_| {
            for loss in &grant.loss {
                if !storage.acknowledge_recovery_loss(&grant.fence, loss.id, &loss.watermarks)? {
                    // Roll back any preceding cause's deletion as well.
                    return Err(StorageError::NotFound);
                }
            }
            Ok(())
        });
        if let Err(error) = reclaimed {
            self.adapter
                .restore_delivery_overflow_guard(attempt.marker_token);
            storage.restore_unacknowledged_recovery_loss()?;
            return if matches!(error, StorageError::NotFound) {
                Ok(false)
            } else {
                Err(error.into())
            };
        }
        self.delivery_overflow_recovery_pending = false;
        self.delivery_overflow_recovery_marker_token = None;
        self.adapter
            .record_delivery_overflow_recovery_success(elapsed);
        Ok(true)
    }

    /// Worker-only boundary: import loss and synchronize the existing receipt
    /// consumer before selecting a revision-fenced immutable history plan.
    pub(crate) fn authorize_account_recovery(
        &mut self,
        explicit: Option<&mut ExplicitRecoveryPermit>,
        seam: marmot_forensics::EpochBackfillExecutionSeam,
    ) -> Result<Option<AttemptGrant>, AppError> {
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
        let Some(mut grant) = self.recovery_owner.select_authorized_attempt(
            &storage,
            readiness,
            Instant::now(),
            explicit,
        )?
        else {
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
        for (id, revision) in &grant.fence.obligations {
            let demand = demands
                .iter()
                .find(|demand| demand.ticket.id == *id)
                .ok_or_else(|| {
                    StorageError::Serialization("selected recovery demand disappeared".into())
                })?;
            let stored = storage.recovery_scope_snapshots(*id)?;
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
        let inventory = self.freeze_recovery_inventory(&mut goals)?;
        let Some(mut grant) = self.recovery_owner.freeze_plan(&storage, grant, goals)? else {
            return Ok(None);
        };
        grant.inventory = inventory;
        for obligation in &grant.plan {
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
                grant.loss.push(GrantedLoss {
                    id: obligation.id,
                    watermarks: storage.recovery_loss_watermarks(&self.state.label, cause)?,
                });
            }
        }
        Ok(Some(grant))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(grant.mode, RecoveryExecutorMode::Normal);
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
        assert_eq!(grant.mode, RecoveryExecutorMode::Conservative);
        drop(grant);
        assert!(owner.select_executor_mode(RecoveryExecutorMode::Normal));
        assert_eq!(storage.recovery_revision_fence().unwrap(), before);
        assert_eq!(storage.recovery_retry_state().unwrap().attempt_serial, 2);
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
            .freeze_plan(&storage, grant, vec![(id, vec![scope])])
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
            .freeze_plan(&storage, grant, vec![(id, vec![goal])])
            .unwrap()
            .unwrap();
        let plan = grant.plan().unwrap();
        assert_eq!(plan[0].id, id);
        assert_eq!(plan[0].scopes[0].goal.until_seconds, 10);
        assert_eq!(plan[0].scopes[0].token.scope_id, 0);
        let restored = storage.recovery_scope_snapshots(id).unwrap();
        assert_eq!(restored[0].plan.until_seconds, 10);
        assert!(restored[0].token == plan[0].scopes[0].token);
        drop(grant);
        assert_eq!(storage.pending_recovery_demands().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn post_join_boundary_completes_only_its_predicate_and_keeps_grace_fixed() {
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
            bounded_epoch_backfill_config(),
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
        let mut permit = ExplicitRecoveryPermit::default();
        let grant = client
            .authorize_account_recovery(
                Some(&mut permit),
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .unwrap()
            .unwrap();
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
        tokio::time::sleep(Duration::from_millis(5)).await;
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
}
