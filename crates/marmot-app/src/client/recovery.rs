//! Account recovery seams. The recovery runner owns every history fetch
//! (mdk#2660 phase 4); this module keeps the account's native replay ingress,
//! flushes the recovery observations each seam owes the ledger, and keeps the
//! logical clock the ledger's deadlines are read against.
use cgka_traits::MaintenanceStorage;
use std::time::{Duration, Instant};
use storage_sqlite::SqliteAppStorage;

use super::AppClient;
use crate::{AppError, unix_now_seconds};

use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};
use storage_sqlite::{RecoveryRevisionFence, RecoveryScopePlan, RecoveryScopeToken};

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

#[derive(Clone)]
pub(crate) struct GrantedScope {
    pub(crate) goal: RecoveryScopePlan,
    pub(crate) token: RecoveryScopeToken,
}

/// The post-join history fetch a live maintenance session was installed for,
/// keyed by the session's subscription id.
pub(crate) struct PostJoinHistorySession {
    /// The fetch's id: the post-join obligation created with that copy.
    pub(crate) fetch: cgka_traits::MessageId,
    /// The session's recovery boundary qualified: a relay it was admitted
    /// for reached end-of-stored-events.
    pub(crate) boundary: bool,
}

#[derive(Clone)]
pub(crate) struct MaintenanceRecoveryObservation {
    pub(crate) fence: RecoveryRevisionFence,
    pub(crate) attempt_serial: u64,
    pub(crate) id: [u8; 16],
    pub(crate) scopes: Vec<GrantedScope>,
}

pub(crate) struct AccountRecoveryOwner {
    pub(super) native_batch: Option<transport_nostr_adapter::ReplayBatch>,
    pub(super) native_ingress: Option<transport_nostr_adapter::ReplayIngress>,
    pub(super) retained_spill: std::collections::HashMap<cgka_traits::MessageId, i64>,
    pub(super) native_cursor_target: Option<u64>,
    pub(super) native_receive_pending: bool,
    pub(crate) maintenance_observations:
        std::collections::HashMap<cgka_traits::GroupId, MaintenanceRecoveryObservation>,
    wall_anchor_ms: u64,
    monotonic_anchor: Instant,
    replay_generation: Option<u64>,
    /// The replay generation the last full synchronization saw, authorized or
    /// not. The adapter bumps its generation only when its replay sources
    /// change; native progress re-sends the same one (mdk#2923 telemetry).
    replay_observed_generation: Option<u64>,
    replay_complete: bool,
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
    pub(super) fn native_replay_authorizes(&self, generation: u64) -> bool {
        self.replay_generation == Some(generation) && self.replay_complete
    }

    pub(crate) fn open(
        storage: &SqliteAppStorage,
        wall_now_ms: u64,
        monotonic_now: Instant,
        policy: RecoveryRetryPolicy,
        runner_owns_debt: bool,
    ) -> StorageResult<Self> {
        policy.delay_ms(0)?;
        if !runner_owns_debt {
            storage.restore_unacknowledged_recovery_loss()?;
        }
        storage.restore_recovery_waiters()?;
        storage.reclaim_completed_recovery_events()?;
        storage.restore_recovery_retry(wall_now_ms, duration_ms(policy.cap)?)?;
        Ok(Self {
            native_batch: None,
            native_ingress: None,
            retained_spill: std::collections::HashMap::new(),
            native_cursor_target: None,
            native_receive_pending: false,
            maintenance_observations: std::collections::HashMap::new(),
            wall_anchor_ms: wall_now_ms,
            monotonic_anchor: monotonic_now,
            replay_generation: None,
            replay_observed_generation: None,
            replay_complete: false,
        })
    }

    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn test_replay_complete(&self) -> bool {
        self.replay_complete
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
}

impl AppClient {
    /// Native ingress remains ordered. Its original windows become durable
    /// ledger debt, without legacy replay obligations or a coverage claim.
    /// The actual seal still checks this generation, placement and held frames
    /// under the plane's existing locks.
    async fn synchronize_runner_native_replay(
        &mut self,
        observation: transport_nostr_adapter::ReplayAdmissionStatus<'_>,
    ) -> Result<(), AppError> {
        let generation = observation.generation();
        let changed_generation = self.recovery_owner.replay_generation != Some(generation);
        self.recovery_owner.replay_generation = None;
        self.recovery_owner.replay_complete = false;
        let active = observation.active();
        let floor = unix_now_seconds()
            .saturating_sub(storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS);
        let routing = self.routing.snapshot();
        let mut goals = std::collections::BTreeMap::<u64, Vec<_>>::new();
        for source in observation.sources() {
            let routes = source
                .group_routes()
                .copied()
                .filter(|route| {
                    routing
                        .group_routes
                        .iter()
                        .any(|current| current.transport_group_id.as_slice() == route.as_slice())
                })
                .map(storage_sqlite::TransportReconciliationRoute::Group)
                .collect::<Vec<_>>();
            let routes = if source.group_routes().next().is_none() {
                vec![storage_sqlite::TransportReconciliationRoute::Inbox]
            } else {
                routes
            };
            goals
                .entry(source.since().max(floor))
                .or_default()
                .extend(routes);
        }
        drop(observation);
        #[cfg(test)]
        if let Some((reached, release)) = self.test_replay_sync_gate.take() {
            let _ = reached.send(());
            let _ = release.await;
        }
        let storage = self.app.account_storage(&self.state.label)?;
        let app = storage.app_storage();
        self.synchronize_recovery_loss(&app)?;
        self.finish_runner_loss_import()?;
        storage.with_transaction(|_| {
            for (since, routes) in &goals {
                app.widen_recovery_coverage_goals(routes, *since)?;
            }
            Ok::<_, StorageError>(())
        })?;
        if changed_generation {
            self.wake_recovery_runner();
        }
        self.record_native_coverage(&app).await;
        // Permission means the input is placed or durably owed, never that a
        // full live EOSE proved complete history. A stale generation cannot seal.
        self.recovery_owner.replay_generation = active.then_some(generation);
        self.recovery_owner.replay_complete = active;
        Ok(())
    }

    /// Copy limited native source facts, then persist without holding the
    /// adapter guard. The cursor seal rechecks the copied generation and current
    /// pending/loss facts; this is never exhaustive history or loss evidence.
    pub(crate) async fn synchronize_native_replay(&mut self) -> Result<(), AppError> {
        let adapter = self.adapter.clone();
        let observation = adapter.replay_admission().await;
        let generation = observation.generation();
        // The generation this pass synchronizes, recorded from the same
        // guarded snapshot it classifies and processes: the next full pass for
        // a later one counts as a source change (mdk#2923 telemetry).
        let previous = self
            .recovery_owner
            .replay_observed_generation
            .replace(generation);
        let runner = self.app.recovery_runner_owns_debt();
        if self.recovery_owner.native_replay_authorizes(generation)
            && !(runner && self.delivery_loss_blocks_cursor())
        {
            return Ok(());
        }
        // Each full synchronization is timed under its trigger: a changed
        // source set (a new generation) or a retry of one that did not
        // authorize, each with or without admission still pending. Success
        // means it authorized the generation (mdk#2923).
        let reason = match (
            previous == Some(generation),
            observation.pending || observation.spill_pending,
        ) {
            (false, false) => crate::RuntimePerformanceOperation::ReplaySyncSourcesChanged,
            (false, true) => crate::RuntimePerformanceOperation::ReplaySyncSourcesChangedPending,
            (true, false) => crate::RuntimePerformanceOperation::ReplaySyncRetry,
            (true, true) => crate::RuntimePerformanceOperation::ReplaySyncRetryPending,
        };
        let span = self
            .runtime_telemetry
            .as_ref()
            .map(|telemetry| telemetry.observe(reason));
        let result = self.synchronize_runner_native_replay(observation).await;
        if let Some(span) = span {
            // The adapter may have moved on while this ran; the pass succeeded
            // if the generation it holds now is authorized.
            let current = self.adapter.replay_admission().await.generation();
            span.finish(match &result {
                Err(_) => marmot_observability::Outcome::Failure,
                Ok(()) if self.recovery_owner.native_replay_authorizes(current) => {
                    marmot_observability::Outcome::Success
                }
                Ok(()) => marmot_observability::Outcome::NotReady,
            });
        }
        result
    }

    pub(super) fn comparison_route_goals(
        &self,
        until: u64,
    ) -> Result<Vec<RecoveryScopePlan>, AppError> {
        let routing = self.routing.snapshot();
        let mut goals = Vec::new();
        let mut push = |group_id: Option<Vec<u8>>,
                        transport_group_id: Option<[u8; 32]>,
                        endpoints: &[cgka_traits::TransportEndpoint]| {
            let admitted = self.adapter.recovery_admitted_endpoints(endpoints);
            let required = transport_nostr::recovery_required_endpoints(
                &admitted,
                &self.app.config.deployment.recovery_operated_relays,
            );
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
                admitted_endpoints: admitted,
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

    pub(crate) fn request_bounded_comparison(&mut self) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let app = storage.app_storage();
        self.synchronize_recovery_loss(&app)?;
        drop(self.transport_receipts()?);
        self.observe_recovery_route_policy()?;
        let now = wall_now_ms()?;
        let goals = self.comparison_route_goals(now / 1000)?;
        app.observe_recovery_comparison_capability(
            self.adapter.recovery_comparison_capability_key(),
        )?;
        app.join_recovery_comparison(&rand::random(), now, &goals)?;
        Ok(())
    }

    /// Floor of a joined group's post-join maintenance REQ: the creation of the
    /// Welcome that installed this copy, less the clock-skew allowance.
    ///
    /// The member cannot open anything older than its join epoch, and the
    /// commits it must see before its first self-update were made after that
    /// Welcome, however late the member processed it. So the anchor is the
    /// Welcome, which the engine clamps to no later than the join, and never
    /// the local join time. `None`, a full-history request, when the copy has
    /// no Welcome time.
    pub(crate) fn post_join_maintenance_since(
        &self,
        group_id: &cgka_traits::GroupId,
    ) -> Option<cgka_traits::transport::Timestamp> {
        self.runtime
            .group_record(group_id)
            .ok()?
            .local_copy_welcome_created_at
            .map(|created_at| crate::history_floor(created_at.0))
    }

    /// End the group's owed post-join history fetch `fetch`. Once its live
    /// session's boundary has qualified, it ends as fetched when everything
    /// that group's replay holds has been ingested, however long after the
    /// deadline that is; before then, it ends only at the deadline set when
    /// the session was installed. `boundary` is this pass's qualification.
    /// Returns whether the fetch ended.
    pub(super) async fn settle_post_join_history_fetch(
        &mut self,
        group_id: &cgka_traits::GroupId,
        fetch: &cgka_traits::MessageId,
        boundary: bool,
    ) -> Result<bool, AppError> {
        let Some((subscription, _)) = self
            .post_join_maintenance_subscriptions
            .get(group_id)
            .cloned()
        else {
            return Ok(false);
        };
        let Some(session) = self
            .post_join_history_sessions
            .get_mut(&subscription)
            .filter(|session| session.fetch == *fetch)
        else {
            return Ok(false);
        };
        session.boundary |= boundary;
        let completion = if session.boundary {
            // Native ingress acknowledges a frame only after its ingest, so a
            // placed session has had everything it delivered processed. The
            // group's frames flush only once all of its streams are ready, so
            // placement is the group's, not this subscription's alone.
            if self.recovery_owner.native_ingress.is_none()
                || self.adapter.group_maintenance_placed(&subscription).await != Some(true)
            {
                return Ok(false);
            }
            self.runtime
                .finish_post_join_history_fetch(group_id, fetch)?
        } else {
            self.runtime
                .expire_post_join_history_fetch(group_id, fetch)?
        };
        let Some(completion) = completion else {
            return Ok(false);
        };
        tracing::debug!(
            target: "marmot_app::maintenance",
            method = "settle_post_join_history_fetch",
            outcome = match completion.outcome {
                cgka_traits::PostJoinHistoryFetchOutcome::Fetched => "fetched",
                cgka_traits::PostJoinHistoryFetchOutcome::DeadlineExpired => "deadline_expired",
            },
            "post-join history fetch ended"
        );
        Ok(true)
    }

    /// Forget the fetch of every post-join session that is no longer live.
    pub(super) fn retain_live_post_join_history_sessions(&mut self) {
        let live = self
            .post_join_maintenance_subscriptions
            .values()
            .map(|(subscription, _)| subscription)
            .collect::<std::collections::HashSet<_>>();
        self.post_join_history_sessions
            .retain(|subscription, _| live.contains(subscription));
    }

    pub(super) async fn observe_post_join_recovery_boundary(
        &mut self,
        group_id: &cgka_traits::GroupId,
    ) -> Result<bool, AppError> {
        self.synchronize_native_replay().await?;
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
                replay_admitted: false,
            });
        }
        let storage = self.app.account_storage(&self.state.label)?;
        self.synchronize_recovery_loss(&storage.app_storage())?;
        self.observe_recovery_route_policy()?;
        let domain_updates = self.runtime.post_join_eose_updates(group_id)?;
        storage.with_transaction(|storage| {
            let qualified = storage.app_storage().checkpoint_recovery_obligation(
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
        // The operated set decides which relays certify a scope, so changing it
        // is a policy change that rebuilds every pending scope.
        let mut operated = self
            .app
            .config
            .deployment
            .recovery_operated_relays
            .iter()
            .collect::<Vec<_>>();
        operated.sort();
        operated.dedup();
        let canonical = serde_json::to_vec(&("history-route-policy-v2", inbox, groups, operated))
            .map_err(|_| {
            StorageError::Serialization("invalid recovery route snapshot".into())
        })?;
        self.app
            .account_storage(&self.state.label)?
            .app_storage()
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
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
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

    /// Imported ledger debt replaces the cursor's loss fence. This is a
    /// durable handoff, not proof of recovery and not a recovery-success metric.
    pub(crate) fn finish_runner_loss_import(&mut self) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let app = storage.app_storage();
        let entries = app
            .converted_recovery_loss()?
            .into_iter()
            .filter(|entry| entry.account_label == self.state.label)
            .collect::<Vec<_>>();
        let observed = self.adapter.pending_delivery_overflow_generation();
        if let Some(observed) = observed {
            self.delivery_overflow_recovery_pending = true;
            let contains = |cause, token, count| {
                entries.iter().any(|entry| {
                    entry.cause == cause
                        && entry.watermarks.iter().any(|watermark| {
                            watermark.marker_token == token && watermark.observed_count == count
                        })
                })
            };
            if (observed.dropped > 0
                && !contains(
                    storage_sqlite::RecoveryLossCause::Queue,
                    observed.marker_token,
                    observed.dropped,
                ))
                || (observed.notification_losses > 0
                    && !contains(
                        storage_sqlite::RecoveryLossCause::NotificationConsumer,
                        observed.notification_token,
                        0,
                    ))
            {
                return Ok(false);
            }
            // Exact current counters, durable marker, no marker writer still
            // running and no queued signal. The plane holds all these checks
            // under its own lock; a concurrent new omission keeps its guard.
            if self
                .adapter
                .finish_delivery_overflow_recovery(observed)
                .is_none()
            {
                return Ok(false);
            }
        }
        let restore_token = observed.map(|observed| observed.marker_token).or_else(|| {
            entries
                .iter()
                .flat_map(|entry| &entry.watermarks)
                .next()
                .map(|mark| mark.marker_token)
        });
        let reclaimed = storage.with_transaction(|_| {
            for entry in &entries {
                if !app.reclaim_converted_recovery_loss(entry)? {
                    return Err(StorageError::NotFound);
                }
            }
            Ok::<_, StorageError>(())
        });
        if let Err(error) = reclaimed {
            self.delivery_overflow_recovery_pending = true;
            if let Some(token) = restore_token {
                self.adapter.restore_delivery_overflow_guard(token);
            }
            return Err(error.into());
        }
        let pending = self.adapter.pending_delivery_overflow_generation();
        self.delivery_overflow_recovery_pending = pending.is_some();
        self.delivery_overflow_recovery_marker_token = pending.map(|pending| pending.marker_token);
        Ok(!self.delivery_overflow_recovery_pending)
    }

    /// The other ending for loss debt: the user retired it as "history may be
    /// incomplete". Mirrors [`Self::finish_qualified_recovery_loss`] without
    /// acknowledging coverage or recording success. The fence stays while any
    /// loss obligation is still pending, and the plane clears only the exact
    /// generation `observed` before retirement, so an omission that is not yet
    /// durable keeps the fence until it rearms recovery as new loss. Retired
    /// evidence keeps its watermark; only a later qualified acknowledgment of
    /// that cause reclaims it. Returns whether the fence was released.
    pub(super) fn release_retired_delivery_loss(
        &mut self,
        observed: Option<transport_nostr::AccountDeliveryOverflow>,
    ) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        if storage
            .app_storage()
            .pending_recovery_demands()?
            .iter()
            .any(|demand| {
                matches!(
                    demand.cause,
                    storage_sqlite::RecoveryCause::QueueLoss
                        | storage_sqlite::RecoveryCause::NotificationLoss
                )
            })
        {
            return Ok(false);
        }
        if !self.adapter.retire_delivery_overflow(observed) {
            return Ok(false);
        }
        self.delivery_overflow_recovery_pending = false;
        self.delivery_overflow_recovery_marker_token = None;
        Ok(true)
    }

    /// Whether recovery may contact any relay of the account's routes. With
    /// none, no grant can be selected, so no caller should wait for a credit.
    pub(crate) fn recovery_endpoints_admitted(&self) -> bool {
        let routing = self.routing.snapshot();
        !self
            .adapter
            .recovery_admitted_endpoints(&routing.local_inbox_endpoints)
            .is_empty()
            || routing.group_routes.iter().any(|route| {
                !self
                    .adapter
                    .recovery_admitted_endpoints(&route.endpoints)
                    .is_empty()
            })
    }

    /// Flush recovery observations at a recovery seam: synchronize native
    /// replay facts, import loss, retry buffered epoch-gap arms and capacity
    /// pressure, and observe the current route policy. A wake-collection
    /// (`CursorPersistence::Frozen`) process leaves them to an Advance runtime.
    /// The recovery runner owns every history fetch (mdk#2660 phase 4).
    pub(crate) async fn refresh_account_recovery(&mut self) -> Result<(), AppError> {
        self.synchronize_native_replay().await?;
        if self.app.cursor_persistence() == crate::CursorPersistence::Frozen {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?;
        self.synchronize_recovery_loss(&storage.app_storage())?;
        // Failed detector persistence is retried here. These observations
        // carry demand only; SQL remains the retry authority.
        let arms = self
            .pending_recovery_arm_writes
            .iter()
            .map(|(group, epoch)| storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(group.as_slice()),
                stalled_epoch: *epoch,
            })
            .collect::<Vec<_>>();
        self.arm_epoch_gap_recovery(&arms)?;
        self.pending_recovery_arm_writes.clear();
        for (group, epoch) in &self.pending_recovery_capacity_writes {
            storage.app_storage().record_recovery_capacity_pressure(
                group.as_slice(),
                *epoch,
                self.recovery_owner.logical_now_ms(Instant::now())?,
            )?;
        }
        self.pending_recovery_capacity_writes.clear();
        drop(self.transport_receipts()?);
        self.observe_recovery_route_policy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn native_fixture() -> (
        tempfile::TempDir,
        crate::MarmotApp,
        Arc<crate::tests::ScriptedPushRelayClient>,
        AppClient,
    ) {
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(crate::tests::ScriptedPushRelayClient::default());
        // These tests answer each REQ themselves, to see the owner before
        // and after its EOSE.
        relay.hold_replies(Some(crate::tests::every_reply));
        let mut app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.relay_plane = crate::MarmotRelayPlane::new_with_directory_fetcher_for_test(
            Some(Duration::from_secs(120)),
            relay.clone(),
            relay.clone(),
            app.config.allow_loopback_relay_endpoints,
        );
        relay.connect_relays(&["wss://relay.example"]).await;
        let client = crate::tests::client_on_app_relay_plane(&app, "alice").await;
        (dir, app, relay, client)
    }

    /// #2793: an unadmitted, unfloored inbox scope an earlier owner left
    /// behind must not broaden a newly current group's live REQ after
    /// conversion. The runner keeps the inbox debt without inheriting its
    /// query floor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runner_owned_inbox_debt_does_not_lower_a_new_groups_live_req() {
        use cgka_traits::transport::Timestamp;
        use transport_nostr_adapter::NostrSubscription;
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(crate::tests::ScriptedPushRelayClient::default());
        relay.hold_replies(Some(crate::tests::every_reply));
        let mut app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.relay_plane = crate::MarmotRelayPlane::new_with_directory_fetcher_for_test(
            Some(Duration::from_secs(120)),
            relay.clone(),
            relay.clone(),
            app.config.allow_loopback_relay_endpoints,
        );
        relay.connect_relays(&["wss://relay.example"]).await;
        // A nightly-shaped durable input, written as an earlier owner wrote
        // it before any runner opened the account: a newer saved cursor
        // beside a still-unadmitted native inbox scope with no floor.
        let ledger = app.account_storage("alice").unwrap().app_storage();
        let cursor = unix_now_seconds().saturating_sub(60);
        let (ticket, _) = ledger
            .request_recovery_observed(
                storage_sqlite::RecoveryRequest::SubscriptionReplay { snapshot: &[7; 32] },
                0,
            )
            .unwrap();
        ledger
            .install_recovery_scope_plan(
                &ledger.recovery_revision_fence().unwrap(),
                0,
                ticket.id,
                &[RecoveryScopePlan {
                    scope_id: 1,
                    route_kind: 0,
                    route_role: 0,
                    group_id: None,
                    transport_group_id: None,
                    since_seconds: None,
                    until_seconds: cursor,
                    known_event_id: None,
                    inventory_floor: None,
                    required_endpoints: vec!["wss://relay.example".into()],
                    admitted_endpoints: vec!["wss://relay.example".into()],
                }],
            )
            .unwrap()
            .expect("the native inbox scope installs");
        assert!(
            ledger
                .recovery_scope_snapshots(ticket.id)
                .unwrap()
                .iter()
                .all(|scope| !scope.replay_admitted && scope.plan.since_seconds.is_none()),
            "an unresolved unfloored inbox scope"
        );
        let mut state = app.load_state("alice").unwrap();
        state.last_transport_timestamp = Some(cursor);
        app.save_state(&state).unwrap();

        let mut client = crate::tests::client_on_app_relay_plane(&app, "alice").await;
        let before = relay.accepted_subscriptions().len();
        let group = client
            .create_group("new route while inbox owes", &[])
            .await
            .unwrap();
        let live_since = relay
            .accepted_subscriptions()
            .into_iter()
            .skip(before)
            .filter_map(|subscription| match subscription {
                NostrSubscription::Group {
                    group_id, since, ..
                } if group_id == group => Some(since),
                NostrSubscription::GroupBatch { routes, since, .. }
                    if routes.iter().any(|route| route.group_id == group) =>
                {
                    Some(since)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            !live_since.is_empty(),
            "a real live group REQ must have been issued"
        );
        let expected = Some(Timestamp(cursor.saturating_sub(120)));
        assert!(
            live_since.iter().all(|since| *since == expected),
            "new group's live REQs {live_since:?}, expected {expected:?}"
        );
        let inbox = storage_sqlite::TransportReconciliationRoute::Inbox;
        assert!(!ledger.recovery_conversion_pending().unwrap());
        assert!(
            ledger.recovery_coverage_goal(&inbox).unwrap().unwrap() < cursor - 120,
            "conversion keeps older inbox debt beyond the new group's live range"
        );
        assert!(
            ledger
                .recovery_coverage_ranges(&inbox, "wss://relay.example")
                .unwrap()
                .is_empty(),
            "the inbox has not answered or proved coverage"
        );
        assert!(
            ledger
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .all(|demand| demand.cause != storage_sqlite::RecoveryCause::SubscriptionReplay)
        );
    }

    /// Each full replay synchronization is timed under its trigger: opening
    /// the transport syncs a new generation, a sync on a generation that did
    /// not authorize is a retry, and an authorized generation records nothing
    /// (mdk#2923).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_replay_synchronization_is_timed_by_trigger() {
        use crate::RuntimePerformanceOperation as Op;
        let (_dir, _app, relay, mut client) = native_fixture().await;
        let telemetry = marmot_observability::PerformanceRecorder::default();
        client.runtime_telemetry = Some(telemetry.clone());
        let spans = |op: Op| {
            telemetry
                .snapshot()
                .runtime_operations
                .into_iter()
                .find(|snapshot| snapshot.operation == op)
                .map(|snapshot| (snapshot.completed, snapshot.successes))
                .unwrap()
        };
        client.prepare_transport().await.unwrap();
        assert!(
            spans(Op::ReplaySyncSourcesChanged).0 >= 1,
            "opening the transport syncs its first generation"
        );
        relay.answer_held_replies().await;
        client.synchronize_native_replay().await.unwrap();
        let generation = client.adapter.replay_admission().await.generation();
        assert!(client.recovery_owner.native_replay_authorizes(generation));

        let (retries, retry_successes) = spans(Op::ReplaySyncRetry);
        let changed = spans(Op::ReplaySyncSourcesChanged);
        client.recovery_owner.replay_generation = Some(generation.wrapping_sub(1));
        client.synchronize_native_replay().await.unwrap();
        assert_eq!(
            spans(Op::ReplaySyncRetry),
            (retries + 1, retry_successes + 1),
            "the same generation again is a retry, and it authorizes"
        );
        assert_eq!(spans(Op::ReplaySyncSourcesChanged), changed);

        client.synchronize_native_replay().await.unwrap();
        assert_eq!(
            spans(Op::ReplaySyncRetry),
            (retries + 1, retry_successes + 1),
            "an authorized generation records nothing"
        );
    }

    /// A pass records the generation it synchronized, not one the adapter
    /// moved to while it ran: the first full pass for the later generation
    /// still counts as a source change (mdk#2923).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_generation_change_during_a_pass_counts_as_a_source_change() {
        use crate::RuntimePerformanceOperation as Op;
        let (_dir, _app, relay, mut client) = native_fixture().await;
        let telemetry = marmot_observability::PerformanceRecorder::default();
        client.runtime_telemetry = Some(telemetry.clone());
        let changed = || {
            telemetry
                .snapshot()
                .runtime_operations
                .into_iter()
                .find(|snapshot| snapshot.operation == Op::ReplaySyncSourcesChanged)
                .unwrap()
                .completed
        };
        client.prepare_transport().await.unwrap();
        relay.answer_held_replies().await;
        client.synchronize_native_replay().await.unwrap();
        let first = client.adapter.replay_admission().await.generation();
        assert!(client.recovery_owner.native_replay_authorizes(first));

        // A full pass on the first generation, which the adapter leaves for
        // the second while the pass is paused after its snapshot.
        client.recovery_owner.replay_generation = Some(first.wrapping_sub(1));
        let (reached_tx, reached) = tokio::sync::oneshot::channel();
        let (release, release_rx) = tokio::sync::oneshot::channel();
        client.test_replay_sync_gate = Some((reached_tx, release_rx));
        let adapter = client.adapter.clone();
        let (pass, ()) = tokio::join!(client.synchronize_native_replay(), async move {
            reached.await.unwrap();
            adapter.change_replay_sources_for_test().await;
            release.send(()).unwrap();
        });
        pass.unwrap();
        let second = client.adapter.replay_admission().await.generation();
        assert_ne!(second, first, "the adapter moved on during the pass");
        assert_eq!(
            client.recovery_owner.replay_observed_generation,
            Some(first)
        );

        let before = changed();
        client.synchronize_native_replay().await.unwrap();
        assert_eq!(changed(), before + 1, "the second generation's first pass");
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
}
