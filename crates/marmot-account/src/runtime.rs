//! Account-device runtime: drives session effects through transport publish,
//! confirmation, and rollback, and the effect aggregates it produces.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use cgka_session::{
    AccountDeviceSession, CreateGroupEffects, IngestEffects, PublishWork, QueuedIntentRef,
    SessionEffects,
};
use cgka_traits::AppComponentId;
use cgka_traits::engine::{
    CreateGroupRequest, GroupEvent, GroupHydrationQuarantineReason, KeyPackage, SendIntent,
};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::group::{Group, Member};
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::maintenance::{
    DurableTransportFanout, GroupEvolutionPhase, GroupEvolutionSemantic, GroupMaintenanceStatus,
    KeyPackageLifecycleState, MaintenanceObligation, MaintenancePhase, MaintenanceTrigger,
    PendingKeyPackageReplacement, PeriodicMaintenancePolicy, RetainedKeyPackagePrivateMaterial,
    SendMaintenanceDisposition, TransportFanoutAttemptState, TransportFanoutTarget,
};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::{
    EpochId, FanoutMlsState, GroupId, MemberId, OutboundFanout, OutboundFanoutOutcome, Timestamp,
    TransportAccountActivation, TransportAdapter, TransportAdapterError, TransportDelivery,
    TransportEndpoint, TransportEndpointFailure, TransportEndpointReceipt, TransportGroupSync,
    TransportPublishReport, TransportPublishRequest, TransportPublishTarget,
};
use marmot_forensics::{
    AuditEventContext, AuditEventKind, AuditTransportWire, MessageArtifactKind, PublishRelayFailure,
};

use crate::error::{AccountError, AccountResult};
use crate::key_package::{KeyPackagePublication, KeyPackagePublisher, NoopKeyPackagePublisher};
use crate::routing::{
    StaticTransportRouting, TransportRoutingPolicy, publish_target_group_id, publish_target_kind,
    publish_target_relay_urls,
};
use crate::time::{
    MaintenanceRandom, MonotonicClock, OsMaintenanceRandom, SystemMonotonicClock, SystemWallClock,
    WallClock,
};

const TRACE_TARGET: &str = "marmot_account::runtime";
const KEY_PACKAGE_MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;
const KEY_PACKAGE_REFRESH_MIN_LEAD_SECS: u64 = 14 * 24 * 60 * 60;
const KEY_PACKAGE_REFRESH_MAX_LEAD_SECS: u64 = 21 * 24 * 60 * 60;
const MAINTENANCE_EOSE_TIMEOUT_SECS: u64 = 5 * 60;
const MAINTENANCE_POST_EOSE_GRACE_SECS: u64 = 15;
const MAINTENANCE_QUIET_SECS: u64 = 60;
const PERIODIC_MIN_SECS: u64 = 24 * 24 * 60 * 60;
const PERIODIC_MAX_SECS: u64 = 36 * 24 * 60 * 60;
const TRANSPORT_FANOUT_RETENTION_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PublishStatus {
    met_required_acks: bool,
    accepted_by_any_endpoint: bool,
    possible_ambiguous_exposure: bool,
    retry_deferred: bool,
}

pub struct AccountDeviceRuntime<A, R = StaticTransportRouting, K = NoopKeyPackagePublisher> {
    session: AccountDeviceSession,
    adapter: A,
    routing: R,
    key_packages: K,
    wall_clock: Arc<dyn WallClock>,
    monotonic_clock: Arc<dyn MonotonicClock>,
    maintenance_random: Arc<dyn MaintenanceRandom>,
    maintenance_paused: bool,
    maintenance_quiet_monotonic: HashMap<cgka_traits::MessageId, Duration>,
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    pub fn new(session: AccountDeviceSession, adapter: A, routing: R, key_packages: K) -> Self {
        Self {
            session,
            adapter,
            routing,
            key_packages,
            wall_clock: Arc::new(SystemWallClock),
            monotonic_clock: Arc::new(SystemMonotonicClock::default()),
            maintenance_random: Arc::new(OsMaintenanceRandom::default()),
            maintenance_paused: false,
            maintenance_quiet_monotonic: HashMap::new(),
        }
    }

    pub fn with_maintenance_sources(
        mut self,
        wall_clock: Arc<dyn WallClock>,
        monotonic_clock: Arc<dyn MonotonicClock>,
        maintenance_random: Arc<dyn MaintenanceRandom>,
    ) -> Self {
        self.wall_clock = wall_clock;
        self.monotonic_clock = monotonic_clock;
        self.maintenance_random = maintenance_random;
        self
    }

    pub fn session(&self) -> &AccountDeviceSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut AccountDeviceSession {
        &mut self.session
    }

    pub fn group_record(&self, group_id: &GroupId) -> AccountResult<Group> {
        Ok(self.session.group_record(group_id)?)
    }

    pub fn new_protocol_profile(&self) -> cgka_traits::group::ProtocolProfile {
        self.session.new_protocol_profile()
    }

    pub fn live_group_ids(&self) -> AccountResult<Vec<GroupId>> {
        Ok(self.session.live_group_ids()?)
    }

    /// Stored groups that failed session-open hydration and were skipped
    /// (mdk#151 / #417), paired with their coarse quarantine reason.
    /// Backs the application's per-group recovery surface (mdk#426).
    pub fn quarantined_groups(&self) -> Vec<(GroupId, GroupHydrationQuarantineReason)> {
        self.session.quarantined_groups()
    }

    /// Re-attempt hydration of a single quarantined group. `Ok(true)` if it
    /// recovered and is now live, `Ok(false)` if still unhealthy. Errors with
    /// `UnknownGroup` if the id is not currently quarantined.
    pub fn retry_hydrate_quarantined_group(&mut self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.retry_hydrate_quarantined_group(group_id)?)
    }

    pub fn admin_pubkeys(&self, group_id: &GroupId) -> AccountResult<Vec<[u8; 32]>> {
        Ok(self.session.admin_pubkeys(group_id)?)
    }

    pub fn app_component(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<Option<Vec<u8>>> {
        Ok(self.session.app_component(group_id, component_id)?)
    }

    pub fn safe_export_secret(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<cgka_traits::SecretBytes> {
        Ok(self.session.safe_export_secret(group_id, component_id)?)
    }

    pub fn exporter_secret(
        &self,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> AccountResult<cgka_traits::SecretBytes> {
        Ok(self.session.exporter_secret(group_id, label, length)?)
    }

    pub fn exporter_secret_with_epoch(
        &self,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> AccountResult<(EpochId, cgka_traits::SecretBytes)> {
        Ok(self
            .session
            .exporter_secret_with_epoch(group_id, label, length)?)
    }

    pub fn safe_export_secret_with_epoch(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<(EpochId, cgka_traits::SecretBytes)> {
        Ok(self
            .session
            .safe_export_secret_with_epoch(group_id, component_id)?)
    }

    pub fn current_safe_export_epoch(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<EpochId> {
        Ok(self
            .session
            .current_safe_export_epoch(group_id, component_id)?)
    }

    pub async fn activate_transport(&self, since: Option<Timestamp>) -> AccountResult<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "activate_transport",
            inbox_endpoint_count = self.routing.local_inbox_endpoints().len(),
            group_subscription_count = self.routing.group_subscriptions().len(),
            "activating account transport"
        );
        self.adapter
            .activate_account(TransportAccountActivation {
                account_id: self.session.self_id(),
                inbox_endpoints: self.routing.local_inbox_endpoints(),
                group_subscriptions: self.routing.group_subscriptions(),
                since,
            })
            .await?;
        Ok(())
    }

    pub async fn sync_transport_groups(&self, since: Option<Timestamp>) -> AccountResult<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "sync_transport_groups",
            group_subscription_count = self.routing.group_subscriptions().len(),
            "syncing account group subscriptions"
        );
        self.adapter
            .sync_account_groups(TransportGroupSync {
                account_id: self.session.self_id(),
                group_subscriptions: self.routing.group_subscriptions(),
                since,
            })
            .await?;
        Ok(())
    }

    pub async fn publish_fresh_key_package(&mut self) -> AccountResult<KeyPackage> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "publish_fresh_key_package",
            endpoint_count = self.routing.key_package_endpoints().len(),
            "publishing fresh key package"
        );
        let now = self.wall_clock.now();
        let endpoints = self.routing.key_package_endpoints();
        let mut lifecycle = match self.session.key_package_lifecycle()? {
            Some(state) => state,
            None => KeyPackageLifecycleState {
                stable_slot_id: self
                    .key_packages
                    .legacy_slot_id(&self.session.self_id())
                    .unwrap_or_else(|| {
                        (0..4)
                            .flat_map(|_| self.maintenance_random.next_u64().to_be_bytes())
                            .map(|byte| format!("{byte:02x}"))
                            .collect()
                    }),
                phase: cgka_traits::MaintenancePhase::Complete,
                current_key_package: None,
                current_key_package_ref: None,
                current_not_before: None,
                current_not_after: None,
                authored_event_id: None,
                authored_event_created_at: None,
                authored_signed_event: None,
                publication_targets: Vec::new(),
                refresh_at: None,
                upgrade_rotation_recorded: false,
                last_consumed_key_package_ref: None,
                last_consumed_at: None,
                retained_private_material: Vec::new(),
                pending_replacement: None,
            },
        };

        if lifecycle.pending_replacement.is_none() {
            let created_at = Timestamp(
                lifecycle
                    .authored_event_created_at
                    .map(|previous| previous.0.saturating_add(1))
                    .unwrap_or(now.0)
                    .max(now.0),
            );
            if created_at.0 > now.0.saturating_add(KEY_PACKAGE_MAX_FUTURE_SKEW_SECS) {
                lifecycle.phase = cgka_traits::MaintenancePhase::ClockSkewBlocked;
                self.session.put_key_package_lifecycle(&lifecycle)?;
                return Err(AccountError::ClockSkewBlocked);
            }
            let key_package = self.session.fresh_key_package().await?;
            let metadata = self.session.key_package_metadata(&key_package)?;
            let lead = self.maintenance_random.sample_inclusive(
                KEY_PACKAGE_REFRESH_MIN_LEAD_SECS,
                KEY_PACKAGE_REFRESH_MAX_LEAD_SECS,
            );
            lifecycle.pending_replacement = Some(PendingKeyPackageReplacement {
                key_package,
                key_package_ref: hex::decode(&metadata.key_package_ref_hex)
                    .map_err(|error| cgka_traits::EngineError::Serialize(error.to_string()))?,
                authored_created_at: created_at,
                not_before: Timestamp(metadata.not_before),
                not_after: Timestamp(metadata.not_after),
                refresh_at: Timestamp(metadata.not_after.saturating_sub(lead)),
                signed_event: None,
                targets: endpoints
                    .iter()
                    .cloned()
                    .map(|endpoint| TransportFanoutTarget {
                        endpoint,
                        state: TransportFanoutAttemptState::Unattempted,
                        attempt_count: 0,
                        last_attempt_at: None,
                        failure_code: None,
                    })
                    .collect(),
                attempt_count: 0,
                last_failure_code: None,
            });
            lifecycle.phase = cgka_traits::MaintenancePhase::PendingPublication;
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }

        if lifecycle
            .pending_replacement
            .as_ref()
            .is_some_and(|pending| pending.signed_event.is_none())
        {
            let pending = lifecycle
                .pending_replacement
                .as_ref()
                .expect("unsigned pending replacement exists");
            let publication = KeyPackagePublication {
                account_id: self.session.self_id().clone(),
                key_package: pending.key_package.clone(),
                slot_id: lifecycle.stable_slot_id.clone(),
                created_at: pending.authored_created_at,
                endpoints: pending
                    .targets
                    .iter()
                    .map(|target| target.endpoint.clone())
                    .collect(),
            };
            let artifact = self.key_packages.prepare_key_package(publication).await?;
            lifecycle
                .pending_replacement
                .as_mut()
                .expect("unsigned pending replacement exists")
                .signed_event = Some(artifact);
            // Exact signed bytes are durable before the first network call.
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }

        let pending = lifecycle
            .pending_replacement
            .as_ref()
            .expect("pending replacement exists");
        let artifact = pending
            .signed_event
            .as_ref()
            .expect("prepared replacement has an exact signed event")
            .clone();
        let publication = KeyPackagePublication {
            account_id: self.session.self_id().clone(),
            key_package: pending.key_package.clone(),
            slot_id: lifecycle.stable_slot_id.clone(),
            created_at: artifact.created_at,
            endpoints: pending
                .targets
                .iter()
                .map(|target| target.endpoint.clone())
                .collect(),
        };
        let receipt = match self
            .key_packages
            .publish_prepared_key_package(&publication, &artifact)
            .await
        {
            Ok(receipt) => receipt,
            Err(error) => {
                if let Some(pending) = lifecycle.pending_replacement.as_mut() {
                    pending.attempt_count = pending.attempt_count.saturating_add(1);
                    pending.last_failure_code = Some(
                        if error.externally_exposed {
                            "ambiguous_exposure"
                        } else {
                            "publish_failed"
                        }
                        .into(),
                    );
                    note_key_package_attempt(
                        &mut pending.targets,
                        &publication.endpoints,
                        &[],
                        &[],
                        self.wall_clock.now(),
                    );
                }
                lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
                self.session.put_key_package_lifecycle(&lifecycle)?;
                return Err(error.into());
            }
        };
        if receipt.accepted.is_empty() {
            if let Some(pending) = lifecycle.pending_replacement.as_mut() {
                pending.attempt_count = pending.attempt_count.saturating_add(1);
                pending.last_failure_code = Some("no_acknowledgement".into());
                note_key_package_attempt(
                    &mut pending.targets,
                    &publication.endpoints,
                    &receipt.accepted,
                    &receipt.failed,
                    self.wall_clock.now(),
                );
            }
            lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
            self.session.put_key_package_lifecycle(&lifecycle)?;
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "no KeyPackage relay acknowledged the replacement",
            )
            .into());
        }

        let mut replacement = lifecycle
            .pending_replacement
            .take()
            .expect("published replacement exists");
        note_key_package_attempt(
            &mut replacement.targets,
            &publication.endpoints,
            &receipt.accepted,
            &receipt.failed,
            self.wall_clock.now(),
        );
        let previous = lifecycle.current_key_package.clone();
        let previous_was_consumed = lifecycle.current_key_package_ref.is_some()
            && lifecycle.current_key_package_ref == lifecycle.last_consumed_key_package_ref;
        if !previous_was_consumed
            && let (Some(key_package), Some(key_package_ref), Some(not_after)) = (
                previous.clone(),
                lifecycle.current_key_package_ref.clone(),
                lifecycle.current_not_after,
            )
        {
            lifecycle
                .retained_private_material
                .push(RetainedKeyPackagePrivateMaterial {
                    key_package,
                    key_package_ref,
                    not_after,
                    replaced_at: self.wall_clock.now(),
                });
        }
        lifecycle.current_key_package = Some(replacement.key_package.clone());
        lifecycle.current_key_package_ref = Some(replacement.key_package_ref);
        lifecycle.current_not_before = Some(replacement.not_before);
        lifecycle.current_not_after = Some(replacement.not_after);
        lifecycle.authored_event_id = Some(artifact.id.clone());
        lifecycle.authored_event_created_at = Some(artifact.created_at);
        lifecycle.authored_signed_event = Some(artifact);
        lifecycle.publication_targets = replacement.targets;
        lifecycle.refresh_at = Some(replacement.refresh_at);
        lifecycle.phase = if lifecycle.publication_targets.iter().all(|target| {
            matches!(
                target.state,
                TransportFanoutAttemptState::Accepted
                    | TransportFanoutAttemptState::PolicyProhibited
            )
        }) {
            cgka_traits::MaintenancePhase::Complete
        } else {
            cgka_traits::MaintenancePhase::Fanout
        };
        lifecycle.upgrade_rotation_recorded = true;
        lifecycle.last_consumed_key_package_ref = None;
        lifecycle.last_consumed_at = None;
        let retired = if previous_was_consumed {
            previous.into_iter().collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        self.session
            .promote_key_package_lifecycle(&retired, &lifecycle)?;
        Ok(replacement.key_package)
    }

    pub fn key_package_maintenance_status(
        &self,
    ) -> AccountResult<Option<KeyPackageLifecycleState>> {
        Ok(self.session.key_package_lifecycle()?)
    }

    pub fn key_package_network_maintenance_due(&self) -> AccountResult<bool> {
        let now = self.wall_clock.now();
        Ok(match self.session.key_package_lifecycle()? {
            None => true,
            Some(lifecycle) => match lifecycle.pending_replacement.as_ref() {
                Some(pending) => {
                    pending.signed_event.is_none()
                        || pending
                            .targets
                            .iter()
                            .any(|target| key_package_target_retry_due(target, now))
                }
                None => {
                    lifecycle.current_key_package.is_none()
                        || lifecycle.last_consumed_key_package_ref
                            == lifecycle.current_key_package_ref
                        || lifecycle.refresh_at.is_some_and(|deadline| deadline <= now)
                        || !lifecycle.upgrade_rotation_recorded
                }
            },
        })
    }

    pub fn key_package_has_pending_fanout(&self) -> AccountResult<bool> {
        Ok(self
            .session
            .key_package_lifecycle()?
            .is_some_and(|lifecycle| {
                lifecycle.authored_signed_event.is_some()
                    && lifecycle.publication_targets.iter().any(|target| {
                        matches!(
                            target.state,
                            TransportFanoutAttemptState::Unattempted
                                | TransportFanoutAttemptState::AttemptedFailed
                        )
                    })
            }))
    }

    async fn retry_key_package_fanout(&mut self) -> AccountResult<()> {
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(());
        };
        if lifecycle.pending_replacement.is_some() {
            return Ok(());
        }
        let Some(artifact) = lifecycle.authored_signed_event.clone() else {
            return Ok(());
        };
        let endpoints = lifecycle
            .publication_targets
            .iter()
            .filter(|target| key_package_target_retry_due(target, self.wall_clock.now()))
            .map(|target| target.endpoint.clone())
            .collect::<Vec<_>>();
        if endpoints.is_empty() {
            return Ok(());
        }
        let Some(key_package) = lifecycle.current_key_package.clone() else {
            return Ok(());
        };
        lifecycle.phase = cgka_traits::MaintenancePhase::Fanout;
        self.session.put_key_package_lifecycle(&lifecycle)?;
        let publication = KeyPackagePublication {
            account_id: self.session.self_id().clone(),
            key_package,
            slot_id: lifecycle.stable_slot_id.clone(),
            created_at: artifact.created_at,
            endpoints,
        };
        match self
            .key_packages
            .publish_prepared_key_package(&publication, &artifact)
            .await
        {
            Ok(receipt) => {
                note_key_package_attempt(
                    &mut lifecycle.publication_targets,
                    &publication.endpoints,
                    &receipt.accepted,
                    &receipt.failed,
                    self.wall_clock.now(),
                );
                lifecycle.phase = if lifecycle.publication_targets.iter().all(|target| {
                    matches!(
                        target.state,
                        TransportFanoutAttemptState::Accepted
                            | TransportFanoutAttemptState::PolicyProhibited
                    )
                }) {
                    cgka_traits::MaintenancePhase::Complete
                } else {
                    cgka_traits::MaintenancePhase::Fanout
                };
                self.session.put_key_package_lifecycle(&lifecycle)?;
                Ok(())
            }
            Err(error) => {
                note_key_package_attempt(
                    &mut lifecycle.publication_targets,
                    &publication.endpoints,
                    &[],
                    &[],
                    self.wall_clock.now(),
                );
                lifecycle.phase = cgka_traits::MaintenancePhase::Fanout;
                self.session.put_key_package_lifecycle(&lifecycle)?;
                Err(error.into())
            }
        }
    }

    pub fn key_package_maintenance_requires_catch_up(&self) -> AccountResult<bool> {
        let now = self.wall_clock.now();
        Ok(match self.session.key_package_lifecycle()? {
            None => true,
            Some(lifecycle) => {
                lifecycle.pending_replacement.is_none()
                    && lifecycle.last_consumed_key_package_ref != lifecycle.current_key_package_ref
                    && (lifecycle.current_key_package.is_none()
                        || lifecycle.refresh_at.is_some_and(|deadline| deadline <= now)
                        || !lifecycle.upgrade_rotation_recorded)
            }
        })
    }

    /// Delete expired private init-key material even when network maintenance
    /// is paused or transport cursor persistence is frozen.
    pub fn sweep_expired_key_package_private_material(&mut self) -> AccountResult<usize> {
        let now = self.wall_clock.now();
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(0);
        };
        let mut retired = Vec::new();
        if lifecycle
            .current_not_after
            .is_some_and(|deadline| deadline <= now)
            && let Some(expired) = lifecycle.current_key_package.take()
        {
            lifecycle.current_key_package_ref = None;
            lifecycle.current_not_before = None;
            lifecycle.current_not_after = None;
            lifecycle.authored_signed_event = None;
            lifecycle.publication_targets.clear();
            lifecycle.refresh_at = None;
            lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
            retired.push(expired);
        }
        if lifecycle
            .pending_replacement
            .as_ref()
            .is_some_and(|pending| pending.not_after <= now)
            && let Some(expired) = lifecycle.pending_replacement.take()
        {
            lifecycle.phase = cgka_traits::MaintenancePhase::Failed;
            retired.push(expired.key_package);
        }
        let consumed_ref = lifecycle.last_consumed_key_package_ref.as_deref();
        let mut consumed_retained_deleted = false;
        let mut retained = Vec::with_capacity(lifecycle.retained_private_material.len());
        for material in lifecycle.retained_private_material.drain(..) {
            let was_consumed = consumed_ref
                .is_some_and(|consumed| consumed == material.key_package_ref.as_slice());
            if material.not_after <= now || was_consumed {
                consumed_retained_deleted |= was_consumed;
                retired.push(material.key_package);
            } else {
                retained.push(material);
            }
        }
        lifecycle.retained_private_material = retained;
        if consumed_retained_deleted {
            lifecycle.last_consumed_key_package_ref = None;
            lifecycle.last_consumed_at = None;
        }
        let deleted = retired.len();
        if deleted > 0 {
            self.session
                .promote_key_package_lifecycle(&retired, &lifecycle)?;
        }
        Ok(deleted)
    }

    pub fn maintenance_status(&self, group_id: &GroupId) -> AccountResult<GroupMaintenanceStatus> {
        Ok(GroupMaintenanceStatus {
            group_id: group_id.clone(),
            state: self.session.group_maintenance(group_id)?,
            obligations: self
                .session
                .maintenance_obligations()?
                .into_iter()
                .filter(|obligation| &obligation.group_id == group_id)
                .collect(),
            evolutions: self
                .session
                .group_evolutions()?
                .into_iter()
                .filter(|evolution| &evolution.group_id == group_id)
                .collect(),
            fanouts: self
                .session
                .transport_fanouts()?
                .into_iter()
                .filter(|fanout| fanout.group_id.as_ref() == Some(group_id))
                .collect(),
            paused: self.maintenance_paused,
        })
    }

    pub fn periodic_maintenance_policy(&self) -> AccountResult<PeriodicMaintenancePolicy> {
        Ok(self.session.periodic_maintenance_policy()?)
    }

    pub fn set_periodic_maintenance_policy(
        &self,
        policy: PeriodicMaintenancePolicy,
    ) -> AccountResult<()> {
        Ok(self.session.put_periodic_maintenance_policy(policy)?)
    }

    pub fn pause_maintenance(&mut self) {
        self.maintenance_paused = true;
    }

    pub fn resume_maintenance(&mut self) {
        self.maintenance_paused = false;
    }

    pub fn maintenance_is_paused(&self) -> bool {
        self.maintenance_paused
    }

    pub fn schedule_manual_self_update(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<cgka_traits::MessageId> {
        use sha2::{Digest, Sha256};
        self.session.group_record(group_id)?;
        let now = self.wall_clock.now();
        let mut hasher = Sha256::new();
        hasher.update(b"marmot-manual-self-update-v1");
        hasher.update((group_id.as_slice().len() as u64).to_be_bytes());
        hasher.update(group_id.as_slice());
        hasher.update(now.0.to_be_bytes());
        hasher.update(self.maintenance_random.next_u64().to_be_bytes());
        let id = cgka_traits::MessageId::new(hasher.finalize().to_vec());
        let obligation = MaintenanceObligation {
            id: id.clone(),
            group_id: group_id.clone(),
            trigger: MaintenanceTrigger::Manual,
            phase: MaintenancePhase::Quiet,
            created_at: now,
            operational_target_at: None,
            overdue: false,
            eose_deadline_at: None,
            grace_until: None,
            quiet_since: Some(now),
            own_leaf_baseline_hash: Some(self.session.own_leaf_hash(group_id)?),
            sampled_jitter_ms: self.maintenance_random.sample_inclusive(0, 30_000),
            not_before: None,
            attempt_count: 0,
            semantic_rearm_count: 0,
            last_failure_code: None,
        };
        self.session.put_maintenance_obligation(&obligation)?;
        self.maintenance_quiet_monotonic
            .insert(id.clone(), self.monotonic_clock.elapsed());
        Ok(id)
    }

    /// Record successful installation of the temporary post-join
    /// full-history subscription. The five-minute EOSE deadline starts here.
    pub fn mark_post_join_subscription_installed(&self, group_id: &GroupId) -> AccountResult<()> {
        let now = self.wall_clock.now();
        for mut obligation in self.session.maintenance_obligations()? {
            if obligation.group_id == *group_id
                && obligation.trigger == MaintenanceTrigger::PostJoin
                && obligation.phase == MaintenancePhase::CatchUp
                && obligation.eose_deadline_at.is_none()
            {
                obligation.eose_deadline_at = Some(Timestamp(
                    now.0.saturating_add(MAINTENANCE_EOSE_TIMEOUT_SECS),
                ));
                self.session.put_maintenance_obligation(&obligation)?;
            }
        }
        Ok(())
    }

    pub fn mark_post_join_eose(&self, group_id: &GroupId) -> AccountResult<()> {
        let now = self.wall_clock.now();
        for mut obligation in self.session.maintenance_obligations()? {
            if obligation.group_id == *group_id
                && obligation.trigger == MaintenanceTrigger::PostJoin
                && matches!(
                    obligation.phase,
                    MaintenancePhase::CatchUp | MaintenancePhase::EoseTimeout
                )
            {
                obligation.phase = MaintenancePhase::Grace;
                obligation.grace_until = Some(Timestamp(
                    now.0.saturating_add(MAINTENANCE_POST_EOSE_GRACE_SECS),
                ));
                self.session.put_maintenance_obligation(&obligation)?;
            }
        }
        Ok(())
    }

    /// Only call this for authenticated, valid MLS commits or proposals.
    pub fn note_valid_state_bearing_input(&mut self, group_id: &GroupId) -> AccountResult<()> {
        let now = self.wall_clock.now();
        for mut obligation in self.session.maintenance_obligations()? {
            if obligation.group_id == *group_id
                && !matches!(
                    obligation.phase,
                    MaintenancePhase::Complete | MaintenancePhase::Failed
                )
            {
                obligation.phase = MaintenancePhase::Quiet;
                obligation.quiet_since = Some(now);
                obligation.not_before = None;
                self.session.put_maintenance_obligation(&obligation)?;
                self.maintenance_quiet_monotonic
                    .insert(obligation.id, self.monotonic_clock.elapsed());
            }
        }
        Ok(())
    }

    /// Advance durable maintenance state and publish work whose safety windows
    /// have elapsed. Callers may invoke this from any timer cadence; all
    /// deadlines and sampled jitter are persisted.
    pub async fn run_due_maintenance(&mut self) -> AccountResult<AccountDeviceEffects> {
        use sha2::{Digest, Sha256};

        self.sweep_expired_key_package_private_material()?;
        let mut output = AccountDeviceEffects::default();
        // Hydration recreates the publication edge for a surviving staged
        // evolution. Consume that edge before consulting the semantic
        // obligation below. Otherwise a successful retry can confirm the
        // pending evolution, drain the still-buffered hydration work as part
        // of confirmation, and attempt to confirm the same PendingStateRef a
        // second time. The durable fanout backoff in publish_one still makes
        // this safe to call before a failed target is retryable.
        let recovered = self.session.drain();
        if !recovered.is_empty() {
            let recovered = self.publish_session_effects(recovered).await?;
            output.absorb_account_effects(recovered);
        }
        let now = self.wall_clock.now();
        // Fanout of an already-acknowledged exact event is publication
        // recovery, not a new preparation, so it continues while paused.
        if self.key_package_has_pending_fanout()?
            && let Err(error) = self.retry_key_package_fanout().await
        {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "run_due_maintenance",
                error_kind = if error.to_string().is_empty() {
                    "key_package_fanout"
                } else {
                    "key_package_fanout_retry"
                },
                "key package exact-event fanout remains retryable"
            );
        }
        let key_package_due = self.key_package_network_maintenance_due()?;
        let key_package_prepared = self
            .session
            .key_package_lifecycle()?
            .is_some_and(|lifecycle| lifecycle.pending_replacement.is_some());
        if key_package_due
            && (!self.maintenance_paused || key_package_prepared)
            && let Err(error) = self.publish_fresh_key_package().await
        {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "run_due_maintenance",
                error_kind = if matches!(error, AccountError::ClockSkewBlocked) {
                    "clock_skew_blocked"
                } else {
                    "key_package_retry"
                },
                "key package maintenance remains retryable"
            );
        }
        self.retry_confirmed_transport_fanouts(&mut output).await?;

        // Old groups have no enrollment row and are intentionally excluded.
        for group_id in if self.maintenance_paused {
            Vec::new()
        } else {
            self.session.live_group_ids()?
        } {
            let Some(mut state) = self.session.group_maintenance(&group_id)? else {
                continue;
            };
            if !state.periodic_enrolled {
                continue;
            }
            let has_active =
                self.session
                    .maintenance_obligations()?
                    .into_iter()
                    .any(|obligation| {
                        obligation.group_id == group_id
                            && !matches!(
                                obligation.phase,
                                MaintenancePhase::Complete | MaintenancePhase::Failed
                            )
                    });
            if has_active {
                continue;
            }
            if state.next_periodic_rotation_at.is_none()
                && let Some(last_rotation) = state.last_own_leaf_rotation_at
            {
                state.next_periodic_rotation_at = Some(Timestamp(
                    last_rotation.0.saturating_add(
                        self.maintenance_random
                            .sample_inclusive(PERIODIC_MIN_SECS, PERIODIC_MAX_SECS),
                    ),
                ));
                self.session.put_group_maintenance(&state)?;
            }
            if state
                .next_periodic_rotation_at
                .is_some_and(|deadline| deadline <= now)
            {
                let mut hasher = Sha256::new();
                hasher.update(b"marmot-periodic-self-update-v1");
                hasher.update((group_id.as_slice().len() as u64).to_be_bytes());
                hasher.update(group_id.as_slice());
                hasher.update(
                    state
                        .next_periodic_rotation_at
                        .expect("checked above")
                        .0
                        .to_be_bytes(),
                );
                let id = cgka_traits::MessageId::new(hasher.finalize().to_vec());
                let obligation = MaintenanceObligation {
                    id: id.clone(),
                    group_id: group_id.clone(),
                    trigger: MaintenanceTrigger::Periodic,
                    phase: MaintenancePhase::Quiet,
                    created_at: now,
                    operational_target_at: None,
                    overdue: false,
                    eose_deadline_at: None,
                    grace_until: None,
                    quiet_since: Some(now),
                    own_leaf_baseline_hash: Some(self.session.own_leaf_hash(&group_id)?),
                    sampled_jitter_ms: self.maintenance_random.sample_inclusive(0, 15 * 60 * 1_000),
                    not_before: None,
                    attempt_count: 0,
                    semantic_rearm_count: 0,
                    last_failure_code: None,
                };
                self.session.put_maintenance_obligation(&obligation)?;
                self.maintenance_quiet_monotonic
                    .insert(id, self.monotonic_clock.elapsed());
            }
        }

        let mut obligations = self.session.maintenance_obligations()?;
        obligations.sort_by_key(|obligation| obligation.created_at);
        for mut obligation in obligations {
            if matches!(
                obligation.phase,
                MaintenancePhase::Complete | MaintenancePhase::Failed
            ) {
                continue;
            }
            if obligation
                .operational_target_at
                .is_some_and(|target| target <= now)
            {
                obligation.overdue = true;
            }

            if self.maintenance_paused {
                let has_prepared_evolution =
                    self.session
                        .group_evolutions()?
                        .into_iter()
                        .any(|evolution| {
                            evolution.phase != GroupEvolutionPhase::SupersededByConvergence
                                && matches!(
                                    &evolution.semantic,
                                    GroupEvolutionSemantic::SelfUpdate {
                                        obligation_id,
                                        ..
                                    } if obligation_id == &obligation.id
                                )
                                && matches!(
                                    evolution.phase,
                                    GroupEvolutionPhase::Prepared | GroupEvolutionPhase::Attempting
                                )
                        });
                if !has_prepared_evolution {
                    self.session.put_maintenance_obligation(&obligation)?;
                    continue;
                }
            }

            match obligation.phase {
                MaintenancePhase::CatchUp => {
                    if obligation
                        .eose_deadline_at
                        .is_some_and(|deadline| deadline <= now)
                    {
                        obligation.phase = MaintenancePhase::EoseTimeout;
                        obligation.grace_until = Some(Timestamp(
                            now.0.saturating_add(MAINTENANCE_POST_EOSE_GRACE_SECS),
                        ));
                    }
                    self.session.put_maintenance_obligation(&obligation)?;
                    continue;
                }
                MaintenancePhase::EoseTimeout | MaintenancePhase::Grace => {
                    if obligation.grace_until.is_none_or(|deadline| deadline > now) {
                        self.session.put_maintenance_obligation(&obligation)?;
                        continue;
                    }
                    obligation.phase = MaintenancePhase::Quiet;
                    obligation.quiet_since = Some(now);
                    self.maintenance_quiet_monotonic
                        .insert(obligation.id.clone(), self.monotonic_clock.elapsed());
                    self.session.put_maintenance_obligation(&obligation)?;
                    continue;
                }
                MaintenancePhase::Quiet => {
                    let quiet_long_enough = self
                        .maintenance_quiet_monotonic
                        .get(&obligation.id)
                        .map(|started| {
                            self.monotonic_clock.elapsed().saturating_sub(*started)
                                >= Duration::from_secs(MAINTENANCE_QUIET_SECS)
                        })
                        .unwrap_or_else(|| {
                            obligation.quiet_since.is_some_and(|started| {
                                now.0.saturating_sub(started.0) >= MAINTENANCE_QUIET_SECS
                            })
                        });
                    if !quiet_long_enough {
                        self.session.put_maintenance_obligation(&obligation)?;
                        continue;
                    }
                    let jitter_secs = obligation.sampled_jitter_ms.saturating_add(999) / 1_000;
                    obligation.phase = MaintenancePhase::Jitter;
                    obligation.not_before = Some(Timestamp(now.0.saturating_add(jitter_secs)));
                    self.session.put_maintenance_obligation(&obligation)?;
                    continue;
                }
                MaintenancePhase::Jitter => {
                    if obligation.not_before.is_none_or(|deadline| deadline > now) {
                        self.session.put_maintenance_obligation(&obligation)?;
                        continue;
                    }
                }
                MaintenancePhase::PendingPublication | MaintenancePhase::Retry => {
                    if let Some(evolution) =
                        self.session
                            .group_evolutions()?
                            .into_iter()
                            .find(|evolution| {
                                evolution.phase != GroupEvolutionPhase::SupersededByConvergence
                                    && matches!(
                                        &evolution.semantic,
                                        GroupEvolutionSemantic::SelfUpdate {
                                            obligation_id,
                                            ..
                                        } if obligation_id == &obligation.id
                                    )
                            })
                    {
                        if evolution.phase == GroupEvolutionPhase::Confirmed {
                            self.complete_maintenance_obligation(&mut obligation, now)?;
                            continue;
                        }
                        if let (Some(pending), Some(message_id)) =
                            (evolution.pending_ref, evolution.signed_message_id)
                            && let Some(fanout) = self.session.transport_fanout(&message_id)?
                        {
                            let retry = SessionEffects {
                                events: Vec::new(),
                                publish: vec![PublishWork::AutoPublish {
                                    msg: fanout.exact_message,
                                    pending,
                                }],
                                queued: Vec::new(),
                                pending_convergence: Vec::new(),
                            };
                            let retried = self.publish_session_effects(retry).await?;
                            let confirmed = retried.pending.iter().any(|resolution| {
                                matches!(
                                    resolution,
                                    PendingResolution::Confirmed { pending: resolved }
                                        if *resolved == pending
                                )
                            });
                            output.absorb_account_effects(retried);
                            if confirmed {
                                self.complete_maintenance_obligation(&mut obligation, now)?;
                            } else {
                                obligation.phase = MaintenancePhase::PendingPublication;
                                obligation.attempt_count =
                                    obligation.attempt_count.saturating_add(1);
                                self.session.put_maintenance_obligation(&obligation)?;
                            }
                            continue;
                        }
                    }
                    obligation.phase = MaintenancePhase::Retry;
                }
                MaintenancePhase::Paused
                | MaintenancePhase::Overdue
                | MaintenancePhase::ClockSkewBlocked
                | MaintenancePhase::Fanout
                | MaintenancePhase::SupersededByConvergence => {
                    obligation.phase = MaintenancePhase::Retry;
                }
                MaintenancePhase::Complete | MaintenancePhase::Failed => continue,
            }

            if self
                .session
                .has_pending_convergence_inputs(&obligation.group_id)?
                || self
                    .session
                    .quarantined_groups()
                    .iter()
                    .any(|(group_id, _)| group_id == &obligation.group_id)
            {
                obligation.phase = MaintenancePhase::Retry;
                obligation.last_failure_code = Some("safety_gate".into());
                self.session.put_maintenance_obligation(&obligation)?;
                continue;
            }

            let group_id = obligation.group_id.clone();
            match self
                .send(SendIntent::SelfUpdate {
                    group_id: group_id.clone(),
                })
                .await
            {
                Ok(effects) => {
                    let confirmed = effects.pending.iter().any(|resolution| {
                        matches!(resolution, PendingResolution::Confirmed { .. })
                    });
                    output.absorb_account_effects(effects);
                    if confirmed {
                        self.complete_maintenance_obligation(&mut obligation, now)?;
                    } else {
                        obligation.phase = MaintenancePhase::PendingPublication;
                        obligation.attempt_count = obligation.attempt_count.saturating_add(1);
                        self.session.put_maintenance_obligation(&obligation)?;
                    }
                }
                Err(error) => {
                    obligation.phase = MaintenancePhase::Retry;
                    obligation.attempt_count = obligation.attempt_count.saturating_add(1);
                    obligation.last_failure_code = Some(
                        if error.to_string().is_empty() {
                            "maintenance_send_failed"
                        } else {
                            "maintenance_deferred"
                        }
                        .into(),
                    );
                    self.session.put_maintenance_obligation(&obligation)?;
                }
            }
        }
        Ok(output)
    }

    fn complete_maintenance_obligation(
        &mut self,
        obligation: &mut MaintenanceObligation,
        completed_at: Timestamp,
    ) -> AccountResult<()> {
        obligation.phase = MaintenancePhase::Complete;
        obligation.last_failure_code = None;
        self.session.put_maintenance_obligation(obligation)?;
        self.maintenance_quiet_monotonic.remove(&obligation.id);
        if let Some(mut state) = self.session.group_maintenance(&obligation.group_id)? {
            state.last_own_leaf_rotation_at = Some(completed_at);
            state.next_periodic_rotation_at = state.periodic_enrolled.then(|| {
                Timestamp(
                    completed_at.0.saturating_add(
                        self.maintenance_random
                            .sample_inclusive(PERIODIC_MIN_SECS, PERIODIC_MAX_SECS),
                    ),
                )
            });
            self.session.put_group_maintenance(&state)?;
        }
        Ok(())
    }

    pub async fn create_group(
        &mut self,
        request: CreateGroupRequest,
    ) -> AccountResult<(GroupId, AccountDeviceEffects)> {
        let CreateGroupEffects { group_id, effects } = self.session.create_group(request).await?;
        let effects = self.publish_session_effects(effects).await?;
        Ok((group_id, effects))
    }

    pub fn constructable_capabilities(
        &self,
        key_packages: &[cgka_traits::engine::KeyPackage],
    ) -> AccountResult<cgka_traits::capabilities::GroupCapabilities> {
        Ok(self.session.constructable_capabilities(key_packages)?)
    }

    pub async fn create_group_with_audit_context(
        &mut self,
        request: CreateGroupRequest,
        context: AuditEventContext,
    ) -> AccountResult<(GroupId, AccountDeviceEffects)> {
        let CreateGroupEffects { group_id, effects } = self
            .prepare_create_group_with_audit_context(request, context.clone())
            .await?;
        let effects = self
            .publish_prepared_session_effects_with_audit_context(effects, context)
            .await?;
        Ok((group_id, effects))
    }

    /// Prepare group creation without performing transport side effects.
    ///
    /// The application runtime uses this seam to durably record every
    /// current-profile founding Welcome obligation before the first publish
    /// attempt. Callers must subsequently pass the returned effects to
    /// [`Self::publish_prepared_session_effects_with_audit_context`].
    pub async fn prepare_create_group_with_audit_context(
        &mut self,
        request: CreateGroupRequest,
        context: AuditEventContext,
    ) -> AccountResult<CreateGroupEffects> {
        self.prepare_create_group_with_optional_app_components_and_audit_context(
            request,
            Vec::new(),
            context,
        )
        .await
    }

    pub async fn prepare_create_group_with_optional_app_components_and_audit_context(
        &mut self,
        request: CreateGroupRequest,
        optional_app_components: Vec<cgka_traits::app_components::AppComponentData>,
        context: AuditEventContext,
    ) -> AccountResult<CreateGroupEffects> {
        Ok(self
            .session
            .create_group_with_optional_app_components_and_audit_context(
                request,
                optional_app_components,
                context,
            )
            .await?)
    }

    /// Publish effects returned by
    /// [`Self::prepare_create_group_with_audit_context`].
    pub async fn publish_prepared_session_effects_with_audit_context(
        &mut self,
        effects: SessionEffects,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        self.publish_session_effects_with_audit_context(effects, Some(context))
            .await
    }

    pub async fn send(&mut self, intent: SendIntent) -> AccountResult<AccountDeviceEffects> {
        let disposition_group = match &intent {
            SendIntent::AppMessage { group_id, .. } => Some(group_id.clone()),
            _ => None,
        };
        let effects = self.session.send(intent).await?;
        let mut output = self.publish_session_effects(effects).await?;
        if let Some(group_id) = disposition_group
            && self
                .session
                .maintenance_obligations()?
                .into_iter()
                .any(|obligation| {
                    obligation.group_id == group_id
                        && obligation.trigger == MaintenanceTrigger::PostJoin
                        && !matches!(
                            obligation.phase,
                            MaintenancePhase::Complete | MaintenancePhase::Failed
                        )
                })
        {
            output.maintenance_disposition =
                SendMaintenanceDisposition::PostJoinRotationPendingRetryable;
        }
        Ok(output)
    }

    pub async fn send_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let disposition_group = match &intent {
            SendIntent::AppMessage { group_id, .. } => Some(group_id.clone()),
            _ => None,
        };
        let effects = self
            .session
            .send_with_audit_context(intent, context.clone())
            .await?;
        let mut output = self
            .publish_session_effects_with_audit_context(effects, Some(context))
            .await?;
        if let Some(group_id) = disposition_group
            && self
                .session
                .maintenance_obligations()?
                .into_iter()
                .any(|obligation| {
                    obligation.group_id == group_id
                        && obligation.trigger == MaintenanceTrigger::PostJoin
                        && !matches!(
                            obligation.phase,
                            MaintenancePhase::Complete | MaintenancePhase::Failed
                        )
                })
        {
            output.maintenance_disposition =
                SendMaintenanceDisposition::PostJoinRotationPendingRetryable;
        }
        Ok(output)
    }

    pub async fn advance_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<AccountDeviceEffects> {
        let effects = self.session.advance_convergence(group_id).await?;
        self.publish_session_effects(effects).await
    }

    pub fn has_pending_convergence_inputs(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.has_pending_convergence_inputs(group_id)?)
    }

    pub fn members(&self, group_id: &GroupId) -> AccountResult<Vec<Member>> {
        Ok(self.session.members(group_id)?)
    }

    pub fn own_leaf_index(&self, group_id: &GroupId) -> AccountResult<u32> {
        Ok(self.session.own_leaf_index(group_id)?)
    }

    /// Drain any session effects queued by the engine without an inbound
    /// transport delivery (e.g. `GroupHydrationQuarantined` queued during
    /// `open()` hydration, or `GroupHydrationRecovered` queued by a successful
    /// `retry_hydrate_quarantined_group`). Without this, those events only
    /// reach app/runtime subscribers when an unrelated relay delivery happens
    /// to trigger a drain (mdk#426). Publishes any incidental transport
    /// work the same way `ingest_delivery` does.
    pub async fn drain(&mut self) -> AccountResult<AccountDeviceEffects> {
        let effects = self.session.drain();
        let mut output = self.publish_session_effects(effects).await?;
        let resumed = self.resume_outbound_fanouts().await?;
        output.extend(resumed);
        Ok(output)
    }

    pub async fn ingest_delivery(
        &mut self,
        delivery: TransportDelivery,
    ) -> AccountResult<AccountIngestEffects> {
        if delivery.account_id != self.session.self_id() {
            return Err(AccountError::WrongAccountDelivery);
        }
        let IngestEffects {
            outcome,
            effects,
            valid_proposal_groups,
        } = self.session.ingest_delivery(delivery).await?;
        let effects = self.publish_session_effects(effects).await?;
        let mut state_bearing_groups = effects
            .events
            .iter()
            .filter_map(|event| match event {
                GroupEvent::EpochChanged { group_id, .. } => Some(group_id.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        state_bearing_groups.extend(valid_proposal_groups);
        let mut unique_state_bearing_groups = Vec::new();
        for group_id in state_bearing_groups {
            if !unique_state_bearing_groups.contains(&group_id) {
                self.note_valid_state_bearing_input(&group_id)?;
                unique_state_bearing_groups.push(group_id);
            }
        }
        Ok(AccountIngestEffects { outcome, effects })
    }

    pub async fn publish_session_effects(
        &mut self,
        effects: SessionEffects,
    ) -> AccountResult<AccountDeviceEffects> {
        self.publish_session_effects_with_audit_context(effects, None)
            .await
    }

    async fn publish_session_effects_with_audit_context(
        &mut self,
        effects: SessionEffects,
        context: Option<AuditEventContext>,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        let mut queue = VecDeque::new();
        output.absorb_session_effects(effects, &mut queue);
        self.publish_queue(&mut output, &mut queue, context).await?;
        self.reconcile_confirmed_own_leaf_rotations(&output.events)?;
        self.reconcile_superseded_maintenance(&output.events)?;
        Ok(output)
    }

    async fn publish_queue(
        &mut self,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        while let Some(work) = queue.pop_front() {
            match work {
                PublishWork::ApplicationMessage {
                    msg,
                    queued_intent,
                    group_id,
                    app_event_id,
                    source_epoch,
                    retention,
                } => {
                    let reports_before = output.reports.len();
                    let status =
                        Box::pin(self.publish_one(msg, None, output, queue, context.clone()))
                            .await?;
                    if status.accepted_by_any_endpoint {
                        if let Some(message_id) = output
                            .reports
                            .get(reports_before)
                            .map(|report| report.message_id.clone())
                        {
                            output
                                .published_app_messages
                                .push(PublishedApplicationMessage {
                                    group_id,
                                    app_event_id,
                                    message_id,
                                    source_epoch,
                                    retention,
                                });
                        } else {
                            tracing::warn!(
                                target: TRACE_TARGET,
                                method = "publish_session_effects_with_audit_context",
                                error_kind = "accepted_app_publish_report_missing",
                                "accepted application publish had no transport report"
                            );
                        }
                    }
                    self.resolve_regenerated_queued_intent(queued_intent, status);
                }
                PublishWork::Proposal { msg, queued_intent } => {
                    let status =
                        Box::pin(self.publish_one(msg, None, output, queue, context.clone()))
                            .await?;
                    self.resolve_regenerated_queued_intent(queued_intent, status);
                }
                PublishWork::GroupCreated { welcomes, pending } => {
                    Box::pin(self.publish_group_created(
                        welcomes,
                        pending,
                        output,
                        queue,
                        context.clone(),
                    ))
                    .await?;
                }
                PublishWork::FoundingGroupCreated { welcomes } => {
                    self.publish_founding_group_created(welcomes, output, queue, context.clone())
                        .await?;
                }
                PublishWork::GroupEvolution {
                    msg,
                    welcomes,
                    pending,
                } => {
                    Box::pin(self.publish_group_evolution(
                        msg,
                        welcomes,
                        pending,
                        output,
                        queue,
                        context.clone(),
                    ))
                    .await?;
                }
                PublishWork::AutoPublish { msg, pending } => {
                    self.publish_pending(vec![msg], pending, output, queue, context.clone())
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// Resume every incomplete frozen fanout in original staging order.
    pub async fn resume_outbound_fanouts(&mut self) -> AccountResult<AccountDeviceEffects> {
        let fanouts = self.session.outbound_fanouts()?;
        let mut output = AccountDeviceEffects::default();
        let mut queue = VecDeque::new();
        for fanout in fanouts {
            let outcome = fanout.outcome();
            if outcome.outstanding_targets > 0
                || matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
            {
                Box::pin(self.drive_outbound_fanout(fanout, &mut output, &mut queue, None)).await?;
            } else {
                self.session.delete_outbound_fanout(fanout.message_id())?;
            }
        }
        self.publish_queue(&mut output, &mut queue, None).await?;
        self.reconcile_confirmed_own_leaf_rotations(&output.events)?;
        self.reconcile_superseded_maintenance(&output.events)?;
        Ok(output)
    }

    fn reconcile_confirmed_own_leaf_rotations(
        &mut self,
        events: &[GroupEvent],
    ) -> AccountResult<()> {
        let changed_groups = events
            .iter()
            .filter_map(|event| match event {
                GroupEvent::EpochChanged { group_id, .. } => Some(group_id.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut unique_changed_groups = Vec::new();
        let now = self.wall_clock.now();
        for group_id in changed_groups {
            if unique_changed_groups.contains(&group_id) {
                continue;
            }
            unique_changed_groups.push(group_id.clone());
            let self_id = self.session.self_id();
            let local_member_present = self
                .session
                .members(&group_id)?
                .iter()
                .any(|member| member.id == self_id);
            if !local_member_present {
                for mut obligation in self.session.maintenance_obligations()? {
                    if obligation.group_id != group_id
                        || matches!(
                            obligation.phase,
                            MaintenancePhase::Complete | MaintenancePhase::Failed
                        )
                    {
                        continue;
                    }
                    obligation.phase = MaintenancePhase::Failed;
                    obligation.last_failure_code = Some("local_member_removed".into());
                    self.session.put_maintenance_obligation(&obligation)?;
                    self.maintenance_quiet_monotonic.remove(&obligation.id);
                }
                if let Some(mut state) = self.session.group_maintenance(&group_id)? {
                    state.periodic_enrolled = false;
                    state.next_periodic_rotation_at = None;
                    self.session.put_group_maintenance(&state)?;
                }
                continue;
            }
            let current = self.session.own_leaf_hash(&group_id)?;
            for mut obligation in self.session.maintenance_obligations()? {
                if obligation.group_id != group_id
                    || matches!(
                        obligation.phase,
                        MaintenancePhase::Complete | MaintenancePhase::Failed
                    )
                {
                    continue;
                }
                if obligation
                    .own_leaf_baseline_hash
                    .as_ref()
                    .is_some_and(|baseline| baseline.as_slice() != current.as_slice())
                {
                    self.complete_maintenance_obligation(&mut obligation, now)?;
                }
            }
        }
        Ok(())
    }

    fn reconcile_superseded_maintenance(&mut self, events: &[GroupEvent]) -> AccountResult<()> {
        let superseded = events
            .iter()
            .filter_map(|event| match event {
                GroupEvent::GroupStateInvalidated {
                    group_id,
                    invalidated_commit_id,
                    ..
                } => Some((group_id.clone(), invalidated_commit_id.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();
        if superseded.is_empty() {
            return Ok(());
        }

        let now = self.wall_clock.now();
        for (group_id, invalidated_commit_id) in superseded {
            let evolutions = self.session.group_evolutions()?;
            for mut evolution in evolutions.into_iter().filter(|evolution| {
                evolution.group_id == group_id
                    && evolution.signed_message_id.as_ref() == Some(&invalidated_commit_id)
                    && evolution.phase != GroupEvolutionPhase::SupersededByConvergence
            }) {
                evolution.phase = GroupEvolutionPhase::SupersededByConvergence;
                self.session.put_group_evolution(&evolution)?;

                let GroupEvolutionSemantic::SelfUpdate { obligation_id, .. } = evolution.semantic
                else {
                    continue;
                };
                let Some(mut obligation) = self.session.maintenance_obligation(&obligation_id)?
                else {
                    continue;
                };
                let selected_branch_rotated_own_leaf = evolution
                    .own_leaf_before_hash
                    .as_ref()
                    .is_some_and(|before| {
                        self.session
                            .own_leaf_hash(&group_id)
                            .is_ok_and(|current| current.as_slice() != before.as_slice())
                    });
                if selected_branch_rotated_own_leaf {
                    self.complete_maintenance_obligation(&mut obligation, now)?;
                } else {
                    obligation.phase = MaintenancePhase::Quiet;
                    obligation.quiet_since = Some(now);
                    obligation.not_before = None;
                    obligation.semantic_rearm_count =
                        obligation.semantic_rearm_count.saturating_add(1);
                    obligation.last_failure_code = Some("superseded_by_convergence".into());
                    self.maintenance_quiet_monotonic
                        .insert(obligation.id.clone(), self.monotonic_clock.elapsed());
                    self.session.put_maintenance_obligation(&obligation)?;
                }
            }
        }
        Ok(())
    }

    fn resolve_regenerated_queued_intent(
        &mut self,
        intent: Option<QueuedIntentRef>,
        status: PublishStatus,
    ) {
        let Some(intent) = intent else {
            return;
        };
        if status.met_required_acks || status.accepted_by_any_endpoint {
            if self
                .session
                .confirm_regenerated_queued_intent(&intent)
                .is_err()
            {
                // The message is externally visible, so do not report the send
                // as failed. Keep the durable intent and re-arm convergence;
                // the duplicate-safe publish layer can retry cleanup later.
                self.session.retry_regenerated_queued_intent(&intent);
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "resolve_regenerated_queued_intent",
                    error_kind = "queued_intent_cleanup",
                    "published queued message but could not clear its durable intent"
                );
            }
        } else {
            // Nothing accepted the publish. The durable intent was never
            // deleted; re-arm its group for the normal convergence retry.
            self.session.retry_regenerated_queued_intent(&intent);
        }
    }

    /// Confirm a published commit, retrying on transient backend contention.
    ///
    /// `confirm_published` is the apply half of publish-before-apply: by the
    /// time it runs the commit is already on the wire, so abandoning it on a
    /// transient `SQLITE_BUSY` would leave the local device behind an epoch the
    /// group has accepted — a self-inflicted fork seam. The engine's confirm
    /// path is structured to be retry-safe (the in-memory state-machine
    /// transition only runs after its durable storage transaction commits), so
    /// re-running after a lock blip converges. The backend already blocks up to
    /// its `busy_timeout` per attempt; these few extra attempts cover the rare
    /// case where contention outlives that window. A non-transient error, or
    /// exhausted attempts, propagates as before.
    async fn confirm_published_retrying(
        &mut self,
        pending: PendingStateRef,
    ) -> AccountResult<SessionEffects> {
        const MAX_CONFIRM_ATTEMPTS: u32 = 4;
        let mut attempt = 0;
        loop {
            match self.session.confirm_published(pending).await {
                Ok(effects) => return Ok(effects),
                Err(e) if e.is_transient() && attempt + 1 < MAX_CONFIRM_ATTEMPTS => {
                    attempt += 1;
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "confirm_published_retrying",
                        attempt,
                        "confirm hit a transient backend lock; retrying"
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn confirm_published_fanout_retrying(
        &mut self,
        pending: PendingStateRef,
        fanout: &mut OutboundFanout,
    ) -> AccountResult<SessionEffects> {
        const MAX_CONFIRM_ATTEMPTS: u32 = 4;
        let mut attempt = 0;
        loop {
            match self.session.confirm_published_fanout(pending, fanout).await {
                Ok(effects) => return Ok(effects),
                Err(e) if e.is_transient() && attempt + 1 < MAX_CONFIRM_ATTEMPTS => {
                    attempt += 1;
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "confirm_published_fanout_retrying",
                        attempt,
                        "fanout confirm hit a transient backend lock; retrying"
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn publish_pending(
        &mut self,
        messages: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        let maintenance_evolution = messages.len() == 1
            && self
                .session
                .group_evolutions()?
                .into_iter()
                .any(|evolution| {
                    evolution.signed_message_id.as_ref()
                        == messages.first().map(|message| &message.id)
                });
        if maintenance_evolution {
            // A crash can land after the first relay acknowledgement and its
            // durable maintenance-fanout write but before local MLS
            // confirmation. The accepted target is sufficient evidence to
            // apply the original staged evolution without another exposure.
            if let [message] = messages.as_slice()
                && let Some(fanout) = self.session.transport_fanout(&message.id)?
                && fanout
                    .targets
                    .iter()
                    .any(|target| target.state == TransportFanoutAttemptState::Accepted)
            {
                let effects = self.confirm_published_retrying(pending).await?;
                output
                    .pending
                    .push(PendingResolution::Confirmed { pending });
                output.absorb_session_effects(effects, queue);
                self.mark_transport_fanout_evolution_confirmed(&message.id);
                self.finish_transport_fanout(&message.id, output).await?;
                return Ok(());
            }

            let mut all_published = true;
            let mut any_accepted = false;
            let mut ambiguous_exposure = false;
            let mut retry_deferred = false;
            let mut message_ids = Vec::with_capacity(messages.len());
            for message in messages {
                message_ids.push(message.id.clone());
                let status = self
                    .publish_legacy_one(message, output, context.clone())
                    .await?;
                any_accepted |= status.accepted_by_any_endpoint;
                all_published &= status.met_required_acks;
                ambiguous_exposure |= status.possible_ambiguous_exposure;
                retry_deferred |= status.retry_deferred;
            }

            if all_published || any_accepted {
                let effects = self.confirm_published_retrying(pending).await?;
                output
                    .pending
                    .push(PendingResolution::Confirmed { pending });
                output.absorb_session_effects(effects, queue);
                for message_id in message_ids {
                    self.mark_transport_fanout_evolution_confirmed(&message_id);
                    self.finish_transport_fanout(&message_id, output).await?;
                }
            } else if !ambiguous_exposure && !retry_deferred {
                let effects = self.session.publish_failed(pending).await?;
                output
                    .pending
                    .push(PendingResolution::RolledBack { pending });
                output.absorb_session_effects(effects, queue);
            }
            return Ok(());
        }

        // A pending MLS state has one frozen group-message artifact. Its first
        // relay acknowledgement releases MLS inside `drive_outbound_fanout`;
        // remaining targets continue as an independent durable obligation.
        let mut messages = messages.into_iter();
        let Some(message) = messages.next() else {
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
            return Ok(());
        };
        debug_assert!(messages.next().is_none());
        Box::pin(self.publish_one(message, Some(pending), output, queue, context)).await?;
        Ok(())
    }

    async fn publish_group_created(
        &mut self,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        let mut all_published = true;
        let mut any_welcome_exposed = false;
        let mut retry_deferred = false;
        let mut welcome_failures = Vec::new();
        let mut delivered_welcome_ids = Vec::new();
        for welcome in welcomes {
            let recipient = welcome_recipient(&welcome);
            let welcome_id = welcome.id.clone();
            let failures_before = output.failures.len();
            let status =
                Box::pin(self.publish_one(welcome, None, output, queue, context.clone())).await?;
            any_welcome_exposed |= status.accepted_by_any_endpoint;
            retry_deferred |= status.retry_deferred;
            if status.met_required_acks {
                delivered_welcome_ids.push(welcome_id);
            } else {
                if let Some(recipient) = recipient {
                    welcome_failures.push(self.welcome_delivery_failure(
                        welcome_id,
                        recipient,
                        None,
                        output,
                        failures_before,
                    ));
                }
                all_published = false;
                if !any_welcome_exposed {
                    break;
                }
            }
        }

        if all_published || any_welcome_exposed {
            let effects = self.confirm_published_retrying(pending).await?;
            let group_id = confirmed_group_id(&effects);
            output
                .pending
                .push(PendingResolution::Confirmed { pending });
            output.absorb_session_effects(effects, queue);
            for message_id in &delivered_welcome_ids {
                self.mark_welcome_delivered_best_effort(message_id);
            }
            for failure in &mut welcome_failures {
                if failure.group_id.is_none() {
                    failure.group_id = group_id.clone();
                }
            }
            // Only a confirmed legacy create leaves welcomes worth
            // re-delivering; a rolled-back create discards the whole
            // evolution, welcomes included.
            output.welcome_failures.extend(welcome_failures);
        } else if !retry_deferred {
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
        }
        Ok(())
    }

    async fn publish_founding_group_created(
        &mut self,
        welcomes: Vec<TransportMessage>,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        let group_id = output.events.iter().find_map(|event| match event {
            GroupEvent::GroupCreated { group_id } => Some(group_id.clone()),
            _ => None,
        });
        for welcome in welcomes {
            let recipient = welcome_recipient(&welcome);
            let welcome_id = welcome.id.clone();
            let failures_before = output.failures.len();
            let status = self
                .publish_one(welcome, None, output, queue, context.clone())
                .await?;
            if status.met_required_acks {
                self.mark_welcome_delivered_best_effort(&welcome_id);
            } else if let Some(recipient) = recipient {
                output.welcome_failures.push(self.welcome_delivery_failure(
                    welcome_id,
                    recipient,
                    group_id.clone(),
                    output,
                    failures_before,
                ));
            }
        }
        Ok(())
    }

    async fn publish_group_evolution(
        &mut self,
        commit: TransportMessage,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        let commit_id = commit.id.clone();
        let maintenance_evolution = self
            .session
            .group_evolutions()?
            .into_iter()
            .any(|evolution| {
                evolution.signed_message_id.as_ref() == Some(&commit_id)
                    && matches!(
                        evolution.semantic,
                        GroupEvolutionSemantic::SelfUpdate { .. }
                    )
            });
        if maintenance_evolution {
            let commit_status = self
                .publish_legacy_one(commit, output, context.clone())
                .await?;
            if commit_status.met_required_acks || commit_status.accepted_by_any_endpoint {
                let effects = self.confirm_published_retrying(pending).await?;
                output
                    .pending
                    .push(PendingResolution::Confirmed { pending });
                output.absorb_session_effects(effects, queue);
                self.mark_transport_fanout_evolution_confirmed(&commit_id);
                self.finish_transport_fanout(&commit_id, output).await?;
                debug_assert!(welcomes.is_empty());
                return Ok(());
            }
            if !commit_status.possible_ambiguous_exposure && !commit_status.retry_deferred {
                let effects = self.session.publish_failed(pending).await?;
                output
                    .pending
                    .push(PendingResolution::RolledBack { pending });
                output.absorb_session_effects(effects, queue);
            }
            return Ok(());
        }

        let commit_status =
            Box::pin(self.publish_one(commit, Some(pending), output, queue, context.clone()))
                .await?;
        if commit_status.accepted_by_any_endpoint {
            let group_id = confirmed_group_id_from_events(&output.events);
            for welcome in welcomes {
                let recipient = welcome_recipient(&welcome);
                let welcome_id = welcome.id.clone();
                let failures_before = output.failures.len();
                let status =
                    Box::pin(self.publish_one(welcome, None, output, queue, context.clone()))
                        .await?;
                if status.met_required_acks {
                    self.mark_welcome_delivered_best_effort(&welcome_id);
                } else {
                    // The commit is already confirmed, so this member's join
                    // hinges on re-delivering exactly this welcome.
                    if let Some(recipient) = recipient {
                        let failure = self.welcome_delivery_failure(
                            welcome_id,
                            recipient,
                            group_id.clone(),
                            output,
                            failures_before,
                        );
                        output.welcome_failures.push(failure);
                    }
                }
            }
        }
        Ok(())
    }

    fn mark_transport_fanout_evolution_confirmed(&self, message_id: &cgka_traits::MessageId) {
        let Ok(Some(mut fanout)) = self.session.transport_fanout(message_id) else {
            return;
        };
        fanout.evolution_confirmed = true;
        if let Err(error) = self.session.put_transport_fanout(&fanout) {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "mark_transport_fanout_evolution_confirmed",
                transient = error.is_transient(),
                "confirmed evolution fanout remains conservatively unconfirmed"
            );
        }
    }

    async fn retry_confirmed_transport_fanouts(
        &self,
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<()> {
        let now = self.wall_clock.now();
        for fanout in self.session.transport_fanouts()? {
            if fanout
                .bounded_until
                .is_some_and(|bounded_until| bounded_until <= now)
            {
                continue;
            }
            if fanout.evolution_id.is_some() && !fanout.evolution_confirmed {
                continue;
            }
            self.finish_transport_fanout(&fanout.id, output).await?;
        }
        Ok(())
    }

    /// Complete the endpoint snapshot for an already-persisted exact event.
    ///
    /// Group evolutions call this only after the first accepted acknowledgement
    /// has been applied locally. These attempts therefore cannot reopen the MLS
    /// pending state or change the canonical branch.
    async fn finish_transport_fanout(
        &self,
        message_id: &cgka_traits::MessageId,
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<()> {
        let Some(mut fanout) = self.session.transport_fanout(message_id)? else {
            return Ok(());
        };
        let remaining = fanout
            .targets
            .iter()
            .filter(|target| transport_fanout_target_retry_due(target, self.wall_clock.now()))
            .map(|target| target.endpoint.clone())
            .collect::<Vec<_>>();
        for endpoint in remaining {
            let target = publish_target_for_endpoint(&fanout.target, endpoint.clone());
            match self
                .adapter
                .publish(TransportPublishRequest {
                    account_id: self.session.self_id(),
                    message: fanout.exact_message.clone(),
                    target,
                    required_acks: 1,
                })
                .await
            {
                Ok(report) => {
                    apply_report_to_fanout(
                        &mut fanout,
                        std::slice::from_ref(&endpoint),
                        &report,
                        self.wall_clock.now(),
                    );
                    if !report.met_required_acks() {
                        output.failures.push(PublishFailure {
                            message_id: report.message_id.clone(),
                            reason: "fanout endpoint did not acknowledge".into(),
                        });
                    }
                    output.reports.push(report);
                }
                Err(_) => {
                    fanout.possible_exposure = true;
                    if let Some(target) = fanout
                        .targets
                        .iter_mut()
                        .find(|target| target.endpoint == endpoint)
                    {
                        target.attempt_count = target.attempt_count.saturating_add(1);
                        target.last_attempt_at = Some(self.wall_clock.now());
                        target.state = TransportFanoutAttemptState::AttemptedFailed;
                        target.failure_code = Some("adapter_error".into());
                    }
                    output.failures.push(PublishFailure {
                        message_id: message_id.clone(),
                        reason: "fanout adapter error".into(),
                    });
                }
            }
            self.session.put_transport_fanout(&fanout)?;
        }
        Ok(())
    }

    /// Re-publish a stored welcome whose original delivery failed after its
    /// commit was already confirmed (mdk#352).
    ///
    /// The wrapped welcome is loaded from the engine's sent-message store, so
    /// no re-commit happens and no pending confirm/rollback lifecycle is
    /// involved — the group evolution this welcome belongs to was confirmed
    /// when the failure was recorded. A re-delivery that again misses the ack
    /// threshold records a fresh [`WelcomeDeliveryFailure`] on the returned
    /// effects, so the caller can keep retrying from the same handle.
    pub async fn redeliver_welcome(
        &mut self,
        message_id: &cgka_traits::MessageId,
    ) -> AccountResult<AccountDeviceEffects> {
        let (group_id, message) = self.session.stored_sent_welcome(message_id)?;
        // `stored_sent_welcome` only returns welcome envelopes.
        let recipient = welcome_recipient(&message);
        let mut output = AccountDeviceEffects::default();
        let failures_before = output.failures.len();
        // This is an explicit operator/user retry, so do not make the caller
        // wait for the automatic fanout backoff window. The original exact
        // Welcome and target snapshot are still reused.
        let status = self
            .publish_one_with_retry_policy(message, &mut output, None, true)
            .await?;
        if status.met_required_acks {
            self.mark_welcome_delivered_best_effort(message_id);
        } else if let Some(recipient) = recipient {
            let failure = self.welcome_delivery_failure(
                message_id.clone(),
                recipient,
                Some(group_id),
                &output,
                failures_before,
            );
            output.welcome_failures.push(failure);
        }
        Ok(output)
    }

    /// Retained outbound Welcome obligations that have not met their
    /// acknowledgement policy. Unlike app projections, this list is rooted in
    /// the engine transaction that made the corresponding group state
    /// canonical, so non-app callers and cold restarts can recover it.
    pub fn outstanding_welcome_deliveries(
        &self,
    ) -> AccountResult<Vec<(GroupId, TransportMessage)>> {
        Ok(self.session.outstanding_sent_welcomes()?)
    }

    /// IDs of delivery-aware outbound Welcomes, including completed ones.
    ///
    /// This lets app projections clear a completed founding intent without
    /// disturbing older pending-delivery rows whose engine payloads predate
    /// delivery-aware tagging.
    pub fn tracked_outbound_welcome_ids(&self) -> AccountResult<Vec<cgka_traits::MessageId>> {
        Ok(self.session.tracked_outbound_welcome_ids()?)
    }

    /// Delivery is already externally visible when this runs. A local state
    /// write failure must therefore leave the Welcome conservatively retryable
    /// rather than turn canonical creation/evolution into a false hard error.
    fn mark_welcome_delivered_best_effort(&self, message_id: &cgka_traits::MessageId) {
        if let Err(error) = self.session.mark_sent_welcome_delivered(message_id) {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "mark_welcome_delivered_best_effort",
                transient = error.is_transient(),
                "acknowledged Welcome remains conservatively retryable"
            );
        }
    }

    /// Build the structured re-delivery record for a welcome that just failed
    /// to publish, pairing the recipient with the reason `publish_one` pushed.
    fn welcome_delivery_failure(
        &self,
        message_id: cgka_traits::MessageId,
        recipient: MemberId,
        group_id: Option<GroupId>,
        output: &AccountDeviceEffects,
        failures_before: usize,
    ) -> WelcomeDeliveryFailure {
        // `publish_one` pushes exactly one `PublishFailure` on each failing
        // path (routing, adapter, required_acks); the defensive fallback only
        // guards against that contract changing.
        let reason = output
            .failures
            .get(failures_before..)
            .and_then(<[PublishFailure]>::last)
            .map(|failure| failure.reason.clone())
            .unwrap_or_else(|| "welcome publish failed".into());
        WelcomeDeliveryFailure {
            message_id,
            recipient,
            group_id,
            reason,
        }
    }

    async fn publish_one(
        &mut self,
        message: TransportMessage,
        pending: Option<PendingStateRef>,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<PublishStatus> {
        if matches!(message.envelope, TransportEnvelope::GroupMessage { .. }) {
            let target = match self.routing.publish_target(&message) {
                Ok(target) => target,
                Err(error) => {
                    output.failures.push(PublishFailure {
                        message_id: message.id,
                        reason: error.to_string(),
                    });
                    self.rollback_unstaged_pending(pending, output, queue)
                        .await?;
                    return Ok(PublishStatus::default());
                }
            };
            let required_acks = self.routing.required_acks(&target);
            let pending_group_id = match pending
                .map(|pending| self.session.pending_group_id(pending))
                .transpose()
            {
                Ok(group_id) => group_id,
                Err(error) => {
                    self.rollback_unstaged_pending(pending, output, queue)
                        .await?;
                    return Err(error.into());
                }
            };
            let fanout = match OutboundFanout::stage(
                TransportPublishRequest {
                    account_id: self.session.self_id(),
                    message,
                    target,
                    required_acks,
                },
                pending,
                pending_group_id,
                0,
            ) {
                Ok(fanout) => fanout,
                Err(error) => {
                    self.rollback_unstaged_pending(pending, output, queue)
                        .await?;
                    return Err(error.into());
                }
            };
            if let Err(error) = self.session.put_outbound_fanout(&fanout) {
                self.rollback_unstaged_pending(pending, output, queue)
                    .await?;
                return Err(error.into());
            }
            Box::pin(self.drive_outbound_fanout(fanout, output, queue, context)).await
        } else {
            self.publish_legacy_one(message, output, context).await
        }
    }

    async fn rollback_unstaged_pending(
        &mut self,
        pending: Option<PendingStateRef>,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
    ) -> AccountResult<()> {
        if let Some(pending) = pending {
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
        }
        Ok(())
    }

    async fn drive_outbound_fanout(
        &mut self,
        mut fanout: OutboundFanout,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<PublishStatus> {
        self.resolve_outbound_fanout_mls(&mut fanout, output, queue)
            .await?;
        let endpoints = fanout.request().target.endpoints().to_vec();
        for index in fanout.outstanding_target_indexes() {
            let endpoint = endpoints[index].clone();
            fanout.mark_attempt_started(index)?;
            self.session.put_outbound_fanout(&fanout)?;

            let attempt = TransportPublishRequest {
                account_id: fanout.request().account_id.clone(),
                message: fanout.request().message.clone(),
                target: single_endpoint_target(&fanout.request().target, endpoint.clone()),
                required_acks: 1,
            };
            let accepted = match self.adapter.publish(attempt).await {
                Ok(report) => {
                    fanout.record_published_message_id(report.message_id)?;
                    report
                        .accepted
                        .iter()
                        .any(|receipt| receipt.endpoint == endpoint)
                }
                Err(_) => false,
            };
            if accepted {
                fanout.mark_target_accepted(index)?;
            } else {
                fanout.mark_target_failed(index)?;
            }
            self.session.put_outbound_fanout(&fanout)?;
            self.resolve_outbound_fanout_mls(&mut fanout, output, queue)
                .await?;
        }

        let report = frozen_fanout_report(&fanout);
        let status = PublishStatus {
            met_required_acks: report.met_required_acks(),
            accepted_by_any_endpoint: report.accepted_count() > 0,
            possible_ambiguous_exposure: false,
            retry_deferred: false,
        };
        if !status.met_required_acks {
            output.failures.push(PublishFailure {
                message_id: report.message_id.clone(),
                reason: "insufficient publish acknowledgements".into(),
            });
        }
        // `EpochConfirmed` / `EpochRolledBack` records the MLS edge. This
        // endpoint-free publish row records the separate terminal fanout edge;
        // relay URLs stay solely in the encrypted fanout record and never enter
        // this privacy-safe audit summary.
        self.session.record_audit_event(
            fanout.group_id(),
            context,
            AuditEventKind::PublishOutcome {
                msg_id: hex::encode(report.message_id.as_slice()),
                artifact_kind: None,
                target_kind: "frozen_group_fanout".into(),
                relay_url: None,
                accepted_relay_urls: Vec::new(),
                failed_relays: Vec::new(),
                required_acks: report.required_acks as u64,
                met_required_acks: status.met_required_acks,
                transport: Some(publish_wire_metadata(&fanout.request().message)),
            },
        );
        output.reports.push(report);
        output.fanout.push(fanout.outcome());
        if fanout.outcome().fanout_complete
            && !matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
        {
            self.session.delete_outbound_fanout(fanout.message_id())?;
        }
        Ok(status)
    }

    async fn resolve_outbound_fanout_mls(
        &mut self,
        fanout: &mut OutboundFanout,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
    ) -> AccountResult<()> {
        let outcome = fanout.outcome();
        if outcome.mls_confirmation_required {
            let pending = fanout
                .pending_ref()
                .expect("confirmation-required fanout retains pending ref");
            let effects = self
                .confirm_published_fanout_retrying(pending, fanout)
                .await?;
            output
                .pending
                .push(PendingResolution::Confirmed { pending });
            output.absorb_session_effects(effects, queue);
        } else if outcome.fanout_complete
            && outcome.accepted_targets == 0
            && let Some(pending) = fanout.pending_ref()
        {
            let effects = self.session.publish_failed_fanout(pending, fanout).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
        }
        Ok(())
    }

    async fn publish_legacy_one(
        &self,
        message: TransportMessage,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
    ) -> AccountResult<PublishStatus> {
        self.publish_one_with_retry_policy(message, output, context, false)
            .await
    }

    async fn publish_one_with_retry_policy(
        &self,
        message: TransportMessage,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
        retry_immediately: bool,
    ) -> AccountResult<PublishStatus> {
        let message_id = message.id.clone();
        let msg_id_hex = hex::encode(message_id.as_slice());
        // Capture the outbound wire envelope before `message` is moved into the
        // publish request. The post-wrap relay event id / ephemeral pubkey are
        // produced inside the transport adapter and are not available here, so
        // only the transport source and transport group id are recorded.
        let wire = publish_wire_metadata(&message);
        // A welcome is unambiguously a welcome; a group message could be a
        // commit/proposal/app message, which is not distinguishable from the
        // transport envelope alone, so it is left unattributed here.
        let artifact_kind = match &message.envelope {
            TransportEnvelope::Welcome { .. } => Some(MessageArtifactKind::Welcome),
            TransportEnvelope::GroupMessage { .. } => None,
        };
        let mut publish_context = context.unwrap_or_default();
        publish_context.operation_id = Some(format!("publish-{msg_id_hex}"));
        let existing_fanout = self.session.transport_fanout(&message_id)?;
        if existing_fanout
            .as_ref()
            .is_some_and(|fanout| fanout.exact_message != message)
        {
            return Err(AccountError::Transport(TransportAdapterError::Publish(
                "persisted exact transport event does not match retry input".into(),
            )));
        }
        let target = if let Some(fanout) = existing_fanout.as_ref() {
            fanout.target.clone()
        } else {
            match self.routing.publish_target(&message) {
                Ok(target) => target,
                Err(e) => {
                    self.session.record_audit_event(
                        None,
                        Some(publish_context),
                        AuditEventKind::PublishFailure {
                            msg_id: msg_id_hex,
                            artifact_kind,
                            stage: "routing".into(),
                            target_kind: "unknown".into(),
                            relay_url: None,
                            relay_urls: Vec::new(),
                            required_acks: None,
                            reason: e.to_string(),
                            detail: None,
                            transport: Some(wire),
                        },
                    );
                    output.failures.push(PublishFailure {
                        message_id,
                        reason: e.to_string(),
                    });
                    return Ok(PublishStatus::default());
                }
            }
        };
        let required_acks = existing_fanout
            .as_ref()
            .map(|fanout| fanout.required_acks)
            .unwrap_or_else(|| self.routing.required_acks(&target));
        let target_kind = publish_target_kind(&target).to_string();
        let relay_urls = publish_target_relay_urls(&target);
        let target_group_id = publish_target_group_id(&target);
        self.session.record_audit_event(
            target_group_id.as_ref(),
            Some(publish_context.clone()),
            AuditEventKind::PublishAttempt {
                msg_id: msg_id_hex.clone(),
                artifact_kind,
                target_kind: target_kind.clone(),
                relay_url: None,
                relay_urls: relay_urls.clone(),
                required_acks: required_acks as u64,
                transport: Some(wire.clone()),
            },
        );
        let mut fanout = if let Some(fanout) = existing_fanout {
            fanout
        } else {
            DurableTransportFanout {
                id: message_id.clone(),
                group_id: target_group_id.clone(),
                evolution_id: self
                    .session
                    .group_evolutions()?
                    .into_iter()
                    .find(|evolution| evolution.signed_message_id.as_ref() == Some(&message_id))
                    .map(|evolution| evolution.id),
                exact_message: message.clone(),
                target: target.clone(),
                targets: target
                    .endpoints()
                    .iter()
                    .cloned()
                    .map(|endpoint| TransportFanoutTarget {
                        endpoint,
                        state: TransportFanoutAttemptState::Unattempted,
                        attempt_count: 0,
                        last_attempt_at: None,
                        failure_code: None,
                    })
                    .collect(),
                required_acks,
                evolution_confirmed: false,
                possible_exposure: false,
                created_at: self.wall_clock.now(),
                bounded_until: Some(Timestamp(
                    self.wall_clock
                        .now()
                        .0
                        .saturating_add(TRANSPORT_FANOUT_RETENTION_SECS),
                )),
            }
        };
        // Exact signed bytes and the endpoint snapshot are durable before the
        // first network call.
        self.session.put_transport_fanout(&fanout)?;
        let defers_remaining_fanout_until_confirmation = fanout.evolution_id.is_some();
        if let Some(evolution_id) = fanout.evolution_id.as_ref()
            && let Some(mut evolution) = self
                .session
                .group_evolutions()?
                .into_iter()
                .find(|evolution| &evolution.id == evolution_id)
            && evolution.phase == GroupEvolutionPhase::Prepared
        {
            evolution.phase = GroupEvolutionPhase::Attempting;
            self.session.put_group_evolution(&evolution)?;
        }

        let retry_endpoints = fanout
            .targets
            .iter()
            .filter(|target| {
                retry_immediately && target.state == TransportFanoutAttemptState::AttemptedFailed
                    || transport_fanout_target_retry_due(target, self.wall_clock.now())
            })
            .map(|target| target.endpoint.clone())
            .collect::<Vec<_>>();
        let accepted_before = fanout
            .targets
            .iter()
            .filter(|target| target.state == TransportFanoutAttemptState::Accepted)
            .count();
        if retry_endpoints.is_empty() {
            let retry_deferred = accepted_before < required_acks.max(1)
                && fanout.targets.iter().any(|target| {
                    matches!(
                        target.state,
                        TransportFanoutAttemptState::Unattempted
                            | TransportFanoutAttemptState::AttemptedFailed
                    )
                });
            return Ok(PublishStatus {
                met_required_acks: accepted_before >= required_acks.max(1),
                accepted_by_any_endpoint: accepted_before > 0,
                possible_ambiguous_exposure: fanout.possible_exposure,
                retry_deferred,
            });
        }
        let attempt_target = publish_target_with_endpoints(&target, retry_endpoints.clone());
        let attempt_required_acks = required_acks
            .max(1)
            .saturating_sub(accepted_before)
            .max(1)
            .min(retry_endpoints.len());

        let report = match self
            .adapter
            .publish(TransportPublishRequest {
                account_id: self.session.self_id(),
                message: message.clone(),
                target: attempt_target,
                required_acks: attempt_required_acks,
            })
            .await
        {
            Ok(report) => report,
            Err(e) => {
                fanout.possible_exposure = true;
                for target in &mut fanout.targets {
                    if retry_endpoints.contains(&target.endpoint)
                        && target.state != TransportFanoutAttemptState::Accepted
                    {
                        target.attempt_count = target.attempt_count.saturating_add(1);
                        target.last_attempt_at = Some(self.wall_clock.now());
                        target.state = TransportFanoutAttemptState::AttemptedFailed;
                        target.failure_code = Some("adapter_error".into());
                    }
                }
                self.session.put_transport_fanout(&fanout)?;
                self.session.record_audit_event(
                    target_group_id.as_ref(),
                    Some(publish_context),
                    AuditEventKind::PublishFailure {
                        msg_id: msg_id_hex,
                        artifact_kind,
                        stage: "adapter".into(),
                        target_kind,
                        relay_url: None,
                        relay_urls,
                        required_acks: Some(required_acks as u64),
                        reason: e.to_string(),
                        detail: None,
                        transport: Some(wire),
                    },
                );
                output.failures.push(PublishFailure {
                    message_id,
                    reason: e.to_string(),
                });
                return Ok(PublishStatus {
                    possible_ambiguous_exposure: true,
                    ..PublishStatus::default()
                });
            }
        };
        apply_report_to_fanout(
            &mut fanout,
            &retry_endpoints,
            &report,
            self.wall_clock.now(),
        );
        self.session.put_transport_fanout(&fanout)?;
        let accepted_total = fanout
            .targets
            .iter()
            .filter(|target| target.state == TransportFanoutAttemptState::Accepted)
            .count();
        let published = accepted_total >= required_acks.max(1);
        let accepted_by_any_endpoint = accepted_total > 0;
        self.session.record_audit_event(
            target_group_id.as_ref(),
            Some(publish_context.clone()),
            AuditEventKind::PublishOutcome {
                msg_id: hex::encode(report.message_id.as_slice()),
                artifact_kind,
                target_kind: target_kind.clone(),
                relay_url: None,
                accepted_relay_urls: report
                    .accepted
                    .iter()
                    .map(|receipt| receipt.endpoint.0.clone())
                    .collect(),
                failed_relays: report
                    .failed
                    .iter()
                    .map(|failure| PublishRelayFailure {
                        relay_url: failure.endpoint.0.clone(),
                        reason: failure.reason.clone(),
                    })
                    .collect(),
                required_acks: report.required_acks as u64,
                met_required_acks: published,
                transport: Some(wire.clone()),
            },
        );
        if !published {
            self.session.record_audit_event(
                target_group_id.as_ref(),
                Some(publish_context),
                AuditEventKind::PublishFailure {
                    msg_id: hex::encode(report.message_id.as_slice()),
                    artifact_kind,
                    stage: "required_acks".into(),
                    target_kind,
                    relay_url: None,
                    relay_urls,
                    required_acks: Some(report.required_acks as u64),
                    reason: "insufficient publish acknowledgements".into(),
                    detail: None,
                    transport: Some(wire),
                },
            );
            output.failures.push(PublishFailure {
                message_id: report.message_id.clone(),
                reason: "insufficient publish acknowledgements".into(),
            });
        }
        output.reports.push(report);
        if !defers_remaining_fanout_until_confirmation {
            self.finish_transport_fanout(&message_id, output).await?;
        }
        Ok(PublishStatus {
            met_required_acks: published,
            accepted_by_any_endpoint,
            possible_ambiguous_exposure: fanout.possible_exposure,
            retry_deferred: false,
        })
    }
}

fn single_endpoint_target(
    target: &TransportPublishTarget,
    endpoint: TransportEndpoint,
) -> TransportPublishTarget {
    publish_target_with_endpoints(target, vec![endpoint])
}

fn publish_target_for_endpoint(
    target: &TransportPublishTarget,
    endpoint: TransportEndpoint,
) -> TransportPublishTarget {
    publish_target_with_endpoints(target, vec![endpoint])
}

fn publish_target_with_endpoints(
    target: &TransportPublishTarget,
    endpoints: Vec<TransportEndpoint>,
) -> TransportPublishTarget {
    match target {
        TransportPublishTarget::Group {
            group_id,
            transport_group_id,
            ..
        } => TransportPublishTarget::Group {
            group_id: group_id.clone(),
            transport_group_id: transport_group_id.clone(),
            endpoints,
        },
        TransportPublishTarget::Inbox { recipient, .. } => TransportPublishTarget::Inbox {
            recipient: recipient.clone(),
            endpoints,
        },
    }
}

fn frozen_fanout_report(fanout: &OutboundFanout) -> TransportPublishReport {
    let endpoints = fanout.request().target.endpoints();
    let mut accepted = Vec::new();
    let mut failed = Vec::new();
    for (endpoint, status) in endpoints.iter().zip(fanout.target_statuses()) {
        match status {
            cgka_traits::FanoutTargetStatus::Accepted => {
                accepted.push(TransportEndpointReceipt {
                    endpoint: endpoint.clone(),
                    accepted_at: None,
                });
            }
            cgka_traits::FanoutTargetStatus::Failed => {
                failed.push(TransportEndpointFailure {
                    endpoint: endpoint.clone(),
                    reason: "publish attempt failed".into(),
                });
            }
            cgka_traits::FanoutTargetStatus::NotAttempted
            | cgka_traits::FanoutTargetStatus::Attempting => {}
        }
    }
    TransportPublishReport {
        message_id: fanout
            .published_message_id()
            .unwrap_or_else(|| fanout.message_id())
            .clone(),
        accepted,
        failed,
        required_acks: fanout.request().required_acks,
    }
}

fn apply_report_to_fanout(
    fanout: &mut DurableTransportFanout,
    attempted: &[TransportEndpoint],
    report: &TransportPublishReport,
    attempted_at: Timestamp,
) {
    for target in &mut fanout.targets {
        if target.state == TransportFanoutAttemptState::Accepted
            || !attempted.contains(&target.endpoint)
        {
            continue;
        }
        let accepted = report
            .accepted
            .iter()
            .any(|receipt| receipt.endpoint == target.endpoint);
        let failed = report
            .failed
            .iter()
            .find(|failure| failure.endpoint == target.endpoint);
        target.attempt_count = target.attempt_count.saturating_add(1);
        target.last_attempt_at = Some(attempted_at);
        if accepted {
            target.state = TransportFanoutAttemptState::Accepted;
            target.failure_code = None;
        } else {
            target.state = TransportFanoutAttemptState::AttemptedFailed;
            // Persist a coarse category only. Detailed transport errors may
            // contain endpoint-specific or otherwise identifying data.
            target.failure_code = Some(
                if failed.is_none_or(|failure| failure.reason.is_empty()) {
                    "publish_failed"
                } else {
                    "transport_rejected"
                }
                .into(),
            );
        }
    }
}

fn note_key_package_attempt(
    targets: &mut [TransportFanoutTarget],
    attempted: &[TransportEndpoint],
    accepted: &[TransportEndpoint],
    failed: &[TransportEndpoint],
    attempted_at: Timestamp,
) {
    for target in targets {
        if target.state == TransportFanoutAttemptState::Accepted
            || !attempted.contains(&target.endpoint)
        {
            continue;
        }
        target.attempt_count = target.attempt_count.saturating_add(1);
        target.last_attempt_at = Some(attempted_at);
        if accepted.contains(&target.endpoint) {
            target.state = TransportFanoutAttemptState::Accepted;
            target.failure_code = None;
        } else {
            target.state = TransportFanoutAttemptState::AttemptedFailed;
            target.failure_code = Some(
                if failed.contains(&target.endpoint) {
                    "transport_rejected"
                } else {
                    "publish_failed"
                }
                .into(),
            );
        }
    }
}

fn key_package_target_retry_due(target: &TransportFanoutTarget, now: Timestamp) -> bool {
    transport_fanout_target_retry_due(target, now)
}

fn transport_fanout_target_retry_due(target: &TransportFanoutTarget, now: Timestamp) -> bool {
    if matches!(
        target.state,
        TransportFanoutAttemptState::Accepted | TransportFanoutAttemptState::PolicyProhibited
    ) {
        return false;
    }
    let shift = target.attempt_count.saturating_sub(1).min(7);
    let backoff = 30_u64.saturating_mul(1_u64 << shift).min(60 * 60);
    target
        .last_attempt_at
        .is_none_or(|last| now.0 >= last.0.saturating_add(backoff))
}

/// The welcome recipient carried in the message's transport envelope, if the
/// message is a welcome.
fn welcome_recipient(message: &TransportMessage) -> Option<MemberId> {
    match &message.envelope {
        TransportEnvelope::Welcome { recipient } => Some(recipient.clone()),
        TransportEnvelope::GroupMessage { .. } => None,
    }
}

/// Extract the group id from the event that confirms a create/evolution.
///
/// Session effects are drained after every session call, so the confirmation
/// effects contain exactly one `GroupCreated` or `EpochChanged` for this
/// pending operation rather than events left by earlier work. This per-call
/// drain is load-bearing: batching effects across calls would require matching
/// the event to the pending operation explicitly. Keeping extraction
/// best-effort preserves the existing `WelcomeDeliveryFailure::group_id`
/// contract without re-reading the durable sent-welcome record.
fn confirmed_group_id(effects: &SessionEffects) -> Option<GroupId> {
    confirmed_group_id_from_events(&effects.events)
}

fn confirmed_group_id_from_events(events: &[GroupEvent]) -> Option<GroupId> {
    events.iter().rev().find_map(|event| match event {
        GroupEvent::GroupCreated { group_id } | GroupEvent::EpochChanged { group_id, .. } => {
            Some(group_id.clone())
        }
        _ => None,
    })
}

/// Build the outbound transport wire envelope for a publish, from the message's
/// transport source and (for group messages) the transport-visible group id.
/// Transport-generic: the post-wrap relay event id and ephemeral pubkey are
/// produced inside the transport adapter and are intentionally not recorded
/// here.
fn publish_wire_metadata(message: &TransportMessage) -> AuditTransportWire {
    let transport_group_id = match &message.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => {
            Some(hex::encode(transport_group_id))
        }
        TransportEnvelope::Welcome { .. } => None,
    };
    AuditTransportWire {
        transport: Some(message.source.0.clone()),
        transport_group_id,
        ..Default::default()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountDeviceEffects {
    pub events: Vec<GroupEvent>,
    pub queued: Vec<QueuedIntentRef>,
    pub pending_convergence: Vec<GroupId>,
    pub reports: Vec<TransportPublishReport>,
    /// Privacy-safe summaries separate MLS release from target fanout completion.
    pub fanout: Vec<OutboundFanoutOutcome>,
    pub failures: Vec<PublishFailure>,
    /// Application messages accepted by at least one transport endpoint,
    /// carrying source-state metadata captured by the exact MLS encryption
    /// operation and the adapter-visible transport id.
    pub published_app_messages: Vec<PublishedApplicationMessage>,
    /// Welcomes whose publish failed after their commit/create was already
    /// confirmed. Unlike `failures`, each entry carries the recipient and
    /// group so the caller can re-deliver the stored welcome via
    /// [`AccountDeviceRuntime::redeliver_welcome`] without re-committing.
    pub welcome_failures: Vec<WelcomeDeliveryFailure>,
    pub pending: Vec<PendingResolution>,
    pub maintenance_disposition: SendMaintenanceDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedApplicationMessage {
    pub group_id: GroupId,
    pub app_event_id: String,
    pub message_id: cgka_traits::MessageId,
    pub source_epoch: EpochId,
    pub retention: cgka_traits::app_event::AppMessageRetentionDecision,
}

impl AccountDeviceEffects {
    fn extend(&mut self, other: Self) {
        self.events.extend(other.events);
        self.queued.extend(other.queued);
        self.pending_convergence.extend(other.pending_convergence);
        self.reports.extend(other.reports);
        self.fanout.extend(other.fanout);
        self.failures.extend(other.failures);
        self.published_app_messages
            .extend(other.published_app_messages);
        self.welcome_failures.extend(other.welcome_failures);
        self.pending.extend(other.pending);
    }

    fn absorb_session_effects(
        &mut self,
        effects: SessionEffects,
        queue: &mut VecDeque<PublishWork>,
    ) {
        self.events.extend(effects.events);
        self.queued.extend(effects.queued);
        self.pending_convergence.extend(effects.pending_convergence);
        queue.extend(effects.publish);
    }

    fn absorb_account_effects(&mut self, mut other: AccountDeviceEffects) {
        self.events.append(&mut other.events);
        self.queued.append(&mut other.queued);
        self.pending_convergence
            .append(&mut other.pending_convergence);
        self.reports.append(&mut other.reports);
        self.failures.append(&mut other.failures);
        self.published_app_messages
            .append(&mut other.published_app_messages);
        self.welcome_failures.append(&mut other.welcome_failures);
        self.pending.append(&mut other.pending);
        if other.maintenance_disposition
            == SendMaintenanceDisposition::PostJoinRotationPendingRetryable
        {
            self.maintenance_disposition = other.maintenance_disposition;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountIngestEffects {
    pub outcome: IngestOutcome,
    pub effects: AccountDeviceEffects,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishFailure {
    pub message_id: cgka_traits::MessageId,
    pub reason: String,
}

/// A welcome left undelivered by a confirmed group create/evolution (mdk#352).
///
/// The added member cannot join until the welcome reaches them, and the commit
/// cannot be rolled back (it is already confirmed and externally visible), so
/// re-delivery is the only repair. The wrapped welcome stays available in the
/// engine's sent-message store under `message_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WelcomeDeliveryFailure {
    pub message_id: cgka_traits::MessageId,
    pub recipient: MemberId,
    /// From the already-known confirmation or stored sent-welcome record;
    /// best-effort.
    pub group_id: Option<GroupId>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingResolution {
    Confirmed { pending: PendingStateRef },
    RolledBack { pending: PendingStateRef },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published_message(id: u8) -> PublishedApplicationMessage {
        PublishedApplicationMessage {
            group_id: GroupId::new(vec![id]),
            app_event_id: format!("event-{id}"),
            message_id: cgka_traits::MessageId::new(vec![id]),
            source_epoch: EpochId(u64::from(id)),
            retention: cgka_traits::app_event::AppMessageRetentionDecision::new(10, 0),
        }
    }

    #[test]
    fn extending_effects_preserves_published_application_messages() {
        let first = published_message(1);
        let second = published_message(2);
        let mut combined = AccountDeviceEffects {
            published_app_messages: vec![first.clone()],
            ..AccountDeviceEffects::default()
        };
        combined.extend(AccountDeviceEffects {
            published_app_messages: vec![second.clone()],
            ..AccountDeviceEffects::default()
        });

        assert_eq!(combined.published_app_messages, vec![first, second]);
    }
}
