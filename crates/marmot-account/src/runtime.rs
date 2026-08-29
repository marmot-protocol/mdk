//! Account-device runtime: drives session effects through transport publish,
//! confirmation, and rollback, and the effect aggregates it produces.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use cgka_session::{
    AccountDeviceSession, CreateGroupEffects, IngestEffects, PublishWork, QueuedIntentRef,
    SessionEffects, SessionError,
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
    KeyPackageLifecycleState, MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES,
    MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES_WITH_LIVE_DELETION_OVERFLOW,
    MaintenanceObligation, MaintenancePhase, MaintenanceTrigger, PeriodicMaintenancePolicy,
    RetainedKeyPackagePrivateMaterial, RetiredKeyPackagePublication, SendMaintenanceDisposition,
    SignedPublicationArtifact, TransportFanoutAttemptState, TransportFanoutTarget,
};
use cgka_traits::storage::{LeaveRequestStorage, MessageStorage, StorageProvider};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::{
    EpochId, FanoutMlsState, FanoutPendingKind, GroupId, MemberId, MessageId, OutboundFanout,
    OutboundFanoutOutcome, StorageError, Timestamp, TransportAccountActivation, TransportAdapter,
    TransportAdapterError, TransportDelivery, TransportEndpoint, TransportEndpointFailure,
    TransportEndpointFailureKind, TransportEndpointReceipt, TransportGroupSync,
    TransportPublishReport, TransportPublishRequest, TransportPublishTarget,
};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use marmot_forensics::{
    AuditEventContext, AuditEventKind, AuditTransportWire, MessageArtifactKind, PublishRelayFailure,
};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use storage_sqlite::{
    AccountVisibilityJournalRow, AccountVisibilityJournalUpsert, SqliteAccountStorage,
};

use crate::error::{AccountError, AccountResult};
use crate::key_package::{
    DetailedKeyPackagePublishReceipt, KeyPackagePublication, KeyPackagePublisher,
    NoopKeyPackagePublisher,
};
use crate::routing::{
    StaticTransportRouting, TransportRoutingPolicy, publish_target_group_id, publish_target_kind,
    publish_target_relay_urls,
};
use crate::time::{
    MaintenanceRandom, MonotonicClock, OsMaintenanceRandom, SystemMonotonicClock, SystemWallClock,
    WallClock,
};

const TRACE_TARGET: &str = "marmot_account::runtime";
const WELCOME_PUBLISH_CONCURRENCY: usize = 8;
const KEY_PACKAGE_MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;
// One relay attempt bounds a maintenance call by one transport publish
// deadline even when the durable privacy journal is full. Later ticks drain
// additional endpoints without monopolizing the serialized account worker.
const KEY_PACKAGE_RETIRED_DELETION_ATTEMPTS_PER_CALL: usize = 1;
const KEY_PACKAGE_REFRESH_MIN_LEAD_SECS: u64 = 14 * 24 * 60 * 60;
const KEY_PACKAGE_REFRESH_MAX_LEAD_SECS: u64 = 21 * 24 * 60 * 60;
const MAINTENANCE_EOSE_TIMEOUT_SECS: u64 = 5 * 60;
const MAINTENANCE_POST_EOSE_GRACE_SECS: u64 = 15;
const MAINTENANCE_QUIET_SECS: u64 = 60;
const PERIODIC_MIN_SECS: u64 = 24 * 24 * 60 * 60;
const PERIODIC_MAX_SECS: u64 = 36 * 24 * 60 * 60;
const TRANSPORT_FANOUT_RETENTION_SECS: u64 = 24 * 60 * 60;
const FROZEN_FANOUT_RETRY_BASE_MS: u64 = 30 * 1_000;
const FROZEN_FANOUT_RETRY_MAX_MS: u64 = 60 * 60 * 1_000;
const ACCOUNT_VISIBILITY_RECORD_VERSION: u8 = 1;
const ACCOUNT_VISIBILITY_CONTROL_ORDINAL: u64 = i64::MAX as u64 - 1;
const ACCOUNT_VISIBILITY_NON_SESSION_ORDINAL: u64 = i64::MAX as u64;

/// Run independent async work with fixed fan-out while returning results in
/// input order. Completion order therefore cannot reorder reports or select a
/// different caller-visible error.
#[cfg(test)]
async fn collect_bounded_ordered<I, F, T, E>(work: I, limit: usize) -> Result<Vec<T>, E>
where
    I: IntoIterator<Item = F>,
    I::IntoIter: Send,
    F: std::future::Future<Output = Result<T, E>> + Send,
    T: Send,
    E: Send,
{
    let mut results = futures::stream::iter(work.into_iter().enumerate())
        .map(|(index, future)| async move { (index, future.await) })
        .buffer_unordered(limit.max(1))
        .collect::<Vec<_>>()
        .await;
    results.sort_unstable_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PublishStatus {
    met_required_acks: bool,
    accepted_by_any_endpoint: bool,
    possible_ambiguous_exposure: bool,
    retry_deferred: bool,
}

struct PendingFanoutContinuation {
    pending: PendingStateRef,
    kind: FanoutPendingKind,
    post_confirmation_welcomes: Vec<TransportMessage>,
}

/// Cutover-facing outcome from one bounded retired-KeyPackage deletion pass.
///
/// `terminal_endpoints` contains only endpoints whose accepted deletion or
/// confirmed-absence receipt has already been committed durably. A remaining
/// uncovered deletion is currently eligible even though no strictly newer
/// live revision has an accepted receipt at that endpoint; cutover discovery
/// must therefore stay armed because a later retry may reveal older relay
/// history.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[must_use]
pub struct RetiredKeyPackageDeletionPassReport {
    pub terminal_endpoints: Vec<TransportEndpoint>,
    pub has_uncovered_eligible_deletion: bool,
}

enum PreparedLegacyPublish {
    Complete(PublishStatus),
    Network(Box<PreparedLegacyPublishAttempt>),
}

enum LegacyPublishCompletion {
    Complete(PublishStatus),
    Network(
        Box<PreparedLegacyPublishAttempt>,
        Result<TransportPublishReport, TransportAdapterError>,
    ),
}

struct PreparedLegacyPublishAttempt {
    message_id: cgka_traits::MessageId,
    msg_id_hex: String,
    wire: AuditTransportWire,
    artifact_kind: Option<MessageArtifactKind>,
    publish_context: AuditEventContext,
    fanout: DurableTransportFanout,
    retry_endpoints: Vec<TransportEndpoint>,
    accepted_before: usize,
    required_acks: usize,
    target_kind: String,
    relay_urls: Vec<String>,
    target_group_id: Option<GroupId>,
    defers_remaining_fanout_until_confirmation: bool,
    request: TransportPublishRequest,
}

struct WelcomePublishMetadata {
    recipient: Option<MemberId>,
    welcome_id: cgka_traits::MessageId,
    effects: AccountDeviceEffects,
}

struct PreparedWelcomePublish {
    group_id: Option<GroupId>,
    metadata: Vec<WelcomePublishMetadata>,
    completions: Vec<Option<LegacyPublishCompletion>>,
    pending: VecDeque<(usize, Box<PreparedLegacyPublishAttempt>)>,
}

struct CompletedWelcomePublish {
    group_id: Option<GroupId>,
    metadata: Vec<WelcomePublishMetadata>,
    completions: Vec<Option<LegacyPublishCompletion>>,
}

/// One caller-visible account-effects batch that has not yet crossed the
/// account-runtime boundary.
///
/// The engine persists application deliveries for process-restart replay, but
/// its live `events_buf` and the account runtime's publication summaries are
/// one-shot. Keeping the complete account-shaped batch prevents a failed or
/// cancelled later publish from losing an earlier report, application-message
/// acceptance, pending resolution, or session event.
struct RetainedSessionVisibilityBatch {
    operation_id: Option<[u8; 16]>,
    effects: AccountDeviceEffects,
}

#[derive(Clone, Copy)]
struct SessionVisibilityHandoff {
    retained_batch_count: usize,
    operation_id: [u8; 16],
    fragment_id: u64,
}

struct DurableVisibilityOperation {
    source: AccountVisibilitySource,
    next_event_ordinal: u64,
    session_control: StoredSessionControlV1,
    non_session_fragments: BTreeMap<u64, AccountDeviceEffects>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredAccountVisibilityRecordV1 {
    version: u8,
    source: AccountVisibilitySource,
    payload: StoredAccountVisibilityPayloadV1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredAccountVisibilityPayloadV1 {
    Header {
        maintenance_disposition: SendMaintenanceDisposition,
    },
    Event {
        event: GroupEvent,
        engine_outbox_provenance: bool,
    },
    SessionControl(StoredSessionControlV1),
    NonSession(StoredNonSessionEffectsV1),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoredSessionControlV1 {
    queued: Vec<StoredQueuedIntentRefV1>,
    pending_convergence: Vec<GroupId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredQueuedIntentRefV1 {
    group_id: GroupId,
    intent_id: MessageId,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoredNonSessionEffectsV1 {
    reports: Vec<TransportPublishReport>,
    fanout: Vec<OutboundFanoutOutcome>,
    failures: Vec<PublishFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    action_outcomes: Vec<AccountVisibilityActionOutcome>,
    published_app_messages: Vec<PublishedApplicationMessage>,
    welcome_failures: Vec<WelcomeDeliveryFailure>,
    pending: Vec<PendingResolution>,
}

/// Opaque generation for one account-effects visibility handoff.
///
/// Acknowledging a stale generation is a no-op: every later leased return
/// supersedes the prior lease and contains its still-unacknowledged effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use = "the matching visibility lease must be acknowledged after projection staging"]
pub struct AccountVisibilityLease(u64);

struct RetainedReturnedVisibilityLease {
    lease: AccountVisibilityLease,
    batch_ids: Vec<Vec<u8>>,
}

/// Relay-only half of a prepared Welcome retry.
///
/// The account worker may run this task independently of its serialized
/// engine/SQLite owner. Preparation has already retained the exact event and
/// endpoint snapshot; [`AccountDeviceRuntime::finish_welcome_publish_task`]
/// must reconcile the returned completion before another retry is started.
#[doc(hidden)]
#[must_use = "a prepared Welcome publish task must be run and reconciled"]
pub struct PreparedWelcomePublishTask {
    adapter: Arc<dyn TransportAdapter>,
    prepared: PreparedWelcomePublish,
    message_ids: Vec<cgka_traits::MessageId>,
}

/// Opaque relay results from [`PreparedWelcomePublishTask::run`].
#[doc(hidden)]
pub struct CompletedWelcomePublishTask {
    completed: CompletedWelcomePublish,
    message_ids: Vec<cgka_traits::MessageId>,
}

impl PreparedWelcomePublishTask {
    /// Exact message ids reserved by this task while relay I/O is in flight.
    pub fn message_ids(&self) -> &[cgka_traits::MessageId] {
        &self.message_ids
    }

    /// Run only the bounded relay publication phase. This owns no engine or
    /// SQLite state and is therefore safe to poll beside the account worker.
    pub async fn run(self) -> CompletedWelcomePublishTask {
        CompletedWelcomePublishTask {
            completed: self.prepared.publish(self.adapter.as_ref()).await,
            message_ids: self.message_ids,
        }
    }
}

impl PreparedWelcomePublish {
    fn network_message_ids(&self) -> Vec<cgka_traits::MessageId> {
        self.pending
            .iter()
            .map(|(_, attempt)| attempt.message_id.clone())
            .collect()
    }

    async fn publish(mut self, adapter: &dyn TransportAdapter) -> CompletedWelcomePublish {
        let publish = |index, attempt: Box<PreparedLegacyPublishAttempt>| async move {
            let result = adapter.publish(attempt.request.clone()).await;
            (index, attempt, result)
        };
        let mut in_flight = FuturesUnordered::new();
        while in_flight.len() < WELCOME_PUBLISH_CONCURRENCY {
            let Some((index, attempt)) = self.pending.pop_front() else {
                break;
            };
            in_flight.push(publish(index, attempt));
        }
        while let Some((index, attempt, result)) = in_flight.next().await {
            self.completions[index] = Some(LegacyPublishCompletion::Network(attempt, result));
            if let Some((next_index, next_attempt)) = self.pending.pop_front() {
                in_flight.push(publish(next_index, next_attempt));
            }
        }

        CompletedWelcomePublish {
            group_id: self.group_id,
            metadata: self.metadata,
            completions: self.completions,
        }
    }
}

/// A locally staged commit whose transport publication has not started.
///
/// Keeping the pending handle beside the extracted Welcomes lets callers
/// either publish the commit after durable Welcome-intent persistence or roll
/// the staged MLS change back while external exposure is still impossible.
#[must_use = "a prepared commit must be published or rolled back; dropping it strands the staged MLS commit"]
pub struct PreparedSessionCommit {
    effects: SessionEffects,
    welcomes: Vec<TransportMessage>,
    pending: PendingStateRef,
}

/// Result of accepting an intent at the pre-publication boundary.
///
/// Convergence may durably queue an invite without staging an MLS commit. That
/// is successful `AcceptedPending` work, not a malformed prepared commit.
pub enum PreparedSessionSend {
    Commit(PreparedSessionCommit),
    Queued(SessionEffects),
}

impl PreparedSessionCommit {
    pub fn welcomes(&self) -> &[TransportMessage] {
        &self.welcomes
    }

    pub fn into_effects_and_welcomes(self) -> (SessionEffects, Vec<TransportMessage>) {
        (self.effects, self.welcomes)
    }

    fn into_parts(self) -> (SessionEffects, Vec<TransportMessage>, PendingStateRef) {
        (self.effects, self.welcomes, self.pending)
    }
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
    /// Exact Welcome events whose relay-only publish phase currently runs
    /// outside the serialized account owner. Other maintenance/manual retry
    /// paths skip these ids until their results are reconciled, preventing two
    /// concurrent publications of the same retained event.
    detached_welcome_publishes: HashSet<cgka_traits::MessageId>,
    /// Test-only fault injection: while armed, the finish stage of a prepared
    /// legacy publish for this message id fails with a transient storage
    /// error. Never set by production code.
    finish_stage_failure: Option<cgka_traits::MessageId>,
    /// Session visibility drained before an awaited publication completed.
    /// Batches stay here across `Err` and future cancellation. A later
    /// successful leased return hands them off in original order.
    retained_session_visibility: VecDeque<RetainedSessionVisibilityBatch>,
    visibility_storage: SqliteAccountStorage,
    durable_visibility_operations: HashMap<[u8; 16], DurableVisibilityOperation>,
    active_visibility_operation: Option<[u8; 16]>,
    next_visibility_fragment_id: u64,
    visibility_load_error: Option<String>,
    /// Engine application-outbox events are hydrated into the session's live
    /// buffer before this runtime opens. When the same exact event already has
    /// a durable visibility row, suppress that one live copy so replay + later
    /// drain cannot publish it twice.
    hydrated_visibility_suppressions: Vec<GroupEvent>,
    /// Exact effects already returned through a leased API but not yet
    /// acknowledged by the app projection/V1 boundary. A later leased return
    /// prepends this batch without re-running any publication work.
    returned_visibility_lease: Option<RetainedReturnedVisibilityLease>,
    next_visibility_lease_id: u64,
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    pub fn new(session: AccountDeviceSession, adapter: A, routing: R, key_packages: K) -> Self {
        let visibility_storage = session.storage_handle();
        let (visibility_load_error, hydrated_visibility_suppressions) =
            match visibility_storage.load_account_visibility_journal() {
                Ok(rows) => {
                    let mut suppressions = Vec::new();
                    let mut decode_error = None;
                    for row in rows {
                        match decode_account_visibility_row(row) {
                            Ok(batch) => {
                                if matches!(
                                    batch.kind,
                                    AccountVisibilityRecordKind::Event {
                                        engine_outbox_provenance: true
                                    }
                                ) {
                                    suppressions.extend(batch.effects.events);
                                }
                            }
                            Err(error) => {
                                decode_error = Some(error.to_string());
                                break;
                            }
                        }
                    }
                    (decode_error, suppressions)
                }
                Err(error) => (Some(error.to_string()), Vec::new()),
            };
        Self {
            session,
            adapter,
            routing,
            key_packages,
            wall_clock: Arc::new(SystemWallClock),
            monotonic_clock: Arc::new(SystemMonotonicClock::default()),
            maintenance_random: Arc::new(OsMaintenanceRandom),
            maintenance_paused: false,
            maintenance_quiet_monotonic: HashMap::new(),
            detached_welcome_publishes: HashSet::new(),
            finish_stage_failure: None,
            retained_session_visibility: VecDeque::new(),
            visibility_storage,
            durable_visibility_operations: HashMap::new(),
            active_visibility_operation: None,
            next_visibility_fragment_id: 1,
            visibility_load_error,
            hydrated_visibility_suppressions,
            returned_visibility_lease: None,
            next_visibility_lease_id: 1,
        }
    }

    /// Test-only hook: arm a one-message finish-stage failure so tests can
    /// exercise reconciliation of already-exposed publishes. Not a production
    /// entry point; hidden from the public API docs.
    #[doc(hidden)]
    pub fn arm_finish_stage_failure(&mut self, message_id: cgka_traits::MessageId) {
        self.finish_stage_failure = Some(message_id);
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

    pub fn epoch_state(&self, group_id: &GroupId) -> Option<cgka_traits::EpochState> {
        self.session.epoch_state(group_id)
    }

    pub fn disband_request(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<Option<cgka_traits::DisbandRequest>> {
        Ok(self.session.disband_request(group_id)?)
    }

    pub fn disbanding_in_progress(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.disbanding_in_progress(group_id)?)
    }

    pub fn disbanding_support_blockers(&self, group_id: &GroupId) -> AccountResult<Vec<MemberId>> {
        Ok(self.session.disbanding_support_blockers(group_id)?)
    }

    pub fn acknowledge_disband_failure(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.acknowledge_disband_failure(group_id)?)
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

    /// Re-send the current durable authored KeyPackage event to the current
    /// authoritative publication targets without staging a replacement MLS
    /// KeyPackage. A bounded-age transport may first author a newer signed
    /// revision at the same replaceable-event coordinate.
    ///
    /// When no usable current package or signed artifact exists, this falls back to
    /// [`Self::publish_fresh_key_package`].
    pub async fn republish_key_package(&mut self) -> AccountResult<KeyPackage> {
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "republish_key_package",
                fallback_reason = "no_lifecycle_state",
                "no republishable current key package artifact; falling back to fresh publication"
            );
            return self.publish_fresh_key_package().await;
        };
        ensure_key_package_cutover_publication_allowed(&lifecycle)?;
        if lifecycle.pending_replacement.is_some() {
            return Err(AccountError::KeyPackageRotationInProgress);
        }
        if lifecycle.stable_slot_id.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "key package lifecycle is migration-blocked because the stable replaceable-event slot is unavailable",
            )
            .into());
        }
        let now = self.wall_clock.now();
        if let Some(fallback_reason) = current_key_package_republish_blocker(&lifecycle, now) {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "republish_key_package",
                fallback_reason,
                "no republishable current key package artifact; falling back to fresh publication"
            );
            return self.publish_fresh_key_package().await;
        }

        tracing::debug!(
            target: TRACE_TARGET,
            method = "republish_key_package",
            endpoint_count = self.routing.key_package_endpoints().len(),
            "republishing current key package"
        );

        let current_endpoints = self.routing.key_package_endpoints();
        let additional_policy_targets = current_endpoints
            .iter()
            .filter(|endpoint| {
                !lifecycle
                    .publication_targets
                    .iter()
                    .any(|target| target.endpoint == **endpoint)
            })
            .count();
        self.ensure_key_package_publication_liability_capacity(
            &mut lifecycle,
            additional_policy_targets,
        )?;
        merge_republish_publication_targets(&mut lifecycle.publication_targets, &current_endpoints);
        let endpoints = current_endpoints.to_vec();
        if endpoints.is_empty() {
            self.session.put_key_package_lifecycle(&lifecycle)?;
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "no KeyPackage publication endpoints are configured",
            )
            .into());
        }

        let Some(key_package) = lifecycle.current_key_package.clone() else {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "republish_key_package",
                fallback_reason = "missing_current_key_package",
                "no republishable current key package artifact; falling back to fresh publication"
            );
            return self.publish_fresh_key_package().await;
        };
        self.reauthor_current_key_package_if_stale(&mut lifecycle, &key_package, &endpoints)
            .await?;
        let Some(artifact) = lifecycle.authored_signed_event.clone() else {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "republish_key_package",
                fallback_reason = "missing_authored_signed_event",
                "no republishable current key package artifact; falling back to fresh publication"
            );
            return self.publish_fresh_key_package().await;
        };

        let publication = KeyPackagePublication {
            account_id: self.session.self_id().clone(),
            key_package: key_package.clone(),
            slot_id: lifecycle.stable_slot_id.clone(),
            created_at: artifact.created_at,
            endpoints: endpoints.clone(),
        };
        lifecycle.phase = cgka_traits::MaintenancePhase::Fanout;
        begin_key_package_attempt(
            &mut lifecycle.publication_targets,
            &publication.endpoints,
            self.wall_clock.now(),
        );
        self.session.put_key_package_lifecycle(&lifecycle)?;
        match self
            .key_packages
            .publish_prepared_key_package_detailed(&publication, &artifact)
            .await
        {
            Ok(receipt) => {
                let receipt = scope_key_package_publish_receipt(receipt, &publication.endpoints);
                finish_key_package_attempt(
                    &mut lifecycle.publication_targets,
                    &receipt.accepted,
                    &receipt.rejected,
                    &receipt.confirmed_absent,
                    &receipt.failed,
                );
                if receipt.accepted.is_empty() {
                    lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
                    self.session.put_key_package_lifecycle(&lifecycle)?;
                    return Err(crate::key_package::KeyPackagePublishError::exposed(
                        "no KeyPackage relay acknowledged the republication",
                    )
                    .into());
                }
                lifecycle.phase = if lifecycle
                    .publication_targets
                    .iter()
                    .all(key_package_target_is_terminal)
                {
                    cgka_traits::MaintenancePhase::Complete
                } else {
                    cgka_traits::MaintenancePhase::Fanout
                };
                self.session.put_key_package_lifecycle(&lifecycle)?;
                Ok(key_package)
            }
            Err(error) => {
                lifecycle.phase = if error.externally_exposed {
                    cgka_traits::MaintenancePhase::Fanout
                } else {
                    cgka_traits::MaintenancePhase::Retry
                };
                self.session.put_key_package_lifecycle(&lifecycle)?;
                Err(error.into())
            }
        }
    }

    /// Replace a stale pending transport revision without replacing the MLS
    /// KeyPackage or its durable private material. The signed revision and all
    /// correlated lifecycle fields are committed before any network call.
    async fn reauthor_pending_key_package_if_stale(
        &mut self,
        lifecycle: &mut KeyPackageLifecycleState,
    ) -> AccountResult<()> {
        let Some(pending) = lifecycle.pending_replacement.as_ref() else {
            return Ok(());
        };
        let Some(previous_artifact) = pending.signed_event.clone() else {
            return Ok(());
        };
        let pending_key_package = pending.key_package.clone();
        let pending_key_package_ref = pending.key_package_ref.clone();
        let pending_not_after = pending.not_after;
        let pending_targets = pending.targets.clone();
        let now = self.wall_clock.now();
        let force_reauthor = lifecycle
            .deleted_live_revision_event_ids
            .contains(&previous_artifact.id);
        let reauthor_after = force_reauthor
            .then_some(0)
            .or(self.key_packages.signed_artifact_reauthor_at_age_secs());
        let created_at = match key_package_reauthor_created_at(
            &previous_artifact,
            now,
            reauthor_after,
            lifecycle.authored_event_created_at,
            true,
        ) {
            Ok(Some(created_at)) => created_at,
            Ok(None) => return Ok(()),
            Err(()) => {
                lifecycle.phase = MaintenancePhase::ClockSkewBlocked;
                self.session.put_key_package_lifecycle(lifecycle)?;
                return Err(AccountError::ClockSkewBlocked);
            }
        };
        let endpoints = pending_targets
            .iter()
            .filter(|target| target.state != TransportFanoutAttemptState::PolicyProhibited)
            .map(|target| target.endpoint.clone())
            .collect::<Vec<_>>();
        let publication = KeyPackagePublication {
            account_id: self.session.self_id().clone(),
            key_package: pending_key_package,
            slot_id: lifecycle.stable_slot_id.clone(),
            created_at,
            endpoints: endpoints.clone(),
        };
        let retired_publication = retired_key_package_publication(
            &previous_artifact,
            Some(&pending_key_package_ref),
            Some(pending_not_after),
            false,
            &pending_targets,
        );
        let projected_liabilities = projected_pending_key_package_reauthor_liability_count(
            lifecycle,
            retired_publication.as_ref(),
            &endpoints,
        );
        self.ensure_key_package_publication_liability_count(lifecycle, projected_liabilities)?;
        let artifact = self.key_packages.prepare_key_package(publication).await?;
        validate_reauthored_key_package_artifact(&previous_artifact, created_at, &artifact)?;

        if let Some(retired_publication) = retired_publication {
            retain_retired_key_package_publication(lifecycle, retired_publication);
        }
        let pending = lifecycle
            .pending_replacement
            .as_mut()
            .expect("pending replacement remains serialized while reauthoring");
        pending.authored_created_at = artifact.created_at;
        pending.signed_event = Some(artifact);
        pending.attempt_count = 0;
        pending.last_failure_code = None;
        replace_key_package_publication_targets(&mut pending.targets, &endpoints);
        lifecycle
            .deleted_live_revision_event_ids
            .retain(|event_id| *event_id != previous_artifact.id);
        lifecycle.phase = MaintenancePhase::PendingPublication;
        self.session.put_key_package_lifecycle(lifecycle)?;
        Ok(())
    }

    /// Reconcile a durable pending revision with the account's current
    /// authoritative publication policy before either reauthoring or sending
    /// it. Endpoint changes do not alter the signed Nostr event bytes, but they
    /// do alter the exact privacy-liability set and therefore must pass the
    /// global bound and commit before network I/O.
    fn reconcile_pending_key_package_publication_targets(
        &mut self,
        lifecycle: &mut KeyPackageLifecycleState,
        authoritative_endpoints: &[TransportEndpoint],
    ) -> AccountResult<()> {
        let Some(_) = lifecycle.pending_replacement.as_ref() else {
            return Ok(());
        };
        let mut reconciled = lifecycle.clone();
        merge_republish_publication_targets(
            &mut reconciled
                .pending_replacement
                .as_mut()
                .expect("pending replacement remains present in cloned lifecycle")
                .targets,
            authoritative_endpoints,
        );
        if key_package_signed_publication_liability_count(&reconciled)
            > MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES
        {
            lifecycle.phase = MaintenancePhase::Retry;
            self.session.put_key_package_lifecycle(lifecycle)?;
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "key package signed-publication endpoint-liability journal is full",
            )
            .into());
        }
        if reconciled != *lifecycle {
            *lifecycle = reconciled;
            self.session.put_key_package_lifecycle(lifecycle)?;
        }
        Ok(())
    }

    /// Replace a stale current transport revision while retaining the same MLS
    /// KeyPackage coordinate. Every live target must receive the newer
    /// parameterized-replaceable event, including relays that acknowledged the
    /// superseded revision.
    async fn reauthor_current_key_package_if_stale(
        &mut self,
        lifecycle: &mut KeyPackageLifecycleState,
        key_package: &KeyPackage,
        live_endpoints: &[TransportEndpoint],
    ) -> AccountResult<()> {
        let Some(previous_artifact) = lifecycle.authored_signed_event.clone() else {
            return Ok(());
        };
        let now = self.wall_clock.now();
        let force_reauthor = lifecycle
            .deleted_live_revision_event_ids
            .contains(&previous_artifact.id);
        let reauthor_after = force_reauthor
            .then_some(0)
            .or(self.key_packages.signed_artifact_reauthor_at_age_secs());
        let created_at = match key_package_reauthor_created_at(
            &previous_artifact,
            now,
            reauthor_after,
            lifecycle.authored_event_created_at,
            false,
        ) {
            Ok(Some(created_at)) => created_at,
            Ok(None) => return Ok(()),
            Err(()) => {
                lifecycle.phase = MaintenancePhase::ClockSkewBlocked;
                self.session.put_key_package_lifecycle(lifecycle)?;
                return Err(AccountError::ClockSkewBlocked);
            }
        };
        let publication = KeyPackagePublication {
            account_id: self.session.self_id().clone(),
            key_package: key_package.clone(),
            slot_id: lifecycle.stable_slot_id.clone(),
            created_at,
            endpoints: live_endpoints.to_vec(),
        };
        let retired_publication = retired_key_package_publication(
            &previous_artifact,
            lifecycle.current_key_package_ref.as_deref(),
            lifecycle.current_not_after,
            false,
            &lifecycle.publication_targets,
        );
        let projected_liabilities = projected_current_key_package_reauthor_liability_count(
            lifecycle,
            retired_publication.as_ref(),
            live_endpoints,
        );
        self.ensure_key_package_publication_liability_count(lifecycle, projected_liabilities)?;
        let artifact = self.key_packages.prepare_key_package(publication).await?;
        validate_reauthored_key_package_artifact(&previous_artifact, created_at, &artifact)?;

        if let Some(retired_publication) = retired_publication {
            retain_retired_key_package_publication(lifecycle, retired_publication);
        }
        lifecycle.authored_event_id = Some(artifact.id.clone());
        lifecycle.authored_event_created_at = Some(artifact.created_at);
        lifecycle.authored_signed_event = Some(artifact);
        lifecycle
            .deleted_live_revision_event_ids
            .retain(|event_id| *event_id != previous_artifact.id);
        replace_key_package_publication_targets(&mut lifecycle.publication_targets, live_endpoints);
        lifecycle.phase = MaintenancePhase::Fanout;
        self.session.put_key_package_lifecycle(lifecycle)?;
        Ok(())
    }

    /// Stage the next MLS KeyPackage, durable private material, and initial
    /// signed publication revision without performing any network I/O.
    ///
    /// This is the durable local-readiness boundary for generated accounts:
    /// callers may return the identity only after this succeeds, then resume
    /// the same durable lifecycle later. Publication uses the current signed
    /// revision exactly unless bounded-age policy first persists a newer
    /// revision at the same replaceable-event coordinate.
    pub async fn prepare_fresh_key_package(
        &mut self,
        endpoints: Vec<TransportEndpoint>,
    ) -> AccountResult<KeyPackage> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "prepare_fresh_key_package",
            endpoint_count = endpoints.len(),
            "preparing fresh key package for later publication"
        );
        self.sweep_expired_key_package_private_material()?;
        let now = self.wall_clock.now();
        let mut lifecycle = match self.session.key_package_lifecycle()? {
            Some(state) => state,
            None => {
                let stable_slot_id = self
                    .key_packages
                    .legacy_slot_id(&self.session.self_id())?
                    .ok_or_else(|| {
                        crate::key_package::KeyPackagePublishError::unexposed(
                            "key package slot is uninitialized; provision a durable slot before publication",
                        )
                    })?;
                KeyPackageLifecycleState {
                    stable_slot_id,
                    phase: cgka_traits::MaintenancePhase::Complete,
                    cutover_publication_blocked: false,
                    current_key_package: None,
                    current_key_package_ref: None,
                    current_not_before: None,
                    current_not_after: None,
                    authored_event_id: None,
                    authored_event_created_at: None,
                    authored_signed_event: None,
                    deleted_live_revision_event_ids: Vec::new(),
                    deletion_overflow_owner_event_id: None,
                    retired_publications_pending_deletion: Vec::new(),
                    publication_targets: Vec::new(),
                    refresh_at: None,
                    upgrade_rotation_recorded: false,
                    last_consumed_key_package_ref: None,
                    last_consumed_at: None,
                    consumed_key_package_refs: Vec::new(),
                    retained_private_material: Vec::new(),
                    pending_replacement: None,
                }
            }
        };
        if lifecycle.stable_slot_id.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "key package lifecycle is migration-blocked because the stable replaceable-event slot is unavailable",
            )
            .into());
        }

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
            let lead = self.maintenance_random.sample_inclusive(
                KEY_PACKAGE_REFRESH_MIN_LEAD_SECS,
                KEY_PACKAGE_REFRESH_MAX_LEAD_SECS,
            );
            self.session.stage_key_package_replacement(
                &mut lifecycle,
                created_at,
                lead,
                endpoints
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
            )?;
        }

        // A pending replacement can outlive the route policy that originally
        // staged it. Reconcile before signing so a zero-target draft is not
        // frozen into an artifact that a real transport correctly refuses to
        // publish once a route later appears.
        self.reconcile_pending_key_package_publication_targets(&mut lifecycle, &endpoints)?;

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
                    .filter(|target| target.state != TransportFanoutAttemptState::PolicyProhibited)
                    .map(|target| target.endpoint.clone())
                    .collect(),
            };
            self.ensure_key_package_publication_liability_capacity(
                &mut lifecycle,
                publication.endpoints.len(),
            )?;
            let artifact = self.key_packages.prepare_key_package(publication).await?;
            lifecycle
                .pending_replacement
                .as_mut()
                .expect("unsigned pending replacement exists")
                .signed_event = Some(artifact);
            // Exact signed bytes are durable before the first network call.
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }

        // Relay discovery may have advanced the stable-slot high-water after
        // this exact pending artifact was signed. Reauthor locally while the
        // cutover gate is still armed; the superseded exact revision and the
        // strict-newer signed bytes commit before this method returns, and no
        // network I/O occurs here.
        self.reauthor_pending_key_package_if_stale(&mut lifecycle)
            .await?;

        Ok(lifecycle
            .pending_replacement
            .as_ref()
            .expect("prepared replacement exists")
            .key_package
            .clone())
    }

    pub async fn publish_fresh_key_package(&mut self) -> AccountResult<KeyPackage> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "publish_fresh_key_package",
            endpoint_count = self.routing.key_package_endpoints().len(),
            "publishing fresh key package"
        );
        if let Some(lifecycle) = self.session.key_package_lifecycle()? {
            ensure_key_package_cutover_publication_allowed(&lifecycle)?;
        }
        let endpoints = self.routing.key_package_endpoints().to_vec();
        self.prepare_fresh_key_package(endpoints.clone()).await?;
        let mut lifecycle = self
            .session
            .key_package_lifecycle()?
            .expect("prepared lifecycle is durable");

        self.reconcile_pending_key_package_publication_targets(&mut lifecycle, &endpoints)?;

        self.reauthor_pending_key_package_if_stale(&mut lifecycle)
            .await?;

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
                .filter(|target| target.state != TransportFanoutAttemptState::PolicyProhibited)
                .map(|target| target.endpoint.clone())
                .collect(),
        };
        begin_key_package_attempt(
            &mut lifecycle
                .pending_replacement
                .as_mut()
                .expect("pending replacement remains durable before publication")
                .targets,
            &publication.endpoints,
            self.wall_clock.now(),
        );
        lifecycle.phase = MaintenancePhase::PendingPublication;
        self.session.put_key_package_lifecycle(&lifecycle)?;
        let receipt = match self
            .key_packages
            .publish_prepared_key_package_detailed(&publication, &artifact)
            .await
        {
            Ok(receipt) => scope_key_package_publish_receipt(receipt, &publication.endpoints),
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
                }
                lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
                self.session.put_key_package_lifecycle(&lifecycle)?;
                return Err(error.into());
            }
        };
        if receipt.accepted.is_empty() {
            if let Some(pending) = lifecycle.pending_replacement.as_mut() {
                pending.attempt_count = pending.attempt_count.saturating_add(1);
                pending.last_failure_code = Some("ambiguous_exposure".into());
                finish_key_package_attempt(
                    &mut pending.targets,
                    &receipt.accepted,
                    &receipt.rejected,
                    &receipt.confirmed_absent,
                    &receipt.failed,
                );
            }
            lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
            self.session.put_key_package_lifecycle(&lifecycle)?;
            return Err(crate::key_package::KeyPackagePublishError::exposed(
                "no KeyPackage relay acknowledged the replacement",
            )
            .into());
        }

        let mut replacement = lifecycle
            .pending_replacement
            .take()
            .expect("published replacement exists");
        finish_key_package_attempt(
            &mut replacement.targets,
            &receipt.accepted,
            &receipt.rejected,
            &receipt.confirmed_absent,
            &receipt.failed,
        );
        let previous = lifecycle.current_key_package.clone();
        let previous_key_package_ref = lifecycle.current_key_package_ref.clone();
        let previous_was_consumed = previous_key_package_ref
            .as_deref()
            .is_some_and(|key_package_ref| lifecycle.key_package_ref_is_consumed(key_package_ref));
        let superseded_publication =
            retired_current_key_package_publication(&lifecycle, previous_was_consumed);
        if let Some(superseded_publication) = superseded_publication {
            retain_retired_key_package_publication(&mut lifecycle, superseded_publication);
        }
        if previous_was_consumed && let Some(key_package_ref) = previous_key_package_ref.as_deref()
        {
            mark_retired_key_package_revisions_unusable(&mut lifecycle, key_package_ref);
        }
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
        // A relay-acknowledged semantic replacement supersedes every deleted
        // live revision that could otherwise have been retried.
        lifecycle.deleted_live_revision_event_ids.clear();
        lifecycle.publication_targets = replacement.targets;
        lifecycle.refresh_at = Some(replacement.refresh_at);
        lifecycle.phase = if lifecycle
            .publication_targets
            .iter()
            .all(key_package_target_is_terminal)
        {
            cgka_traits::MaintenancePhase::Complete
        } else {
            cgka_traits::MaintenancePhase::Fanout
        };
        lifecycle.upgrade_rotation_recorded = true;
        if previous_was_consumed
            && let Some(key_package_ref) = previous_key_package_ref.as_deref()
            && !key_package_ref_has_live_private_material(&lifecycle, key_package_ref)
        {
            lifecycle.clear_consumed_key_package_ref(key_package_ref);
        }
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

    /// Transfer cutover-era Welcome-consumption evidence onto every exact
    /// relay revision admitted by a completed authoritative scan, then reclaim
    /// bounded ref-journal entries that no longer protect live private
    /// material.
    ///
    /// The app calls this after all authoritative relay pages were processed
    /// and before it persists the scan-complete marker or clears the
    /// publication gate. A crash beforehand retains the refs; afterward each
    /// matching exact liability independently carries
    /// `delete_without_successor`.
    pub fn finalize_key_package_cutover_consumption_evidence(&mut self) -> AccountResult<()> {
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(());
        };
        let mut live_refs = lifecycle
            .current_key_package_ref
            .clone()
            .into_iter()
            .chain(
                lifecycle
                    .pending_replacement
                    .as_ref()
                    .map(|pending| pending.key_package_ref.clone()),
            )
            .chain(
                lifecycle
                    .retained_private_material
                    .iter()
                    .map(|retained| retained.key_package_ref.clone()),
            )
            .collect::<Vec<_>>();
        for key_package in self.session.durably_owned_key_packages()? {
            let metadata = self.session.key_package_metadata(&key_package)?;
            live_refs.push(hex::decode(&metadata.key_package_ref_hex).map_err(|error| {
                cgka_traits::EngineError::Serialize(format!(
                    "durable key package reference: {error}"
                ))
            })?);
        }
        live_refs.sort();
        live_refs.dedup();

        let refs = lifecycle.consumed_key_package_refs.clone();
        for key_package_ref in refs {
            mark_retired_key_package_revisions_unusable(&mut lifecycle, &key_package_ref);
            if live_refs.contains(&key_package_ref) {
                continue;
            }
            lifecycle.clear_consumed_key_package_ref(&key_package_ref);
        }
        self.session.put_key_package_lifecycle(&lifecycle)?;
        Ok(())
    }

    /// Persist the upgrade-cutover publication interlock under the account
    /// runtime's single-writer authority.
    ///
    /// Exact retired-revision deletion remains available while blocked. Every
    /// kind-30443 publication path checks this bit immediately before it can
    /// prepare a network attempt, so worker ticks and manual commands cannot
    /// race an incomplete relay scan.
    pub fn set_key_package_cutover_publication_blocked(
        &mut self,
        blocked: bool,
    ) -> AccountResult<()> {
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "cannot update the key package cutover gate without lifecycle state",
            )
            .into());
        };
        if lifecycle.stable_slot_id.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "cannot update the key package cutover gate without a stable slot",
            )
            .into());
        }
        if lifecycle.cutover_publication_blocked != blocked {
            lifecycle.cutover_publication_blocked = blocked;
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok(())
    }

    /// Retain the signed relay timestamp of an exact live same-slot revision.
    ///
    /// Upgrade-era cache rows can carry a defaulted or stale `published_at`
    /// even though the relay still has the exact signed event.  A strict
    /// cutover scan verifies the event signature and stable slot before
    /// calling this method. Persisting both the raw timestamp and every exact
    /// source endpoint before the scan is marked complete prevents a later
    /// replacement from losing NIP-33 ordering or hiding an old relay copy
    /// after a local clock rollback or route change. Endpoints beyond the
    /// ordinary liability bound are returned deferred; strict cutover must
    /// retain its publication gate until those endpoints are durable.
    pub fn observe_live_key_package_publication(
        &mut self,
        stable_slot_id: String,
        event_id: &MessageId,
        authored_created_at: Timestamp,
        mut endpoints: Vec<TransportEndpoint>,
    ) -> AccountResult<(Vec<TransportEndpoint>, Vec<TransportEndpoint>)> {
        if endpoints.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "observed live key package revision requires at least one source endpoint",
            )
            .into());
        }
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "cannot observe a live key package revision without lifecycle state",
            )
            .into());
        };
        if lifecycle.stable_slot_id.is_empty() || lifecycle.stable_slot_id != stable_slot_id {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "observed live key package revision does not match the local stable slot",
            )
            .into());
        }
        let matches_current = lifecycle
            .authored_signed_event
            .as_ref()
            .is_some_and(|artifact| artifact.id == *event_id)
            || lifecycle.authored_event_id.as_ref() == Some(event_id);
        let matches_pending = lifecycle
            .pending_replacement
            .as_ref()
            .and_then(|pending| pending.signed_event.as_ref())
            .is_some_and(|artifact| artifact.id == *event_id);
        if !matches_current && !matches_pending {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "observed key package revision is not the exact live current or pending event",
            )
            .into());
        }

        endpoints.sort();
        endpoints.dedup();
        let mut liability_count = key_package_signed_publication_liability_count(&lifecycle);
        let mut admitted = Vec::new();
        let mut deferred = Vec::new();
        for endpoint in endpoints {
            let already_durable =
                key_package_event_endpoint_is_liability(&lifecycle, event_id, &endpoint);
            if !already_durable && liability_count >= MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES
            {
                deferred.push(endpoint);
                continue;
            }
            if !already_durable {
                liability_count = liability_count.saturating_add(1);
            }
            admitted.push(endpoint);
        }

        let targets = if matches_current {
            &mut lifecycle.publication_targets
        } else {
            &mut lifecycle
                .pending_replacement
                .as_mut()
                .expect("a matching pending artifact remains in lifecycle state")
                .targets
        };
        let mut targets_changed = false;
        for endpoint in &admitted {
            if let Some(target) = targets
                .iter_mut()
                .find(|target| target.endpoint == *endpoint)
            {
                let observed_attempt_at = target
                    .last_attempt_at
                    .map(|previous| previous.max(authored_created_at))
                    .unwrap_or(authored_created_at);
                if target.state != TransportFanoutAttemptState::Accepted
                    || target.attempt_count == 0
                    || target.last_attempt_at != Some(observed_attempt_at)
                    || target.failure_code.is_some()
                {
                    target.state = TransportFanoutAttemptState::Accepted;
                    target.attempt_count = target.attempt_count.max(1);
                    target.last_attempt_at = Some(observed_attempt_at);
                    target.failure_code = None;
                    targets_changed = true;
                }
            } else {
                targets.push(TransportFanoutTarget {
                    endpoint: endpoint.clone(),
                    state: TransportFanoutAttemptState::Accepted,
                    attempt_count: 1,
                    last_attempt_at: Some(authored_created_at),
                    failure_code: None,
                });
                targets_changed = true;
            }
        }
        targets.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));

        let observed_high_water = lifecycle
            .authored_event_created_at
            .map(|previous| previous.max(authored_created_at))
            .unwrap_or(authored_created_at);
        if lifecycle.authored_event_created_at != Some(observed_high_water) || targets_changed {
            lifecycle.authored_event_created_at = Some(observed_high_water);
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok((admitted, deferred))
    }

    /// Durably import an exact non-live KeyPackage revision discovered during
    /// an upgrade relay scan, without performing transport I/O.
    ///
    /// The caller must pass the parsed event's stable slot and
    /// safety-canonicalized source endpoints. The slot must match this local
    /// account-device lifecycle; same-account directory scans can also return
    /// sibling-device slots, which must never be deleted. Existing
    /// event/endpoint liabilities are returned as admitted, while newly seen
    /// endpoints are admitted individually up to the global journal bound and
    /// the remainder are returned as deferred. A live current or pending event
    /// id is rejected so discovery cannot reclassify the selected revision as
    /// retired behind the account worker's back.
    pub fn journal_discovered_retired_key_package_publication(
        &mut self,
        stable_slot_id: String,
        event_id: MessageId,
        authored_created_at: Timestamp,
        key_package_ref: Vec<u8>,
        package_not_after: Timestamp,
        endpoints: Vec<TransportEndpoint>,
    ) -> AccountResult<(Vec<TransportEndpoint>, Vec<TransportEndpoint>)> {
        self.journal_discovered_retired_key_package_publication_with_policy(
            stable_slot_id,
            event_id,
            authored_created_at,
            key_package_ref,
            package_not_after,
            endpoints,
            false,
        )
    }

    /// The teardown variant commits destructive eligibility in the same SQL
    /// lifecycle update that first journals a relay-revealed predecessor.
    #[allow(clippy::too_many_arguments)]
    pub fn journal_discovered_retired_key_package_publication_with_policy(
        &mut self,
        stable_slot_id: String,
        event_id: MessageId,
        authored_created_at: Timestamp,
        key_package_ref: Vec<u8>,
        package_not_after: Timestamp,
        mut endpoints: Vec<TransportEndpoint>,
        delete_without_successor: bool,
    ) -> AccountResult<(Vec<TransportEndpoint>, Vec<TransportEndpoint>)> {
        if endpoints.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "discovered key package revision requires at least one source endpoint",
            )
            .into());
        }
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "cannot journal a discovered key package revision without lifecycle state",
            )
            .into());
        };
        if lifecycle.stable_slot_id.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "cannot journal a discovered key package revision without a stable slot",
            )
            .into());
        }
        if stable_slot_id != lifecycle.stable_slot_id {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "discovered key package revision does not match the local stable slot",
            )
            .into());
        }
        let matches_current = lifecycle
            .authored_signed_event
            .as_ref()
            .is_some_and(|artifact| artifact.id == event_id)
            || lifecycle.authored_event_id.as_ref() == Some(&event_id);
        let matches_pending = lifecycle
            .pending_replacement
            .as_ref()
            .and_then(|pending| pending.signed_event.as_ref())
            .is_some_and(|artifact| artifact.id == event_id);
        let matches_durably_deleted_live_revision = lifecycle
            .deleted_live_revision_event_ids
            .contains(&event_id);
        if (matches_current || matches_pending) && !matches_durably_deleted_live_revision {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "cannot classify a live key package revision as relay-discovered retirement",
            )
            .into());
        }

        // A relay can expose a same-slot revision authored by an older client
        // after the local lifecycle snapshot was persisted. Preserve that
        // transport ordering evidence even when journal capacity defers every
        // endpoint: the next fresh artifact must sort strictly after every
        // discovered revision or it cannot supersede the relay copy.
        let previous_authored_high_water = lifecycle.authored_event_created_at;
        lifecycle.authored_event_created_at = Some(
            previous_authored_high_water
                .map(|previous| previous.max(authored_created_at))
                .unwrap_or(authored_created_at),
        );
        let authored_high_water_advanced =
            lifecycle.authored_event_created_at != previous_authored_high_water;

        endpoints.sort();
        endpoints.dedup();
        let mut liability_count = key_package_signed_publication_liability_count(&lifecycle);
        let mut admitted = Vec::new();
        let mut deferred = Vec::new();
        for endpoint in endpoints {
            let already_durable =
                key_package_event_endpoint_is_liability(&lifecycle, &event_id, &endpoint);
            if !already_durable && liability_count >= MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES
            {
                deferred.push(endpoint);
                continue;
            }
            if !already_durable {
                liability_count = liability_count.saturating_add(1);
            }
            admitted.push(endpoint);
        }
        let delete_without_successor = delete_without_successor
            || matches_durably_deleted_live_revision
            || lifecycle.key_package_ref_is_consumed(&key_package_ref);
        if !admitted.is_empty() {
            retain_retired_key_package_publication(
                &mut lifecycle,
                RetiredKeyPackagePublication {
                    event_id,
                    authored_created_at,
                    key_package_ref: Some(key_package_ref),
                    package_not_after: Some(package_not_after),
                    delete_without_successor,
                    deletion_targets: admitted
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
                },
            );
        }
        if !admitted.is_empty() || authored_high_water_advanced {
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok((admitted, deferred))
    }

    /// Serialize exact endpoint-scoped recovery intent before an explicit
    /// transport deletion can escape.
    ///
    /// Unknown relay-discovered event ids are journaled too: a later local
    /// NIP-33 replacement cannot supersede an event in another stable slot.
    /// The returned deferred endpoints were not journaled and must not be sent.
    pub fn prepare_key_package_deletion_recovery(
        &mut self,
        event_id: &cgka_traits::MessageId,
        endpoints: Vec<TransportEndpoint>,
    ) -> AccountResult<(Vec<TransportEndpoint>, Vec<TransportEndpoint>)> {
        if endpoints.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "key package deletion requires at least one relay endpoint",
            )
            .into());
        }
        let mut lifecycle = match self.session.key_package_lifecycle()? {
            Some(lifecycle) => lifecycle,
            None => {
                let stable_slot_id = self
                    .key_packages
                    .legacy_slot_id(&self.session.self_id())?
                    .ok_or_else(|| {
                        crate::key_package::KeyPackagePublishError::unexposed(
                            "cannot durably journal KeyPackage deletion without a stable slot",
                        )
                    })?;
                KeyPackageLifecycleState::slot_only(stable_slot_id)
            }
        };
        if lifecycle.stable_slot_id.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "cannot durably journal KeyPackage deletion without a stable slot",
            )
            .into());
        }

        let deletes_live_revision = lifecycle
            .authored_signed_event
            .as_ref()
            .is_some_and(|artifact| artifact.id == *event_id)
            || lifecycle
                .authored_event_id
                .as_ref()
                .is_some_and(|authored| authored == event_id)
            || lifecycle
                .pending_replacement
                .as_ref()
                .and_then(|pending| pending.signed_event.as_ref())
                .is_some_and(|artifact| artifact.id == *event_id);
        let mut endpoints = endpoints;
        endpoints.sort();
        endpoints.dedup();
        let overflow_owner_before = lifecycle.deletion_overflow_owner_event_id.clone();
        let (admitted, deferred) = admit_atomic_exact_key_package_deletion_liabilities(
            &mut lifecycle,
            event_id,
            endpoints,
        );
        if !admitted.is_empty()
            && deletes_live_revision
            && !lifecycle.deleted_live_revision_event_ids.contains(event_id)
        {
            lifecycle
                .deleted_live_revision_event_ids
                .push(event_id.clone());
        }
        if !admitted.is_empty()
            || lifecycle.deletion_overflow_owner_event_id != overflow_owner_before
        {
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok((admitted, deferred))
    }

    /// Atomically retain an unparsable/legacy same-slot revision's exact
    /// endpoint liabilities and its signed NIP-33 ordering high-water.
    ///
    /// This differs from arbitrary manual deletion admission: the caller has
    /// verified the event signature and stable `d` coordinate, so its raw
    /// `created_at` must constrain every later replacement even when journal
    /// capacity defers the endpoint set. The whole exact source set is admitted
    /// atomically through the bounded deletion reserve or returned deferred;
    /// live current/pending ids are rejected rather than reclassified as
    /// cutover debris.
    pub fn journal_discovered_unparsed_key_package_publication(
        &mut self,
        stable_slot_id: String,
        event_id: cgka_traits::MessageId,
        authored_created_at: Timestamp,
        endpoints: Vec<TransportEndpoint>,
    ) -> AccountResult<(Vec<TransportEndpoint>, Vec<TransportEndpoint>)> {
        if endpoints.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "discovered key package revision requires at least one source endpoint",
            )
            .into());
        }
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "cannot journal a discovered key package revision without lifecycle state",
            )
            .into());
        };
        if lifecycle.stable_slot_id.is_empty() || lifecycle.stable_slot_id != stable_slot_id {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "discovered key package revision does not match the local stable slot",
            )
            .into());
        }
        let matches_current = lifecycle
            .authored_signed_event
            .as_ref()
            .is_some_and(|artifact| artifact.id == event_id)
            || lifecycle.authored_event_id.as_ref() == Some(&event_id);
        let matches_pending = lifecycle
            .pending_replacement
            .as_ref()
            .and_then(|pending| pending.signed_event.as_ref())
            .is_some_and(|artifact| artifact.id == event_id);
        if matches_current || matches_pending {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "cannot classify a live key package revision as relay-discovered retirement",
            )
            .into());
        }

        let previous_authored_high_water = lifecycle.authored_event_created_at;
        lifecycle.authored_event_created_at = Some(
            previous_authored_high_water
                .map(|previous| previous.max(authored_created_at))
                .unwrap_or(authored_created_at),
        );
        let authored_high_water_advanced =
            lifecycle.authored_event_created_at != previous_authored_high_water;
        let mut endpoints = endpoints;
        endpoints.sort();
        endpoints.dedup();
        let overflow_owner_before = lifecycle.deletion_overflow_owner_event_id.clone();
        let (admitted, deferred) = admit_atomic_exact_key_package_deletion_liabilities(
            &mut lifecycle,
            &event_id,
            endpoints,
        );
        if let Some(retired) = lifecycle
            .retired_publications_pending_deletion
            .iter_mut()
            .find(|retired| retired.event_id == event_id)
        {
            retired.authored_created_at = retired.authored_created_at.max(authored_created_at);
        }
        if !admitted.is_empty()
            || authored_high_water_advanced
            || lifecycle.deletion_overflow_owner_event_id != overflow_owner_before
        {
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok((admitted, deferred))
    }

    /// Delete an exact signed KeyPackage revision with the account worker as
    /// the sole lifecycle-row owner. Admission and a possible-exposure marker
    /// are durable before network I/O; only endpoint-specific Accepted or
    /// confirmed-absence receipts prune the retry journal.
    pub async fn delete_key_package_revision_durably(
        &mut self,
        event_id: &cgka_traits::MessageId,
        endpoints: Vec<TransportEndpoint>,
    ) -> AccountResult<(DetailedKeyPackagePublishReceipt, Vec<TransportEndpoint>)> {
        let (mut admitted, mut deferred) =
            self.prepare_key_package_deletion_recovery(event_id, endpoints)?;
        let mut combined = DetailedKeyPackagePublishReceipt::default();
        let mut attempted_cleanup_for_capacity = false;

        loop {
            if admitted.is_empty() {
                if deferred.is_empty() || attempted_cleanup_for_capacity {
                    break;
                }
                // A full journal must not permanently wedge explicit cleanup.
                // One bounded active-deletion attempt may free a slot; failure
                // leaves every existing liability durable and the new pair
                // unsent/deferred.
                attempted_cleanup_for_capacity = true;
                let _ = self.retry_retired_key_package_deletions().await;
                (admitted, deferred) =
                    self.prepare_key_package_deletion_recovery(event_id, deferred)?;
                continue;
            }

            let mut lifecycle = self
                .session
                .key_package_lifecycle()?
                .expect("manual KeyPackage deletion admission persists lifecycle state");
            let retired = lifecycle
                .retired_publications_pending_deletion
                .iter_mut()
                .find(|retired| retired.event_id == *event_id)
                .expect("manual KeyPackage deletion admission persists the exact event");
            begin_key_package_attempt(
                &mut retired.deletion_targets,
                &admitted,
                self.wall_clock.now(),
            );
            self.session.put_key_package_lifecycle(&lifecycle)?;

            let receipt = self
                .key_packages
                .delete_key_package_revision(event_id, &admitted)
                .await?;
            let accepted = receipt
                .accepted
                .into_iter()
                .filter(|endpoint| admitted.contains(endpoint))
                .collect::<Vec<_>>();
            let rejected = receipt
                .rejected
                .into_iter()
                .filter(|endpoint| admitted.contains(endpoint))
                .collect::<Vec<_>>();
            let confirmed_absent = receipt
                .confirmed_absent
                .into_iter()
                .filter(|endpoint| admitted.contains(endpoint))
                .collect::<Vec<_>>();
            let failed = receipt
                .failed
                .into_iter()
                .filter(|endpoint| admitted.contains(endpoint))
                .collect::<Vec<_>>();

            let retired = lifecycle
                .retired_publications_pending_deletion
                .iter_mut()
                .find(|retired| retired.event_id == *event_id)
                .expect("manual KeyPackage deletion remains serialized through receipt commit");
            finish_key_package_attempt(
                &mut retired.deletion_targets,
                &accepted,
                &rejected,
                &confirmed_absent,
                &failed,
            );
            retired.deletion_targets.retain(|target| {
                !accepted.contains(&target.endpoint) && !confirmed_absent.contains(&target.endpoint)
            });
            lifecycle
                .retired_publications_pending_deletion
                .retain(|retired| {
                    retired.event_id != *event_id || !retired.deletion_targets.is_empty()
                });
            release_settled_key_package_deletion_overflow_owner(&mut lifecycle);
            let terminal_endpoints = accepted
                .iter()
                .chain(confirmed_absent.iter())
                .cloned()
                .collect::<Vec<_>>();
            mark_live_key_package_revision_endpoints_absent(
                &mut lifecycle,
                event_id,
                &terminal_endpoints,
            );
            self.session.put_key_package_lifecycle(&lifecycle)?;

            combined.accepted.extend(accepted);
            combined.rejected.extend(rejected);
            combined.confirmed_absent.extend(confirmed_absent);
            combined.failed.extend(failed);
            if deferred.is_empty() {
                break;
            }
            // Terminal receipts above may have freed journal capacity. Admit
            // only the previously deferred endpoints, never resending an
            // endpoint already attempted by this command.
            (admitted, deferred) =
                self.prepare_key_package_deletion_recovery(event_id, deferred)?;
        }

        combined.accepted.sort();
        combined.accepted.dedup();
        combined.rejected.sort();
        combined.rejected.dedup();
        combined.confirmed_absent.sort();
        combined.confirmed_absent.dedup();
        combined.failed.sort();
        combined.failed.dedup();
        Ok((combined, deferred))
    }

    pub fn durably_owned_key_packages(&self) -> AccountResult<Vec<KeyPackage>> {
        Ok(self.session.durably_owned_key_packages()?)
    }

    pub fn key_package_network_maintenance_due(&self) -> AccountResult<bool> {
        let now = self.wall_clock.now();
        Ok(match self.session.key_package_lifecycle()? {
            None => true,
            Some(lifecycle) if lifecycle.cutover_publication_blocked => false,
            Some(lifecycle) => match lifecycle.pending_replacement.as_ref() {
                Some(pending) => {
                    pending.signed_event.as_ref().is_some_and(|artifact| {
                        lifecycle
                            .deleted_live_revision_event_ids
                            .contains(&artifact.id)
                            || lifecycle
                                .authored_event_created_at
                                .is_some_and(|high_water| artifact.created_at < high_water)
                    }) || lifecycle.key_package_ref_is_consumed(&pending.key_package_ref)
                        || pending.signed_event.is_none()
                        || pending
                            .targets
                            .iter()
                            .any(|target| key_package_target_retry_due(target, now))
                }
                None => {
                    current_key_package_revision_is_deleted(&lifecycle)
                        || current_key_package_artifact_precedes_authoring_high_water(&lifecycle)
                        || lifecycle.current_key_package.is_none()
                        || lifecycle.current_key_package_ref.as_deref().is_some_and(
                            |key_package_ref| {
                                lifecycle.key_package_ref_is_consumed(key_package_ref)
                            },
                        )
                        || lifecycle.refresh_at.is_some_and(|deadline| deadline <= now)
                        || !lifecycle.upgrade_rotation_recorded
                }
            },
        })
    }

    pub fn key_package_has_pending_fanout(&self) -> AccountResult<bool> {
        let authoritative_endpoints = self.routing.key_package_endpoints();
        Ok(self
            .session
            .key_package_lifecycle()?
            .is_some_and(|lifecycle| {
                !lifecycle.cutover_publication_blocked
                    && lifecycle
                        .current_key_package_ref
                        .as_deref()
                        .is_some_and(|key_package_ref| {
                            !lifecycle.key_package_ref_is_consumed(key_package_ref)
                        })
                    && lifecycle.authored_signed_event.is_some()
                    && (lifecycle
                        .publication_targets
                        .iter()
                        .any(key_package_target_is_retryable)
                        || key_package_publication_targets_need_policy_reconciliation(
                            &lifecycle.publication_targets,
                            &authoritative_endpoints,
                        ))
            }))
    }

    /// Run one bounded pass over eligible superseded-revision deletions.
    ///
    /// This is the narrow post-discovery seam for hosts that first journal
    /// exact relay-observed revisions with
    /// [`Self::journal_discovered_retired_key_package_publication`]. The
    /// durable journal is the crash boundary; this call performs at most the
    /// configured per-pass deletion budget and leaves every failed or deferred
    /// endpoint for ordinary maintenance/restart recovery.
    pub async fn retry_retired_key_package_deletions_once(&mut self) -> AccountResult<()> {
        self.retry_retired_key_package_deletions().await.map(|_| ())
    }

    /// Make every durably journaled retired revision immediately deletable.
    ///
    /// This is reserved for quiesced account teardown after the user requested
    /// removal of their KeyPackages. Ordinary maintenance must continue to
    /// require a strictly newer accepted successor so it does not reduce
    /// invitation availability while the account remains active.
    pub fn authorize_teardown_key_package_deletions_without_successor(
        &mut self,
    ) -> AccountResult<()> {
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(());
        };
        let mut changed = false;
        for retired in &mut lifecycle.retired_publications_pending_deletion {
            if !retired.delete_without_successor {
                retired.delete_without_successor = true;
                changed = true;
            }
        }
        if changed {
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok(())
    }

    /// Run one bounded deletion pass and return the durable terminal endpoints
    /// that a cutover relay-history scan must immediately re-fetch.
    ///
    /// Unlike ordinary maintenance, cutover also needs to know whether a later
    /// retry can delete a revision without an accepted strictly newer successor
    /// covering that endpoint. The report ignores retry backoff for that
    /// classification so a deferred liability cannot let the cutover gate open.
    pub async fn retry_retired_key_package_deletions_once_reported(
        &mut self,
    ) -> AccountResult<RetiredKeyPackageDeletionPassReport> {
        self.retry_retired_key_package_deletions().await
    }

    /// Retry durable deletion obligations for superseded signed revisions.
    ///
    /// A live endpoint is eligible only after it acknowledges a strictly
    /// newer current revision. Removed-policy endpoints and expired packages
    /// are eligible immediately. Accepted endpoints are pruned synchronously
    /// before this future reaches another cancellation point; a process crash
    /// before that commit merely causes a safe duplicate deletion retry.
    async fn retry_retired_key_package_deletions(
        &mut self,
    ) -> AccountResult<RetiredKeyPackageDeletionPassReport> {
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(RetiredKeyPackageDeletionPassReport::default());
        };
        let now = self.wall_clock.now();
        let event_ids = lifecycle
            .retired_publications_pending_deletion
            .iter()
            .map(|retired| retired.event_id.clone())
            .collect::<Vec<_>>();
        let mut first_error = None;
        let mut attempts_remaining = KEY_PACKAGE_RETIRED_DELETION_ATTEMPTS_PER_CALL;
        let mut reported_terminal_endpoints = Vec::new();

        for event_id in event_ids {
            if attempts_remaining == 0 {
                break;
            }
            let Some(retired) = lifecycle
                .retired_publications_pending_deletion
                .iter()
                .find(|retired| retired.event_id == event_id)
                .cloned()
            else {
                continue;
            };
            let endpoints = retired
                .deletion_targets
                .iter()
                .filter(|target| {
                    retired_key_package_deletion_target_is_eligible(
                        &lifecycle, &retired, target, now,
                    ) && key_package_target_retry_due(target, now)
                })
                .map(|target| target.endpoint.clone())
                .take(attempts_remaining)
                .collect::<Vec<_>>();
            if endpoints.is_empty() {
                continue;
            }
            attempts_remaining = attempts_remaining.saturating_sub(endpoints.len());
            begin_key_package_attempt(
                &mut lifecycle
                    .retired_publications_pending_deletion
                    .iter_mut()
                    .find(|retired| retired.event_id == event_id)
                    .expect("retired KeyPackage revision remains serialized before deletion")
                    .deletion_targets,
                &endpoints,
                self.wall_clock.now(),
            );
            self.session.put_key_package_lifecycle(&lifecycle)?;

            let (accepted, rejected, confirmed_absent, failed, error) = match self
                .key_packages
                .delete_key_package_revision(&event_id, &endpoints)
                .await
            {
                Ok(receipt) => {
                    let accepted = receipt
                        .accepted
                        .into_iter()
                        .filter(|endpoint| endpoints.contains(endpoint))
                        .collect::<Vec<_>>();
                    let rejected = receipt
                        .rejected
                        .into_iter()
                        .filter(|endpoint| endpoints.contains(endpoint))
                        .collect::<Vec<_>>();
                    let confirmed_absent = receipt
                        .confirmed_absent
                        .into_iter()
                        .filter(|endpoint| endpoints.contains(endpoint))
                        .collect::<Vec<_>>();
                    let failed = receipt
                        .failed
                        .into_iter()
                        .filter(|endpoint| endpoints.contains(endpoint))
                        .collect::<Vec<_>>();
                    (accepted, rejected, confirmed_absent, failed, None)
                }
                Err(error) => (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Some(error)),
            };

            let retired = lifecycle
                .retired_publications_pending_deletion
                .iter_mut()
                .find(|retired| retired.event_id == event_id)
                .expect("retired KeyPackage revision remains serialized during deletion");
            finish_key_package_attempt(
                &mut retired.deletion_targets,
                &accepted,
                &rejected,
                &confirmed_absent,
                &failed,
            );
            retired.deletion_targets.retain(|target| {
                !accepted.contains(&target.endpoint) && !confirmed_absent.contains(&target.endpoint)
            });
            lifecycle
                .retired_publications_pending_deletion
                .retain(|retired| {
                    retired.event_id != event_id || !retired.deletion_targets.is_empty()
                });
            release_settled_key_package_deletion_overflow_owner(&mut lifecycle);
            let newly_terminal_endpoints = accepted
                .iter()
                .chain(confirmed_absent.iter())
                .cloned()
                .collect::<Vec<_>>();
            mark_live_key_package_revision_endpoints_absent(
                &mut lifecycle,
                &event_id,
                &newly_terminal_endpoints,
            );
            self.session.put_key_package_lifecycle(&lifecycle)?;
            reported_terminal_endpoints.extend(newly_terminal_endpoints);

            if let Some(error) = error
                && first_error.is_none()
            {
                first_error = Some(AccountError::from(error));
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(retired_key_package_deletion_pass_report(
                &lifecycle,
                self.wall_clock.now(),
                reported_terminal_endpoints,
            )),
        }
    }

    fn ensure_key_package_publication_liability_capacity(
        &mut self,
        lifecycle: &mut KeyPackageLifecycleState,
        additional_revisions: usize,
    ) -> AccountResult<()> {
        let projected = key_package_signed_publication_liability_count(lifecycle)
            .saturating_add(additional_revisions);
        self.ensure_key_package_publication_liability_count(lifecycle, projected)
    }

    fn ensure_key_package_publication_liability_count(
        &mut self,
        lifecycle: &mut KeyPackageLifecycleState,
        projected: usize,
    ) -> AccountResult<()> {
        if projected <= MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES {
            return Ok(());
        }
        lifecycle.phase = MaintenancePhase::Retry;
        self.session.put_key_package_lifecycle(lifecycle)?;
        Err(crate::key_package::KeyPackagePublishError::unexposed(
            "key package signed-publication endpoint-liability journal is full",
        )
        .into())
    }

    async fn retry_key_package_fanout(&mut self) -> AccountResult<()> {
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(());
        };
        ensure_key_package_cutover_publication_allowed(&lifecycle)?;
        if lifecycle.pending_replacement.is_some() {
            return Ok(());
        }
        if lifecycle
            .current_key_package_ref
            .as_deref()
            .is_some_and(|key_package_ref| lifecycle.key_package_ref_is_consumed(key_package_ref))
        {
            // An MLS KeyPackage is single-use. Once a Welcome consumes the
            // current revision, only a newly generated replacement may be
            // published; retrying the exact deleted event would advertise
            // private material that no longer exists locally.
            return Ok(());
        }
        let Some(key_package) = lifecycle.current_key_package.clone() else {
            return Ok(());
        };
        let live_endpoints = self.routing.key_package_endpoints().to_vec();
        // Apply removals and re-authorizations of already-journaled endpoints
        // before admitting any new liability. If the journal is full, a newly
        // added endpoint may remain deferred, but an endpoint removed from the
        // authoritative policy must never remain eligible for automatic I/O.
        let represented_live_endpoints = live_endpoints
            .iter()
            .filter(|endpoint| {
                lifecycle
                    .publication_targets
                    .iter()
                    .any(|target| target.endpoint == **endpoint)
            })
            .cloned()
            .collect::<Vec<_>>();
        let targets_before_policy_update = lifecycle.publication_targets.clone();
        merge_republish_publication_targets(
            &mut lifecycle.publication_targets,
            &represented_live_endpoints,
        );
        if lifecycle.publication_targets != targets_before_policy_update {
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }
        let additional_policy_targets = live_endpoints
            .iter()
            .filter(|endpoint| {
                !lifecycle
                    .publication_targets
                    .iter()
                    .any(|target| target.endpoint == **endpoint)
            })
            .count();
        self.ensure_key_package_publication_liability_capacity(
            &mut lifecycle,
            additional_policy_targets,
        )?;
        let targets_before_reconciliation = lifecycle.publication_targets.clone();
        merge_republish_publication_targets(&mut lifecycle.publication_targets, &live_endpoints);
        if lifecycle.publication_targets != targets_before_reconciliation {
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }
        self.reauthor_current_key_package_if_stale(&mut lifecycle, &key_package, &live_endpoints)
            .await?;
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
        let publication = KeyPackagePublication {
            account_id: self.session.self_id().clone(),
            key_package,
            slot_id: lifecycle.stable_slot_id.clone(),
            created_at: artifact.created_at,
            endpoints,
        };
        lifecycle.phase = cgka_traits::MaintenancePhase::Fanout;
        begin_key_package_attempt(
            &mut lifecycle.publication_targets,
            &publication.endpoints,
            self.wall_clock.now(),
        );
        self.session.put_key_package_lifecycle(&lifecycle)?;
        match self
            .key_packages
            .publish_prepared_key_package_detailed(&publication, &artifact)
            .await
        {
            Ok(receipt) => {
                let receipt = scope_key_package_publish_receipt(receipt, &publication.endpoints);
                finish_key_package_attempt(
                    &mut lifecycle.publication_targets,
                    &receipt.accepted,
                    &receipt.rejected,
                    &receipt.confirmed_absent,
                    &receipt.failed,
                );
                lifecycle.phase = if lifecycle
                    .publication_targets
                    .iter()
                    .all(key_package_target_is_terminal)
                {
                    cgka_traits::MaintenancePhase::Complete
                } else {
                    cgka_traits::MaintenancePhase::Fanout
                };
                self.session.put_key_package_lifecycle(&lifecycle)?;
                Ok(())
            }
            Err(error) => {
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
            Some(lifecycle) => match lifecycle.pending_replacement.as_ref() {
                Some(pending) => lifecycle.key_package_ref_is_consumed(&pending.key_package_ref),
                None => {
                    lifecycle.current_key_package.is_none()
                        || lifecycle.current_key_package_ref.as_deref().is_some_and(
                            |key_package_ref| {
                                lifecycle.key_package_ref_is_consumed(key_package_ref)
                            },
                        )
                        || lifecycle.refresh_at.is_some_and(|deadline| deadline <= now)
                        || !lifecycle.upgrade_rotation_recorded
                }
            },
        })
    }

    /// Delete expired private init-key material even when network maintenance
    /// is paused or transport cursor persistence is frozen.
    pub fn sweep_expired_key_package_private_material(&mut self) -> AccountResult<usize> {
        let now = self.wall_clock.now();
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(0);
        };
        let legacy_only_consumption_evidence = lifecycle.consumed_key_package_refs.is_empty()
            && lifecycle.last_consumed_key_package_ref.is_some();
        let consumed_refs_before = lifecycle.consumed_key_package_refs.clone();
        // Import the legacy single marker and deduplicate before making any
        // consumption decision. Only handled refs are cleared below.
        lifecycle.reconcile_consumed_key_package_refs();
        if legacy_only_consumption_evidence {
            // Legacy writers overwrote this single marker on each Welcome, so
            // the surviving ref cannot prove that any other durable bundle is
            // unconsumed, including pre-lifecycle bundles with no current,
            // pending, or retained projection. Pay a one-time availability
            // cost at upgrade: retire every durably owned package and every
            // known signed revision, then force a fresh replacement. Keep the
            // bounded ref tombstones so a later strict relay scan can classify
            // an exact revision for deletion without first publishing a
            // successor. The lifecycle transition and private-material
            // deletion commit atomically, so a crash observes either the
            // legacy sentinel again or the complete fail-closed state, never a
            // republishable half-transition.
            let legacy_last_consumed_ref = lifecycle.last_consumed_key_package_ref.clone();
            let legacy_last_consumed_at = lifecycle.last_consumed_at;
            let durably_owned = self.session.durably_owned_key_packages()?;
            let mut legacy_consumed_refs = lifecycle.consumed_key_package_refs.clone();
            let mut durable_packages = Vec::with_capacity(durably_owned.len());
            for key_package in durably_owned {
                let metadata = self.session.key_package_metadata(&key_package)?;
                let key_package_ref =
                    hex::decode(&metadata.key_package_ref_hex).map_err(|error| {
                        cgka_traits::EngineError::Serialize(format!(
                            "durable key package reference: {error}"
                        ))
                    })?;
                legacy_consumed_refs.push(key_package_ref.clone());
                durable_packages.push((key_package, key_package_ref));
            }
            legacy_consumed_refs.sort();
            legacy_consumed_refs.dedup();
            if legacy_consumed_refs.len()
                > cgka_traits::maintenance::MAX_CONSUMED_KEY_PACKAGE_REFS_PENDING_CLEANUP
            {
                return Err(crate::key_package::KeyPackagePublishError::unexposed(
                    "legacy consumed KeyPackage cleanup journal is full",
                )
                .into());
            }
            let mut retired = retire_legacy_only_consumption_projections(&mut lifecycle, now);
            for (key_package, key_package_ref) in durable_packages {
                mark_retired_key_package_revisions_unusable(&mut lifecycle, &key_package_ref);
                retain_key_package_for_private_material_retirement(&mut retired, key_package);
            }
            lifecycle.consumed_key_package_refs = legacy_consumed_refs;
            lifecycle.last_consumed_key_package_ref = legacy_last_consumed_ref;
            lifecycle.last_consumed_at = legacy_last_consumed_at;
            let deleted = retired.len();
            if deleted > 0 {
                self.session
                    .promote_key_package_lifecycle(&retired, &lifecycle)?;
            } else {
                self.session.put_key_package_lifecycle(&lifecycle)?;
            }
            return Ok(deleted);
        }
        let mut retired = Vec::new();
        let mut handled_consumed_refs = Vec::new();
        let mut lifecycle_changed = lifecycle.consumed_key_package_refs != consumed_refs_before;

        for key_package in self.session.durably_owned_key_packages()? {
            let metadata = self.session.key_package_metadata(&key_package)?;
            let key_package_ref = hex::decode(&metadata.key_package_ref_hex).map_err(|error| {
                cgka_traits::EngineError::Serialize(format!(
                    "durable key package reference: {error}"
                ))
            })?;
            if lifecycle.key_package_ref_is_consumed(&key_package_ref)
                && !key_package_ref_has_live_private_material(&lifecycle, &key_package_ref)
            {
                mark_retired_key_package_revisions_unusable(&mut lifecycle, &key_package_ref);
                handled_consumed_refs.push(key_package_ref);
                retired.push(key_package);
                lifecycle_changed = true;
            }
        }
        let current_was_consumed = lifecycle
            .current_key_package_ref
            .as_deref()
            .is_some_and(|key_package_ref| lifecycle.key_package_ref_is_consumed(key_package_ref));
        if current_was_consumed
            && let Some(key_package_ref) = lifecycle.current_key_package_ref.clone()
        {
            let retired_before = lifecycle.retired_publications_pending_deletion.clone();
            if let Some(retired_publication) =
                retired_current_key_package_publication(&lifecycle, true)
            {
                retain_retired_key_package_publication(&mut lifecycle, retired_publication);
            }
            mark_retired_key_package_revisions_unusable(&mut lifecycle, &key_package_ref);
            lifecycle_changed |= lifecycle.retired_publications_pending_deletion != retired_before;
        }
        if lifecycle
            .current_not_after
            .is_some_and(|deadline| deadline <= now)
            && lifecycle.current_key_package.is_some()
        {
            let expired_key_package_ref = lifecycle.current_key_package_ref.clone();
            if let Some(retired_publication) =
                retired_current_key_package_publication(&lifecycle, true)
            {
                retain_retired_key_package_publication(&mut lifecycle, retired_publication);
            }
            let expired = lifecycle
                .current_key_package
                .take()
                .expect("expired current KeyPackage remains present");
            lifecycle.current_key_package_ref = None;
            lifecycle.current_not_before = None;
            lifecycle.current_not_after = None;
            lifecycle.authored_event_id = None;
            // Keep the stable-slot authoring high-water even after the
            // semantic package expires so its replacement cannot sort behind
            // a relay copy of this exact revision after clock rollback.
            lifecycle.authored_signed_event = None;
            lifecycle.publication_targets.clear();
            lifecycle.refresh_at = None;
            lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
            if current_was_consumed && let Some(key_package_ref) = expired_key_package_ref {
                handled_consumed_refs.push(key_package_ref);
            }
            retired.push(expired);
            lifecycle_changed = true;
        }
        let pending_was_consumed = lifecycle
            .pending_replacement
            .as_ref()
            .is_some_and(|pending| lifecycle.key_package_ref_is_consumed(&pending.key_package_ref));
        if pending_was_consumed && let Some(consumed) = lifecycle.pending_replacement.take() {
            let consumed_created_at = consumed
                .signed_event
                .as_ref()
                .map(|artifact| artifact.created_at)
                .unwrap_or(consumed.authored_created_at);
            if let Some(retired_publication) = consumed.signed_event.as_ref().and_then(|artifact| {
                retired_key_package_publication(
                    artifact,
                    Some(&consumed.key_package_ref),
                    Some(consumed.not_after),
                    true,
                    &consumed.targets,
                )
            }) {
                retain_retired_key_package_publication(&mut lifecycle, retired_publication);
            }
            mark_retired_key_package_revisions_unusable(&mut lifecycle, &consumed.key_package_ref);
            // The relay may already have selected this newer pending revision
            // despite the missing acknowledgement. Preserve its authoring
            // high-water and force an immediate semantic replacement so the
            // consumed single-use package cannot remain the NIP-33 winner.
            lifecycle.authored_event_created_at = Some(
                lifecycle
                    .authored_event_created_at
                    .map(|current| current.max(consumed_created_at))
                    .unwrap_or(consumed_created_at),
            );
            lifecycle.refresh_at = Some(now);
            lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
            handled_consumed_refs.push(consumed.key_package_ref.clone());
            retired.push(consumed.key_package);
            lifecycle_changed = true;
        }
        if lifecycle
            .pending_replacement
            .as_ref()
            .is_some_and(|pending| pending.not_after <= now)
            && let Some(expired) = lifecycle.pending_replacement.take()
        {
            let expired_created_at = expired
                .signed_event
                .as_ref()
                .map(|artifact| artifact.created_at)
                .unwrap_or(expired.authored_created_at);
            if let Some(retired_publication) = expired.signed_event.as_ref().and_then(|artifact| {
                retired_key_package_publication(
                    artifact,
                    Some(&expired.key_package_ref),
                    Some(expired.not_after),
                    true,
                    &expired.targets,
                )
            }) {
                retain_retired_key_package_publication(&mut lifecycle, retired_publication);
            }
            lifecycle.authored_event_created_at = Some(
                lifecycle
                    .authored_event_created_at
                    .map(|current| current.max(expired_created_at))
                    .unwrap_or(expired_created_at),
            );
            lifecycle.refresh_at = Some(now);
            lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
            retired.push(expired.key_package);
            lifecycle_changed = true;
        }
        let consumed_refs = lifecycle.consumed_key_package_refs.clone();
        let mut consumed_retained_refs = Vec::new();
        let mut retained = Vec::with_capacity(lifecycle.retained_private_material.len());
        for material in lifecycle.retained_private_material.drain(..) {
            let was_consumed = consumed_refs
                .iter()
                .any(|consumed| consumed == &material.key_package_ref);
            if material.not_after <= now || was_consumed {
                if was_consumed {
                    consumed_retained_refs.push(material.key_package_ref.clone());
                }
                retired.push(material.key_package);
            } else {
                retained.push(material);
            }
        }
        lifecycle.retained_private_material = retained;
        for key_package_ref in consumed_retained_refs {
            mark_retired_key_package_revisions_unusable(&mut lifecycle, &key_package_ref);
            handled_consumed_refs.push(key_package_ref);
        }
        handled_consumed_refs.sort();
        handled_consumed_refs.dedup();
        for key_package_ref in handled_consumed_refs {
            if !key_package_ref_has_live_private_material(&lifecycle, &key_package_ref)
                && !lifecycle.cutover_publication_blocked
            {
                lifecycle.clear_consumed_key_package_ref(&key_package_ref);
            }
        }
        let consumed_refs_before_reconcile = lifecycle.consumed_key_package_refs.clone();
        let last_consumed_before_reconcile = lifecycle.last_consumed_key_package_ref.clone();
        lifecycle.reconcile_consumed_key_package_refs();
        lifecycle_changed |= lifecycle.consumed_key_package_refs != consumed_refs_before_reconcile
            || lifecycle.last_consumed_key_package_ref != last_consumed_before_reconcile;
        let deleted_live_revision_event_ids_before =
            lifecycle.deleted_live_revision_event_ids.clone();
        retain_only_live_deleted_key_package_revision_ids(&mut lifecycle);
        lifecycle_changed |=
            lifecycle.deleted_live_revision_event_ids != deleted_live_revision_event_ids_before;
        let deleted = retired.len();
        if deleted > 0 {
            self.session
                .promote_key_package_lifecycle(&retired, &lifecycle)?;
        } else if lifecycle_changed {
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok(deleted)
    }

    pub fn maintenance_status(&self, group_id: &GroupId) -> AccountResult<GroupMaintenanceStatus> {
        let mut obligations = self.session.maintenance_obligations_for_group(group_id)?;
        if self.maintenance_paused {
            // Pause is intentionally process-local. Project it in status
            // without overwriting the durable phase/deadlines needed by resume.
            for obligation in &mut obligations {
                if !matches!(
                    obligation.phase,
                    MaintenancePhase::Complete | MaintenancePhase::Failed
                ) {
                    obligation.phase = MaintenancePhase::Paused;
                }
            }
        }
        Ok(GroupMaintenanceStatus {
            group_id: group_id.clone(),
            state: self.session.group_maintenance(group_id)?,
            obligations,
            evolutions: self.session.group_evolutions_for_group(group_id)?,
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
        if let Some(existing) = self
            .session
            .maintenance_obligations_for_group(group_id)?
            .into_iter()
            .find(|obligation| {
                !matches!(
                    obligation.phase,
                    MaintenancePhase::Complete | MaintenancePhase::Failed
                )
            })
        {
            return Ok(existing.id);
        }
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
            sampled_jitter_ms: self.maintenance_random.sample_inclusive(
                0,
                cgka_traits::maintenance::POST_JOIN_CONTENTION_JITTER_MAX_MS,
            ),
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
        for mut obligation in self.session.maintenance_obligations_for_group(group_id)? {
            if obligation.trigger == MaintenanceTrigger::PostJoin
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
        for mut obligation in self.session.maintenance_obligations_for_group(group_id)? {
            if obligation.trigger == MaintenanceTrigger::PostJoin
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
        for mut obligation in self.session.maintenance_obligations_for_group(group_id)? {
            if matches!(
                obligation.phase,
                MaintenancePhase::CatchUp
                    | MaintenancePhase::EoseTimeout
                    | MaintenancePhase::Grace
                    | MaintenancePhase::Quiet
                    | MaintenancePhase::Jitter
                    | MaintenancePhase::Overdue
            ) {
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
    pub async fn run_due_maintenance_leased(
        &mut self,
    ) -> AccountResult<LeasedAccountDeviceEffects> {
        let effects = self.run_due_maintenance_recording_visibility().await?;
        self.lease_current_returned_visibility(effects)
    }

    pub async fn run_due_maintenance(&mut self) -> AccountResult<AccountDeviceEffects> {
        let effects = self.run_due_maintenance_recording_visibility().await?;
        self.discard_active_visibility_operation()?;
        Ok(effects)
    }

    async fn run_due_maintenance_recording_visibility(
        &mut self,
    ) -> AccountResult<AccountDeviceEffects> {
        use sha2::{Digest, Sha256};

        self.start_account_visibility_operation(AccountVisibilitySource::Maintenance {
            observed_at: self.wall_clock.now(),
        })?;
        let visibility_handoff = self.begin_session_visibility_handoff()?;
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
            let recovered = self
                .publish_session_effects_in_current_operation(recovered, None)
                .await?;
            self.retain_account_visibility_memory_only(&recovered);
            output.absorb_account_effects(recovered);
        }
        let now = self.wall_clock.now();
        // Fanout of an already-acknowledged KeyPackage is publication recovery,
        // not a new MLS preparation, so it continues while paused. A transport
        // may first supersede a stale signed revision at the same coordinate.
        if self.key_package_has_pending_fanout()?
            && let Err(_error) = self.retry_key_package_fanout().await
        {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "run_due_maintenance",
                error_kind = "key_package_fanout_retry",
                "key package event fanout remains retryable"
            );
        }
        let key_package_due = self.key_package_network_maintenance_due()?;
        let key_package_lifecycle = self.session.key_package_lifecycle()?;
        let key_package_prepared = key_package_lifecycle
            .as_ref()
            .is_some_and(|lifecycle| lifecycle.pending_replacement.is_some());
        let force_current_reauthor = key_package_lifecycle.as_ref().is_some_and(|lifecycle| {
            lifecycle.pending_replacement.is_none()
                && lifecycle.current_key_package.is_some()
                && lifecycle
                    .current_key_package_ref
                    .as_deref()
                    .is_some_and(|key_package_ref| {
                        !lifecycle.key_package_ref_is_consumed(key_package_ref)
                    })
                && lifecycle.authored_signed_event.is_some()
                && (current_key_package_revision_is_deleted(lifecycle)
                    || current_key_package_artifact_precedes_authoring_high_water(lifecycle))
        });
        if key_package_due
            && (!self.maintenance_paused || key_package_prepared || force_current_reauthor)
        {
            let result = if force_current_reauthor {
                self.republish_key_package().await.map(|_| ())
            } else {
                self.publish_fresh_key_package().await.map(|_| ())
            };
            if let Err(error) = result {
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
        }
        if self.retry_retired_key_package_deletions().await.is_err() {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "run_due_maintenance",
                error_kind = "key_package_revision_deletion_retry",
                "superseded key package revision deletion remains retryable"
            );
        }
        let retry_visibility_handoff = self.begin_session_visibility_handoff()?;
        self.start_current_publish_visibility(retry_visibility_handoff);
        let mut retried_fanouts = AccountDeviceEffects::default();
        self.retry_confirmed_transport_fanouts(
            &mut retried_fanouts,
            Some(retry_visibility_handoff),
        )
        .await?;
        self.checkpoint_current_publish_visibility(retry_visibility_handoff, &retried_fanouts)?;
        self.finish_current_visibility_handoff(retry_visibility_handoff);
        self.retain_account_visibility_memory_only(&retried_fanouts);
        output.absorb_account_effects(retried_fanouts);

        // Old groups have no enrollment row and are intentionally excluded.
        let active_obligations = self.session.maintenance_obligations()?;
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
            let has_active = active_obligations.iter().any(|obligation| {
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
            let original_obligation = obligation.clone();
            if obligation
                .operational_target_at
                .is_some_and(|target| target <= now)
            {
                obligation.overdue = true;
            }

            if self.maintenance_paused {
                let has_prepared_evolution = self
                    .session
                    .group_evolutions_for_group(&obligation.group_id)?
                    .into_iter()
                    .any(|evolution| {
                        evolution.phase != GroupEvolutionPhase::SupersededByConvergence
                            && matches!(
                                &evolution.semantic,
                                GroupEvolutionSemantic::SelfUpdate {
                                    obligation_id,
                                    ..
                                } if obligation_id.as_ref() == Some(&obligation.id)
                            )
                            && matches!(
                                evolution.phase,
                                GroupEvolutionPhase::Prepared | GroupEvolutionPhase::Attempting
                            )
                    });
                if !has_prepared_evolution {
                    self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
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
                    self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                    continue;
                }
                MaintenancePhase::EoseTimeout | MaintenancePhase::Grace => {
                    if obligation.grace_until.is_none_or(|deadline| deadline > now) {
                        self.put_maintenance_obligation_if_changed(
                            &original_obligation,
                            &obligation,
                        )?;
                        continue;
                    }
                    obligation.phase = MaintenancePhase::Quiet;
                    obligation.quiet_since = Some(now);
                    self.maintenance_quiet_monotonic
                        .insert(obligation.id.clone(), self.monotonic_clock.elapsed());
                    self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
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
                        self.put_maintenance_obligation_if_changed(
                            &original_obligation,
                            &obligation,
                        )?;
                        continue;
                    }
                    let jitter_secs = obligation.sampled_jitter_ms.saturating_add(999) / 1_000;
                    obligation.phase = MaintenancePhase::Jitter;
                    obligation.not_before = Some(Timestamp(now.0.saturating_add(jitter_secs)));
                    self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                    continue;
                }
                MaintenancePhase::Jitter => {
                    if obligation.not_before.is_none_or(|deadline| deadline > now) {
                        self.put_maintenance_obligation_if_changed(
                            &original_obligation,
                            &obligation,
                        )?;
                        continue;
                    }
                }
                MaintenancePhase::PendingPublication | MaintenancePhase::Retry => {
                    if let Some(evolution) = self
                        .session
                        .group_evolutions_for_group(&obligation.group_id)?
                        .into_iter()
                        .find(|evolution| {
                            evolution.phase != GroupEvolutionPhase::SupersededByConvergence
                                && matches!(
                                    &evolution.semantic,
                                    GroupEvolutionSemantic::SelfUpdate {
                                        obligation_id,
                                        ..
                                    } if obligation_id.as_ref() == Some(&obligation.id)
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
                            let retried = self
                                .publish_session_effects_in_current_operation(retry, None)
                                .await?;
                            let confirmed = retried.pending.iter().any(|resolution| {
                                matches!(
                                    resolution,
                                    PendingResolution::Confirmed { pending: resolved }
                                        if *resolved == pending
                                )
                            });
                            self.retain_account_visibility_memory_only(&retried);
                            output.absorb_account_effects(retried);
                            if confirmed {
                                self.complete_maintenance_obligation(&mut obligation, now)?;
                            } else {
                                obligation.phase = MaintenancePhase::PendingPublication;
                                obligation.attempt_count =
                                    obligation.attempt_count.saturating_add(1);
                                self.put_maintenance_obligation_if_changed(
                                    &original_obligation,
                                    &obligation,
                                )?;
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
                self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                continue;
            }

            let group_id = obligation.group_id.clone();
            let send_visibility_handoff = self.begin_session_visibility_handoff()?;
            match self
                .send_in_current_operation(
                    SendIntent::SelfUpdate {
                        group_id: group_id.clone(),
                    },
                    None,
                )
                .await
            {
                Ok(effects) => {
                    let confirmed = effects.pending.iter().any(|resolution| {
                        matches!(resolution, PendingResolution::Confirmed { .. })
                    });
                    self.retain_account_visibility_memory_only(&effects);
                    output.absorb_account_effects(effects);
                    if confirmed {
                        self.complete_maintenance_obligation(&mut obligation, now)?;
                    } else {
                        obligation.phase = MaintenancePhase::PendingPublication;
                        obligation.attempt_count = obligation.attempt_count.saturating_add(1);
                        self.put_maintenance_obligation_if_changed(
                            &original_obligation,
                            &obligation,
                        )?;
                    }
                }
                Err(error) => {
                    // Maintenance treats one failed self-update as retryable
                    // and continues the outer pass. Preserve any session
                    // events the failed child produced before its later
                    // publication/storage error by copying those journaled
                    // batches into this call's output before the outer
                    // handoff clears its own range.
                    self.append_retained_visibility_since(send_visibility_handoff, &mut output);
                    obligation.phase = MaintenancePhase::Retry;
                    obligation.attempt_count = obligation.attempt_count.saturating_add(1);
                    obligation.last_failure_code = Some(
                        match error {
                            AccountError::Transport(_) => "maintenance_transport_failed",
                            _ => "maintenance_send_failed",
                        }
                        .into(),
                    );
                    self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                }
            }
        }
        self.finish_current_visibility_handoff(visibility_handoff);
        Ok(output)
    }

    fn put_maintenance_obligation_if_changed(
        &self,
        before: &MaintenanceObligation,
        after: &MaintenanceObligation,
    ) -> AccountResult<()> {
        if before != after {
            self.session.put_maintenance_obligation(after)?;
        }
        Ok(())
    }

    pub fn maintenance_run_summary(
        &self,
        effects: &AccountDeviceEffects,
    ) -> AccountResult<cgka_traits::MaintenanceRunSummary> {
        let obligations = self.session.maintenance_obligations()?;
        let lifecycle = self.session.key_package_lifecycle()?;
        let fanouts = self.session.transport_fanouts()?;
        let deferred = obligations
            .iter()
            .filter(|obligation| {
                !matches!(
                    obligation.phase,
                    MaintenancePhase::Complete | MaintenancePhase::Failed
                )
            })
            .count()
            + usize::from(
                lifecycle
                    .as_ref()
                    .is_some_and(|state| state.pending_replacement.is_some()),
            );
        let ambiguous_exposure = fanouts
            .iter()
            .filter(|fanout| fanout.possible_exposure)
            .count()
            + usize::from(lifecycle.as_ref().is_some_and(|state| {
                state.pending_replacement.as_ref().is_some_and(|pending| {
                    pending.last_failure_code.as_deref() == Some("ambiguous_exposure")
                })
            }));
        let failures = effects.failures.len()
            + obligations
                .iter()
                .filter(|obligation| obligation.phase == MaintenancePhase::Failed)
                .count();
        Ok(cgka_traits::MaintenanceRunSummary {
            published: saturating_u32(effects.reports.len()),
            message_ids: effects
                .reports
                .iter()
                .map(|report| report.message_id.clone())
                .collect(),
            deferred: saturating_u32(deferred),
            ambiguous_exposure: saturating_u32(ambiguous_exposure),
            failures: saturating_u32(failures),
        })
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
        let (group_id, effects) = self.create_group_recording_visibility(request).await?;
        self.discard_active_visibility_operation()?;
        Ok((group_id, effects))
    }

    pub async fn create_group_leased(
        &mut self,
        request: CreateGroupRequest,
    ) -> AccountResult<(GroupId, LeasedAccountDeviceEffects)> {
        let (group_id, effects) = self.create_group_recording_visibility(request).await?;
        Ok((group_id, self.lease_current_returned_visibility(effects)?))
    }

    async fn create_group_recording_visibility(
        &mut self,
        request: CreateGroupRequest,
    ) -> AccountResult<(GroupId, AccountDeviceEffects)> {
        self.start_account_visibility_operation(AccountVisibilitySource::Outbound {
            group_id: None,
            observed_at: self.wall_clock.now(),
            action: None,
            action_message_id: None,
        })?;
        let CreateGroupEffects { group_id, effects } = self.session.create_group(request).await?;
        let effects = self
            .publish_session_effects_in_current_operation(effects, None)
            .await?;
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

    pub async fn publish_prepared_session_effects_with_audit_context_leased(
        &mut self,
        effects: SessionEffects,
        context: AuditEventContext,
    ) -> AccountResult<LeasedAccountDeviceEffects> {
        let effects = self
            .publish_session_effects_recording_visibility(effects, Some(context))
            .await?;
        self.lease_current_returned_visibility(effects)
    }

    pub async fn send(&mut self, intent: SendIntent) -> AccountResult<AccountDeviceEffects> {
        let effects = self.send_recording_visibility(intent, None).await?;
        self.discard_active_visibility_operation()?;
        Ok(effects)
    }

    pub async fn send_leased(
        &mut self,
        intent: SendIntent,
    ) -> AccountResult<LeasedAccountDeviceEffects> {
        let effects = self.send_recording_visibility(intent, None).await?;
        self.lease_current_returned_visibility(effects)
    }

    async fn send_recording_visibility(
        &mut self,
        intent: SendIntent,
        context: Option<AuditEventContext>,
    ) -> AccountResult<AccountDeviceEffects> {
        self.start_account_visibility_operation(AccountVisibilitySource::Outbound {
            group_id: send_intent_group_id(&intent),
            observed_at: self.wall_clock.now(),
            action: account_visibility_outbound_action(&intent),
            action_message_id: None,
        })?;
        self.send_in_current_operation(intent, context).await
    }

    pub async fn send_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let effects = self
            .send_recording_visibility(intent, Some(context))
            .await?;
        self.discard_active_visibility_operation()?;
        Ok(effects)
    }

    pub async fn send_with_audit_context_leased(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<LeasedAccountDeviceEffects> {
        let effects = self
            .send_recording_visibility(intent, Some(context))
            .await?;
        self.lease_current_returned_visibility(effects)
    }

    async fn send_in_current_operation(
        &mut self,
        intent: SendIntent,
        context: Option<AuditEventContext>,
    ) -> AccountResult<AccountDeviceEffects> {
        let visibility_handoff = self.begin_session_visibility_handoff()?;
        let outbound_action = account_visibility_outbound_action(&intent);
        let disposition_group = match &intent {
            SendIntent::AppMessage { group_id, .. } => Some(group_id.clone()),
            _ => None,
        };
        let effects = match context.as_ref() {
            Some(context) => {
                self.session
                    .send_with_audit_context(intent, context.clone())
                    .await?
            }
            None => self.session.send(intent).await?,
        };
        if let Some(action) = outbound_action {
            let message_id = outbound_action_message_id(action, &effects).ok_or_else(|| {
                account_visibility_error(
                    "accepted outbound action did not produce its exact publish message",
                )
            })?;
            self.bind_active_outbound_action_message(action, message_id)?;
        }
        let mut output = self
            .publish_session_effects_in_current_operation(effects, context)
            .await?;
        self.retain_account_visibility_memory_only(&output);
        if let Some(group_id) = disposition_group
            && self.post_join_rotation_pending(&group_id)?
        {
            output.maintenance_disposition =
                SendMaintenanceDisposition::PostJoinRotationPendingRetryable;
            self.update_active_visibility_header(output.maintenance_disposition)?;
        }
        self.finish_current_visibility_handoff(visibility_handoff);
        Ok(output)
    }

    /// Accept an outbound commit intent without publishing it.
    ///
    /// A ready group returns a staged commit with extracted Welcome payloads;
    /// unsettled convergence returns the durable queued effects instead. For a
    /// staged commit, the caller must record exact Welcome delivery obligations
    /// before [`Self::publish_prepared_session_effects_with_audit_context`]
    /// exposes the commit on the wire.
    pub async fn confirm_commit_without_publish_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<PreparedSessionSend> {
        if !supports_deferred_commit_publish(&intent) {
            return Err(cgka_traits::EngineError::Other(
                "deferred-publish acceptance requires a commit-producing or durably queued intent"
                    .into(),
            )
            .into());
        }
        let session_effects = self
            .session
            .send_with_audit_context(intent, context)
            .await?;
        classify_prepared_session_send(session_effects)
    }

    /// Roll back a prepared commit before that commit has any transport side
    /// effect, then publish any independent work generated while buffered input
    /// is replayed against the restored group state.
    pub async fn rollback_prepared_session_commit(
        &mut self,
        prepared: PreparedSessionCommit,
    ) -> AccountResult<AccountDeviceEffects> {
        let effects = self
            .rollback_prepared_session_commit_recording_visibility(prepared)
            .await?;
        self.discard_active_visibility_operation()?;
        Ok(effects)
    }

    pub async fn rollback_prepared_session_commit_leased(
        &mut self,
        prepared: PreparedSessionCommit,
    ) -> AccountResult<LeasedAccountDeviceEffects> {
        let effects = self
            .rollback_prepared_session_commit_recording_visibility(prepared)
            .await?;
        self.lease_current_returned_visibility(effects)
    }

    async fn rollback_prepared_session_commit_recording_visibility(
        &mut self,
        prepared: PreparedSessionCommit,
    ) -> AccountResult<AccountDeviceEffects> {
        self.start_account_visibility_operation(AccountVisibilitySource::Outbound {
            group_id: None,
            observed_at: self.wall_clock.now(),
            action: None,
            action_message_id: None,
        })?;
        let visibility_handoff = self.begin_session_visibility_handoff()?;
        self.start_current_publish_visibility(visibility_handoff);
        let (mut prepared_effects, _welcomes, pending) = prepared.into_parts();
        prepared_effects.publish.clear();

        let mut output = AccountDeviceEffects::default();
        let mut queue = VecDeque::new();
        self.absorb_session_effects_retaining_visibility(
            &mut output,
            prepared_effects,
            &mut queue,
            visibility_handoff,
        )?;

        let rollback_effects = self.session.publish_failed(pending).await?;
        output
            .pending
            .push(PendingResolution::RolledBack { pending });
        self.absorb_session_effects_retaining_visibility(
            &mut output,
            rollback_effects,
            &mut queue,
            visibility_handoff,
        )?;
        self.checkpoint_current_publish_visibility(visibility_handoff, &output)?;
        self.publish_queue(&mut output, &mut queue, None, visibility_handoff)
            .await?;
        self.reconcile_confirmed_own_leaf_rotations(&output.events)?;
        self.reconcile_superseded_maintenance(&output.events)?;
        self.finish_current_visibility_handoff(visibility_handoff);
        Ok(output)
    }

    /// Confirm an outbound intent's commit without waiting for Welcome fanout,
    /// or preserve its accepted-pending disposition when convergence queued it.
    ///
    /// Founding creates and existing-group invites persist exact Welcome bytes
    /// before this returns. The caller records those obligations, returns the
    /// canonical mutation, then drives [`Self::publish_welcome_messages_with_audit_context`].
    pub async fn send_confirming_commit_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<(AccountDeviceEffects, Vec<TransportMessage>)> {
        let (effects, welcomes) = self
            .send_confirming_commit_with_audit_context_recording_visibility(intent, context)
            .await?;
        self.discard_active_visibility_operation()?;
        Ok((effects, welcomes))
    }

    pub async fn send_confirming_commit_with_audit_context_leased(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<(LeasedAccountDeviceEffects, Vec<TransportMessage>)> {
        let (effects, welcomes) = self
            .send_confirming_commit_with_audit_context_recording_visibility(intent, context)
            .await?;
        Ok((self.lease_current_returned_visibility(effects)?, welcomes))
    }

    async fn send_confirming_commit_with_audit_context_recording_visibility(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<(AccountDeviceEffects, Vec<TransportMessage>)> {
        self.start_account_visibility_operation(AccountVisibilitySource::Outbound {
            group_id: send_intent_group_id(&intent),
            observed_at: self.wall_clock.now(),
            action: account_visibility_outbound_action(&intent),
            action_message_id: None,
        })?;
        let visibility_handoff = self.begin_session_visibility_handoff()?;
        let disposition_group = match &intent {
            SendIntent::AppMessage { group_id, .. } => Some(group_id.clone()),
            _ => None,
        };
        let prepared = self
            .confirm_commit_without_publish_with_audit_context(intent, context.clone())
            .await?;
        let (session_effects, welcomes) = match prepared {
            PreparedSessionSend::Commit(prepared) => {
                let (effects, welcomes, _pending) = prepared.into_parts();
                (effects, welcomes)
            }
            PreparedSessionSend::Queued(effects) => (effects, Vec::new()),
        };
        let mut output = self
            .publish_session_effects_in_current_operation(session_effects, Some(context))
            .await?;
        self.retain_account_visibility_memory_only(&output);
        if let Some(group_id) = disposition_group
            && self.post_join_rotation_pending(&group_id)?
        {
            output.maintenance_disposition =
                SendMaintenanceDisposition::PostJoinRotationPendingRetryable;
            self.update_active_visibility_header(output.maintenance_disposition)?;
        }
        self.finish_current_visibility_handoff(visibility_handoff);
        Ok((output, welcomes))
    }

    /// Publish previously deferred Welcome obligations with bounded concurrency.
    pub async fn publish_welcome_messages_with_audit_context(
        &mut self,
        welcomes: Vec<TransportMessage>,
        group_id: Option<GroupId>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        self.publish_welcome_fanout(welcomes, group_id, &mut output, Some(context), false, None)
            .await?;
        Ok(output)
    }

    /// Retry retained Welcome obligations immediately with the shared bounded
    /// fanout, bypassing the automatic backoff for this explicit startup pass.
    pub async fn retry_welcome_messages_with_audit_context(
        &mut self,
        welcomes: Vec<TransportMessage>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        self.publish_welcome_fanout(welcomes, None, &mut output, Some(context), true, None)
            .await?;
        Ok(output)
    }

    /// Prepare a startup Welcome retry whose relay I/O can run independently
    /// from the serialized account worker.
    ///
    /// Preparation persists the exact event/endpoint attempts and reserves
    /// their message ids in-memory before this returns. The returned task owns
    /// only a cloned transport adapter; callers must pass its completion to
    /// [`Self::finish_welcome_publish_task`] or release its reservation with
    /// [`Self::abandon_welcome_publish_task`].
    #[doc(hidden)]
    pub fn prepare_welcome_retry_task_with_audit_context(
        &mut self,
        welcomes: Vec<TransportMessage>,
        context: AuditEventContext,
    ) -> AccountResult<PreparedWelcomePublishTask>
    where
        A: Clone + 'static,
    {
        let prepared = self.prepare_welcome_publish(welcomes, None, Some(context), true)?;
        let message_ids = prepared.network_message_ids();
        self.detached_welcome_publishes
            .extend(message_ids.iter().cloned());
        Ok(PreparedWelcomePublishTask {
            adapter: Arc::new(self.adapter.clone()),
            prepared,
            message_ids,
        })
    }

    /// Reconcile every relay result from a detached Welcome publish in input
    /// order, then release its in-memory exact-event reservations.
    #[doc(hidden)]
    pub async fn finish_welcome_publish_task(
        &mut self,
        task: CompletedWelcomePublishTask,
    ) -> AccountResult<AccountDeviceEffects> {
        let CompletedWelcomePublishTask {
            completed,
            message_ids,
        } = task;
        let mut output = AccountDeviceEffects::default();
        let result = self
            .finish_welcome_publish(completed, &mut output, None)
            .await;
        self.abandon_welcome_publish_task(&message_ids);
        result.map(|()| output)
    }

    /// Release the in-memory reservation after a detached relay task is
    /// cancelled or panics. Durable fanout remains retryable.
    #[doc(hidden)]
    pub fn abandon_welcome_publish_task(&mut self, message_ids: &[cgka_traits::MessageId]) {
        for message_id in message_ids {
            self.detached_welcome_publishes.remove(message_id);
        }
    }

    pub async fn queue_app_message_with_audit_context(
        &mut self,
        group_id: GroupId,
        payload: Vec<u8>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let effects = self
            .queue_app_message_with_audit_context_recording_visibility(group_id, payload, context)
            .await?;
        self.discard_active_visibility_operation()?;
        Ok(effects)
    }

    pub async fn queue_app_message_with_audit_context_leased(
        &mut self,
        group_id: GroupId,
        payload: Vec<u8>,
        context: AuditEventContext,
    ) -> AccountResult<LeasedAccountDeviceEffects> {
        let effects = self
            .queue_app_message_with_audit_context_recording_visibility(group_id, payload, context)
            .await?;
        self.lease_current_returned_visibility(effects)
    }

    async fn queue_app_message_with_audit_context_recording_visibility(
        &mut self,
        group_id: GroupId,
        payload: Vec<u8>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        self.start_account_visibility_operation(AccountVisibilitySource::Outbound {
            group_id: Some(group_id.clone()),
            observed_at: self.wall_clock.now(),
            action: None,
            action_message_id: None,
        })?;
        let visibility_handoff = self.begin_session_visibility_handoff()?;
        let effects = self
            .session
            .queue_app_message_with_audit_context(group_id.clone(), payload, context.clone())
            .await?;
        let mut output = self
            .publish_session_effects_in_current_operation(effects, Some(context))
            .await?;
        self.retain_account_visibility_memory_only(&output);
        if self.post_join_rotation_pending(&group_id)? {
            output.maintenance_disposition =
                SendMaintenanceDisposition::PostJoinRotationPendingRetryable;
            self.update_active_visibility_header(output.maintenance_disposition)?;
        }
        self.finish_current_visibility_handoff(visibility_handoff);
        Ok(output)
    }

    fn post_join_rotation_pending(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self
            .session
            .maintenance_obligations_for_group(group_id)?
            .into_iter()
            .any(|obligation| {
                obligation.trigger == MaintenanceTrigger::PostJoin
                    && !matches!(
                        obligation.phase,
                        MaintenancePhase::Complete | MaintenancePhase::Failed
                    )
            }))
    }

    pub async fn advance_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<AccountDeviceEffects> {
        let effects = self
            .advance_convergence_recording_visibility(group_id)
            .await?;
        self.discard_active_visibility_operation()?;
        Ok(effects)
    }

    async fn advance_convergence_recording_visibility(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<AccountDeviceEffects> {
        self.start_account_visibility_operation(AccountVisibilitySource::Convergence {
            group_id: group_id.clone(),
            observed_at: self.wall_clock.now(),
        })?;
        let effects = self.session.advance_convergence(group_id).await?;
        self.publish_session_effects_in_current_operation(effects, None)
            .await
    }

    pub async fn advance_convergence_leased(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<LeasedAccountDeviceEffects> {
        let effects = self
            .advance_convergence_recording_visibility(group_id)
            .await?;
        self.lease_current_returned_visibility(effects)
    }

    pub fn has_pending_convergence_inputs(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.has_pending_convergence_inputs(group_id)?)
    }

    pub fn has_queued_outbound_intents(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.has_queued_outbound_intents(group_id)?)
    }

    pub fn prepare_convergence_cutoff_delay_ms(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<Option<u64>> {
        Ok(self.session.prepare_convergence_cutoff_delay_ms(group_id)?)
    }

    pub fn deferred_peel_cutoff_delay_ms(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<Option<u64>> {
        Ok(self.session.deferred_peel_cutoff_delay_ms(group_id)?)
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
        let (effects, recovered_operation_ids) = self.drain_recording_visibility().await?;
        self.discard_visibility_operations(&recovered_operation_ids)?;
        Ok(effects)
    }

    async fn drain_recording_visibility(
        &mut self,
    ) -> AccountResult<(AccountDeviceEffects, Vec<[u8; 16]>)> {
        self.start_account_visibility_operation(AccountVisibilitySource::Drain {
            observed_at: self.wall_clock.now(),
        })?;
        let effects = self.session.drain();
        let (mut output, current_visibility_batch) = self
            .publish_session_effects_retaining_visibility(effects, None)
            .await?;
        let resumed = self.resume_outbound_fanouts_in_current_operation().await?;
        output.extend(resumed);
        let recovered_operation_ids =
            self.finish_drain_visibility_handoff(current_visibility_batch, &mut output);
        Ok((output, recovered_operation_ids))
    }

    pub async fn drain_leased(&mut self) -> AccountResult<LeasedAccountDeviceEffects> {
        let (effects, _) = self.drain_recording_visibility().await?;
        self.lease_current_returned_visibility(effects)
    }

    pub async fn ingest_delivery(
        &mut self,
        delivery: TransportDelivery,
    ) -> AccountResult<AccountIngestEffects> {
        let effects = self.ingest_delivery_recording_visibility(delivery).await?;
        self.discard_active_visibility_operation()?;
        Ok(effects)
    }

    async fn ingest_delivery_recording_visibility(
        &mut self,
        delivery: TransportDelivery,
    ) -> AccountResult<AccountIngestEffects> {
        if delivery.account_id != self.session.self_id() {
            return Err(AccountError::WrongAccountDelivery);
        }
        let source_delivery = delivery.clone();
        let IngestEffects {
            outcome,
            left_object_unpersisted,
            effects,
            valid_proposal_groups,
        } = self.session.ingest_delivery(delivery).await?;
        self.start_account_visibility_operation(AccountVisibilitySource::Inbound {
            delivery: source_delivery,
            outcome: outcome.clone(),
            observed_at: self.wall_clock.now(),
        })?;
        let (effects, current_visibility_batch) = self
            .publish_session_effects_retaining_visibility(effects, None)
            .await?;
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
        self.finish_current_visibility_handoff(current_visibility_batch);
        Ok(AccountIngestEffects {
            outcome,
            left_object_unpersisted,
            effects,
        })
    }

    pub async fn ingest_delivery_leased(
        &mut self,
        delivery: TransportDelivery,
    ) -> AccountResult<LeasedAccountIngestEffects> {
        let AccountIngestEffects {
            outcome,
            left_object_unpersisted,
            effects,
        } = self.ingest_delivery_recording_visibility(delivery).await?;
        let leased = self.lease_current_returned_visibility(effects)?;
        Ok(LeasedAccountIngestEffects {
            outcome,
            left_object_unpersisted,
            effects: leased.effects,
            batches: leased.batches,
            lease: leased.lease,
            current_operation_id: leased.current_operation_id,
        })
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
        let output = self
            .publish_session_effects_recording_visibility(effects, context)
            .await?;
        self.discard_active_visibility_operation()?;
        Ok(output)
    }

    async fn publish_session_effects_recording_visibility(
        &mut self,
        effects: SessionEffects,
        context: Option<AuditEventContext>,
    ) -> AccountResult<AccountDeviceEffects> {
        self.start_account_visibility_operation(AccountVisibilitySource::Outbound {
            group_id: None,
            observed_at: self.wall_clock.now(),
            action: None,
            action_message_id: None,
        })?;
        self.publish_session_effects_in_current_operation(effects, context)
            .await
    }

    async fn publish_session_effects_in_current_operation(
        &mut self,
        effects: SessionEffects,
        context: Option<AuditEventContext>,
    ) -> AccountResult<AccountDeviceEffects> {
        let (output, current_visibility_batch) = self
            .publish_session_effects_retaining_visibility(effects, context)
            .await?;
        self.finish_current_visibility_handoff(current_visibility_batch);
        Ok(output)
    }

    /// Publish one session batch while leaving its caller-visible vectors in
    /// runtime-owned memory until the outermost account operation is ready to
    /// return. This is the cancellation boundary shared by `drain`, ingest,
    /// and direct session-effect publication.
    async fn publish_session_effects_retaining_visibility(
        &mut self,
        effects: SessionEffects,
        context: Option<AuditEventContext>,
    ) -> AccountResult<(AccountDeviceEffects, SessionVisibilityHandoff)> {
        let visibility_handoff = self.begin_session_visibility_handoff()?;
        self.start_current_publish_visibility(visibility_handoff);
        let mut output = AccountDeviceEffects::default();
        let mut queue = VecDeque::new();
        self.absorb_session_effects_retaining_visibility(
            &mut output,
            effects,
            &mut queue,
            visibility_handoff,
        )?;
        self.publish_queue(&mut output, &mut queue, context, visibility_handoff)
            .await?;
        self.reconcile_confirmed_own_leaf_rotations(&output.events)?;
        self.reconcile_superseded_maintenance(&output.events)?;
        Ok((output, visibility_handoff))
    }

    fn start_account_visibility_operation(
        &mut self,
        source: AccountVisibilitySource,
    ) -> AccountResult<()> {
        self.ensure_visibility_journal_loaded()?;
        let mut operation_id = [0_u8; 16];
        loop {
            OsRng.fill_bytes(&mut operation_id);
            if !self
                .durable_visibility_operations
                .contains_key(&operation_id)
            {
                break;
            }
        }
        let header = StoredAccountVisibilityRecordV1 {
            version: ACCOUNT_VISIBILITY_RECORD_VERSION,
            source: source.clone(),
            payload: StoredAccountVisibilityPayloadV1::Header {
                maintenance_disposition: SendMaintenanceDisposition::Ready,
            },
        };
        self.upsert_visibility_record(&operation_id, 0, &header)?;
        self.durable_visibility_operations.insert(
            operation_id,
            DurableVisibilityOperation {
                source,
                next_event_ordinal: 1,
                session_control: StoredSessionControlV1::default(),
                non_session_fragments: BTreeMap::new(),
            },
        );
        self.active_visibility_operation = Some(operation_id);
        Ok(())
    }

    fn begin_session_visibility_handoff(&mut self) -> AccountResult<SessionVisibilityHandoff> {
        let operation_id = self
            .active_visibility_operation
            .ok_or_else(|| account_visibility_error("visibility operation was not started"))?;
        let fragment_id = self.next_visibility_fragment_id;
        self.next_visibility_fragment_id = self.next_visibility_fragment_id.wrapping_add(1).max(1);
        self.durable_visibility_operations
            .get_mut(&operation_id)
            .expect("active visibility operation must have durable state")
            .non_session_fragments
            .insert(fragment_id, AccountDeviceEffects::default());
        Ok(SessionVisibilityHandoff {
            retained_batch_count: self.retained_session_visibility.len(),
            operation_id,
            fragment_id,
        })
    }

    /// Reserve the first batch in a publish handoff for a replaceable snapshot
    /// of every non-session field accumulated by completed publish work. The
    /// following session-event batches remain append-only and preserve their
    /// own engine order.
    fn start_current_publish_visibility(&mut self, handoff: SessionVisibilityHandoff) {
        debug_assert_eq!(
            self.retained_session_visibility.len(),
            handoff.retained_batch_count
        );
        self.retained_session_visibility
            .push_back(RetainedSessionVisibilityBatch {
                operation_id: Some(handoff.operation_id),
                effects: AccountDeviceEffects::default(),
            });
    }

    /// Replace the current publish handoff's non-session snapshot before the
    /// queue crosses its next await. Replacing one slot instead of appending
    /// cumulative snapshots prevents replay duplicates.
    fn checkpoint_current_publish_visibility(
        &mut self,
        handoff: SessionVisibilityHandoff,
        output: &AccountDeviceEffects,
    ) -> AccountResult<()> {
        let Some(batch) = self
            .retained_session_visibility
            .get_mut(handoff.retained_batch_count)
        else {
            debug_assert!(false, "publish visibility slot must remain live");
            return Err(account_visibility_error(
                "publish visibility slot did not remain live",
            ));
        };
        batch.effects = output.non_session_visibility_clone();
        let operation = self
            .durable_visibility_operations
            .get_mut(&handoff.operation_id)
            .ok_or_else(|| account_visibility_error("visibility operation state is missing"))?;
        operation
            .non_session_fragments
            .insert(handoff.fragment_id, output.non_session_visibility_clone());
        let source = operation.source.clone();
        let mut cumulative = AccountDeviceEffects::default();
        for fragment in operation.non_session_fragments.values() {
            cumulative.extend(fragment.non_session_visibility_clone());
        }
        let record = StoredAccountVisibilityRecordV1 {
            version: ACCOUNT_VISIBILITY_RECORD_VERSION,
            source,
            payload: StoredAccountVisibilityPayloadV1::NonSession(
                StoredNonSessionEffectsV1::from_effects(&cumulative),
            ),
        };
        self.upsert_visibility_record(
            &handoff.operation_id,
            ACCOUNT_VISIBILITY_NON_SESSION_ORDINAL,
            &record,
        )?;
        Ok(())
    }

    fn checkpoint_optional_publish_visibility(
        &mut self,
        handoff: Option<SessionVisibilityHandoff>,
        output: &AccountDeviceEffects,
    ) -> AccountResult<()> {
        if let Some(handoff) = handoff {
            self.checkpoint_current_publish_visibility(handoff, output)?;
        }
        Ok(())
    }

    fn retain_session_visibility(
        &mut self,
        handoff: SessionVisibilityHandoff,
        effects: &SessionEffects,
    ) -> AccountResult<()> {
        if effects.events.is_empty()
            && effects.queued.is_empty()
            && effects.pending_convergence.is_empty()
        {
            return Ok(());
        }

        let (source, first_event_ordinal, mut control) = {
            let operation = self
                .durable_visibility_operations
                .get(&handoff.operation_id)
                .ok_or_else(|| account_visibility_error("visibility operation state is missing"))?;
            (
                operation.source.clone(),
                operation.next_event_ordinal,
                operation.session_control.clone(),
            )
        };
        let mut records = Vec::with_capacity(effects.events.len().saturating_add(1));
        for (index, event) in effects.events.iter().enumerate() {
            let ordinal = first_event_ordinal.saturating_add(index as u64);
            let record = StoredAccountVisibilityRecordV1 {
                version: ACCOUNT_VISIBILITY_RECORD_VERSION,
                source: source.clone(),
                payload: StoredAccountVisibilityPayloadV1::Event {
                    event: event.clone(),
                    engine_outbox_provenance: matches!(
                        event,
                        GroupEvent::MessageReceived { .. } | GroupEvent::GroupJoined { .. }
                    ),
                },
            };
            records.push(self.encode_visibility_upsert(&handoff.operation_id, ordinal, &record)?);
        }

        if !effects.queued.is_empty() || !effects.pending_convergence.is_empty() {
            control
                .queued
                .extend(effects.queued.iter().map(|queued| StoredQueuedIntentRefV1 {
                    group_id: queued.group_id.clone(),
                    intent_id: queued.intent_id.clone(),
                }));
            control
                .pending_convergence
                .extend(effects.pending_convergence.iter().cloned());
            let record = StoredAccountVisibilityRecordV1 {
                version: ACCOUNT_VISIBILITY_RECORD_VERSION,
                source: source.clone(),
                payload: StoredAccountVisibilityPayloadV1::SessionControl(control.clone()),
            };
            records.push(self.encode_visibility_upsert(
                &handoff.operation_id,
                ACCOUNT_VISIBILITY_CONTROL_ORDINAL,
                &record,
            )?);
        }

        self.visibility_storage
            .upsert_account_visibility_journal_records(&records)
            .map_err(|error| AccountError::Session(SessionError::Storage(error)))?;
        let operation = self
            .durable_visibility_operations
            .get_mut(&handoff.operation_id)
            .expect("visibility operation remains live after atomic persistence");
        operation.next_event_ordinal = first_event_ordinal
            .saturating_add(u64::try_from(effects.events.len()).unwrap_or(u64::MAX));
        operation.session_control = control;

        self.retained_session_visibility
            .push_back(RetainedSessionVisibilityBatch {
                operation_id: Some(handoff.operation_id),
                effects: AccountDeviceEffects {
                    events: effects.events.clone(),
                    queued: effects.queued.clone(),
                    pending_convergence: effects.pending_convergence.clone(),
                    ..AccountDeviceEffects::default()
                },
            });
        Ok(())
    }

    fn retain_account_visibility_memory_only(&mut self, effects: &AccountDeviceEffects) {
        if effects == &AccountDeviceEffects::default() {
            return;
        }

        self.retained_session_visibility
            .push_back(RetainedSessionVisibilityBatch {
                operation_id: self.active_visibility_operation,
                effects: effects.clone(),
            });
    }

    fn absorb_session_effects_retaining_visibility(
        &mut self,
        output: &mut AccountDeviceEffects,
        mut effects: SessionEffects,
        queue: &mut VecDeque<PublishWork>,
        handoff: SessionVisibilityHandoff,
    ) -> AccountResult<()> {
        self.suppress_hydrated_visibility_duplicates(&mut effects);
        self.retain_session_visibility(handoff, &effects)?;
        output.absorb_session_effects(effects, queue);
        Ok(())
    }

    fn absorb_session_effects_retaining_optional_visibility(
        &mut self,
        output: &mut AccountDeviceEffects,
        mut effects: SessionEffects,
        queue: &mut VecDeque<PublishWork>,
        handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<()> {
        self.suppress_hydrated_visibility_duplicates(&mut effects);
        if let Some(handoff) = handoff {
            self.retain_session_visibility(handoff, &effects)?;
        }
        output.absorb_session_effects(effects, queue);
        Ok(())
    }

    fn suppress_hydrated_visibility_duplicates(&mut self, effects: &mut SessionEffects) {
        effects.events.retain(|event| {
            let Some(index) = self
                .hydrated_visibility_suppressions
                .iter()
                .position(|retained| retained == event)
            else {
                return true;
            };
            self.hydrated_visibility_suppressions.remove(index);
            false
        });
    }

    /// Every batch created by this operation is already present in its
    /// `output`; only remove those journal copies after the operation's final
    /// fallible step has finished.
    fn finish_current_visibility_handoff(&mut self, handoff: SessionVisibilityHandoff) {
        self.retained_session_visibility
            .truncate(handoff.retained_batch_count);
    }

    fn append_retained_visibility_since(
        &self,
        handoff: SessionVisibilityHandoff,
        output: &mut AccountDeviceEffects,
    ) {
        for batch in self
            .retained_session_visibility
            .iter()
            .skip(handoff.retained_batch_count)
        {
            output.extend(batch.effects.clone());
        }
    }

    fn take_retained_visibility(&mut self) -> AccountDeviceEffects {
        let mut recovered = AccountDeviceEffects::default();
        for batch in self.retained_session_visibility.drain(..) {
            recovered.extend(batch.effects);
        }
        recovered
    }

    /// A no-inbound drain is the replay surface for batches stranded by an
    /// earlier failed or cancelled operation. Exclude the current batch (it is
    /// already at the front of `output`) and prepend every older batch in its
    /// original order. No await may follow this handoff.
    ///
    /// Returns the cancelled operations whose effects were actually prepended
    /// so a legacy `drain` can ACK them in the same transaction as the current
    /// operation.
    fn finish_drain_visibility_handoff(
        &mut self,
        handoff: SessionVisibilityHandoff,
        output: &mut AccountDeviceEffects,
    ) -> Vec<[u8; 16]> {
        self.finish_current_visibility_handoff(handoff);
        let mut recovered_operation_ids = Vec::new();
        let mut seen = HashSet::new();
        for batch in &self.retained_session_visibility {
            if let Some(operation_id) = batch.operation_id
                && seen.insert(operation_id)
            {
                recovered_operation_ids.push(operation_id);
            }
        }
        if self.retained_session_visibility.is_empty() {
            return recovered_operation_ids;
        }

        let mut recovered = self.take_retained_visibility();
        recovered.extend(std::mem::take(output));
        *output = recovered;
        recovered_operation_ids
    }

    fn lease_current_returned_visibility(
        &mut self,
        effects: AccountDeviceEffects,
    ) -> AccountResult<LeasedAccountDeviceEffects> {
        let operation_id = self.active_visibility_operation.ok_or_else(|| {
            account_visibility_error("leased visibility operation was not started")
        })?;
        self.update_active_visibility_header(effects.maintenance_disposition)?;
        self.lease_returned_visibility(effects, Some(operation_id))
    }

    fn lease_returned_visibility(
        &mut self,
        effects: AccountDeviceEffects,
        current_operation_id: Option<[u8; 16]>,
    ) -> AccountResult<LeasedAccountDeviceEffects> {
        let batches = self.load_visibility_batches()?;

        let lease = AccountVisibilityLease(self.next_visibility_lease_id);
        self.next_visibility_lease_id = self.next_visibility_lease_id.wrapping_add(1).max(1);
        self.returned_visibility_lease = Some(RetainedReturnedVisibilityLease {
            lease,
            batch_ids: batches.iter().map(|batch| batch.batch_id.clone()).collect(),
        });
        Ok(LeasedAccountDeviceEffects {
            effects,
            batches,
            lease,
            current_operation_id: current_operation_id.map(|operation_id| operation_id.to_vec()),
        })
    }

    /// Return durable visibility left by an earlier cancelled/dropped runtime
    /// before starting any new transport work.
    pub fn replay_visibility_leased(
        &mut self,
    ) -> AccountResult<Option<LeasedAccountDeviceEffects>> {
        if self
            .visibility_storage
            .load_account_visibility_journal()
            .map_err(|error| AccountError::Session(SessionError::Storage(error)))?
            .is_empty()
        {
            return Ok(None);
        }
        self.lease_returned_visibility(AccountDeviceEffects::default(), None)
            .map(Some)
    }

    /// Stable row ids for deletion in the app's projection transaction.
    pub fn visibility_lease_batch_ids(
        &self,
        lease: AccountVisibilityLease,
    ) -> Option<Vec<Vec<u8>>> {
        self.returned_visibility_lease
            .as_ref()
            .filter(|retained| retained.lease == lease)
            .map(|retained| retained.batch_ids.clone())
    }

    /// Acknowledge that the app has durably staged every effect carried by
    /// `lease`. Returns `false` for an already-acknowledged or superseded
    /// generation and never clears a newer handoff.
    pub fn acknowledge_visibility_lease(&mut self, lease: AccountVisibilityLease) -> bool {
        let Some(batch_ids) = self.visibility_lease_batch_ids(lease) else {
            return false;
        };
        self.delete_visibility_batches_acking_engine_outbox(&batch_ids)
            .is_ok()
            && self
                .forget_durably_acknowledged_visibility_lease(lease)
                .unwrap_or(false)
    }

    /// Delete visibility rows and ACK any engine application-event ids they
    /// carry in one storage transaction. Legacy `drain` / `ingest_delivery`
    /// transfer ownership synchronously; without this ACK a returned
    /// `MessageReceived` / `GroupJoined` is hydrated back into the engine
    /// outbox on every reopen.
    fn delete_visibility_batches_acking_engine_outbox(
        &self,
        batch_ids: &[Vec<u8>],
    ) -> AccountResult<()> {
        if batch_ids.is_empty() {
            return Ok(());
        }
        let batches = self.load_visibility_batches()?;
        let engine_outbox_ids = batches
            .iter()
            .filter(|batch| batch_ids.contains(&batch.batch_id))
            .filter(|batch| {
                matches!(
                    batch.kind,
                    AccountVisibilityRecordKind::Event {
                        engine_outbox_provenance: true
                    }
                )
            })
            .flat_map(|batch| batch.effects.events.iter())
            .filter_map(engine_outbox_event_id)
            .collect::<Vec<_>>();
        self.visibility_storage
            .with_transaction(|storage| {
                storage.delete_pending_application_events(&engine_outbox_ids)?;
                storage.delete_account_visibility_journal_batches(batch_ids)?;
                Ok::<_, StorageError>(())
            })
            .map_err(|error| AccountError::Session(SessionError::Storage(error)))?;
        Ok(())
    }

    /// Forget a lease only after its rows were durably deleted, normally inside
    /// the app's projection transaction through `SqliteAccountStorage`.
    pub fn forget_durably_acknowledged_visibility_lease(
        &mut self,
        lease: AccountVisibilityLease,
    ) -> AccountResult<bool> {
        let Some(batch_ids) = self.visibility_lease_batch_ids(lease) else {
            return Ok(false);
        };
        self.forget_durably_acknowledged_visibility_batches(lease, &batch_ids)
    }

    /// Advance one lease after the app atomically deleted a projected subset
    /// of its stable row ids. Returns `true` only when the lease is now fully
    /// acknowledged; a projected prefix leaves the remaining ids leased.
    ///
    /// This boundary is deliberately storage-free. The caller invokes it only
    /// after its projection transaction has committed the row deletions, and a
    /// terminal close is allowed to close SQLite immediately after that
    /// commit. Re-reading the journal here would turn harmless in-memory lease
    /// cleanup into a post-commit failure window where both durable copies are
    /// gone but the app cannot promote its one-shot visibility summary.
    pub fn forget_durably_acknowledged_visibility_batches(
        &mut self,
        lease: AccountVisibilityLease,
        acknowledged_batch_ids: &[Vec<u8>],
    ) -> AccountResult<bool> {
        let Some(retained) = self.returned_visibility_lease.as_ref() else {
            return Ok(false);
        };
        if retained.lease != lease
            || acknowledged_batch_ids
                .iter()
                .any(|batch_id| !retained.batch_ids.contains(batch_id))
        {
            return Ok(false);
        }
        let retained = self
            .returned_visibility_lease
            .as_mut()
            .expect("matching lease remains live");
        retained
            .batch_ids
            .retain(|batch_id| !acknowledged_batch_ids.contains(batch_id));
        if !retained.batch_ids.is_empty() {
            return Ok(false);
        }
        self.returned_visibility_lease = None;
        self.retained_session_visibility.clear();
        // A matching lease is always the newest generation and snapshots every
        // journal row then present. `&mut self` prevents a new account
        // operation from adding rows between its return and this advancement;
        // any later operation would instead have installed a newer lease and
        // made the generation mismatch above return `false`.
        self.durable_visibility_operations.clear();
        Ok(true)
    }

    fn ensure_visibility_journal_loaded(&self) -> AccountResult<()> {
        match &self.visibility_load_error {
            Some(error) => Err(account_visibility_error(format!(
                "load account visibility journal: {error}"
            ))),
            None => Ok(()),
        }
    }

    /// Compatibility boundary for legacy methods that return effects without
    /// an explicit projection lease. A successful legacy call has transferred
    /// ownership synchronously to its caller, so only that operation's rows
    /// are removed; older failed/cancelled operations remain replayable.
    fn discard_active_visibility_operation(&mut self) -> AccountResult<()> {
        self.discard_visibility_operations(&[])
    }

    /// ACK the current operation plus every recovered operation whose effects
    /// were actually handed off, in one storage transaction. Used by legacy
    /// `drain`, which prepends cancelled batches and must not leave their
    /// journal rows and engine outbox ids live across reopen.
    fn discard_visibility_operations(
        &mut self,
        recovered_operation_ids: &[[u8; 16]],
    ) -> AccountResult<()> {
        let mut operation_ids = recovered_operation_ids.to_vec();
        if let Some(operation_id) = self.active_visibility_operation.take() {
            operation_ids.push(operation_id);
        }
        if operation_ids.is_empty() {
            return Ok(());
        }
        let batch_ids = self
            .visibility_storage
            .load_account_visibility_journal()
            .map_err(|error| AccountError::Session(SessionError::Storage(error)))?
            .into_iter()
            .filter(|row| {
                operation_ids
                    .iter()
                    .any(|operation_id| row.operation_id.as_slice() == operation_id)
            })
            .map(|row| row.batch_id)
            .collect::<Vec<_>>();
        self.delete_visibility_batches_acking_engine_outbox(&batch_ids)?;
        for operation_id in operation_ids {
            self.durable_visibility_operations.remove(&operation_id);
        }
        Ok(())
    }

    fn upsert_visibility_record(
        &self,
        operation_id: &[u8; 16],
        ordinal: u64,
        record: &StoredAccountVisibilityRecordV1,
    ) -> AccountResult<u64> {
        let upsert = self.encode_visibility_upsert(operation_id, ordinal, record)?;
        self.visibility_storage
            .upsert_account_visibility_journal(
                &upsert.operation_id,
                upsert.ordinal,
                &upsert.batch_id,
                &upsert.record,
            )
            .map_err(|error| AccountError::Session(SessionError::Storage(error)))
    }

    fn encode_visibility_upsert(
        &self,
        operation_id: &[u8; 16],
        ordinal: u64,
        record: &StoredAccountVisibilityRecordV1,
    ) -> AccountResult<AccountVisibilityJournalUpsert> {
        let encoded = serde_json::to_vec(record).map_err(|error| {
            account_visibility_error(format!("serialize account visibility record: {error}"))
        })?;
        Ok(AccountVisibilityJournalUpsert {
            operation_id: operation_id.to_vec(),
            ordinal,
            batch_id: account_visibility_batch_id(operation_id, ordinal),
            record: encoded,
        })
    }

    fn update_active_visibility_header(
        &self,
        maintenance_disposition: SendMaintenanceDisposition,
    ) -> AccountResult<()> {
        let Some(operation_id) = self.active_visibility_operation else {
            return Ok(());
        };
        let source = self
            .durable_visibility_operations
            .get(&operation_id)
            .ok_or_else(|| account_visibility_error("visibility operation state is missing"))?
            .source
            .clone();
        let record = StoredAccountVisibilityRecordV1 {
            version: ACCOUNT_VISIBILITY_RECORD_VERSION,
            source,
            payload: StoredAccountVisibilityPayloadV1::Header {
                maintenance_disposition,
            },
        };
        self.upsert_visibility_record(&operation_id, 0, &record)?;
        Ok(())
    }

    fn bind_active_outbound_action_message(
        &mut self,
        action: AccountVisibilityOutboundAction,
        message_id: MessageId,
    ) -> AccountResult<()> {
        let operation_id = self.active_visibility_operation.ok_or_else(|| {
            account_visibility_error("bound outbound action has no visibility operation")
        })?;
        let operation = self
            .durable_visibility_operations
            .get_mut(&operation_id)
            .ok_or_else(|| account_visibility_error("visibility operation state is missing"))?;
        match &mut operation.source {
            AccountVisibilitySource::Outbound {
                action: initiating_action,
                action_message_id,
                ..
            } if *initiating_action == Some(action) => {
                *action_message_id = Some(message_id);
            }
            _ => {
                return Err(account_visibility_error(
                    "bound outbound action does not match its visibility source",
                ));
            }
        }
        // Session acceptance has already atomically installed the exact sent
        // SelfRemove and LeaveRequest. Rewrite the pre-acceptance Header before
        // any relay await; a crash in the narrow interval between those writes
        // is repaired from the request's paired message id below.
        self.update_active_visibility_header(SendMaintenanceDisposition::Ready)
    }

    fn load_visibility_batches(&self) -> AccountResult<Vec<AccountVisibilityBatch>> {
        self.ensure_visibility_journal_loaded()?;
        let mut batches = self
            .visibility_storage
            .load_account_visibility_journal()
            .map_err(|error| AccountError::Session(SessionError::Storage(error)))?
            .into_iter()
            .map(decode_account_visibility_row)
            .collect::<AccountResult<Vec<_>>>()?;
        struct LeaveHeaderRef {
            index: usize,
            sequence: u64,
            operation_id: Vec<u8>,
            bound: Option<MessageId>,
        }
        let mut by_group = HashMap::<GroupId, Vec<LeaveHeaderRef>>::new();
        for (index, batch) in batches.iter().enumerate() {
            let AccountVisibilitySource::Outbound {
                group_id: Some(group_id),
                action: Some(AccountVisibilityOutboundAction::Leave),
                action_message_id,
                ..
            } = &batch.source
            else {
                continue;
            };
            by_group
                .entry(group_id.clone())
                .or_default()
                .push(LeaveHeaderRef {
                    index,
                    sequence: batch.sequence,
                    operation_id: batch.operation_id.clone(),
                    bound: action_message_id.clone(),
                });
        }
        let mut repaired = Vec::new();
        for (group_id, mut headers) in by_group {
            headers.sort_by_key(|header| header.sequence);
            let current_id = self
                .visibility_storage
                .leave_request(&group_id)
                .map_err(|error| AccountError::Session(SessionError::Storage(error)))?
                .and_then(|request| request.last_proposed_message_id);
            let Some(current_id) = current_id else {
                continue;
            };
            // One semantic owner per group. Prefer a Header already bound to
            // the live Leave id, else the newest previously bound Header so
            // M1 follows to M2, else the newest unbound pre-acceptance Header.
            // A later LeaveAlreadyRequested Header must not also inherit.
            let owner_operation_id = headers
                .iter()
                .find(|header| header.bound.as_ref() == Some(&current_id))
                .map(|header| header.operation_id.clone())
                .or_else(|| {
                    headers
                        .iter()
                        .rev()
                        .find(|header| header.bound.is_some())
                        .map(|header| header.operation_id.clone())
                })
                .or_else(|| headers.last().map(|header| header.operation_id.clone()));
            let Some(owner_operation_id) = owner_operation_id else {
                continue;
            };
            for header in &headers {
                let AccountVisibilitySource::Outbound {
                    action_message_id, ..
                } = &mut batches[header.index].source
                else {
                    continue;
                };
                let desired = if header.operation_id == owner_operation_id {
                    Some(current_id.clone())
                } else if action_message_id.as_ref() == Some(&current_id) {
                    None
                } else {
                    continue;
                };
                if action_message_id != &desired {
                    *action_message_id = desired;
                    repaired.push(header.index);
                }
            }
        }
        self.persist_repaired_leave_sources(&batches, &repaired)?;
        Ok(batches)
    }

    fn persist_repaired_leave_sources(
        &self,
        batches: &[AccountVisibilityBatch],
        repaired: &[usize],
    ) -> AccountResult<()> {
        if repaired.is_empty() {
            return Ok(());
        }
        let repaired_ids = repaired
            .iter()
            .map(|&index| batches[index].batch_id.clone())
            .collect::<HashSet<_>>();
        let rows = self
            .visibility_storage
            .load_account_visibility_journal()
            .map_err(|error| AccountError::Session(SessionError::Storage(error)))?;
        let mut upserts = Vec::new();
        for row in rows {
            if !repaired_ids.contains(&row.batch_id) {
                continue;
            }
            let live = batches
                .iter()
                .find(|batch| batch.batch_id == row.batch_id)
                .ok_or_else(|| {
                    account_visibility_error("repaired visibility batch is missing from memory")
                })?;
            let mut record: StoredAccountVisibilityRecordV1 = serde_json::from_slice(&row.record)
                .map_err(|error| {
                account_visibility_error(format!("decode account visibility record: {error}"))
            })?;
            if record.source == live.source {
                continue;
            }
            record.source = live.source.clone();
            let encoded = serde_json::to_vec(&record).map_err(|error| {
                account_visibility_error(format!("serialize account visibility record: {error}"))
            })?;
            upserts.push(AccountVisibilityJournalUpsert {
                operation_id: row.operation_id,
                ordinal: row.ordinal,
                batch_id: row.batch_id,
                record: encoded,
            });
        }
        if !upserts.is_empty() {
            self.visibility_storage
                .upsert_account_visibility_journal_records(&upserts)
                .map_err(|error| AccountError::Session(SessionError::Storage(error)))?;
        }
        Ok(())
    }

    fn record_terminal_outbound_action_outcome(
        &self,
        message_id: &MessageId,
        published: bool,
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<()> {
        if let Some(existing) = output
            .action_outcomes
            .iter()
            .find(|outcome| &outcome.message_id == message_id)
        {
            if existing.published != published {
                return Err(account_visibility_error(
                    "outbound action changed its terminal publish outcome",
                ));
            }
            return Ok(());
        }

        let batches = self.load_visibility_batches()?;
        if let Some(existing) = batches
            .iter()
            .flat_map(|batch| &batch.effects.action_outcomes)
            .find(|outcome| &outcome.message_id == message_id)
        {
            if existing.published != published {
                return Err(account_visibility_error(
                    "durable outbound action changed its terminal publish outcome",
                ));
            }
            return Ok(());
        }
        let mut pending = None::<AccountVisibilityActionOutcome>;
        for batch in &batches {
            let AccountVisibilitySource::Outbound {
                group_id: Some(group_id),
                action: Some(action),
                action_message_id: Some(bound_message_id),
                ..
            } = &batch.source
            else {
                continue;
            };
            if bound_message_id != message_id {
                continue;
            }
            let candidate = AccountVisibilityActionOutcome {
                operation_id: batch.operation_id.clone(),
                group_id: group_id.clone(),
                message_id: message_id.clone(),
                action: *action,
                published,
            };
            match &pending {
                Some(existing) if existing != &candidate => {
                    return Err(account_visibility_error(
                        "outbound action message is bound to multiple visibility operations",
                    ));
                }
                Some(_) => {}
                None => pending = Some(candidate),
            }
        }
        if pending.is_none() {
            // Provenance must outlive Header ACK. Terminal M1 failure deletes
            // the Leave Header; an epoch-driven M2 still has the LeaveRequest
            // naming this exact SelfRemove.
            pending = self.leave_request_outcome_for_message(message_id, published)?;
        }
        if let Some(outcome) = pending {
            output.action_outcomes.push(outcome);
        }
        Ok(())
    }

    fn leave_request_outcome_for_message(
        &self,
        message_id: &MessageId,
        published: bool,
    ) -> AccountResult<Option<AccountVisibilityActionOutcome>> {
        let mut group_ids = Vec::new();
        let fanouts = self.session.outbound_fanouts()?;
        for fanout in fanouts {
            if fanout.message_id() == message_id
                && let Some(group_id) = fanout.group_id()
                && !group_ids.contains(group_id)
            {
                group_ids.push(group_id.clone());
            }
        }
        if let Some(operation_id) = self.active_visibility_operation
            && let Some(operation) = self.durable_visibility_operations.get(&operation_id)
            && let AccountVisibilitySource::Outbound {
                group_id: Some(group_id),
                action: Some(AccountVisibilityOutboundAction::Leave),
                ..
            } = &operation.source
            && !group_ids.contains(group_id)
        {
            group_ids.push(group_id.clone());
        }
        for group_id in group_ids {
            let owns_message = self
                .visibility_storage
                .leave_request(&group_id)
                .map_err(|error| AccountError::Session(SessionError::Storage(error)))?
                .and_then(|request| request.last_proposed_message_id)
                .as_ref()
                == Some(message_id);
            if !owns_message {
                continue;
            }
            let operation_id = self
                .active_visibility_operation
                .map(|operation_id| operation_id.to_vec())
                .unwrap_or_else(|| message_id.as_slice().to_vec());
            return Ok(Some(AccountVisibilityActionOutcome {
                operation_id,
                group_id,
                message_id: message_id.clone(),
                action: AccountVisibilityOutboundAction::Leave,
                published,
            }));
        }
        Ok(None)
    }

    fn leave_fanout_requires_action_outcome(&self, fanout: &OutboundFanout) -> AccountResult<bool> {
        let Some(group_id) = fanout.group_id() else {
            return Ok(false);
        };
        Ok(self
            .visibility_storage
            .leave_request(group_id)
            .map_err(|error| AccountError::Session(SessionError::Storage(error)))?
            .and_then(|request| request.last_proposed_message_id)
            .as_ref()
            == Some(fanout.message_id()))
    }

    fn leave_action_outcome_is_recorded(
        &self,
        message_id: &MessageId,
        published: bool,
        output: &AccountDeviceEffects,
    ) -> AccountResult<bool> {
        if let Some(existing) = output
            .action_outcomes
            .iter()
            .find(|outcome| &outcome.message_id == message_id)
        {
            if existing.published != published {
                return Err(account_visibility_error(
                    "outbound action changed its terminal publish outcome",
                ));
            }
            return Ok(true);
        }
        let batches = self.load_visibility_batches()?;
        if let Some(existing) = batches
            .iter()
            .flat_map(|batch| &batch.effects.action_outcomes)
            .find(|outcome| &outcome.message_id == message_id)
        {
            if existing.published != published {
                return Err(account_visibility_error(
                    "durable outbound action changed its terminal publish outcome",
                ));
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn ensure_leave_fanout_outcome_recorded(
        &self,
        fanout: &OutboundFanout,
        published: bool,
        output: &AccountDeviceEffects,
    ) -> AccountResult<()> {
        if !self.leave_fanout_requires_action_outcome(fanout)? {
            return Ok(());
        }
        if self.leave_action_outcome_is_recorded(fanout.message_id(), published, output)? {
            return Ok(());
        }
        Err(account_visibility_error(
            "leave fanout produced no durable action outcome",
        ))
    }

    async fn publish_queue(
        &mut self,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
        visibility_handoff: SessionVisibilityHandoff,
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
                    let unresolved_before = output.unresolved_publishes.len();
                    let status = Box::pin(self.publish_one(
                        msg,
                        None,
                        output,
                        queue,
                        context.clone(),
                        Some(visibility_handoff),
                    ))
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
                    } else if status.retry_deferred
                        && let Some(unresolved) = output.unresolved_publishes.get(unresolved_before)
                    {
                        output
                            .unresolved_app_messages
                            .push(UnresolvedApplicationMessage {
                                group_id,
                                app_event_id,
                                message_id: unresolved.message_id.clone(),
                                reason: unresolved.reason,
                            });
                    }
                    self.resolve_regenerated_queued_intent(queued_intent, status);
                }
                PublishWork::Proposal { msg, queued_intent } => {
                    let status = Box::pin(self.publish_one(
                        msg,
                        None,
                        output,
                        queue,
                        context.clone(),
                        Some(visibility_handoff),
                    ))
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
                        visibility_handoff,
                    ))
                    .await?;
                }
                PublishWork::FoundingGroupCreated { welcomes } => {
                    self.publish_founding_group_created(
                        welcomes,
                        output,
                        queue,
                        context.clone(),
                        visibility_handoff,
                    )
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
                        visibility_handoff,
                    ))
                    .await?;
                }
                PublishWork::AutoPublish { msg, pending } => {
                    self.publish_pending(
                        vec![msg],
                        pending,
                        output,
                        queue,
                        context.clone(),
                        visibility_handoff,
                    )
                    .await?;
                }
            }
            // This checkpoint is synchronous and is the final action before
            // the loop can poll the next PublishWork. A later work item may
            // block or fail, but every caller-visible field produced so far is
            // now replayable without publishing the completed item again.
            self.checkpoint_current_publish_visibility(visibility_handoff, output)?;
        }
        Ok(())
    }

    /// Resume every incomplete frozen fanout in original staging order.
    pub async fn resume_outbound_fanouts(&mut self) -> AccountResult<AccountDeviceEffects> {
        self.start_account_visibility_operation(AccountVisibilitySource::Drain {
            observed_at: self.wall_clock.now(),
        })?;
        let effects = self.resume_outbound_fanouts_in_current_operation().await?;
        self.discard_active_visibility_operation()?;
        Ok(effects)
    }

    async fn resume_outbound_fanouts_in_current_operation(
        &mut self,
    ) -> AccountResult<AccountDeviceEffects> {
        let visibility_handoff = self.begin_session_visibility_handoff()?;
        self.start_current_publish_visibility(visibility_handoff);
        let fanouts = self.session.outbound_fanouts()?;
        let mut output = AccountDeviceEffects::default();
        let mut queue = VecDeque::new();
        for fanout in fanouts {
            let outcome = fanout.outcome();
            if outcome.outstanding_targets > 0
                || matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
            {
                Box::pin(self.drive_outbound_fanout(
                    fanout,
                    &mut output,
                    &mut queue,
                    None,
                    Some(visibility_handoff),
                ))
                .await?;
                self.checkpoint_current_publish_visibility(visibility_handoff, &output)?;
            } else {
                let published = outcome.accepted_targets >= fanout.request().required_acks.max(1);
                self.record_terminal_outbound_action_outcome(
                    fanout.message_id(),
                    published,
                    &mut output,
                )?;
                self.ensure_leave_fanout_outcome_recorded(&fanout, published, &output)?;
                self.checkpoint_current_publish_visibility(visibility_handoff, &output)?;
                self.session.delete_outbound_fanout(fanout.message_id())?;
            }
        }
        self.publish_queue(&mut output, &mut queue, None, visibility_handoff)
            .await?;
        self.reconcile_confirmed_own_leaf_rotations(&output.events)?;
        self.reconcile_superseded_maintenance(&output.events)?;
        self.finish_current_visibility_handoff(visibility_handoff);
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
                for mut obligation in self.session.maintenance_obligations_for_group(&group_id)? {
                    if matches!(
                        obligation.phase,
                        MaintenancePhase::Complete | MaintenancePhase::Failed
                    ) {
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
            for mut obligation in self.session.maintenance_obligations_for_group(&group_id)? {
                if matches!(
                    obligation.phase,
                    MaintenancePhase::Complete | MaintenancePhase::Failed
                ) {
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
            let evolutions = self.session.group_evolutions_for_group(&group_id)?;
            for mut evolution in evolutions.into_iter().filter(|evolution| {
                evolution.signed_message_id.as_ref() == Some(&invalidated_commit_id)
                    && evolution.phase != GroupEvolutionPhase::SupersededByConvergence
            }) {
                evolution.phase = GroupEvolutionPhase::SupersededByConvergence;
                self.session.put_group_evolution(&evolution)?;

                let GroupEvolutionSemantic::SelfUpdate { obligation_id, .. } = evolution.semantic
                else {
                    continue;
                };
                let Some(obligation_id) = obligation_id else {
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
        visibility_handoff: SessionVisibilityHandoff,
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
                self.absorb_session_effects_retaining_visibility(
                    output,
                    effects,
                    queue,
                    visibility_handoff,
                )?;
                self.mark_transport_fanout_evolution_confirmed(&message.id);
                self.checkpoint_current_publish_visibility(visibility_handoff, output)?;
                self.finish_transport_fanout(&message.id, output, Some(visibility_handoff))
                    .await?;
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
                    .publish_legacy_one(message, output, context.clone(), Some(visibility_handoff))
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
                self.absorb_session_effects_retaining_visibility(
                    output,
                    effects,
                    queue,
                    visibility_handoff,
                )?;
                self.checkpoint_current_publish_visibility(visibility_handoff, output)?;
                for message_id in message_ids {
                    self.mark_transport_fanout_evolution_confirmed(&message_id);
                    self.finish_transport_fanout(&message_id, output, Some(visibility_handoff))
                        .await?;
                }
            } else if !ambiguous_exposure && !retry_deferred {
                let effects = self.session.publish_failed(pending).await?;
                output
                    .pending
                    .push(PendingResolution::RolledBack { pending });
                self.absorb_session_effects_retaining_visibility(
                    output,
                    effects,
                    queue,
                    visibility_handoff,
                )?;
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
            self.absorb_session_effects_retaining_visibility(
                output,
                effects,
                queue,
                visibility_handoff,
            )?;
            return Ok(());
        };
        debug_assert!(messages.next().is_none());
        Box::pin(self.publish_one(
            message,
            Some(pending),
            output,
            queue,
            context,
            Some(visibility_handoff),
        ))
        .await?;
        Ok(())
    }

    async fn publish_group_created(
        &mut self,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
        visibility_handoff: SessionVisibilityHandoff,
    ) -> AccountResult<()> {
        let mut welcomes = welcomes.into_iter();
        let Some(first_welcome) = welcomes.next() else {
            let effects = self.confirm_published_retrying(pending).await?;
            output
                .pending
                .push(PendingResolution::Confirmed { pending });
            self.absorb_session_effects_retaining_visibility(
                output,
                effects,
                queue,
                visibility_handoff,
            )?;
            return Ok(());
        };
        Box::pin(self.publish_one_with_post_confirmation_welcomes(
            first_welcome,
            Some(PendingFanoutContinuation {
                pending,
                kind: FanoutPendingKind::CreateGroup,
                post_confirmation_welcomes: welcomes.collect(),
            }),
            output,
            queue,
            context,
            Some(visibility_handoff),
        ))
        .await?;
        Ok(())
    }

    async fn publish_founding_group_created(
        &mut self,
        welcomes: Vec<TransportMessage>,
        output: &mut AccountDeviceEffects,
        _queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
        visibility_handoff: SessionVisibilityHandoff,
    ) -> AccountResult<()> {
        let group_id = output.events.iter().find_map(|event| match event {
            GroupEvent::GroupCreated { group_id } => Some(group_id.clone()),
            _ => None,
        });
        self.publish_welcome_fanout(
            welcomes,
            group_id,
            output,
            context,
            false,
            Some(visibility_handoff),
        )
        .await
    }

    /// Bounded-concurrency Welcome publication used by founding creates and by
    /// deferred existing-group invite fanout after the commit is confirmed.
    async fn publish_welcome_fanout(
        &mut self,
        welcomes: Vec<TransportMessage>,
        group_id: Option<GroupId>,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
        force_retry: bool,
        visibility_handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<()> {
        let prepared = self.prepare_welcome_publish(welcomes, group_id, context, force_retry)?;
        if visibility_handoff.is_some() {
            let mut prepared_visibility = output.clone();
            for metadata in &prepared.metadata {
                prepared_visibility.extend(metadata.effects.clone());
            }
            self.checkpoint_optional_publish_visibility(visibility_handoff, &prepared_visibility)?;
        }
        let completed = prepared.publish(&self.adapter).await;
        self.finish_welcome_publish(completed, output, visibility_handoff)
            .await
    }

    fn prepare_welcome_publish(
        &self,
        welcomes: Vec<TransportMessage>,
        group_id: Option<GroupId>,
        context: Option<AuditEventContext>,
        force_retry: bool,
    ) -> AccountResult<PreparedWelcomePublish> {
        let mut metadata = Vec::with_capacity(welcomes.len());
        let mut completions = Vec::with_capacity(welcomes.len());
        completions.resize_with(welcomes.len(), || None);
        let mut pending = VecDeque::new();
        for (index, welcome) in welcomes.into_iter().enumerate() {
            let recipient = welcome_recipient(&welcome);
            let welcome_id = welcome.id.clone();
            let mut effects = AccountDeviceEffects::default();
            match self.prepare_legacy_publish(
                welcome,
                &mut effects,
                context.clone(),
                force_retry,
            )? {
                PreparedLegacyPublish::Complete(status) => {
                    completions[index] = Some(LegacyPublishCompletion::Complete(status));
                }
                PreparedLegacyPublish::Network(attempt) => pending.push_back((index, attempt)),
            }
            metadata.push(WelcomePublishMetadata {
                recipient,
                welcome_id,
                effects,
            });
        }

        Ok(PreparedWelcomePublish {
            group_id,
            metadata,
            completions,
            pending,
        })
    }

    async fn finish_welcome_publish(
        &mut self,
        completed: CompletedWelcomePublish,
        output: &mut AccountDeviceEffects,
        visibility_handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<()> {
        let CompletedWelcomePublish {
            group_id,
            metadata,
            completions,
        } = completed;
        // Every network attempt above has already been exposed to relays, so a
        // finish-stage failure for one recipient must not skip completion
        // bookkeeping for the rest: reconcile every completion in input order
        // and surface the first error only after all exposed publishes have
        // been durably finished. Otherwise later recipients' fanout state
        // would stay `Unattempted` and a restart could republish Welcomes that
        // were already delivered.
        let mut first_error = None;
        for (metadata, completion) in metadata.into_iter().zip(completions) {
            let WelcomePublishMetadata {
                recipient,
                welcome_id,
                effects,
            } = metadata;
            let failures_before = output.failures.len();
            output.extend(effects);
            let status = match completion.expect("every Welcome publish completed") {
                LegacyPublishCompletion::Complete(status) => Ok(status),
                LegacyPublishCompletion::Network(attempt, result) => {
                    self.finish_prepared_legacy_publish(
                        *attempt,
                        result,
                        output,
                        visibility_handoff,
                    )
                    .await
                }
            };
            let status = match status {
                Ok(status) => Some(status),
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    None
                }
            };
            if let Some(status) = status {
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
            self.checkpoint_optional_publish_visibility(visibility_handoff, output)?;
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish_group_evolution(
        &mut self,
        commit: TransportMessage,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
        visibility_handoff: SessionVisibilityHandoff,
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
                .publish_legacy_one(commit, output, context.clone(), Some(visibility_handoff))
                .await?;
            if commit_status.met_required_acks || commit_status.accepted_by_any_endpoint {
                let effects = self.confirm_published_retrying(pending).await?;
                output
                    .pending
                    .push(PendingResolution::Confirmed { pending });
                self.absorb_session_effects_retaining_visibility(
                    output,
                    effects,
                    queue,
                    visibility_handoff,
                )?;
                self.mark_transport_fanout_evolution_confirmed(&commit_id);
                self.checkpoint_current_publish_visibility(visibility_handoff, output)?;
                self.finish_transport_fanout(&commit_id, output, Some(visibility_handoff))
                    .await?;
                debug_assert!(welcomes.is_empty());
                return Ok(());
            }
            if !commit_status.possible_ambiguous_exposure && !commit_status.retry_deferred {
                let effects = self.session.publish_failed(pending).await?;
                output
                    .pending
                    .push(PendingResolution::RolledBack { pending });
                self.absorb_session_effects_retaining_visibility(
                    output,
                    effects,
                    queue,
                    visibility_handoff,
                )?;
            }
            return Ok(());
        }

        Box::pin(self.publish_one_with_post_confirmation_welcomes(
            commit,
            Some(PendingFanoutContinuation {
                pending,
                kind: self.session.pending_fanout_kind(pending)?,
                post_confirmation_welcomes: welcomes,
            }),
            output,
            queue,
            context,
            Some(visibility_handoff),
        ))
        .await?;
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
        &mut self,
        output: &mut AccountDeviceEffects,
        visibility_handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<()> {
        let now = self.wall_clock.now();
        for fanout in self.session.transport_fanouts()? {
            if fanout
                .bounded_until
                .is_some_and(|bounded_until| bounded_until <= now)
            {
                self.session.delete_transport_fanout(&fanout.id)?;
                continue;
            }
            if fanout.evolution_id.is_some() && !fanout.evolution_confirmed {
                continue;
            }
            self.finish_transport_fanout(&fanout.id, output, visibility_handoff)
                .await?;
        }
        Ok(())
    }

    /// Complete the endpoint snapshot for an already-persisted exact event.
    ///
    /// Group evolutions call this only after the first accepted acknowledgement
    /// has been applied locally. These attempts therefore cannot reopen the MLS
    /// pending state or change the canonical branch.
    async fn finish_transport_fanout(
        &mut self,
        message_id: &cgka_traits::MessageId,
        output: &mut AccountDeviceEffects,
        visibility_handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<()> {
        if self.detached_welcome_publishes.contains(message_id) {
            return Ok(());
        }
        let Some(mut fanout) = self.session.transport_fanout(message_id)? else {
            return Ok(());
        };
        let remaining = fanout
            .targets
            .iter()
            .filter(|target| transport_fanout_target_retry_due(target, self.wall_clock.now()))
            .map(|target| target.endpoint.clone())
            .collect::<Vec<_>>();
        if !remaining.is_empty() {
            // Concurrent single-endpoint publishes with `required_acks: 1`,
            // the per-endpoint contract the old sequential loop used; see
            // `drive_outbound_fanout` for why a multi-endpoint batch would
            // turn partial acceptance into a whole-call error.
            let adapter = &self.adapter;
            let account_id = self.session.self_id();
            let attempts = remaining.iter().map(|endpoint| {
                let request = TransportPublishRequest {
                    account_id: account_id.clone(),
                    message: fanout.exact_message.clone(),
                    target: publish_target_with_endpoints(&fanout.target, vec![endpoint.clone()]),
                    required_acks: 1,
                };
                async move { (endpoint.clone(), adapter.publish(request).await) }
            });
            for (endpoint, result) in futures::future::join_all(attempts).await {
                match result {
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
            }
            self.checkpoint_optional_publish_visibility(visibility_handoff, output)?;
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
            .publish_one_with_retry_policy(message, &mut output, None, true, None)
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
        visibility_handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<PublishStatus> {
        let continuation = match pending {
            Some(pending) => Some(PendingFanoutContinuation {
                pending,
                kind: self.session.pending_fanout_kind(pending)?,
                post_confirmation_welcomes: Vec::new(),
            }),
            None => None,
        };
        self.publish_one_with_post_confirmation_welcomes(
            message,
            continuation,
            output,
            queue,
            context,
            visibility_handoff,
        )
        .await
    }

    async fn publish_one_with_post_confirmation_welcomes(
        &mut self,
        message: TransportMessage,
        continuation: Option<PendingFanoutContinuation>,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
        visibility_handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<PublishStatus> {
        let (pending, pending_kind, post_confirmation_welcomes) = match continuation {
            Some(continuation) => (
                Some(continuation.pending),
                Some(continuation.kind),
                continuation.post_confirmation_welcomes,
            ),
            None => (None, None, Vec::new()),
        };
        if matches!(message.envelope, TransportEnvelope::GroupMessage { .. }) || pending.is_some() {
            let target = match self.routing.publish_target(&message) {
                Ok(target) => target,
                Err(error) => {
                    output.failures.push(PublishFailure {
                        message_id: message.id.clone(),
                        reason: error.to_string(),
                    });
                    self.rollback_unstaged_pending(pending, output, queue, visibility_handoff)
                        .await?;
                    self.record_terminal_outbound_action_outcome(&message.id, false, output)?;
                    self.checkpoint_optional_publish_visibility(visibility_handoff, output)?;
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
                    self.rollback_unstaged_pending(pending, output, queue, visibility_handoff)
                        .await?;
                    return Err(error.into());
                }
            };
            let pending_origin_message_id = if pending_kind == Some(FanoutPendingKind::CreateGroup)
            {
                None
            } else {
                match pending
                    .map(|pending| self.session.pending_origin_message_id(pending))
                    .transpose()
                {
                    Ok(message_id) => message_id,
                    Err(error) => {
                        self.rollback_unstaged_pending(pending, output, queue, visibility_handoff)
                            .await?;
                        return Err(error.into());
                    }
                }
            };
            let fanout = match OutboundFanout::stage_with_post_confirmation_welcomes(
                TransportPublishRequest {
                    account_id: self.session.self_id(),
                    message,
                    target,
                    required_acks,
                },
                pending,
                pending_group_id,
                self.wall_clock.now().0.saturating_mul(1_000),
                pending_origin_message_id,
                pending_kind,
                post_confirmation_welcomes,
            ) {
                Ok(fanout) => fanout,
                Err(error) => {
                    self.rollback_unstaged_pending(pending, output, queue, visibility_handoff)
                        .await?;
                    return Err(error.into());
                }
            };
            if let Err(error) = self.session.put_outbound_fanout(&fanout) {
                self.rollback_unstaged_pending(pending, output, queue, visibility_handoff)
                    .await?;
                return Err(error.into());
            }
            Box::pin(self.drive_outbound_fanout(fanout, output, queue, context, visibility_handoff))
                .await
        } else {
            self.publish_legacy_one(message, output, context, visibility_handoff)
                .await
        }
    }

    async fn rollback_unstaged_pending(
        &mut self,
        pending: Option<PendingStateRef>,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        visibility_handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<()> {
        if let Some(pending) = pending {
            self.checkpoint_optional_publish_visibility(visibility_handoff, output)?;
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            self.absorb_session_effects_retaining_optional_visibility(
                output,
                effects,
                queue,
                visibility_handoff,
            )?;
        }
        Ok(())
    }

    async fn drive_outbound_fanout(
        &mut self,
        mut fanout: OutboundFanout,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
        visibility_handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<PublishStatus> {
        self.resolve_outbound_fanout_mls(
            &mut fanout,
            output,
            queue,
            context.clone(),
            visibility_handoff,
        )
        .await?;
        self.checkpoint_optional_publish_visibility(visibility_handoff, output)?;
        let endpoints = fanout.request().target.endpoints().to_vec();
        let now_ms = self.wall_clock.now().0.saturating_mul(1_000);
        let due = fanout
            .outstanding_target_indexes()
            .into_iter()
            .filter(|&index| frozen_fanout_target_retry_due(&fanout, index, now_ms))
            .collect::<Vec<_>>();
        let attempted_any = !due.is_empty();
        if !due.is_empty() {
            for &index in &due {
                fanout.mark_attempt_started_at(index, now_ms)?;
            }
            self.session.put_outbound_fanout(&fanout)?;

            // Publish every outstanding endpoint concurrently as
            // single-endpoint requests with `required_acks: 1`, the same
            // per-endpoint contract the old sequential loop used. A
            // multi-endpoint batch cannot be used here: the adapter treats an
            // unmet `required_acks` as a whole-call error that discards the
            // successful receipts, so an ordinary partial acceptance would
            // read as "every endpoint failed" and roll back a commit that
            // already reached a relay. Per-endpoint requests keep each
            // endpoint's outcome independent while removing the
            // one-awaited-ack-at-a-time serialization.
            let adapter = &self.adapter;
            let account_id = fanout.request().account_id.clone();
            let attempts = due.iter().map(|&index| {
                let attempt = TransportPublishRequest {
                    account_id: account_id.clone(),
                    message: fanout.request().message.clone(),
                    target: publish_target_with_endpoints(
                        &fanout.request().target,
                        vec![endpoints[index].clone()],
                    ),
                    required_acks: 1,
                };
                async move { (index, adapter.publish(attempt).await) }
            });
            for (index, result) in futures::future::join_all(attempts).await {
                let endpoint = endpoints[index].clone();
                let failure = match result {
                    Ok(report) => {
                        fanout.record_published_message_id(report.message_id)?;
                        if report
                            .accepted
                            .iter()
                            .any(|receipt| receipt.endpoint == endpoint)
                        {
                            fanout.mark_target_accepted(index)?;
                            None
                        } else {
                            Some(
                                report
                                    .failed
                                    .iter()
                                    .find(|failure| failure.endpoint == endpoint)
                                    .cloned()
                                    .unwrap_or_else(|| ambiguous_endpoint_failure(endpoint)),
                            )
                        }
                    }
                    Err(error) => {
                        if let Some(message_id) = error.publish_message_id() {
                            fanout.record_published_message_id(message_id.clone())?;
                        }
                        Some(
                            error
                                .publish_endpoint_failures()
                                .iter()
                                .find(|failure| failure.endpoint == endpoint)
                                .cloned()
                                .unwrap_or_else(|| ambiguous_endpoint_failure(endpoint)),
                        )
                    }
                };
                if let Some(failure) = failure {
                    fanout.record_target_failure(index, failure)?;
                }
            }
            self.session.put_outbound_fanout(&fanout)?;
            let report = frozen_fanout_report(&fanout);
            // Record this artifact before confirmation releases any frozen
            // Welcome continuations, preserving transport chronology in the
            // returned effects while keeping the MLS edge atomic below.
            // `EpochConfirmed` / `EpochRolledBack` records the MLS edge. This
            // endpoint-free publish row records the separate terminal fanout
            // edge; relay URLs stay solely in the encrypted fanout record and
            // never enter this privacy-safe audit summary.
            self.session.record_audit_event(
                fanout.group_id(),
                context.clone(),
                AuditEventKind::PublishOutcome {
                    msg_id: hex::encode(report.message_id.as_slice()),
                    artifact_kind: None,
                    target_kind: "frozen_group_fanout".into(),
                    relay_url: None,
                    accepted_relay_urls: Vec::new(),
                    failed_relays: Vec::new(),
                    required_acks: report.required_acks as u64,
                    met_required_acks: report.met_required_acks(),
                    transport: Some(publish_wire_metadata(&fanout.request().message)),
                },
            );
            output.reports.push(report);
            self.resolve_outbound_fanout_mls(
                &mut fanout,
                output,
                queue,
                context.clone(),
                visibility_handoff,
            )
            .await?;
        }

        let report = frozen_fanout_report(&fanout);
        let fanout_outcome = fanout.outcome();
        let possible_ambiguous_exposure = fanout.possible_exposure();
        let status = PublishStatus {
            met_required_acks: report.met_required_acks(),
            accepted_by_any_endpoint: report.accepted_count() > 0,
            possible_ambiguous_exposure,
            retry_deferred: fanout_outcome.outstanding_targets > 0,
        };
        let publish_failure_reason =
            if fanout_outcome.outstanding_targets > 0 && !status.met_required_acks {
                output.unresolved_publishes.push(UnresolvedPublish {
                    message_id: report.message_id.clone(),
                    reason: if possible_ambiguous_exposure {
                        UnresolvedPublishReason::AcknowledgementUnknown
                    } else {
                        UnresolvedPublishReason::RetryableUnavailable
                    },
                });
                None
            } else if !status.met_required_acks {
                let reason = "insufficient publish acknowledgements".to_owned();
                output.failures.push(PublishFailure {
                    message_id: report.message_id.clone(),
                    reason: reason.clone(),
                });
                Some(reason)
            } else {
                None
            };
        if matches!(
            fanout.request().message.envelope,
            TransportEnvelope::Welcome { .. }
        ) {
            if status.met_required_acks {
                self.mark_welcome_delivered_best_effort(fanout.message_id());
            } else if attempted_any
                && matches!(fanout.mls_state(), FanoutMlsState::Confirmed)
                && let Some(recipient) = welcome_recipient(&fanout.request().message)
            {
                output.welcome_failures.push(WelcomeDeliveryFailure {
                    message_id: fanout.message_id().clone(),
                    recipient,
                    group_id: fanout.group_id().cloned(),
                    reason: publish_failure_reason
                        .clone()
                        .unwrap_or_else(|| "welcome publish failed".into()),
                });
            }
        }
        output.fanout.push(fanout_outcome.clone());
        // Leave membership is authorized by `published: true`. Required ACKs
        // can land while an optional target stays retryable, so emit durable
        // true at quorum rather than waiting for complete fanout. `published:
        // false` stays terminal: only a finished fanout that missed quorum.
        if status.met_required_acks {
            self.record_terminal_outbound_action_outcome(fanout.message_id(), true, output)?;
        } else if fanout_outcome.fanout_complete {
            self.record_terminal_outbound_action_outcome(fanout.message_id(), false, output)?;
        }
        if fanout_outcome.fanout_complete {
            let published = status.met_required_acks;
            self.ensure_leave_fanout_outcome_recorded(&fanout, published, output)?;
        }
        self.checkpoint_optional_publish_visibility(visibility_handoff, output)?;
        if fanout_outcome.fanout_complete
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
        context: Option<AuditEventContext>,
        visibility_handoff: Option<SessionVisibilityHandoff>,
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
            self.absorb_session_effects_retaining_optional_visibility(
                output,
                effects,
                queue,
                visibility_handoff,
            )?;
        } else if outcome.fanout_complete
            && outcome.accepted_targets == 0
            && !fanout.possible_exposure()
            && let Some(pending) = fanout.pending_ref()
        {
            let effects = self.session.publish_failed_fanout(pending, fanout).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            self.absorb_session_effects_retaining_optional_visibility(
                output,
                effects,
                queue,
                visibility_handoff,
            )?;
        }
        if matches!(fanout.mls_state(), FanoutMlsState::Confirmed)
            && !fanout.pending_post_confirmation_welcomes().is_empty()
        {
            let welcomes = fanout.pending_post_confirmation_welcomes().to_vec();
            let group_id = fanout.group_id().cloned();
            self.publish_welcome_fanout(
                welcomes,
                group_id,
                output,
                context,
                false,
                visibility_handoff,
            )
            .await?;
            if fanout.mark_post_confirmation_welcomes_released() {
                self.session.put_outbound_fanout(fanout)?;
            }
        }
        Ok(())
    }

    async fn publish_legacy_one(
        &mut self,
        message: TransportMessage,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
        visibility_handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<PublishStatus> {
        self.publish_one_with_retry_policy(message, output, context, false, visibility_handoff)
            .await
    }

    async fn publish_one_with_retry_policy(
        &mut self,
        message: TransportMessage,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
        retry_immediately: bool,
        visibility_handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<PublishStatus> {
        match self.prepare_legacy_publish(message, output, context, retry_immediately)? {
            PreparedLegacyPublish::Complete(status) => Ok(status),
            PreparedLegacyPublish::Network(attempt) => {
                let result = self.adapter.publish(attempt.request.clone()).await;
                self.finish_prepared_legacy_publish(*attempt, result, output, visibility_handoff)
                    .await
            }
        }
    }

    fn prepare_legacy_publish(
        &self,
        message: TransportMessage,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
        retry_immediately: bool,
    ) -> AccountResult<PreparedLegacyPublish> {
        let message_id = message.id.clone();
        if self.detached_welcome_publishes.contains(&message_id) {
            return Ok(PreparedLegacyPublish::Complete(PublishStatus {
                retry_deferred: true,
                ..PublishStatus::default()
            }));
        }
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
                    return Ok(PreparedLegacyPublish::Complete(PublishStatus::default()));
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
        let fanout = if let Some(fanout) = existing_fanout {
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
                (retry_immediately && target.state == TransportFanoutAttemptState::AttemptedFailed)
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
            return Ok(PreparedLegacyPublish::Complete(PublishStatus {
                met_required_acks: accepted_before >= required_acks.max(1),
                accepted_by_any_endpoint: accepted_before > 0,
                possible_ambiguous_exposure: fanout.possible_exposure,
                retry_deferred,
            }));
        }
        let attempt_target = publish_target_with_endpoints(&target, retry_endpoints.clone());
        let attempt_required_acks = required_acks
            .max(1)
            .saturating_sub(accepted_before)
            .max(1)
            .min(retry_endpoints.len());

        Ok(PreparedLegacyPublish::Network(Box::new(
            PreparedLegacyPublishAttempt {
                message_id,
                msg_id_hex,
                wire,
                artifact_kind,
                publish_context,
                fanout,
                retry_endpoints,
                accepted_before,
                required_acks,
                target_kind,
                relay_urls,
                target_group_id,
                defers_remaining_fanout_until_confirmation,
                request: TransportPublishRequest {
                    account_id: self.session.self_id(),
                    message,
                    target: attempt_target,
                    required_acks: attempt_required_acks,
                },
            },
        )))
    }

    async fn finish_prepared_legacy_publish(
        &mut self,
        attempt: PreparedLegacyPublishAttempt,
        result: Result<TransportPublishReport, TransportAdapterError>,
        output: &mut AccountDeviceEffects,
        visibility_handoff: Option<SessionVisibilityHandoff>,
    ) -> AccountResult<PublishStatus> {
        let PreparedLegacyPublishAttempt {
            message_id,
            msg_id_hex,
            wire,
            artifact_kind,
            publish_context,
            mut fanout,
            retry_endpoints,
            accepted_before,
            required_acks,
            target_kind,
            relay_urls,
            target_group_id,
            defers_remaining_fanout_until_confirmation,
            request: _,
        } = attempt;
        // Test-only fault injection (`arm_finish_stage_failure`): behaves like
        // the durable fanout persist below failing with transient contention.
        if self.finish_stage_failure.as_ref() == Some(&message_id) {
            return Err(AccountError::Session(SessionError::Storage(
                StorageError::Busy("injected finish-stage failure".into()),
            )));
        }
        let report = match result {
            Ok(report) => report,
            Err(error) => {
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
                        reason: error.to_string(),
                        detail: None,
                        transport: Some(wire),
                    },
                );
                output.failures.push(PublishFailure {
                    message_id,
                    reason: error.to_string(),
                });
                return Ok(PublishStatus {
                    met_required_acks: accepted_before >= required_acks.max(1),
                    accepted_by_any_endpoint: accepted_before > 0,
                    possible_ambiguous_exposure: true,
                    retry_deferred: false,
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
        self.checkpoint_optional_publish_visibility(visibility_handoff, output)?;
        if !defers_remaining_fanout_until_confirmation {
            self.finish_transport_fanout(&message_id, output, visibility_handoff)
                .await?;
        }
        Ok(PublishStatus {
            met_required_acks: published,
            accepted_by_any_endpoint,
            possible_ambiguous_exposure: fanout.possible_exposure,
            retry_deferred: false,
        })
    }
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

fn ambiguous_endpoint_failure(endpoint: TransportEndpoint) -> TransportEndpointFailure {
    TransportEndpointFailure {
        endpoint,
        reason: "publish acknowledgement unknown".into(),
        kind: TransportEndpointFailureKind::PossiblyExposed,
        rejection_category: None,
    }
}

fn frozen_fanout_target_retry_due(fanout: &OutboundFanout, index: usize, now_ms: u64) -> bool {
    use cgka_traits::FanoutTargetStatus;

    match fanout.target_status(index) {
        Some(FanoutTargetStatus::NotAttempted | FanoutTargetStatus::Attempting) => true,
        Some(FanoutTargetStatus::PossiblyExposed | FanoutTargetStatus::RetryableUnavailable) => {
            let attempt_count = fanout.target_attempt_count(index);
            let shift = attempt_count.saturating_sub(1).min(7);
            let backoff_ms = FROZEN_FANOUT_RETRY_BASE_MS
                .saturating_mul(1_u64 << shift)
                .min(FROZEN_FANOUT_RETRY_MAX_MS);
            fanout
                .target_last_attempt_at_ms(index)
                .is_none_or(|last| now_ms >= last.saturating_add(backoff_ms))
        }
        Some(FanoutTargetStatus::Accepted | FanoutTargetStatus::Failed) | None => false,
    }
}

fn account_visibility_error(error: impl Into<String>) -> AccountError {
    AccountError::Session(SessionError::Storage(StorageError::Backend(error.into())))
}

fn account_visibility_batch_id(operation_id: &[u8; 16], ordinal: u64) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"marmot-account-visibility-v1");
    hasher.update(operation_id);
    hasher.update(ordinal.to_be_bytes());
    hasher.finalize().to_vec()
}

fn decode_account_visibility_row(
    row: AccountVisibilityJournalRow,
) -> AccountResult<AccountVisibilityBatch> {
    let operation_id = <[u8; 16]>::try_from(row.operation_id.as_slice())
        .map_err(|_| account_visibility_error("visibility operation id has invalid length"))?;
    if row.batch_id != account_visibility_batch_id(&operation_id, row.ordinal) {
        return Err(account_visibility_error(
            "visibility batch id does not match its operation and ordinal",
        ));
    }
    let record: StoredAccountVisibilityRecordV1 =
        serde_json::from_slice(&row.record).map_err(|error| {
            account_visibility_error(format!("decode account visibility record: {error}"))
        })?;
    if record.version != ACCOUNT_VISIBILITY_RECORD_VERSION {
        return Err(account_visibility_error(format!(
            "unsupported account visibility record version {}",
            record.version
        )));
    }
    let mut effects = AccountDeviceEffects::default();
    let kind = match record.payload {
        StoredAccountVisibilityPayloadV1::Header {
            maintenance_disposition,
        } => {
            if row.ordinal != 0 {
                return Err(account_visibility_error(
                    "visibility header has a nonzero ordinal",
                ));
            }
            effects.maintenance_disposition = maintenance_disposition;
            AccountVisibilityRecordKind::Header
        }
        StoredAccountVisibilityPayloadV1::Event {
            event,
            engine_outbox_provenance,
        } => {
            if row.ordinal == 0 || row.ordinal >= ACCOUNT_VISIBILITY_CONTROL_ORDINAL {
                return Err(account_visibility_error(
                    "visibility event has a reserved ordinal",
                ));
            }
            effects.events.push(event);
            AccountVisibilityRecordKind::Event {
                engine_outbox_provenance,
            }
        }
        StoredAccountVisibilityPayloadV1::SessionControl(control) => {
            if row.ordinal != ACCOUNT_VISIBILITY_CONTROL_ORDINAL {
                return Err(account_visibility_error(
                    "visibility session-control record has the wrong ordinal",
                ));
            }
            effects.queued = control
                .queued
                .into_iter()
                .map(|queued| QueuedIntentRef {
                    group_id: queued.group_id,
                    intent_id: queued.intent_id,
                })
                .collect();
            effects.pending_convergence = control.pending_convergence;
            AccountVisibilityRecordKind::SessionControl
        }
        StoredAccountVisibilityPayloadV1::NonSession(non_session) => {
            if row.ordinal != ACCOUNT_VISIBILITY_NON_SESSION_ORDINAL {
                return Err(account_visibility_error(
                    "visibility non-session record has the wrong ordinal",
                ));
            }
            effects = non_session.into_effects();
            AccountVisibilityRecordKind::NonSession
        }
    };
    Ok(AccountVisibilityBatch {
        sequence: row.sequence,
        operation_id: row.operation_id,
        batch_id: row.batch_id,
        source: record.source,
        kind,
        effects,
    })
}

fn frozen_fanout_report(fanout: &OutboundFanout) -> TransportPublishReport {
    let endpoints = fanout.request().target.endpoints();
    let mut accepted = Vec::new();
    let mut failed = Vec::new();
    for (index, (endpoint, status)) in endpoints.iter().zip(fanout.target_statuses()).enumerate() {
        match status {
            cgka_traits::FanoutTargetStatus::Accepted => {
                accepted.push(TransportEndpointReceipt {
                    endpoint: endpoint.clone(),
                    accepted_at: None,
                });
            }
            cgka_traits::FanoutTargetStatus::Failed => {
                failed.push(fanout.target_failure(index).cloned().unwrap_or_else(|| {
                    TransportEndpointFailure {
                        endpoint: endpoint.clone(),
                        reason: "publish attempt failed before exposure".into(),
                        kind: TransportEndpointFailureKind::NotExposed,
                        rejection_category: None,
                    }
                }));
            }
            cgka_traits::FanoutTargetStatus::NotAttempted
            | cgka_traits::FanoutTargetStatus::Attempting => {}
            cgka_traits::FanoutTargetStatus::PossiblyExposed
            | cgka_traits::FanoutTargetStatus::RetryableUnavailable => {
                if let Some(failure) = fanout.target_failure(index) {
                    failed.push(failure.clone());
                }
            }
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

/// Whether durable teardown evidence says the live current revision was
/// deleted. Pre-artifact lifecycle rows can carry only `authored_event_id`, so
/// both identity representations are authoritative during upgrade recovery.
fn current_key_package_revision_is_deleted(lifecycle: &KeyPackageLifecycleState) -> bool {
    lifecycle
        .authored_signed_event
        .as_ref()
        .is_some_and(|artifact| {
            lifecycle
                .deleted_live_revision_event_ids
                .contains(&artifact.id)
        })
        || lifecycle
            .authored_event_id
            .as_ref()
            .is_some_and(|event_id| lifecycle.deleted_live_revision_event_ids.contains(event_id))
}

fn current_key_package_artifact_precedes_authoring_high_water(
    lifecycle: &KeyPackageLifecycleState,
) -> bool {
    lifecycle
        .authored_signed_event
        .as_ref()
        .zip(lifecycle.authored_event_created_at)
        .is_some_and(|(artifact, high_water)| artifact.created_at < high_water)
}

fn ensure_key_package_cutover_publication_allowed(
    lifecycle: &KeyPackageLifecycleState,
) -> AccountResult<()> {
    if lifecycle.cutover_publication_blocked {
        return Err(crate::key_package::KeyPackagePublishError::unexposed(
            "key package publication is blocked until strict cutover discovery completes",
        )
        .into());
    }
    Ok(())
}

fn current_key_package_republish_blocker(
    lifecycle: &KeyPackageLifecycleState,
    now: Timestamp,
) -> Option<&'static str> {
    if lifecycle.current_key_package.is_none() {
        Some("missing_current_key_package")
    } else if lifecycle.current_key_package_ref.is_none() {
        Some("missing_current_key_package_ref")
    } else if lifecycle
        .current_not_before
        .is_none_or(|not_before| not_before > now)
    {
        Some("current_not_before_unreached")
    } else if lifecycle
        .current_not_after
        .is_none_or(|not_after| not_after <= now)
    {
        Some("current_not_after_expired")
    } else if lifecycle.authored_event_id.is_none() {
        Some("missing_authored_event_id")
    } else if lifecycle.authored_event_created_at.is_none() {
        Some("missing_authored_event_created_at")
    } else if lifecycle.authored_signed_event.is_none() {
        Some("missing_authored_signed_event")
    } else if lifecycle
        .authored_signed_event
        .as_ref()
        .zip(lifecycle.authored_event_created_at)
        .is_some_and(|(artifact, high_water)| artifact.created_at < high_water)
    {
        Some("newer_stable_slot_revision_requires_semantic_replacement")
    } else if lifecycle
        .current_key_package_ref
        .as_deref()
        .is_some_and(|key_package_ref| lifecycle.key_package_ref_is_consumed(key_package_ref))
    {
        Some("current_key_package_ref_consumed")
    } else if !lifecycle.upgrade_rotation_recorded {
        Some("upgrade_rotation_required")
    } else {
        None
    }
}

fn merge_republish_publication_targets(
    targets: &mut Vec<TransportFanoutTarget>,
    current_endpoints: &[TransportEndpoint],
) {
    for endpoint in current_endpoints {
        if let Some(target) = targets
            .iter_mut()
            .find(|target| target.endpoint == *endpoint)
        {
            if target.state == TransportFanoutAttemptState::PolicyProhibited {
                if target.attempt_count == 0 && target.last_attempt_at.is_none() {
                    target.state = TransportFanoutAttemptState::Unattempted;
                    target.failure_code = None;
                } else {
                    // Re-authorizing the same exact event at a formerly removed
                    // endpoint must retain its historical exposure evidence.
                    target.state = TransportFanoutAttemptState::AttemptedFailed;
                    target.failure_code = Some("possible_exposure".into());
                }
            }
            continue;
        }
        targets.push(TransportFanoutTarget {
            endpoint: endpoint.clone(),
            state: TransportFanoutAttemptState::Unattempted,
            attempt_count: 0,
            last_attempt_at: None,
            failure_code: None,
        });
    }
    for target in targets.iter_mut() {
        if current_endpoints.contains(&target.endpoint) {
            continue;
        }
        if target.state == TransportFanoutAttemptState::PolicyProhibited {
            continue;
        }
        target.state = TransportFanoutAttemptState::PolicyProhibited;
        target.failure_code = Some("endpoint_removed_from_policy".into());
    }
}

fn key_package_publication_targets_need_policy_reconciliation(
    targets: &[TransportFanoutTarget],
    current_endpoints: &[TransportEndpoint],
) -> bool {
    current_endpoints.iter().any(|endpoint| {
        !targets.iter().any(|target| {
            target.endpoint == *endpoint
                && target.state != TransportFanoutAttemptState::PolicyProhibited
        })
    }) || targets.iter().any(|target| {
        target.state != TransportFanoutAttemptState::PolicyProhibited
            && !current_endpoints.contains(&target.endpoint)
    })
}

fn key_package_reauthor_created_at(
    artifact: &SignedPublicationArtifact,
    now: Timestamp,
    reauthor_after_secs: Option<u64>,
    ordering_high_water: Option<Timestamp>,
    require_strictly_above_high_water: bool,
) -> Result<Option<Timestamp>, ()> {
    let ordering_requires_reauthor = ordering_high_water.is_some_and(|high_water| {
        if require_strictly_above_high_water {
            high_water >= artifact.created_at
        } else {
            high_water > artifact.created_at
        }
    });
    if reauthor_after_secs.is_none() && !ordering_requires_reauthor {
        return Ok(None);
    }
    if artifact.created_at.0 > now.0.saturating_add(KEY_PACKAGE_MAX_FUTURE_SKEW_SECS) {
        return Err(());
    }
    let policy_requires_reauthor = reauthor_after_secs.is_some_and(|reauthor_after_secs| {
        now.0.saturating_sub(artifact.created_at.0) >= reauthor_after_secs
    });
    if !policy_requires_reauthor && !ordering_requires_reauthor {
        return Ok(None);
    }
    let strictly_newer = artifact.created_at.0.checked_add(1).ok_or(())?;
    let strictly_above_high_water = ordering_high_water
        .filter(|high_water| *high_water > artifact.created_at)
        .map(|high_water| high_water.0.checked_add(1).ok_or(()))
        .transpose()?
        .unwrap_or(strictly_newer);
    let created_at = Timestamp(now.0.max(strictly_newer).max(strictly_above_high_water));
    if created_at.0 <= artifact.created_at.0
        || created_at.0 > now.0.saturating_add(KEY_PACKAGE_MAX_FUTURE_SKEW_SECS)
    {
        return Err(());
    }
    Ok(Some(created_at))
}

fn validate_reauthored_key_package_artifact(
    previous: &SignedPublicationArtifact,
    requested_created_at: Timestamp,
    replacement: &SignedPublicationArtifact,
) -> AccountResult<()> {
    if replacement.created_at != requested_created_at
        || replacement.created_at <= previous.created_at
        || replacement.id == previous.id
        || replacement.bytes == previous.bytes
    {
        return Err(crate::key_package::KeyPackagePublishError::unexposed(
            "reauthored KeyPackage event does not form a strictly newer signed revision",
        )
        .into());
    }
    Ok(())
}

fn replace_key_package_publication_targets(
    targets: &mut Vec<TransportFanoutTarget>,
    live_endpoints: &[TransportEndpoint],
) {
    *targets = live_endpoints
        .iter()
        .cloned()
        .map(|endpoint| TransportFanoutTarget {
            endpoint,
            state: TransportFanoutAttemptState::Unattempted,
            attempt_count: 0,
            last_attempt_at: None,
            failure_code: None,
        })
        .collect();
}

fn retired_key_package_publication(
    artifact: &SignedPublicationArtifact,
    key_package_ref: Option<&[u8]>,
    package_not_after: Option<Timestamp>,
    delete_without_successor: bool,
    targets: &[TransportFanoutTarget],
) -> Option<RetiredKeyPackagePublication> {
    retired_key_package_publication_from_identity(
        &artifact.id,
        artifact.created_at,
        key_package_ref,
        package_not_after,
        delete_without_successor,
        targets,
    )
}

/// Snapshot the exact current publication even for upgrade rows that predate
/// durable signed-artifact bytes. `authored_event_id` plus the stable-slot
/// high-water and endpoint fanout remain sufficient deletion evidence; losing
/// that identity while superseding private material would make an exposed
/// relay revision permanently unreachable.
fn retired_current_key_package_publication(
    lifecycle: &KeyPackageLifecycleState,
    delete_without_successor: bool,
) -> Option<RetiredKeyPackagePublication> {
    let (event_id, authored_created_at) = match lifecycle.authored_signed_event.as_ref() {
        Some(artifact) => (&artifact.id, artifact.created_at),
        None => (
            lifecycle.authored_event_id.as_ref()?,
            lifecycle.authored_event_created_at.unwrap_or(Timestamp(0)),
        ),
    };
    retired_key_package_publication_from_identity(
        event_id,
        authored_created_at,
        lifecycle.current_key_package_ref.as_deref(),
        lifecycle.current_not_after,
        delete_without_successor,
        &lifecycle.publication_targets,
    )
}

fn retired_key_package_publication_from_identity(
    event_id: &cgka_traits::MessageId,
    authored_created_at: Timestamp,
    key_package_ref: Option<&[u8]>,
    package_not_after: Option<Timestamp>,
    delete_without_successor: bool,
    targets: &[TransportFanoutTarget],
) -> Option<RetiredKeyPackagePublication> {
    // Every snapshotted endpoint is a possible exposure. Publication records
    // are updated only after the awaited network call returns, so cancellation
    // or process death can leave a relay-held event marked `Unattempted` (and a
    // later policy edit can turn that same ambiguous target `PolicyProhibited`).
    let mut deletion_targets = targets
        .iter()
        .filter(|target| target.failure_code.as_deref() != Some("confirmed_absent"))
        .map(|target| TransportFanoutTarget {
            endpoint: target.endpoint.clone(),
            state: TransportFanoutAttemptState::Unattempted,
            attempt_count: 0,
            last_attempt_at: None,
            failure_code: None,
        })
        .collect::<Vec<_>>();
    deletion_targets.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
    deletion_targets.dedup_by(|left, right| left.endpoint == right.endpoint);
    (!deletion_targets.is_empty()).then(|| RetiredKeyPackagePublication {
        event_id: event_id.clone(),
        authored_created_at,
        key_package_ref: key_package_ref.map(ToOwned::to_owned),
        package_not_after,
        delete_without_successor,
        deletion_targets,
    })
}

fn manual_key_package_deletion_liability(
    lifecycle: &KeyPackageLifecycleState,
    event_id: &cgka_traits::MessageId,
    endpoint: TransportEndpoint,
) -> RetiredKeyPackagePublication {
    let current_matches = lifecycle
        .authored_signed_event
        .as_ref()
        .is_some_and(|artifact| artifact.id == *event_id)
        || lifecycle.authored_event_id.as_ref() == Some(event_id);
    let pending = lifecycle.pending_replacement.as_ref().filter(|pending| {
        pending
            .signed_event
            .as_ref()
            .is_some_and(|artifact| artifact.id == *event_id)
    });
    let existing = lifecycle
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == *event_id);
    let authored_created_at = existing
        .map(|retired| retired.authored_created_at)
        .or_else(|| {
            current_matches.then(|| {
                lifecycle
                    .authored_signed_event
                    .as_ref()
                    .filter(|artifact| artifact.id == *event_id)
                    .map(|artifact| artifact.created_at)
                    .or(lifecycle.authored_event_created_at)
                    .unwrap_or(Timestamp(0))
            })
        })
        .or_else(|| pending.map(|pending| pending.authored_created_at))
        .unwrap_or(Timestamp(0));
    let key_package_ref = existing
        .and_then(|retired| retired.key_package_ref.clone())
        .or_else(|| {
            current_matches
                .then(|| lifecycle.current_key_package_ref.clone())
                .flatten()
        })
        .or_else(|| pending.map(|pending| pending.key_package_ref.clone()));
    let package_not_after = existing
        .and_then(|retired| retired.package_not_after)
        .or_else(|| {
            current_matches
                .then_some(lifecycle.current_not_after)
                .flatten()
        })
        .or_else(|| pending.map(|pending| pending.not_after));
    RetiredKeyPackagePublication {
        event_id: event_id.clone(),
        authored_created_at,
        key_package_ref,
        package_not_after,
        delete_without_successor: true,
        deletion_targets: vec![TransportFanoutTarget {
            endpoint,
            state: TransportFanoutAttemptState::Unattempted,
            attempt_count: 0,
            last_attempt_at: None,
            failure_code: None,
        }],
    }
}

fn admit_manual_key_package_deletion_liabilities(
    lifecycle: &mut KeyPackageLifecycleState,
    event_id: &cgka_traits::MessageId,
    mut endpoints: Vec<TransportEndpoint>,
    liability_limit: usize,
) -> (Vec<TransportEndpoint>, Vec<TransportEndpoint>) {
    endpoints.sort();
    endpoints.dedup();
    let mut liability_count = key_package_signed_publication_liability_count(lifecycle);
    let mut admitted = Vec::new();
    let mut deferred = Vec::new();
    for endpoint in endpoints {
        let already_durable =
            key_package_event_endpoint_is_liability(lifecycle, event_id, &endpoint);
        if !already_durable && liability_count >= liability_limit {
            deferred.push(endpoint);
            continue;
        }
        if !already_durable {
            liability_count = liability_count.saturating_add(1);
        }
        admitted.push(endpoint.clone());
        let retired = manual_key_package_deletion_liability(lifecycle, event_id, endpoint);
        retain_retired_key_package_publication(lifecycle, retired);
    }
    (admitted, deferred)
}

/// Admit one exact deletion set atomically while giving its event exclusive
/// use of the small overflow above the ordinary signed-publication bound.
///
/// Requests that fit under the ordinary bound do not consume the reserve. The
/// first request that crosses that bound becomes the durable owner; until its
/// last deletion target is terminal, a different exact event is wholly
/// deferred even if some ordinary capacity later becomes available. This
/// prevents two independently atomic relay sets from sharing a reserve whose
/// safety argument assumes one selected deletion.
fn admit_atomic_exact_key_package_deletion_liabilities(
    lifecycle: &mut KeyPackageLifecycleState,
    event_id: &cgka_traits::MessageId,
    mut endpoints: Vec<TransportEndpoint>,
) -> (Vec<TransportEndpoint>, Vec<TransportEndpoint>) {
    endpoints.sort();
    endpoints.dedup();
    release_settled_key_package_deletion_overflow_owner(lifecycle);

    if lifecycle
        .deletion_overflow_owner_event_id
        .as_ref()
        .is_some_and(|owner| owner != event_id)
    {
        return (Vec::new(), endpoints);
    }

    let additional_liabilities = endpoints
        .iter()
        .filter(|endpoint| !key_package_event_endpoint_is_liability(lifecycle, event_id, endpoint))
        .count();
    let projected = key_package_signed_publication_liability_count(lifecycle)
        .saturating_add(additional_liabilities);
    if projected > MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES_WITH_LIVE_DELETION_OVERFLOW {
        return (Vec::new(), endpoints);
    }
    if projected > MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES
        && lifecycle.deletion_overflow_owner_event_id.is_none()
    {
        lifecycle.deletion_overflow_owner_event_id = Some(event_id.clone());
    }

    let liability_limit = if lifecycle.deletion_overflow_owner_event_id.as_ref() == Some(event_id) {
        MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES_WITH_LIVE_DELETION_OVERFLOW
    } else {
        MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES
    };
    let (admitted, deferred) = admit_manual_key_package_deletion_liabilities(
        lifecycle,
        event_id,
        endpoints,
        liability_limit,
    );
    debug_assert!(
        deferred.is_empty(),
        "atomic exact deletion was preflighted against its complete endpoint set"
    );
    (admitted, deferred)
}

fn release_settled_key_package_deletion_overflow_owner(lifecycle: &mut KeyPackageLifecycleState) {
    let owner_is_settled = lifecycle
        .deletion_overflow_owner_event_id
        .as_ref()
        .is_some_and(|owner| {
            !lifecycle
                .retired_publications_pending_deletion
                .iter()
                .any(|retired| {
                    retired.event_id == *owner
                        && retired.deletion_targets.iter().any(|target| {
                            target.failure_code.as_deref() != Some("confirmed_absent")
                        })
                })
        });
    if owner_is_settled {
        lifecycle.deletion_overflow_owner_event_id = None;
    }
}

fn retain_retired_key_package_publication(
    lifecycle: &mut KeyPackageLifecycleState,
    retired: RetiredKeyPackagePublication,
) {
    if let Some(existing) = lifecycle
        .retired_publications_pending_deletion
        .iter_mut()
        .find(|existing| existing.event_id == retired.event_id)
    {
        if existing.key_package_ref.is_none() {
            existing.key_package_ref = retired.key_package_ref;
        }
        existing.package_not_after = match (existing.package_not_after, retired.package_not_after) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left @ Some(_), None) | (None, left @ Some(_)) => left,
            (None, None) => None,
        };
        existing.delete_without_successor |= retired.delete_without_successor;
        for target in retired.deletion_targets {
            if !existing
                .deletion_targets
                .iter()
                .any(|existing| existing.endpoint == target.endpoint)
            {
                existing.deletion_targets.push(target);
            }
        }
        existing
            .deletion_targets
            .sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
        return;
    }
    lifecycle
        .retired_publications_pending_deletion
        .push(retired);
    lifecycle
        .retired_publications_pending_deletion
        .sort_by(|left, right| {
            left.authored_created_at
                .cmp(&right.authored_created_at)
                .then_with(|| left.event_id.as_slice().cmp(right.event_id.as_slice()))
        });
}

fn mark_retired_key_package_revisions_unusable(
    lifecycle: &mut KeyPackageLifecycleState,
    key_package_ref: &[u8],
) {
    for retired in &mut lifecycle.retired_publications_pending_deletion {
        if retired.key_package_ref.as_deref() == Some(key_package_ref) {
            retired.delete_without_successor = true;
        }
    }
}

/// Consume the ambiguous legacy single-ref marker by retiring every semantic
/// KeyPackage it could have overwritten evidence for.
///
/// OpenMLS intentionally retains last-resort KeyPackage bundles after a
/// Welcome, so local bundle presence cannot distinguish an unconsumed package
/// from one whose older marker was overwritten. This one-time upgrade path
/// therefore chooses privacy over availability and forces a fresh package.
fn retire_legacy_only_consumption_projections(
    lifecycle: &mut KeyPackageLifecycleState,
    now: Timestamp,
) -> Vec<KeyPackage> {
    let mut retired_private_material = Vec::new();
    let mut projected_refs = lifecycle.consumed_key_package_refs.clone();
    let mut authored_high_water = lifecycle.authored_event_created_at;

    if let Some(retired_publication) = retired_current_key_package_publication(lifecycle, true) {
        retain_retired_key_package_publication(lifecycle, retired_publication);
    }
    if let Some(key_package_ref) = lifecycle.current_key_package_ref.clone() {
        projected_refs.push(key_package_ref);
    }
    if let Some(created_at) = lifecycle
        .authored_signed_event
        .as_ref()
        .map(|artifact| artifact.created_at)
    {
        authored_high_water = Some(
            authored_high_water
                .map(|current| current.max(created_at))
                .unwrap_or(created_at),
        );
    }
    if let Some(key_package) = lifecycle.current_key_package.take() {
        retain_key_package_for_private_material_retirement(
            &mut retired_private_material,
            key_package,
        );
    }
    lifecycle.current_key_package_ref = None;
    lifecycle.current_not_before = None;
    lifecycle.current_not_after = None;
    lifecycle.authored_event_id = None;
    lifecycle.authored_signed_event = None;
    lifecycle.publication_targets.clear();

    if let Some(pending) = lifecycle.pending_replacement.take() {
        let pending_created_at = pending
            .signed_event
            .as_ref()
            .map(|artifact| artifact.created_at)
            .unwrap_or(pending.authored_created_at);
        authored_high_water = Some(
            authored_high_water
                .map(|current| current.max(pending_created_at))
                .unwrap_or(pending_created_at),
        );
        if let Some(retired_publication) = pending.signed_event.as_ref().and_then(|artifact| {
            retired_key_package_publication(
                artifact,
                Some(&pending.key_package_ref),
                Some(pending.not_after),
                true,
                &pending.targets,
            )
        }) {
            retain_retired_key_package_publication(lifecycle, retired_publication);
        }
        projected_refs.push(pending.key_package_ref);
        retain_key_package_for_private_material_retirement(
            &mut retired_private_material,
            pending.key_package,
        );
    }

    for retained in std::mem::take(&mut lifecycle.retained_private_material) {
        projected_refs.push(retained.key_package_ref);
        retain_key_package_for_private_material_retirement(
            &mut retired_private_material,
            retained.key_package,
        );
    }
    projected_refs.sort();
    projected_refs.dedup();
    for key_package_ref in projected_refs {
        mark_retired_key_package_revisions_unusable(lifecycle, &key_package_ref);
    }

    lifecycle.authored_event_created_at = authored_high_water;
    lifecycle.refresh_at = Some(now);
    lifecycle.phase = MaintenancePhase::Retry;
    lifecycle.consumed_key_package_refs.clear();
    lifecycle.last_consumed_key_package_ref = None;
    lifecycle.last_consumed_at = None;
    retain_only_live_deleted_key_package_revision_ids(lifecycle);
    retired_private_material
}

fn retain_key_package_for_private_material_retirement(
    retired: &mut Vec<KeyPackage>,
    key_package: KeyPackage,
) {
    if !retired.contains(&key_package) {
        retired.push(key_package);
    }
}

fn key_package_ref_has_live_private_material(
    lifecycle: &KeyPackageLifecycleState,
    key_package_ref: &[u8],
) -> bool {
    lifecycle.current_key_package_ref.as_deref() == Some(key_package_ref)
        || lifecycle
            .pending_replacement
            .as_ref()
            .is_some_and(|pending| pending.key_package_ref == key_package_ref)
        || lifecycle
            .retained_private_material
            .iter()
            .any(|retained| retained.key_package_ref == key_package_ref)
}

fn retain_only_live_deleted_key_package_revision_ids(lifecycle: &mut KeyPackageLifecycleState) {
    let current_event_id = lifecycle
        .authored_signed_event
        .as_ref()
        .map(|artifact| artifact.id.clone())
        .or_else(|| lifecycle.authored_event_id.clone());
    let pending_event_id = lifecycle
        .pending_replacement
        .as_ref()
        .and_then(|pending| pending.signed_event.as_ref())
        .map(|artifact| artifact.id.clone());
    lifecycle
        .deleted_live_revision_event_ids
        .retain(|event_id| {
            current_event_id.as_ref() == Some(event_id)
                || pending_event_id.as_ref() == Some(event_id)
        });
}

fn mark_live_key_package_revision_endpoints_absent(
    lifecycle: &mut KeyPackageLifecycleState,
    event_id: &cgka_traits::MessageId,
    endpoints: &[TransportEndpoint],
) {
    if endpoints.is_empty() {
        return;
    }
    if lifecycle
        .authored_signed_event
        .as_ref()
        .is_some_and(|artifact| artifact.id == *event_id)
        || lifecycle.authored_event_id.as_ref() == Some(event_id)
    {
        for target in &mut lifecycle.publication_targets {
            if endpoints.contains(&target.endpoint) {
                target.state = TransportFanoutAttemptState::AttemptedFailed;
                target.failure_code = Some("confirmed_absent".into());
            }
        }
    }
    if let Some(pending) = lifecycle.pending_replacement.as_mut()
        && pending
            .signed_event
            .as_ref()
            .is_some_and(|artifact| artifact.id == *event_id)
    {
        for target in &mut pending.targets {
            if endpoints.contains(&target.endpoint) {
                target.state = TransportFanoutAttemptState::AttemptedFailed;
                target.failure_code = Some("confirmed_absent".into());
            }
        }
    }
}

fn key_package_signed_publication_liability_count(lifecycle: &KeyPackageLifecycleState) -> usize {
    let mut liabilities = HashSet::new();
    for retired in &lifecycle.retired_publications_pending_deletion {
        insert_key_package_endpoint_liabilities(
            &mut liabilities,
            &retired.event_id,
            &retired.deletion_targets,
        );
    }
    if let Some(event_id) = lifecycle
        .authored_signed_event
        .as_ref()
        .map(|artifact| &artifact.id)
        .or(lifecycle.authored_event_id.as_ref())
    {
        insert_key_package_endpoint_liabilities(
            &mut liabilities,
            event_id,
            &lifecycle.publication_targets,
        );
    }
    if let Some(pending) = lifecycle.pending_replacement.as_ref()
        && let Some(artifact) = pending.signed_event.as_ref()
    {
        insert_key_package_endpoint_liabilities(&mut liabilities, &artifact.id, &pending.targets);
    }
    liabilities.len()
}

fn projected_current_key_package_reauthor_liability_count(
    lifecycle: &KeyPackageLifecycleState,
    retired_publication: Option<&RetiredKeyPackagePublication>,
    live_endpoints: &[TransportEndpoint],
) -> usize {
    let mut projected = lifecycle.clone();
    if let Some(retired_publication) = retired_publication {
        retain_retired_key_package_publication(&mut projected, retired_publication.clone());
    }
    let projected_event_id = unused_projected_key_package_event_id(&projected);
    projected.authored_event_id = Some(projected_event_id.clone());
    projected.authored_signed_event = Some(SignedPublicationArtifact {
        id: projected_event_id,
        created_at: Timestamp(0),
        bytes: Vec::new(),
    });
    replace_key_package_publication_targets(&mut projected.publication_targets, live_endpoints);
    key_package_signed_publication_liability_count(&projected)
}

fn projected_pending_key_package_reauthor_liability_count(
    lifecycle: &KeyPackageLifecycleState,
    retired_publication: Option<&RetiredKeyPackagePublication>,
    live_endpoints: &[TransportEndpoint],
) -> usize {
    let mut projected = lifecycle.clone();
    if let Some(retired_publication) = retired_publication {
        retain_retired_key_package_publication(&mut projected, retired_publication.clone());
    }
    let projected_event_id = unused_projected_key_package_event_id(&projected);
    if let Some(pending) = projected.pending_replacement.as_mut() {
        pending.signed_event = Some(SignedPublicationArtifact {
            id: projected_event_id,
            created_at: Timestamp(0),
            bytes: Vec::new(),
        });
        replace_key_package_publication_targets(&mut pending.targets, live_endpoints);
    }
    key_package_signed_publication_liability_count(&projected)
}

/// Model a future signed revision in capacity projections without depending on
/// its not-yet-authored hash. The synthetic id never leaves memory and is
/// chosen outside every identity currently represented in the lifecycle.
fn unused_projected_key_package_event_id(lifecycle: &KeyPackageLifecycleState) -> MessageId {
    let event_id_is_used = |candidate: &[u8]| {
        lifecycle
            .authored_signed_event
            .as_ref()
            .is_some_and(|artifact| artifact.id.as_slice() == candidate)
            || lifecycle
                .authored_event_id
                .as_ref()
                .is_some_and(|event_id| event_id.as_slice() == candidate)
            || lifecycle
                .pending_replacement
                .as_ref()
                .and_then(|pending| pending.signed_event.as_ref())
                .is_some_and(|artifact| artifact.id.as_slice() == candidate)
            || lifecycle
                .retired_publications_pending_deletion
                .iter()
                .any(|retired| retired.event_id.as_slice() == candidate)
    };
    let mut candidate = vec![0_u8; 33];
    while event_id_is_used(&candidate) {
        candidate.push(0);
    }
    MessageId::new(candidate)
}

fn key_package_event_endpoint_is_liability(
    lifecycle: &KeyPackageLifecycleState,
    event_id: &cgka_traits::MessageId,
    endpoint: &TransportEndpoint,
) -> bool {
    let target_is_liability = |target: &TransportFanoutTarget| {
        target.endpoint == *endpoint && target.failure_code.as_deref() != Some("confirmed_absent")
    };
    lifecycle
        .retired_publications_pending_deletion
        .iter()
        .any(|retired| {
            retired.event_id == *event_id
                && retired.deletion_targets.iter().any(target_is_liability)
        })
        || (lifecycle
            .authored_signed_event
            .as_ref()
            .map(|artifact| &artifact.id)
            .or(lifecycle.authored_event_id.as_ref())
            == Some(event_id)
            && lifecycle
                .publication_targets
                .iter()
                .any(target_is_liability))
        || lifecycle
            .pending_replacement
            .as_ref()
            .is_some_and(|pending| {
                pending
                    .signed_event
                    .as_ref()
                    .is_some_and(|artifact| artifact.id == *event_id)
                    && pending.targets.iter().any(target_is_liability)
            })
}

fn insert_key_package_endpoint_liabilities(
    liabilities: &mut HashSet<(Vec<u8>, TransportEndpoint)>,
    event_id: &cgka_traits::MessageId,
    targets: &[TransportFanoutTarget],
) {
    for target in targets {
        if target.failure_code.as_deref() != Some("confirmed_absent") {
            liabilities.insert((event_id.as_slice().to_vec(), target.endpoint.clone()));
        }
    }
}

fn retired_key_package_deletion_target_is_eligible(
    lifecycle: &KeyPackageLifecycleState,
    retired: &RetiredKeyPackagePublication,
    target: &TransportFanoutTarget,
    now: Timestamp,
) -> bool {
    if retired.delete_without_successor
        || retired
            .package_not_after
            .is_some_and(|not_after| not_after <= now)
    {
        return true;
    }
    let Some(current_artifact) = lifecycle.authored_signed_event.as_ref() else {
        return false;
    };
    if current_artifact.created_at <= retired.authored_created_at {
        return false;
    }
    match lifecycle
        .publication_targets
        .iter()
        .find(|current| current.endpoint == target.endpoint)
    {
        Some(current) => matches!(
            current.state,
            TransportFanoutAttemptState::Accepted | TransportFanoutAttemptState::PolicyProhibited
        ),
        None => true,
    }
}

fn retired_key_package_deletion_pass_report(
    lifecycle: &KeyPackageLifecycleState,
    now: Timestamp,
    mut terminal_endpoints: Vec<TransportEndpoint>,
) -> RetiredKeyPackageDeletionPassReport {
    terminal_endpoints.sort();
    terminal_endpoints.dedup();
    let has_uncovered_eligible_deletion = lifecycle
        .retired_publications_pending_deletion
        .iter()
        .any(|retired| {
            retired.deletion_targets.iter().any(|target| {
                retired_key_package_deletion_target_is_eligible(lifecycle, retired, target, now)
                    && !retired_key_package_deletion_target_has_accepted_newer_successor(
                        lifecycle, retired, target,
                    )
            })
        });
    RetiredKeyPackageDeletionPassReport {
        terminal_endpoints,
        has_uncovered_eligible_deletion,
    }
}

fn retired_key_package_deletion_target_has_accepted_newer_successor(
    lifecycle: &KeyPackageLifecycleState,
    retired: &RetiredKeyPackagePublication,
    target: &TransportFanoutTarget,
) -> bool {
    let Some(current_artifact) = lifecycle.authored_signed_event.as_ref() else {
        return false;
    };
    if current_artifact.created_at <= retired.authored_created_at
        || lifecycle
            .deleted_live_revision_event_ids
            .contains(&current_artifact.id)
    {
        return false;
    }
    lifecycle.publication_targets.iter().any(|current| {
        current.endpoint == target.endpoint
            && current.state == TransportFanoutAttemptState::Accepted
    })
}

/// Persist this before awaiting transport. A crash after the socket send then
/// leaves durable possible-exposure evidence instead of an `Unattempted` lie.
fn begin_key_package_attempt(
    targets: &mut [TransportFanoutTarget],
    attempted: &[TransportEndpoint],
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
        target.state = TransportFanoutAttemptState::AttemptedFailed;
        target.failure_code = Some("possible_exposure".into());
    }
}

/// Constrain an untrusted publication receipt to the exact fanout attempted by
/// this call. A category may mention an endpoint at most once, and stronger
/// evidence wins when a malformed adapter reports the same endpoint in more
/// than one category. `confirmed_absent` is deletion-only evidence: a kind
/// 30443 publication adapter cannot prove that no older delivery exists, so
/// such a claim is conservatively demoted to an ambiguous failure.
fn scope_key_package_publish_receipt(
    mut receipt: crate::key_package::DetailedKeyPackagePublishReceipt,
    attempted: &[TransportEndpoint],
) -> crate::key_package::DetailedKeyPackagePublishReceipt {
    let scope = attempted.iter().cloned().collect::<HashSet<_>>();
    let normalize = |endpoints: &mut Vec<TransportEndpoint>| {
        endpoints.retain(|endpoint| scope.contains(endpoint));
        endpoints.sort();
        endpoints.dedup();
    };
    normalize(&mut receipt.accepted);
    normalize(&mut receipt.confirmed_absent);
    normalize(&mut receipt.rejected);
    normalize(&mut receipt.failed);
    receipt
        .rejected
        .retain(|endpoint| !receipt.accepted.contains(endpoint));
    receipt.failed.append(&mut receipt.confirmed_absent);
    receipt.failed.sort();
    receipt.failed.dedup();
    receipt.failed.retain(|endpoint| {
        !receipt.accepted.contains(endpoint) && !receipt.rejected.contains(endpoint)
    });
    receipt
}

fn finish_key_package_attempt(
    targets: &mut [TransportFanoutTarget],
    accepted: &[TransportEndpoint],
    rejected: &[TransportEndpoint],
    confirmed_absent: &[TransportEndpoint],
    failed: &[TransportEndpoint],
) {
    for target in targets {
        if target.state == TransportFanoutAttemptState::Accepted {
            continue;
        }
        if accepted.contains(&target.endpoint) {
            target.state = TransportFanoutAttemptState::Accepted;
            target.failure_code = None;
        } else if confirmed_absent.contains(&target.endpoint) {
            target.state = TransportFanoutAttemptState::AttemptedFailed;
            target.failure_code = Some("confirmed_absent".into());
        } else if rejected.contains(&target.endpoint) {
            target.state = TransportFanoutAttemptState::AttemptedFailed;
            // A negative publication ACK does not prove absence. Older
            // clients did not persist a pre-I/O marker, so a durable
            // `Unattempted` row may already have escaped to this relay before
            // a crash. Only a deletion-specific NotFound receipt is terminal.
            target.failure_code = Some("transport_rejected".into());
        } else if failed.contains(&target.endpoint) {
            // The pre-I/O marker is already the conservative terminal state
            // for a timeout, disconnect, or other ambiguous transport result.
            target.state = TransportFanoutAttemptState::AttemptedFailed;
            target.failure_code = Some("possible_exposure".into());
        }
    }
}

fn key_package_target_retry_due(target: &TransportFanoutTarget, now: Timestamp) -> bool {
    if !key_package_target_is_retryable(target) {
        return false;
    }
    transport_fanout_target_retry_due(target, now)
}

fn key_package_target_is_terminal(target: &TransportFanoutTarget) -> bool {
    matches!(
        target.state,
        TransportFanoutAttemptState::Accepted | TransportFanoutAttemptState::PolicyProhibited
    ) || target.failure_code.as_deref() == Some("confirmed_absent")
}

fn key_package_target_is_retryable(target: &TransportFanoutTarget) -> bool {
    !key_package_target_is_terminal(target)
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

/// Pull Welcome payloads off publish work so the commit/create can confirm
/// without waiting for recipient delivery. Empty Welcome vectors remain on the
/// original work items so later publish still confirms the commit.
fn take_deferred_welcomes(effects: &mut SessionEffects) -> Vec<TransportMessage> {
    let mut welcomes = Vec::new();
    for work in &mut effects.publish {
        match work {
            PublishWork::GroupEvolution {
                welcomes: items, ..
            }
            | PublishWork::GroupCreated {
                welcomes: items, ..
            }
            | PublishWork::FoundingGroupCreated { welcomes: items } => {
                welcomes.append(items);
            }
            _ => {}
        }
    }
    welcomes
}

fn supports_deferred_commit_publish(intent: &SendIntent) -> bool {
    matches!(
        intent,
        SendIntent::Invite { .. }
            | SendIntent::RemoveMembers { .. }
            | SendIntent::SelfUpdate { .. }
            | SendIntent::UpdateAppComponents { .. }
            | SendIntent::UpdateGroupData { .. }
            | SendIntent::EnableDisbanding { .. }
    )
}

fn send_intent_group_id(intent: &SendIntent) -> Option<GroupId> {
    Some(match intent {
        SendIntent::AppMessage { group_id, .. }
        | SendIntent::Invite { group_id, .. }
        | SendIntent::RemoveMembers { group_id, .. }
        | SendIntent::Leave { group_id }
        | SendIntent::SelfUpdate { group_id }
        | SendIntent::UpdateAppComponents { group_id, .. }
        | SendIntent::UpdateGroupData { group_id, .. }
        | SendIntent::EnableDisbanding { group_id }
        | SendIntent::Disband { group_id } => group_id.clone(),
    })
}

fn account_visibility_outbound_action(
    intent: &SendIntent,
) -> Option<AccountVisibilityOutboundAction> {
    match intent {
        SendIntent::Leave { .. } => Some(AccountVisibilityOutboundAction::Leave),
        _ => None,
    }
}

fn outbound_action_message_id(
    action: AccountVisibilityOutboundAction,
    effects: &SessionEffects,
) -> Option<MessageId> {
    match action {
        AccountVisibilityOutboundAction::Leave => effects.publish.iter().find_map(|work| {
            if let PublishWork::Proposal { msg, .. } = work {
                Some(msg.id.clone())
            } else {
                None
            }
        }),
    }
}

fn engine_outbox_event_id(event: &GroupEvent) -> Option<MessageId> {
    match event {
        GroupEvent::MessageReceived { message_id, .. } => Some(message_id.clone()),
        GroupEvent::GroupJoined { via_welcome, .. } => Some(via_welcome.clone()),
        _ => None,
    }
}

fn classify_prepared_session_send(
    mut effects: SessionEffects,
) -> AccountResult<PreparedSessionSend> {
    let pending = effects.publish.iter().find_map(|work| match work {
        PublishWork::GroupEvolution { pending, .. } | PublishWork::GroupCreated { pending, .. } => {
            Some(*pending)
        }
        _ => None,
    });
    let Some(pending) = pending else {
        if !effects.queued.is_empty() {
            return Ok(PreparedSessionSend::Queued(effects));
        }
        return Err(cgka_traits::EngineError::Backend(
            "prepared send contained neither a pending MLS evolution nor a queued intent".into(),
        )
        .into());
    };
    let welcomes = take_deferred_welcomes(&mut effects);
    Ok(PreparedSessionSend::Commit(PreparedSessionCommit {
        effects,
        welcomes,
        pending,
    }))
}

/// The welcome recipient carried in the message's transport envelope, if the
/// message is a welcome.
fn welcome_recipient(message: &TransportMessage) -> Option<MemberId> {
    match &message.envelope {
        TransportEnvelope::Welcome { recipient } => Some(recipient.clone()),
        TransportEnvelope::GroupMessage { .. } => None,
    }
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

/// Outbound action whose app-side tail must retain source semantics across
/// cancellation and process restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountVisibilityOutboundAction {
    Leave,
}

/// Terminal publish result for a source-attributed outbound action.
///
/// `operation_id` names the original operation whose Header remains pending;
/// recovery may carry this outcome in a later Drain operation after resuming
/// the exact frozen fanout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountVisibilityActionOutcome {
    pub operation_id: Vec<u8>,
    pub group_id: GroupId,
    pub message_id: MessageId,
    pub action: AccountVisibilityOutboundAction,
    pub published: bool,
}

/// Fixed attribution for one durable visibility operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum AccountVisibilitySource {
    Inbound {
        delivery: TransportDelivery,
        outcome: IngestOutcome,
        observed_at: Timestamp,
    },
    Drain {
        observed_at: Timestamp,
    },
    Convergence {
        group_id: GroupId,
        observed_at: Timestamp,
    },
    Maintenance {
        observed_at: Timestamp,
    },
    Outbound {
        group_id: Option<GroupId>,
        observed_at: Timestamp,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action: Option<AccountVisibilityOutboundAction>,
        /// Exact engine message id bound atomically after acceptance and before
        /// relay I/O. A pending pre-acceptance Header leaves this absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action_message_id: Option<MessageId>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountVisibilityRecordKind {
    Header,
    Event { engine_outbox_provenance: bool },
    SessionControl,
    NonSession,
}

/// One independently acknowledgeable, source-attributed durable visibility row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountVisibilityBatch {
    pub sequence: u64,
    pub operation_id: Vec<u8>,
    pub batch_id: Vec<u8>,
    pub source: AccountVisibilitySource,
    pub kind: AccountVisibilityRecordKind,
    pub effects: AccountDeviceEffects,
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
    /// Exact signed events retained because publication completion is not yet
    /// known. This is a typed non-failure result: callers must not create a
    /// semantically new send to recover it.
    pub unresolved_publishes: Vec<UnresolvedPublish>,
    /// Application-message identity attached to unresolved publication so app
    /// consumers can keep exactly the affected local row in a sending state.
    pub unresolved_app_messages: Vec<UnresolvedApplicationMessage>,
    /// Terminal source-action results, including recovered fanouts whose
    /// originating visibility Header belongs to an older operation.
    pub action_outcomes: Vec<AccountVisibilityActionOutcome>,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedApplicationMessage {
    pub group_id: GroupId,
    pub app_event_id: String,
    pub message_id: cgka_traits::MessageId,
    pub source_epoch: EpochId,
    pub retention: cgka_traits::app_event::AppMessageRetentionDecision,
}

impl AccountDeviceEffects {
    fn non_session_visibility_clone(&self) -> Self {
        Self {
            reports: self.reports.clone(),
            fanout: self.fanout.clone(),
            failures: self.failures.clone(),
            unresolved_publishes: self.unresolved_publishes.clone(),
            unresolved_app_messages: self.unresolved_app_messages.clone(),
            action_outcomes: self.action_outcomes.clone(),
            published_app_messages: self.published_app_messages.clone(),
            welcome_failures: self.welcome_failures.clone(),
            pending: self.pending.clone(),
            maintenance_disposition: self.maintenance_disposition,
            ..Self::default()
        }
    }

    fn extend(&mut self, mut other: Self) {
        self.fanout.append(&mut other.fanout);
        self.absorb_account_effects(other);
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
        self.unresolved_publishes
            .append(&mut other.unresolved_publishes);
        self.unresolved_app_messages
            .append(&mut other.unresolved_app_messages);
        self.action_outcomes.append(&mut other.action_outcomes);
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

impl StoredNonSessionEffectsV1 {
    fn from_effects(effects: &AccountDeviceEffects) -> Self {
        Self {
            reports: effects.reports.clone(),
            fanout: effects.fanout.clone(),
            failures: effects.failures.clone(),
            action_outcomes: effects.action_outcomes.clone(),
            published_app_messages: effects.published_app_messages.clone(),
            welcome_failures: effects.welcome_failures.clone(),
            pending: effects.pending.clone(),
        }
    }

    fn into_effects(self) -> AccountDeviceEffects {
        AccountDeviceEffects {
            reports: self.reports,
            fanout: self.fanout,
            failures: self.failures,
            action_outcomes: self.action_outcomes,
            published_app_messages: self.published_app_messages,
            welcome_failures: self.welcome_failures,
            pending: self.pending,
            ..AccountDeviceEffects::default()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountIngestEffects {
    pub outcome: IngestOutcome,
    /// The engine kept no durable trace of this delivery's transport object.
    /// Carried verbatim from [`IngestEffects::left_object_unpersisted`].
    pub left_object_unpersisted: bool,
    pub effects: AccountDeviceEffects,
}

/// Account effects retained by [`AccountDeviceRuntime`] until the app
/// explicitly acknowledges projection/V1 ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "acknowledge `lease` only after the effects are durably staged"]
pub struct LeasedAccountDeviceEffects {
    pub effects: AccountDeviceEffects,
    pub batches: Vec<AccountVisibilityBatch>,
    pub lease: AccountVisibilityLease,
    /// Operation produced by the command that returned this lease. `None`
    /// identifies replay-only handoffs, where every batch predates the caller.
    pub current_operation_id: Option<Vec<u8>>,
}

/// Ingest outcome plus account effects retained until the app explicitly
/// acknowledges projection/V1 ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "acknowledge `lease` only after the effects are durably staged"]
pub struct LeasedAccountIngestEffects {
    pub outcome: IngestOutcome,
    /// The engine kept no durable trace of this delivery's transport object.
    /// Carried verbatim from [`AccountIngestEffects::left_object_unpersisted`].
    pub left_object_unpersisted: bool,
    pub effects: AccountDeviceEffects,
    pub batches: Vec<AccountVisibilityBatch>,
    pub lease: AccountVisibilityLease,
    /// Operation produced by the inbound delivery that returned this lease.
    pub current_operation_id: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishFailure {
    pub message_id: cgka_traits::MessageId,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnresolvedPublishReason {
    AcknowledgementUnknown,
    RetryableUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnresolvedPublish {
    pub message_id: cgka_traits::MessageId,
    pub reason: UnresolvedPublishReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnresolvedApplicationMessage {
    pub group_id: GroupId,
    pub app_event_id: String,
    pub message_id: cgka_traits::MessageId,
    pub reason: UnresolvedPublishReason,
}

/// A welcome left undelivered by a confirmed group create/evolution (mdk#352).
///
/// The added member cannot join until the welcome reaches them, and the commit
/// cannot be rolled back (it is already confirmed and externally visible), so
/// re-delivery is the only repair. The wrapped welcome stays available in the
/// engine's sent-message store under `message_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeDeliveryFailure {
    pub message_id: cgka_traits::MessageId,
    pub recipient: MemberId,
    /// From the already-known confirmation or stored sent-welcome record;
    /// best-effort.
    pub group_id: Option<GroupId>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingResolution {
    Confirmed { pending: PendingStateRef },
    RolledBack { pending: PendingStateRef },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_artifact_at(created_at: u64) -> SignedPublicationArtifact {
        SignedPublicationArtifact {
            id: cgka_traits::MessageId::new(created_at.to_be_bytes().to_vec()),
            created_at: Timestamp(created_at),
            bytes: created_at.to_be_bytes().to_vec(),
        }
    }

    #[test]
    fn key_package_reauthor_policy_is_opt_in_and_uses_an_inclusive_age_boundary() {
        let artifact = signed_artifact_at(10_000);
        assert_eq!(
            key_package_reauthor_created_at(&artifact, Timestamp(1), None, None, false),
            Ok(None),
            "publishers that do not opt in preserve exact retries across clock rollback"
        );
        assert_eq!(
            key_package_reauthor_created_at(&artifact, Timestamp(10_599), Some(600), None, false),
            Ok(None)
        );
        assert_eq!(
            key_package_reauthor_created_at(&artifact, Timestamp(10_600), Some(600), None, false),
            Ok(Some(Timestamp(10_600)))
        );
        assert_eq!(
            key_package_reauthor_created_at(&artifact, Timestamp(1), Some(600), None, false),
            Err(()),
            "an opted-in transport fails closed after a large wall-clock rollback"
        );
        assert_eq!(
            key_package_reauthor_created_at(
                &artifact,
                Timestamp(10_000),
                None,
                Some(Timestamp(10_020)),
                false,
            ),
            Ok(Some(Timestamp(10_021))),
            "a relay-discovered same-slot high-water forces a strictly newer revision"
        );
        assert_eq!(
            key_package_reauthor_created_at(
                &signed_artifact_at(u64::MAX),
                Timestamp(u64::MAX),
                Some(0),
                None,
                false,
            ),
            Err(()),
            "a strictly newer timestamp must be representable"
        );
    }

    #[test]
    fn reauthor_replacement_targets_only_the_current_live_policy() {
        let prohibited_endpoint = TransportEndpoint("wss://removed.example".into());
        let live_endpoint = TransportEndpoint("wss://live.example".into());
        let mut targets = vec![
            TransportFanoutTarget {
                endpoint: prohibited_endpoint.clone(),
                state: TransportFanoutAttemptState::PolicyProhibited,
                attempt_count: 7,
                last_attempt_at: Some(Timestamp(9)),
                failure_code: Some("endpoint_removed_from_policy".into()),
            },
            TransportFanoutTarget {
                endpoint: live_endpoint.clone(),
                state: TransportFanoutAttemptState::Accepted,
                attempt_count: 3,
                last_attempt_at: Some(Timestamp(8)),
                failure_code: None,
            },
        ];

        replace_key_package_publication_targets(&mut targets, std::slice::from_ref(&live_endpoint));

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].endpoint, live_endpoint);
        assert_eq!(targets[0].state, TransportFanoutAttemptState::Unattempted);
        assert_eq!(targets[0].attempt_count, 0);
        assert!(targets[0].last_attempt_at.is_none());
        assert!(targets[0].failure_code.is_none());
    }

    #[test]
    fn retired_key_package_publication_keeps_every_possibly_exposed_target() {
        let artifact = signed_artifact_at(10);
        let target =
            |endpoint: &str,
             state: TransportFanoutAttemptState,
             attempt_count: u32,
             last_attempt_at: Option<Timestamp>| TransportFanoutTarget {
                endpoint: TransportEndpoint(endpoint.into()),
                state,
                attempt_count,
                last_attempt_at,
                failure_code: None,
            };
        let retired = retired_key_package_publication(
            &artifact,
            Some(b"key-package-ref"),
            Some(Timestamp(20)),
            false,
            &[
                target(
                    "wss://accepted.example",
                    TransportFanoutAttemptState::Accepted,
                    1,
                    Some(Timestamp(1)),
                ),
                target(
                    "wss://failed.example",
                    TransportFanoutAttemptState::AttemptedFailed,
                    1,
                    Some(Timestamp(1)),
                ),
                target(
                    "wss://removed-after-attempt.example",
                    TransportFanoutAttemptState::PolicyProhibited,
                    2,
                    Some(Timestamp(2)),
                ),
                target(
                    "wss://never-attempted.example",
                    TransportFanoutAttemptState::Unattempted,
                    0,
                    None,
                ),
                target(
                    "wss://prohibited-before-attempt.example",
                    TransportFanoutAttemptState::PolicyProhibited,
                    0,
                    None,
                ),
            ],
        )
        .expect("attempted targets create a deletion obligation");

        assert_eq!(retired.event_id, artifact.id);
        assert_eq!(retired.authored_created_at, artifact.created_at);
        assert_eq!(
            retired.key_package_ref.as_deref(),
            Some(&b"key-package-ref"[..])
        );
        assert_eq!(retired.package_not_after, Some(Timestamp(20)));
        assert!(!retired.delete_without_successor);
        assert_eq!(
            retired
                .deletion_targets
                .iter()
                .map(|target| target.endpoint.clone())
                .collect::<Vec<_>>(),
            vec![
                TransportEndpoint("wss://accepted.example".into()),
                TransportEndpoint("wss://failed.example".into()),
                TransportEndpoint("wss://never-attempted.example".into()),
                TransportEndpoint("wss://prohibited-before-attempt.example".into()),
                TransportEndpoint("wss://removed-after-attempt.example".into()),
            ]
        );
        assert!(retired.deletion_targets.iter().all(|target| {
            target.state == TransportFanoutAttemptState::Unattempted
                && target.attempt_count == 0
                && target.last_attempt_at.is_none()
        }));
    }

    #[test]
    fn key_package_liability_counter_counts_each_event_endpoint_pair() {
        let endpoints = (0..256)
            .map(|index| TransportFanoutTarget {
                endpoint: TransportEndpoint(format!("wss://liability-{index}.example")),
                state: TransportFanoutAttemptState::Unattempted,
                attempt_count: 0,
                last_attempt_at: None,
                failure_code: None,
            })
            .collect::<Vec<_>>();
        let mut lifecycle = KeyPackageLifecycleState::slot_only("slot".into());
        lifecycle
            .retired_publications_pending_deletion
            .push(RetiredKeyPackagePublication {
                event_id: cgka_traits::MessageId::new(vec![0x73; 32]),
                authored_created_at: Timestamp(1),
                key_package_ref: None,
                package_not_after: None,
                delete_without_successor: true,
                deletion_targets: endpoints,
            });

        assert_eq!(
            key_package_signed_publication_liability_count(&lifecycle),
            MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES
        );
    }

    #[test]
    fn deletion_pass_report_dedupes_terminals_and_ignores_backoff_for_uncovered_work() {
        let covered_endpoint = TransportEndpoint("wss://covered.example".into());
        let uncovered_endpoint = TransportEndpoint("wss://uncovered.example".into());
        let deletion_target = |endpoint: TransportEndpoint| TransportFanoutTarget {
            endpoint,
            state: TransportFanoutAttemptState::AttemptedFailed,
            attempt_count: 9,
            last_attempt_at: Some(Timestamp(50)),
            failure_code: Some("possible_exposure".into()),
        };
        let current_artifact = signed_artifact_at(20);
        let mut lifecycle = KeyPackageLifecycleState::slot_only("slot".into());
        lifecycle.authored_signed_event = Some(current_artifact.clone());
        lifecycle.publication_targets = vec![
            TransportFanoutTarget {
                endpoint: covered_endpoint.clone(),
                state: TransportFanoutAttemptState::Accepted,
                attempt_count: 1,
                last_attempt_at: Some(Timestamp(20)),
                failure_code: None,
            },
            TransportFanoutTarget {
                endpoint: uncovered_endpoint.clone(),
                state: TransportFanoutAttemptState::PolicyProhibited,
                attempt_count: 0,
                last_attempt_at: None,
                failure_code: Some("endpoint_removed_from_policy".into()),
            },
        ];
        lifecycle
            .retired_publications_pending_deletion
            .push(RetiredKeyPackagePublication {
                event_id: MessageId::new(vec![0x7a; 32]),
                authored_created_at: Timestamp(10),
                key_package_ref: None,
                package_not_after: Some(Timestamp(1_000)),
                delete_without_successor: false,
                deletion_targets: vec![
                    deletion_target(covered_endpoint.clone()),
                    deletion_target(uncovered_endpoint.clone()),
                ],
            });

        let report = retired_key_package_deletion_pass_report(
            &lifecycle,
            Timestamp(50),
            vec![covered_endpoint.clone(), covered_endpoint.clone()],
        );
        assert_eq!(report.terminal_endpoints, vec![covered_endpoint]);
        assert!(
            report.has_uncovered_eligible_deletion,
            "a policy-removed target remains eligible without an accepted successor even during retry backoff"
        );

        lifecycle.publication_targets[1].state = TransportFanoutAttemptState::Accepted;
        lifecycle.publication_targets[1].failure_code = None;
        assert!(
            !retired_key_package_deletion_pass_report(&lifecycle, Timestamp(50), Vec::new())
                .has_uncovered_eligible_deletion,
            "strictly newer accepted successors cover every eligible deletion"
        );

        lifecycle
            .deleted_live_revision_event_ids
            .push(current_artifact.id);
        assert!(
            retired_key_package_deletion_pass_report(&lifecycle, Timestamp(50), Vec::new())
                .has_uncovered_eligible_deletion,
            "a live revision already marked for deletion cannot cover its predecessors"
        );
    }

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

    #[test]
    fn prepared_send_preserves_a_durably_queued_invite() {
        let queued = QueuedIntentRef {
            group_id: GroupId::new(vec![7]),
            intent_id: cgka_traits::MessageId::new(vec![9]),
        };
        let classified = classify_prepared_session_send(SessionEffects {
            events: Vec::new(),
            publish: Vec::new(),
            queued: vec![queued.clone()],
            pending_convergence: vec![queued.group_id.clone()],
        })
        .expect("queued acceptance is not a malformed prepared commit");

        match classified {
            PreparedSessionSend::Queued(effects) => {
                assert_eq!(effects.queued, vec![queued]);
                assert_eq!(effects.pending_convergence.len(), 1);
            }
            PreparedSessionSend::Commit(_) => panic!("queued invite must not pretend to be staged"),
        }
    }

    #[test]
    fn deferred_publish_boundary_rejects_non_commit_intents() {
        let group_id = GroupId::new(vec![1]);
        assert!(!supports_deferred_commit_publish(&SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: Vec::new(),
        }));
        assert!(!supports_deferred_commit_publish(&SendIntent::Leave {
            group_id: group_id.clone(),
        }));
        assert!(supports_deferred_commit_publish(
            &SendIntent::RemoveMembers {
                group_id,
                members: Vec::new(),
            }
        ));
    }

    #[test]
    fn outbound_visibility_action_is_typed_and_legacy_json_defaults_to_none() {
        let group_id = GroupId::new(vec![7]);
        let source = AccountVisibilitySource::Outbound {
            group_id: Some(group_id.clone()),
            observed_at: Timestamp(42),
            action: Some(AccountVisibilityOutboundAction::Leave),
            action_message_id: Some(MessageId::new(vec![4])),
        };
        let mut json = serde_json::to_value(&source).expect("serialize outbound source");
        assert_eq!(json.get("action"), Some(&serde_json::json!("leave")));
        assert!(json.get("action_message_id").is_some());
        assert_eq!(
            serde_json::from_value::<AccountVisibilitySource>(json.clone())
                .expect("decode typed outbound action"),
            source
        );

        json.as_object_mut()
            .expect("tagged source is an object")
            .remove("action");
        json.as_object_mut()
            .expect("tagged source is an object")
            .remove("action_message_id");
        let legacy = serde_json::from_value::<AccountVisibilitySource>(json)
            .expect("legacy outbound source without action still decodes");
        assert_eq!(
            legacy,
            AccountVisibilitySource::Outbound {
                group_id: Some(group_id),
                observed_at: Timestamp(42),
                action: None,
                action_message_id: None,
            }
        );
        assert!(
            serde_json::to_value(legacy)
                .expect("serialize legacy-compatible source")
                .get("action")
                .is_none(),
            "None keeps the exact legacy JSON shape"
        );
    }

    #[test]
    fn legacy_outbound_visibility_record_decodes_without_a_version_bump() {
        let operation_id = [0x5a; 16];
        let group_id = GroupId::new(vec![8]);
        let record = StoredAccountVisibilityRecordV1 {
            version: ACCOUNT_VISIBILITY_RECORD_VERSION,
            source: AccountVisibilitySource::Outbound {
                group_id: Some(group_id.clone()),
                observed_at: Timestamp(77),
                action: Some(AccountVisibilityOutboundAction::Leave),
                action_message_id: Some(MessageId::new(vec![5])),
            },
            payload: StoredAccountVisibilityPayloadV1::Header {
                maintenance_disposition: SendMaintenanceDisposition::Ready,
            },
        };
        let mut json = serde_json::to_value(record).expect("serialize visibility record");
        json.get_mut("source")
            .and_then(serde_json::Value::as_object_mut)
            .expect("visibility source is an object")
            .remove("action");
        json.get_mut("source")
            .and_then(serde_json::Value::as_object_mut)
            .expect("visibility source is an object")
            .remove("action_message_id");
        assert_eq!(
            json.get("version"),
            Some(&serde_json::json!(1)),
            "adding source semantics must not bump the decodable V1 record"
        );

        let decoded = decode_account_visibility_row(AccountVisibilityJournalRow {
            sequence: 1,
            operation_id: operation_id.to_vec(),
            ordinal: 0,
            batch_id: account_visibility_batch_id(&operation_id, 0),
            record: serde_json::to_vec(&json).expect("encode legacy visibility row"),
        })
        .expect("decode legacy V1 visibility row");
        assert_eq!(decoded.kind, AccountVisibilityRecordKind::Header);
        assert_eq!(
            decoded.source,
            AccountVisibilitySource::Outbound {
                group_id: Some(group_id),
                observed_at: Timestamp(77),
                action: None,
                action_message_id: None,
            }
        );
    }

    #[tokio::test]
    async fn welcome_publish_work_is_bounded_concurrent_and_ordered() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::Semaphore;
        use tokio::time::{Duration, timeout};

        for item_count in [1, 5, 20] {
            let active = Arc::new(AtomicUsize::new(0));
            let max_active = Arc::new(AtomicUsize::new(0));
            let release = Arc::new(Semaphore::new(0));
            let work_active = active.clone();
            let work_max_active = max_active.clone();
            let work_release = release.clone();
            let work = (0..item_count).map(move |index| {
                let active = work_active.clone();
                let max_active = work_max_active.clone();
                let release = work_release.clone();
                async move {
                    let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(now_active, Ordering::SeqCst);
                    let permit = release.acquire().await.unwrap();
                    permit.forget();
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, &'static str>(index)
                }
            });

            let expected_parallelism = item_count.min(WELCOME_PUBLISH_CONCURRENCY);
            let task = tokio::spawn(collect_bounded_ordered(work, WELCOME_PUBLISH_CONCURRENCY));
            timeout(Duration::from_secs(1), async {
                while max_active.load(Ordering::SeqCst) < expected_parallelism {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("bounded collector should start the available parallel work");
            assert_eq!(max_active.load(Ordering::SeqCst), expected_parallelism);
            release.add_permits(item_count);

            assert_eq!(
                task.await.unwrap().unwrap(),
                (0..item_count).collect::<Vec<_>>()
            );
        }
    }
}
