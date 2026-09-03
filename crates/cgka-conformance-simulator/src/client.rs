//! `HarnessClient` — wraps an `Engine<SqliteAccountStorage>` + Nostr peeler + bus
//! attachment. Provides scenario-level affordances: `send`, `tick`,
//! `confirm_all_pending`, `assert_at_epoch`.

use crate::audit_capture::{AuditCapture, CapturingRecorder};
use crate::bus::{ClientId, TransportBus};
use crate::decryptability::DecryptabilityProbeSendStatus;
use crate::pending_work::{ClientStructuralProgress, PendingWorkObservation};
use crate::scenario_input_ledger::{
    ScenarioInputKind, ScenarioInputLedgerEntry, ScenarioInputMetadata, ScenarioInputTracker,
};
use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::canonicalization::{CanonicalizationPolicy, CanonicalizationResult};
use cgka_engine::conformance_snapshot::ConformanceStructuralProgressSnapshot;
use cgka_engine::engine_metrics::{EngineMetricsSnapshot, HistogramSnapshot};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{ConvergenceClock, Engine, EngineBuilder};
use cgka_traits::app_components::{
    AppComponentData, GROUP_ADMIN_POLICY_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1,
    default_group_components, encode_nostr_routing_v1,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::engine::{
    CgkaEngine, CreateGroupRequest, GroupEvent, KeyPackage, SendIntent, SendResult,
};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{ConvergencePassStorage, MessageStorage, StorageProvider};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use cgka_traits::{ConvergenceCutoffCause, ConvergencePassPhase, DurableConvergencePass};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage, SqliteStorageOptions};
use transport_nostr_peeler::NostrMlsPeeler;

const STORAGE_MODE_ENV: &str = "MDK_CONFORMANCE_SQLITE_STORAGE";
const TEMP_FILE_KEY: &str = "marmot-conformance-sqlite-temp-key";
const HARNESS_CONVERGENCE_SETTLED_AT_MS: u64 = 1_000_000;
const HARNESS_CONVERGENCE_DRAIN_PASSES: usize = 8;

pub struct HarnessClient {
    engine: Option<Engine<SqliteAccountStorage>>,
    pub bus_id: ClientId,
    bus: TransportBus,
    storage: Option<SqliteAccountStorage>,
    storage_backing: HarnessStorageBacking,
    identity: Vec<u8>,
    signer: nostr::Keys,
    registry: FeatureRegistry,
    protocol_profile: ProtocolProfile,
    convergence_clock: Option<Arc<dyn ConvergenceClock>>,
    disable_app_witnesses_for_tests: bool,
    replay_probe_budget_override: Option<u64>,
    completed_replay_probe_count: u64,
    completed_engine_metrics: EngineMetricsSnapshot,
    virtual_time_tick_enabled: bool,
    pending_events: Vec<GroupEvent>,
    /// Default MLS group id used by single-group scenarios. Set
    /// automatically after the first create/join.
    default_group: Option<GroupId>,
    app_event_counter: u64,
    scenario_input_counter: u64,
    next_scenario_input_id: Option<String>,
    scenario_input_tracker: ScenarioInputTracker,
    pending_scenario_inputs: HashMap<PendingStateRef, String>,
    pending_publication_artifacts: HashMap<PendingStateRef, Vec<MessageId>>,
    pending_confirmation_artifacts: HashMap<PendingStateRef, Vec<MessageId>>,
    regenerated_queued_intents: HashMap<MessageId, (GroupId, MessageId)>,
    /// Shared in-memory capture of the engine's forensic audit events, used to
    /// observe decisions no `GroupEvent` exposes (e.g. `convergence_decision`).
    audit_capture: AuditCapture,
    convergence_checkpoints: HashMap<String, (GroupId, DurableConvergencePass)>,
    #[cfg(test)]
    scripted_convergence_drain: Option<ScriptedConvergenceDrain>,
}

#[cfg(test)]
struct ScriptedConvergenceDrain {
    group_id: GroupId,
    remaining_retained_messages: usize,
    remaining_passes: usize,
    attempted_passes: usize,
    generation: u64,
    scheduled: bool,
    advance_generation: bool,
    fail_on_attempt: Option<usize>,
}

#[cfg(test)]
impl ScriptedConvergenceDrain {
    /// Builds bounded retained-history work for harness-level tick tests.
    fn retained_history(retained_messages: usize, passes: usize) -> Self {
        Self {
            group_id: GroupId::new(b"scripted-convergence-drain".to_vec()),
            remaining_retained_messages: retained_messages,
            remaining_passes: passes,
            attempted_passes: 0,
            generation: 1,
            scheduled: passes > 0,
            advance_generation: true,
            fail_on_attempt: None,
        }
    }

    /// Builds a scheduler that re-arms forever without changing durable state.
    fn stalled() -> Self {
        Self {
            advance_generation: false,
            ..Self::retained_history(0, usize::MAX)
        }
    }

    /// Builds a drain whose underlying convergence operation fails verbatim.
    fn failing(attempt: usize) -> Self {
        Self {
            fail_on_attempt: Some(attempt),
            ..Self::retained_history(attempt, attempt)
        }
    }

    /// Drains the scripted one-shot schedule edge.
    fn drain_pending_groups(&mut self) -> Vec<GroupId> {
        if !self.scheduled {
            return Vec::new();
        }
        self.scheduled = false;
        vec![self.group_id.clone()]
    }

    /// Captures the same privacy-safe fields used by the real engine seam.
    fn progress(&self) -> ConformanceStructuralProgressSnapshot {
        let pending_work = cgka_engine::conformance_snapshot::ConformancePendingWorkSnapshot {
            scheduled_convergence_groups: usize::from(self.scheduled),
            ..Default::default()
        };
        ConformanceStructuralProgressSnapshot {
            current_epoch: self.generation,
            current_monotonic_ms: HARNESS_CONVERGENCE_SETTLED_AT_MS,
            lifecycle: cgka_traits::engine_state::GroupLifecycleState::Stable,
            pending_work,
            pass_generation: Some(self.generation),
            pass_phase: Some(ConvergencePassPhase::Resolving),
            earliest_next_wake_monotonic_ms: None,
            runnable_work: 1,
            terminal_unrecoverable: false,
        }
    }

    /// Executes one scripted convergence round and re-arms when work remains.
    fn converge(&mut self) -> Result<Vec<SendResult>, EngineError> {
        self.attempted_passes = self.attempted_passes.saturating_add(1);
        if self.fail_on_attempt == Some(self.attempted_passes) {
            return Err(EngineError::Backend(
                "scripted underlying convergence failure".into(),
            ));
        }
        if self.advance_generation {
            let messages_this_pass = self
                .remaining_retained_messages
                .div_ceil(self.remaining_passes);
            self.remaining_retained_messages = self
                .remaining_retained_messages
                .saturating_sub(messages_this_pass);
            self.remaining_passes = self.remaining_passes.saturating_sub(1);
            self.generation = self.generation.saturating_add(1);
            self.scheduled = self.remaining_passes > 0;
        } else {
            self.scheduled = true;
        }
        Ok(Vec::new())
    }
}

/// Saturating-merge one engine metrics snapshot into the harness aggregate.
pub(crate) fn merge_engine_metrics(
    target: &mut EngineMetricsSnapshot,
    source: &EngineMetricsSnapshot,
) {
    target.settles = target.settles.saturating_add(source.settles);
    target.post_settle_reorgs = target
        .post_settle_reorgs
        .saturating_add(source.post_settle_reorgs);
    merge_histogram(&mut target.reorg_rewind_depth, &source.reorg_rewind_depth);
    merge_histogram(&mut target.reorg_lateness_ms, &source.reorg_lateness_ms);
    merge_histogram(
        &mut target.pass_apply_latency_ms,
        &source.pass_apply_latency_ms,
    );
    merge_histogram(&mut target.generation_gap_ms, &source.generation_gap_ms);
    merge_histogram(&mut target.freeze_overdue_ms, &source.freeze_overdue_ms);
    target.admin_reservation_hold_observations = target
        .admin_reservation_hold_observations
        .saturating_add(source.admin_reservation_hold_observations);
    target.admin_reservation_prepared = target
        .admin_reservation_prepared
        .saturating_add(source.admin_reservation_prepared);
    target.admin_reservation_failed = target
        .admin_reservation_failed
        .saturating_add(source.admin_reservation_failed);
    merge_histogram(
        &mut target.outbound_required_convergence_ms,
        &source.outbound_required_convergence_ms,
    );
    merge_histogram(
        &mut target.outbound_deferred_peel_ms,
        &source.outbound_deferred_peel_ms,
    );
    merge_histogram(
        &mut target.outbound_queue_accept_ms,
        &source.outbound_queue_accept_ms,
    );
    merge_histogram(
        &mut target.outbound_wire_prepare_ms,
        &source.outbound_wire_prepare_ms,
    );
    merge_histogram(
        &mut target.foreground_deferred_rows_attempted,
        &source.foreground_deferred_rows_attempted,
    );
    merge_histogram(
        &mut target.foreground_deferred_backlog,
        &source.foreground_deferred_backlog,
    );
    target.foreground_deferred_completed = target
        .foreground_deferred_completed
        .saturating_add(source.foreground_deferred_completed);
    target.foreground_deferred_budget_exhausted = target
        .foreground_deferred_budget_exhausted
        .saturating_add(source.foreground_deferred_budget_exhausted);
    target.foreground_deferred_normalization_pending = target
        .foreground_deferred_normalization_pending
        .saturating_add(source.foreground_deferred_normalization_pending);
    target.foreground_deferred_unchanged = target
        .foreground_deferred_unchanged
        .saturating_add(source.foreground_deferred_unchanged);
    target.foreground_deferred_errors = target
        .foreground_deferred_errors
        .saturating_add(source.foreground_deferred_errors);
    merge_histogram(
        &mut target.foreground_deferred_budget_overrun_ms,
        &source.foreground_deferred_budget_overrun_ms,
    );
    target.deferred_peel_sweeps = target
        .deferred_peel_sweeps
        .saturating_add(source.deferred_peel_sweeps);
    target.deferred_peel_candidate_enumerations = target
        .deferred_peel_candidate_enumerations
        .saturating_add(source.deferred_peel_candidate_enumerations);
    target.deferred_peel_candidate_contexts = target
        .deferred_peel_candidate_contexts
        .saturating_add(source.deferred_peel_candidate_contexts);
    merge_histogram(
        &mut target.deferred_peel_candidate_context_depth,
        &source.deferred_peel_candidate_context_depth,
    );
    target.deferred_peel_candidate_replay_probes = target
        .deferred_peel_candidate_replay_probes
        .saturating_add(source.deferred_peel_candidate_replay_probes);
    target.deferred_peel_candidate_cache_hits = target
        .deferred_peel_candidate_cache_hits
        .saturating_add(source.deferred_peel_candidate_cache_hits);
    target.deferred_peel_candidate_cache_misses = target
        .deferred_peel_candidate_cache_misses
        .saturating_add(source.deferred_peel_candidate_cache_misses);
    target.deferred_peel_candidate_cache_invalidations = target
        .deferred_peel_candidate_cache_invalidations
        .saturating_add(source.deferred_peel_candidate_cache_invalidations);
    merge_histogram(
        &mut target.deferred_peel_candidate_enumeration_ms,
        &source.deferred_peel_candidate_enumeration_ms,
    );
    merge_histogram(
        &mut target.queued_outbound_wait_ms,
        &source.queued_outbound_wait_ms,
    );
}

/// Saturating-merge histogram buckets while retaining upper-bound order.
fn merge_histogram(target: &mut HistogramSnapshot, source: &HistogramSnapshot) {
    for source_bucket in &source.buckets {
        if let Some(target_bucket) = target
            .buckets
            .iter_mut()
            .find(|bucket| bucket.upper_bound == source_bucket.upper_bound)
        {
            target_bucket.count = target_bucket.count.saturating_add(source_bucket.count);
        } else {
            target.buckets.push(source_bucket.clone());
        }
    }
    target.buckets.sort_by_key(|bucket| bucket.upper_bound);
    target.overflow_count = target.overflow_count.saturating_add(source.overflow_count);
}

/// Rejects only an exact full-slice repeat of scheduled structural state.
///
/// A durable pass-generation change counts as progress. More complex cycles
/// remain the scenario fixed-point driver's responsibility; this local guard
/// exists to catch a scheduler that repeatedly re-arms the same state without
/// turning the per-tick work bound into a convergence deadline.
fn ensure_convergence_drain_progress(
    attempts: usize,
    continuation_scheduled: bool,
    initial: &ConformanceStructuralProgressSnapshot,
    current: &ConformanceStructuralProgressSnapshot,
) -> Result<(), EngineError> {
    if attempts == HARNESS_CONVERGENCE_DRAIN_PASSES && continuation_scheduled && initial == current
    {
        return Err(EngineError::Backend(
            "convergence scheduler repeated a drain without structural progress".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_engine::conformance_snapshot::ConformancePendingWorkSnapshot;
    use cgka_engine::engine_metrics::HistogramBucket;
    use cgka_traits::engine_state::GroupLifecycleState;

    /// Builds a single-bucket histogram fixture.
    fn histogram(upper_bound: u64, count: u64, overflow_count: u64) -> HistogramSnapshot {
        HistogramSnapshot {
            buckets: vec![HistogramBucket { upper_bound, count }],
            overflow_count,
        }
    }

    /// Every engine metric participates in the aggregate merge.
    #[test]
    fn merge_engine_metrics_covers_every_snapshot_field() {
        let source = EngineMetricsSnapshot {
            settles: 1,
            post_settle_reorgs: 2,
            reorg_rewind_depth: histogram(3, 4, 5),
            reorg_lateness_ms: histogram(6, 7, 8),
            pass_apply_latency_ms: histogram(9, 10, 11),
            generation_gap_ms: histogram(12, 13, 14),
            freeze_overdue_ms: histogram(15, 16, 17),
            admin_reservation_hold_observations: 18,
            admin_reservation_prepared: 19,
            admin_reservation_failed: 20,
            outbound_required_convergence_ms: histogram(21, 22, 23),
            outbound_deferred_peel_ms: histogram(24, 25, 26),
            outbound_queue_accept_ms: histogram(27, 28, 29),
            outbound_wire_prepare_ms: histogram(30, 31, 32),
            foreground_deferred_rows_attempted: histogram(33, 34, 35),
            foreground_deferred_backlog: histogram(36, 37, 38),
            foreground_deferred_completed: 39,
            foreground_deferred_budget_exhausted: 40,
            foreground_deferred_normalization_pending: 41,
            foreground_deferred_unchanged: 42,
            foreground_deferred_errors: 43,
            foreground_deferred_budget_overrun_ms: histogram(44, 45, 46),
            deferred_peel_sweeps: 47,
            deferred_peel_candidate_enumerations: 48,
            deferred_peel_candidate_contexts: 49,
            deferred_peel_candidate_context_depth: histogram(50, 51, 52),
            deferred_peel_candidate_replay_probes: 53,
            deferred_peel_candidate_cache_hits: 54,
            deferred_peel_candidate_cache_misses: 55,
            deferred_peel_candidate_cache_invalidations: 56,
            deferred_peel_candidate_enumeration_ms: histogram(57, 58, 59),
            queued_outbound_wait_ms: histogram(60, 61, 62),
        };
        let mut target = EngineMetricsSnapshot::default();

        merge_engine_metrics(&mut target, &source);

        assert_eq!(target, source);
    }

    /// An unchanged, re-armed eighth attempt is a local scheduler spin.
    #[test]
    fn eight_repeated_convergence_drain_states_are_a_typed_failure() {
        let progress = structural_progress(7);

        let error = ensure_convergence_drain_progress(
            HARNESS_CONVERGENCE_DRAIN_PASSES,
            true,
            &progress,
            &progress,
        )
        .expect_err("identical scheduled state must not spin");

        assert!(
            matches!(error, EngineError::Backend(message) if message.contains("without structural progress"))
        );
    }

    /// Seven unchanged attempts remain below the deterministic slice bound.
    #[test]
    fn seven_repeated_convergence_drain_states_can_continue() {
        let progress = structural_progress(7);

        ensure_convergence_drain_progress(
            HARNESS_CONVERGENCE_DRAIN_PASSES - 1,
            true,
            &progress,
            &progress,
        )
        .expect("the deterministic slice still has one attempt left");
    }

    /// Advancing the durable pass generation permits cross-tick continuation.
    #[test]
    fn changed_convergence_drain_state_can_continue_after_eight_attempts() {
        let previous = structural_progress(7);
        let current = structural_progress(8);

        ensure_convergence_drain_progress(
            HARNESS_CONVERGENCE_DRAIN_PASSES,
            true,
            &previous,
            &current,
        )
        .expect("a later pass generation is structural progress");
    }

    /// Twelve retained-history rounds can span an eight- plus four-pass slice.
    #[test]
    fn large_retained_history_can_continue_in_a_later_bounded_slice() {
        // The 384-message natural-history case advances through twelve commit
        // rounds. Eight fit in the first harness slice; the remaining four are
        // valid work for the following scenario tick.
        ensure_convergence_drain_progress(
            HARNESS_CONVERGENCE_DRAIN_PASSES,
            true,
            &structural_progress(1),
            &structural_progress(9),
        )
        .expect("the first bounded slice made progress");
        ensure_convergence_drain_progress(
            4,
            false,
            &structural_progress(9),
            &structural_progress(13),
        )
        .expect("the following tick can settle the retained history");
    }

    /// Seven and eight scheduled passes both complete in one harness tick.
    #[tokio::test]
    async fn harness_tick_covers_seven_and_eight_pass_boundaries() {
        for passes in [
            HARNESS_CONVERGENCE_DRAIN_PASSES - 1,
            HARNESS_CONVERGENCE_DRAIN_PASSES,
        ] {
            let mut client =
                scripted_client(ScriptedConvergenceDrain::retained_history(passes, passes));

            let outcomes = client.tick().await;

            assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
            let script = client.scripted_convergence_drain.as_ref().unwrap();
            assert_eq!(script.attempted_passes, passes);
            assert_eq!(script.remaining_passes, 0);
            assert_eq!(script.remaining_retained_messages, 0);
            assert!(!script.scheduled);
        }
    }

    /// A 384-message, twelve-round drain continues on a second harness tick.
    #[tokio::test]
    async fn harness_tick_continues_large_retained_history_after_eight_passes() {
        let mut client = scripted_client(ScriptedConvergenceDrain::retained_history(384, 12));

        let first = client.tick().await;

        assert!(first.iter().all(Result::is_ok), "{first:?}");
        let script = client.scripted_convergence_drain.as_ref().unwrap();
        assert_eq!(script.attempted_passes, HARNESS_CONVERGENCE_DRAIN_PASSES);
        assert_eq!(script.remaining_passes, 4);
        assert_eq!(script.remaining_retained_messages, 128);
        assert!(script.scheduled);

        let second = client.tick().await;

        assert!(second.iter().all(Result::is_ok), "{second:?}");
        let script = client.scripted_convergence_drain.as_ref().unwrap();
        assert_eq!(script.attempted_passes, 12);
        assert_eq!(script.remaining_passes, 0);
        assert_eq!(script.remaining_retained_messages, 0);
        assert!(!script.scheduled);
    }

    /// The same tick path retains a typed failure for an unchanged re-arm loop.
    #[tokio::test]
    async fn harness_tick_rejects_a_true_scheduler_spin() {
        let mut client = scripted_client(ScriptedConvergenceDrain::stalled());

        let outcomes = client.tick().await;

        assert!(matches!(
            outcomes.as_slice(),
            [Err(EngineError::Backend(message))]
                if message.contains("without structural progress")
        ));
        assert_eq!(
            client
                .scripted_convergence_drain
                .as_ref()
                .unwrap()
                .attempted_passes,
            HARNESS_CONVERGENCE_DRAIN_PASSES
        );
    }

    /// A real convergence error is not replaced by the slice guard.
    #[tokio::test]
    async fn harness_tick_preserves_underlying_convergence_error() {
        let mut client = scripted_client(ScriptedConvergenceDrain::failing(8));

        let outcomes = client.tick().await;

        assert!(matches!(
            outcomes.as_slice(),
            [Err(EngineError::Backend(message))]
                if message == "scripted underlying convergence failure"
        ));
    }

    /// Wraps a scripted drain in a real `HarnessClient` tick surface.
    fn scripted_client(script: ScriptedConvergenceDrain) -> HarnessClient {
        let bus = TransportBus::ordered();
        let mut client = ClientBuilder::new(b"scripted-drain-client".to_vec()).attach(&bus);
        client.scripted_convergence_drain = Some(script);
        client
    }

    /// Builds a privacy-safe structural state for drain-boundary tests.
    fn structural_progress(pass_generation: u64) -> ConformanceStructuralProgressSnapshot {
        ConformanceStructuralProgressSnapshot {
            current_epoch: pass_generation,
            current_monotonic_ms: HARNESS_CONVERGENCE_SETTLED_AT_MS,
            lifecycle: GroupLifecycleState::Stable,
            pending_work: ConformancePendingWorkSnapshot::default(),
            pass_generation: Some(pass_generation),
            pass_phase: Some(ConvergencePassPhase::Resolving),
            earliest_next_wake_monotonic_ms: None,
            runnable_work: 1,
            terminal_unrecoverable: false,
        }
    }
}

pub struct ClientBuilder {
    identity: Vec<u8>,
    signer: nostr::Keys,
    registry: FeatureRegistry,
    protocol_profile: ProtocolProfile,
    storage_mode: HarnessStorageMode,
    storage_options: SqliteStorageOptions,
    explicit_file_storage: Option<ExplicitFileStorage>,
    convergence_clock: Option<Arc<dyn ConvergenceClock>>,
    disable_app_witnesses_for_tests: bool,
    replay_probe_budget_override: Option<u64>,
}

pub(crate) enum HarnessPublicationError {
    AlreadyExposed { recipient_exposures: usize },
    Engine(EngineError),
}

impl From<EngineError> for HarnessPublicationError {
    fn from(error: EngineError) -> Self {
        Self::Engine(error)
    }
}

impl HarnessPublicationError {
    fn into_engine_error(self) -> EngineError {
        match self {
            Self::AlreadyExposed {
                recipient_exposures,
            } => EngineError::Other(format!(
                "cannot report definite publication failure after {recipient_exposures} matching artifact(s) reached a recipient mailbox"
            )),
            Self::Engine(error) => error,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarnessStorageMode {
    InMemorySqlite,
    TempFileBackedSqlite,
}

impl HarnessStorageMode {
    pub fn from_env() -> Self {
        match std::env::var(STORAGE_MODE_ENV) {
            Ok(value) => Self::parse(&value).unwrap_or_else(|err| panic!("{err}")),
            Err(_) => Self::InMemorySqlite,
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "file" | "file-backed" | "tempfile" => Ok(Self::TempFileBackedSqlite),
            "memory" | "in-memory" | "sqlite-memory" => Ok(Self::InMemorySqlite),
            _ => Err(format!(
                "{STORAGE_MODE_ENV} and --storage must be one of memory, in-memory, sqlite-memory, file, file-backed, or tempfile; got {value:?}"
            )),
        }
    }

    pub fn report_label(self) -> &'static str {
        match self {
            Self::InMemorySqlite => "in-memory-sqlite",
            Self::TempFileBackedSqlite => "encrypted-file-sqlite",
        }
    }
}

struct ExplicitFileStorage {
    path: PathBuf,
    key: SqlCipherKey,
    options: SqliteStorageOptions,
}

enum HarnessStorageBacking {
    InMemory,
    FileBacked {
        _storage_dir: Option<tempfile::TempDir>,
        path: PathBuf,
        key: SqlCipherKey,
        options: SqliteStorageOptions,
    },
}

impl HarnessStorageBacking {
    fn from_mode(mode: HarnessStorageMode, options: SqliteStorageOptions) -> Result<Self, String> {
        match mode {
            HarnessStorageMode::InMemorySqlite => Ok(Self::InMemory),
            HarnessStorageMode::TempFileBackedSqlite => {
                let storage_dir = tempfile::tempdir().map_err(|err| err.to_string())?;
                let path = storage_dir.path().join("client.sqlite3");
                let key = SqlCipherKey::new(TEMP_FILE_KEY).map_err(|err| err.to_string())?;
                Ok(Self::FileBacked {
                    _storage_dir: Some(storage_dir),
                    path,
                    key,
                    options,
                })
            }
        }
    }

    fn from_explicit(explicit: ExplicitFileStorage) -> Self {
        Self::FileBacked {
            _storage_dir: None,
            path: explicit.path,
            key: explicit.key,
            options: explicit.options,
        }
    }

    fn open(&self) -> Result<SqliteAccountStorage, String> {
        match self {
            Self::InMemory => SqliteAccountStorage::in_memory().map_err(|err| err.to_string()),
            Self::FileBacked {
                path, key, options, ..
            } => SqliteAccountStorage::open_encrypted_with_options(path, key, options.clone())
                .map_err(|err| err.to_string()),
        }
    }

    fn is_file_backed(&self) -> bool {
        matches!(self, Self::FileBacked { .. })
    }

    fn database_path(&self) -> Option<&Path> {
        match self {
            Self::InMemory => None,
            Self::FileBacked { path, .. } => Some(path),
        }
    }
}

impl ClientBuilder {
    pub fn new(identity: impl Into<Vec<u8>>) -> Self {
        let seed = identity.into();
        let signer = deterministic_nostr_keys(&seed);
        let identity = signer.public_key().to_bytes().to_vec();
        register_logical_identity(&seed, &identity);
        Self {
            identity,
            signer,
            registry: FeatureRegistry::new(),
            protocol_profile: ProtocolProfile::Legacy,
            storage_mode: HarnessStorageMode::from_env(),
            storage_options: SqliteStorageOptions::default(),
            explicit_file_storage: None,
            convergence_clock: None,
            disable_app_witnesses_for_tests: false,
            replay_probe_budget_override: None,
        }
    }

    pub fn registry(mut self, r: FeatureRegistry) -> Self {
        self.registry = r;
        self
    }

    pub fn storage_mode(mut self, mode: HarnessStorageMode) -> Self {
        self.storage_mode = mode;
        self.explicit_file_storage = None;
        self
    }

    pub fn storage_options(mut self, options: SqliteStorageOptions) -> Self {
        self.storage_options = options;
        self
    }

    pub fn file_backed_storage(
        mut self,
        path: impl Into<PathBuf>,
        key: SqlCipherKey,
        options: SqliteStorageOptions,
    ) -> Self {
        self.storage_mode = HarnessStorageMode::TempFileBackedSqlite;
        self.explicit_file_storage = Some(ExplicitFileStorage {
            path: path.into(),
            key,
            options,
        });
        self
    }

    pub fn protocol_profile(mut self, profile: ProtocolProfile) -> Self {
        self.protocol_profile = profile;
        self
    }

    pub fn convergence_clock(mut self, clock: Arc<dyn ConvergenceClock>) -> Self {
        self.convergence_clock = Some(clock);
        self
    }

    #[cfg(feature = "test-policy-overrides")]
    pub fn without_app_witnesses_for_tests(mut self) -> Self {
        self.disable_app_witnesses_for_tests = true;
        self
    }

    #[cfg(feature = "test-policy-overrides")]
    pub fn replay_probe_budget_for_tests(mut self, limit: Option<u64>) -> Self {
        self.replay_probe_budget_override = limit;
        self
    }

    pub fn attach(self, bus: &TransportBus) -> HarnessClient {
        let storage_backing = match self.explicit_file_storage {
            Some(explicit) => HarnessStorageBacking::from_explicit(explicit),
            None => HarnessStorageBacking::from_mode(self.storage_mode, self.storage_options)
                .expect("storage backing opens"),
        };
        let storage = storage_backing.open().expect("storage opens");
        let audit_capture = AuditCapture::default();
        let engine = build_harness_engine(
            &storage,
            &self.identity,
            &self.signer,
            &self.registry,
            self.protocol_profile,
            &audit_capture,
            HarnessEngineOptions {
                convergence_clock: self.convergence_clock.as_ref(),
                disable_app_witnesses_for_tests: self.disable_app_witnesses_for_tests,
                replay_probe_budget_override: self.replay_probe_budget_override,
            },
        );
        let bus_id = bus.attach(MemberId::new(self.identity.clone()));
        bus.capture_outbound_for(bus_id);
        HarnessClient {
            engine: Some(engine),
            bus_id,
            bus: bus.clone(),
            storage: Some(storage),
            storage_backing,
            identity: self.identity,
            signer: self.signer,
            registry: self.registry,
            protocol_profile: self.protocol_profile,
            convergence_clock: self.convergence_clock,
            disable_app_witnesses_for_tests: self.disable_app_witnesses_for_tests,
            replay_probe_budget_override: self.replay_probe_budget_override,
            completed_replay_probe_count: 0,
            completed_engine_metrics: EngineMetricsSnapshot::default(),
            virtual_time_tick_enabled: false,
            pending_events: Vec::new(),
            default_group: None,
            app_event_counter: 0,
            scenario_input_counter: 0,
            next_scenario_input_id: None,
            scenario_input_tracker: ScenarioInputTracker::default(),
            pending_scenario_inputs: HashMap::new(),
            pending_publication_artifacts: HashMap::new(),
            pending_confirmation_artifacts: HashMap::new(),
            regenerated_queued_intents: HashMap::new(),
            audit_capture,
            convergence_checkpoints: HashMap::new(),
            #[cfg(test)]
            scripted_convergence_drain: None,
        }
    }
}

/// Build an engine wired the way every harness client needs it, including the
/// [`CapturingRecorder`] that retains forensic events. `attach` and `restart`
/// both go through here so a rebuilt engine keeps recording into the same shared
/// buffer — otherwise a restart would silently drop captured decisions.
struct HarnessEngineOptions<'a> {
    convergence_clock: Option<&'a Arc<dyn ConvergenceClock>>,
    disable_app_witnesses_for_tests: bool,
    replay_probe_budget_override: Option<u64>,
}

fn build_harness_engine(
    storage: &SqliteAccountStorage,
    identity: &[u8],
    signer: &nostr::Keys,
    registry: &FeatureRegistry,
    protocol_profile: ProtocolProfile,
    audit_capture: &AuditCapture,
    options: HarnessEngineOptions<'_>,
) -> Engine<SqliteAccountStorage> {
    // The engine's legacy compatibility switch is deliberately debug-only.
    // A release-built harness must fail loudly instead of claiming it ran a
    // legacy profile while silently exercising current compatibility rules.
    #[cfg(not(debug_assertions))]
    assert_ne!(
        protocol_profile,
        ProtocolProfile::Legacy,
        "the legacy harness protocol profile is unavailable in release builds"
    );
    let peeler = NostrMlsPeeler::new().with_welcome_signer(signer.clone());
    let mut builder = EngineBuilder::new(storage.clone())
        .identity(identity.to_vec())
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
            keys: signer.clone(),
        }))
        .protocol_profile(protocol_profile)
        .feature_registry(registry.clone())
        .supported_app_components(harness_supported_app_components())
        .peeler(Box::new(peeler))
        .recorder(Box::new(CapturingRecorder::new(audit_capture.clone())));
    #[cfg(debug_assertions)]
    if protocol_profile == ProtocolProfile::Legacy {
        builder = builder.legacy_compatibility_profile();
    }
    if let Some(clock) = options.convergence_clock {
        builder = builder.convergence_clock(clock.clone());
    }
    #[cfg(feature = "test-policy-overrides")]
    if options.disable_app_witnesses_for_tests {
        builder = builder.without_app_witnesses_for_tests();
    }
    #[cfg(feature = "test-policy-overrides")]
    if options.replay_probe_budget_override.is_some() {
        builder = builder.replay_probe_budget_for_tests(options.replay_probe_budget_override);
    }
    #[cfg(not(feature = "test-policy-overrides"))]
    let _ = (
        options.disable_app_witnesses_for_tests,
        options.replay_probe_budget_override,
    );
    builder.build().expect("engine builds")
}

fn deterministic_nostr_keys(seed: &[u8]) -> nostr::Keys {
    let mut counter = 0_u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"marmot-cgka-conformance-nostr-key-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let secret = hasher.finalize();
        if let Ok(keys) = nostr::Keys::parse(&hex::encode(secret)) {
            return keys;
        }
        counter = counter
            .checked_add(1)
            .expect("deterministic Nostr key search exhausted");
    }
}

fn harness_supported_app_components() -> Vec<u16> {
    let mut components = default_group_components();
    components.insert(NOSTR_ROUTING_COMPONENT_ID);
    components.into_iter().collect()
}

fn harness_nostr_routing_component(creator_identity: &[u8], name: &str) -> AppComponentData {
    let routing = NostrRoutingV1::new(
        deterministic_nostr_group_id(creator_identity, name),
        vec!["wss://group.example".to_owned()],
    )
    .expect("harness Nostr routing is valid");
    AppComponentData {
        component_id: NOSTR_ROUTING_COMPONENT_ID,
        data: encode_nostr_routing_v1(&routing).expect("harness Nostr routing encodes"),
    }
}

fn deterministic_nostr_group_id(creator_identity: &[u8], name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-cgka-conformance-nostr-group-id-v1");
    hasher.update(creator_identity);
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

fn key_package_with_harness_source(key_package: KeyPackage) -> KeyPackage {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-cgka-conformance-key-package-event-id-v1");
    hasher.update(key_package.bytes());
    let protocol_profile = key_package.protocol_profile;
    KeyPackage::with_source_event_id(
        key_package.bytes().to_vec(),
        MessageId::new(hasher.finalize().to_vec()),
    )
    .with_protocol_profile(protocol_profile)
}

/// Stable variant name for unexpected-result errors. Debug-formatting a
/// [`SendResult`] would embed transport payload bytes in the error string.
fn send_result_kind(res: &SendResult) -> &'static str {
    match res {
        SendResult::NoChange { .. } => "NoChange",
        SendResult::DisbandRequested { .. } => "DisbandRequested",
        SendResult::ApplicationMessage { .. } => "ApplicationMessage",
        SendResult::Queued { .. } => "Queued",
        SendResult::Proposal { .. } => "Proposal",
        SendResult::GroupEvolution { .. } => "GroupEvolution",
        SendResult::GroupCreated { .. } => "GroupCreated",
        SendResult::FoundingGroupCreated { .. } => "FoundingGroupCreated",
    }
}

#[derive(Clone)]
struct NostrAccountIdentityProofSigner {
    keys: nostr::Keys,
}

impl AccountIdentityProofSigner for NostrAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.keys.public_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match harness Nostr key".into());
        }
        let event = request.proof_event().and_then(|event| {
            event
                .sign_with_keys(&self.keys)
                .map_err(|err| err.to_string())
        })?;
        request.signature_from_signed_event(event)
    }
}

pub(crate) fn logical_label_for_member_id(bytes: &[u8]) -> Option<String> {
    logical_identity_labels()
        .lock()
        .expect("logical identity label registry lock")
        .get(bytes)
        .cloned()
}

fn register_logical_identity(seed: &[u8], identity: &[u8]) {
    let Some(label) = logical_label_from_seed(seed) else {
        return;
    };
    logical_identity_labels()
        .lock()
        .expect("logical identity label registry lock")
        .insert(identity.to_vec(), label);
}

fn logical_identity_labels() -> &'static Mutex<HashMap<Vec<u8>, String>> {
    static LABELS: OnceLock<Mutex<HashMap<Vec<u8>, String>>> = OnceLock::new();
    LABELS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn logical_label_from_seed(seed: &[u8]) -> Option<String> {
    let end = seed
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |i| i + 1);
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&seed[..end])
        .ok()
        .filter(|label| !label.is_empty())
        .map(str::to_owned)
}

impl HarnessClient {
    pub(crate) fn select_default_group(&mut self, group_id: GroupId) {
        self.default_group = Some(group_id);
    }
    pub fn engine(&self) -> &Engine<SqliteAccountStorage> {
        self.engine.as_ref().expect("harness engine is available")
    }

    pub fn engine_mut(&mut self) -> &mut Engine<SqliteAccountStorage> {
        self.engine.as_mut().expect("harness engine is available")
    }

    pub fn storage(&self) -> &SqliteAccountStorage {
        self.storage.as_ref().expect("harness storage is available")
    }

    pub fn database_path(&self) -> Option<&Path> {
        self.storage_backing.database_path()
    }

    /// Export the sensitive engine/OpenMLS state needed to replay captured
    /// transport bytes without regenerating MLS messages.
    pub fn export_conformance_replay_checkpoint(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<u8>, EngineError> {
        self.storage()
            .export_conformance_replay_snapshot(group_id)
            .map_err(EngineError::Storage)
    }

    /// Restore a sensitive replay checkpoint and rebuild the engine over it.
    pub fn restore_conformance_replay_checkpoint(
        &mut self,
        group_id: &GroupId,
        checkpoint: &[u8],
    ) -> Result<(), EngineError> {
        self.storage()
            .import_conformance_replay_snapshot(group_id, checkpoint)
            .map_err(EngineError::Storage)?;
        self.default_group = Some(group_id.clone());
        self.restart();
        Ok(())
    }

    /// Deliver one exact captured transport object directly to this client.
    pub fn inject_captured_transport(&self, message: TransportMessage) {
        self.bus.inject(self.bus_id, message);
    }

    pub(crate) fn replay_group_id(&self) -> Option<&GroupId> {
        self.default_group.as_ref()
    }

    pub(crate) fn replay_protocol_profile(&self) -> ProtocolProfile {
        self.protocol_profile
    }

    pub(crate) fn replay_uses_virtual_time(&self) -> bool {
        self.virtual_time_tick_enabled
    }

    pub(crate) fn enable_virtual_time_tick(&mut self) {
        self.virtual_time_tick_enabled = true;
    }

    pub(crate) fn pending_publication_for_message(
        &self,
        message_id: &MessageId,
    ) -> Option<PendingStateRef> {
        self.pending_publication_artifacts
            .iter()
            .find_map(|(pending, message_ids)| message_ids.contains(message_id).then_some(*pending))
    }

    /// Pending publication handles currently awaiting a transport outcome.
    ///
    /// This is a low-level harness probe for focused engine tests. Portable
    /// scenarios must drive opaque outbound artifacts through
    /// `ConvergenceSubject::poll_outbound` and `acknowledge_outbound` instead.
    pub fn pending_publication_refs(&self) -> Vec<PendingStateRef> {
        let mut pending = self
            .pending_publication_artifacts
            .keys()
            .copied()
            .collect::<Vec<_>>();
        pending.sort_by_key(|pending| pending.as_u64());
        pending
    }

    pub(crate) fn message_confirms_pending(
        &self,
        pending: PendingStateRef,
        message_id: &MessageId,
    ) -> bool {
        self.pending_confirmation_artifacts
            .get(&pending)
            .is_some_and(|message_ids| message_ids.contains(message_id))
    }

    pub(crate) fn regenerated_queued_intent_for_message(
        &self,
        message_id: &MessageId,
    ) -> Option<(GroupId, MessageId)> {
        self.regenerated_queued_intents.get(message_id).cloned()
    }

    pub(crate) fn confirm_regenerated_queued_intent(
        &mut self,
        intent_id: &MessageId,
    ) -> Result<(), EngineError> {
        self.engine_mut().confirm_queued_outbound_intent(intent_id)
    }

    pub(crate) fn retry_regenerated_queued_intent(
        &mut self,
        group_id: &GroupId,
        intent_id: &MessageId,
    ) {
        self.engine_mut()
            .retry_queued_outbound_intent(group_id, intent_id);
    }

    pub(crate) fn forget_regenerated_queued_intent(&mut self, message_id: &MessageId) {
        self.regenerated_queued_intents.remove(message_id);
    }

    pub fn restart(&mut self) {
        self.completed_replay_probe_count = self
            .completed_replay_probe_count
            .saturating_add(self.engine().conformance_replay_probe_count());
        let completed_metrics = self.engine().engine_metrics();
        merge_engine_metrics(&mut self.completed_engine_metrics, &completed_metrics);
        drop(self.engine.take());
        let storage = if self.storage_backing.is_file_backed() {
            drop(self.storage.take());
            self.storage_backing.open().expect("file storage reopens")
        } else {
            self.storage().clone()
        };
        let mut engine = build_harness_engine(
            &storage,
            &self.identity,
            &self.signer,
            &self.registry,
            self.protocol_profile,
            &self.audit_capture,
            HarnessEngineOptions {
                convergence_clock: self.convergence_clock.as_ref(),
                disable_app_witnesses_for_tests: self.disable_app_witnesses_for_tests,
                replay_probe_budget_override: self.replay_probe_budget_override,
            },
        );
        engine
            .hydrate_all_stored_groups()
            .expect("engine hydrates from storage");
        self.storage = Some(storage);
        self.engine = Some(engine);
        self.pending_events.clear();
    }

    pub fn replay_probe_count(&self) -> u64 {
        self.completed_replay_probe_count
            .saturating_add(self.engine().conformance_replay_probe_count())
    }

    pub fn engine_metrics(&self) -> EngineMetricsSnapshot {
        let mut metrics = self.completed_engine_metrics.clone();
        merge_engine_metrics(&mut metrics, &self.engine().engine_metrics());
        metrics
    }

    /// Change the full-engine replay ceiling without changing durable state.
    /// Clearing the override is the repair step after an intentional
    /// `ReplayBudgetExceeded` campaign result.
    #[cfg(feature = "test-policy-overrides")]
    pub fn set_replay_probe_budget_for_tests(&mut self, limit: Option<u64>) {
        self.replay_probe_budget_override = limit;
        self.engine_mut().set_replay_probe_budget_for_tests(limit);
    }

    /// Freeze the current durable pass at its quiescence boundary. This is a
    /// harness-level restart fault operation; scenarios should not reach into
    /// engine storage to manufacture the boundary themselves.
    pub fn freeze_convergence_pass(&mut self, group_id: &GroupId) {
        let mut pass = self
            .storage()
            .convergence_pass(group_id)
            .expect("load durable convergence pass")
            .expect("durable convergence pass exists");
        pass.phase = ConvergencePassPhase::Frozen;
        pass.cutoff_cause = Some(ConvergenceCutoffCause::Quiescence);
        pass.frozen_at_wall_ms = Some(pass.quiescence_deadline_wall_ms);
        self.storage()
            .put_convergence_pass(&pass)
            .expect("persist frozen convergence pass");
    }

    /// Snapshot group state and separately retain the pass row, which group
    /// epoch snapshots intentionally exclude.
    pub fn checkpoint_convergence(&mut self, group_id: &GroupId, name: &str) {
        let pass = self
            .storage()
            .convergence_pass(group_id)
            .expect("load convergence pass for checkpoint")
            .expect("checkpoint requires a convergence pass");
        self.storage()
            .create_group_snapshot(group_id, name)
            .expect("create convergence group snapshot");
        self.convergence_checkpoints
            .insert(name.to_owned(), (group_id.clone(), pass));
    }

    /// Restore a harness convergence checkpoint, including the pass row omitted
    /// from the group epoch snapshot, then rebuild the engine over the restored
    /// durable state.
    pub fn restore_convergence_checkpoint(&mut self, name: &str) {
        let (group_id, pass) = self
            .convergence_checkpoints
            .get(name)
            .cloned()
            .expect("convergence checkpoint exists");
        self.storage()
            .with_transaction(|storage| {
                storage.rollback_group_to_snapshot(&group_id, name)?;
                storage.put_convergence_pass(&pass)
            })
            .expect("atomically restore convergence checkpoint");
        self.restart();
    }

    pub fn converge_stored_at(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> CanonicalizationResult {
        self.try_converge_stored_at(group_id, now_ms)
            .expect("stored convergence succeeds")
    }

    pub fn try_converge_stored_at(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<CanonicalizationResult, cgka_engine::openmls_projection::OpenMlsProjectionError>
    {
        self.engine_mut()
            .converge_stored_openmls_messages_at(group_id, now_ms)
    }

    /// Drain the `convergence_decision` events the engine has emitted since the
    /// last call.
    ///
    /// The engine surfaces these only through its forensic recorder, so — unlike
    /// fork recoveries — no `GroupEvent` carries them and [`Self::drain_events`]
    /// never sees them. Returns them oldest-first; other captured audit records
    /// are left in place.
    pub fn drain_convergence_decisions(&mut self) -> Vec<marmot_forensics::AuditEventKind> {
        crate::audit_capture::drain_convergence_decisions(&self.audit_capture)
    }

    /// Discard captured convergence decisions, resetting the observation window.
    /// Mirrors what `ScenarioStep::ClearEvents` does for `GroupEvent`s so a
    /// scenario can isolate a decision that happens after setup.
    pub fn clear_audit_capture(&mut self) {
        crate::audit_capture::clear(&self.audit_capture);
    }

    pub fn member_id(&self) -> MemberId {
        self.engine().self_id()
    }

    /// Assign the stable synthetic id consumed by the next commit, proposal, or
    /// application input this client produces.
    pub fn name_next_scenario_input(&mut self, scenario_id: impl Into<String>) {
        assert!(
            self.next_scenario_input_id.is_none(),
            "previous scenario input id was not consumed"
        );
        self.next_scenario_input_id = Some(scenario_id.into());
    }

    pub async fn fresh_key_package(&mut self) -> KeyPackage {
        let key_package = self.engine_mut().fresh_key_package().await.expect("kp");
        key_package_with_harness_source(key_package)
    }

    /// Create a new group with the given members + features.
    pub async fn create_group(
        &mut self,
        name: &str,
        invitees: Vec<KeyPackage>,
        required_features: Vec<cgka_traits::capabilities::Feature>,
    ) -> (GroupId, PendingStateRef) {
        self.create_group_with_admins(name, invitees, required_features, vec![])
            .await
    }

    /// Variant of `create_group` that lets the test bootstrap a multi-admin
    /// group. The creator is always implicitly an admin; pass additional
    /// member ids in `initial_admins`.
    pub async fn create_group_with_admins(
        &mut self,
        name: &str,
        invitees: Vec<KeyPackage>,
        required_features: Vec<cgka_traits::capabilities::Feature>,
        initial_admins: Vec<MemberId>,
    ) -> (GroupId, PendingStateRef) {
        self.try_create_group_with_admins(name, invitees, required_features, initial_admins)
            .await
            .expect("create_group")
    }

    pub async fn try_create_group_with_admins(
        &mut self,
        name: &str,
        invitees: Vec<KeyPackage>,
        required_features: Vec<cgka_traits::capabilities::Feature>,
        initial_admins: Vec<MemberId>,
    ) -> Result<(GroupId, PendingStateRef), EngineError> {
        let (group_id, pending) = self
            .try_create_group_with_admins_maybe_pending(
                name,
                invitees,
                required_features,
                initial_admins,
            )
            .await?;
        pending.map(|pending| (group_id, pending)).ok_or_else(|| {
            EngineError::Other("current founding creation has no pending state".into())
        })
    }

    pub async fn create_group_with_admins_maybe_pending(
        &mut self,
        name: &str,
        invitees: Vec<KeyPackage>,
        required_features: Vec<cgka_traits::capabilities::Feature>,
        initial_admins: Vec<MemberId>,
    ) -> (GroupId, Option<PendingStateRef>) {
        self.try_create_group_with_admins_maybe_pending(
            name,
            invitees,
            required_features,
            initial_admins,
        )
        .await
        .expect("create_group")
    }

    async fn try_create_group_with_admins_maybe_pending(
        &mut self,
        name: &str,
        invitees: Vec<KeyPackage>,
        required_features: Vec<cgka_traits::capabilities::Feature>,
        initial_admins: Vec<MemberId>,
    ) -> Result<(GroupId, Option<PendingStateRef>), EngineError> {
        let routing_component = harness_nostr_routing_component(&self.identity, name);
        let res = self
            .engine_mut()
            .create_group(CreateGroupRequest {
                name: name.into(),
                description: "".into(),
                members: invitees,
                required_features,
                app_components: vec![routing_component],
                initial_admins,
            })
            .await?;
        let (gid, pending, welcomes) = match res {
            (gid, SendResult::GroupCreated { pending, welcomes }) => (gid, Some(pending), welcomes),
            (gid, SendResult::FoundingGroupCreated { welcomes }) => (gid, None, welcomes),
            (_, other) => {
                return Err(EngineError::Other(format!(
                    "expected group creation result, got {other:?}"
                )));
            }
        };
        if let Some(action_id) = self.next_scenario_input_id.take()
            && pending.is_some()
        {
            for welcome in &welcomes {
                self.bus
                    .register_scenario_action(welcome.id.clone(), action_id.clone());
            }
        }
        if let Some(pending) = pending {
            self.remember_pending_publication(
                pending,
                welcomes.iter().map(|welcome| welcome.id.clone()),
            );
            self.remember_pending_confirmation(
                pending,
                welcomes.iter().map(|welcome| welcome.id.clone()),
            );
        }
        for w in welcomes {
            self.bus.send(self.bus_id, w);
        }
        self.default_group = Some(gid.clone());
        if pending.is_none() {
            self.capture_engine_events();
        }
        Ok((gid, pending))
    }

    /// Confirm a pending publish. Required after every commit-producing
    /// action (create, invite, upgrade) when the simulated transport
    /// "succeeds."
    pub async fn confirm(&mut self, pending: PendingStateRef) {
        self.try_confirm(pending).await.expect("confirm_published");
    }

    pub(crate) async fn try_confirm(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<(), EngineError> {
        self.engine_mut().confirm_published(pending).await?;
        self.pending_publication_artifacts.remove(&pending);
        self.pending_confirmation_artifacts.remove(&pending);
        if let Some(scenario_id) = self.pending_scenario_inputs.remove(&pending) {
            self.scenario_input_tracker.record_confirmed(&scenario_id);
        }
        Ok(())
    }

    /// Confirm a pending transition only when it produced no transport
    /// artifacts. Both direct subject actions and engine-generated creation
    /// results use this helper so the no-op publication rule has one predicate.
    pub(crate) async fn confirm_empty_publication(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<bool, EngineError> {
        let artifact_ids = self
            .pending_publication_artifacts
            .get(&pending)
            .ok_or_else(|| EngineError::Other("missing pending publication bookkeeping".into()))?;
        if !artifact_ids.is_empty() {
            return Ok(false);
        }
        self.try_confirm(pending).await?;
        self.capture_engine_events();
        Ok(true)
    }

    /// Report a publish failure for a pending operation. The engine
    /// discards the staged commit and rewinds to `Stable` at the prior
    /// epoch. Used by the rollback proptest property.
    pub async fn fail(&mut self, pending: PendingStateRef) {
        self.try_fail(pending).await.expect("publish_failed");
    }

    pub async fn try_fail(&mut self, pending: PendingStateRef) -> Result<(), EngineError> {
        self.try_fail_publication(pending)
            .await
            .map_err(HarnessPublicationError::into_engine_error)
    }

    pub(crate) async fn try_fail_publication(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<(), HarnessPublicationError> {
        let message_ids = self
            .pending_publication_artifacts
            .get(&pending)
            .cloned()
            .unwrap_or_default();
        self.bus
            .retract_undelivered_publication(self.bus_id, &message_ids)
            .map_err(
                |recipient_exposures| HarnessPublicationError::AlreadyExposed {
                    recipient_exposures,
                },
            )?;
        self.engine_mut().publish_failed(pending).await?;
        self.pending_publication_artifacts.remove(&pending);
        self.pending_confirmation_artifacts.remove(&pending);
        if let Some(scenario_id) = self.pending_scenario_inputs.remove(&pending) {
            self.scenario_input_tracker.record_rolled_back(&scenario_id);
        }
        Ok(())
    }

    /// Issue a `SendIntent::UpgradeCapabilities` for the default group
    /// and bus-broadcast the resulting commit. Returns the
    /// `PendingStateRef` so the test can confirm or fail it.
    pub async fn upgrade(&mut self) -> PendingStateRef {
        let gid = self.default_group.clone().expect("group");
        let res = self
            .engine_mut()
            .upgrade_group_capabilities(&gid)
            .await
            .expect("upgrade");
        match res {
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                let routed = route(msg, &gid);
                self.remember_pending_publication(
                    pending,
                    welcomes
                        .iter()
                        .map(|welcome| welcome.id.clone())
                        .chain(std::iter::once(routed.id.clone())),
                );
                self.remember_pending_confirmation(pending, std::iter::once(routed.id.clone()));
                for w in welcomes {
                    self.bus.send(self.bus_id, w);
                }
                self.publish_commit_scenario_input(&routed, pending).await;
                self.bus.send(self.bus_id, routed);
                pending
            }
            other => panic!("expected GroupEvolution from upgrade, got {other:?}"),
        }
    }

    pub async fn update_group_data(&mut self, name: impl Into<String>) -> PendingStateRef {
        self.update_group_profile(Some(name.into()), None).await
    }

    pub async fn update_group_profile(
        &mut self,
        name: Option<String>,
        description: Option<String>,
    ) -> PendingStateRef {
        let gid = self.default_group.clone().expect("group");
        let res = self
            .engine_mut()
            .send(SendIntent::UpdateGroupData {
                group_id: gid.clone(),
                name,
                description,
            })
            .await
            .expect("update group profile");
        self.publish_group_evolution(res, &gid, "update_group_profile")
            .await
    }

    pub async fn remove_members(&mut self, members: Vec<MemberId>) -> PendingStateRef {
        let gid = self.default_group.clone().expect("group");
        let result = self
            .engine_mut()
            .send(SendIntent::RemoveMembers {
                group_id: gid.clone(),
                members,
            })
            .await
            .expect("remove members");
        self.publish_group_evolution(result, &gid, "remove_members")
            .await
    }

    pub async fn self_update(&mut self) -> PendingStateRef {
        let gid = self.default_group.clone().expect("group");
        let result = self
            .engine_mut()
            .send(SendIntent::SelfUpdate {
                group_id: gid.clone(),
            })
            .await
            .expect("self update");
        self.publish_group_evolution(result, &gid, "self_update")
            .await
    }

    async fn publish_group_evolution(
        &mut self,
        result: SendResult,
        group_id: &GroupId,
        operation: &str,
    ) -> PendingStateRef {
        match result {
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                assert!(
                    welcomes.is_empty(),
                    "{operation} should not create welcomes"
                );
                let routed = route(msg, group_id);
                self.remember_pending_publication(pending, std::iter::once(routed.id.clone()));
                self.remember_pending_confirmation(pending, std::iter::once(routed.id.clone()));
                self.publish_commit_scenario_input(&routed, pending).await;
                self.bus.send(self.bus_id, routed);
                pending
            }
            other => panic!("expected GroupEvolution from {operation}, got {other:?}"),
        }
    }

    pub async fn update_admin_policy(
        &mut self,
        admins: Vec<MemberId>,
    ) -> Result<PendingStateRef, EngineError> {
        let gid = self.default_group.clone().expect("group");
        let data = encode_admin_policy(admins)?;
        let res = self
            .engine_mut()
            .send(SendIntent::UpdateAppComponents {
                group_id: gid.clone(),
                updates: vec![AppComponentData {
                    component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
                    data,
                }],
            })
            .await?;
        match res {
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                assert!(
                    welcomes.is_empty(),
                    "admin policy update should not create welcomes"
                );
                let routed = route(msg, &gid);
                self.remember_pending_publication(pending, std::iter::once(routed.id.clone()));
                self.remember_pending_confirmation(pending, std::iter::once(routed.id.clone()));
                self.publish_commit_scenario_input(&routed, pending).await;
                self.bus.send(self.bus_id, routed);
                Ok(pending)
            }
            other => Err(EngineError::Backend(format!(
                "expected GroupEvolution from update_admin_policy, got {other:?}"
            ))),
        }
    }

    pub fn admin_labels(&self) -> Vec<String> {
        let gid = self.default_group.clone().expect("group");
        self.engine()
            .admin_pubkeys(&gid)
            .expect("admin pubkeys")
            .into_iter()
            .map(|admin| logical_label_for_member_id(&admin).unwrap_or_else(|| hex::encode(admin)))
            .collect()
    }

    /// Send an application message and return the wrapped TransportMessage
    /// that was put on the bus. Useful for the same-id-replay proptest
    /// property which needs to re-inject that exact message.
    pub async fn send_app_capture(&mut self, payload: impl Into<Vec<u8>>) -> TransportMessage {
        let gid = self
            .default_group
            .clone()
            .expect("must create or join a group first");
        let payload = self.next_app_payload(payload.into());
        let (logical_id, logical_payload) = logical_message_fields(&payload);
        let scenario_input = self.next_scenario_input_metadata(
            ScenarioInputKind::Application,
            Some(logical_id),
            Some(logical_payload),
        );
        self.scenario_input_tracker
            .record_send_attempt(&scenario_input);
        let res = self
            .engine_mut()
            .send(SendIntent::AppMessage {
                group_id: gid.clone(),
                payload,
            })
            .await
            .expect("send app");
        match res {
            SendResult::ApplicationMessage { msg, .. } => {
                self.scenario_input_tracker
                    .record_send_accepted(&scenario_input, false);
                let routed = route(msg, &gid);
                self.register_published_scenario_input(&routed, scenario_input)
                    .await;
                self.bus.send(self.bus_id, routed.clone());
                routed
            }
            _ => panic!("expected ApplicationMessage"),
        }
    }

    /// Send an application message to the default group.
    pub async fn send_app(&mut self, payload: impl Into<Vec<u8>>) {
        let _ = self
            .try_send_app(payload)
            .await
            .expect("send app message through harness");
    }

    pub async fn request_disband(&mut self) -> Result<(), EngineError> {
        let group_id = self.default_group.clone().expect("group");
        match self
            .engine_mut()
            .send(SendIntent::Disband { group_id })
            .await?
        {
            SendResult::DisbandRequested { .. } => Ok(()),
            other => Err(EngineError::Backend(format!(
                "expected DisbandRequested, got {other:?}"
            ))),
        }
    }

    pub(crate) async fn try_send_app(
        &mut self,
        payload: impl Into<Vec<u8>>,
    ) -> Result<(DecryptabilityProbeSendStatus, String), EngineError> {
        let gid = self
            .default_group
            .clone()
            .ok_or_else(|| EngineError::Other("must create or join a group first".into()))?;
        let payload = self.next_app_payload(payload.into());
        let (logical_id, logical_payload) = logical_message_fields(&payload);
        let scenario_input = self.next_scenario_input_metadata(
            ScenarioInputKind::Application,
            Some(logical_id.clone()),
            Some(logical_payload),
        );
        self.scenario_input_tracker
            .record_send_attempt(&scenario_input);
        let res = self
            .engine_mut()
            .send(SendIntent::AppMessage {
                group_id: gid.clone(),
                payload,
            })
            .await?;
        match res {
            SendResult::ApplicationMessage { msg, .. } => {
                self.scenario_input_tracker
                    .record_send_accepted(&scenario_input, false);
                let routed = route(msg, &gid);
                self.register_published_scenario_input(&routed, scenario_input)
                    .await;
                self.bus.send(self.bus_id, routed);
                Ok((DecryptabilityProbeSendStatus::Published, logical_id))
            }
            SendResult::Queued { .. } => {
                self.scenario_input_tracker
                    .record_send_accepted(&scenario_input, true);
                Ok((DecryptabilityProbeSendStatus::Queued, logical_id))
            }
            other => Err(EngineError::Backend(format!(
                "expected ApplicationMessage or Queued, got {other:?}"
            ))),
        }
    }

    /// Invite new members to the default group.
    pub async fn invite(&mut self, kps: Vec<KeyPackage>) -> PendingStateRef {
        self.try_invite(kps).await.expect("send invite")
    }

    /// Invite new members to the default group, surfacing the engine error
    /// instead of panicking. Nothing reaches the bus on failure. Used by
    /// scenarios that deliberately fail an invite during commit staging
    /// (e.g. the phantom committed-from regression).
    pub async fn try_invite(
        &mut self,
        kps: Vec<KeyPackage>,
    ) -> Result<PendingStateRef, EngineError> {
        let gid = self.default_group.clone().expect("group");
        let res = self
            .engine_mut()
            .send(SendIntent::Invite {
                group_id: gid.clone(),
                key_packages: kps,
                initial_admins: vec![],
            })
            .await?;
        match res {
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                // Send welcomes before the commit so new members join via
                // welcome and only then classify the commit echo as
                // AlreadyAtEpoch.
                let routed = route(msg, &gid);
                self.remember_pending_publication(
                    pending,
                    welcomes
                        .iter()
                        .map(|welcome| welcome.id.clone())
                        .chain(std::iter::once(routed.id.clone())),
                );
                self.remember_pending_confirmation(pending, std::iter::once(routed.id.clone()));
                for w in welcomes {
                    self.bus.send(self.bus_id, w);
                }
                self.publish_commit_scenario_input(&routed, pending).await;
                self.bus.send(self.bus_id, routed);
                Ok(pending)
            }
            other => Err(EngineError::Other(format!(
                "expected GroupEvolution, got {other:?}"
            ))),
        }
    }

    /// Send a SelfRemove proposal (Leave intent).
    pub async fn leave(&mut self) -> Result<(), EngineError> {
        self.leave_capture().await.map(|_| ())
    }

    /// Send a SelfRemove proposal and return the wrapped transport message.
    ///
    /// A refused leave releases any id reserved via
    /// [`Self::name_next_scenario_input`]; only a sent proposal consumes it,
    /// so the next named action neither trips the unconsumed-id assertion nor
    /// inherits the failed leave's id.
    pub async fn leave_capture(&mut self) -> Result<TransportMessage, EngineError> {
        let result = self.leave_capture_inner().await;
        if result.is_err() {
            self.next_scenario_input_id = None;
        }
        result
    }

    async fn leave_capture_inner(&mut self) -> Result<TransportMessage, EngineError> {
        let gid = self
            .default_group
            .clone()
            .ok_or_else(|| EngineError::Other("must create or join a group first".into()))?;
        let res = self
            .engine_mut()
            .send(SendIntent::Leave {
                group_id: gid.clone(),
            })
            .await?;
        if let SendResult::Proposal { msg } = res {
            let scenario_input =
                self.next_scenario_input_metadata(ScenarioInputKind::Proposal, None, None);
            self.scenario_input_tracker
                .record_send_attempt(&scenario_input);
            self.scenario_input_tracker
                .record_send_accepted(&scenario_input, false);
            let routed = route(msg, &gid);
            self.register_published_scenario_input(&routed, scenario_input)
                .await;
            self.bus.send(self.bus_id, routed.clone());
            Ok(routed)
        } else {
            Err(EngineError::Other(format!(
                "expected Proposal, got {}",
                send_result_kind(&res)
            )))
        }
    }

    /// Drain the bus mailbox into the engine and simulate due convergence
    /// timer work. Returns ingest outcomes for each message in order.
    pub async fn tick(&mut self) -> Vec<Result<IngestOutcome, EngineError>> {
        let mut outcomes = self.tick_ingest_only().await;
        if let Some(gid) = self.default_group.clone() {
            let now_ms = self.harness_convergence_now_ms();
            // The legacy harness shortcut represents both sides of a timer
            // boundary in one tick. Give newly peeled inputs an explicit
            // pre-cutoff admission point before the far-future settlement
            // point; production and virtual-time subjects use their real
            // single clock instant and never take this compatibility prepass.
            if !self.virtual_time_tick_enabled
                && let Err(e) = self
                    .engine_mut()
                    .advance_convergence_inputs_until_settled(&gid, 0)
                    .await
            {
                outcomes.push(Err(EngineError::Backend(format!(
                    "prepare buffered group: {e}"
                ))));
                return outcomes;
            }
            match self
                .engine_mut()
                .advance_convergence_inputs_until_settled(&gid, now_ms)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    outcomes.push(Err(EngineError::Backend(format!(
                        "converge buffered group: {e}"
                    ))));
                    return outcomes;
                }
            }
            self.capture_engine_events();
        }
        self.drive_due_convergence(&mut outcomes).await;
        self.drain_auto_publish().await;
        outcomes
    }

    /// Ingest every message in the mailbox without running convergence.
    ///
    /// Production clients defer commit application to a scheduled convergence
    /// pass; this helper models that ingest-only boundary.
    pub async fn tick_ingest_only(&mut self) -> Vec<Result<IngestOutcome, EngineError>> {
        let inbound = self.bus.mailbox(self.bus_id);
        let mut outcomes = Vec::with_capacity(inbound.len());
        for msg in inbound {
            let scenario_input = self.bus.scenario_input_for_transport(&msg.id);
            let result = self.engine_mut().ingest(msg).await;
            if let Some(scenario_input) = scenario_input {
                self.scenario_input_tracker
                    .record_ingest(&scenario_input, result.as_ref().map_err(|_| ()));
            }
            if result.is_ok() {
                self.capture_engine_events();
            }
            outcomes.push(result);
        }
        outcomes
    }

    /// Override the engine-wide convergence policy (quiescence window, etc.).
    ///
    /// Debug/test harness escape hatch; release builds reject non-v1 policies.
    pub fn set_convergence_policy(&mut self, policy: CanonicalizationPolicy) {
        self.engine_mut()
            .set_convergence_policy(policy)
            .expect("convergence policy accepted");
    }

    /// Run the same convergence entry point the app uses after a scheduled
    /// timer (`CgkaEngine::advance_convergence`), then capture emitted events.
    pub async fn advance_convergence(&mut self) -> Result<(), EngineError> {
        let gid = self.default_group.clone().expect("group");
        let results = self.engine_mut().advance_convergence(&gid).await?;
        self.capture_engine_events();
        for result in results {
            self.publish_send_result(result).await?;
        }
        self.drain_auto_publish().await;
        Ok(())
    }

    /// Model the fixed marmot-app account worker: if a scheduled pass did not
    /// settle stored convergence inputs, wait for the quiescence window (+ the
    /// same schedule margin production uses) and run one retry pass.
    ///
    /// Production re-arms repeatedly until inputs settle; this helper models only
    /// the first re-arm after a premature tick.
    pub async fn advance_convergence_with_app_retry(
        &mut self,
        quiescence_ms: u64,
    ) -> Result<(), EngineError> {
        const SCHEDULE_MARGIN_MS: u64 = 100;
        self.advance_convergence().await?;
        if !self.has_pending_convergence_inputs() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(
            quiescence_ms.saturating_add(SCHEDULE_MARGIN_MS),
        ))
        .await;
        self.advance_convergence().await
    }

    pub fn has_pending_convergence_inputs(&self) -> bool {
        let gid = self.default_group.clone().expect("group");
        self.engine()
            .has_pending_convergence_inputs(&gid)
            .expect("pending convergence probe")
    }

    pub fn received_app_payloads(&mut self) -> Vec<Vec<u8>> {
        self.capture_engine_events();
        self.pending_events
            .iter()
            .filter_map(|event| match event {
                GroupEvent::MessageReceived { payload, .. } => {
                    Some(decode_harness_app_payload(payload))
                }
                _ => None,
            })
            .collect()
    }

    /// Drains the next one-shot convergence schedule batch.
    fn drain_harness_convergence_groups(&mut self) -> Vec<GroupId> {
        #[cfg(test)]
        if let Some(script) = self.scripted_convergence_drain.as_mut() {
            return script.drain_pending_groups();
        }
        self.engine_mut().drain_pending_convergence_groups()
    }

    /// Captures structural progress through the production or scripted seam.
    fn harness_convergence_progress(
        &self,
        group_id: &GroupId,
    ) -> Result<ConformanceStructuralProgressSnapshot, EngineError> {
        #[cfg(test)]
        if let Some(script) = self.scripted_convergence_drain.as_ref() {
            assert_eq!(&script.group_id, group_id, "scripted convergence group");
            return Ok(script.progress());
        }
        self.engine()
            .conformance_structural_progress_snapshot(group_id)
    }

    /// Runs one convergence attempt through the production or scripted seam.
    async fn harness_converge_and_drain(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<Vec<SendResult>, EngineError> {
        #[cfg(test)]
        if let Some(script) = self.scripted_convergence_drain.as_mut() {
            assert_eq!(&script.group_id, group_id, "scripted convergence group");
            return script.converge();
        }
        self.engine_mut()
            .converge_and_drain_queued_outbound_intents(group_id, now_ms)
            .await
    }

    /// Executes one deterministic convergence-work slice for this harness tick.
    async fn drive_due_convergence(
        &mut self,
        outcomes: &mut Vec<Result<IngestOutcome, EngineError>>,
    ) {
        let now_ms = self.harness_convergence_now_ms();
        let mut successful_attempts =
            HashMap::<GroupId, (usize, ConformanceStructuralProgressSnapshot)>::new();
        let mut encountered_error = false;
        for _ in 0..HARNESS_CONVERGENCE_DRAIN_PASSES {
            let mut groups = self.drain_harness_convergence_groups();
            if groups.is_empty() {
                return;
            }
            groups.sort_by(|left, right| left.as_slice().cmp(right.as_slice()));
            for group_id in groups {
                let initial_progress = if successful_attempts.contains_key(&group_id) {
                    None
                } else {
                    match self.harness_convergence_progress(&group_id) {
                        Ok(progress) => Some(progress),
                        Err(error) => {
                            outcomes.push(Err(error));
                            encountered_error = true;
                            continue;
                        }
                    }
                };
                let results = match self.harness_converge_and_drain(&group_id, now_ms).await {
                    Ok(results) => results,
                    Err(e) => {
                        outcomes.push(Err(e));
                        encountered_error = true;
                        continue;
                    }
                };
                self.capture_engine_events();
                for result in results {
                    if let Err(e) = self.publish_send_result(result).await {
                        outcomes.push(Err(e));
                        encountered_error = true;
                    }
                }
                self.drain_auto_publish().await;
                successful_attempts
                    .entry(group_id)
                    .and_modify(|(attempts, _)| {
                        *attempts = attempts.saturating_add(1);
                    })
                    .or_insert_with(|| {
                        (
                            1,
                            initial_progress.expect("untracked group captured initial progress"),
                        )
                    });
            }
        }
        if encountered_error {
            return;
        }
        let mut successful_attempts = successful_attempts.into_iter().collect::<Vec<_>>();
        successful_attempts.sort_by(|(left, _), (right, _)| left.as_slice().cmp(right.as_slice()));
        for (group_id, (attempts, initial)) in successful_attempts {
            let mut current = match self.harness_convergence_progress(&group_id) {
                Ok(progress) => progress,
                Err(error) => {
                    outcomes.push(Err(error));
                    return;
                }
            };
            let continuation_scheduled = current.pending_work.scheduled_convergence_groups > 0;
            // The one-shot schedule edge was drained before the initial
            // snapshot. Normalize a re-armed edge out of the comparison.
            current.pending_work.scheduled_convergence_groups = 0;
            if let Err(error) = ensure_convergence_drain_progress(
                attempts,
                continuation_scheduled,
                &initial,
                &current,
            ) {
                outcomes.push(Err(error));
                return;
            }
        }
    }

    /// A subject switches to its injected clock on the first virtual-time
    /// advance. Other harness clients retain the historical far-future
    /// settlement shortcut.
    fn harness_convergence_now_ms(&self) -> u64 {
        if self.virtual_time_tick_enabled {
            self.convergence_clock
                .as_ref()
                .map(|clock| clock.now().monotonic_ms)
                .unwrap_or(HARNESS_CONVERGENCE_SETTLED_AT_MS)
        } else {
            HARNESS_CONVERGENCE_SETTLED_AT_MS
        }
    }

    async fn publish_send_result(&mut self, result: SendResult) -> Result<(), EngineError> {
        let gid = self.default_group.clone();
        match result {
            SendResult::ApplicationMessage {
                msg, app_event_id, ..
            } => {
                let queued_intent = self
                    .engine_mut()
                    .regenerated_queued_intent_for_message(&msg.id);
                let routed = if let Some(gid) = &gid {
                    route(msg, gid)
                } else {
                    msg
                };
                if let Some(queued_intent) = queued_intent {
                    self.regenerated_queued_intents
                        .insert(routed.id.clone(), queued_intent);
                }
                let scenario_input = self
                    .scenario_input_tracker
                    .metadata_for_logical(&app_event_id)
                    .ok_or_else(|| {
                        EngineError::Backend(format!(
                            "missing scenario-input metadata for regenerated app event {app_event_id}"
                        ))
                    })?;
                self.register_published_scenario_input(&routed, scenario_input)
                    .await;
                self.bus.send(self.bus_id, routed);
            }
            SendResult::Proposal { msg } => {
                let queued_intent = self
                    .engine_mut()
                    .regenerated_queued_intent_for_message(&msg.id);
                let routed = if let Some(gid) = &gid {
                    route(msg, gid)
                } else {
                    msg
                };
                if let Some(queued_intent) = queued_intent {
                    self.regenerated_queued_intents
                        .insert(routed.id.clone(), queued_intent);
                }
                let scenario_input =
                    self.next_scenario_input_metadata(ScenarioInputKind::Proposal, None, None);
                self.scenario_input_tracker
                    .record_send_attempt(&scenario_input);
                self.scenario_input_tracker
                    .record_send_accepted(&scenario_input, false);
                self.register_published_scenario_input(&routed, scenario_input)
                    .await;
                self.bus.send(self.bus_id, routed);
            }
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                let routed = if let Some(gid) = &gid {
                    route(msg, gid)
                } else {
                    msg
                };
                self.remember_pending_publication(
                    pending,
                    welcomes
                        .iter()
                        .map(|welcome| welcome.id.clone())
                        .chain(std::iter::once(routed.id.clone())),
                );
                self.remember_pending_confirmation(pending, std::iter::once(routed.id.clone()));
                for welcome in welcomes {
                    self.bus.send(self.bus_id, welcome);
                }
                self.publish_commit_scenario_input(&routed, pending).await;
                self.bus.send(self.bus_id, routed);
            }
            SendResult::GroupCreated { welcomes, pending } => {
                self.remember_pending_publication(
                    pending,
                    welcomes.iter().map(|welcome| welcome.id.clone()),
                );
                self.remember_pending_confirmation(
                    pending,
                    welcomes.iter().map(|welcome| welcome.id.clone()),
                );
                for welcome in welcomes {
                    self.bus.send(self.bus_id, welcome);
                }
                self.confirm_empty_publication(pending).await?;
            }
            SendResult::FoundingGroupCreated { welcomes } => {
                for welcome in welcomes {
                    self.bus.send(self.bus_id, welcome);
                }
                self.capture_engine_events();
            }
            SendResult::NoChange { .. }
            | SendResult::DisbandRequested { .. }
            | SendResult::Queued { .. } => {}
        }
        Ok(())
    }

    async fn drain_auto_publish(&mut self) {
        let auto = self.engine_mut().drain_auto_publish();
        let gid = self.default_group.clone();
        for auto in auto {
            let routed = if let Some(gid) = &gid {
                route(auto.msg, gid)
            } else {
                auto.msg
            };
            self.publish_commit_scenario_input(&routed, auto.pending)
                .await;
            self.remember_pending_publication(auto.pending, std::iter::once(routed.id.clone()));
            self.remember_pending_confirmation(auto.pending, std::iter::once(routed.id.clone()));
            self.bus.send(self.bus_id, routed);
        }
        let proposals = self.engine_mut().drain_auto_proposals();
        for msg in proposals {
            let queued_intent = self
                .engine_mut()
                .regenerated_queued_intent_for_message(&msg.id);
            let routed = if let Some(gid) = &gid {
                route(msg, gid)
            } else {
                msg
            };
            if let Some(queued_intent) = queued_intent {
                self.regenerated_queued_intents
                    .insert(routed.id.clone(), queued_intent);
            }
            let scenario_input =
                self.next_scenario_input_metadata(ScenarioInputKind::Proposal, None, None);
            self.scenario_input_tracker
                .record_send_attempt(&scenario_input);
            self.scenario_input_tracker
                .record_send_accepted(&scenario_input, false);
            self.register_published_scenario_input(&routed, scenario_input)
                .await;
            self.bus.send(self.bus_id, routed);
        }
    }

    pub fn drain_events(&mut self) -> Vec<GroupEvent> {
        self.capture_engine_events();
        std::mem::take(&mut self.pending_events)
    }

    /// Count matching application payloads in the current observation window
    /// without consuming the events that a later report observation must see.
    pub(crate) fn pending_payload_count(&mut self, expected: &str) -> usize {
        self.capture_engine_events();
        self.pending_events
            .iter()
            .filter_map(|event| match event {
                GroupEvent::MessageReceived { payload, .. } => {
                    Some(decode_harness_app_payload(payload))
                }
                _ => None,
            })
            .filter(|payload| payload.as_slice() == expected.as_bytes())
            .count()
    }

    pub fn epoch(&self) -> EpochId {
        let gid = self.default_group.clone().expect("group");
        self.engine().epoch(&gid).expect("epoch")
    }

    pub(crate) fn has_active_group(&self) -> bool {
        self.default_group
            .as_ref()
            .is_some_and(|group_id| self.engine().epoch(group_id).is_ok())
    }

    pub fn members(&self) -> Vec<cgka_traits::group::Member> {
        let gid = self.default_group.clone().expect("group");
        match self.engine().members(&gid) {
            Ok(members) => members,
            Err(error) => {
                let record = self.engine().group_record(&gid).unwrap_or_else(|_| {
                    panic!("members unavailable without terminal group record: {error}")
                });
                assert!(
                    record.disbanded.is_some(),
                    "members unavailable for non-disbanded group: {error}"
                );
                record.members
            }
        }
    }

    /// Current app-facing group name mirrored from signed group-profile state.
    ///
    /// This is a branch-sensitive observable: a `marmot.group.profile.v1`
    /// (`UpdateGroupData`) commit changes only the group name/description, which
    /// epoch and member-count observations cannot distinguish. Two clients stuck
    /// on different competing group-data branches share the same epoch and member
    /// count but observe different names, so convergence oracles compare this to
    /// catch a permanent fork that epoch/member equality alone would miss.
    pub fn group_name(&self) -> String {
        let gid = self.default_group.clone().expect("group");
        self.engine().group_record(&gid).expect("group record").name
    }

    /// Current app-facing group description mirrored from signed group-profile state.
    pub fn group_description(&self) -> String {
        let gid = self.default_group.clone().expect("group");
        self.engine()
            .group_record(&gid)
            .expect("group record")
            .description
    }

    pub fn group_id(&self) -> GroupId {
        self.default_group.clone().expect("group")
    }

    /// Capture the conformance-only canonical state projection for the default
    /// group without exposing the wrapped engine to scenario code.
    pub fn canonical_group_snapshot(
        &self,
    ) -> cgka_engine::conformance_snapshot::ConformanceGroupSnapshot {
        let group_id = self.default_group.clone().expect("group");
        self.engine()
            .conformance_group_snapshot(&group_id)
            .expect("capture canonical group snapshot")
    }

    pub fn canonical_state_snapshot(
        &self,
    ) -> cgka_engine::conformance_snapshot::ConformanceCanonicalStateSnapshot {
        self.try_canonical_state_snapshot()
            .expect("capture canonical state snapshot")
    }

    pub(crate) fn try_canonical_state_snapshot(
        &self,
    ) -> Result<cgka_engine::conformance_snapshot::ConformanceCanonicalStateSnapshot, EngineError>
    {
        let group_id = self
            .default_group
            .clone()
            .ok_or_else(|| EngineError::Other("no default group to snapshot".into()))?;
        self.engine()
            .conformance_canonical_state_snapshot(&group_id)
    }

    pub fn scenario_input_ledger(&mut self) -> Vec<ScenarioInputLedgerEntry> {
        let observed_states = self
            .scenario_input_tracker
            .state_queries()
            .into_iter()
            .map(|(scenario_id, kind, aliases)| {
                let state = self
                    .engine()
                    .conformance_message_state(&aliases)
                    .expect("capture conformance message state");
                (scenario_id, kind, state)
            })
            .collect::<Vec<_>>();
        for (scenario_id, kind, state) in observed_states {
            match state {
                Some(state) => {
                    self.scenario_input_tracker
                        .record_storage_state(&scenario_id, kind, state)
                }
                None => self
                    .scenario_input_tracker
                    .record_storage_absence(&scenario_id),
            }
        }
        self.scenario_input_tracker.snapshot()
    }

    pub fn pending_work_observation(&self) -> PendingWorkObservation {
        let group_id = self.default_group.clone().expect("group");
        let engine = self
            .engine()
            .conformance_pending_work_snapshot(&group_id)
            .expect("capture conformance pending work");
        let bus = self.bus.pending_work_snapshot(self.bus_id);
        PendingWorkObservation {
            engine,
            bus_queued_messages: bus.queued_messages,
            bus_delayed_messages: bus.delayed_messages,
            bus_mailbox_messages: bus.mailbox_messages,
            scenario_inputs_pending: self.scenario_input_tracker.pending_count(),
        }
    }

    pub(crate) fn structural_progress_observation(
        &self,
        client: String,
    ) -> Result<ClientStructuralProgress, EngineError> {
        Ok(ClientStructuralProgress {
            client,
            engine: self
                .default_group
                .as_ref()
                .map(|group_id| {
                    self.engine()
                        .conformance_structural_progress_snapshot(group_id)
                })
                .transpose()?,
            scenario_inputs_pending: self.scenario_input_tracker.pending_count(),
        })
    }

    fn next_app_payload(&mut self, payload: Vec<u8>) -> Vec<u8> {
        let seq = self.app_event_counter;
        self.app_event_counter = self
            .app_event_counter
            .checked_add(1)
            .expect("app event counter exhausted");
        encode_harness_app_payload(&self.engine().self_id(), seq, payload)
    }

    async fn publish_commit_scenario_input(
        &mut self,
        message: &TransportMessage,
        pending: PendingStateRef,
    ) {
        let scenario_input =
            self.next_scenario_input_metadata(ScenarioInputKind::Commit, None, None);
        self.scenario_input_tracker
            .record_send_attempt(&scenario_input);
        self.scenario_input_tracker
            .record_send_accepted(&scenario_input, false);
        let scenario_input = self
            .register_published_scenario_input(message, scenario_input)
            .await;
        self.remember_pending_scenario_input(pending, &scenario_input);
    }

    async fn register_published_scenario_input(
        &mut self,
        message: &TransportMessage,
        mut metadata: ScenarioInputMetadata,
    ) -> ScenarioInputMetadata {
        metadata.aliases = self
            .engine()
            .conformance_message_aliases(&message.id)
            .expect("sender exposes durable scenario-input aliases");
        let content_id = metadata
            .aliases
            .iter()
            .find(|alias| **alias != message.id)
            .cloned()
            .unwrap_or_else(|| message.id.clone());
        self.bus
            .register_scenario_input(message.id.clone(), content_id, metadata.clone());
        self.scenario_input_tracker.record_published(&metadata);
        metadata
    }

    fn next_scenario_input_metadata(
        &mut self,
        kind: ScenarioInputKind,
        logical_id: Option<String>,
        payload: Option<String>,
    ) -> ScenarioInputMetadata {
        let sequence = self.scenario_input_counter;
        self.scenario_input_counter = self
            .scenario_input_counter
            .checked_add(1)
            .expect("scenario input counter exhausted");
        let sender = logical_label_for_member_id(&self.identity)
            .unwrap_or_else(|| hex::encode(&self.identity));
        let scenario_id = self
            .next_scenario_input_id
            .take()
            .unwrap_or_else(|| format!("{sender}/{}-{sequence}", kind.label()));
        ScenarioInputMetadata {
            scenario_id,
            kind,
            sender,
            logical_id,
            payload,
            aliases: Vec::new(),
        }
    }

    fn remember_pending_scenario_input(
        &mut self,
        pending: PendingStateRef,
        metadata: &ScenarioInputMetadata,
    ) {
        self.pending_scenario_inputs
            .insert(pending, metadata.scenario_id.clone());
    }

    fn remember_pending_publication(
        &mut self,
        pending: PendingStateRef,
        message_ids: impl IntoIterator<Item = MessageId>,
    ) {
        self.pending_publication_artifacts
            .entry(pending)
            .or_default()
            .extend(message_ids);
    }

    fn remember_pending_confirmation(
        &mut self,
        pending: PendingStateRef,
        message_ids: impl IntoIterator<Item = MessageId>,
    ) {
        self.pending_confirmation_artifacts
            .entry(pending)
            .or_default()
            .extend(message_ids);
    }

    /// Return a clone of `msg` whose payload is the peeled MLS wire bytes.
    ///
    /// This keeps replay/projection tests honest about the transport boundary:
    /// harness delivery still uses Nostr-shaped events, while OpenMLS probes
    /// receive the same bytes the engine sees after peeling.
    pub async fn openmls_projection_message(
        &self,
        msg: &TransportMessage,
    ) -> Result<TransportMessage, String> {
        let group_id = match &msg.envelope {
            TransportEnvelope::GroupMessage { .. } => self
                .default_group
                .clone()
                .ok_or_else(|| "must create or join a group first".to_owned())?,
            TransportEnvelope::Welcome { .. } => {
                return Err("welcomes do not carry MLS group-message bytes".into());
            }
        };
        let ctx = self
            .engine()
            .group_context(&group_id)
            .map_err(|e| format!("group context: {e}"))?;
        let snapshot = GroupContextSnapshot::from_context(
            ctx.as_ref(),
            &[transport_nostr_peeler::DEFAULT_EXPORTER_LABEL],
        );
        let peeled = NostrMlsPeeler::default()
            .peel_group_message(msg, &snapshot)
            .await
            .map_err(|e| format!("peel group message: {e}"))?;
        match peeled.content {
            PeeledContent::MlsMessage { bytes } => Ok(TransportMessage {
                payload: bytes,
                ..msg.clone()
            }),
            PeeledContent::Welcome { .. } => Err("group peeler returned a welcome".into()),
        }
    }
}

impl HarnessClient {
    pub(crate) fn capture_engine_events(&mut self) {
        let events = self.engine_mut().drain_events();
        let mut delivered_application_events = Vec::new();
        for event in events {
            match &event {
                GroupEvent::GroupJoined {
                    group_id,
                    via_welcome,
                    ..
                } => {
                    if self.default_group.is_none() {
                        self.default_group = Some(group_id.clone());
                    }
                    delivered_application_events.push(via_welcome.clone());
                }
                GroupEvent::TransportObjectResourceRefused { message_id, .. } => {
                    // Deferred-peel storage is keyed by the raw transport id,
                    // but alternate peelers and migrated rows may report the
                    // content-derived alias. Treat both durable aliases as the
                    // same scenario input so a released row cannot remain
                    // falsely pending in the black-box ledger.
                    if let Some(scenario_input) = self
                        .bus
                        .scenario_input_for_transport(message_id)
                        .or_else(|| self.bus.scenario_input_for_content(message_id))
                    {
                        self.scenario_input_tracker
                            .record_resource_refused(&scenario_input);
                    }
                }
                GroupEvent::MessageReceived {
                    message_id,
                    payload,
                    ..
                } => {
                    let (logical_id, _) = logical_message_fields(payload);
                    self.scenario_input_tracker
                        .record_delivered_logical(&logical_id);
                    delivered_application_events.push(message_id.clone());
                }
                GroupEvent::AppMessageInvalidated {
                    message_id, reason, ..
                } => {
                    if let Some(scenario_input) = self.bus.scenario_input_for_content(message_id) {
                        self.scenario_input_tracker
                            .record_app_invalidated(&scenario_input, *reason);
                    }
                }
                GroupEvent::CommitRolledBack {
                    invalidated_commit_id,
                    ..
                } => {
                    if let Some(scenario_input) = self
                        .bus
                        .scenario_input_for_transport(invalidated_commit_id)
                        .or_else(|| self.bus.scenario_input_for_content(invalidated_commit_id))
                    {
                        self.scenario_input_tracker
                            .record_commit_invalidated(&scenario_input, "commit_rolled_back");
                    }
                }
                GroupEvent::GroupStateInvalidated {
                    invalidated_commit_id,
                    ..
                } => {
                    if let Some(scenario_input) = self
                        .bus
                        .scenario_input_for_transport(invalidated_commit_id)
                        .or_else(|| self.bus.scenario_input_for_content(invalidated_commit_id))
                    {
                        self.scenario_input_tracker.record_commit_invalidated(
                            &scenario_input,
                            "group_state_invalidated_superseded",
                        );
                    }
                }
                _ => {}
            }
            self.pending_events.push(event);
        }
        self.storage()
            .delete_pending_application_events(&delivered_application_events)
            .expect("captured application events are durably acknowledged");
    }
}

fn logical_message_fields(payload: &[u8]) -> (String, String) {
    let event = MarmotAppEvent::decode(payload).expect("harness application payload decodes");
    (
        event.id,
        String::from_utf8_lossy(&decode_harness_app_payload(payload)).into_owned(),
    )
}

pub fn encode_harness_app_payload(sender: &MemberId, sequence: u64, payload: Vec<u8>) -> Vec<u8> {
    let (content, tags) = match String::from_utf8(payload) {
        Ok(content) => (content, Vec::new()),
        Err(err) => (
            hex::encode(err.into_bytes()),
            vec![vec![
                "harness-payload-encoding".to_owned(),
                "hex".to_owned(),
            ]],
        ),
    };
    MarmotAppEvent::new(
        hex::encode(sender.as_slice()),
        1_700_000_000 + sequence,
        MARMOT_APP_EVENT_KIND_CHAT,
        tags,
        content,
    )
    .encode()
    .expect("harness app event encodes")
}

pub fn decode_harness_app_payload(payload: &[u8]) -> Vec<u8> {
    let Ok(event) = MarmotAppEvent::decode(payload) else {
        return payload.to_vec();
    };
    if event
        .tags
        .iter()
        .any(|tag| tag.as_slice() == ["harness-payload-encoding", "hex"])
        && let Ok(bytes) = hex::decode(&event.content)
    {
        return bytes;
    }
    event.content.into_bytes()
}

fn route(msg: TransportMessage, _gid: &GroupId) -> TransportMessage {
    msg
}

fn encode_admin_policy(admins: Vec<MemberId>) -> Result<Vec<u8>, EngineError> {
    let mut admins = admins
        .into_iter()
        .map(|admin| {
            let bytes = admin.as_slice();
            let admin: [u8; 32] = bytes.try_into().map_err(|_| {
                EngineError::Other(format!(
                    "admin policy requires 32-byte member identities; got {}",
                    bytes.len()
                ))
            })?;
            Ok(admin)
        })
        .collect::<Result<Vec<_>, EngineError>>()?;
    admins.sort();
    admins.dedup();

    let mut admin_bytes = Vec::with_capacity(admins.len() * 32);
    for admin in admins {
        admin_bytes.extend_from_slice(&admin);
    }
    let mut out = Vec::new();
    cgka_traits::app_components::encode_quic_varint(admin_bytes.len() as u64, &mut out);
    out.extend_from_slice(&admin_bytes);
    Ok(out)
}
