//! [`Engine<S>`] is the OpenMLS-backed [`CgkaEngine`] implementation.
//!
//! Generic over `S: cgka_traits::StorageProvider`. Holds OpenMLS RustCrypto
//! for the crypto + rand half of OpenMLS's provider surface, materializing an
//! `EngineOpenMlsProvider` on demand per MLS call.
//!
//! This file owns construction, trait dispatch, event drains, and small
//! read-only helpers. Group creation, ingest/send, publish lifecycle,
//! convergence, and capability logic live in focused sibling modules.

use crate::bounded_id_set::{BoundedIdSet, DEDUP_CACHE_CAPACITY};
use crate::convergence_clock::{ConvergenceClock, ConvergenceTime, SystemConvergenceClock};
use crate::feature_registry::FeatureRegistry;
use crate::identity::Identity;
use async_trait::async_trait;
use cgka_traits::OutboundFanout;
use cgka_traits::app_components::{AppComponentId, AppComponentSet, default_group_components};
use cgka_traits::capabilities::{Feature, FeatureStatus, GroupCapabilities};
use cgka_traits::engine::{
    AutoPublish, CgkaEngine, CreateGroupRequest, GroupEvent, GroupHydrationQuarantineReason,
    GroupStateChange, KeyPackage, SendIntent, SendResult,
};
use cgka_traits::engine_state::{PendingStateRef, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::group::{Group, Member, ProtocolProfile};
use cgka_traits::group_context::GroupContext;
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::maintenance::{MaintenanceRandom, WallClock};
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{LeaveRequest, StorageError, StorageProvider};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::MessageId;
use cgka_traits::types::{EpochId, GroupId, MemberId};
use marmot_forensics::{
    AuditEngineContext, AuditEventContext, AuditEventKind, AuditGroupContext, AuditRecord,
    ForensicRecorder, NoopRecorder,
};
use openmls::prelude::{
    MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent, Proposal, ProtocolMessage,
};
use openmls_rust_crypto::RustCrypto;
pub use openmls_traits::types::Ciphersuite;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tls_codec::{Deserialize as _, Serialize as _};

/// Default ciphersuite. MLS-1.0 mandatory-to-implement; TLS-ish naming.
pub const DEFAULT_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Clone, Copy)]
enum SendAcceptance {
    Prepare,
    QueueAppMessage,
}

#[derive(Clone, Copy, Debug, Default)]
struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now(&self) -> cgka_traits::Timestamp {
        cgka_traits::Timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    }

    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Default)]
struct OsMaintenanceRandom;

impl MaintenanceRandom for OsMaintenanceRandom {
    fn next_u64(&self) -> u64 {
        rand::rngs::OsRng.next_u64()
    }
}

fn hydration_quarantine_reason_tag(reason: GroupHydrationQuarantineReason) -> &'static str {
    match reason {
        GroupHydrationQuarantineReason::OpenMlsLoadFailed => "openmls_load_failed",
        GroupHydrationQuarantineReason::OpenMlsGroupMissing => "openmls_group_missing",
        GroupHydrationQuarantineReason::MemberValidationFailed => "member_validation_failed",
        GroupHydrationQuarantineReason::GroupRecordLoadFailed => "group_record_load_failed",
        GroupHydrationQuarantineReason::PendingCommitRecoveryFailed => {
            "pending_commit_recovery_failed"
        }
    }
}

pub(crate) fn hydration_quarantine_group_digest(group_id: &GroupId) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-hydration-quarantine-group/v1");
    hasher.update(group_id.as_slice());
    hex::encode(hasher.finalize())
}

/// OpenMLS-backed CGKA engine. Construct via [`EngineBuilder`].
/// A group-state change effected by a locally staged commit, buffered until
/// publish confirmation merges that commit. `actor` attributes the change: for
/// our own invite/remove/profile commits it is the local member; for an
/// auto-committed peer SelfRemove it is the leaving member, not us.
#[derive(Clone)]
pub(crate) struct PendingGroupStateChange {
    pub(crate) actor: Option<MemberId>,
    pub(crate) change: GroupStateChange,
}

#[derive(Clone, Debug)]
pub(crate) struct ScheduledSelfRemoveAutoCommit {
    pub(crate) group_id: GroupId,
    pub(crate) proposal_id: MessageId,
    pub(crate) source_epoch: EpochId,
    pub(crate) due_at_ms: u64,
}

pub struct Engine<S: StorageProvider> {
    pub(crate) storage: S,
    pub(crate) crypto: RustCrypto,
    pub(crate) identity: Identity,
    pub(crate) registry: FeatureRegistry,
    pub(crate) supported_app_components: AppComponentSet,
    /// Profile emitted by newly created KeyPackages and groups. Existing
    /// groups retain their independently persisted/wire-classified profile.
    pub(crate) new_protocol_profile: ProtocolProfile,
    pub(crate) peeler: Box<dyn TransportPeeler>,
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) max_past_epochs: usize,
    pub(crate) wall_clock: Arc<dyn WallClock>,
    pub(crate) maintenance_random: Arc<dyn MaintenanceRandom>,

    /// Per-group state-machine owner. Every transition, pending-ref
    /// allocation, and fork-detection marker flows through this struct.
    pub(crate) epoch_manager: crate::epoch_manager::EpochManager,

    /// Storage-layer identity of the origin commit behind each in-flight
    /// pending publish, so `do_confirm_published` can mark the sent commit
    /// row `Processed` (and key its own-commit checkpoint) and
    /// `do_publish_failed` can drop the entry again.
    pub(crate) pending_origin_commits: HashMap<PendingStateRef, MessageId>,

    pub(crate) events_buf: VecDeque<GroupEvent>,
    pub(crate) auto_publish_buf: VecDeque<AutoPublish>,
    /// Standalone proposal messages produced by engine-maintained lifecycle
    /// work. Unlike `auto_publish_buf`, these do not have a pending commit ref.
    pub(crate) auto_proposal_buf: VecDeque<TransportMessage>,
    /// Authenticated standalone proposals accepted during ingest. This
    /// internal signal lets the account scheduler reset its quiet window
    /// without exposing proposals as user-visible group events.
    pub(crate) valid_proposal_groups: HashSet<GroupId>,
    /// Group-state changes effected by a locally staged commit, with the actor
    /// to attribute each to. Buffered here because publish-before-apply defers
    /// the OpenMLS merge: the `GroupEvent::GroupStateChanged` events are emitted
    /// in `do_confirm_published`, once the pending commit is actually merged,
    /// and dropped in `do_publish_failed`.
    pub(crate) pending_state_changes: HashMap<PendingStateRef, Vec<PendingGroupStateChange>>,

    /// MessageIds the engine has ingested. Backs the typed duplicate exclusion.
    ///
    /// Bounded hot-process cache in front of the authoritative durable
    /// `MessageRecord` store (checked first in `do_ingest`), so an id that ages
    /// out of the cap is still classified by storage.
    pub(crate) seen_message_ids: BoundedIdSet<MessageId>,

    /// One-shot marker for a cap-dropped, unpersisted ingest. The outer
    /// `do_ingest` epilogue must not promote that retryable id into the
    /// terminal `seen_message_ids` cache.
    pub(crate) retryable_unpersisted_ingest_id: Option<MessageId>,
    /// Whether the last completed `ingest` left its transport object with no
    /// durable trace, so only relay redelivery can present it again. See
    /// [`Engine::last_ingest_left_object_unpersisted`].
    pub(crate) last_ingest_left_object_unpersisted: bool,

    /// MessageIds this engine has produced via `send` or `create_group` /
    /// `invite`. Backs the typed own-echo exclusion when a message we produced
    /// bounces back via ingest before we filter it client-side.
    ///
    /// Bounded hot-process cache; see `seen_message_ids` above.
    pub(crate) sent_message_ids: BoundedIdSet<MessageId>,

    /// Durable leave requests keyed by group. This is the source of truth for
    /// a user's request to leave across epoch changes and restarts.
    pub(crate) leave_requests: HashMap<GroupId, LeaveRequest>,

    /// Fast runtime gate for groups where the local member must not produce
    /// further outbound group traffic while a leave request is outstanding.
    pub(crate) leaving_groups: HashSet<GroupId>,

    /// Delayed SelfRemove auto-commit attempts keyed by the standalone
    /// proposal's content-derived message id. These are re-checked against live
    /// storage before staging so unrelated commits can invalidate them without
    /// producing a commit storm.
    pub(crate) scheduled_self_remove_auto_commits:
        HashMap<MessageId, ScheduledSelfRemoveAutoCommit>,

    /// Groups the application should feed through its convergence timer even
    /// when the triggering input was processed (for example, a delayed
    /// SelfRemove auto-commit schedule) rather than returned as
    /// `IngestOutcome::Buffered`.
    pub(crate) pending_convergence_groups: HashSet<GroupId>,

    /// Queued intents regenerated into standalone publish work. The session
    /// reads these associations when it builds `PublishWork`, then deletes
    /// the durable intent only after the transport reports acceptance. An
    /// intent present here is in flight: the drain must not regenerate it a
    /// second time until the host confirms or retries it (mdk#1472).
    pub(crate) queued_intent_by_message: HashMap<MessageId, (GroupId, MessageId)>,

    /// Queued group evolutions stay associated with their pending publish so
    /// confirm can delete the durable intent in the same transaction as the
    /// MLS merge. Publish failure drops only this in-memory association and
    /// leaves the intent queued for retry.
    pub(crate) queued_intent_by_pending: HashMap<PendingStateRef, (GroupId, MessageId)>,

    pub(crate) convergence_policy: crate::canonicalization::CanonicalizationPolicy,
    /// Test-only selection experiment switch. It is always true in production;
    /// only the feature-gated builder method can disable witness admission.
    #[cfg(feature = "test-policy-overrides")]
    pub(crate) admit_app_witnesses: bool,
    /// Optional hard replay-probe ceiling for explicit exhaustion campaigns.
    /// Production construction cannot set it.
    #[cfg(feature = "test-policy-overrides")]
    pub(crate) replay_probe_budget_override: Option<u64>,
    #[cfg(feature = "test-conformance-snapshot")]
    pub(crate) conformance_replay_probe_count: u64,
    pub(crate) convergence_clock: Arc<dyn ConvergenceClock>,
    /// Identifies the process-local monotonic clock domain persisted in active
    /// convergence passes. A mismatch on hydration forces deadline rebasing
    /// from the required millisecond wall clock.
    pub(crate) convergence_clock_instance_id: u64,

    /// Diagnostic post-settle reorg telemetry. Recorded at the convergence
    /// apply site and exposed via [`Engine::engine_metrics`]. Never an input to
    /// convergence or branch selection.
    pub(crate) engine_metrics: crate::engine_metrics::EngineMetrics,

    /// Forensic audit-log recorder. Defaults to [`NoopRecorder`] when the
    /// session is built without one. Engine call sites emit typed events
    /// at every state-relevant decision point so a later analyzer can
    /// reconstruct what each device saw and decided.
    pub(crate) recorder: Box<dyn ForensicRecorder>,
    pub(crate) audit_operation_counter: u64,
    /// Audit context for the in-flight local operation. The
    /// `*_with_audit_context` entry points set this around their `do_*` call so
    /// the secondary rows those emit (e.g. `message_state_changed`,
    /// `group_context`) inherit the operation's `human_action` instead of
    /// landing context-free. `None` outside a human-initiated operation.
    pub(crate) current_audit_context: Option<AuditEventContext>,

    /// Stored groups that failed session-open hydration and were skipped so the
    /// rest of the account could open (mdk#151 / #417). Keyed by group
    /// id with the coarse recovery reason, this is the engine-side source of
    /// truth the application reads to surface a per-group recovery flow
    /// (mdk#426) distinct from healthy or archived groups. Entries are
    /// added by [`Self::quarantine_stored_group_on_hydrate`] and removed by a
    /// successful [`Self::retry_hydrate_quarantined_group`].
    pub(crate) quarantined_groups: HashMap<GroupId, GroupHydrationQuarantineReason>,

    /// Groups seeded by the session-open cheap pass whose full per-group
    /// hydration (MLS load, validation, pending-commit recovery) has not run
    /// yet (mdk#1161). The seed grants each group a provisional
    /// `Stable(record.epoch)` epoch entry — so `live_group_ids` and the app
    /// projection keep listing it — while [`Self::ensure_group_live`] fails
    /// closed with [`EngineError::GroupNotHydrated`] on every gated surface.
    /// Membership leaves this set only through [`Self::ensure_hydrated`]:
    /// success promotes the group to live, failure moves it to
    /// [`Self::quarantined_groups`] exactly like an open-time quarantine.
    pub(crate) unhydrated_groups: HashSet<GroupId>,

    /// Seeded, non-disbanded groups with no durable transport-route row yet
    /// (records predating migration 0043, or a provider without a route
    /// store). While non-empty, a routing-index miss cannot be trusted:
    /// ingest backfills these groups' routes on demand — each group leaves
    /// this set permanently after one MLS load, preserving mdk#740's
    /// attacker-paced-scan bound in amortized form.
    pub(crate) route_backfill_pending: HashSet<GroupId>,

    /// Authoritative `transport_group_id -> GroupId` resolver for inbound
    /// routing (#740). A Nostr-routed group's `transport_group_id`
    /// (`nostr_group_id`) differs from its MLS group id, so the direct
    /// `get_group` lookup in `group_id_for_transport_group_id` misses on the
    /// normal production path; this index answers that in O(1) instead of the
    /// former O(groups) scan that deserialized EVERY joined `MlsGroup` — a scan
    /// that ran BEFORE payload authentication, so an unauthenticated peer could
    /// flood unknown `transport_group_id`s to force attacker-paced CPU + storage
    /// I/O. Populated for every group at hydration
    /// ([`Self::hydrate_one_stored_group`]) and establishment (`do_create_group`
    /// / `do_join_welcome`); a `transport_group_id` is immutable for a group's
    /// maintenance is needed for a static route. A `transport_group_id` CAN
    /// change via a Nostr routing-component update commit (rotation); every
    /// commit-apply site therefore calls [`Self::reindex_transport_group_id`],
    /// which additively inserts the new id while leaving the prior id in place
    /// for the rotation overlap window (this map is intentionally many-to-one).
    /// The engine has no group-deletion path today (`StorageProvider::delete_group`
    /// is never called from engine code; a left group's record is retained), so an
    /// entry cannot outlive its group — and even a hypothetical stale entry is
    /// self-correcting, since the resolved `GroupId` is loaded by the caller and a
    /// missing group is dropped as unknown. If engine-side group deletion is ever
    /// added, that site MUST remove the corresponding index entries.
    pub(crate) transport_group_id_index: HashMap<Vec<u8>, GroupId>,

    /// #636: cached hex-encoded snapshot of `seen_message_ids` for the
    /// convergence `CanonicalizationState`, tagged with the seen-set generation
    /// it was built from. A convergence drain runs the pass up to 16× and
    /// previously re-hex-encoded the whole (up to 100k-entry) set every pass;
    /// this rebuilds only when the set actually changed. `None` until first use.
    pub(crate) seen_message_ids_hex_cache: Option<(u64, std::collections::BTreeSet<String>)>,

    /// Per-group deferred-peel performance state: aggregate sweep count and
    /// cached row-count/cap bookkeeping. Correctness-critical completion and
    /// residence bookkeeping lives durably on each MessageRecord.
    pub(crate) deferred_peel: HashMap<GroupId, crate::message_processor::DeferredPeelGroupState>,

    /// Retry budget before a `PeelDeferred` row is resource-refused and
    /// released without terminal deduplication. Field (not a const) so tests
    /// can exhaust it quickly via [`Self::set_deferred_peel_retry_budget`].
    pub(crate) deferred_peel_retry_budget: u32,
    /// Durable local residence budget for a `PeelDeferred` row. Field (not a
    /// const) so deterministic tests can advance a short deadline.
    pub(crate) deferred_peel_residence_ms: u64,
    /// Foreground-only deferred-history allowance (mdk#1176). Kept as fields
    /// so deterministic tests can use a short deadline without changing the
    /// production contract.
    pub(crate) foreground_deferred_peel_budget_ms: u64,
    pub(crate) foreground_deferred_peel_rows: usize,
}

// ── Builder ─────────────────────────────────────────────────────────────────

/// Construction-time wiring for [`Engine`].
pub struct EngineBuilder<S: StorageProvider> {
    storage: S,
    identity_bytes: Option<Vec<u8>>,
    account_identity_proof_signer:
        Option<Arc<dyn crate::account_identity_proof::AccountIdentityProofSigner>>,
    registry: FeatureRegistry,
    supported_app_components: AppComponentSet,
    new_protocol_profile: ProtocolProfile,
    allow_legacy_compatibility_profile: bool,
    peeler: Option<Box<dyn TransportPeeler>>,
    ciphersuite: Ciphersuite,
    max_past_epochs: usize,
    wall_clock: Arc<dyn WallClock>,
    maintenance_random: Arc<dyn MaintenanceRandom>,
    convergence_clock: Arc<dyn ConvergenceClock>,
    #[cfg(feature = "test-policy-overrides")]
    admit_app_witnesses: bool,
    #[cfg(feature = "test-policy-overrides")]
    replay_probe_budget_override: Option<u64>,
    recorder: Option<Box<dyn ForensicRecorder>>,
}

impl<S: StorageProvider> EngineBuilder<S> {
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            identity_bytes: None,
            account_identity_proof_signer: None,
            registry: FeatureRegistry::new(),
            supported_app_components: AppComponentSet::new(default_group_components()),
            new_protocol_profile: ProtocolProfile::Current,
            allow_legacy_compatibility_profile: false,
            peeler: None,
            ciphersuite: DEFAULT_CIPHERSUITE,
            max_past_epochs: crate::wire_format::DEFAULT_MAX_PAST_EPOCHS,
            wall_clock: Arc::new(SystemWallClock),
            maintenance_random: Arc::new(OsMaintenanceRandom),
            convergence_clock: Arc::new(SystemConvergenceClock::default()),
            #[cfg(feature = "test-policy-overrides")]
            admit_app_witnesses: true,
            #[cfg(feature = "test-policy-overrides")]
            replay_probe_budget_override: None,
            recorder: None,
        }
    }

    pub fn identity(mut self, bytes: Vec<u8>) -> Self {
        self.identity_bytes = Some(bytes);
        self
    }

    pub fn account_identity_proof_signer(
        mut self,
        signer: Arc<dyn crate::account_identity_proof::AccountIdentityProofSigner>,
    ) -> Self {
        self.account_identity_proof_signer = Some(signer);
        self
    }

    pub fn feature_registry(mut self, registry: FeatureRegistry) -> Self {
        self.registry = registry;
        self
    }

    pub fn supported_app_components(
        mut self,
        components: impl IntoIterator<Item = AppComponentId>,
    ) -> Self {
        self.supported_app_components = AppComponentSet::new(components);
        self
    }

    /// Select the profile emitted by fresh KeyPackages and newly created
    /// groups. Defaults to current after the coordinated strict cutover.
    /// Passing legacy is rejected by [`Self::build`]; only the explicitly
    /// named compatibility-fixture seam can construct legacy artifacts.
    pub fn protocol_profile(mut self, protocol_profile: ProtocolProfile) -> Self {
        self.new_protocol_profile = protocol_profile;
        self.allow_legacy_compatibility_profile = false;
        self
    }

    /// Construct legacy artifacts only for compatibility fixtures and
    /// conformance coverage. This surface is absent from release builds.
    #[cfg(debug_assertions)]
    pub fn legacy_compatibility_profile(mut self) -> Self {
        self.new_protocol_profile = ProtocolProfile::Legacy;
        self.allow_legacy_compatibility_profile = true;
        self
    }

    pub fn peeler(mut self, peeler: Box<dyn TransportPeeler>) -> Self {
        self.peeler = Some(peeler);
        self
    }

    pub fn ciphersuite(mut self, cs: Ciphersuite) -> Self {
        self.ciphersuite = cs;
        self
    }

    pub fn max_past_epochs(mut self, max_past_epochs: usize) -> Self {
        self.max_past_epochs = max_past_epochs;
        self
    }

    pub fn maintenance_sources(
        mut self,
        wall_clock: Arc<dyn WallClock>,
        maintenance_random: Arc<dyn MaintenanceRandom>,
    ) -> Self {
        self.wall_clock = wall_clock;
        self.maintenance_random = maintenance_random;
        self
    }

    /// Install the convergence-only dual clock.
    ///
    /// This does not affect protocol, identity, transport-event, or
    /// maintenance timestamps.
    pub fn convergence_clock(mut self, clock: Arc<dyn ConvergenceClock>) -> Self {
        self.convergence_clock = clock;
        self
    }

    /// Disable application-message witnesses for a full-engine comparison.
    ///
    /// This does not define or negotiate another Marmot convergence policy.
    /// It exists only in explicit test-policy builds so campaigns can measure
    /// whether the v1 witness term changes outcomes enough to justify itself.
    #[cfg(feature = "test-policy-overrides")]
    pub fn without_app_witnesses_for_tests(mut self) -> Self {
        self.admit_app_witnesses = false;
        self
    }

    /// Override the per-pass OpenMLS replay-probe ceiling for fail-closed
    /// resource campaigns. A zero limit deterministically fails the first
    /// probe; `None` restores the production-derived budget.
    #[cfg(feature = "test-policy-overrides")]
    pub fn replay_probe_budget_for_tests(mut self, limit: Option<u64>) -> Self {
        self.replay_probe_budget_override = limit;
        self
    }

    /// Install a forensic audit-log recorder. Without this call the engine
    /// uses [`NoopRecorder`] and emits no audit events.
    pub fn recorder(mut self, recorder: Box<dyn ForensicRecorder>) -> Self {
        self.recorder = Some(recorder);
        self
    }

    pub fn build(self) -> Result<Engine<S>, EngineError> {
        if self.new_protocol_profile == ProtocolProfile::Legacy
            && !self.allow_legacy_compatibility_profile
        {
            return Err(EngineError::Other(
                "strict cutover forbids creating a legacy-profile engine".into(),
            ));
        }
        // spec/foundation/mls-protocol.md:11-15 — Marmot has a single
        // mandatory-to-implement ciphersuite. Reject any other ciphersuite at
        // construction so no group can ever be created off-spec.
        if self.ciphersuite != DEFAULT_CIPHERSUITE {
            return Err(EngineError::UnsupportedCiphersuite {
                got: u16::from(self.ciphersuite),
                required: u16::from(DEFAULT_CIPHERSUITE),
            });
        }
        // Normal builds keep the MLS past-epoch window pinned to the v1
        // app-message horizon. Only explicit test harness builds may shrink it
        // for decrypt-window probes (mdk#970).
        #[cfg(not(feature = "test-policy-overrides"))]
        if self.max_past_epochs != crate::wire_format::DEFAULT_MAX_PAST_EPOCHS {
            return Err(EngineError::Other(
                "max_past_epochs must equal the pinned v1 app-message window".into(),
            ));
        }
        let identity_bytes = self
            .identity_bytes
            .ok_or_else(|| EngineError::Other("identity bytes are required".into()))?;
        let peeler = self
            .peeler
            .ok_or_else(|| EngineError::Other("TransportPeeler is required".into()))?;
        let proof_signer = self.account_identity_proof_signer.ok_or_else(|| {
            EngineError::Other("account identity proof signer is required".into())
        })?;
        let crypto = RustCrypto::default();
        let identity = Identity::load_or_generate(
            self.ciphersuite,
            identity_bytes,
            &self.storage,
            self.new_protocol_profile,
            proof_signer.as_ref(),
        )
        .map_err(EngineError::Other)?;

        let pending_application_events = self.storage.list_pending_application_events()?;

        Ok(Engine {
            storage: self.storage,
            crypto,
            identity,
            registry: self.registry,
            supported_app_components: self.supported_app_components,
            new_protocol_profile: self.new_protocol_profile,
            peeler,
            ciphersuite: self.ciphersuite,
            max_past_epochs: self.max_past_epochs,
            wall_clock: self.wall_clock,
            maintenance_random: self.maintenance_random,
            epoch_manager: crate::epoch_manager::EpochManager::new(),
            pending_origin_commits: HashMap::new(),
            events_buf: pending_application_events.into(),
            auto_publish_buf: VecDeque::new(),
            auto_proposal_buf: VecDeque::new(),
            valid_proposal_groups: HashSet::new(),
            pending_state_changes: HashMap::new(),
            seen_message_ids: BoundedIdSet::with_capacity(DEDUP_CACHE_CAPACITY),
            retryable_unpersisted_ingest_id: None,
            last_ingest_left_object_unpersisted: false,
            sent_message_ids: BoundedIdSet::with_capacity(DEDUP_CACHE_CAPACITY),
            leave_requests: HashMap::new(),
            leaving_groups: HashSet::new(),
            scheduled_self_remove_auto_commits: HashMap::new(),
            pending_convergence_groups: HashSet::new(),
            queued_intent_by_message: HashMap::new(),
            queued_intent_by_pending: HashMap::new(),
            // Keep the in-memory app-message window aligned with MLS
            // `max_past_epochs` from construction so the two knobs cannot drift
            // before the first `set_convergence_policy` call.
            convergence_policy: crate::canonicalization::CanonicalizationPolicy {
                app_message_past_epoch_limit: self.max_past_epochs as u64,
                ..crate::canonicalization::CanonicalizationPolicy::default()
            },
            #[cfg(feature = "test-policy-overrides")]
            admit_app_witnesses: self.admit_app_witnesses,
            #[cfg(feature = "test-policy-overrides")]
            replay_probe_budget_override: self.replay_probe_budget_override,
            #[cfg(feature = "test-conformance-snapshot")]
            conformance_replay_probe_count: 0,
            convergence_clock: self.convergence_clock,
            convergence_clock_instance_id: rand::rngs::OsRng.next_u64(),
            engine_metrics: crate::engine_metrics::EngineMetrics::default(),
            recorder: self.recorder.unwrap_or_else(|| Box::new(NoopRecorder)),
            audit_operation_counter: 0,
            current_audit_context: None,
            quarantined_groups: HashMap::new(),
            unhydrated_groups: HashSet::new(),
            route_backfill_pending: HashSet::new(),
            transport_group_id_index: HashMap::new(),
            seen_message_ids_hex_cache: None,
            deferred_peel: HashMap::new(),
            deferred_peel_retry_budget: crate::message_processor::MAX_DEFERRED_PEEL_ATTEMPTS,
            deferred_peel_residence_ms: crate::message_processor::MAX_DEFERRED_PEEL_RESIDENCE_MS,
            foreground_deferred_peel_budget_ms:
                crate::message_processor::FOREGROUND_DEFERRED_PEEL_BUDGET_MS,
            foreground_deferred_peel_rows: crate::message_processor::MAX_FOREGROUND_DEFERRED_ROWS,
        })
    }
}

impl<S: StorageProvider> Engine<S> {
    /// Change the explicit replay-probe ceiling for a running exhaustion
    /// campaign. Production builds do not expose this method.
    #[cfg(feature = "test-policy-overrides")]
    pub fn set_replay_probe_budget_for_tests(&mut self, limit: Option<u64>) {
        self.replay_probe_budget_override = limit;
    }

    pub fn epoch_state(&self, group_id: &GroupId) -> Option<cgka_traits::EpochState> {
        if self.ensure_group_live(group_id).is_err() {
            return None;
        }
        self.epoch_manager.state(group_id).cloned()
    }

    /// Capture the adopted Marmot conformance projection for one live group.
    ///
    /// This synthetic-test interface is deliberately feature-gated. It returns
    /// public protocol state and a domain-separated exporter commitment, never
    /// the raw exporter secret. Production telemetry and app surfaces must not
    /// enable `test-conformance-snapshot`.
    #[cfg(feature = "test-conformance-snapshot")]
    pub fn conformance_group_snapshot(
        &self,
        group_id: &GroupId,
    ) -> Result<crate::conformance_snapshot::ConformanceGroupSnapshot, EngineError> {
        self.ensure_group_live(group_id)?;
        let epoch_state = self
            .epoch_manager
            .state(group_id)
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        crate::conformance_snapshot::capture_group_snapshot(
            &self.storage,
            &self.crypto,
            group_id,
            epoch_state,
        )
    }

    /// Capture exact canonical state for either a live group or an
    /// authenticated terminal disband tombstone.
    #[cfg(feature = "test-conformance-snapshot")]
    pub fn conformance_canonical_state_snapshot(
        &self,
        group_id: &GroupId,
    ) -> Result<crate::conformance_snapshot::ConformanceCanonicalStateSnapshot, EngineError> {
        self.ensure_group_live(group_id)?;
        if let Some(tombstone) = self.storage.disband_tombstone(group_id)? {
            return Ok(
                crate::conformance_snapshot::ConformanceCanonicalStateSnapshot::Disbanded(
                    crate::conformance_snapshot::capture_disbanded_group_snapshot(
                        group_id, &tombstone,
                    ),
                ),
            );
        }
        self.conformance_group_snapshot(group_id)
            .map(Box::new)
            .map(crate::conformance_snapshot::ConformanceCanonicalStateSnapshot::Live)
    }

    /// Capture aggregate outstanding work for the synthetic conformance
    /// simulator. This is an oracle diagnostic only and never affects engine
    /// scheduling or protocol decisions.
    #[cfg(feature = "test-conformance-snapshot")]
    pub fn conformance_pending_work_snapshot(
        &self,
        group_id: &GroupId,
    ) -> Result<crate::conformance_snapshot::ConformancePendingWorkSnapshot, EngineError> {
        crate::conformance_snapshot::capture_pending_work_snapshot(self, group_id)
    }

    /// Capture sanitized structural work and scheduling state for a black-box
    /// conformance runner. This read-only surface cannot influence selection.
    #[cfg(feature = "test-conformance-snapshot")]
    pub fn conformance_structural_progress_snapshot(
        &self,
        group_id: &GroupId,
    ) -> Result<crate::conformance_snapshot::ConformanceStructuralProgressSnapshot, EngineError>
    {
        crate::conformance_snapshot::capture_structural_progress_snapshot(self, group_id)
    }

    /// Read the durable state of one synthetic scenario input under either its
    /// transport or content-derived id.
    ///
    /// The simulator supplies both aliases because outbound and inbound copies
    /// of the same MLS bytes can use different storage keys. This observation is
    /// feature-gated, exposes no payload bytes, and never affects processing.
    #[cfg(feature = "test-conformance-snapshot")]
    pub fn conformance_message_state(
        &self,
        aliases: &[MessageId],
    ) -> Result<Option<cgka_traits::MessageState>, EngineError> {
        for alias in aliases {
            match self.storage.get_message(alias) {
                Ok(record) => return Ok(Some(record.state)),
                Err(cgka_traits::storage::StorageError::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(None)
    }

    /// Cumulative candidate replay probes since this engine process opened.
    #[cfg(feature = "test-conformance-snapshot")]
    pub fn conformance_replay_probe_count(&self) -> u64 {
        self.conformance_replay_probe_count
    }

    /// Return the transport and content-derived ids for a durable synthetic
    /// scenario input without exposing its wire bytes.
    ///
    /// Locally produced OpenMLS messages are retained under the exact
    /// transport id and a content marker. The simulator needs both aliases to
    /// correlate a re-wrapped inbound copy and later invalidation events, but
    /// must not re-peel a commit after the sender has already advanced state.
    #[cfg(feature = "test-conformance-snapshot")]
    pub fn conformance_message_aliases(
        &self,
        transport_id: &MessageId,
    ) -> Result<Vec<MessageId>, EngineError> {
        let record = self.storage.get_message(transport_id)?;
        let mut aliases = vec![transport_id.clone()];
        if let Ok(payload) = StoredMessagePayload::decode(&record.payload)
            && let Some(openmls_message) = payload.as_openmls_wire()
        {
            let content_id =
                MessageId::new(Sha256::digest(openmls_message.payload.as_slice()).to_vec());
            if content_id != *transport_id {
                aliases.push(content_id);
            }
        }
        Ok(aliases)
    }

    /// Persist a frozen transport fanout before or after one lifecycle edge.
    pub fn put_outbound_fanout(&self, fanout: &OutboundFanout) -> Result<(), EngineError> {
        if let Some(group_id) = fanout.group_id() {
            self.ensure_group_live(group_id)?;
        }
        self.storage.put_outbound_fanout(fanout)?;
        Ok(())
    }

    /// Read all frozen fanouts in original staging order.
    pub fn outbound_fanouts(&self) -> Result<Vec<OutboundFanout>, EngineError> {
        Ok(self
            .storage
            .list_outbound_fanouts()?
            .into_iter()
            .filter(|fanout| {
                fanout.group_id().is_none_or(|group_id| {
                    // Unhydrated groups' fanouts stay frozen until full
                    // hydration restores their pending lifecycle (mdk#1161);
                    // quarantined groups' fanouts are hidden as before.
                    !self.quarantined_groups.contains_key(group_id)
                        && !self.unhydrated_groups.contains(group_id)
                })
            })
            .collect())
    }

    /// Delete a terminal fanout after its outcome has been returned.
    pub fn delete_outbound_fanout(&self, message_id: &MessageId) -> Result<(), EngineError> {
        if let Some(group_id) = self
            .storage
            .outbound_fanout(message_id)?
            .as_ref()
            .and_then(OutboundFanout::group_id)
        {
            self.ensure_group_live(group_id)?;
        }
        self.storage.delete_outbound_fanout(message_id)?;
        Ok(())
    }

    /// Resolve the group owning a live pending reference without exposing
    /// epoch-manager internals across the session/runtime boundary.
    pub fn pending_group_id(&self, pending: PendingStateRef) -> Result<GroupId, EngineError> {
        let group_id = self
            .epoch_manager
            .group_for_pending(pending)
            .ok_or(EngineError::UnknownPending)?;
        self.ensure_group_live(&group_id)?;
        Ok(group_id)
    }

    /// Originating stored commit for a live pending publication.
    pub fn pending_origin_message_id(
        &self,
        pending: PendingStateRef,
    ) -> Result<MessageId, EngineError> {
        self.pending_group_id(pending)?;
        self.peek_pending_origin_commit(pending)
            .ok_or(EngineError::UnknownPending)
    }

    /// Durable fanout discriminator for a live pending publication.
    pub fn pending_fanout_kind(
        &self,
        pending: PendingStateRef,
    ) -> Result<cgka_traits::FanoutPendingKind, EngineError> {
        self.pending_group_id(pending)?;
        match self.epoch_manager.kind_for_pending(pending) {
            Some(crate::epoch_manager::PendingKind::CreateGroup) => {
                Ok(cgka_traits::FanoutPendingKind::CreateGroup)
            }
            Some(crate::epoch_manager::PendingKind::GroupEvolution) => {
                Ok(cgka_traits::FanoutPendingKind::GroupEvolution)
            }
            Some(crate::epoch_manager::PendingKind::Disband) => {
                Ok(cgka_traits::FanoutPendingKind::Disband)
            }
            None => Err(EngineError::UnknownPending),
        }
    }

    /// Confirm MLS and persist the matching fanout's terminal MLS edge in the
    /// same backend transaction.
    pub async fn confirm_published_fanout(
        &mut self,
        pending: PendingStateRef,
        fanout: &mut OutboundFanout,
    ) -> Result<GroupEvent, EngineError> {
        if let Some(group_id) = fanout.group_id() {
            self.ensure_group_live(group_id)?;
        }
        self.pending_group_id(pending)?;
        self.do_confirm_published_with_fanout(pending, Some(fanout))
            .await
    }

    /// Roll back MLS and persist the matching all-failed fanout edge in the
    /// same backend transaction.
    pub async fn publish_failed_fanout(
        &mut self,
        pending: PendingStateRef,
        fanout: &mut OutboundFanout,
    ) -> Result<(), EngineError> {
        if let Some(group_id) = fanout.group_id() {
            self.ensure_group_live(group_id)?;
        }
        self.pending_group_id(pending)?;
        self.do_publish_failed_with_fanout(pending, Some(fanout))
            .await
    }

    pub fn drain_valid_proposal_groups(&mut self) -> Vec<GroupId> {
        self.valid_proposal_groups.drain().collect()
    }

    /// Whether the last completed [`CgkaEngine::ingest`] left its transport
    /// object unpersisted, so relay redelivery is the only path back to it.
    ///
    /// This is the same fact that suppresses the engine's own seen-cache
    /// insertion (`retryable_unpersisted_ingest_id`), reported instead of left
    /// implicit. Callers that maintain their own dedup index must skip it for
    /// exactly these objects: an index entry with no durable object behind it
    /// makes the object permanently unfetchable, which is the opposite of the
    /// retry the engine deliberately left available.
    ///
    /// It is not recoverable from [`IngestOutcome`]. `ResourceRefused` is
    /// always unpersisted, but `Ignored { UnknownGroup }` is returned both for
    /// input the engine dropped without a trace (no group row: #740 forbids
    /// retaining unknown-route floods) and for input it durably dedup-marked
    /// (the disband-tombstone path). The two are indistinguishable in the
    /// outcome and must be treated differently, so the engine reports the
    /// disposition rather than making every caller re-derive a rule only it can
    /// know.
    pub fn last_ingest_left_object_unpersisted(&self) -> bool {
        self.last_ingest_left_object_unpersisted
    }

    pub async fn ingest_with_audit_context(
        &mut self,
        msg: TransportMessage,
        transport_context: Option<marmot_forensics::AuditTransportContext>,
    ) -> Result<IngestOutcome, EngineError> {
        let operation_id = self.next_audit_operation_id();
        let msg_id_hex = hex::encode(msg.id.as_slice());
        let mut context = AuditEventContext {
            operation_id: Some(operation_id.clone()),
            human_action: None,
            transport: transport_context,
            engine: None,
            group: None,
            convergence: None,
            source: None,
        };
        // Record the transport wire evidence before ingest when the transport
        // layer supplied it, so an analyzer sees what arrived on the wire ahead
        // of the engine's ingest_entry/outcome for the same message.
        if let Some(wire) = context
            .transport
            .as_ref()
            .and_then(|transport| transport.wire.clone())
        {
            self.audit_with_context(
                None,
                Some(context.clone()),
                crate::audit_helpers::transport_received_event(&msg, wire),
            );
        }
        self.audit_with_context(
            None,
            Some(context.clone()),
            crate::audit_helpers::ingest_entry_event(&msg),
        );
        let result = self.do_ingest(msg).await;
        match &result {
            Ok(outcome) => {
                let group_ref = crate::audit_helpers::ingest_outcome_group_ref(outcome);
                self.recorder.record(AuditRecord {
                    group_ref,
                    context: Some(context),
                    kind: crate::audit_helpers::ingest_outcome_event(msg_id_hex, outcome),
                });
            }
            Err(err) => {
                context.engine = Some(self.audit_engine_context_snapshot());
                self.audit_with_context(
                    None,
                    Some(context),
                    AuditEventKind::IngestError {
                        msg_id: msg_id_hex,
                        error_kind: crate::audit_helpers::engine_error_kind(err).to_string(),
                        detail: crate::audit_helpers::engine_error_detail(err),
                    },
                );
            }
        }
        result
    }

    pub async fn send_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: Option<AuditEventContext>,
    ) -> Result<SendResult, EngineError> {
        self.accept_send_with_audit_context(intent, context, SendAcceptance::Prepare)
            .await
    }

    pub async fn queue_app_message_with_audit_context(
        &mut self,
        group_id: GroupId,
        payload: Vec<u8>,
        context: Option<AuditEventContext>,
    ) -> Result<SendResult, EngineError> {
        self.accept_send_with_audit_context(
            SendIntent::AppMessage { group_id, payload },
            context,
            SendAcceptance::QueueAppMessage,
        )
        .await
    }

    async fn accept_send_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: Option<AuditEventContext>,
        acceptance: SendAcceptance,
    ) -> Result<SendResult, EngineError> {
        let operation_id = self.next_audit_operation_id();
        let intent_kind = crate::audit_helpers::send_intent_kind_str(&intent).to_string();
        let group_ref = crate::audit_helpers::send_intent_group_ref(&intent);
        let recipient_group_id = crate::audit_helpers::send_intent_group_id(&intent);
        let mut context = context.unwrap_or_default();
        context.operation_id = Some(operation_id);
        self.recorder.record(AuditRecord {
            group_ref: group_ref.clone(),
            context: Some(context.clone()),
            kind: AuditEventKind::SendEntry {
                intent_kind: intent_kind.clone(),
            },
        });
        self.current_audit_context = Some(context.clone());
        let result = match acceptance {
            SendAcceptance::Prepare => self.do_send(intent).await,
            SendAcceptance::QueueAppMessage => {
                let SendIntent::AppMessage { group_id, payload } = intent else {
                    unreachable!("queue app-message acceptance constructs an AppMessage intent")
                };
                self.do_queue_app_message(group_id, payload)
            }
        };
        self.current_audit_context = None;
        match &result {
            Ok(send_result) => {
                self.recorder.record(AuditRecord {
                    group_ref: group_ref.clone(),
                    context: Some(context.clone()),
                    kind: crate::audit_helpers::send_outcome_event(intent_kind, send_result),
                });
                for (msg_id, expectation) in
                    self.recipient_expectation_records(&recipient_group_id, send_result)
                {
                    self.recorder.record(AuditRecord {
                        group_ref: group_ref.clone(),
                        context: Some(context.clone()),
                        kind: AuditEventKind::RecipientExpectation {
                            msg_id,
                            expectation,
                        },
                    });
                }
            }
            Err(err) => {
                self.recorder.record(AuditRecord {
                    group_ref,
                    context: Some(context),
                    kind: AuditEventKind::SendError {
                        intent_kind,
                        error_kind: crate::audit_helpers::engine_error_kind(err).to_string(),
                        detail: crate::audit_helpers::engine_error_detail(err),
                    },
                });
            }
        }
        result
    }

    pub async fn create_group_with_audit_context(
        &mut self,
        req: CreateGroupRequest,
        context: Option<AuditEventContext>,
    ) -> Result<(GroupId, SendResult), EngineError> {
        self.create_group_with_optional_app_components_and_audit_context(req, Vec::new(), context)
            .await
    }

    pub async fn create_group_with_optional_app_components_and_audit_context(
        &mut self,
        req: CreateGroupRequest,
        optional_app_components: Vec<cgka_traits::app_components::AppComponentData>,
        context: Option<AuditEventContext>,
    ) -> Result<(GroupId, SendResult), EngineError> {
        let operation_id = self.next_audit_operation_id();
        let mut context = context.unwrap_or_default();
        context.operation_id = Some(operation_id);
        context.engine = Some(self.audit_engine_context_snapshot());
        self.audit_with_context(
            None,
            Some(context.clone()),
            AuditEventKind::CreateGroupEntry {
                member_count: req.members.len() as u64,
                required_feature_count: req.required_features.len() as u64,
                app_component_count: (req.app_components.len() + optional_app_components.len())
                    as u64,
                initial_admin_count: req.initial_admins.len() as u64,
            },
        );
        self.current_audit_context = Some(context.clone());
        let result = self.do_create_group(req, optional_app_components).await;
        match &result {
            Ok((group_id, send_result)) => {
                let mut outcome_context = context.clone();
                outcome_context.group = self.audit_group_context_snapshot(group_id);
                self.audit_group_with_context(
                    group_id,
                    outcome_context.clone(),
                    crate::audit_helpers::create_group_outcome_event(send_result),
                );
                for (msg_id, expectation) in
                    self.recipient_expectation_records(group_id, send_result)
                {
                    self.audit_group_with_context(
                        group_id,
                        outcome_context.clone(),
                        AuditEventKind::RecipientExpectation {
                            msg_id,
                            expectation,
                        },
                    );
                }
                self.audit_group_context(group_id, "create_group");
            }
            Err(err) => {
                self.audit_with_context(
                    None,
                    Some(context),
                    AuditEventKind::CreateGroupError {
                        error_kind: crate::audit_helpers::engine_error_kind(err).to_string(),
                        detail: crate::audit_helpers::engine_error_detail(err),
                    },
                );
            }
        }
        self.current_audit_context = None;
        result
    }

    /// Compute per-message recipient expectations for a completed send/create,
    /// derived from authenticated membership: the main message (commit, app
    /// message, or proposal) targets all OTHER current group members; each
    /// welcome targets only its added member. Recipients are represented only by
    /// salted member refs and aggregate counts.
    fn recipient_expectation_records(
        &self,
        group_id: &GroupId,
        result: &SendResult,
    ) -> Vec<(
        marmot_forensics::MessageRefHex,
        marmot_forensics::RecipientExpectation,
    )> {
        use cgka_traits::transport::TransportEnvelope;
        use marmot_forensics::{MessageArtifactKind, RecipientExpectation, RecipientScope};

        let membership_epoch = self
            .audit_group_context_snapshot(group_id)
            .and_then(|ctx| ctx.epoch);
        let mut rows = Vec::new();

        let main = match result {
            SendResult::NoChange { .. } | SendResult::DisbandRequested { .. } => None,
            SendResult::ApplicationMessage { msg, .. } => {
                Some((msg, MessageArtifactKind::ApplicationMessage))
            }
            SendResult::Proposal { msg } => Some((msg, MessageArtifactKind::Proposal)),
            SendResult::GroupEvolution { msg, .. } => Some((msg, MessageArtifactKind::Commit)),
            SendResult::GroupCreated { .. }
            | SendResult::FoundingGroupCreated { .. }
            | SendResult::Queued { .. } => None,
        };
        if let Some((msg, artifact_kind)) = main {
            let self_id = self.identity.self_id();
            let members = self.do_members(group_id).unwrap_or_default();
            let others: Vec<_> = members.iter().filter(|m| &m.id != self_id).collect();
            rows.push((
                hex::encode(msg.id.as_slice()),
                RecipientExpectation {
                    artifact_kind,
                    recipient_scope: RecipientScope::AllOtherCurrentGroupMembers,
                    membership_epoch,
                    basis_commit_id: None,
                    expected_member_refs: others
                        .iter()
                        .map(|m| crate::audit_helpers::member_ref_hex(&m.id))
                        .collect(),
                    expected_count: Some(others.len() as u64),
                },
            ));
        }

        let welcomes = match result {
            SendResult::GroupEvolution { welcomes, .. }
            | SendResult::GroupCreated { welcomes, .. }
            | SendResult::FoundingGroupCreated { welcomes } => welcomes.as_slice(),
            _ => [].as_slice(),
        };
        for welcome in welcomes {
            let recipient = match &welcome.envelope {
                TransportEnvelope::Welcome { recipient } => Some(recipient.clone()),
                TransportEnvelope::GroupMessage { .. } => None,
            };
            let (expected_member_refs, expected_count) = match &recipient {
                Some(recipient) => (
                    vec![crate::audit_helpers::member_ref_hex(recipient)],
                    Some(1),
                ),
                None => (Vec::new(), None),
            };
            rows.push((
                hex::encode(welcome.id.as_slice()),
                RecipientExpectation {
                    artifact_kind: MessageArtifactKind::Welcome,
                    recipient_scope: RecipientScope::AddedMemberOnly,
                    membership_epoch,
                    basis_commit_id: None,
                    expected_member_refs,
                    expected_count,
                },
            ));
        }
        rows
    }

    /// Insert one transport route into the in-memory resolver AND the durable
    /// route table (mdk#1161), stamped with the group epoch that observed the
    /// route as current, then retire durable rows the retained-history window
    /// has moved past (routing-v1: a prior address is accepted only until no
    /// epoch using it remains in either retained window).
    ///
    /// The durable writes are best-effort with the same policy as every route
    /// refresh: a failure only forfeits the next cold-start route seed, never
    /// routing correctness — the in-memory insert stays authoritative for
    /// this session, and the session-open seed detects the resulting stale
    /// epoch stamp and schedules a backfill repair.
    pub(crate) fn index_transport_group_route(
        &mut self,
        transport_group_id: Vec<u8>,
        group_id: &GroupId,
        source_epoch: EpochId,
    ) {
        self.transport_group_id_index
            .insert(transport_group_id.clone(), group_id.clone());
        let _ = self
            .storage
            .put_transport_group_route(&transport_group_id, group_id, source_epoch);
        // Durable retirement: rows last observed current before the retained
        // horizon can no longer carry acceptable traffic. (The in-memory map
        // stays session-scoped; its growth is tracked separately as #896.)
        if let Ok(policy) = self.convergence_policy_for_group_ungated(group_id) {
            let cutoff = EpochId(
                source_epoch
                    .0
                    .saturating_sub(policy.convergence.max_rewind_commits),
            );
            let _ = self
                .storage
                .delete_transport_group_routes_below_epoch(group_id, cutoff);
        }
    }

    /// Additively refresh a group's `transport_group_id_index` entry from live
    /// MLS state after a commit that may have changed the Nostr routing
    /// component (#740 rotation). Inserts the group's CURRENT `transport_group_id`;
    /// any prior id is left in place so inbound messages still addressed to the
    /// pre-rotation route during the overlap window keep resolving (the map is
    /// many-to-one, matching the spec's "publish to the prior routing address"
    /// overlap model). Called at the commit-apply sites (`do_confirm_published`
    /// for local rotation, remote-commit ingest, and convergence apply); these
    /// only fire on commit application, not per app message, so the extra
    /// `MlsGroup::load` is cost-appropriate. Best-effort: a load / routing-read
    /// failure just forfeits the fast path for this group (inbound would fall to
    /// the unknown-group disposition), never fails the merge — and because this
    /// runs after the commit transaction, the durable route row can lag the
    /// record epoch; the session-open seed treats that lag as a stale route
    /// set and schedules a backfill repair (mdk#1161).
    pub(crate) fn reindex_transport_group_id(&mut self, group_id: &GroupId) {
        let mls_group = {
            let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                &self.crypto,
                self.storage.mls_storage(),
            );
            let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
            match openmls::group::MlsGroup::load(
                <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                    &provider,
                ),
                &mls_gid,
            ) {
                Ok(Some(group)) => group,
                _ => return,
            }
        };
        if let Ok(transport_group_id) =
            crate::app_components::transport_group_id_of_group(&mls_group)
        {
            let current_epoch = EpochId(mls_group.epoch().as_u64());
            self.index_transport_group_route(transport_group_id, group_id, current_epoch);
        }
    }

    /// Session-open cheap pass (mdk#1161): seed every stored group's epoch
    /// entry, terminal markers, and transport route from durable records —
    /// without loading MLS state, listing snapshots, or scanning messages —
    /// so open cost stays flat in stored group count.
    ///
    /// Seeded groups enter [`Self::unhydrated_groups`] and fail closed with
    /// [`EngineError::GroupNotHydrated`] on every gated surface until
    /// [`Self::ensure_hydrated`] runs their full hydration (on demand from a
    /// `&mut` entry point, or from the embedder's background pipeline over
    /// [`Self::unhydrated_group_ids`]). Disbanded and unrecoverable groups
    /// restore their terminal state here exactly as before, including the
    /// every-open `GroupUnrecoverable` re-emit. Idempotent: groups that
    /// already hold an epoch entry or a quarantine entry are left untouched,
    /// so a second call never demotes a live group.
    pub fn hydrate_stable_groups_from_storage(&mut self) -> Result<(), EngineError> {
        // One unreadable record must quarantine that one group, never abort
        // the whole account open (mdk#151 / #417). The bulk read is the fast
        // path; if it fails, re-read per group and carry each failure as the
        // group id it belongs to.
        let records: Vec<Result<Group, GroupId>> = match self.storage.list_group_records() {
            Ok(records) => records.into_iter().map(Ok).collect(),
            Err(_) => self
                .storage
                .list_groups()?
                .into_iter()
                .map(|group_id| self.storage.get_group(&group_id).map_err(|_| group_id))
                .collect(),
        };
        let mut tombstones: HashMap<GroupId, cgka_traits::DisbandTombstone> = self
            .storage
            .list_disband_tombstones()?
            .into_iter()
            .collect();
        let mut stored_group_ids = HashSet::with_capacity(records.len());
        let mut seeded_group_epochs: HashMap<GroupId, EpochId> = HashMap::new();
        for record in records {
            let group = match record {
                Ok(group) => group,
                Err(group_id) => {
                    stored_group_ids.insert(group_id.clone());
                    if self.epoch_manager.state(&group_id).is_none()
                        && !self.quarantined_groups.contains_key(&group_id)
                    {
                        self.quarantine_stored_group_on_hydrate(
                            &group_id,
                            GroupHydrationQuarantineReason::GroupRecordLoadFailed,
                        );
                    }
                    continue;
                }
            };
            stored_group_ids.insert(group.id.clone());
            if self.epoch_manager.state(&group.id).is_some()
                || self.quarantined_groups.contains_key(&group.id)
            {
                continue;
            }
            // The guard row is the authority on the `announced` marker: the
            // group record's mirror is written once at settle and never
            // updated, and the row outlives the record when the user deletes
            // local history. The mirror is the payload fallback only.
            let tombstone = tombstones
                .remove(&group.id)
                .or_else(|| group.disbanded.clone());
            if let Some(tombstone) = tombstone {
                // Reconcile the single deterministic system row after a crash.
                // The replay is idempotent (the application projection
                // canonicalizes it) *and* announced-once, so an already
                // announced guard restores its epoch entry in silence.
                self.restore_disband_tombstone(group.id, tombstone)?;
                continue;
            }
            if group.unrecoverable {
                // mdk#971: a durable Unrecoverable halt must survive process
                // restart. Seed the halted epoch entry so every convergence /
                // ingest gate observes it immediately, and queue the group
                // for full hydration like any other seeded group: an
                // unrecoverable group still needs its per-group hydration
                // work (route indexing, interrupted probe/apply recovery,
                // leave-request restore) — the pre-mdk#1161 open always ran
                // it, and `hydrate_all_stored_groups` must stay
                // behavior-preserving. `hydrate_one_stored_group` restores
                // the halt and re-emits the application-facing
                // `GroupUnrecoverable` event when it runs, so the event
                // stays once-per-open on the eager path and arrives with the
                // group's promotion on the deferred path.
                self.epoch_manager
                    .restore_unrecoverable(group.id.clone(), group.epoch);
                self.audit_group(
                    &group.id,
                    crate::audit_helpers::epoch_state_changed_event(
                        None,
                        "unrecoverable",
                        group.epoch,
                        "hydrate_unrecoverable_group",
                        None,
                        None,
                    ),
                );
                self.unhydrated_groups.insert(group.id.clone());
                seeded_group_epochs.insert(group.id, group.epoch);
                continue;
            }
            // Provisional seed: the durable record's epoch mirror keeps
            // `live_group_ids` and the app projection listing this group
            // while full hydration is outstanding. A crash mid-probe may
            // have left the record rewound; the interrupted-probe rollback
            // runs inside `ensure_hydrated` before any gated read, and the
            // only pre-rollback reads are these display-provisional record
            // fields, which full hydration re-derives.
            self.epoch_manager.set_stable(group.id.clone(), group.epoch);
            self.audit_group(
                &group.id,
                crate::audit_helpers::epoch_state_changed_event(
                    None,
                    "seeded",
                    group.epoch,
                    "hydrate_seed_group",
                    None,
                    None,
                ),
            );
            self.unhydrated_groups.insert(group.id.clone());
            seeded_group_epochs.insert(group.id, group.epoch);
        }

        // Seed inbound routing from the durable route table so unhydrated
        // groups still resolve (mdk#740 semantics preserved: many-to-one,
        // rotation overlap retained). A group's route set is trusted only if
        // some row was stamped at the record's current epoch: every commit
        // apply refreshes the current route's epoch stamp, so a lagging stamp
        // means the last commit (which may have rotated the route) was not
        // followed by a route write — a crash or write failure — and current
        // traffic could miss the index. Untrusted and route-less groups —
        // including records predating migration 0043 or providers without a
        // route store — go to the backfill set: ingest re-derives their
        // current route from one MLS load on demand, and the background
        // pipeline orders them first. Stale rows still seed the index so
        // overlap-window traffic keeps resolving.
        let mut current_routed_group_ids = HashSet::new();
        for route in self.storage.list_transport_group_routes()? {
            if !stored_group_ids.contains(&route.group_id) {
                continue;
            }
            if seeded_group_epochs
                .get(&route.group_id)
                .is_some_and(|epoch| route.source_epoch >= *epoch)
            {
                current_routed_group_ids.insert(route.group_id.clone());
            }
            self.transport_group_id_index
                .insert(route.transport_group_id, route.group_id);
        }
        for group_id in seeded_group_epochs.into_keys() {
            if !current_routed_group_ids.contains(&group_id) {
                self.route_backfill_pending.insert(group_id);
            }
        }

        for (group_id, tombstone) in tombstones {
            if !stored_group_ids.contains(&group_id)
                && self.epoch_manager.state(&group_id).is_none()
            {
                self.restore_disband_tombstone(group_id, tombstone)?;
            }
        }
        let stored_group_count = stored_group_ids.len();
        tracing::debug!(
            target: "cgka_engine::hydrate",
            method = "hydrate_stable_groups_from_storage",
            stored_groups = stored_group_count,
            unhydrated_groups = self.unhydrated_groups.len(),
            route_backfill_pending = self.route_backfill_pending.len(),
            "seeded stored groups without full hydration"
        );
        Ok(())
    }

    /// Eager-compatibility hydration: run the cheap pass, then drain every
    /// seeded group through full hydration immediately, swallowing per-group
    /// quarantines exactly like the pre-mdk#1161 all-groups open loop. For
    /// tests and embedders that want every group live (or quarantined) before
    /// the session serves work.
    pub fn hydrate_all_stored_groups(&mut self) -> Result<(), EngineError> {
        self.hydrate_stable_groups_from_storage()?;
        for group_id in self.unhydrated_group_ids() {
            // A failed hydration quarantines the group inside
            // `ensure_hydrated`; the rest of the account still opens.
            let _ = self.ensure_hydrated(&group_id);
        }
        Ok(())
    }

    /// Group ids that successfully hydrated into this live engine session.
    /// Stored records quarantined during open are intentionally omitted: they
    /// use the separate recovery surface and must not be projected as healthy.
    pub fn live_group_ids(&self) -> Result<Vec<GroupId>, EngineError> {
        Ok(self
            .storage
            .list_groups()?
            .into_iter()
            .filter(|group_id| {
                self.epoch_manager.state(group_id).is_some_and(|state| {
                    !matches!(state, cgka_traits::engine_state::EpochState::Disbanded(_))
                })
            })
            .collect())
    }

    /// Restore one terminal guard's epoch entry, and replay its
    /// `GroupDisbanded` to the application at most once ever.
    ///
    /// The epoch entry is in-memory and is restored unconditionally on every
    /// open; only the replay is marked.
    ///
    /// # Why the mark happens here and not at settle
    ///
    /// A settle commits the guard durably, but the live `GroupDisbanded` it
    /// emits only reaches the application through a later drain that can drop
    /// the whole batch without a crash — `observe_drained_session_events` runs
    /// `fail_if_publish_failed(effects)?` before it projects any event. A
    /// settle-time marker could therefore suppress an announcement the
    /// application never received. Marking at replay time instead guarantees
    /// live delivery plus exactly one belt-and-braces replay, then silence.
    ///
    /// # The loss window
    ///
    /// This runs inside `AccountDeviceSession::open`, so the mark is durable at
    /// *account open* — before any drain exists to consume the event it
    /// announces. The window in which the replay can be lost is therefore
    /// `[account open, first successful drained projection]`: it spans app
    /// startup, and **one** process death (or one drained batch that fails its
    /// publish gate) is enough to close it with the event unprojected. That is
    /// wider than a same-drain window, which is exactly why the consequences
    /// below have to be reconciled from durable state rather than from this
    /// event.
    ///
    /// # What a lost replay costs
    ///
    /// Re-derived from the guard row on every read, so unaffected:
    ///
    /// - `Group::disbanded` (`MarmotApp::visible_groups`, via
    ///   `list_disband_tombstones`)
    /// - transport-route exclusion (`MarmotApp::routing_for`, same source)
    /// - chat-list terminal flag and the account unread-aggregate exclusion
    ///   (correlated `EXISTS`/`NOT EXISTS` over `cgka_disband_tombstones`)
    ///
    /// Reconciled from the guard row once per account open by
    /// `AppClient::sweep_terminal_groups_from_guards`, so also unaffected:
    ///
    /// - held-send resolution (`invalidate_pending_sent_app_events_for_group`)
    ///   — the mdk#1177 reconciler, which would otherwise strand a send at
    ///   "Sending…" permanently
    /// - stale peer push tokens (`remove_stale_group_push_tokens`)
    ///
    /// Still event-only, and therefore the actual residual:
    ///
    /// - the durable kind-1210 "group disbanded" system row
    ///   (`project_group_system_rows`) — a missing transcript entry
    /// - `clear_terminal_local_group_deletion_frontiers` — an idempotent
    ///   `DELETE` whose loss leaves a local-deletion marker lingering
    /// - `queue_current_push_registration_removal_for_group` — deliberately
    ///   left out of the open-time sweep because it is an upsert that arms an
    ///   outbox publish, so sweeping it would re-queue work on every open and
    ///   reintroduce exactly the per-open cost this marker removes
    ///
    /// None of those can make a terminal group look live, routable, unread, or
    /// stuck sending. An application-acknowledged marker would close even them,
    /// but no ack seam covers `GroupStateChanged` today (only `MessageReceived`
    /// / `GroupJoined`), so the plumbing is not proportionate to what is left.
    fn restore_disband_tombstone(
        &mut self,
        group_id: GroupId,
        tombstone: cgka_traits::DisbandTombstone,
    ) -> Result<(), EngineError> {
        self.epoch_manager
            .restore_disbanded(group_id.clone(), tombstone.epoch)?;
        if tombstone.announced {
            return Ok(());
        }
        self.events_buf.push_back(GroupEvent::GroupStateChanged {
            group_id: group_id.clone(),
            epoch: tombstone.epoch,
            actor: Some(tombstone.actor),
            change: GroupStateChange::GroupDisbanded,
            origin_commit_id: tombstone.origin_commit_id,
        });
        // Best-effort by design. A failed mark leaves the guard unannounced, so
        // the next open replays again — the pre-fix behavior, and the safe
        // direction. Propagating instead would quarantine a terminal group over
        // a deduplication write.
        if self
            .storage
            .mark_disband_tombstone_announced(&group_id)
            .is_err()
        {
            tracing::debug!(
                target: "cgka_engine::hydrate",
                method = "restore_disband_tombstone",
                error_kind = "mark_disband_tombstone_announced_failed",
                "terminal guard replayed but not marked announced; the next open replays it again"
            );
        }
        Ok(())
    }

    /// Full per-group hydration: load and validate one stored group's MLS and
    /// Marmot state, run its crash recovery, and restore its live epoch entry.
    ///
    /// The application is expected to resolve publish success/failure
    /// (`confirm_published` / `publish_failed`) before shutdown, but a *crash*
    /// between transport publish and that resolution violates the
    /// precondition: OpenMLS durably persists the staged commit
    /// (`MlsGroupState::PendingCommit`) and `MlsGroup::load` restores it, while
    /// the in-memory `PendingStateRef` that `confirm_published` /
    /// `publish_failed` require is gone (the `EpochManager` starts empty on
    /// every open). Left untouched, the group is stranded: every subsequent
    /// commit-creating operation fails with a pending-commit error forever.
    ///
    /// So hydration detects a surviving pending commit and clears it,
    /// treating an unresolved pending publish as publish-failed (the same
    /// rewind `do_publish_failed` performs). The MLS group returns to its
    /// pre-stage epoch, we re-derive the Marmot record from that cleared
    /// state, and we surface a typed `PendingCommitRecovered` event so the
    /// application can run a recovery / resync path — if relays accepted the
    /// commit before the crash, this device is now behind and must catch up.
    ///
    /// **Member-removing commits are deliberately left untouched.** A surviving
    /// pending commit is NOT a reliable crash signal on its own: a deferred
    /// SelfRemove-only commit (the MIP-03 leave path) legitimately persists a
    /// staged commit across process boundaries — a remaining member stages the
    /// commit, projects the departing member out of the Marmot record
    /// *forward*, and a later run publishes + confirms it. Rolling that
    /// back re-derives the record from the pre-stage MLS state and so re-adds a
    /// member who already left, forking convergence (the remaining members
    /// advance past the leave while this device silently rewinds it). Clearing
    /// an additive (invite) commit is safe — it only drops an invitee who never
    /// actually joined — but clearing a Remove/SelfRemove is not. We therefore
    /// scope crash-recovery to staged commits that remove no members, matching
    /// the prior (pre-recovery) behaviour for removal-bearing commits.
    fn hydrate_one_stored_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<EpochId, GroupHydrationQuarantineReason> {
        // Hydration and repair replace the live OpenMLS projection. Any
        // exporter-bearing candidate contexts from the prior projection are
        // stale even when the durable fingerprint later compares equal.
        self.invalidate_deferred_peel_candidate_cache(group_id);
        // A convergence rewind probe — the pass's, or the deferred-peel sweep's
        // candidate-branch enumeration — durably rewinds the group while it
        // explores historical candidates. Process termination cannot run the
        // in-process rollback guard, so restore its pre-probe live snapshot
        // before loading any MLS or Marmot state — including the group record
        // read below, whose epoch seeds the epoch manager.
        crate::openmls_projection::recover_interrupted_rewind_probe(&self.storage, group_id)
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?;
        crate::openmls_projection::recover_interrupted_apply_snapshot(&self.storage, group_id)
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?;

        // The one group-record read for this hydration (mdk#1161): every later
        // consumer (tombstone check, profile mirror check, pending-commit
        // recovery, epoch seeding) shares this post-recovery record.
        let mut group = self
            .storage
            .get_group(group_id)
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?;
        // Same guard-row-first precedence as the cheap hydration pass, for the
        // same reason. Live groups already paid this lookup, so the query count
        // is unchanged for them; a terminal group gains one indexed read.
        let tombstone = self
            .storage
            .disband_tombstone(group_id)
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?
            .or_else(|| group.disbanded.clone());
        if let Some(tombstone) = tombstone {
            // Same once-only reconciliation as the cheap pass: idempotent if it
            // does replay, and silent once the guard is marked announced.
            let epoch = tombstone.epoch;
            self.restore_disband_tombstone(group_id.clone(), tombstone)
                .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?;
            return Ok(epoch);
        }

        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = {
            let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                &self.crypto,
                self.storage.mls_storage(),
            );
            let provider_storage =
                <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider);
            openmls::group::MlsGroup::load(provider_storage, &mls_gid)
                .map_err(|_| GroupHydrationQuarantineReason::OpenMlsLoadFailed)?
                .ok_or(GroupHydrationQuarantineReason::OpenMlsGroupMissing)?
        };

        // Record the transport routing id as soon as the MLS state loads —
        // before any validation that can quarantine the group — so inbound
        // messages for a quarantined-but-loadable group still resolve to the
        // group id and can be retained for post-repair replay instead of
        // dying as UnknownGroup at routing (mdk#364).
        if let Ok(transport_group_id) =
            crate::app_components::transport_group_id_of_group(&mls_group)
        {
            let current_epoch = EpochId(mls_group.epoch().as_u64());
            self.index_transport_group_route(transport_group_id, group_id, current_epoch);
        }
        self.route_backfill_pending.remove(group_id);
        let wire_protocol_profile =
            crate::account_identity_proof::protocol_profile_of_group(&mls_group)
                .map_err(|_| GroupHydrationQuarantineReason::MemberValidationFailed)?;
        crate::app_components::validate_current_profile_group_invariants(&mls_group)
            .map_err(|_| GroupHydrationQuarantineReason::MemberValidationFailed)?;

        // Member-credential + account-identity-proof validation runs one
        // BIP-340 schnorr verification per leaf. All of this state was already
        // validated at join/invite/commit ingress and read back from this
        // device's own encrypted storage, so re-verifying every leaf of every
        // group on every session open is pure repeated work (mdk#152:
        // ~50 groups x ~50 members ≈ 2500 schnorr verifications per open, and
        // marmot-app opens a fresh session per client() call).
        //
        // Gate the full walk behind a cheap, content-bound marker (a hash over
        // the exported ratchet-tree bytes). If the stored marker matches the
        // current tree, this exact tree already passed validation in a prior
        // run and is byte-identical now, so the schnorr re-verification is
        // skipped. Any membership/leaf/proof change (or a marker-version bump)
        // yields a different marker and forces full re-validation, so
        // correctness never depends on the marker — only performance. A marker
        // computation/IO failure simply falls back to full validation.
        let current_marker =
            crate::group_lifecycle::compute_validated_tree_marker(&mls_group, self.ciphersuite)
                .ok();
        let already_validated = match (
            &current_marker,
            self.storage.validated_tree_marker(group_id),
        ) {
            (Some(current), Ok(Some(stored))) => stored == *current,
            _ => false,
        };
        if !already_validated {
            crate::group_lifecycle::validate_member_credentials_and_account_proofs(
                &mls_group,
                self.ciphersuite,
            )
            .map_err(|_| GroupHydrationQuarantineReason::MemberValidationFailed)?;
            // Validation passed for this tree state; persist the marker so the
            // next open of an unchanged group skips the per-leaf schnorr work.
            // A write failure is non-fatal: it only forfeits the optimization
            // (the next open re-validates), so it must not quarantine a healthy
            // group.
            if let Some(marker) = &current_marker {
                let _ = self.storage.put_validated_tree_marker(group_id, marker);
            }
        }

        if group.protocol_profile != wire_protocol_profile {
            return Err(GroupHydrationQuarantineReason::MemberValidationFailed);
        }

        // OpenMLS persists sender-ratchet policy per group. Groups created
        // while MDK accidentally inherited OpenMLS's 5-message default would
        // therefore remain fragile after merely changing the creation/join
        // presets. Validate the profile and member invariants before mutating
        // the group, then write the pinned engine config through in place
        // before any new traffic can be processed. The migration is
        // intentionally triggered only by sender-ratchet drift:
        // `set_configuration` does not resize the live past-epoch secret store.
        // Construction tests separately assert that create and Welcome paths
        // persist the same full join config. This cannot restore secrets
        // already pruned, but it protects all future within-epoch application
        // traffic.
        let required_config = crate::wire_format::join_config(self.max_past_epochs);
        if mls_group.configuration().sender_ratchet_configuration()
            != required_config.sender_ratchet_configuration()
        {
            mls_group
                .set_configuration(self.storage.mls_storage(), &required_config)
                .map_err(|_| GroupHydrationQuarantineReason::OpenMlsLoadFailed)?;
        }

        let durable_pending_fanout = self
            .storage
            .list_outbound_fanouts_for_group(group_id)
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?
            .into_iter()
            .find(|fanout| {
                fanout.group_id() == Some(group_id)
                    && matches!(fanout.mls_state(), cgka_traits::FanoutMlsState::Pending(_))
            });
        let pending_recovery = if mls_group.pending_commit().is_some()
            && let Some(fanout) = durable_pending_fanout.as_ref()
        {
            let pending_ref = fanout
                .pending_ref()
                .expect("pending fanout state retains its pending ref");
            let prior_epoch = EpochId(mls_group.epoch().as_u64());
            // Validate the fanout's origin-commit row still resolves to a
            // stored OpenMLS wire message before restoring the pending
            // lifecycle around it.
            let origin_message_id = fanout.pending_origin_message_id().cloned();
            let stored_message_id = origin_message_id
                .as_ref()
                .unwrap_or_else(|| fanout.message_id());
            let stored = self
                .storage
                .get_message(stored_message_id)
                .map_err(|_| GroupHydrationQuarantineReason::PendingCommitRecoveryFailed)?;
            let payload = StoredMessagePayload::decode(&stored.payload)
                .map_err(|_| GroupHydrationQuarantineReason::PendingCommitRecoveryFailed)?;
            let valid_origin = if origin_message_id.is_some() {
                payload.as_openmls_wire().is_some()
            } else {
                payload
                    .as_outbound_welcome()
                    .or_else(|| payload.as_raw_transport())
                    .is_some_and(|message| {
                        matches!(message.envelope, TransportEnvelope::Welcome { .. })
                    })
            };
            if !valid_origin {
                return Err(GroupHydrationQuarantineReason::PendingCommitRecoveryFailed);
            }
            Some((
                pending_ref,
                prior_epoch,
                origin_message_id,
                fanout
                    .pending_kind()
                    .unwrap_or(cgka_traits::FanoutPendingKind::GroupEvolution),
            ))
        } else {
            None
        };
        let restored_pending = pending_recovery.is_some();

        // A staged commit that survived process restart *may* mean the
        // application crashed mid-publish. Clear it (treat as
        // publish-failed) so the group is not permanently wedged, then
        // re-derive the Marmot record from the post-clear MLS state.
        //
        // BUT a surviving pending commit is also the normal cross-process
        // state of a deferred SelfRemove auto-commit, whose Marmot record
        // is already projected forward past the leave. Rolling back a
        // commit that removes a member would re-add the departed member and
        // fork convergence, so we only recover commits that add no
        // member-removal (no `Remove`, no `SelfRemove`). Removal-bearing
        // staged commits are left exactly as they were before this recovery
        // path existed.
        let staged_removes_member = mls_group.pending_commit().is_some_and(|staged| {
            staged.queued_proposals().any(|queued| {
                matches!(
                    queued.proposal(),
                    openmls::prelude::Proposal::Remove(_) | openmls::prelude::Proposal::SelfRemove
                )
            })
        });
        let restored_durable_evolution =
            if mls_group.pending_commit().is_some() && !restored_pending {
                self.restore_durable_group_evolution_on_hydrate(group_id, &mls_group)?
            } else {
                false
            };
        if mls_group.pending_commit().is_some()
            && !staged_removes_member
            && !restored_pending
            && !restored_durable_evolution
        {
            // Clear the staged commit transactionally (preserves the #421
            // crash-safety fix): the MLS storage mutation must be atomic so a
            // crash mid-clear cannot leave torn group state.
            self.storage
                .with_transaction(|storage| {
                    let source_epoch = EpochId(mls_group.epoch().as_u64());
                    crate::message_processor::transition_staged_invite_welcomes(
                        storage,
                        group_id,
                        source_epoch,
                        None,
                        MessageState::Failed,
                    )?;
                    let tx_provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                        &self.crypto,
                        storage.mls_storage(),
                    );
                    mls_group
                        .clear_pending_commit(
                            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&tx_provider),
                        )
                        .map_err(|e| EngineError::Backend(format!("clear_pending: {e:?}")))
                })
                .map_err(|_| GroupHydrationQuarantineReason::PendingCommitRecoveryFailed)?;
            let recovered_epoch = EpochId(mls_group.epoch().as_u64());
            group.epoch = recovered_epoch;
            group.members = crate::group_lifecycle::marmot_members(&mls_group);
            group.required_capabilities =
                crate::capability_manager::required_capabilities_from_group(&mls_group);
            crate::group_lifecycle::mirror_app_components_into_record(&mls_group, &mut group);
            self.storage
                .put_group(&group)
                .map_err(|_| GroupHydrationQuarantineReason::PendingCommitRecoveryFailed)?;
            self.audit_group(
                group_id,
                AuditEventKind::PendingCommitRecoveredOnOpen {
                    recovered_epoch: recovered_epoch.0,
                },
            );
            self.events_buf
                .push_back(GroupEvent::PendingCommitRecovered {
                    group_id: group_id.clone(),
                    recovered_epoch,
                });
        }

        // The one full message scan for this hydration (mdk#1161): the
        // leave-request probe, the convergence-input gate, the deferred-peel
        // check, and the self-remove schedule restore below all classify
        // subsets of the same rows, so they share this fetch instead of each
        // re-reading the whole group message table.
        let stored_message_records = self
            .storage
            .list_messages(group_id, EpochId(0))
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?;

        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let leave_request = self
            .leave_request_to_restore_on_hydrate(
                group_id,
                &mut mls_group,
                &group,
                &provider,
                &stored_message_records,
            )
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?;

        // Startup must recreate the in-memory scheduling edge for durable
        // convergence work. Otherwise queued user sends and stored branch
        // inputs remain asleep after a process restart until unrelated traffic
        // happens to touch the group.
        let has_queued_intents = !self
            .storage
            .list_queued_outbound_intents(group_id)
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?
            .is_empty();
        let has_convergence_inputs = self
            .has_unresolved_convergence_inputs_in_records(group_id, &group, &stored_message_records)
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?;
        let has_deferred_peels = stored_message_records
            .iter()
            .any(|record| record.state == MessageState::PeelDeferred);

        // Do not expose any recovered pending state until every fallible
        // hydration read and validation above has succeeded. If a later step
        // quarantines the group, neither runtime fanout resumption nor direct
        // pending access may observe a half-hydrated lifecycle.
        // mdk#971: a durable Unrecoverable halt must survive process restart.
        // Do not restore PendingPublish or silently `set_stable` over an
        // unrepaired base — keep ingest/convergence blocked until a verified
        // repair path clears the marker.
        let (hydrate_state, hydrate_reason) = if group.unrecoverable {
            self.epoch_manager
                .restore_unrecoverable(group_id.clone(), group.epoch);
            ("unrecoverable", "hydrate_unrecoverable_group")
        } else if let Some((pending_ref, prior_epoch, message_id, pending_kind)) = pending_recovery
        {
            let pending_kind = match pending_kind {
                cgka_traits::FanoutPendingKind::GroupEvolution => {
                    crate::epoch_manager::PendingKind::GroupEvolution
                }
                cgka_traits::FanoutPendingKind::CreateGroup => {
                    crate::epoch_manager::PendingKind::CreateGroup
                }
                cgka_traits::FanoutPendingKind::Disband => {
                    crate::epoch_manager::PendingKind::Disband
                }
            };
            self.epoch_manager
                .restore_pending(
                    group_id.clone(),
                    prior_epoch,
                    EpochId(prior_epoch.0.saturating_add(1)),
                    StagedCommitHandle::from_bytes(group_id.as_slice().to_vec()),
                    pending_ref,
                    pending_kind,
                )
                .map_err(|_| GroupHydrationQuarantineReason::PendingCommitRecoveryFailed)?;
            if let Some(message_id) = message_id {
                self.track_pending_origin_commit(pending_ref, message_id);
            }
            ("pending_publish", "hydrate_stable_group")
        } else if restored_durable_evolution {
            ("pending_publish", "hydrate_stable_group")
        } else {
            self.epoch_manager.set_stable(group_id.clone(), group.epoch);
            ("stable", "hydrate_stable_group")
        };
        if let Some(request) = leave_request {
            self.leave_requests.insert(group_id.clone(), request);
            self.leaving_groups.insert(group_id.clone());
        } else {
            self.leave_requests.remove(group_id);
            self.leaving_groups.remove(group_id);
        }

        // #740: the transport routing id was already indexed right after the
        // MLS load above (kept pre-validation so quarantined groups resolve
        // too); nothing on this path changes it.

        self.audit_group(
            group_id,
            crate::audit_helpers::epoch_state_changed_event(
                None,
                hydrate_state,
                group.epoch,
                hydrate_reason,
                None,
                None,
            ),
        );
        self.audit_group_context(group_id, hydrate_reason);
        if group.unrecoverable {
            // The durable lifecycle marker is also an application-facing
            // repair requirement. Re-emit it on every session open because the
            // original transition event belonged to the prior process.
            self.events_buf.push_back(GroupEvent::GroupUnrecoverable {
                group_id: group_id.clone(),
            });
        }

        let restored_self_remove_work = self
            .restore_self_remove_auto_commit_schedules_in_records(
                group_id,
                group.epoch,
                self.convergence_now_ms(),
                &stored_message_records,
            )
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?;
        if has_queued_intents
            || has_convergence_inputs
            || has_deferred_peels
            || restored_self_remove_work
        {
            self.schedule_pending_convergence_group(group_id);
        }
        Ok(group.epoch)
    }

    /// Restore a prepared/attempted evolution from its exact signed transport
    /// record instead of clearing the surviving OpenMLS pending commit.
    ///
    /// Returns `Ok(false)` for legacy staged commits that predate durable
    /// evolution records; the caller keeps the existing compatibility
    /// recovery for those.
    fn restore_durable_group_evolution_on_hydrate(
        &mut self,
        group_id: &GroupId,
        mls_group: &openmls::group::MlsGroup,
    ) -> Result<bool, GroupHydrationQuarantineReason> {
        use cgka_traits::maintenance::GroupEvolutionPhase;
        use cgka_traits::message::StoredMessagePayload;

        let Some(maintenance) = self.storage.maintenance_storage() else {
            return Ok(false);
        };
        let source_epoch = EpochId(mls_group.epoch().as_u64());
        let own_leaf_hash = mls_group
            .own_leaf_node()
            .and_then(|leaf| leaf.tls_serialize_detached().ok())
            .map(|leaf| Sha256::digest(leaf).to_vec());
        let evolution = maintenance
            .list_group_evolutions_for_group(group_id)
            .map_err(|_| GroupHydrationQuarantineReason::PendingCommitRecoveryFailed)?
            .into_iter()
            .rev()
            .find(|evolution| {
                evolution.source_epoch == source_epoch
                    && evolution.own_leaf_before_hash == own_leaf_hash
                    && matches!(
                        evolution.phase,
                        GroupEvolutionPhase::Prepared | GroupEvolutionPhase::Attempting
                    )
            });
        let Some(evolution) = evolution else {
            return Ok(false);
        };
        let Some(message_id) = evolution.signed_message_id.clone() else {
            return Ok(false);
        };
        let recovery_failed = || {
            tracing::warn!(
                target: "cgka_engine::maintenance",
                method = "restore_durable_group_evolution_on_hydrate",
                "durable evolution was incomplete; using compatibility recovery"
            );
            Ok(false)
        };
        let record = match self.storage.get_message(&message_id) {
            Ok(record) => record,
            Err(_) => return recovery_failed(),
        };
        let payload = match StoredMessagePayload::decode(&record.payload) {
            Ok(payload) => payload,
            Err(_) => return recovery_failed(),
        };
        let Some(exact_message) = payload.as_exact_transport().cloned() else {
            return recovery_failed();
        };
        if payload.as_openmls_wire().is_none() {
            return recovery_failed();
        }
        if mls_group.pending_commit().is_none() {
            return recovery_failed();
        }

        self.epoch_manager
            .set_stable(group_id.clone(), source_epoch);
        let pending = self.epoch_manager.next_pending_ref();
        let mut evolution = evolution;
        evolution.pending_ref = Some(pending);
        if maintenance.put_group_evolution(&evolution).is_err() {
            return recovery_failed();
        }
        if self
            .epoch_manager
            .begin_pending(
                group_id.clone(),
                source_epoch,
                evolution.target_epoch,
                cgka_traits::engine_state::StagedCommitHandle::from_bytes(
                    group_id.as_slice().to_vec(),
                ),
                pending,
                crate::epoch_manager::PendingKind::GroupEvolution,
                None,
            )
            .is_err()
        {
            evolution.pending_ref = None;
            let _ = maintenance.put_group_evolution(&evolution);
            return recovery_failed();
        }
        self.track_pending_origin_commit(pending, message_id);
        self.auto_publish_buf.push_back(cgka_traits::AutoPublish {
            msg: exact_message,
            pending,
        });
        self.audit_group(
            group_id,
            crate::audit_helpers::epoch_state_changed_event(
                None,
                "pending_publish",
                evolution.target_epoch,
                "hydrate_durable_group_evolution",
                Some(pending),
                Some("group_evolution"),
            ),
        );
        Ok(true)
    }

    fn leave_request_to_restore_on_hydrate(
        &self,
        group_id: &GroupId,
        mls_group: &mut openmls::group::MlsGroup,
        group: &Group,
        provider: &crate::provider::EngineOpenMlsProvider<'_, S>,
        stored_message_records: &[cgka_traits::message::MessageRecord],
    ) -> Result<Option<LeaveRequest>, StorageError> {
        let self_is_still_member = group
            .members
            .iter()
            .any(|member| &member.id == self.identity.self_id());
        if !self_is_still_member {
            self.storage.clear_leave_request(group_id)?;
            return Ok(None);
        }

        if let Some(mut request) = self.storage.leave_request(group_id)? {
            if request.last_proposed_epoch.is_none()
                && self.sent_self_remove_leaving_gate_should_restore(
                    group_id,
                    mls_group,
                    group,
                    provider,
                    stored_message_records,
                )?
            {
                request.last_proposed_epoch = Some(group.epoch);
                self.storage.put_leave_request(&request)?;
            }
            return Ok(Some(request));
        }

        if self.sent_self_remove_leaving_gate_should_restore(
            group_id,
            mls_group,
            group,
            provider,
            stored_message_records,
        )? {
            let request = LeaveRequest {
                group_id: group_id.clone(),
                requested_at_ms: self.convergence_now_ms(),
                last_proposed_epoch: Some(group.epoch),
            };
            self.storage.put_leave_request(&request)?;
            return Ok(Some(request));
        }

        Ok(None)
    }

    pub(crate) fn load_leave_request_state(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Option<LeaveRequest>, StorageError> {
        if let Some(request) = self.leave_requests.get(group_id) {
            return Ok(Some(request.clone()));
        }
        let Some(request) = self.storage.leave_request(group_id)? else {
            return Ok(None);
        };
        self.leave_requests
            .insert(group_id.clone(), request.clone());
        self.leaving_groups.insert(group_id.clone());
        Ok(Some(request))
    }

    pub(crate) fn has_leave_send_gate(&mut self, group_id: &GroupId) -> Result<bool, StorageError> {
        Ok(self.load_leave_request_state(group_id)?.is_some()
            || self.leaving_groups.contains(group_id))
    }

    pub(crate) fn clear_leave_request_state(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), StorageError> {
        self.storage.clear_leave_request(group_id)?;
        self.leave_requests.remove(group_id);
        self.leaving_groups.remove(group_id);
        Ok(())
    }

    /// Whether the local copy of `group_id` is marked removed (realized
    /// self-eviction; member-departure.md "Realizing removal"). A removed copy
    /// is terminal for outbound work: nothing may be prepared or published for
    /// it. Unknown groups report `false` — callers fail them with their own
    /// unknown-group handling. The marker clears through an authenticated
    /// re-join (`do_join_welcome` rebuilds the record) or when branch
    /// selection supersedes the removal that set it — the convergence reorg
    /// path re-derives membership from the selected canonical branch
    /// (`emit_convergence_events`).
    pub(crate) fn group_record_is_removed(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        match self.storage.get_group(group_id) {
            Ok(group) => Ok(group.removed),
            Err(StorageError::NotFound) => Ok(false),
            Err(err) => Err(EngineError::Storage(err)),
        }
    }

    /// Ensure a durable `Unrecoverable` halt is reflected in the in-memory
    /// epoch map (mdk#971). Returns `true` when the group is halted. Used as
    /// defense-in-depth on paths that may run before or without session-open
    /// hydration so a persisted marker cannot be skipped by a bare
    /// `set_stable` overwrite.
    pub(crate) fn sync_unrecoverable_halt_from_storage(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        if self.epoch_manager.is_unrecoverable(group_id) {
            return Ok(true);
        }
        let group = match self.storage.get_group(group_id) {
            Ok(group) => group,
            Err(StorageError::NotFound) => return Ok(false),
            Err(err) => return Err(EngineError::Storage(err)),
        };
        if !group.unrecoverable {
            return Ok(false);
        }
        self.epoch_manager
            .restore_unrecoverable(group_id.clone(), group.epoch);
        Ok(true)
    }

    /// Clear ONLY the live OpenMLS group state for `group_id`, leaving every
    /// retained artifact in place.
    ///
    /// Called inside the authenticated re-join transaction when a removed
    /// local member receives a fresh Welcome. It deletes the OpenMLS-owned rows
    /// for the group — ratchet tree, group context, epoch/message secrets,
    /// resumption PSKs, own-leaf index/nodes, group state/config, the proposal
    /// queue, and the current-epoch encryption key pairs — via
    /// `MlsGroup::delete`. That is enough to stop the re-add Welcome from
    /// failing with `GroupAlreadyExists` when OpenMLS stages the fresh join,
    /// and to keep OpenMLS from stacking the re-join on stale epoch keypairs /
    /// message secrets / own-leaf index (mdk#557).
    ///
    /// Crucially it does NOT delete the Marmot `cgka_groups` record, the retained
    /// anchor snapshots, the stored commit/message history, or the convergence
    /// policy. Keeping those preserves both the removed member's tombstoned
    /// read-only view (member list + history remain queryable) and the
    /// retained-anchor reorg material the canonicalization contract requires:
    /// a competing valid branch arriving within `max_rewind_commits` can still
    /// roll back a losing removal branch by restoring a retained snapshot
    /// (`docs/marmot-architecture/cgka-engine-canonicalization-contract.md`).
    ///
    /// Idempotent and tolerant of partially-missing state: a group whose live
    /// OpenMLS state is already gone (or never materialized) is a no-op. The
    /// in-memory epoch/leave/convergence bookkeeping is intentionally left
    /// untouched here; the durable record still describes the (now non-member)
    /// group, and the bookkeeping is reset when the group is re-joined.
    ///
    /// No identifiers are logged (observability.md privacy rule).
    pub(crate) fn clear_live_openmls_group_on_storage(
        &self,
        storage_provider: &S,
        group_id: &GroupId,
    ) -> Result<(), EngineError> {
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            storage_provider.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let storage = <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
            &provider,
        );
        let loaded = openmls::group::MlsGroup::load(storage, &mls_gid)
            .map_err(|e| EngineError::Backend(format!("load live group: {e:?}")))?;
        if let Some(mut mls_group) = loaded {
            mls_group
                .delete(storage)
                .map_err(|e| EngineError::Backend(format!("delete live group: {e:?}")))?;
        }
        Ok(())
    }

    fn sent_self_remove_leaving_gate_should_restore(
        &self,
        group_id: &GroupId,
        mls_group: &mut openmls::group::MlsGroup,
        group: &Group,
        provider: &crate::provider::EngineOpenMlsProvider<'_, S>,
        stored_message_records: &[cgka_traits::message::MessageRecord],
    ) -> Result<bool, cgka_traits::storage::StorageError> {
        if !group
            .members
            .iter()
            .any(|member| &member.id == self.identity.self_id())
        {
            return Ok(false);
        }

        for record in stored_message_records {
            if record.state != MessageState::Sent {
                continue;
            }
            let Ok(stored_payload) = StoredMessagePayload::decode(&record.payload) else {
                continue;
            };
            let Some(message) = stored_payload.as_openmls_wire() else {
                continue;
            };
            let Ok(projection) = crate::openmls_projection::project_mls_message(&message.payload)
            else {
                continue;
            };
            if projection.kind != crate::openmls_projection::OpenMlsContentKind::Proposal {
                continue;
            }

            let Ok(msg_in) = MlsMessageIn::tls_deserialize_exact(message.payload.as_slice()) else {
                continue;
            };
            let protocol: ProtocolMessage = match msg_in.extract() {
                MlsMessageBodyIn::PrivateMessage(private) => private.into(),
                MlsMessageBodyIn::PublicMessage(public) => public.into(),
                _ => continue,
            };
            let mut hasher = Sha256::new();
            hasher.update(b"cgka-engine-hydrate-selfremove-probe/v1");
            hasher.update(group_id.as_slice());
            hasher.update(record.id.as_slice());
            let digest = hasher.finalize();
            let probe_snapshot = format!("hydrate-selfremove-probe-{}", hex::encode(&digest[..8]));
            let guard = crate::snapshot_guard::SnapshotRollbackGuard::create_group_state(
                &self.storage,
                group_id.clone(),
                probe_snapshot,
            )?;
            let processed = mls_group.process_message(provider, protocol);
            guard.commit()?;
            let Ok(processed) = processed else {
                continue;
            };
            if let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content()
                && matches!(queued.proposal(), Proposal::SelfRemove)
                && crate::app_components::authorize_standalone_proposal(mls_group, &queued).is_ok()
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn quarantine_stored_group_on_hydrate(
        &mut self,
        group_id: &GroupId,
        reason: GroupHydrationQuarantineReason,
    ) {
        self.invalidate_deferred_peel_candidate_cache(group_id);
        let reason_tag = hydration_quarantine_reason_tag(reason);
        let group_digest = hydration_quarantine_group_digest(group_id);
        tracing::warn!(
            target: "cgka_engine::hydrate",
            method = "quarantine_stored_group_on_hydrate",
            reason = reason_tag,
            "quarantined stored group during session-open hydration"
        );
        self.audit(AuditEventKind::GroupHydrationQuarantined {
            group_digest,
            reason: reason_tag.to_string(),
        });
        // A quarantined group must not retain an epoch entry: the cheap-pass
        // seed (and any partial transition applied before the failure) would
        // otherwise keep it listed in `live_group_ids` while every accessor
        // rejects it (mdk#1161).
        self.epoch_manager.clear_group_state(group_id);
        self.quarantined_groups.insert(group_id.clone(), reason);
        self.events_buf
            .push_back(GroupEvent::GroupHydrationQuarantined {
                group_id: group_id.clone(),
                reason,
            });
    }

    /// Stored groups that failed session-open hydration and were skipped so the
    /// rest of the account could open (mdk#151 / #417), paired with the
    /// coarse [`GroupHydrationQuarantineReason`] that classifies why.
    ///
    /// This is the engine-side source of truth for the application's per-group
    /// recovery flow (mdk#426): a quarantined group is not in the live
    /// roster and otherwise vanishes from the account with no explanation. The
    /// contract is enforced on every live surface (mdk#364 / #365):
    /// every accessor that reads durable or MLS group state (`epoch`,
    /// `members`, `group_record`, `group_context`, `admin_pubkeys`,
    /// `app_component`, `feature_status`, the safe-export family, …) returns
    /// `UnknownGroup`; `send` and convergence refuse to run; inbound group
    /// messages are retained durably (`PeelDeferred`) and classified
    /// `Stale { reason: Quarantined }` without touching group state. Retained
    /// input replays automatically after a successful
    /// [`Self::retry_hydrate_quarantined_group`] or an authenticated re-join
    /// welcome (both clear the quarantine). The app reads this list to surface
    /// those groups distinctly from healthy/archived ones and to offer
    /// [`Self::retry_hydrate_quarantined_group`].
    ///
    /// Order is unspecified. The returned reason is a copy; the engine retains
    /// its own entry until a retry succeeds.
    pub fn quarantined_groups(&self) -> Vec<(GroupId, GroupHydrationQuarantineReason)> {
        self.quarantined_groups
            .iter()
            .map(|(group_id, reason)| (group_id.clone(), *reason))
            .collect()
    }

    /// Quarantine lookup for the live data-path gates.
    pub(crate) fn quarantined_reason(
        &self,
        group_id: &GroupId,
    ) -> Option<GroupHydrationQuarantineReason> {
        self.quarantined_groups.get(group_id).copied()
    }

    /// Enforce the documented quarantine contract on a live surface: a
    /// quarantined group is indistinguishable from an unknown one on every
    /// accessor and every send/convergence entry point, so validation-rejected
    /// state can neither leak to the application nor keep evolving out of
    /// band (mdk#364 / #365). Ingest has its own gate that additionally
    /// retains the input for post-repair replay.
    pub(crate) fn ensure_group_live(&self, group_id: &GroupId) -> Result<(), EngineError> {
        if self.quarantined_groups.contains_key(group_id) {
            return Err(EngineError::UnknownGroup(group_id.clone()));
        }
        // Seeded-but-unhydrated groups fail closed with the retryable variant
        // (mdk#1161): full hydration has not validated this group yet, so no
        // accessor, send, or convergence path may treat it as live. `&mut`
        // entry points call [`Self::ensure_hydrated`] first to promote the
        // group instead of failing.
        if self.unhydrated_groups.contains(group_id) {
            return Err(EngineError::GroupNotHydrated(group_id.clone()));
        }
        Ok(())
    }

    /// Run full per-group hydration for a group the session-open cheap pass
    /// only seeded (mdk#1161). No-op for live, quarantined, disbanded, or
    /// unknown groups — callers keep their existing handling for those.
    ///
    /// On success the group is promoted to live: its recovery events
    /// (`PendingCommitRecovered`, leave-request restore) and convergence
    /// scheduling fire now. On failure the group moves to the quarantine
    /// surface exactly as an open-time hydration failure would, and the
    /// caller observes `UnknownGroup` — the same view a quarantined group
    /// has always presented.
    pub fn ensure_hydrated(&mut self, group_id: &GroupId) -> Result<(), EngineError> {
        if !self.unhydrated_groups.contains(group_id) {
            return Ok(());
        }
        self.unhydrated_groups.remove(group_id);
        // Retract the provisional seed so full hydration derives the real
        // epoch entry from the same entry-absent conditions the open-time
        // loop always had. The record's epoch mirror is projected forward
        // over a pending evolution, so leaving the seed in place would hand
        // `restore_pending` a wrong `begin_pending` base.
        self.epoch_manager.clear_group_state(group_id);
        match self.hydrate_one_stored_group(group_id) {
            Ok(_epoch) => {
                self.route_backfill_pending.remove(group_id);
                Ok(())
            }
            Err(reason) => {
                self.route_backfill_pending.remove(group_id);
                self.quarantine_stored_group_on_hydrate(group_id, reason);
                Err(EngineError::UnknownGroup(group_id.clone()))
            }
        }
    }

    /// Group ids still awaiting full hydration, route-backfill-pending groups
    /// first (they also block trust in routing-index misses, so a background
    /// pipeline should clear them earliest).
    pub fn unhydrated_group_ids(&self) -> Vec<GroupId> {
        let mut ids: Vec<GroupId> = self
            .route_backfill_pending
            .iter()
            .filter(|group_id| self.unhydrated_groups.contains(*group_id))
            .cloned()
            .collect();
        ids.extend(
            self.unhydrated_groups
                .iter()
                .filter(|group_id| !self.route_backfill_pending.contains(*group_id))
                .cloned(),
        );
        ids
    }

    /// Re-attempt hydration of a single quarantined group.
    ///
    /// This is the non-destructive, user-initiated recovery path for a
    /// transiently-bad group — e.g. a partial DB restore that has since been
    /// completed, or storage that was unreadable at session open but is now
    /// available. It re-runs the exact same per-group hydration the session
    /// performs at open ([`Self::hydrate_one_stored_group`]), which only reads
    /// stored state and, at most, clears a stranded non-removal pending commit
    /// (the same crash-recovery already performed at open). It never edits the
    /// encrypted DB, never re-joins, and never discards a group's local
    /// history.
    ///
    /// Returns:
    /// - `Ok(true)` — the group hydrated successfully; it is removed from the
    ///   quarantine list, dropped from [`Self::quarantined_groups`], and is now
    ///   a live group (`epoch`/`members` resolve). A `GroupHydrationRecovered`
    ///   event is queued for the application to refresh its projection.
    /// - `Ok(false)` — the group is still unhealthy. It stays quarantined; the
    ///   stored reason is refreshed to the latest classification so the UI can
    ///   show whether the failure mode changed.
    ///
    /// **Errors.** `UnknownGroup` if the id is not currently quarantined (the
    /// app should only call this for ids returned by
    /// [`Self::quarantined_groups`]).
    ///
    /// Whether and when to retry — automatically on reconnect, on a timer, or
    /// only on explicit user action — is a product decision left to the
    /// application; the engine only exposes the mechanism.
    pub fn retry_hydrate_quarantined_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        if !self.quarantined_groups.contains_key(group_id) {
            return Err(EngineError::UnknownGroup(group_id.clone()));
        }
        match self.hydrate_one_stored_group(group_id) {
            Ok(recovered_epoch) => {
                self.quarantined_groups.remove(group_id);
                let reason_tag = "recovered";
                let group_digest = hydration_quarantine_group_digest(group_id);
                tracing::info!(
                    target: "cgka_engine::hydrate",
                    method = "retry_hydrate_quarantined_group",
                    outcome = reason_tag,
                    "recovered a quarantined stored group on retry"
                );
                self.audit(AuditEventKind::GroupHydrationRecovered { group_digest });
                // `recovered_epoch` is the epoch hydration just established and
                // wrote through to storage + epoch_manager (set_stable). Use it
                // directly rather than a second storage.get_group() that could
                // fail and silently emit epoch 0 (mdk#441 finding 3).
                self.events_buf
                    .push_back(GroupEvent::GroupHydrationRecovered {
                        group_id: group_id.clone(),
                        recovered_epoch,
                    });
                // Inbound messages that arrived while the group was
                // quarantined were retained as PeelDeferred. Schedule the
                // group so the application's convergence drain replays them
                // now that the group is live again.
                self.schedule_pending_convergence_group(group_id);
                Ok(true)
            }
            Err(reason) => {
                // Still unhealthy. Keep it quarantined, but refresh the stored
                // reason so the UI reflects the current failure mode. Do not
                // re-emit a quarantine event — the group was never live.
                let reason_tag = hydration_quarantine_reason_tag(reason);
                tracing::warn!(
                    target: "cgka_engine::hydrate",
                    method = "retry_hydrate_quarantined_group",
                    reason = reason_tag,
                    "retry did not recover the quarantined stored group"
                );
                self.quarantined_groups.insert(group_id.clone(), reason);
                Ok(false)
            }
        }
    }

    pub(crate) fn convergence_now(&self) -> ConvergenceTime {
        self.convergence_clock.now()
    }

    pub(crate) fn convergence_now_ms(&self) -> u64 {
        self.convergence_now().monotonic_ms
    }

    /// Aggregate, privacy-safe snapshot of engine diagnostic telemetry.
    ///
    /// Currently the post-settle reorg counters and histograms used for
    /// quiescence tuning (`docs/marmot-architecture/relay-delivery-telemetry.md`
    /// §"Validation: post-settle reorg rate"). Carries only counts and
    /// millisecond/commit buckets — no group ids, epochs, or branch ids. Like
    /// `drain_events`, it is read-only and never feeds convergence.
    pub fn engine_metrics(&self) -> crate::engine_metrics::EngineMetricsSnapshot {
        tracing::trace!(
            target: "cgka_engine::engine_metrics",
            method = "engine_metrics",
            "snapshotting engine metrics"
        );
        self.engine_metrics.snapshot()
    }

    /// Emit an audit-log event with no group attribution.
    pub(crate) fn audit(&self, kind: AuditEventKind) {
        self.audit_with_context(None, None, kind);
    }

    /// Emit an audit-log event attributed to a specific group.
    pub(crate) fn audit_group(&self, group_id: &GroupId, kind: AuditEventKind) {
        self.audit_with_context(Some(group_id), None, kind);
    }

    pub(crate) fn audit_group_with_context(
        &self,
        group_id: &GroupId,
        context: AuditEventContext,
        kind: AuditEventKind,
    ) {
        self.audit_with_context(Some(group_id), Some(context), kind);
    }

    pub(crate) fn audit_with_context(
        &self,
        group_id: Option<&GroupId>,
        context: Option<AuditEventContext>,
        kind: AuditEventKind,
    ) {
        // Fall back to the in-flight operation's context so secondary rows
        // emitted via the context-less `audit`/`audit_group` helpers still
        // carry the operation's `human_action`. An explicit context always wins.
        let context = context.or_else(|| self.current_audit_context.clone());
        let mut record = AuditRecord::new(
            group_id.map(|group_id| hex::encode(group_id.as_slice())),
            kind,
        );
        record.context = context;
        self.recorder.record(record);
    }

    pub fn audit_external(
        &self,
        group_id: Option<&GroupId>,
        context: Option<AuditEventContext>,
        kind: AuditEventKind,
    ) {
        self.audit_with_context(group_id, context, kind);
    }

    pub fn audit_recorder_health(&self) {
        let health = self.recorder.health_snapshot();
        self.audit(AuditEventKind::RecorderHealth {
            serialization_failures: health.serialization_failures,
            write_failures: health.write_failures,
            flush_failures: health.flush_failures,
        });
    }

    /// Filesystem path the installed forensic recorder appends to, if it is
    /// file-backed. `None` for the default [`NoopRecorder`].
    pub fn audit_recorder_path(&self) -> Option<std::path::PathBuf> {
        self.recorder.audit_log_path()
    }

    /// Rotate the installed forensic recorder: discard its current file and
    /// begin a fresh one, then keep recording. No-op for non-file recorders.
    pub fn rotate_audit_recorder(&self) -> std::io::Result<()> {
        self.recorder.rotate()
    }

    /// Override the deferred-peel retry budget (mdk#339). Rows that
    /// exceed it without ever peeling are resource-refused and released.
    /// Exposed so tests can exhaust the budget
    /// quickly; production uses the default.
    pub fn set_deferred_peel_retry_budget(&mut self, budget: u32) {
        self.deferred_peel_retry_budget = budget.max(1);
    }

    /// Override the durable deferred-peel residence budget. Production uses
    /// the conservative default; tests use this to advance expiry without
    /// sleeping.
    pub fn set_deferred_peel_residence_ms(&mut self, residence_ms: u64) {
        self.deferred_peel_residence_ms = residence_ms.max(1);
    }

    #[doc(hidden)]
    pub fn set_foreground_deferred_peel_budget(&mut self, budget_ms: u64, rows: usize) {
        self.foreground_deferred_peel_budget_ms = budget_ms.max(1);
        self.foreground_deferred_peel_rows = rows.max(1);
    }

    /// Replace the installed forensic recorder on a live engine. Dropping the
    /// prior recorder flushes and closes any file it held. Used to start or
    /// stop audit logging in place when the audit switch is toggled, without
    /// rebuilding the engine. Pass [`NoopRecorder`] to stop recording.
    pub fn set_recorder(&mut self, recorder: Box<dyn ForensicRecorder>) {
        self.recorder = recorder;
    }

    pub(crate) fn next_audit_operation_id(&mut self) -> String {
        let id = self.audit_operation_counter;
        self.audit_operation_counter = self.audit_operation_counter.wrapping_add(1);
        format!("op-{id}")
    }

    pub fn audit_engine_context(&self) {
        self.audit(AuditEventKind::EngineContext {
            context: self.audit_engine_context_snapshot(),
        });
    }

    pub(crate) fn audit_engine_context_snapshot(&self) -> AuditEngineContext {
        AuditEngineContext {
            ciphersuite: Some(u16::from(self.ciphersuite)),
            max_past_epochs: Some(self.max_past_epochs as u64),
            convergence_max_rewind_commits: Some(
                self.convergence_policy.convergence.max_rewind_commits,
            ),
            supported_app_component_count: Some(self.supported_app_components.ids.len() as u64),
            feature_count: Some(self.registry.iter().count() as u64),
        }
    }

    pub(crate) fn audit_group_context_snapshot(
        &self,
        group_id: &GroupId,
    ) -> Option<AuditGroupContext> {
        let group = self.storage.get_group(group_id).ok()?;
        Some(AuditGroupContext {
            epoch: Some(group.epoch.0),
            member_count: Some(group.members.len() as u64),
            required_app_component_count: Some(
                group.required_capabilities.app_components.ids.len() as u64,
            ),
            admin_count: self
                .admin_pubkeys(group_id)
                .ok()
                .map(|admins| admins.len() as u64),
            convergence_max_rewind_commits: Some(
                self.convergence_policy.convergence.max_rewind_commits,
            ),
        })
    }

    pub(crate) fn audit_group_context(&self, group_id: &GroupId, reason: &str) {
        if let Some(context) = self.audit_group_context_snapshot(group_id) {
            self.audit_group(
                group_id,
                AuditEventKind::GroupContext {
                    reason: reason.to_string(),
                    context,
                },
            );
        }
    }

    /// Record the origin-commit storage id of a freshly staged pending
    /// publish. `do_confirm_published` reads it to mark the sent commit row
    /// `Processed` and key its own-commit checkpoint; `do_publish_failed`
    /// drops it again.
    pub(crate) fn track_pending_origin_commit(
        &mut self,
        pending: PendingStateRef,
        origin_commit_id: MessageId,
    ) {
        self.pending_origin_commits
            .insert(pending, origin_commit_id);
    }

    /// Read the origin-commit storage id for a pending entry **without**
    /// consuming it. `do_confirm_published` needs this id inside its durable
    /// transaction, but the entry must survive until the transaction has
    /// committed so a rolled-back, retried confirm sees the same state.
    pub(crate) fn peek_pending_origin_commit(&self, pending: PendingStateRef) -> Option<MessageId> {
        self.pending_origin_commits.get(&pending).cloned()
    }

    /// Consume the pending entry after its publish lifecycle resolved
    /// (confirmed or failed).
    pub(crate) fn take_pending_origin_commit(
        &mut self,
        pending: PendingStateRef,
    ) -> Option<MessageId> {
        self.pending_origin_commits.remove(&pending)
    }

    /// Return the Marmot group metadata mirrored from signed MLS group state.
    ///
    /// App surfaces use this for projections such as group profile components
    /// without reaching into OpenMLS internals.
    pub fn group_record(&self, group_id: &GroupId) -> Result<Group, EngineError> {
        self.ensure_group_live(group_id)?;
        Ok(self.storage.get_group(group_id)?)
    }

    /// Profile selected for newly emitted KeyPackages and newly created groups.
    pub fn new_protocol_profile(&self) -> ProtocolProfile {
        self.new_protocol_profile
    }

    /// Return the stored outbound welcome for `id` along with its group.
    ///
    /// Founding Welcomes are persisted at canonical creation and invite
    /// Welcomes are promoted when their Add commit confirms, both as
    /// delivery-aware `OutboundWelcome` records. Historical `Sent`
    /// raw-transport Welcome records remain directly re-deliverable by a known
    /// id for compatibility, but are not rediscovered as outstanding after an
    /// upgrade because older versions did not persist acknowledgement
    /// completion (mdk#352).
    pub fn stored_sent_welcome(
        &self,
        id: &MessageId,
    ) -> Result<(GroupId, TransportMessage), EngineError> {
        let record = self.storage.get_message(id)?;
        self.ensure_group_live(&record.group_id)?;
        if record.state != MessageState::Sent {
            return Err(EngineError::Backend(
                "stored message is not an outbound sent record".into(),
            ));
        }
        let payload = StoredMessagePayload::decode(&record.payload)
            .map_err(|e| EngineError::Backend(format!("stored payload decode: {e}")))?;
        let message = match &payload {
            StoredMessagePayload::OutboundWelcome(message) => Some(message),
            // `RawTransport` is the explicit legacy representation used before
            // delivery-aware and staged Welcome variants existed. New invite
            // paths never use it while a commit is unconfirmed.
            StoredMessagePayload::RawTransport(message) => Some(message),
            StoredMessagePayload::StagedInviteWelcome { .. }
            | StoredMessagePayload::OpenMlsWire(_)
            | StoredMessagePayload::SignedOpenMlsWire { .. }
            | StoredMessagePayload::OwnCommitWire { .. } => None,
        }
        .ok_or_else(|| {
            EngineError::Backend(
                "stored message is not an outbound Welcome transport record".into(),
            )
        })?;
        if !matches!(message.envelope, TransportEnvelope::Welcome { .. }) {
            return Err(EngineError::Backend(
                "stored message is not a welcome".into(),
            ));
        }
        Ok((record.group_id.clone(), message.clone()))
    }

    /// Return every retained outbound Welcome whose delivery policy has not
    /// yet been acknowledged.
    ///
    /// Founding creation and existing-group invite confirmation persist
    /// delivery-aware `OutboundWelcome` records in the same transaction that
    /// makes their group state canonical. This scan is therefore the
    /// authoritative cold-restart recovery index even if a higher-layer
    /// pending-delivery projection was not written before process termination.
    /// Historical raw `Sent` Welcome rows are deliberately excluded because
    /// their acknowledgement state is unknowable.
    pub fn outstanding_sent_welcomes(
        &self,
    ) -> Result<Vec<(GroupId, TransportMessage)>, EngineError> {
        let mut welcomes = Vec::new();
        for group_id in self.storage.list_groups()? {
            if self.ensure_group_live(&group_id).is_err() {
                continue;
            }
            for record in self.storage.list_messages(&group_id, EpochId(0))? {
                if record.state != MessageState::Sent {
                    continue;
                }
                let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
                    continue;
                };
                let Some(message) = payload.as_outbound_welcome() else {
                    continue;
                };
                if matches!(message.envelope, TransportEnvelope::Welcome { .. }) {
                    welcomes.push((group_id.clone(), message.clone()));
                }
            }
        }
        Ok(welcomes)
    }

    /// IDs of every delivery-aware or explicitly staged outbound Welcome
    /// retained by this engine, including completed obligations.
    ///
    /// Higher layers use this to reconcile founding/invite projection rows.
    /// Staged invite ids are tracked but not outstanding, so a pre-confirmation
    /// app projection cannot expose them for delivery. Historical raw `Sent`
    /// payloads remain outside this lifecycle.
    pub fn tracked_outbound_welcome_ids(&self) -> Result<Vec<MessageId>, EngineError> {
        let mut ids = Vec::new();
        for group_id in self.storage.list_groups()? {
            if self.ensure_group_live(&group_id).is_err() {
                continue;
            }
            for record in self.storage.list_messages(&group_id, EpochId(0))? {
                let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
                    continue;
                };
                if payload.as_outbound_welcome().is_some()
                    || payload.as_staged_invite_welcome().is_some()
                {
                    ids.push(record.id);
                }
            }
        }
        Ok(ids)
    }

    /// Mark one retained outbound Welcome's independent delivery obligation
    /// complete. The canonical group lifecycle is unaffected.
    pub fn mark_sent_welcome_delivered(&self, id: &MessageId) -> Result<(), EngineError> {
        // Validate the exact retained artifact before using `Processed` as its
        // terminal delivery state.
        let _ = self.stored_sent_welcome(id)?;
        self.update_stored_message_state(id, MessageState::Processed)
    }

    /// Return the current Marmot admin policy keys mirrored from signed MLS
    /// group state.
    pub fn admin_pubkeys(&self, group_id: &GroupId) -> Result<Vec<[u8; 32]>, EngineError> {
        self.ensure_group_live(group_id)?;
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = openmls::group::MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let mut admins = crate::app_components::admins_of_group(&mls_group)?;
        admins.sort();
        admins.dedup();
        Ok(admins)
    }

    pub fn safe_export_secret_with_epoch(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<(EpochId, cgka_traits::SecretBytes), EngineError> {
        self.ensure_group_live(group_id)?;
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = openmls::group::MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        let required_components =
            crate::app_components::required_app_components_of_group(&mls_group)?;
        if !required_components.contains(component_id) {
            return Err(EngineError::Other(format!(
                "group does not require app component {component_id:#06x}"
            )));
        }

        let crypto =
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::crypto(&provider);
        let storage =
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider);
        if let Some(epoch) = mls_group
            .pending_commit()
            .map(|staged| EpochId(staged.group_context().epoch().as_u64()))
        {
            let secret = mls_group
                .safe_export_secret_from_pending(crypto, storage, component_id)
                .map_err(|e| EngineError::Backend(format!("staged safe_export_secret: {e:?}")))?;
            Ok((epoch, cgka_traits::SecretBytes::new(secret)))
        } else {
            let secret = mls_group
                .safe_export_secret(crypto, storage, component_id)
                .map_err(|e| EngineError::Backend(format!("safe_export_secret: {e:?}")))?;
            Ok((
                EpochId(mls_group.epoch().as_u64()),
                cgka_traits::SecretBytes::new(secret),
            ))
        }
    }

    pub fn current_safe_export_epoch(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<EpochId, EngineError> {
        self.ensure_group_live(group_id)?;
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = openmls::group::MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        let required_components =
            crate::app_components::required_app_components_of_group(&mls_group)?;
        if !required_components.contains(component_id) {
            return Err(EngineError::Other(format!(
                "group does not require app component {component_id:#06x}"
            )));
        }

        if let Some(staged) = mls_group.pending_commit() {
            Ok(EpochId(staged.group_context().epoch().as_u64()))
        } else {
            Ok(EpochId(mls_group.epoch().as_u64()))
        }
    }
}

// ── CgkaEngine impl ─────────────────────────────────────────────────────────
//
// Trait methods stay thin: validate the trait boundary, then delegate to
// the module that owns the behavior.

#[async_trait]
impl<S: StorageProvider + 'static> CgkaEngine for Engine<S> {
    async fn ingest(&mut self, msg: TransportMessage) -> Result<IngestOutcome, EngineError> {
        self.ingest_with_audit_context(msg, None).await
    }

    fn drain_events(&mut self) -> Vec<GroupEvent> {
        self.events_buf.drain(..).collect()
    }

    fn drain_auto_publish(&mut self) -> Vec<AutoPublish> {
        self.auto_publish_buf.drain(..).collect()
    }

    fn drain_auto_proposals(&mut self) -> Vec<TransportMessage> {
        self.auto_proposal_buf.drain(..).collect()
    }

    fn drain_pending_convergence_groups(&mut self) -> Vec<GroupId> {
        self.pending_convergence_groups.drain().collect()
    }

    fn prepare_convergence_cutoff_delay_ms(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Option<u64>, EngineError> {
        Engine::prepare_convergence_cutoff_delay_ms(self, group_id)
            .map_err(|error| EngineError::Backend(format!("load convergence cutoff: {error}")))
    }

    async fn send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError> {
        self.send_with_audit_context(intent, None).await
    }

    async fn queue_app_message(
        &mut self,
        group_id: GroupId,
        payload: Vec<u8>,
    ) -> Result<SendResult, EngineError> {
        self.queue_app_message_with_audit_context(group_id, payload, None)
            .await
    }

    async fn advance_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Vec<SendResult>, EngineError> {
        let now_ms = self.convergence_now_ms();
        self.converge_and_drain_queued_outbound_intents(group_id, now_ms)
            .await
    }

    fn confirm_queued_outbound_intent(&mut self, intent_id: &MessageId) -> Result<(), EngineError> {
        self.confirm_regenerated_queued_intent(intent_id)
    }

    fn retry_queued_outbound_intent(&mut self, group_id: &GroupId, intent_id: &MessageId) {
        self.retry_regenerated_queued_intent(group_id, intent_id);
    }

    async fn confirm_published(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<GroupEvent, EngineError> {
        self.do_confirm_published(pending).await
    }

    async fn publish_failed(&mut self, pending: PendingStateRef) -> Result<(), EngineError> {
        self.do_publish_failed(pending).await
    }

    async fn create_group(
        &mut self,
        req: CreateGroupRequest,
    ) -> Result<(GroupId, SendResult), EngineError> {
        self.create_group_with_audit_context(req, None).await
    }

    async fn create_group_with_optional_app_components(
        &mut self,
        req: CreateGroupRequest,
        optional_app_components: Vec<cgka_traits::app_components::AppComponentData>,
    ) -> Result<(GroupId, SendResult), EngineError> {
        self.create_group_with_optional_app_components_and_audit_context(
            req,
            optional_app_components,
            None,
        )
        .await
    }

    async fn join_welcome(
        &mut self,
        welcome_msg: TransportMessage,
    ) -> Result<GroupId, EngineError> {
        self.do_join_welcome(welcome_msg).await
    }

    fn feature_status(
        &self,
        group_id: &GroupId,
        feature: &Feature,
    ) -> Result<FeatureStatus, EngineError> {
        self.ensure_group_live(group_id)?;
        self.do_feature_status(group_id, feature)
    }

    fn constructable_capabilities(
        &self,
        key_packages: &[KeyPackage],
    ) -> Result<GroupCapabilities, EngineError> {
        self.do_constructable_capabilities(key_packages)
    }

    fn upgradeable_capabilities(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupCapabilities, EngineError> {
        self.ensure_group_live(group_id)?;
        self.do_upgradeable_capabilities(group_id)
    }

    async fn upgrade_group_capabilities(
        &mut self,
        group_id: &GroupId,
    ) -> Result<SendResult, EngineError> {
        self.ensure_group_live(group_id)?;
        self.do_upgrade_group_capabilities(group_id).await
    }

    fn group_context(&self, group_id: &GroupId) -> Result<Box<dyn GroupContext + '_>, EngineError> {
        use crate::provider::EngineOpenMlsProvider;
        // A quarantined group's MLS state may load fine (e.g.
        // MemberValidationFailed) — never export its secrets.
        self.ensure_group_live(group_id)?;
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = openmls::group::MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        // When the group is in `PendingPublish`, the MLS group is at the
        // pre-stage epoch but the staged commit carries the projected
        // future state. Project so callers see the same epoch the rest of
        // the engine reports via `epoch()` / `EpochState`.
        let crypto =
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::crypto(&provider);
        let (epoch, group_secret, media_secret, stream_secret) = if let Some(staged) =
            mls_group.pending_commit()
        {
            let group_secret = staged
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| EngineError::Backend(format!("staged export_secret: {e:?}")))?;
            let media_secret = staged
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::ENCRYPTED_MEDIA_EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| {
                    EngineError::Backend(format!("staged encrypted media export_secret: {e:?}"))
                })?;
            let stream_secret = staged
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::AGENT_TEXT_STREAM_EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| {
                    EngineError::Backend(format!("staged agent text stream export_secret: {e:?}"))
                })?;
            (
                staged.group_context().epoch().as_u64(),
                group_secret,
                media_secret,
                stream_secret,
            )
        } else {
            let group_secret = mls_group
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| EngineError::Backend(format!("export_secret: {e:?}")))?;
            let media_secret = mls_group
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::ENCRYPTED_MEDIA_EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| {
                    EngineError::Backend(format!("encrypted media export_secret: {e:?}"))
                })?;
            let stream_secret = mls_group
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::AGENT_TEXT_STREAM_EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| {
                    EngineError::Backend(format!("agent text stream export_secret: {e:?}"))
                })?;
            (
                mls_group.epoch().as_u64(),
                group_secret,
                media_secret,
                stream_secret,
            )
        };
        let mut map = std::collections::HashMap::new();
        map.insert(
            crate::group_lifecycle::EXPORTER_SNAPSHOT_KEY.to_string(),
            cgka_traits::SecretBytes::new(group_secret),
        );
        map.insert(
            crate::group_lifecycle::ENCRYPTED_MEDIA_EXPORTER_SNAPSHOT_KEY.to_string(),
            cgka_traits::SecretBytes::new(media_secret),
        );
        map.insert(
            crate::group_lifecycle::AGENT_TEXT_STREAM_EXPORTER_SNAPSHOT_KEY.to_string(),
            cgka_traits::SecretBytes::new(stream_secret),
        );
        Ok(Box::new(crate::group_context_view::GroupContextView::new(
            EpochId(epoch),
            map,
            Some(crate::app_components::transport_group_id_of_group(
                &mls_group,
            )?),
        )))
    }

    fn safe_export_secret(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<cgka_traits::SecretBytes, EngineError> {
        self.safe_export_secret_with_epoch(group_id, component_id)
            .map(|(_, secret)| secret)
    }

    fn app_component(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<Option<Vec<u8>>, EngineError> {
        self.ensure_group_live(group_id)?;
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = openmls::group::MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        Ok(crate::app_components::app_component_data_of_group(
            &mls_group,
            component_id,
        ))
    }

    fn own_leaf_index(&self, group_id: &GroupId) -> Result<u32, EngineError> {
        self.ensure_group_live(group_id)?;
        self.do_own_leaf_index(group_id)
    }

    fn members(&self, group_id: &GroupId) -> Result<Vec<Member>, EngineError> {
        self.ensure_group_live(group_id)?;
        self.do_members(group_id)
    }

    fn epoch(&self, group_id: &GroupId) -> Result<EpochId, EngineError> {
        // Gate explicitly: a seeded-but-unhydrated group HOLDS a provisional
        // epoch entry (mdk#1161), so the entry-presence check below no longer
        // implies the group is live the way it did when quarantined groups
        // were simply absent.
        self.ensure_group_live(group_id)?;
        self.epoch_manager
            .epoch(group_id)
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))
    }

    fn self_id(&self) -> MemberId {
        self.identity.self_id().clone()
    }

    async fn fresh_key_package(&mut self) -> Result<KeyPackage, EngineError> {
        self.do_fresh_key_package()
    }

    async fn delete_key_package(&mut self, key_package: &KeyPackage) -> Result<(), EngineError> {
        self.do_delete_key_package(key_package)
    }
}
