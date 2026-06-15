//! Append-only audit log for forensic reconstruction of engine behavior.
//!
//! This module defines a schema for per-engine timeline events plus a
//! `ForensicRecorder` trait that recorder implementations satisfy. The engine
//! emits typed events at every state-relevant decision point so a later
//! analyzer can reconstruct "what each device saw and decided" between
//! divergence and current state.
//!
//! ## Privacy
//!
//! Audit events deliberately carry raw bytes (hex-encoded identifiers,
//! envelope payload digests, and so on) — this is the "sensitive" forensic
//! mode that bypasses the normal redaction discipline. The recorder is
//! opt-in and intended for local debugging of group desync / fork incidents.
//! Do not ship audit log files off-device unless you understand they expose
//! group ids, message ids, and engine identity material.
//!
//! ## Schema stability
//!
//! Every line is tagged with [`AUDIT_LOG_SCHEMA_VERSION`]. Bump the version
//! when adding required fields; analyzers should reject unknown versions.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const AUDIT_LOG_SCHEMA_VERSION: &str = "marmot-forensics-audit/v1";

/// Hex-encoded 16-byte account identity hash. Stable across devices for the
/// same account when the caller supplies it.
pub type AccountRefHex = String;

/// Hex-encoded 16-byte engine identity hash. Stable for the lifetime of a
/// single account-device engine instance.
pub type EngineIdHex = String;

/// Hex-encoded `GroupId` bytes. Raw form; the audit log is local-only.
pub type GroupRefHex = String;

/// Hex-encoded `MessageId` bytes.
pub type MessageRefHex = String;

/// Hex-encoded 32-byte SHA-256 digest.
pub type DigestHex = String;

static RECORDER_SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One line of the JSONL audit log.
///
/// `seq`, `wall_time_ms`, `account_ref`, and `engine_id` are
/// recorder-assigned; the engine supplies the rest via [`AuditRecord`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema_version: String,
    pub seq: u64,
    pub wall_time_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorder_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_ref: Option<AccountRefHex>,
    pub engine_id: EngineIdHex,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_ref: Option<GroupRefHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<AuditEventContext>,
    pub kind: AuditEventKind,
}

/// Caller-supplied payload. The recorder enriches into [`AuditEvent`].
#[derive(Clone, Debug)]
pub struct AuditRecord {
    pub group_ref: Option<GroupRefHex>,
    pub context: Option<AuditEventContext>,
    pub kind: AuditEventKind,
}

impl AuditRecord {
    pub fn new(group_ref: Option<GroupRefHex>, kind: AuditEventKind) -> Self {
        Self {
            group_ref,
            context: None,
            kind,
        }
    }

    pub fn with_context(mut self, context: AuditEventContext) -> Self {
        self.context = Some(context);
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_action: Option<AuditHumanActionContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<AuditTransportContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<AuditEngineContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<AuditGroupContext>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHumanActionContext {
    pub action: String,
    pub origin: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub component_ids: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_count: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTransportContext {
    pub transport_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_plane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEngineContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphersuite: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_past_epochs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub convergence_max_rewind_commits: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_app_component_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_count: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditGroupContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_app_component_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub convergence_max_rewind_commits: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecorderHealthSnapshot {
    pub serialization_failures: u64,
    pub write_failures: u64,
    pub flush_failures: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEventKind {
    /// The JSONL recorder opened a new local recorder session.
    RecorderStarted {
        recorder_session_id: String,
        recorder: String,
    },
    /// Engine/session settings that explain how later decisions should be read.
    EngineContext { context: AuditEngineContext },
    /// Group-scoped settings/state that may vary by group or over time.
    GroupContext {
        reason: String,
        context: AuditGroupContext,
    },
    /// Recorder health counters. Failures remain non-fatal.
    RecorderHealth {
        serialization_failures: u64,
        write_failures: u64,
        flush_failures: u64,
    },
    /// App-level human action marker. This is intentionally sparse and avoids
    /// raw member ids, profile strings, URLs, pubkeys, or payloads.
    HumanAction {
        action: String,
        origin: String,
        phase: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fields: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        component_ids: Vec<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_count: Option<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        message_ids: Vec<MessageRefHex>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// Engine accepted a [`TransportMessage`] at `do_ingest` entry.
    IngestEntry {
        msg_id: MessageRefHex,
        envelope_kind: String,
        transport_source: String,
        payload_len: u64,
        payload_digest: DigestHex,
    },
    /// Engine returned an `IngestOutcome` from `do_ingest`.
    IngestOutcome {
        msg_id: MessageRefHex,
        outcome_kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stale_reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch: Option<u64>,
    },
    /// Engine returned an error from `do_ingest`.
    IngestError {
        msg_id: MessageRefHex,
        error_kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// Engine accepted a `SendIntent` at `do_send` entry.
    SendEntry { intent_kind: String },
    /// Engine returned a `SendResult` from `do_send`.
    SendOutcome {
        intent_kind: String,
        result_kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outbound_msg_id: Option<MessageRefHex>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        outbound_welcome_msg_ids: Vec<MessageRefHex>,
    },
    /// Engine returned an error from `do_send`.
    SendError {
        intent_kind: String,
        error_kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// Engine accepted a create-group request.
    CreateGroupEntry {
        member_count: u64,
        required_feature_count: u64,
        app_component_count: u64,
        initial_admin_count: u64,
    },
    /// Engine successfully built a new group and returned publish work.
    CreateGroupOutcome {
        result_kind: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        outbound_welcome_msg_ids: Vec<MessageRefHex>,
    },
    /// Engine returned an error from create-group.
    CreateGroupError {
        error_kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// Account runtime is about to publish one transport message.
    PublishAttempt {
        msg_id: MessageRefHex,
        target_kind: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        relay_urls: Vec<String>,
        required_acks: u64,
    },
    /// Account runtime received endpoint-level publish results.
    PublishOutcome {
        msg_id: MessageRefHex,
        target_kind: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        accepted_relay_urls: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        failed_relays: Vec<PublishRelayFailure>,
        required_acks: u64,
        met_required_acks: bool,
    },
    /// Account runtime could not complete publish before endpoint receipts.
    PublishFailure {
        msg_id: MessageRefHex,
        stage: String,
        target_kind: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        relay_urls: Vec<String>,
        reason: String,
    },
    /// `EpochManager::confirm_publish` transitioned a group's state forward.
    EpochConfirmed {
        from_epoch: u64,
        to_epoch: u64,
        pending_kind: String,
    },
    /// `EpochManager::rollback_publish` rewound a pending publish.
    EpochRolledBack {
        pending_epoch: u64,
        restored_epoch: u64,
        pending_kind: String,
    },
    /// Session open found an OpenMLS staged commit persisted under the
    /// publish-before-apply contract with no in-memory pending state to
    /// resolve it (the process crashed between publish and
    /// confirm/fail). Hydrate cleared it — treating it as publish-failed —
    /// so the group is no longer wedged on `PendingCommit`. The group is
    /// usable at `recovered_epoch` and the application should resync.
    PendingCommitRecoveredOnOpen { recovered_epoch: u64 },
    /// A single stored group failed session-open hydration and was skipped so
    /// the rest of the account can open. `group_digest` is a SHA-256 digest of
    /// the group id with a domain-separation prefix.
    GroupHydrationQuarantined {
        group_digest: DigestHex,
        reason: String,
    },
    /// Pre-commit snapshot created for fork recovery.
    SnapshotCreated {
        snapshot_name: String,
        source_epoch: u64,
        reason: String,
    },
    /// `ForkRecoveryManager::resolve` returned a verdict for a same-epoch
    /// candidate.
    ForkResolution {
        source_epoch: u64,
        candidate_digest: DigestHex,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        incumbent_digest: Option<DigestHex>,
        winner: ForkWinner,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invalidated_msg_id: Option<MessageRefHex>,
    },
    /// `select_canonical_branch` evaluated a candidate set.
    ConvergenceDecision {
        current_tip_epoch: u64,
        candidate_count: usize,
        eligible_count: usize,
        max_rewind_commits: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selected_branch_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selected_fork_epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selected_tip_epoch: Option<u64>,
    },
    /// Transport peeler returned a result at the engine boundary.
    PeelerOutcome {
        msg_id: MessageRefHex,
        outcome: PeelerOutcomeKind,
        fallback_snapshot_used: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fallback_snapshot_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fallback_snapshot_source_epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fallback_attempt_count: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// `LowestIndexAutoCommitter::decide` returned a decision.
    AutoCommitDecision {
        proposal_kind: String,
        decision: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// A stored message transitioned to a new `MessageState`.
    MessageStateChanged {
        msg_id: MessageRefHex,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_state: Option<String>,
        new_state: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch: Option<u64>,
        reason: String,
    },
    /// A message or intent was rejected with a structured reason.
    Rejection {
        msg_id: MessageRefHex,
        reason: String,
    },
}

impl AuditEventKind {
    /// The serde `type` tag for this kind, exactly as it appears in the JSONL
    /// output. Kept in lockstep with the `#[serde(rename_all = "snake_case")]`
    /// variant names; used to backfill a `system` `human_action` action name on
    /// rows that arrive without one.
    pub fn type_tag(&self) -> &'static str {
        match self {
            AuditEventKind::RecorderStarted { .. } => "recorder_started",
            AuditEventKind::EngineContext { .. } => "engine_context",
            AuditEventKind::GroupContext { .. } => "group_context",
            AuditEventKind::RecorderHealth { .. } => "recorder_health",
            AuditEventKind::HumanAction { .. } => "human_action",
            AuditEventKind::IngestEntry { .. } => "ingest_entry",
            AuditEventKind::IngestOutcome { .. } => "ingest_outcome",
            AuditEventKind::IngestError { .. } => "ingest_error",
            AuditEventKind::SendEntry { .. } => "send_entry",
            AuditEventKind::SendOutcome { .. } => "send_outcome",
            AuditEventKind::SendError { .. } => "send_error",
            AuditEventKind::CreateGroupEntry { .. } => "create_group_entry",
            AuditEventKind::CreateGroupOutcome { .. } => "create_group_outcome",
            AuditEventKind::CreateGroupError { .. } => "create_group_error",
            AuditEventKind::PublishAttempt { .. } => "publish_attempt",
            AuditEventKind::PublishOutcome { .. } => "publish_outcome",
            AuditEventKind::PublishFailure { .. } => "publish_failure",
            AuditEventKind::EpochConfirmed { .. } => "epoch_confirmed",
            AuditEventKind::EpochRolledBack { .. } => "epoch_rolled_back",
            AuditEventKind::PendingCommitRecoveredOnOpen { .. } => {
                "pending_commit_recovered_on_open"
            }
            AuditEventKind::GroupHydrationQuarantined { .. } => "group_hydration_quarantined",
            AuditEventKind::SnapshotCreated { .. } => "snapshot_created",
            AuditEventKind::ForkResolution { .. } => "fork_resolution",
            AuditEventKind::ConvergenceDecision { .. } => "convergence_decision",
            AuditEventKind::PeelerOutcome { .. } => "peeler_outcome",
            AuditEventKind::AutoCommitDecision { .. } => "auto_commit_decision",
            AuditEventKind::MessageStateChanged { .. } => "message_state_changed",
            AuditEventKind::Rejection { .. } => "rejection",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkWinner {
    Candidate,
    Incumbent,
    MissingSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishRelayFailure {
    pub relay_url: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeelerOutcomeKind {
    Success,
    DecryptFailed,
    StaleEpoch,
    Malformed,
    Other,
}

/// Recorder interface. The engine invokes [`record`](Self::record) at every
/// audit-point call site. Implementations must be cheap on the hot path.
///
/// All methods take `&self` so implementations carry interior mutability
/// (e.g. a `Mutex`-protected file handle).
pub trait ForensicRecorder: Send + Sync {
    fn record(&self, record: AuditRecord);

    fn health_snapshot(&self) -> AuditRecorderHealthSnapshot {
        AuditRecorderHealthSnapshot::default()
    }

    /// Filesystem path this recorder appends to, if it is file-backed.
    ///
    /// Returns `None` for recorders with no on-disk file (e.g.
    /// [`NoopRecorder`]). Callers use this to confirm which file a live
    /// recorder owns before deciding whether to [`rotate`](Self::rotate) it
    /// versus removing an unrelated file directly.
    fn audit_log_path(&self) -> Option<PathBuf> {
        None
    }

    /// Discard the recorder's current backing store and begin a fresh one,
    /// then keep recording.
    ///
    /// For a file-backed recorder this deletes the current file and reopens an
    /// empty one at the same path, so a held file handle is never orphaned. The
    /// default is a no-op for recorders with no rotatable backing store.
    fn rotate(&self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Default recorder. Drops every event without observable side effects.
#[derive(Default, Debug, Clone, Copy)]
pub struct NoopRecorder;

impl ForensicRecorder for NoopRecorder {
    fn record(&self, _record: AuditRecord) {}
}

/// JSONL recorder. Appends one JSON line per event to the configured path.
///
/// IO failures are swallowed by design: the forensic log must never break
/// the engine's hot path. Use a typed [`open`](Self::open) error for setup
/// failures only.
pub struct JsonlRecorder {
    /// Path the recorder appends to. Immutable: [`rotate`](ForensicRecorder::rotate)
    /// reopens the same path, so this is held outside the mutex.
    path: PathBuf,
    inner: Mutex<JsonlInner>,
}

struct JsonlInner {
    writer: BufWriter<File>,
    seq: u64,
    account_ref: Option<AccountRefHex>,
    engine_id: EngineIdHex,
    recorder_session_id: String,
    health: AuditRecorderHealthSnapshot,
}

fn validate_account_ref_hex(account_ref: &str) -> std::io::Result<()> {
    let is_valid =
        account_ref.len() == 32 && account_ref.bytes().all(|byte| byte.is_ascii_hexdigit());
    if is_valid {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "account_ref must be a 16-byte hex string",
    ))
}

impl JsonlRecorder {
    pub fn open(path: impl AsRef<Path>, engine_id: EngineIdHex) -> std::io::Result<Self> {
        Self::open_with_account_ref(path, engine_id, None)
    }

    pub fn open_with_account_ref(
        path: impl AsRef<Path>,
        engine_id: EngineIdHex,
        account_ref: Option<AccountRefHex>,
    ) -> std::io::Result<Self> {
        if let Some(account_ref) = account_ref.as_deref() {
            validate_account_ref_hex(account_ref)?;
        }
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let recorder_session_id = generate_recorder_session_id();
        let recorder = Self {
            path,
            inner: Mutex::new(JsonlInner {
                writer: BufWriter::new(file),
                seq: 0,
                account_ref,
                engine_id,
                recorder_session_id: recorder_session_id.clone(),
                health: AuditRecorderHealthSnapshot::default(),
            }),
        };
        recorder.record(AuditRecord::new(
            None,
            AuditEventKind::RecorderStarted {
                recorder_session_id,
                recorder: "marmot_forensics::JsonlRecorder".to_string(),
            },
        ));
        Ok(recorder)
    }
}

fn generate_recorder_session_id() -> String {
    let counter = RECORDER_SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{now:032x}{:08x}{counter:016x}", std::process::id())
}

/// Backfill a `system`-origin `human_action` on any row that arrives without
/// one.
///
/// Locally-initiated operation rows inherit the originating `human_action` in
/// the engine. Everything else — startup lifecycle rows (`recorder_started`,
/// `engine_context`, `recorder_health`) and the entire inbound
/// message-processing path (`ingest_*`, `peeler_outcome`, `message_state_changed`
/// on received messages, fork/convergence/auto-commit decisions) — happens
/// outside any human operation and so carries no `human_action`. Audit consumers
/// require a `human_action` on every row and reject those without one, so we
/// stamp a `system` action named after the row's own kind. Rows that already
/// carry a `human_action` are returned unchanged.
fn stamp_system_human_action(
    context: Option<AuditEventContext>,
    kind: &AuditEventKind,
) -> Option<AuditEventContext> {
    if context
        .as_ref()
        .is_some_and(|ctx| ctx.human_action.is_some())
    {
        return context;
    }
    let mut context = context.unwrap_or_default();
    context.human_action = Some(AuditHumanActionContext {
        action: kind.type_tag().to_string(),
        origin: "system".to_string(),
        ..Default::default()
    });
    Some(context)
}

impl ForensicRecorder for JsonlRecorder {
    fn record(&self, record: AuditRecord) {
        // Poisoning means a prior `record()` panicked while holding the lock.
        // The inner state (writer + seq + engine_id) is plain data — no
        // partially-mutated invariant survives across the panic boundary that
        // would make it unsafe to read here. We recover and continue rather
        // than propagate the panic: the forensic recorder must NEVER crash the
        // engine's hot path, since the audit log is a debug aid layered on top
        // of normal operation.
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let seq = inner.seq;
        inner.seq = seq.wrapping_add(1);
        let context = stamp_system_human_action(record.context, &record.kind);
        let event = AuditEvent {
            schema_version: AUDIT_LOG_SCHEMA_VERSION.to_string(),
            seq,
            wall_time_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            recorder_session_id: Some(inner.recorder_session_id.clone()),
            account_ref: inner.account_ref.clone(),
            engine_id: inner.engine_id.clone(),
            group_ref: record.group_ref,
            context,
            kind: record.kind,
        };
        if let Ok(line) = serde_json::to_string(&event) {
            if writeln!(inner.writer, "{line}").is_err() {
                inner.health.write_failures = inner.health.write_failures.saturating_add(1);
                return;
            }
            if inner.writer.flush().is_err() {
                inner.health.flush_failures = inner.health.flush_failures.saturating_add(1);
            }
        } else {
            inner.health.serialization_failures =
                inner.health.serialization_failures.saturating_add(1);
        }
    }

    fn health_snapshot(&self) -> AuditRecorderHealthSnapshot {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .health
            .clone()
    }

    fn audit_log_path(&self) -> Option<PathBuf> {
        Some(self.path.clone())
    }

    fn rotate(&self) -> std::io::Result<()> {
        // Generate the new session id up front; `record` below re-acquires the
        // lock, so we must release it before recording the boundary line.
        let recorder_session_id = generate_recorder_session_id();
        {
            let mut inner = match self.inner.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            // Best-effort flush of whatever is buffered into the file we are
            // about to discard.
            let _ = inner.writer.flush();
            // Unlink the current file. The fd still held by `inner.writer`
            // keeps pointing at the now-unlinked inode until it is replaced
            // below; on Unix that is harmless and the writer is discarded
            // immediately. A missing file is fine — the goal state is "no old
            // file, fresh file recording".
            match std::fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
            // Open a brand-new file at the same path and swap it in. Assigning
            // to `inner.writer` drops the old `BufWriter`, closing the stale
            // (unlinked) fd.
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            inner.writer = BufWriter::new(file);
            inner.seq = 0;
            inner.recorder_session_id = recorder_session_id.clone();
            inner.health = AuditRecorderHealthSnapshot::default();
        }
        // Mark the start of the fresh file, mirroring `open_with_account_ref`.
        self.record(AuditRecord::new(
            None,
            AuditEventKind::RecorderStarted {
                recorder_session_id,
                recorder: "marmot_forensics::JsonlRecorder".to_string(),
            },
        ));
        Ok(())
    }
}

/// Filename convention for the engine-scoped audit log.
///
/// Returned path is `<dir>/audit-<engine_id>.jsonl`. The caller is
/// responsible for ensuring the directory exists.
pub fn default_jsonl_path(dir: impl AsRef<Path>, engine_id: &str) -> std::path::PathBuf {
    dir.as_ref().join(format!("audit-{engine_id}.jsonl"))
}

#[cfg(test)]
mod tests;
