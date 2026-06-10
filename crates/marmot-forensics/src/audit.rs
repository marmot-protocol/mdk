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
use std::path::Path;
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
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())?;
        let recorder_session_id = generate_recorder_session_id();
        let recorder = Self {
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
            context: record.context,
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
}

/// Filename convention for the engine-scoped audit log.
///
/// Returned path is `<dir>/audit-<engine_id>.jsonl`. The caller is
/// responsible for ensuring the directory exists.
pub fn default_jsonl_path(dir: impl AsRef<Path>, engine_id: &str) -> std::path::PathBuf {
    dir.as_ref().join(format!("audit-{engine_id}.jsonl"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn noop_recorder_is_no_op() {
        let recorder = NoopRecorder;
        recorder.record(AuditRecord::new(
            Some("aa".into()),
            AuditEventKind::IngestEntry {
                msg_id: "bb".into(),
                envelope_kind: "welcome".into(),
                transport_source: "nostr".into(),
                payload_len: 0,
                payload_digest: "cc".into(),
            },
        ));
    }

    #[test]
    fn jsonl_recorder_appends_events_with_monotonic_seq() {
        let dir = TempDir::new().unwrap();
        let path = default_jsonl_path(dir.path(), "engine-abc");
        let recorder = JsonlRecorder::open(&path, "engine-abc".to_string()).unwrap();
        recorder.record(AuditRecord::new(
            None,
            AuditEventKind::SendEntry {
                intent_kind: "app_message".into(),
            },
        ));
        recorder.record(AuditRecord::new(
            Some("group-1".into()),
            AuditEventKind::IngestEntry {
                msg_id: "msg-1".into(),
                envelope_kind: "group_message".into(),
                transport_source: "nostr".into(),
                payload_len: 42,
                payload_digest: "deadbeef".into(),
            },
        ));
        drop(recorder);

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);

        let first: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        let second: AuditEvent = serde_json::from_str(lines[1]).unwrap();
        let third: AuditEvent = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(first.seq, 0);
        assert_eq!(second.seq, 1);
        assert_eq!(third.seq, 2);
        assert_eq!(first.account_ref, None);
        assert_eq!(first.engine_id, "engine-abc");
        assert!(matches!(first.kind, AuditEventKind::RecorderStarted { .. }));
        assert_eq!(third.group_ref.as_deref(), Some("group-1"));
        assert_eq!(first.schema_version, AUDIT_LOG_SCHEMA_VERSION);
        assert!(first.recorder_session_id.is_some());
    }

    #[test]
    fn jsonl_recorder_records_account_ref_when_supplied() {
        let dir = TempDir::new().unwrap();
        let path = default_jsonl_path(dir.path(), "engine-abc");
        let account_ref = "0123456789abcdef0123456789abcdef".to_owned();
        let recorder = JsonlRecorder::open_with_account_ref(
            &path,
            "engine-abc".to_string(),
            Some(account_ref.clone()),
        )
        .unwrap();
        recorder.record(AuditRecord::new(
            None,
            AuditEventKind::SendEntry {
                intent_kind: "app_message".into(),
            },
        ));
        drop(recorder);

        let contents = fs::read_to_string(&path).unwrap();
        let event: AuditEvent = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(event.account_ref.as_deref(), Some(account_ref.as_str()));
    }

    #[test]
    fn jsonl_recorder_rejects_invalid_account_ref() {
        let dir = TempDir::new().unwrap();
        let path = default_jsonl_path(dir.path(), "engine-abc");

        let err = match JsonlRecorder::open_with_account_ref(
            &path,
            "engine-abc".to_string(),
            Some("account-abc".to_string()),
        ) {
            Ok(_) => panic!("invalid account_ref should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn audit_event_round_trips_through_serde() {
        let event = AuditEvent {
            schema_version: AUDIT_LOG_SCHEMA_VERSION.into(),
            seq: 7,
            wall_time_ms: 1_700_000_000_000,
            recorder_session_id: Some("recorder-1".into()),
            account_ref: Some("account-1".into()),
            engine_id: "engine-xyz".into(),
            group_ref: Some("group-1".into()),
            context: Some(AuditEventContext {
                operation_id: Some("op-7".into()),
                human_action: Some(AuditHumanActionContext {
                    action: "update_group_profile".into(),
                    origin: "local_user".into(),
                    fields: vec!["name".into()],
                    component_ids: vec![0x8001],
                    target_count: None,
                }),
                transport: None,
                engine: None,
                group: None,
            }),
            kind: AuditEventKind::ForkResolution {
                source_epoch: 4,
                candidate_digest: "aaaa".into(),
                incumbent_digest: Some("bbbb".into()),
                winner: ForkWinner::Candidate,
                invalidated_msg_id: Some("msg-x".into()),
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn audit_event_kind_round_trips_all_variants() {
        let kinds = vec![
            AuditEventKind::RecorderStarted {
                recorder_session_id: "recorder-1".into(),
                recorder: "jsonl".into(),
            },
            AuditEventKind::EngineContext {
                context: AuditEngineContext {
                    ciphersuite: Some(1),
                    max_past_epochs: Some(10),
                    convergence_max_rewind_commits: Some(5),
                    supported_app_component_count: Some(2),
                    feature_count: Some(3),
                },
            },
            AuditEventKind::GroupContext {
                reason: "open".into(),
                context: AuditGroupContext {
                    epoch: Some(1),
                    member_count: Some(2),
                    required_app_component_count: Some(1),
                    admin_count: Some(1),
                    convergence_max_rewind_commits: Some(5),
                },
            },
            AuditEventKind::RecorderHealth {
                serialization_failures: 0,
                write_failures: 1,
                flush_failures: 2,
            },
            AuditEventKind::HumanAction {
                action: "update_group_profile".into(),
                origin: "local_user".into(),
                phase: "succeeded".into(),
                fields: vec!["name".into(), "description".into()],
                component_ids: vec![0x8001],
                target_count: None,
                message_ids: vec!["m".into()],
                from_epoch: Some(1),
                to_epoch: Some(2),
                error_kind: None,
                detail: None,
            },
            AuditEventKind::IngestEntry {
                msg_id: "m".into(),
                envelope_kind: "welcome".into(),
                transport_source: "nostr".into(),
                payload_len: 1,
                payload_digest: "d".into(),
            },
            AuditEventKind::IngestOutcome {
                msg_id: "m".into(),
                outcome_kind: "stale".into(),
                stale_reason: Some("already_seen".into()),
                epoch: Some(0),
            },
            AuditEventKind::IngestError {
                msg_id: "m".into(),
                error_kind: "unknown_group".into(),
                detail: Some("unknown group".into()),
            },
            AuditEventKind::SendEntry {
                intent_kind: "app_message".into(),
            },
            AuditEventKind::SendOutcome {
                intent_kind: "invite".into(),
                result_kind: "group_evolution".into(),
                outbound_msg_id: Some("m".into()),
                outbound_welcome_msg_ids: vec!["w1".into(), "w2".into()],
            },
            AuditEventKind::SendError {
                intent_kind: "invite".into(),
                error_kind: "unknown_member".into(),
                detail: None,
            },
            AuditEventKind::CreateGroupEntry {
                member_count: 3,
                required_feature_count: 1,
                app_component_count: 2,
                initial_admin_count: 1,
            },
            AuditEventKind::CreateGroupOutcome {
                result_kind: "group_created".into(),
                outbound_welcome_msg_ids: vec!["w1".into()],
            },
            AuditEventKind::CreateGroupError {
                error_kind: "missing_required_capabilities".into(),
                detail: Some("feature missing".into()),
            },
            AuditEventKind::PublishAttempt {
                msg_id: "m".into(),
                target_kind: "group".into(),
                relay_urls: vec!["wss://relay.example".into()],
                required_acks: 1,
            },
            AuditEventKind::PublishOutcome {
                msg_id: "m".into(),
                target_kind: "group".into(),
                accepted_relay_urls: vec!["wss://relay.example".into()],
                failed_relays: vec![PublishRelayFailure {
                    relay_url: "wss://bad.example".into(),
                    reason: "timeout".into(),
                }],
                required_acks: 1,
                met_required_acks: true,
            },
            AuditEventKind::PublishFailure {
                msg_id: "m".into(),
                stage: "required_acks".into(),
                target_kind: "group".into(),
                relay_urls: vec!["wss://bad.example".into()],
                reason: "insufficient publish acknowledgements".into(),
            },
            AuditEventKind::EpochConfirmed {
                from_epoch: 0,
                to_epoch: 1,
                pending_kind: "create_group".into(),
            },
            AuditEventKind::EpochRolledBack {
                pending_epoch: 1,
                restored_epoch: 0,
                pending_kind: "group_evolution".into(),
            },
            AuditEventKind::SnapshotCreated {
                snapshot_name: "fork-1-2-abc".into(),
                source_epoch: 0,
                reason: "pre_commit".into(),
            },
            AuditEventKind::ConvergenceDecision {
                current_tip_epoch: 3,
                candidate_count: 2,
                eligible_count: 1,
                max_rewind_commits: 5,
                selected_branch_id: Some("br-1".into()),
                selected_fork_epoch: Some(2),
                selected_tip_epoch: Some(3),
            },
            AuditEventKind::PeelerOutcome {
                msg_id: "m".into(),
                outcome: PeelerOutcomeKind::DecryptFailed,
                fallback_snapshot_used: true,
                fallback_snapshot_name: Some("fork-anchor-1".into()),
                fallback_snapshot_source_epoch: Some(1),
                fallback_attempt_count: Some(2),
                error_kind: Some("decrypt_failed".into()),
                detail: None,
            },
            AuditEventKind::AutoCommitDecision {
                proposal_kind: "self_remove".into(),
                decision: "observe".into(),
                reason: Some("not_lowest_index".into()),
            },
            AuditEventKind::MessageStateChanged {
                msg_id: "m".into(),
                previous_state: Some("created".into()),
                new_state: "epoch_invalidated".into(),
                epoch: Some(3),
                reason: "fork_loser".into(),
            },
            AuditEventKind::Rejection {
                msg_id: "m".into(),
                reason: "unattributable_sender".into(),
            },
        ];
        for kind in kinds {
            let event = AuditEvent {
                schema_version: AUDIT_LOG_SCHEMA_VERSION.into(),
                seq: 0,
                wall_time_ms: 0,
                recorder_session_id: None,
                account_ref: None,
                engine_id: "e".into(),
                group_ref: None,
                context: None,
                kind: kind.clone(),
            };
            let json = serde_json::to_string(&event).unwrap();
            let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.kind, kind);
        }
    }
}
