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
    pub account_ref: Option<AccountRefHex>,
    pub engine_id: EngineIdHex,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_ref: Option<GroupRefHex>,
    pub kind: AuditEventKind,
}

/// Caller-supplied payload. The recorder enriches into [`AuditEvent`].
#[derive(Clone, Debug)]
pub struct AuditRecord {
    pub group_ref: Option<GroupRefHex>,
    pub kind: AuditEventKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEventKind {
    /// Engine accepted a [`TransportMessage`] at `do_ingest` entry.
    IngestEntry {
        msg_id: MessageRefHex,
        envelope_kind: String,
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
        new_state: String,
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
        Ok(Self {
            inner: Mutex::new(JsonlInner {
                writer: BufWriter::new(file),
                seq: 0,
                account_ref,
                engine_id,
            }),
        })
    }
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
            account_ref: inner.account_ref.clone(),
            engine_id: inner.engine_id.clone(),
            group_ref: record.group_ref,
            kind: record.kind,
        };
        if let Ok(line) = serde_json::to_string(&event) {
            let _ = writeln!(inner.writer, "{line}");
            let _ = inner.writer.flush();
        }
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
        recorder.record(AuditRecord {
            group_ref: Some("aa".into()),
            kind: AuditEventKind::IngestEntry {
                msg_id: "bb".into(),
                envelope_kind: "welcome".into(),
                payload_len: 0,
                payload_digest: "cc".into(),
            },
        });
    }

    #[test]
    fn jsonl_recorder_appends_events_with_monotonic_seq() {
        let dir = TempDir::new().unwrap();
        let path = default_jsonl_path(dir.path(), "engine-abc");
        let recorder = JsonlRecorder::open(&path, "engine-abc".to_string()).unwrap();
        recorder.record(AuditRecord {
            group_ref: None,
            kind: AuditEventKind::SendEntry {
                intent_kind: "app_message".into(),
            },
        });
        recorder.record(AuditRecord {
            group_ref: Some("group-1".into()),
            kind: AuditEventKind::IngestEntry {
                msg_id: "msg-1".into(),
                envelope_kind: "group_message".into(),
                payload_len: 42,
                payload_digest: "deadbeef".into(),
            },
        });
        drop(recorder);

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        let second: AuditEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first.seq, 0);
        assert_eq!(second.seq, 1);
        assert_eq!(first.account_ref, None);
        assert_eq!(first.engine_id, "engine-abc");
        assert_eq!(second.group_ref.as_deref(), Some("group-1"));
        assert_eq!(first.schema_version, AUDIT_LOG_SCHEMA_VERSION);
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
        recorder.record(AuditRecord {
            group_ref: None,
            kind: AuditEventKind::SendEntry {
                intent_kind: "app_message".into(),
            },
        });
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
            account_ref: Some("account-1".into()),
            engine_id: "engine-xyz".into(),
            group_ref: Some("group-1".into()),
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
            AuditEventKind::IngestEntry {
                msg_id: "m".into(),
                envelope_kind: "welcome".into(),
                payload_len: 1,
                payload_digest: "d".into(),
            },
            AuditEventKind::IngestOutcome {
                msg_id: "m".into(),
                outcome_kind: "stale".into(),
                stale_reason: Some("already_seen".into()),
                epoch: Some(0),
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
                detail: None,
            },
            AuditEventKind::AutoCommitDecision {
                proposal_kind: "self_remove".into(),
                decision: "observe".into(),
                reason: Some("not_lowest_index".into()),
            },
            AuditEventKind::MessageStateChanged {
                msg_id: "m".into(),
                new_state: "epoch_invalidated".into(),
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
                account_ref: None,
                engine_id: "e".into(),
                group_ref: None,
                kind: kind.clone(),
            };
            let json = serde_json::to_string(&event).unwrap();
            let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.kind, kind);
        }
    }
}
