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
//!
//! ## Data modes
//!
//! Every line also carries an [`AuditDataMode`] recording how aggressively the
//! producing recorder withheld sensitive content:
//!
//! - [`AuditDataMode::ObfuscatedSensitiveData`] — the default safety posture.
//!   Identifiers are hashed/truncated and no plaintext, decoded content, or
//!   full pubkeys appear.
//! - [`AuditDataMode::FullData`] — an explicit opt-in that additionally emits
//!   decrypted message/app content and full identifiers where useful.
//!
//! A recorder stamps its configured mode onto every event. Switching modes
//! ([`ForensicRecorder::set_data_mode`]) rotates the backing store so each
//! file has a single, unambiguous mode boundary.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const AUDIT_LOG_SCHEMA_VERSION: &str = "marmot-forensics-audit/v2";

/// How aggressively a recorder withholds sensitive content from its events.
///
/// Stamped onto every [`AuditEvent`] so an analyzer can tell, per line, which
/// safety posture produced it without inspecting the whole file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDataMode {
    /// Default/current safety posture. Identifiers are hashed or truncated;
    /// no plaintext, decoded content, full author pubkeys, full group-state
    /// values, or expected-recipient pubkeys are written.
    #[default]
    ObfuscatedSensitiveData,
    /// Explicit opt-in. Additionally includes decrypted message/app content and
    /// full identifiers where useful for forensic reconstruction. Never
    /// includes bearer/upload tokens, auth headers, private keys, ciphertext,
    /// or raw MLS bytes.
    FullData,
}

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

/// Hex-encoded 16-byte stable hash of Marmot member identity bytes.
pub type MemberRefHex = String;

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
    /// Safety posture the producing recorder used for this line. The recorder
    /// always serializes it explicitly; the `default` only makes a truncated or
    /// partially-written final line still deserialize as the safe (obfuscated)
    /// mode rather than erroring.
    #[serde(default)]
    pub audit_data_mode: AuditDataMode,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub convergence: Option<AuditConvergenceContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AuditSourceContext>,
}

/// Identifies the account/device/app that produced an audit log, for upload
/// correlation. `account_pubkey_hex`/`account_npub` are full member identities
/// and appear only in [`AuditDataMode::FullData`]; the labels are opaque,
/// user-supplied display strings safe in both modes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSourceContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_trigger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_npub: Option<String>,
}

/// Correlates every row produced during one distributed-convergence run via a
/// stable `run_id`, so an analyzer can group a run's `convergence_run_state`
/// lifecycle and `convergence_decision` together.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditConvergenceContext {
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<ConvergencePhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inferred: Option<bool>,
}

/// Lifecycle phase of a convergence run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvergencePhase {
    Started,
    Waiting,
    Evaluating,
    Selected,
    Blocked,
    Applied,
    Failed,
    Stable,
    Unrecoverable,
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
    /// Transport wire identifiers for the event that carried this message.
    /// Diagnostic forensic evidence, never consensus input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire: Option<AuditTransportWire>,
}

/// Reusable transport "wire envelope": the transport-layer identifiers of the
/// event that carried a Marmot message, attached to inbound (`transport_received`,
/// `ingest_entry`) and outbound (`publish_*`) audit rows so an analyzer can
/// correlate engine activity with raw transport traffic.
///
/// All fields are optional so any transport (and either direction) can populate
/// only what it has. These are transport-layer identifiers (e.g. an ephemeral
/// Nostr event pubkey), never the message author's account identity, so they
/// are safe in both audit data modes. Never carries auth tokens, signatures,
/// ciphertext, or key material.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTransportWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_plane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_id: Option<String>,
    /// Transport-layer "kind" of the carrying event as a string (e.g. the
    /// stringified Nostr kind). The numeric Nostr kind is on `nostr_kind`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_event_id: Option<DigestHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_kind: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gift_wrap_event_id: Option<DigestHex>,
    /// Outer Nostr event id for a transport-level welcome envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_nostr_event_id: Option<DigestHex>,
    /// Inner gift-wrapped welcome rumor event id, when available after unwrap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_rumor_event_id: Option<DigestHex>,
    /// KeyPackage e-tag (or equivalent) linking a welcome to the added member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_key_package_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_result_id: Option<String>,
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

/// What kind of artifact an outbound message is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageArtifactKind {
    ApplicationMessage,
    Commit,
    Proposal,
    Welcome,
    GroupInfo,
    Unknown,
}

/// Attribution for a membership change, used when `change_kind` alone is
/// ambiguous (e.g. a `member_removed` from an admin action vs a
/// convergence-resolved departure that must not render as an admin action).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipChangeSource {
    SelfLeave,
    AdminAction,
    Convergence,
    RemoteCommit,
    Unknown,
}

/// Who an outbound message is expected to reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientScope {
    AllCurrentGroupMembers,
    AllOtherCurrentGroupMembers,
    AddedMemberOnly,
    ExplicitMembers,
    SelfOnly,
    Unknown,
}

/// The set of recipients an outbound message is expected to reach, derived from
/// authenticated group membership at send time. `expected_pubkeys_hex` carries
/// full member identities and is only populated in
/// [`AuditDataMode::FullData`]; `expected_member_refs` (salted hashes) and
/// `expected_count` are safe in both modes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientExpectation {
    pub artifact_kind: MessageArtifactKind,
    pub recipient_scope: RecipientScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis_commit_id: Option<MessageRefHex>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_member_refs: Vec<MemberRefHex>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_pubkeys_hex: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_count: Option<u64>,
}

/// One message produced by a send/create operation, for the `outbound_messages`
/// inventory on `send_outcome` / `create_group_outcome`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundMessage {
    pub msg_id: MessageRefHex,
    pub artifact_kind: MessageArtifactKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<AuditTransportWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_expectation: Option<RecipientExpectation>,
}

/// One witness application message observed at a future epoch, used by the
/// witness-quorum convergence rule. `sender_pubkey_hex` is full-data only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceAppWitness {
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_ref: Option<MemberRefHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_pubkey_hex: Option<String>,
}

/// The score the selector computed for a convergence candidate. Mirrors the
/// engine's `BranchScore`. `tip_committer_pubkey_hex` is full-data only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceScore {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_commit_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_commit_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_quorum_met: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_witness_score: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_committer_ref: Option<MemberRefHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_committer_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_digest: Option<DigestHex>,
}

/// One branch the convergence selector evaluated.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceCandidate {
    pub branch_id: String,
    pub fork_epoch: u64,
    pub tip_epoch: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commit_ids: Vec<MessageRefHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_digest: Option<DigestHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_digest: Option<DigestHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_committer_ref: Option<MemberRefHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_committer_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_anchor_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_input_time_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligible: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejection_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<ConvergenceScore>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_witnesses: Vec<ConvergenceAppWitness>,
}

/// One selector rule evaluation, recording its inputs, result, and whether it
/// was the decisive rule that picked the winner. `inputs`/`result` are free-form
/// JSON so each rule can carry its own shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceRuleEvaluation {
    pub rule_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_branch_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other_candidate_branch_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<serde_json::Value>,
    pub result: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_branch_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_branch_id: Option<String>,
}

/// The authenticated author of a decoded message. `member_ref` (salted hash) is
/// safe in both modes; the pubkeys/npub are full member identities and appear
/// only in [`AuditDataMode::FullData`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageAuthor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_ref: Option<MemberRefHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npub: Option<String>,
}

/// Decrypted payload bytes, rendered as text/JSON/base64. Full-data only — the
/// producer must not construct this in obfuscated mode.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedPayload {
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_b64: Option<String>,
}

/// Decoded inner application event (Marmot/Nostr-shaped). Full-data only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedApplicationEvent {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_root_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

/// Attachment metadata decoded from an application event's tags. Non-secret
/// descriptors only — never the attachment bytes or decryption keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_id: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_len: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<DigestHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// The value of a group-state change. `digest`/`len` are safe in both modes;
/// `text`/`json`/`pubkeys_hex` carry the cleartext value and appear only in
/// [`AuditDataMode::FullData`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupStateValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<DigestHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pubkeys_hex: Vec<String>,
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
    /// The JSONL recorder opened a new local recorder session. The session id
    /// is carried on the enclosing [`AuditEvent::recorder_session_id`] rather
    /// than duplicated here.
    RecorderStarted { recorder: String },
    /// The recorder's [`AuditDataMode`] changed. Emitted on the freshly-rotated
    /// file so the boundary between modes is explicit. `recorder_restarted` is
    /// `true` when the change rotated the backing store (always so for the
    /// file-backed recorder).
    AuditDataModeChanged {
        previous_mode: AuditDataMode,
        new_mode: AuditDataMode,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recorder_restarted: Option<bool>,
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
    /// A transport event was received and mapped to a Marmot message, recorded
    /// before the engine ingests it. Carries the transport wire envelope so an
    /// analyzer can correlate raw transport traffic with the engine's later
    /// `ingest_entry`/`ingest_outcome` rows for the same `msg_id`.
    TransportReceived {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        msg_id: Option<MessageRefHex>,
        transport: AuditTransportWire,
        payload_len: u64,
        payload_digest: DigestHex,
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
    /// Identifies the account/device/app that produced this log. Emitted once
    /// per recorder session; the cleartext account identity (`account_pubkey_hex`
    /// / `account_npub`) is full-data only.
    SourceContext { source: AuditSourceContext },
    /// Decrypted message content surfaced after a successful MLS/app decode.
    /// Full-data only — the producer must not emit this in obfuscated mode.
    MessageContentDecoded {
        msg_id: MessageRefHex,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        artifact_kind: Option<MessageArtifactKind>,
        author: MessageAuthor,
        decoded_payload: DecodedPayload,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decoded_app_event: Option<DecodedApplicationEvent>,
    },
    /// A per-message recipient expectation derived from authenticated group
    /// membership at send time: normal group messages/commits target all other
    /// current members; welcomes target only the added member.
    RecipientExpectation {
        msg_id: MessageRefHex,
        expectation: RecipientExpectation,
    },
    /// Engine returned a `SendResult` from `do_send`.
    SendOutcome {
        intent_kind: String,
        result_kind: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        outbound_messages: Vec<OutboundMessage>,
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
        outbound_messages: Vec<OutboundMessage>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        artifact_kind: Option<MessageArtifactKind>,
        target_kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_url: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        relay_urls: Vec<String>,
        required_acks: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport: Option<AuditTransportWire>,
    },
    /// Account runtime received endpoint-level publish results.
    PublishOutcome {
        msg_id: MessageRefHex,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        artifact_kind: Option<MessageArtifactKind>,
        target_kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_url: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        accepted_relay_urls: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        failed_relays: Vec<PublishRelayFailure>,
        required_acks: u64,
        met_required_acks: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport: Option<AuditTransportWire>,
    },
    /// Account runtime could not complete publish before endpoint receipts.
    PublishFailure {
        msg_id: MessageRefHex,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        artifact_kind: Option<MessageArtifactKind>,
        stage: String,
        target_kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_url: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        relay_urls: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        required_acks: Option<u64>,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport: Option<AuditTransportWire>,
    },
    /// `EpochManager::confirm_publish` transitioned a group's state forward.
    EpochConfirmed {
        from_epoch: u64,
        to_epoch: u64,
        pending_kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin_commit_id: Option<MessageRefHex>,
    },
    /// `EpochManager::rollback_publish` rewound a pending publish.
    EpochRolledBack {
        pending_epoch: u64,
        restored_epoch: u64,
        pending_kind: String,
    },
    /// The per-group engine epoch state changed. This is the compact state
    /// machine breadcrumb; epoch deltas and publish details remain on the
    /// more specific rows such as `epoch_confirmed`.
    EpochStateChanged {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_state: Option<String>,
        new_state: String,
        epoch: u64,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pending_ref: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pending_kind: Option<String>,
    },
    /// A durable, MLS-authenticated group-state delta was surfaced through
    /// `GroupEvent::GroupStateChanged`. Value-bearing changes intentionally
    /// carry digests/lengths rather than plaintext profile values.
    GroupStateChanged {
        epoch: u64,
        change_kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        membership_change_source: Option<MembershipChangeSource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor_member_ref: Option<MemberRefHex>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor_pubkey_hex: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject_member_ref: Option<MemberRefHex>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject_pubkey_hex: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin_commit_id: Option<MessageRefHex>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fields: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        component_ids: Vec<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<GroupStateValue>,
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
    /// A previously hydration-quarantined group was successfully re-hydrated by
    /// an application-initiated retry (darkmatter#426) and is live again.
    /// `group_digest` is a SHA-256 digest of the group id with the same
    /// domain-separation prefix as [`AuditEventKind::GroupHydrationQuarantined`],
    /// so an analyzer can correlate a quarantine with its later recovery.
    GroupHydrationRecovered { group_digest: DigestHex },
    /// Pre-commit snapshot created for fork recovery.
    SnapshotCreated {
        snapshot_name: String,
        source_epoch: u64,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state_digest: Option<DigestHex>,
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
    /// A distributed-convergence run changed lifecycle phase. Correlated with
    /// its `convergence_decision` via the `convergence.run_id` context.
    ConvergenceRunState {
        phase: ConvergencePhase,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_tip_epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retained_anchor_horizon: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_kind: Option<String>,
    },
    /// `select_canonical_branch` evaluated a candidate set. Carries every
    /// candidate with its score, the full `rule_trace` (each selector rule and
    /// which one was decisive), the selected branch, and the losing branches.
    ConvergenceDecision {
        current_tip_epoch: u64,
        max_rewind_commits: u64,
        // Always serialized (schema-required), even when empty.
        candidates: Vec<ConvergenceCandidate>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        rule_trace: Vec<ConvergenceRuleEvaluation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selected_branch_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selected_fork_epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selected_tip_epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        losing_branch_ids: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        error_kinds: Vec<String>,
    },
    /// Transport peeler returned a result at the engine boundary.
    PeelerOutcome {
        msg_id: MessageRefHex,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        artifact_kind: Option<MessageArtifactKind>,
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
        artifact_kind: Option<MessageArtifactKind>,
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
            AuditEventKind::AuditDataModeChanged { .. } => "audit_data_mode_changed",
            AuditEventKind::EngineContext { .. } => "engine_context",
            AuditEventKind::GroupContext { .. } => "group_context",
            AuditEventKind::RecorderHealth { .. } => "recorder_health",
            AuditEventKind::HumanAction { .. } => "human_action",
            AuditEventKind::TransportReceived { .. } => "transport_received",
            AuditEventKind::IngestEntry { .. } => "ingest_entry",
            AuditEventKind::IngestOutcome { .. } => "ingest_outcome",
            AuditEventKind::IngestError { .. } => "ingest_error",
            AuditEventKind::SourceContext { .. } => "source_context",
            AuditEventKind::MessageContentDecoded { .. } => "message_content_decoded",
            AuditEventKind::RecipientExpectation { .. } => "recipient_expectation",
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
            AuditEventKind::EpochStateChanged { .. } => "epoch_state_changed",
            AuditEventKind::GroupStateChanged { .. } => "group_state_changed",
            AuditEventKind::PendingCommitRecoveredOnOpen { .. } => {
                "pending_commit_recovered_on_open"
            }
            AuditEventKind::GroupHydrationQuarantined { .. } => "group_hydration_quarantined",
            AuditEventKind::GroupHydrationRecovered { .. } => "group_hydration_recovered",
            AuditEventKind::SnapshotCreated { .. } => "snapshot_created",
            AuditEventKind::ForkResolution { .. } => "fork_resolution",
            AuditEventKind::ConvergenceRunState { .. } => "convergence_run_state",
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

    /// The [`AuditDataMode`] this recorder stamps onto every event.
    fn data_mode(&self) -> AuditDataMode {
        AuditDataMode::default()
    }

    /// Switch the recorder's [`AuditDataMode`].
    ///
    /// On a real change this rotates the backing store so the file carries a
    /// single, unambiguous mode, then records an
    /// [`AuditEventKind::AuditDataModeChanged`] boundary row on the fresh file.
    /// When the requested mode already matches the current one this is a no-op
    /// (no spurious rotation). The default is a no-op for recorders with no
    /// mode or rotatable backing store.
    fn set_data_mode(&self, new_mode: AuditDataMode, reason: &str) -> std::io::Result<()> {
        let _ = (new_mode, reason);
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
    data_mode: AuditDataMode,
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

    /// Open a recorder in the default [`AuditDataMode::ObfuscatedSensitiveData`]
    /// posture. To start in another mode use [`open_with_data_mode`].
    ///
    /// [`open_with_data_mode`]: Self::open_with_data_mode
    pub fn open_with_account_ref(
        path: impl AsRef<Path>,
        engine_id: EngineIdHex,
        account_ref: Option<AccountRefHex>,
    ) -> std::io::Result<Self> {
        Self::open_with_data_mode(path, engine_id, account_ref, AuditDataMode::default())
    }

    /// Open a recorder that stamps `data_mode` onto every event.
    pub fn open_with_data_mode(
        path: impl AsRef<Path>,
        engine_id: EngineIdHex,
        account_ref: Option<AccountRefHex>,
        data_mode: AuditDataMode,
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
                recorder_session_id,
                data_mode,
                health: AuditRecorderHealthSnapshot::default(),
            }),
        };
        recorder.record(AuditRecord::new(None, recorder_started_kind()));
        Ok(recorder)
    }
}

/// The `recorder_started` boundary row recorded by [`JsonlRecorder::open`] and
/// after each rotation. The recorder session id lives on the enclosing
/// [`AuditEvent::recorder_session_id`], so the kind only names the recorder.
fn recorder_started_kind() -> AuditEventKind {
    AuditEventKind::RecorderStarted {
        recorder: "marmot_forensics::JsonlRecorder".to_string(),
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
            audit_data_mode: inner.data_mode,
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
        {
            let mut inner = match self.inner.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            self.swap_to_fresh_file(&mut inner)?;
        }
        // Mark the start of the fresh file, mirroring `open_with_data_mode`.
        // `record` re-acquires the lock, so this runs after the guard is
        // dropped above.
        self.record(AuditRecord::new(None, recorder_started_kind()));
        Ok(())
    }

    fn data_mode(&self) -> AuditDataMode {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .data_mode
    }

    fn set_data_mode(&self, new_mode: AuditDataMode, reason: &str) -> std::io::Result<()> {
        let previous_mode = {
            let mut inner = match self.inner.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let previous_mode = inner.data_mode;
            // No real change: leave the current file (and its single mode)
            // intact rather than inserting a spurious boundary.
            if previous_mode == new_mode {
                return Ok(());
            }
            // Apply the mode before swapping so the fresh file is stamped
            // entirely with `new_mode`, then rotate so the old mode's lines
            // never share a file with the new mode's.
            inner.data_mode = new_mode;
            self.swap_to_fresh_file(&mut inner)?;
            previous_mode
        };
        // Boundary rows on the fresh file: the `recorder_started` marker
        // followed by the mode-change record, both stamped with `new_mode`.
        self.record(AuditRecord::new(None, recorder_started_kind()));
        self.record(AuditRecord::new(
            None,
            AuditEventKind::AuditDataModeChanged {
                previous_mode,
                new_mode,
                reason: reason.to_string(),
                recorder_restarted: Some(true),
            },
        ));
        Ok(())
    }
}

impl JsonlRecorder {
    /// Discard the current backing file and reopen an empty one at the same
    /// path, resetting the sequence, recorder session id, and health counters.
    /// The caller must hold the inner lock; the data mode is left untouched so
    /// both [`rotate`](ForensicRecorder::rotate) and
    /// [`set_data_mode`](ForensicRecorder::set_data_mode) can reuse it.
    fn swap_to_fresh_file(&self, inner: &mut JsonlInner) -> std::io::Result<()> {
        // Best-effort flush of whatever is buffered into the file we are about
        // to discard.
        let _ = inner.writer.flush();
        // Unlink the current file. The fd still held by `inner.writer` keeps
        // pointing at the now-unlinked inode until it is replaced below; on
        // Unix that is harmless and the writer is discarded immediately. A
        // missing file is fine — the goal state is "no old file, fresh file
        // recording".
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        // Open a brand-new file at the same path and swap it in. Assigning to
        // `inner.writer` drops the old `BufWriter`, closing the stale (unlinked)
        // fd.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        inner.writer = BufWriter::new(file);
        inner.seq = 0;
        inner.recorder_session_id = generate_recorder_session_id();
        inner.health = AuditRecorderHealthSnapshot::default();
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
