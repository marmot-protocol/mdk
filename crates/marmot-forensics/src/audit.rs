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
//! Audit events carry the obfuscated identifiers, digests, counts, and state
//! transitions needed for incident reconstruction. They never carry decrypted
//! message/app content, cleartext group-state values, or full account/member
//! identities. The recorder is opt-in and intended for local debugging of
//! group desync / fork incidents.
//!
//! ## Schema stability
//!
//! Every line is tagged with [`AUDIT_LOG_SCHEMA_VERSION`]. Bump the version
//! when adding required fields; analyzers should reject unknown versions.
//!
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use web_time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AUDIT_LOG_SCHEMA_VERSION: &str = "marmot-forensics-audit/v4";

/// Size at which [`JsonlRecorder`] seals the active file into an immutable
/// segment and continues into a fresh one (mdk#1181). The repeated source
/// prefix is excluded from this budget; a file can exceed it by that prefix
/// and the final threshold-crossing row.
///
/// The number is picked from measured rows, not from the upload ceiling:
///
/// - A recorded row measures ~597 bytes on average (p90 696, max 811 over a
///   real create-group + 50-send session), so a 1 MiB segment holds ~1,750
///   rows — roughly 250 sends of activity, still an analytically useful unit
///   even for a 4x richer row mix in large groups.
/// - The uploader re-posts the *active* file in full on every trigger, so the
///   threshold is also the bound on that residual. Before rotation the active
///   file grew without bound, which is what made cumulative transfer quadratic;
///   1 MiB makes the per-trigger cost constant instead. Against the ~5.3 MiB
///   mean upload measured in the field that is a 5-10x cut, and it does not
///   decay as a device keeps running.
/// - It leaves a 64x margin under the app's 64 MiB per-request upload ceiling,
///   for normal rows. Arbitrarily large host metadata or individual rows can
///   still exceed the ceiling and are rejected by the upload size gate.
///
/// Smaller segments would cut the residual further but multiply file count
/// (segments are never deleted here — retention is mdk#1014); larger ones
/// re-inflate the residual. 1 MiB is the balance point.
pub const AUDIT_LOG_SEGMENT_MAX_BYTES: u64 = 1024 * 1024;

/// Hex-encoded 16-byte account identity hash. Stable across devices for the
/// same account when the caller supplies it.
pub type AccountRefHex = String;

/// Hex-encoded 16-byte engine identity hash. Stable for the lifetime of a
/// single account-device engine instance.
pub type EngineIdHex = String;

/// Hex-encoded `GroupId` bytes. Raw identifiers remain sensitive in uploaded logs.
pub type GroupRefHex = String;

/// Hex-encoded `MessageId` bytes.
pub type MessageRefHex = String;

/// Hex-encoded 16-byte stable hash of Marmot member identity bytes.
pub type MemberRefHex = String;

/// Domain-separated diagnostic member reference used by audit rows.
///
/// Returns the lowercase hex of the first 16 bytes of
/// `SHA-256(b"marmot-audit-member-ref/v1" || member_identity)`.
/// This is a pseudonymous join key, not authentication or a membership verdict.
/// The prefix is a public domain separator, not a secret salt.
pub fn member_ref_hex(member_identity: &[u8]) -> MemberRefHex {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-audit-member-ref/v1");
    hasher.update(member_identity);
    hex::encode(&hasher.finalize()[..16])
}

/// Hex-encoded 32-byte SHA-256 digest.
pub type DigestHex = String;

static RECORDER_SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One line of the JSONL audit log.
///
/// `seq`, `wall_time_ms`, `account_ref`, and `engine_id` are
/// recorder-assigned; the engine supplies the rest via [`AuditRecord`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// Ephemeral app-validated Nostr Welcome references for the exact publish
    /// batch. Never serialized into v4 or operational v5 contexts; account
    /// publication consumes this only while the operation is in memory.
    #[serde(skip)]
    pub v5_welcome_refs: Vec<(
        MessageRefHex,
        crate::v5::NostrEventRef,
        crate::v5::LocalId,
        crate::v5::GroupRef,
    )>,
}

/// Identifies the account/device/app that produced an audit log, for upload
/// correlation. Account and device display names are never included. Hardware
/// model metadata must come from the host platform, not a user-editable label.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSourceContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// System hardware model, never a user-assigned name, hostname, or serial number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_trigger: Option<String>,
    /// Producer member reference: lowercase hex of the first 16 bytes of
    /// `SHA-256(b"marmot-audit-member-ref/v1" || member_identity_bytes)`.
    ///
    /// This is a pseudonymous diagnostic join so a producing engine can be
    /// correlated with `group_state_changed.subject_member_ref` /
    /// `actor_member_ref`. It is not authentication or a membership verdict.
    /// Absence means unknown or unavailable, including older rows; it is never
    /// evidence that a producer was removed. The value is never an
    /// [`AccountRefHex`] — account and member references use distinct hash
    /// domains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_member_ref: Option<MemberRefHex>,
}

/// Correlates every row produced during one distributed-convergence run via a
/// stable `run_id`, so an analyzer can group a run's `convergence_run_state`
/// lifecycle and `convergence_decision` together.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// What armed an epoch-gap backfill for one stalled group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStallBackfillTrigger {
    UndecryptableThreshold,
    /// The undecryptable threshold was crossed on a group whose stored commit
    /// graph is contested, so the traffic driving the arm is sealed under a
    /// branch this device has not adopted. Recorded apart from
    /// [`Self::UndecryptableThreshold`] because it changes what the replay can
    /// possibly achieve, not whether it ran: the objects are already retained
    /// locally, so no amount of relay history supplies the adoption they need —
    /// convergence adjudication does. An incident that keeps arming under this
    /// trigger is a fork to resolve, not a device to re-sync.
    ContestedForkDeferral,
    ResourceRefusal,
}

/// Worker seam that executed a pending epoch-gap backfill replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochBackfillExecutionSeam {
    Startup,
    Receive,
    ExplicitCatchUp,
    Maintenance,
}

/// Scope of the transport replay issued for epoch-gap recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochBackfillReplayScope {
    AccountFullHistory,
}

/// Typed outcome of `activate_transport(None)` during epoch-gap recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochBackfillActivationOutcome {
    Succeeded,
    Failed,
}

/// What ended the drain of an epoch-gap replay that completed.
///
/// Absent on rows written before this field existed; those predate the
/// end-of-stored-events gate and were all quiescence drains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochBackfillCompletionKind {
    /// Every endpoint-scoped subscription attempt in the replay's frozen route
    /// snapshot was reported end-of-stored-events: the account's stored
    /// history was served in full.
    EndOfStoredEvents,
    /// Legacy completion written by versions that converted a repeatedly
    /// unconfirmed end-of-stored-events gate into a quiet-relay success. Kept
    /// solely so historical audit rows remain readable; current recovery never
    /// emits this weaker claim.
    QuiescenceFallback,
}

/// Why a pending epoch-gap replay was not executed on this pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochBackfillDeferredReason {
    GroupEpochUnavailable,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
/// are safe for audit recording. Never carries auth tokens, signatures,
/// ciphertext, or key material.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
/// authenticated group membership at send time. Recipients are represented by
/// salted member refs and an aggregate count, never full member identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientExpectation {
    pub artifact_kind: MessageArtifactKind,
    pub recipient_scope: RecipientScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis_commit_id: Option<MessageRefHex>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_member_refs: Vec<MemberRefHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_count: Option<u64>,
}

/// One message produced by a send/create operation, for the `outbound_messages`
/// inventory on `send_outcome` / `create_group_outcome`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundMessage {
    pub msg_id: MessageRefHex,
    pub artifact_kind: MessageArtifactKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<AuditTransportWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_expectation: Option<RecipientExpectation>,
}

/// One witness application message observed at a future epoch, used by the
/// witness-quorum convergence rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConvergenceAppWitness {
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_ref: Option<MemberRefHex>,
}

/// The score the selector computed for a convergence candidate. Mirrors the
/// engine's `BranchScore` using only obfuscated identities and digests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub tip_digest: Option<DigestHex>,
}

/// One branch the convergence selector evaluated.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// The value of a group-state change, represented only by a digest and length.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupStateValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<DigestHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecorderHealthSnapshot {
    pub serialization_failures: u64,
    pub write_failures: u64,
    pub flush_failures: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditEventKind {
    /// The JSONL recorder opened a new local recorder session. The session id
    /// is carried on the enclosing [`AuditEvent::recorder_session_id`] rather
    /// than duplicated here.
    RecorderStarted { recorder: String },
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
    /// per recorder session using opaque source labels only.
    SourceContext { source: AuditSourceContext },
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
        subject_member_ref: Option<MemberRefHex>,
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
    /// an application-initiated retry (mdk#426) and is live again.
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
    /// A pairwise same-epoch fork resolution verdict. Emitted only by
    /// pre-unification engine versions (the pairwise fork-resolution route
    /// was deleted in favor of distributed convergence); the kind is kept so
    /// historical JSONL exports remain parseable.
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
    /// candidate with its safe score summary, the selected branch, and the
    /// losing branches.
    ConvergenceDecision {
        current_tip_epoch: u64,
        max_rewind_commits: u64,
        // Always serialized (schema-required), even when empty.
        candidates: Vec<ConvergenceCandidate>,
        /// Name of the first selector rule that distinguished the winner.
        /// This preserves the useful scalar outcome without retaining the
        /// former free-form rule input/value trace.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decisive_rule: Option<String>,
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
        /// How many re-peel attempts a deferred row consumed before this
        /// transition (deferred-peel lifecycle rows only).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_count: Option<u64>,
        /// How many wall-clock milliseconds elapsed between the row's durable
        /// first observation and this transition.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        residence_ms: Option<u64>,
    },
    /// A message or intent was rejected with a structured reason.
    Rejection {
        msg_id: MessageRefHex,
        reason: String,
    },
    /// The account's Nostr subscription plane was rebuilt with a `since` floor.
    /// Records the floor actually requested (`since_secs`; `None` means a
    /// full-history replay because the durable cursor was absent or detectably
    /// corrupt), the lookback subtracted from the durable cursor to derive it
    /// (`lookback_secs`), and the per-relay registration outcome
    /// (`relay_results`). Together with [`AuditEventKind::SyncDrain`] these rows
    /// let an analyzer reconstruct the decisive
    /// persisted-cursor-vs-missed-`created_at` evidence from any export,
    /// including NSE wake sessions.
    ///
    /// Units: the durable transport cursor is advanced from inbound event
    /// `created_at`, which is Nostr second-granular, so the derived floor and
    /// lookback are `_secs` — deliberately not the `_ms` used by wall-clock
    /// rows elsewhere in this schema.
    ///
    /// Privacy: `relay_results` carries relay URLs. This is deliberate and
    /// mirrors the existing publish-path kinds — [`AuditEventKind::PublishAttempt`]
    /// and [`AuditEventKind::PublishOutcome`] already carry `relay_url` /
    /// `relay_urls` / `accepted_relay_urls`. The forensic audit channel is a
    /// consented operational surface, distinct
    /// from the tracing/logging invariant that forbids relay URLs in logs; so
    /// rebuild rows carry the same relay identifiers the publish rows already do
    /// rather than being the odd kind out. The URLs are caller-supplied
    /// subscription endpoints, never a new identity minted at the transport
    /// boundary.
    SubscriptionRebuild {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since_secs: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lookback_secs: Option<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        relay_results: Vec<RelayRegistration>,
    },
    /// The transport drain loop (`sync_sdk_relay`) reached a success or failure
    /// exit. Records how long the drain ran (`duration_ms`, true wall-clock),
    /// how many deliveries it ingested (`deliveries`), how many receives it
    /// dropped as an echo or an already-seen duplicate (`skipped`), and the
    /// durable transport cursor immediately before and after the drain
    /// (`cursor_before_secs` / `cursor_after_secs`; `None` before any delivery
    /// has ever advanced the cursor).
    ///
    /// `deliveries` and `skipped` together are what separate a long drain that
    /// was making progress from one a relay held open with traffic carrying no
    /// new history — the two are indistinguishable from `duration_ms` alone.
    ///
    /// Units: the cursor is a Nostr second-granular timestamp, so those fields
    /// are `_secs`; `duration_ms` is a genuine millisecond wall-clock duration.
    ///
    /// Privacy: scalar counts and timestamps only — no relay URLs, ids, or
    /// payloads.
    SyncDrain {
        duration_ms: u64,
        deliveries: u64,
        /// Receives this drain dropped without ingesting: a relay echo of this
        /// device's own publish, or an event already in the seen index. Split
        /// out from `deliveries` because the two answer different questions —
        /// a long drain with a high `deliveries` count was doing work, while
        /// one with a high `skipped` count was being held open by traffic
        /// carrying no new history. Optional only so rows written before this
        /// field existed stay readable; absent means "not recorded", not zero.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        skipped: Option<u64>,
        /// The subset of `deliveries` the engine refused under a local resource
        /// bound (`IngestOutcome::ResourceRefused`) and therefore did not
        /// retain. Counted inside `deliveries`, not beside it: the delivery was
        /// received and ingested, and `deliveries` keeps its established
        /// meaning. `deliveries - refused` is what the drain durably recovered,
        /// so a run where the two are equal fetched history it could not keep —
        /// per-drain cap saturation, readable straight off the row instead of
        /// reconstructed from raw `ingest_outcome` rows. Optional only so rows
        /// written before this field existed stay readable; absent means "not
        /// recorded", not zero.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refused: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor_before_secs: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor_after_secs: Option<u64>,
    },
    /// A group crossed the epoch-stall backfill threshold — enough distinct
    /// undecryptable messages at one stalled epoch — and armed a full-history
    /// epoch-gap backfill (commit-loss recovery). Emitted once per (group,
    /// stalled epoch) at the arm decision, *before* the replay side effect runs,
    /// so a field export reveals when and why full-history replays fire — the
    /// evidence loop for tuning the empirical backfill threshold.
    ///
    /// Group-scoped: the stalled group's id is on the enclosing
    /// [`AuditEvent::group_ref`], exactly as the `human_action` group rows carry
    /// it; it is deliberately not duplicated into a field here. `stalled_epoch`
    /// is the group epoch the device was stuck at when it armed — correlate it
    /// against the group's live epoch (visible on `group_context` / `epoch_*`
    /// rows) to read the size of the gap that triggered recovery. `threshold` is
    /// the distinct-undecryptable count that armed the backfill, carried so an
    /// export is self-describing when the constant is retuned across builds.
    ///
    /// Privacy: scalar counts plus a closed trigger enum only — no ids, relay
    /// URLs, message ids, or payloads. `trigger` is optional only so existing v2
    /// rows emitted before this field was added remain readable.
    EpochStallBackfillArmed {
        stalled_epoch: u64,
        threshold: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trigger: Option<EpochStallBackfillTrigger>,
    },
    /// A pending epoch-gap backfill replay began executing. Account-scoped:
    /// the replay is account-wide even when multiple groups armed it.
    /// Correlated with the arm and terminal rows via `context.operation_id`.
    EpochStallBackfillStarted {
        seam: EpochBackfillExecutionSeam,
        replay_scope: EpochBackfillReplayScope,
        retry_ordinal: u64,
    },
    /// A pending epoch-gap backfill replay finished after activation and drain.
    /// Group-scoped: `group_ref` is the armed group whose local epoch is
    /// compared before and after the replay. `group_advanced` is true only when
    /// that group's observed local epoch increased across the attempt.
    EpochStallBackfillCompleted {
        retry_ordinal: u64,
        duration_ms: u64,
        activation_outcome: EpochBackfillActivationOutcome,
        /// What ended the drain. Historical `quiescence_fallback` values are a
        /// weaker claim than `end_of_stored_events` and must not be read as
        /// proof the account's stored history was served in full; current
        /// recovery emits only endpoint-covered `end_of_stored_events`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        completion_kind: Option<EpochBackfillCompletionKind>,
        deliveries: u64,
        /// Receives this drain dropped without ingesting: a relay echo of this
        /// device's own publish, or an event already in the seen index. Split
        /// out from `deliveries` because the two answer different questions —
        /// a long drain with a high `deliveries` count was doing work, while
        /// one with a high `skipped` count was being held open by traffic
        /// carrying no new history. Optional only so rows written before this
        /// field existed stay readable; absent means "not recorded", not zero.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        skipped: Option<u64>,
        /// The subset of `deliveries` the engine refused under a local resource
        /// bound and therefore did not retain; see
        /// [`Self::SyncDrain::refused`]. `deliveries - refused` is what this
        /// replay durably recovered, so a replay whose two counts are equal
        /// re-fetched history it could not keep and recovered nothing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refused: Option<u64>,
        local_epoch_before: u64,
        local_epoch_after: u64,
        group_advanced: bool,
    },
    /// A pending epoch-gap backfill replay failed or could not recover the
    /// armed group. Group-scoped for the same epoch observation semantics as
    /// [`Self::EpochStallBackfillCompleted`]. Pending recovery is retained.
    EpochStallBackfillFailed {
        retry_ordinal: u64,
        duration_ms: u64,
        activation_outcome: EpochBackfillActivationOutcome,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_kind: Option<String>,
        deliveries: u64,
        /// Receives this drain dropped without ingesting: a relay echo of this
        /// device's own publish, or an event already in the seen index. Split
        /// out from `deliveries` because the two answer different questions —
        /// a long drain with a high `deliveries` count was doing work, while
        /// one with a high `skipped` count was being held open by traffic
        /// carrying no new history. Optional only so rows written before this
        /// field existed stay readable; absent means "not recorded", not zero.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        skipped: Option<u64>,
        /// The subset of `deliveries` the engine refused under a local resource
        /// bound and therefore did not retain; see
        /// [`Self::SyncDrain::refused`]. `deliveries - refused` is what this
        /// replay durably recovered, so a replay whose two counts are equal
        /// re-fetched history it could not keep and recovered nothing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refused: Option<u64>,
        local_epoch_before: u64,
        local_epoch_after: u64,
        group_advanced: bool,
        /// Whether `local_epoch_after` is a reading at all.
        ///
        /// `false` means the post-replay epoch read failed, so
        /// `local_epoch_after` repeats `local_epoch_before` and
        /// `group_advanced` is that placeholder's arithmetic, not an
        /// observation: this replay's effect on the group is *unknown*, not
        /// absent. Only a failed row can carry it — a run that succeeds has
        /// read every armed group's epoch by definition.
        ///
        /// Absent means the row predates this field *or* the reading was taken,
        /// and an analyzer cannot tell which. The field is additive, so no
        /// schema version separates old rows from new ones, and a pre-change
        /// failed row whose after-read failed looks exactly like an observed
        /// one — that indistinguishability is the very defect this field exists
        /// to end going forward. Read absence as "unknown provenance", never as
        /// proof the reading was taken.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_advanced_observed: Option<bool>,
    },
    /// A pending epoch-gap backfill replay was not executed on this pass.
    /// Account-scoped; does not clear pending recovery.
    EpochStallBackfillDeferred {
        reason: EpochBackfillDeferredReason,
        retry_ordinal: u64,
    },
    /// A group armed `arms` epoch-gap backfills in one run with nothing in
    /// between to show the device had caught up: full-history replay keeps
    /// recovering some backlog, and nothing this device can see says it is
    /// reaching the group. Emitted once per unrecovered run: at the arm that
    /// reached `arm_threshold`, alongside that arm's
    /// `epoch_stall_backfill_armed` row, or — for a group wedged at one epoch —
    /// at the replay completion that reached the fruitless-completion
    /// threshold, alongside that replay's `epoch_stall_backfill_completed` row.
    ///
    /// This is the durable record of the escalation the runtime reports to the
    /// app, which decides whether to run the stronger repair (key-package
    /// rotation plus a full transport re-activation). Where recording is enabled
    /// it is what makes each escalation permanent evidence, and the field-evidence
    /// loop that tunes `arm_threshold`.
    ///
    /// Reading it needs care in both directions. A second row for one group is
    /// not necessarily a second independent failure: the arm-run counter behind
    /// `arms` is in-memory, so a restart clears it and the same unresolved
    /// condition can re-earn a whole run of arms. And the absence of a second
    /// row is not recovery: re-escalating a group whose epoch is still moving
    /// needs that movement to continue, and a group wedged at one epoch reports
    /// once per run — it must gather a whole fresh run's worth of confirmed
    /// evidence before it can report that epoch again.
    ///
    /// A group wedged at one epoch reaches this row by a different route, worth
    /// knowing when reading `arms`. It cannot re-arm on epoch movement, so it
    /// arms on a paced clock instead and escalates on how many of those replays
    /// came back with the relays confirming they had served the account's stored
    /// history and it held nothing. `arms` then counts those confirmed
    /// completions rather than arms — a stricter count, never a larger one.
    /// `arm_threshold` stays the arm-run threshold on every row, including the
    /// ones the fruitless rule decided, so it is the field's constant meaning
    /// and not a record of which rule fired; the emitting warn log names the
    /// deciding threshold. Unlike the arm
    /// run, that evidence is durable, so a restart neither erases it nor
    /// re-reports a group already reported.
    ///
    /// Group-scoped: the group id is on the enclosing [`AuditEvent::group_ref`],
    /// exactly as `epoch_stall_backfill_armed` carries it. `stalled_epoch` is the
    /// epoch the device sat at when the escalating arm fired.
    ///
    /// Privacy: three scalar counts only — no ids, relay URLs, message ids, or
    /// payloads.
    EpochStallBackfillEscalated {
        stalled_epoch: u64,
        arms: u64,
        arm_threshold: u64,
    },
    /// A durable convergence pass whose base epoch disagreed with the device's
    /// current tip was discarded, freeing convergence to reopen at the tip.
    /// Non-terminal by construction: it records a repair, not a fault. The
    /// disagreement is inherited scheduling state — an older binary stamped a
    /// pass's base epoch from the durable group record while convergence compared
    /// the epoch manager, and those two stores can split across a restart — so
    /// `stale_base_epoch` may sit either behind or ahead of `current_tip_epoch`.
    /// `generation` is the discarded pass's generation, so an export shows which
    /// scheduling state was dropped.
    ///
    /// Group-scoped through the enclosing [`AuditEvent::group_ref`]; three scalar
    /// epochs/counters only.
    ConvergencePassDiscarded {
        stale_base_epoch: u64,
        current_tip_epoch: u64,
        generation: u64,
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
            AuditEventKind::TransportReceived { .. } => "transport_received",
            AuditEventKind::IngestEntry { .. } => "ingest_entry",
            AuditEventKind::IngestOutcome { .. } => "ingest_outcome",
            AuditEventKind::IngestError { .. } => "ingest_error",
            AuditEventKind::SourceContext { .. } => "source_context",
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
            AuditEventKind::SubscriptionRebuild { .. } => "subscription_rebuild",
            AuditEventKind::SyncDrain { .. } => "sync_drain",
            AuditEventKind::EpochStallBackfillArmed { .. } => "epoch_stall_backfill_armed",
            AuditEventKind::EpochStallBackfillStarted { .. } => "epoch_stall_backfill_started",
            AuditEventKind::EpochStallBackfillCompleted { .. } => "epoch_stall_backfill_completed",
            AuditEventKind::EpochStallBackfillFailed { .. } => "epoch_stall_backfill_failed",
            AuditEventKind::EpochStallBackfillDeferred { .. } => "epoch_stall_backfill_deferred",
            AuditEventKind::EpochStallBackfillEscalated { .. } => "epoch_stall_backfill_escalated",
            AuditEventKind::ConvergencePassDiscarded { .. } => "convergence_pass_discarded",
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
#[serde(deny_unknown_fields)]
pub struct PublishRelayFailure {
    pub relay_url: String,
    pub reason: String,
}

/// One relay's registration outcome during a subscription rebuild, on
/// [`AuditEventKind::SubscriptionRebuild`]. `relay_url` is the caller-supplied
/// subscription endpoint; `accepted` is whether the relay acknowledged the
/// subscription registration. See the kind doc for why the relay URL is carried
/// here (publish-kind precedent).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayRegistration {
    pub relay_url: String,
    pub accepted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeelerOutcomeKind {
    Success,
    DecryptFailed,
    StaleEpoch,
    Malformed,
    InvalidSignature,
    WrongRecipient,
    Other,
}

/// Recorder interface. The engine invokes [`record`](Self::record) at every
/// audit-point call site. Implementations must be cheap on the hot path.
///
/// All methods take `&self` so implementations carry interior mutability
/// (e.g. a `Mutex`-protected file handle).
pub trait ForensicRecorder: Send + Sync {
    fn record(&self, record: AuditRecord);

    /// Record a native v5 event under the same writer/session/sequence as the
    /// engine's operational audit rows. Older recorders ignore this optional
    /// evidence; an enabled v5 recorder assigns all envelope fields.
    fn record_v5_event(&self, _group_ref: Option<crate::v5::GroupRef>, _event: crate::v5::Event) {}

    /// Observe an explicit clean end to this v5 writer session. Dropping a
    /// recorder does not imply this happened. Legacy and no-op writers ignore it.
    fn finish_v5_recording(&self, _reason: crate::v5::RecordingStopReason) {}

    fn records_v5(&self) -> bool {
        false
    }

    /// Whether this recorder consumes audit events.
    ///
    /// Producers may use this to skip audit-only data loads on hot paths. The
    /// default is enabled so custom recorders remain observable without code
    /// changes; [`NoopRecorder`] is the sole disabled implementation.
    fn is_enabled(&self) -> bool {
        true
    }

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

    fn is_enabled(&self) -> bool {
        false
    }
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
    /// Test seam: forces [`Self::reopen_active`] to fail, so the compensating
    /// rename-back in [`Self::roll_into_segment`] — the only step that must
    /// undo an applied rename — has a deterministic red. One-shot. There is no
    /// way to fail the reopen and not the rename from outside the process:
    /// both need the same directory permission, and the rename removes the
    /// very path the reopen would recreate.
    #[cfg(test)]
    fail_segment_reopen: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_segment_restore: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    disable_segment_rotation: std::sync::atomic::AtomicBool,
}

struct JsonlInner {
    // Option lets Drop consume an uncertain BufWriter without flushing its
    // buffered tail. A live recorder always has Some(writer).
    writer: Option<BufWriter<File>>,
    seq: u64,
    account_ref: Option<AccountRefHex>,
    engine_id: EngineIdHex,
    recorder_session_id: String,
    format: RecorderFormat,
    health: AuditRecorderHealthSnapshot,
    /// In-memory failed record attempts since the last successfully persisted
    /// capture-loss row. This is not a replay journal or a completeness count.
    pending_capture_loss: PendingCaptureLoss,
    recording_finished: bool,
    /// A partial write or flush may have exposed an uncertain tail. Preserve
    /// that inode and seal it before appending any subsequent row.
    writer_needs_seal: bool,
    /// After one seal attempt, defer another until the existing 30s retry
    /// window has elapsed unless an ordinary row was successfully written.
    seal_retry_after: Option<Instant>,
    /// Bytes in the file the writer currently owns, driving segment rolls.
    active_bytes: u64,
    /// Retry deadline after a failed roll; recording continues during backoff.
    segment_retry_after: Option<Instant>,
    /// The writer may remain at a segment path if compensation also failed.
    writer_path: PathBuf,
    /// Lower-bound hint for the next unclaimed segment index, so a roll does
    /// not `read_dir` the account directory on the engine hot path once per
    /// segment. Scanned once when absent and advanced after each sealed
    /// segment; the `exists()` probe in [`JsonlRecorder::next_segment_path`]
    /// stays the authority that no roll ever overwrites a segment, so a stale
    /// or absent hint costs a gap in the numbering at worst. Unbounded segment
    /// counts are mdk#1014's to bound.
    next_segment_index: Option<u32>,
    /// Most recently explicitly recorded `AuditEventKind::SourceContext`.
    /// Retained even when the best-effort write fails so a later successful
    /// rotation can repeat it. Not inferred from
    /// `AuditEventContext.source`. Survives destructive swaps.
    retained_source_context: Option<AuditSourceContext>,
    /// Repeated source bytes do not consume the next segment's event budget.
    /// Even an oversized source must not cause a roll on every ordinary event.
    repeated_source_bytes: u64,
    /// Test seam: fail the next row or segment-prefix write after capturing source
    /// context, so retention can be proven independently of a durable write.
    #[cfg(test)]
    fail_next_write: bool,
    /// Simulate an IO failure after a visible, unterminated prefix for the
    /// prepared-range/segment recovery regression.
    #[cfg(test)]
    fail_next_partial_write: bool,
    /// Simulate a failed flush while a complete row is still buffered.
    #[cfg(test)]
    fail_next_v5_flush_with_buffered_row: bool,
    #[cfg(test)]
    fail_next_v5_write: bool,
}

impl Drop for JsonlInner {
    fn drop(&mut self) {
        if self.writer_needs_seal {
            // BufWriter::drop would retry its buffered tail, turning a row
            // already reported as failed into an unobserved append. Keep all
            // bytes already visible on the inode, but discard only this
            // uncertain in-memory buffer.
            if let Some(writer) = self.writer.take() {
                let _ = writer.into_parts();
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
struct PendingCaptureLoss {
    serialization: u64,
    write: u64,
    flush: u64,
}

impl PendingCaptureLoss {
    fn is_empty(self) -> bool {
        self.serialization == 0 && self.write == 0 && self.flush == 0
    }
}

enum RecorderFormat {
    V4,
    V5 {
        source_ref: crate::v5::SourceRef,
        session_id: crate::v5::SessionId,
        producer: crate::v5::Producer,
        opened_at: Instant,
    },
}

fn v5_session_id(recorder_session_id: &str) -> crate::v5::SessionId {
    let digest = Sha256::digest(recorder_session_id.as_bytes());
    hex::encode(&digest[..16])
        .try_into()
        .expect("16-byte digest")
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

    /// Open a recorder with an optional obfuscated account reference.
    pub fn open_with_account_ref(
        path: impl AsRef<Path>,
        engine_id: EngineIdHex,
        account_ref: Option<AccountRefHex>,
    ) -> std::io::Result<Self> {
        Self::open_with_format(path, engine_id, account_ref, None)
    }

    /// Open the opt-in v5 writer. It shares the v4 writer's private file,
    /// segment, retry, health and destructive-rotation machinery, but never
    /// appends to a v4 filename or changes a v4 body's bytes.
    pub fn open_v5_with_account_ref(
        path: impl AsRef<Path>,
        engine_id: EngineIdHex,
        account_ref: Option<AccountRefHex>,
        producer: crate::v5::Producer,
    ) -> std::io::Result<Self> {
        Self::open_with_format(path, engine_id, account_ref, Some(producer))
    }

    fn open_with_format(
        path: impl AsRef<Path>,
        engine_id: EngineIdHex,
        account_ref: Option<AccountRefHex>,
        producer: Option<crate::v5::Producer>,
    ) -> std::io::Result<Self> {
        if let Some(account_ref) = account_ref.as_deref() {
            validate_account_ref_hex(account_ref)?;
        }
        let path = path.as_ref().to_path_buf();
        // Audit files are private local operational artifacts. Create them
        // owner-only and tighten pre-existing permissive files.
        let file = fs_private::open_private_append(&path)?;
        let active_bytes = file.metadata().map(|meta| meta.len()).unwrap_or(0);
        let recorder_session_id = generate_recorder_session_id();
        let is_v5 = producer.is_some();
        let format = if let Some(producer) = producer {
            let source_ref = crate::v5::SourceRef::try_from(engine_id.clone()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "v5 source must be a 16-byte lowercase hex reference",
                )
            })?;
            RecorderFormat::V5 {
                source_ref,
                session_id: v5_session_id(&recorder_session_id),
                producer,
                opened_at: Instant::now(),
            }
        } else {
            RecorderFormat::V4
        };
        let recorder = Self {
            path: path.clone(),
            inner: Mutex::new(JsonlInner {
                writer: Some(BufWriter::new(file)),
                seq: 0,
                account_ref,
                engine_id,
                recorder_session_id,
                format,
                health: AuditRecorderHealthSnapshot::default(),
                pending_capture_loss: PendingCaptureLoss::default(),
                recording_finished: false,
                writer_needs_seal: false,
                seal_retry_after: None,
                active_bytes,
                segment_retry_after: None,
                writer_path: path.clone(),
                next_segment_index: None,
                retained_source_context: None,
                repeated_source_bytes: 0,
                #[cfg(test)]
                fail_next_write: false,
                #[cfg(test)]
                fail_next_partial_write: false,
                #[cfg(test)]
                fail_next_v5_flush_with_buffered_row: false,
                #[cfg(test)]
                fail_next_v5_write: false,
            }),
            #[cfg(test)]
            fail_segment_reopen: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_segment_restore: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            disable_segment_rotation: std::sync::atomic::AtomicBool::new(false),
        };
        // Upgrade path: a file left over-threshold by a build without segment
        // rotation — including one already past the app's upload ceiling, which
        // no automatic upload can ever accept — is sealed aside here so this
        // session starts on a fresh, uploadable active file. Splitting the
        // oversized file is deliberately not attempted; it stays an immutable
        // segment and the uploader surfaces it. Best-effort: a roll failure
        // must not cost the caller its audit log entirely, so recording
        // continues into the existing file.
        if active_bytes >= AUDIT_LOG_SEGMENT_MAX_BYTES {
            let mut inner = recorder
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            recorder.try_roll_segment(&mut inner, Instant::now());
        }
        if is_v5 {
            recorder.record_v5_event(None, recording_started_event());
        }
        recorder.record(AuditRecord::new(None, recorder_started_kind()));
        Ok(recorder)
    }
}

/// The `recorder_started` boundary row recorded by [`JsonlRecorder::open`] and
/// after each destructive rotation. The recorder session id lives on the enclosing
/// [`AuditEvent::recorder_session_id`], so the kind only names the recorder.
fn recorder_started_kind() -> AuditEventKind {
    AuditEventKind::RecorderStarted {
        recorder: "marmot_forensics::JsonlRecorder".to_string(),
    }
}

fn recording_started_event() -> crate::v5::Event {
    crate::v5::Event::RecordingSessionStarted(crate::v5::RecordingSessionStarted {
        mode: crate::v5::RecordingMode::OptInLocalJsonl,
        limitations: vec![
            crate::v5::RecordingLimitation::BestEffortLocalWrites,
            crate::v5::RecordingLimitation::NoCompletenessGuarantee,
        ],
    })
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
        if inner.recording_finished {
            return;
        }
        if self.ensure_safe_writer(&mut inner).is_err() {
            return;
        }
        Self::try_report_pending_capture_loss(&mut inner);
        let before = inner.health.clone();
        if Self::write_record(&mut inner, record) {
            inner.seal_retry_after = None;
            self.try_roll_segment(&mut inner, Instant::now());
        } else if matches!(inner.format, RecorderFormat::V5 { .. }) {
            Self::remember_failed_attempt(&mut inner, &before);
        }
    }

    fn record_v5_event(&self, group_ref: Option<crate::v5::GroupRef>, event: crate::v5::Event) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !matches!(inner.format, RecorderFormat::V5 { .. }) || inner.recording_finished {
            return;
        }
        if self.ensure_safe_writer(&mut inner).is_err() {
            return;
        }
        Self::try_report_pending_capture_loss(&mut inner);
        let before = inner.health.clone();
        if Self::write_v5_event(&mut inner, group_ref, event) {
            inner.seal_retry_after = None;
            self.try_roll_segment(&mut inner, Instant::now());
        } else {
            Self::remember_failed_attempt(&mut inner, &before);
        }
    }

    fn finish_v5_recording(&self, reason: crate::v5::RecordingStopReason) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !matches!(inner.format, RecorderFormat::V5 { .. }) || inner.recording_finished {
            return;
        }
        // The observed clean-close boundary is terminal even if its row
        // cannot be written. A later record must not follow it.
        inner.recording_finished = true;
        if self.ensure_safe_writer(&mut inner).is_err() {
            return;
        }
        Self::try_report_pending_capture_loss(&mut inner);
        let before = inner.health.clone();
        if Self::write_v5_event(
            &mut inner,
            None,
            crate::v5::Event::RecordingSessionStopped(crate::v5::RecordingSessionStopped {
                reason,
            }),
        ) {
            self.try_roll_segment(&mut inner, Instant::now());
        } else {
            Self::remember_failed_attempt(&mut inner, &before);
        }
        // A failed terminal row cannot be retried without another observed
        // clean-close boundary. Absence of stop remains explicitly unknown.
    }

    fn records_v5(&self) -> bool {
        matches!(
            self.inner.lock().unwrap_or_else(|p| p.into_inner()).format,
            RecorderFormat::V5 { .. }
        )
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
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // An explicit destructive rotation must not flush or replace an
        // uncertain v5 inode before its already-visible bytes are sealed.
        self.ensure_safe_writer(&mut inner)?;
        self.swap_to_fresh_file(&mut inner)?;
        // Replay lifecycle rows under the same mutex. `record()` would
        // re-lock; size-based segment rolls must not take this path.
        if matches!(inner.format, RecorderFormat::V5 { .. }) {
            let before = inner.health.clone();
            if !Self::write_v5_event(&mut inner, None, recording_started_event()) {
                Self::remember_failed_attempt(&mut inner, &before);
            }
            if inner.writer_needs_seal {
                return Ok(());
            }
            Self::try_report_pending_capture_loss(&mut inner);
        }
        let before = inner.health.clone();
        if !Self::write_record(&mut inner, AuditRecord::new(None, recorder_started_kind()))
            && matches!(inner.format, RecorderFormat::V5 { .. })
        {
            Self::remember_failed_attempt(&mut inner, &before);
        }
        if inner.writer_needs_seal {
            return Ok(());
        }
        if let Some(source) = inner.retained_source_context.clone() {
            let before = inner.health.clone();
            if !Self::write_record(
                &mut inner,
                AuditRecord::new(None, AuditEventKind::SourceContext { source }),
            ) && matches!(inner.format, RecorderFormat::V5 { .. })
            {
                Self::remember_failed_attempt(&mut inner, &before);
            }
        }
        Ok(())
    }
}

impl JsonlRecorder {
    fn ensure_safe_writer(&self, inner: &mut JsonlInner) -> std::io::Result<()> {
        if !matches!(inner.format, RecorderFormat::V5 { .. }) || !inner.writer_needs_seal {
            return Ok(());
        }
        let now = Instant::now();
        if inner
            .seal_retry_after
            .is_some_and(|deadline| now < deadline)
        {
            inner.health.write_failures = inner.health.write_failures.saturating_add(1);
            inner.pending_capture_loss.write = inner.pending_capture_loss.write.saturating_add(1);
            return Err(std::io::Error::other("audit writer seal retry deferred"));
        }
        let result = self.seal_uncertain_writer(inner);
        // An immediate first seal preserves transient recovery. After that,
        // persistent failures cannot create one new segment per record.
        inner.seal_retry_after = Some(now + Duration::from_secs(30));
        if let Err(error) = result {
            inner.health.write_failures = inner.health.write_failures.saturating_add(1);
            inner.pending_capture_loss.write = inner.pending_capture_loss.write.saturating_add(1);
            return Err(error);
        }
        Ok(())
    }

    /// Keep every byte the independent delivery cursor may have observed.
    /// Renaming the inode preserves prepared ranges and their digest; a torn
    /// tail remains a visible delivery gap. The failed BufWriter's buffer is
    /// abandoned without a Drop flush only after a fresh writer is ready.
    fn seal_uncertain_writer(&self, inner: &mut JsonlInner) -> std::io::Result<()> {
        let renamed = if inner.writer_path == self.path {
            let (segment, index) = self.next_segment_path(inner)?;
            std::fs::rename(&self.path, &segment)?;
            Some((segment, index))
        } else {
            None
        };
        match self.reopen_active() {
            Ok(file) => {
                let old = inner.writer.replace(BufWriter::new(file));
                if let Some(old) = old {
                    let _ = old.into_parts();
                }
                if let Some((_, index)) = renamed {
                    inner.next_segment_index = Some(index.saturating_add(1));
                }
                inner.active_bytes = 0;
                inner.repeated_source_bytes = 0;
                inner.writer_path = self.path.clone();
                inner.writer_needs_seal = false;
                if let Some(source) = inner.retained_source_context.clone() {
                    let before = inner.health.clone();
                    if !Self::write_record(
                        inner,
                        AuditRecord::new(None, AuditEventKind::SourceContext { source }),
                    ) {
                        Self::remember_failed_attempt(inner, &before);
                    }
                    inner.repeated_source_bytes = inner.active_bytes;
                }
                if inner.writer_needs_seal {
                    return Err(std::io::Error::other("source context repeat failed"));
                }
                Ok(())
            }
            Err(error) => {
                if let Some((segment, _)) = renamed
                    && self.restore_segment(&segment, &self.path).is_err()
                {
                    inner.writer_path = segment;
                }
                Err(error)
            }
        }
    }

    fn remember_failed_attempt(inner: &mut JsonlInner, before: &AuditRecorderHealthSnapshot) {
        let pending = &mut inner.pending_capture_loss;
        pending.serialization = pending.serialization.saturating_add(
            inner
                .health
                .serialization_failures
                .saturating_sub(before.serialization_failures),
        );
        pending.write = pending.write.saturating_add(
            inner
                .health
                .write_failures
                .saturating_sub(before.write_failures),
        );
        pending.flush = pending.flush.saturating_add(
            inner
                .health
                .flush_failures
                .saturating_sub(before.flush_failures),
        );
    }

    fn try_report_pending_capture_loss(inner: &mut JsonlInner) {
        if !matches!(inner.format, RecorderFormat::V5 { .. })
            || inner.pending_capture_loss.is_empty()
        {
            return;
        }
        let pending = inner.pending_capture_loss;
        // A failed attempt to report loss is not recursively counted as
        // another lost product observation. Retain the in-memory observation
        // for a later ordinary write; it is never a second durable journal.
        if Self::write_v5_event(
            inner,
            None,
            crate::v5::Event::RecordingCaptureLoss(crate::v5::RecordingCaptureLoss {
                serialization_failed_attempts: pending.serialization.into(),
                write_failed_attempts: pending.write.into(),
                flush_failed_attempts: pending.flush.into(),
                extent: crate::v5::RecordingLossExtent::Unknown,
            }),
        ) {
            inner.pending_capture_loss = PendingCaptureLoss::default();
        }
    }

    fn write_record(inner: &mut JsonlInner, record: AuditRecord) -> bool {
        if let AuditEventKind::SourceContext { source } = &record.kind {
            inner.retained_source_context = Some(source.clone());
        }
        #[cfg(test)]
        if inner.fail_next_write {
            inner.fail_next_write = false;
            inner.health.write_failures = inner.health.write_failures.saturating_add(1);
            return false;
        }
        let seq = inner.seq;
        inner.seq = seq.wrapping_add(1);
        let body = match &inner.format {
            RecorderFormat::V4 => {
                let kind = record.kind;
                let context = stamp_system_human_action(record.context, &kind);
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
                    kind,
                };
                serde_json::to_vec(&event).ok()
            }
            RecorderFormat::V5 { .. } => {
                let group_ref = record
                    .group_ref
                    .as_deref()
                    .map(crate::v5::group_ref_from_legacy_hex)
                    .transpose();
                group_ref.ok().and_then(|group_ref| {
                    let kind = record.kind;
                    let context = stamp_system_human_action(record.context, &kind);
                    Self::v5_body(
                        inner,
                        group_ref,
                        crate::v5::Event::Operational(Box::new(
                            crate::v5::OperationalEvent::from_audit(AuditRecord {
                                group_ref: None,
                                context,
                                kind,
                            }),
                        )),
                    )
                })
            }
        };
        if let Some(body) = body {
            Self::write_body(inner, &body)
        } else {
            inner.health.serialization_failures =
                inner.health.serialization_failures.saturating_add(1);
            false
        }
    }

    fn write_v5_event(
        inner: &mut JsonlInner,
        group_ref: Option<crate::v5::GroupRef>,
        event: crate::v5::Event,
    ) -> bool {
        #[cfg(test)]
        if inner.fail_next_v5_write {
            inner.fail_next_v5_write = false;
            inner.health.write_failures = inner.health.write_failures.saturating_add(1);
            return false;
        }
        inner.seq = inner.seq.wrapping_add(1);
        if let Some(body) = Self::v5_body(inner, group_ref, event) {
            Self::write_body(inner, &body)
        } else {
            inner.health.serialization_failures =
                inner.health.serialization_failures.saturating_add(1);
            false
        }
    }

    fn v5_body(
        inner: &JsonlInner,
        group_ref: Option<crate::v5::GroupRef>,
        event: crate::v5::Event,
    ) -> Option<Vec<u8>> {
        let RecorderFormat::V5 {
            source_ref,
            session_id,
            producer,
            opened_at,
        } = &inner.format
        else {
            return None;
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis();
        crate::v5::Record::new(crate::v5::RecordFields {
            schema_version: crate::v5::SchemaVersion::V5,
            source_ref: source_ref.clone(),
            session_id: session_id.clone(),
            seq: inner.seq.into(),
            wall_time_ms: (now_ms.min(i64::MAX as u128) as i64).into(),
            mono_us: (opened_at.elapsed().as_micros().min(u64::MAX as u128) as u64).into(),
            producer: producer.clone(),
            group_ref,
            event,
        })
        .ok()?
        .to_json()
        .ok()
    }

    fn write_body(inner: &mut JsonlInner, body: &[u8]) -> bool {
        if inner.writer_needs_seal {
            inner.health.write_failures = inner.health.write_failures.saturating_add(1);
            return false;
        }
        #[cfg(test)]
        if inner.fail_next_partial_write {
            inner.fail_next_partial_write = false;
            let prefix = &body[..(body.len() / 2).max(1)];
            inner
                .writer
                .as_mut()
                .expect("active writer")
                .write_all(prefix)
                .expect("test partial write");
            inner
                .writer
                .as_mut()
                .expect("active writer")
                .flush()
                .expect("test partial flush");
            inner.health.write_failures = inner.health.write_failures.saturating_add(1);
            inner.writer_needs_seal = true;
            return false;
        }
        #[cfg(test)]
        if inner.fail_next_v5_flush_with_buffered_row {
            inner.fail_next_v5_flush_with_buffered_row = false;
            inner
                .writer
                .as_mut()
                .expect("active writer")
                .write_all(body)
                .expect("test buffered write");
            inner
                .writer
                .as_mut()
                .expect("active writer")
                .write_all(b"\n")
                .expect("test buffered newline");
            inner.health.flush_failures = inner.health.flush_failures.saturating_add(1);
            inner.writer_needs_seal = true;
            return false;
        }
        if inner
            .writer
            .as_mut()
            .expect("active writer")
            .write_all(body)
            .is_err()
            || inner
                .writer
                .as_mut()
                .expect("active writer")
                .write_all(b"\n")
                .is_err()
        {
            inner.health.write_failures = inner.health.write_failures.saturating_add(1);
            inner.writer_needs_seal = matches!(inner.format, RecorderFormat::V5 { .. });
            return false;
        }
        if inner
            .writer
            .as_mut()
            .expect("active writer")
            .flush()
            .is_err()
        {
            inner.health.flush_failures = inner.health.flush_failures.saturating_add(1);
            inner.writer_needs_seal = matches!(inner.format, RecorderFormat::V5 { .. });
            return false;
        }
        inner.active_bytes = inner.active_bytes.saturating_add(body.len() as u64 + 1);
        true
    }

    fn try_roll_segment(&self, inner: &mut JsonlInner, now: Instant) {
        #[cfg(test)]
        if self.disable_segment_rotation.load(Ordering::Relaxed) {
            return;
        }
        if inner
            .active_bytes
            .saturating_sub(inner.repeated_source_bytes)
            < AUDIT_LOG_SEGMENT_MAX_BYTES
            || inner
                .segment_retry_after
                .is_some_and(|deadline| now < deadline)
        {
            return;
        }
        inner.segment_retry_after = if self.roll_into_segment(inner).is_err() {
            Some(now + Duration::from_secs(30))
        } else {
            None
        };
    }

    /// Atomically replace the backing file with a fresh empty one at the same
    /// path, resetting the sequence, recorder session id, and health counters.
    /// The fresh file is staged as an owner-only sibling and renamed over the
    /// live path, so any failure leaves the original file, writer fd, seq,
    /// session id, and health state untouched and still recording. The caller
    /// must hold the inner lock.
    fn swap_to_fresh_file(&self, inner: &mut JsonlInner) -> std::io::Result<()> {
        if inner.writer_path != self.path {
            return Err(std::io::Error::other(
                "audit writer must recover its active path before destructive rotation",
            ));
        }
        // Best-effort flush of whatever is buffered into the file we are about
        // to discard.
        let _ = inner.writer.as_mut().expect("active writer").flush();
        // Stage the fresh file as a 0600 sibling. `create_new` refuses to
        // adopt a leftover staged file (whose contents would leak into the
        // fresh log), so clear one from an interrupted earlier swap first.
        let staged = staged_swap_path(&self.path);
        match std::fs::remove_file(&staged) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        // The handle is write-only rather than append — equivalent for a
        // brand-new empty file with a single `BufWriter`.
        let file = fs_private::create_new_private(&staged)?;
        // Atomic replace: the live path always names either the old complete
        // file or the fresh empty one, and rename preserves the staged 0600
        // mode. Recorder state advances only after the rename succeeds. This
        // relies on POSIX rename replacing an existing destination in place;
        // the crate targets Unix only (like `fs_private`'s owner-only file
        // model), so the Windows "rename fails if the destination exists"
        // behavior does not apply — and a delete-then-rename fallback would
        // reintroduce exactly the non-atomic window this swap removes.
        if let Err(err) = std::fs::rename(&staged, &self.path) {
            let _ = std::fs::remove_file(&staged);
            return Err(err);
        }
        // Assigning to `inner.writer` drops the old `BufWriter`, closing the
        // fd of the replaced (now unlinked) file.
        inner.writer = Some(BufWriter::new(file));
        inner.seq = 0;
        inner.recorder_session_id = generate_recorder_session_id();
        if let RecorderFormat::V5 {
            session_id,
            opened_at,
            ..
        } = &mut inner.format
        {
            *session_id = v5_session_id(&inner.recorder_session_id);
            *opened_at = Instant::now();
        }
        inner.health = AuditRecorderHealthSnapshot::default();
        inner.pending_capture_loss = PendingCaptureLoss::default();
        inner.recording_finished = false;
        inner.writer_needs_seal = false;
        inner.seal_retry_after = None;
        inner.active_bytes = 0;
        inner.repeated_source_bytes = 0;
        inner.segment_retry_after = None;
        inner.writer_path = self.path.clone();
        Ok(())
    }

    /// Seal the active file into an immutable segment sibling and continue
    /// recording into a fresh file at the same path (mdk#1181). The caller must
    /// hold the inner lock.
    ///
    /// Nothing is deleted or truncated: the rename hands the *same inode* — and
    /// therefore every recorded byte — to the segment name. Only the latest
    /// source context is repeated, with a fresh sequence, in the new file.
    /// Ordinary events are never replayed. Retention and disk bounding
    /// of the sealed segments are deliberately out of scope here; they belong to
    /// mdk#1014.
    ///
    /// Rotation is transparent to consumers on purpose: `seq`, the recorder
    /// session id, and the health counters carry across the boundary and no
    /// `recorder_started` row is fabricated, so an analyzer sees one continuous
    /// session and the upload endpoint's content-keyed line dedupe never
    /// re-mints a line just because it moved to a new filename.
    ///
    /// Crash safety (`multi-step-state-changes.md`): the rename is atomic and is
    /// the only step that moves data. A crash between the rename and the fresh
    /// open leaves the complete segment on disk and no active file, which the
    /// next open converges from by creating one. If the fresh open fails, the
    /// segment is renamed back so the still-open writer fd and the active path
    /// agree again.
    fn roll_into_segment(&self, inner: &mut JsonlInner) -> std::io::Result<()> {
        // A failed flush must not seal a segment or discard buffered bytes.
        inner
            .writer
            .as_mut()
            .expect("active writer")
            .flush()
            .inspect_err(|_| {
                inner.health.flush_failures = inner.health.flush_failures.saturating_add(1);
            })?;
        let (segment, index) = self.next_segment_path(inner)?;
        let previous_path = inner.writer_path.clone();
        std::fs::rename(&previous_path, &segment)?;
        match self.reopen_active() {
            Ok(file) => {
                inner.writer = Some(BufWriter::new(file));
                inner.active_bytes = 0;
                inner.next_segment_index = Some(index.saturating_add(1));
                inner.writer_path = self.path.clone();
                // Use the same best-effort write and health accounting as all
                // other rows. write_record neither relocks nor attempts rollover.
                if let Some(source) = inner.retained_source_context.clone() {
                    Self::write_record(
                        inner,
                        AuditRecord::new(None, AuditEventKind::SourceContext { source }),
                    );
                }
                inner.repeated_source_bytes = inner.active_bytes;
                Ok(())
            }
            Err(err) => {
                // Compensate the one applied step. If even this fails the data
                // is still on disk under the segment name and the writer keeps
                // appending to it, so no forensic line is lost.
                if self.restore_segment(&segment, &previous_path).is_err() {
                    inner.writer_path = segment;
                }
                Err(err)
            }
        }
    }

    fn restore_segment(&self, segment: &Path, previous: &Path) -> std::io::Result<()> {
        #[cfg(test)]
        if self.fail_segment_restore.swap(false, Ordering::Relaxed) {
            return Err(std::io::Error::other("forced segment restore failure"));
        }
        std::fs::rename(segment, previous)
    }

    /// Reopen the active path after a seal.
    fn reopen_active(&self) -> std::io::Result<std::fs::File> {
        #[cfg(test)]
        if self
            .fail_segment_reopen
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            return Err(std::io::Error::other("forced segment reopen failure"));
        }
        fs_private::open_private_append(&self.path)
    }

    /// Fail the next best-effort write after capturing any source context.
    #[cfg(test)]
    fn fail_next_write(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.fail_next_write = true;
    }

    #[cfg(test)]
    fn fail_next_write_after_partial_bytes(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.fail_next_partial_write = true;
    }

    #[cfg(test)]
    fn fail_next_v5_write(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.fail_next_v5_write = true;
    }

    /// Make the *next* segment reopen fail, so a test can drive the
    /// compensating rename-back and the retry backoff it starts.
    /// One-shot, so a test can also observe recovery afterwards.
    #[cfg(test)]
    fn fail_next_segment_reopen(&self) {
        self.fail_segment_reopen
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Next unclaimed segment name for the active path, and its index.
    ///
    /// Segments keep the audit path's stem so the app's `audit-*.jsonl`
    /// enumeration still finds them, and sort ahead of the active file (`-`
    /// precedes `.`), so the uploader drains sealed segments before the growing
    /// one.
    ///
    /// The starting index comes from `inner.next_segment_index` so the common
    /// case costs no directory read at all; only the first roll of a recorder
    /// (or one following a failed roll) scans. The `exists()` probe below is
    /// what actually guarantees a roll never renames over an existing segment,
    /// which would destroy already-recorded data — the hint only decides where
    /// the probe starts.
    fn next_segment_path(&self, inner: &mut JsonlInner) -> std::io::Result<(PathBuf, u32)> {
        let mut next = match inner.next_segment_index {
            Some(next) => next,
            None => scan_next_segment_index(&self.path),
        };
        loop {
            let candidate = segment_path(&self.path, next);
            if !candidate.exists() {
                return Ok((candidate, next));
            }
            next = next
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("audit log segment indexes exhausted"))?;
        }
    }
}

/// Name stem shared by an audit path and its segments: the file name with a
/// trailing `.jsonl` removed.
fn segment_base_name(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.strip_suffix(".jsonl")
        .map(str::to_owned)
        .unwrap_or(name)
}

fn segment_path(path: &Path, index: u32) -> PathBuf {
    let name = format!("{}-seg{index:06}.jsonl", segment_base_name(path));
    match path.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

/// One directory scan for the highest segment index already sitting next to
/// `path`, plus one. Used to seed the cached hint on a recorder's first roll —
/// after a crash mid-roll, or an earlier session, left segments behind.
fn scan_next_segment_index(path: &Path) -> u32 {
    let prefix = format!("{}-seg", segment_base_name(path));
    let mut next = 1u32;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && let Ok(entries) = std::fs::read_dir(parent)
    {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(index) = name
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(".jsonl"))
                .and_then(|digits| digits.parse::<u32>().ok())
            else {
                continue;
            };
            next = next.max(index.saturating_add(1));
        }
    }
    next
}

/// Staging sibling for [`JsonlRecorder::swap_to_fresh_file`]: the audit path
/// with `.tmp` appended to the whole file name. Appending (rather than
/// `with_extension`) keeps dotless paths from colliding with each other's
/// staged files.
fn staged_swap_path(path: &Path) -> PathBuf {
    let mut staged = path.as_os_str().to_owned();
    staged.push(".tmp");
    PathBuf::from(staged)
}

/// Filename convention for the engine-scoped audit log.
///
/// Returned path is `<dir>/audit-<engine_id>-v4.jsonl`. The caller is
/// responsible for ensuring the directory exists.
pub fn default_jsonl_path(dir: impl AsRef<Path>, engine_id: &str) -> std::path::PathBuf {
    dir.as_ref().join(format!("audit-{engine_id}-v4.jsonl"))
}

/// Distinct opt-in v5 active file; old v4 files and sealed segments remain
/// byte-for-byte intact and are never adopted by the v5 writer.
pub fn default_v5_jsonl_path(dir: impl AsRef<Path>, engine_id: &str) -> std::path::PathBuf {
    dir.as_ref().join(format!("audit-{engine_id}-v5.jsonl"))
}

#[cfg(test)]
mod tests;
