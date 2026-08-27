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
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const AUDIT_LOG_SCHEMA_VERSION: &str = "marmot-forensics-audit/v3";

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
/// correlation. Labels are opaque, user-supplied display strings; full account
/// identities are never included.
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

/// What armed an epoch-gap backfill for one stalled group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStallBackfillTrigger {
    UndecryptableThreshold,
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
/// are safe for audit recording. Never carries auth tokens, signatures,
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
/// authenticated group membership at send time. Recipients are represented by
/// salted member refs and an aggregate count, never full member identities.
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
/// witness-quorum convergence rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceAppWitness {
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_ref: Option<MemberRefHex>,
}

/// The score the selector computed for a convergence candidate. Mirrors the
/// engine's `BranchScore` using only obfuscated identities and digests.
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
pub struct GroupStateValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<DigestHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<u64>,
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
    /// needs that movement to continue, and a group wedged at one epoch is
    /// reported once and then stays latched until the epoch finally moves.
    ///
    /// A group wedged at one epoch reaches this row by a different route, worth
    /// knowing when reading `arms`. It cannot re-arm on epoch movement, so it
    /// arms on a paced clock instead and escalates on how many of those replays
    /// came back with the relays confirming they had served the account's stored
    /// history and it held nothing. `arms` then counts those confirmed
    /// completions rather than arms — a stricter count, never a larger one — and
    /// `arm_threshold` stays the arm-run threshold either way. Unlike the arm
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

    /// Open a recorder with an optional obfuscated account reference.
    pub fn open_with_account_ref(
        path: impl AsRef<Path>,
        engine_id: EngineIdHex,
        account_ref: Option<AccountRefHex>,
    ) -> std::io::Result<Self> {
        if let Some(account_ref) = account_ref.as_deref() {
            validate_account_ref_hex(account_ref)?;
        }
        let path = path.as_ref().to_path_buf();
        // Audit files are private local operational artifacts. Create them
        // owner-only and tighten pre-existing permissive files.
        let file = fs_private::open_private_append(&path)?;
        let recorder_session_id = generate_recorder_session_id();
        let recorder = Self {
            path,
            inner: Mutex::new(JsonlInner {
                writer: BufWriter::new(file),
                seq: 0,
                account_ref,
                engine_id,
                recorder_session_id,
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
        // Mark the start of the fresh file, mirroring `open_with_account_ref`.
        // `record` re-acquires the lock, so this runs after the guard is
        // dropped above.
        self.record(AuditRecord::new(None, recorder_started_kind()));
        Ok(())
    }
}

impl JsonlRecorder {
    /// Atomically replace the backing file with a fresh empty one at the same
    /// path, resetting the sequence, recorder session id, and health counters.
    /// The fresh file is staged as an owner-only sibling and renamed over the
    /// live path, so any failure leaves the original file, writer fd, seq,
    /// session id, and health state untouched and still recording. The caller
    /// must hold the inner lock.
    fn swap_to_fresh_file(&self, inner: &mut JsonlInner) -> std::io::Result<()> {
        // Best-effort flush of whatever is buffered into the file we are about
        // to discard.
        let _ = inner.writer.flush();
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
        inner.writer = BufWriter::new(file);
        inner.seq = 0;
        inner.recorder_session_id = generate_recorder_session_id();
        inner.health = AuditRecorderHealthSnapshot::default();
        Ok(())
    }
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
/// Returned path is `<dir>/audit-<engine_id>.jsonl`. The caller is
/// responsible for ensuring the directory exists.
pub fn default_jsonl_path(dir: impl AsRef<Path>, engine_id: &str) -> std::path::PathBuf {
    dir.as_ref().join(format!("audit-{engine_id}.jsonl"))
}

#[cfg(test)]
mod tests;
